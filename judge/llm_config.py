"""
llm_config.py — Factory des modèles LLM pour DeepTeam (rôles simulator + evaluation).

POURQUOI CE FICHIER
    DeepTeam exige DEUX modèles : `simulator` (génère les attaques) et `evaluation`
    (juge si l'attaque a réussi — rôle le plus sensible). NOTES.md §15 acte la
    stratégie : profil « dev » = Ollama local (qwen2.5:7b) pour les DEUX rôles,
    gratuit et illimité. Cette factory renvoie des INSTANCES (et non des strings) :
    c'est la seule façon vérifiée de fixer le provider par rôle dans deepteam 1.0.7
    (`initialize_model` : une string suit la config globale, une instance est
    utilisée telle quelle).

FAITS VÉRIFIÉS PAR SPIKE (2026-07-17, environnement du projet)
    - OllamaModel(model="qwen2.5:7b", base_url="http://localhost:11434").generate(...)
      -> ("OK", 0.0). Nécessite le paquet python `ollama` (installé : 0.6.2).
    - DeepEvalBaseLLM.__init__(self, model=None, ...) pose self.name puis appelle
      self.load_model(). Un modèle custom implémente generate / a_generate /
      get_model_name / load_model.
"""

from __future__ import annotations

import asyncio
import collections
import os
import threading
import time
from typing import Any, Tuple

# Charge le .env de la racine du projet AVANT de lire les variables ci-dessous, pour
# que GEMINI_API_KEY / AUDIT_LLM_PROFILE soient disponibles sans export manuel. C'est
# le point d'entrée central du choix des modèles → l'endroit naturel où charger .env.
# Défensif : si python-dotenv est absent, on continue (les vars restent lues via l'env).
try:
    from dotenv import load_dotenv

    load_dotenv()  # cherche .env à partir du cwd et remonte (racine projet)
except Exception:
    pass

from deepeval.models import OllamaModel
from deepeval.models.base_model import DeepEvalBaseLLM

# -- Paramètres du profil « dev » (surchargeables par variables d'environnement) -- #
OLLAMA_MODEL = os.environ.get("AUDIT_OLLAMA_MODEL", "qwen2.5:7b")
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")

# Profil actif : env AUDIT_LLM_PROFILE, défaut « dev » (cf. NOTES.md §15).
DEFAULT_PROFILE = os.environ.get("AUDIT_LLM_PROFILE", "dev")

# -- Profil « final » : Gemini Flash (attaques + jugement FIABLES) ------------ #
# ⚠️ QUOTAS FREE-TIER VÉRIFIÉS PAR SPIKE (2026-07-26, clé du projet) :
#   - gemini-2.0-flash / -flash-lite : quota = 0 (429 « limit: 0 » dès le 1er appel).
#   - gemini-flash-latest (=3.6-flash) : 5 req/MIN — trop peu pour un run complet.
#   - gemini-flash-lite-latest        : ~15 req/MIN — DÉFAUT (meilleur compromis
#     débit/force sur le free tier). Passer à `gemini-flash-latest` (plus fort) si
#     la FACTURATION est activée (limite ~2000 req/min).
# Le défaut de la lib deepeval (gemini-2.5-pro) est PAYANT → on ne l'utilise jamais.
GEMINI_MODEL = os.environ.get("AUDIT_GEMINI_MODEL", "gemini-flash-lite-latest")
# Base OpenAI-compatible de Gemini (pour le OpenAIChatTarget de PyRIT). Le SDK
# OpenAI ajoute lui-même « /chat/completions » (comme pour Ollama /v1).
GEMINI_OPENAI_BASE = os.environ.get(
    "GEMINI_OPENAI_BASE", "https://generativelanguage.googleapis.com/v1beta/openai"
)

# Débit max autorisé vers Gemini (req/MINUTE). Free-tier flash-lite = 15/min → on
# reste SOUS (13) pour la marge (le limiteur couvre simulator + evaluation + severity).
GEMINI_RPM = int(os.environ.get("AUDIT_GEMINI_RPM", "13"))


class _RateLimiter:
    """Limiteur à fenêtre glissante : ≤ max_calls sur `period` secondes.

    POURQUOI
        Le free-tier Gemini plafonne à 15 requêtes/MINUTE. Un run ASI01 complet
        (100-200+ appels) le dépasse → 429 RESOURCE_EXHAUSTED en rafale. Ce limiteur
        GLOBAL (partagé par toutes les instances Gemini du process) espace les appels
        pour rester sous la limite. Sans facturation, c'est le seul moyen de faire un
        run complet sur Gemini (NOTES.md §18).

    THREAD-SAFE + ASYNC
        `acquire()` (sync, ex. SeverityJudge) et `acquire_async()` (async, DeepTeam
        async_mode=True) partagent la MÊME fenêtre → le compteur est global et correct
        que l'appelant soit synchrone ou asynchrone.
    """

    def __init__(self, max_calls: int, period: float = 60.0) -> None:
        self.max_calls = max(1, max_calls)
        self.period = period
        self._calls: "collections.deque[float]" = collections.deque()
        self._lock = threading.Lock()

    def _reserve(self) -> float:
        """Réserve un créneau si possible ; sinon renvoie le temps d'attente (s)."""
        with self._lock:
            now = time.monotonic()
            while self._calls and now - self._calls[0] >= self.period:
                self._calls.popleft()
            if len(self._calls) < self.max_calls:
                self._calls.append(now)
                return 0.0
            return self.period - (now - self._calls[0]) + 0.05

    def acquire(self) -> None:
        """Bloque (sync) jusqu'à obtenir un créneau."""
        while True:
            wait = self._reserve()
            if wait <= 0:
                return
            time.sleep(min(wait, self.period))

    async def acquire_async(self) -> None:
        """Attend (async, sans bloquer l'event loop) jusqu'à obtenir un créneau."""
        while True:
            wait = self._reserve()
            if wait <= 0:
                return
            await asyncio.sleep(min(wait, self.period))


# Limiteur GLOBAL Gemini (une seule fenêtre partagée par simulator/evaluation/severity).
_GEMINI_LIMITER = _RateLimiter(GEMINI_RPM)

# Classe Gemini rate-limitée, construite paresseusement (évite d'importer google.genai
# en profil dev). Mise en cache après la 1re création.
_RL_GEMINI_CLS: type | None = None


def _rate_limited_gemini_class() -> type:
    """Retourne (en cache) une sous-classe de GeminiModel qui passe par le limiteur.

    On surcharge `generate` (sync) ET `a_generate` (async) pour acquérir un créneau
    AVANT chaque appel réseau. `*args/**kwargs` : robuste aux variations de signature
    entre versions deepeval (generate(prompt, schema=...) etc.).
    """
    global _RL_GEMINI_CLS
    if _RL_GEMINI_CLS is None:
        from deepeval.models import GeminiModel

        class RateLimitedGeminiModel(GeminiModel):  # type: ignore[misc, valid-type]
            def generate(self, *args: Any, **kwargs: Any) -> Any:
                _GEMINI_LIMITER.acquire()
                return super().generate(*args, **kwargs)

            async def a_generate(self, *args: Any, **kwargs: Any) -> Any:
                await _GEMINI_LIMITER.acquire_async()
                return await super().a_generate(*args, **kwargs)

        _RL_GEMINI_CLS = RateLimitedGeminiModel
    return _RL_GEMINI_CLS


# (simulator, evaluation)
JudgeModels = Tuple[DeepEvalBaseLLM, DeepEvalBaseLLM]


class DryRunModel(DeepEvalBaseLLM):
    """Modèle FACTICE — réponses fixes, ZÉRO appel réseau, coût 0.

    CE QUE ÇA FAIT
        Permet d'exécuter tout le pipeline (get_scenarios → red_team → scoring)
        sans consommer de tokens ni dépendre d'un LLM. `generate` renvoie une
        réponse cannée ; si un schema pydantic est demandé, on tente une instance
        « vide » (best-effort) pour ne pas casser le parsing en aval.

    POURQUOI
        Le mode dry-run est indispensable pour tester la plomberie du framework
        (câblage, callbacks, scoring) rapidement et gratuitement — profil « ci »
        de NOTES.md §15.
    """

    def __init__(self, canned: str = "DRY-RUN: réponse simulée déterministe.") -> None:
        self.canned = canned
        super().__init__("dry-run")  # pose self.name + appelle self.load_model()

    def load_model(self) -> None:
        """Aucun modèle à charger (offline)."""
        return None

    def get_model_name(self) -> str:
        return "DryRunModel (offline, réponses fixes)"

    def generate(self, prompt: str, schema: Any = None) -> tuple[Any, float]:
        """Renvoie (réponse, coût=0) sans réseau ; gère un schema en best-effort."""
        if schema is not None:
            try:
                # pydantic v2 : instance sans validation (dry-run uniquement).
                return schema.model_construct(), 0.0
            except Exception:
                return self.canned, 0.0
        return self.canned, 0.0

    async def a_generate(self, prompt: str, schema: Any = None) -> tuple[Any, float]:
        """Version async — identique (aucun réseau)."""
        return self.generate(prompt, schema)


def _ollama() -> OllamaModel:
    """Instancie un OllamaModel local (profil dev).

    POURQUOI UNE FONCTION
        On crée une instance FRAÎCHE par rôle. Les deux pointent le même modèle
        (qwen2.5:7b) → Ollama ne charge qu'UN modèle en VRAM (pas de swap 8 Go),
        conformément à NOTES.md §15.
    """
    return OllamaModel(model=OLLAMA_MODEL, base_url=OLLAMA_BASE_URL)


def _gemini_api_key() -> str:
    """Retourne GEMINI_API_KEY ou lève une RuntimeError CLAIRE.

    POURQUOI UN GARDE PLACEHOLDER
        Le .env est livré avec un placeholder « <colle-ta-cle-ici> » (non vide) → un
        simple `if not key` ne le détecterait pas et Gemini renverrait une erreur
        d'auth obscure. On rejette donc aussi les valeurs vides, le template
        « AIza-... » et tout ce qui commence par « < » (placeholder non remplacé).
    """
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not key or key.startswith("<") or key in ("AIza-...", "AIza-...ta_clé..."):
        raise RuntimeError(
            "Profil 'final' : GEMINI_API_KEY absente ou non renseignée (placeholder). "
            "Colle ta clé dans .env — gratuite : https://aistudio.google.com/apikey"
        )
    return key


def _gemini() -> "DeepEvalBaseLLM":
    """Instancie un GeminiModel Flash (profil final). EXIGE GEMINI_API_KEY.

    CE QUE ÇA FAIT
        Renvoie une instance deepeval GeminiModel pointant GEMINI_MODEL
        (défaut gemini-flash-lite-latest — free tier actif, cf. constantes ci-dessus).

    POURQUOI PAS LE DÉFAUT DE LA LIB
        Le défaut deepeval est gemini-2.5-pro (PAYANT depuis avril 2026) ; et
        gemini-2.0-flash a un quota free-tier = 0 (429 immédiat). On force donc un
        alias à quota actif via GEMINI_MODEL — NOTES.md §15/§18.

    RATE-LIMITÉ
        On renvoie une instance RATE-LIMITÉE (≤ GEMINI_RPM req/min, limiteur global
        partagé) pour tenir sous le plafond free-tier 15/min sur un run complet.
    """
    cls = _rate_limited_gemini_class()  # sous-classe GeminiModel + limiteur global
    return cls(model=GEMINI_MODEL, api_key=_gemini_api_key())


def get_pyrit_chat_config(profile: str | None = None) -> dict[str, str]:
    """Config du OpenAIChatTarget de PyRIT (adversaire + scorer) selon le profil.

    CE QUE ÇA FAIT
        PyRIT pilote ses attaques multi-turn avec un LLM « adversaire » + un LLM
        « scorer », tous deux exposés via un endpoint OpenAI-compatible. Cette
        fonction renvoie de quoi construire ce target selon le profil :
        - dev / ci : Ollama local (qwen2.5:7b) — attaques faibles mais gratuites.
        - final    : Gemini Flash (attaques FORTES) via son endpoint OpenAI-compat.

    POURQUOI ICI (et pas en dur dans pyrit_runner)
        Le choix du provider par profil est centralisé dans llm_config, comme pour
        get_judge_models — un seul endroit à changer. Vérifié : constat DVAP (§18)
        que l'adversaire 7B génère des attaques trop faibles → Gemini en 'final'.

    Retour : {"model_name", "endpoint", "api_key"}.
        `endpoint` = BASE OpenAI (le SDK openai ajoute lui-même « /chat/completions »,
        exactement comme pour Ollama /v1 — spike §17).
    """
    profile = (profile or DEFAULT_PROFILE or "dev").lower()

    if profile == "final":
        return {
            "model_name": GEMINI_MODEL,
            "endpoint": GEMINI_OPENAI_BASE,
            "api_key": _gemini_api_key(),
        }

    # dev / dry_run / ci → Ollama local (endpoint OpenAI-compat = base + /v1).
    return {
        "model_name": OLLAMA_MODEL,
        "endpoint": OLLAMA_BASE_URL.rstrip("/") + "/v1",
        "api_key": "ollama",
    }


def get_judge_models(profile: str | None = None) -> JudgeModels:
    """Retourne (simulator_model, evaluation_model) selon le profil.

    CE QUE ÇA FAIT
        - "dev" (défaut)     : Ollama qwen2.5:7b pour les DEUX rôles (local, gratuit).
        - "dry_run" / "ci"   : DryRunModel pour les deux (offline, zéro coût/réseau).
        - "final"            : Gemini Flash (gemini-flash-lite-latest) pour les DEUX rôles —
                               attaques fortes + jugement fiable pour la validation /
                               soutenance. Exige google-genai + GEMINI_API_KEY
                               (clé AI Studio gratuite). Voir NOTES.md §15/§18.

    POURQUOI DES INSTANCES
        `initialize_model` (deepteam) ne fixe un provider par rôle QUE si on passe
        une instance ; une string suivrait la config globale. Vérifié par spike.

    Retour : tuple (simulator, evaluation), tous deux DeepEvalBaseLLM.
    """
    profile = (profile or DEFAULT_PROFILE or "dev").lower()

    if profile == "dev":
        # Deux instances du même modèle → un seul chargement VRAM côté Ollama.
        return _ollama(), _ollama()

    if profile in ("dry_run", "dry-run", "ci"):
        return DryRunModel(), DryRunModel()

    if profile == "final":
        # DÉCISION (constat DVAP §18) : le simulateur 7B local génère des attaques
        # TROP FAIBLES → le lab vulnérable obtenait un faux 9.4/10. On met Gemini
        # Flash sur les DEUX rôles (simulator ET evaluation) → attaques fortes +
        # jugement fiable. Exige GEMINI_API_KEY (clé AI Studio gratuite).
        # Deux instances distinctes (une par rôle) : évite tout état partagé.
        return _gemini(), _gemini()

    raise ValueError(
        f"Profil LLM inconnu : {profile!r} (attendu : 'dev', 'dry_run'/'ci', 'final')."
    )
