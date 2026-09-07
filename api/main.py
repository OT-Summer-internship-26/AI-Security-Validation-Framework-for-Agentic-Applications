"""
main.py — API REST du framework d'audit. Sert le dashboard.

CE QUE ÇA FAIT
    Lance de VRAIS audits (les mêmes que `scripts/run_agent.py`) depuis une requête
    HTTP, suit leur progression en direct, et expose les résultats déjà produits.
    Le dashboard n'a donc plus besoin ni de VS Code ni du script de synchronisation.

ENDPOINTS
    GET  /health                     → santé de l'API + dépendances (Docker, Gemini…)
    GET  /agents                     → catalogue des agents ASI disponibles
    GET  /audits                     → tous les résultats d'audit enregistrés
    GET  /audits/{audit_id}          → un résultat complet
    POST /audits                     → LANCE un audit (retourne un run_id)
    GET  /runs                       → audits en cours / récents
    GET  /runs/{run_id}              → progression, journal, résultat final
    POST /runs/{run_id}/cancel       → annule un audit en cours

AUTHENTIFICATION
    Clé d'API optionnelle : si `FRAMEWORK_API_KEY` est défini, le header `X-API-Key`
    est exigé. Sinon (poste de développement) l'API est ouverte en local.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import urllib.parse
import re
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
# Point de resolution UNIQUE du repertoire de resultats : en production
# il pointe vers un volume persistant (AUDIT_RESULTS_DIR).
from workflow.paths import results_dir

RESULTS_DIR = results_dir()

# Format de journal choisi par l'environnement (`LOG_FORMAT=json` en production).
# Installe ICI, a l'import du module : uvicorn configure les siens au demarrage,
# et une configuration posee plus tard laisserait passer les premieres lignes au
# mauvais format — precisement celles qui disent pourquoi le service n'a pas
# demarre.
from api.logging_config import configurer as _configurer_journal

LOG_FORMAT = _configurer_journal()

# `logger` ÉTAIT UTILISÉ SANS JAMAIS AVOIR ÉTÉ DÉFINI.
#     Trois `except` l'appelaient (`Run.__setattr__`, `log`, `add_exchange`) pour
#     absorber un échec de persistance. Sans liaison, ces blocs levaient un
#     `NameError` AU LIEU d'écrire une ligne de journal — et `__setattr__` est
#     sur le chemin chaud : chaque mise à jour de statut y passe.
#
#     Le commentaire disait « le suivi ne fait jamais échouer l'audit ». C'était
#     l'inverse : dès que `store.maj_run` échouait — base verrouillée, disque
#     plein, schéma en désaccord — le gestionnaire censé le rattraper tuait
#     l'audit. Le seul cas où il servait était justement celui où il cassait.
logger = logging.getLogger(__name__)

# Magasin durable : etat des executions et cles d'API, sur le volume partage.
# Initialise a l'import : l'API et l'ouvrier partagent le meme schema, et
# chacun peut demarrer en premier.
from api import store

store.init()
REPLAYS_DIR = ROOT / "data" / "replays"
RUNNER = ROOT / "scripts" / "run_agent.py"

# Charge .env AVANT tout : sans ça `GEMINI_API_KEY` est absent quand l'API est
# lancée par uvicorn, et le profil `final` échoue au moment du run.
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env", override=False)
except Exception:
    pass

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

app = FastAPI(
    title="AI Security Audit Framework",
    description="Audit automatisé OWASP Top 10 for Agentic Applications 2026",
    version="1.0.0",
)

# Le dashboard tourne sur un autre port (Vite :5173) → CORS indispensable.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ══════════════════════════════════════════════════════════════════════
#  Modèles
# ══════════════════════════════════════════════════════════════════════

class AuditRequest(BaseModel):
    """Paramètres de lancement d'un audit.

    MODES (exigence de l'encadrant)
        · `full`     — toutes les catégories implémentées, tous les axes. Plusieurs heures.
        · `targeted` — un sous-ensemble de catégories choisi par l'auditeur.
        · `quick`    — toutes les catégories, mais SEULEMENT les axes déterministes
                       (Garak, Semgrep, pip-audit, sandbox). Aucun appel LLM, donc
                       aucun plafond de débit : quelques minutes, résultat reproductible.
    """

    mode: str = Field(default="targeted", description="full | targeted | quick")
    category: str = Field(default="ASI_05", description="ex. ASI_01 … ASI_10")
    categories: list[str] | None = Field(
        default=None, description="plusieurs catégories ; prioritaire sur `category`"
    )
    # Axes désactivables — le mode `quick` les positionne automatiquement.
    disable_deepteam: bool = False
    disable_pyrit: bool = False
    disable_garak: bool = False
    disable_microsoft: bool = False
    target_url: str = Field(default="http://localhost:8090/api/coding/chat")
    # Format JSON de la cible — indispensable dès qu'on sort du lab par défaut.
    # Ex. lab DVAP `autonomous-agent` : prompt_field="content",
    # extra_payload={"title": "…"} (les deux champs sont requis, sinon 422).
    prompt_field: str = Field(default="message")
    response_field: str = Field(default="response")
    extra_payload: dict[str, Any] | None = None
    profile: str = Field(default="final", description="dev | final | ollama | dry_run")
    attacks_per_type: int = Field(default=3, ge=1, le=10)
    max_concurrent: int = Field(default=2, ge=1, le=10)
    pyrit_max_turns: int = Field(default=5, ge=1, le=15)
    timeout: float = Field(default=180.0, ge=10, le=600)
    source_path: str | None = None
    requirements_path: str | None = None
    explain_passes: bool = True
    garak_probes: str | None = None
    # ASI07 — identité d'agent pair usurpée. Enveloppe chaque prompt dans un
    # message inter-agents non signé : la cible vérifie-t-elle la provenance ?
    peer_agent_id: str | None = None


# ══════════════════════════════════════════════════════════════════════
#  Registre des exécutions en cours
# ══════════════════════════════════════════════════════════════════════

class Run:
    """Une exécution d'audit, ADOSSÉE AU MAGASIN DURABLE.

    POURQUOI CE N'EST PLUS UN OBJET EN MÉMOIRE
        L'état vivait dans un dictionnaire du processus web. Un redémarrage
        perdait le suivi de tous les audits en cours, et deux répliques ne
        voyaient pas les mêmes exécutions — `GET /runs/{id}` répondait 404 une
        fois sur deux derrière un répartiteur.

        Chaque écriture va désormais dans `api/store.py` (SQLite sur le volume
        partagé). L'INTERFACE ne change pas — `log`, `add_exchange`, `status`,
        `progress` — de sorte que `_execute` n'a pas bougé d'une ligne : le
        dupliquer aurait créé deux comportements d'audit divergents, le défaut
        qui a déjà coûté deux runners incompatibles.
    """

    def __init__(self, run_id: str, req: AuditRequest, *, cree_par: str = "",
                 persister: bool = True) -> None:
        # Posé AVANT tout le reste : `__setattr__` le consulte à chaque
        # affectation, et les lignes qui suivent en déclenchent.
        object.__setattr__(self, "_persiste", False)
        self.id = run_id
        self.request = req
        self.status = "queued"       # queued | running | completed | failed | cancelled
        self.progress = 0
        self.stage = "En file d'attente"
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.finished_at: str | None = None
        self.result_file: str | None = None
        self.error: str | None = None
        self.proc: subprocess.Popen[str] | None = None
        self.categories: list[str] | None = None
        self.result_files: list[str] | None = None
        self.created_by = cree_par
        self._lock = threading.Lock()
        if persister:
            store.creer_run(run_id, req.model_dump(), cree_par)
        object.__setattr__(self, "_persiste", True)

    @classmethod
    def depuis_magasin(cls, travail: dict[str, Any]) -> "Run":
        """Reconstruit une exécution PRISE dans la file, sans la recréer."""
        run = cls(travail["run_id"], AuditRequest(**travail["request"]),
                  cree_par=travail.get("created_by", ""), persister=False)
        object.__setattr__(run, "status", travail["status"])
        object.__setattr__(run, "started_at", travail["started_at"])
        return run

    def __setattr__(self, nom: str, valeur: Any) -> None:
        """Persiste les champs de suivi dès qu'ils changent.

        Intercepter l'affectation plutôt que semer des appels partout : c'est ce
        qui garantit qu'une étape ajoutée demain à `_execute` sera persistée sans
        que personne n'y pense — le genre d'oubli qui ne se voit qu'en
        production, quand un audit reste bloqué à « Démarrage ».
        """
        object.__setattr__(self, nom, valeur)
        if nom in _CHAMPS_PERSISTES and getattr(self, "_persiste", False):
            try:
                store.maj_run(self.id, **{nom: valeur})
            except Exception as exc:        # le suivi ne fait jamais échouer l'audit
                logger.debug("suivi non persisté (%s) : %s", nom, exc)

    def log(self, level: str, text: str) -> None:
        try:
            store.ajouter_log(self.id, level, text)
        except Exception as exc:
            logger.debug("journal non persisté : %s", exc)

    def add_exchange(self, entry: dict[str, Any]) -> None:
        try:
            store.ajouter_echange(self.id, entry)
        except Exception as exc:
            logger.debug("échange non persisté : %s", exc)

    def snapshot(self, since: int = 0, since_ex: int = 0) -> dict[str, Any]:
        etat = store.lire_run(self.id, since, since_ex)
        if etat is not None:
            return etat
        # Repli : une exécution absente du magasin (base effacée) ne doit pas
        # faire disparaître le suivi en cours.
        return {"run_id": self.id, "status": self.status, "progress": self.progress,
                "stage": self.stage, "started_at": self.started_at,
                "finished_at": self.finished_at, "result_file": self.result_file,
                "error": self.error, "request": self.request.model_dump(),
                "logs": [], "log_count": 0, "exchanges": [], "exchange_count": 0,
                "categories": self.categories, "result_files": self.result_files}


# Rejeux en cours : ils durent quelques minutes et restent dans ce processus.
# Les faire passer par la file ajouterait un second type de travail pour un
# gain nul.
_REJEUX: dict[str, "Run"] = {}

# Sans ouvrier deploye, l'API execute elle-meme. Mettre a 0 en production, ou
# les audits doivent survivre au redemarrage du serveur web.
EXECUTE_EN_PROCESSUS = os.environ.get(
    "AUDIT_INLINE_WORKER", "1").strip().lower() in ("1", "true", "yes", "on")

# Champs dont toute modification doit atteindre le magasin. `_execute` les écrit
# directement (`run.progress = 40`) sans savoir qu'ils sont persistés.
_CHAMPS_PERSISTES = frozenset({
    "status", "progress", "stage", "finished_at", "result_file",
    "result_files", "categories", "error",
})


# Étapes reconnues dans la sortie du runner → progression affichable.
# Chaque motif marque le DÉBUT de l'étape ; le pourcentage est indicatif.
_STAGES: list[tuple[str, int, str]] = [
    (r"AUDIT ASI", 3, "Initialisation"),
    (r"red_team\(\)|DeepTeam\s*:", 10, "DeepTeam — attaques comportementales"),
    (r"DeepTeam OK", 45, "DeepTeam terminé"),
    (r"PyRIT", 52, "PyRIT — attaque multi-tours"),
    (r"Garak", 66, "Garak — sondes automatiques"),
    (r"Microsoft|Arcanum", 78, "Payloads Microsoft"),
    (r"[Ss]tatique|[Ss]emgrep|pip-audit", 85, "Couche statique"),
    (r"[Dd]ynamique|[Ss]andbox", 92, "Couche dynamique — sandbox Docker"),
    (r"RÉSULTAT", 97, "Consolidation"),
    (r"Enregistré", 100, "Terminé"),
]


def _tail_exchanges(run: Run, path: Path, stop: threading.Event) -> None:
    """Suit le JSONL des échanges écrit par le runner et les pousse dans le run.

    POURQUOI UN FICHIER ET PAS STDOUT (bug MESURÉ le 2026-08-20)
        Les échanges transitaient par une balise `##EXCHANGE##` sur stdout. Mais
        DeepTeam écrit son spinner sur le MÊME flux depuis plusieurs threads : les
        écritures s'entrelacent, la ligne se fragmente, et le JSON devient
        illisible. Sur un run réel, 7 échanges captés sur ~30 — les 23 autres
        finissaient en texte brut dans les logs, et le dashboard affichait un
        panneau d'attaques quasi vide.

        Un fichier dédié n'a qu'un seul écrivain (le runner, sous verrou) : aucune
        fragmentation possible. On le relit ici ligne par ligne.

    Ne lève jamais : un défaut de journalisation ne doit pas casser un audit.
    """
    seen = 0
    # Boucle « sweep puis test » : quand `stop` est levé, on fait un DERNIER passage
    # avant de sortir. Sinon les échanges écrits entre l'avant-dernier réveil et la
    # mort du runner seraient perdus — exactement le genre de fuite silencieuse
    # qu'on vient de corriger.
    while True:
        try:
            if path.exists():
                with path.open(encoding="utf-8") as fh:
                    lines = fh.readlines()
                # Une dernière ligne sans "\n" est en cours d'écriture -> on attend.
                complete = lines if (lines and lines[-1].endswith("\n")) else lines[:-1]
                for line in complete[seen:]:
                    try:
                        entry = json.loads(line)
                    except Exception:
                        continue
                    run.add_exchange(entry)
                    run.log(
                        "warn" if entry.get("http_error") else "info",
                        f"Attaque #{entry.get('n')} envoyée — réponse en "
                        f"{entry.get('elapsed_s')}s"
                        + (" — CIBLE INJOIGNABLE, exclue" if entry.get("http_error") else ""),
                    )
                seen = len(complete)
        except Exception:
            pass
        if stop.is_set():
            return
        stop.wait(1.0)

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# Caractères de spinner Braille + barres de progression : DeepTeam en émet des
# MILLIERS par seconde. Les journaliser saturait le CPU du thread lecteur et
# affamait la boucle uvicorn — l'API devenait injoignable pendant tout l'audit.
_SPINNER = re.compile(r"[⠀-⣿─-▟]")
_NOISE = re.compile(
    r"^\s*(\d+%|\||━|─|╸|Testing|Evaluating|Generating|Simulating)\b.*$|"
    r"^\s*\d+\s*/\s*\d+\s*$"
)


def _drain(run: Run, stream: Any) -> None:
    """Lit la sortie du sous-processus, filtre le bruit et suit la progression.

    Le filtrage n'est pas cosmétique : sans lui, le spinner de DeepTeam produit
    un débit de lignes qui bloque l'API entière (constaté).
    """
    last_line = ""
    dropped = 0
    for raw_line in iter(stream.readline, ""):
        line = _ANSI.sub("", raw_line).rstrip()
        if not line:
            continue

        # Les échanges avec la cible ne passent PLUS par stdout : ils sont lus
        # depuis le JSONL du runner par `_tail_exchanges` (cf. son docstring).

        # La progression se lit AVANT le filtrage : une étape peut être annoncée
        # sur une ligne par ailleurs bruyante.
        for pattern, pct, label in _STAGES:
            if re.search(pattern, line):
                if pct >= run.progress:
                    run.progress, run.stage = pct, label
                break

        # Rejet du bruit : spinner, barres de progression, lignes répétées.
        if _SPINNER.search(line) or _NOISE.match(line) or line == last_line:
            dropped += 1
            continue
        last_line = line

        low = line.lower()
        if "traceback" in low:
            level = "critical"
        elif "error" in low or "[http_error]" in low or "warning" in low or "vulnérabilit" in low or "breach" in low:
            level = "warn"
        else:
            level = "info"
        run.log(level, line[:600])

    if dropped:
        run.log("debug", f"{dropped} ligne(s) de progression filtrées (spinner)")
    stream.close()


def cibles_autorisees() -> tuple[str, ...]:
    """Hôtes autorisés, LUS À L'APPEL. Vide = aucune restriction.

    Ex. : AUDIT_TARGET_ALLOWLIST=localhost,127.0.0.1,.interne.exemple.com

    POURQUOI PAS UNE CONSTANTE DE MODULE
        La première version lisait l'environnement À L'IMPORT. C'est exactement
        le piège déjà corrigé deux fois ici — `AUDIT_TARGET_CONCURRENCY` figé à
        l'import dans `base_agent`, puis le chemin de checkpoint dans
        `audit_graph`. Une variable posée après le chargement du module (test,
        ouvrier, conteneur reconfiguré) était silencieusement ignorée.

        Effet secondaire qui compte : les tests posent désormais la VRAIE variable
        au lieu de surcharger un attribut de module. Ils éprouvent donc ce qu'un
        opérateur configure, pas un raccourci interne.
    """
    brut = os.environ.get("AUDIT_TARGET_ALLOWLIST", "")
    return tuple(h.strip().lower() for h in brut.split(",") if h.strip())

_ALERTE_CIBLE_LIBRE_EMISE = False


def valider_cible(url: str) -> str:
    """POINT UNIQUE de validation d'une cible d'audit. Rend l'URL, ou lève 400/403.

    POURQUOI CE GARDE-FOU EXISTE
        `target_url` partait DIRECTEMENT du corps de la requête à la ligne de
        commande du runner, sans la moindre vérification — pas même le contrôle
        de schéma qui protège déjà les appels au catalogue DVAP (`_open_http`).
        Un opérateur authentifié pouvait viser `169.254.169.254` (métadonnées
        cloud), `localhost`, n'importe quelle adresse interne. Et comme les
        réponses de la cible sont enregistrées dans `run_exchanges` puis
        relisibles par `/runs/{id}` et le dashboard, **une clé opérateur fuitée
        devenait un SSRF authentifié avec exfiltration par le transcript**.

    CE QU'ON N'INTERDIT PAS, ET POURQUOI
        Les adresses privées restent atteignables : auditer un service interne
        qu'on POSSÈDE est exactement le métier de cet outil, et la cible par
        défaut est `http://localhost:8090`. Interdire casserait l'usage légitime.
        On BORNE : une installation déclare ce qu'elle a le droit d'attaquer.

    LE DÉFAUT EST PERMISSIF, MAIS IL NE SE TAIT PAS
        Sans `AUDIT_TARGET_ALLOWLIST`, toute cible est acceptée — mode
        développement. Un avertissement est émis UNE FOIS, pour qu'une mise en
        production ne reste pas ouverte par simple ignorance. Une fois par
        processus et non par audit : une alerte répétée à chaque appel finit
        par être filtrée, donc par ne plus rien signaler.
    """
    global _ALERTE_CIBLE_LIBRE_EMISE

    decoupe = urllib.parse.urlparse(url)
    hote = (decoupe.hostname or "").lower()

    if decoupe.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=400,
            detail=f"schéma de cible non autorisé : "
                   f"{decoupe.scheme or '(aucun)'} — attendu http ou https")
    if not hote:
        raise HTTPException(status_code=400, detail=f"cible sans hôte : {url[:80]}")

    liste = cibles_autorisees()
    if not liste:
        if not _ALERTE_CIBLE_LIBRE_EMISE:
            _ALERTE_CIBLE_LIBRE_EMISE = True
            logger.warning(
                "AUDIT_TARGET_ALLOWLIST n'est pas définie : TOUTE cible est "
                "acceptée (mode développement). En production, déclarez les hôtes "
                "autorisés — sinon une clé opérateur permet d'atteindre n'importe "
                "quelle adresse interne, et les réponses sont conservées dans le "
                "journal d'échanges.")
        return url

    # Un motif couvre l'hôte exact ; commençant par un point, il couvre aussi
    # les sous-domaines (`.interne.exemple.com`) mais JAMAIS le domaine nu —
    # `.exemple.com` n'autorise pas `exemple.com`, qui peut appartenir à un tiers.
    autorise = any(
        hote == motif or (motif.startswith(".") and hote.endswith(motif))
        for motif in liste
    )
    if not autorise:
        raise HTTPException(
            status_code=403,
            detail=(f"cible « {hote} » hors de la liste autorisée "
                    f"({', '.join(liste)}). "
                    "Ajustez AUDIT_TARGET_ALLOWLIST si cette cible vous appartient."))
    return url


def _build_cmd(req: AuditRequest, category: str) -> list[str]:
    """Ligne de commande du runner pour UNE catégorie, selon le mode demandé."""
    cmd = [
        sys.executable, "-u", str(RUNNER), category,
        "--target", req.target_url,
        "--prompt-field", req.prompt_field,
        "--response-field", req.response_field,
        "--profile", req.profile,
        "--attacks-per-type", str(req.attacks_per_type),
        "--max-concurrent", str(req.max_concurrent),
        "--pyrit-max-turns", str(req.pyrit_max_turns),
        "--timeout", str(req.timeout),
    ]
    if req.extra_payload:
        cmd += ["--extra-payload", json.dumps(req.extra_payload)]
    if req.source_path:
        cmd += ["--source-path", req.source_path]
    if req.requirements_path:
        cmd += ["--requirements-path", req.requirements_path]
    if req.garak_probes:
        cmd += ["--garak-probes", req.garak_probes]
    if req.explain_passes:
        cmd += ["--explain-passes"]
    if req.peer_agent_id:
        cmd += ["--peer-agent-id", req.peer_agent_id]

    # Le mode `quick` coupe TOUS les axes qui consomment des appels LLM. Il ne
    # reste que Garak et les couches statique/dynamique — déterministes, sans
    # plafond de débit, donc les seuls qualifiés pour bloquer un déploiement.
    quick = req.mode == "quick"
    if quick or req.disable_deepteam:
        cmd.append("--no-deepteam")
    if quick or req.disable_pyrit:
        cmd.append("--no-pyrit")
    if req.disable_garak:
        cmd.append("--no-garak")
    if quick or req.disable_microsoft:
        cmd.append("--no-microsoft")
    return cmd


def _requested_categories(req: AuditRequest) -> list[str]:
    """Catégories à auditer, selon le mode."""
    try:
        from workflow.audit_graph import AGENT_REGISTRY
        available = sorted(AGENT_REGISTRY)
    except Exception:
        available = []
    if req.mode in ("full", "quick"):
        return available
    # Mode ciblé : l'auditeur choisit UNE OU PLUSIEURS catégories. `category`
    # (au singulier) reste accepté pour la compatibilité avec les anciens appels.
    if req.categories:
        chosen = [c for c in req.categories if c in available]
        if chosen:
            return chosen
        # Toutes les categories demandees sont inconnues : ne rien renvoyer, pour
        # que l'appelant soit refuse au lieu de retomber sur `req.category`.
        return []
    return [req.category] if req.category in available else []


def _execute(run: Run) -> None:
    """Lance le runner en sous-processus et suit son exécution.

    En mode `full` ou `targeted` multi-catégories, les agents sont enchaînés
    SÉQUENTIELLEMENT : ils partagent le même limiteur de débit LLM, donc les
    paralléliser n'apporterait rien (mesuré — le goulot est le quota, pas le CPU).
    """
    req = run.request
    cats = _requested_categories(req)
    run.categories = cats                      # type: ignore[attr-defined]

    if len(cats) > 1:
        _execute_many(run, cats)
        return

    cmd = _build_cmd(req, cats[0])

    # `TERM=dumb` + `NO_COLOR` désactivent le spinner et les couleurs de rich/tqdm
    # utilisés par DeepTeam — c'est la correction À LA SOURCE du flot de lignes
    # qui bloquait l'API. Le filtre côté lecteur reste en ceinture-bretelles.
    env = dict(
        os.environ,
        PYTHONUTF8="1", PYTHONIOENCODING="utf-8",
        TERM="dumb", NO_COLOR="1", FORCE_COLOR="0",
        TQDM_DISABLE="1", DEEPEVAL_DISABLE_PROGRESS_BAR="1",
    )
    before = {p.name for p in RESULTS_DIR.glob("*.json")} if RESULTS_DIR.exists() else set()

    run.status = "running"
    run.stage = "Démarrage du runner"
    run.log("info", f"$ {' '.join(cmd[2:])}")

    # Fichier des échanges : le runner y écrit, `_tail_exchanges` le relit.
    ex_path = RESULTS_DIR / f"{run.id}.exchanges.jsonl"
    ex_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = cmd + ["--exchange-log", str(ex_path)]
    ex_stop = threading.Event()
    ex_thread = threading.Thread(
        target=_tail_exchanges, args=(run, ex_path, ex_stop), daemon=True
    )
    ex_thread.start()

    try:
        run.proc = subprocess.Popen(
            cmd, cwd=str(ROOT), env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding="utf-8",
            errors="replace", bufsize=1,
        )
        _drain(run, run.proc.stdout)
        code = run.proc.wait()
        # Le runner est mort : `ex_stop` déclenche un DERNIER passage (cf. la boucle
        # de `_tail_exchanges`) qui capte les échanges écrits juste avant la sortie.
        ex_stop.set()
        ex_thread.join(timeout=5)

        if run.status == "cancelled":
            run.log("warn", "Audit annulé par l'utilisateur.")
        elif code == 0:
            after = {p.name for p in RESULTS_DIR.glob("*.json")}
            new = sorted(after - before)
            run.result_file = new[-1] if new else None
            run.status = "completed"
            run.progress = 100
            run.stage = "Terminé"
            run.log("info", f"Résultat enregistré : {run.result_file}")
        else:
            run.status = "failed"
            run.error = f"Le runner s'est arrêté avec le code {code}"
            run.log("critical", run.error)
    except Exception as exc:                              # jamais bloquant
        run.status = "failed"
        run.error = f"{type(exc).__name__}: {exc}"
        run.log("critical", run.error)
    finally:
        run.finished_at = datetime.now(timezone.utc).isoformat()


ENV_QUIET = dict(
    PYTHONUTF8="1", PYTHONIOENCODING="utf-8",
    TERM="dumb", NO_COLOR="1", FORCE_COLOR="0",
    TQDM_DISABLE="1", DEEPEVAL_DISABLE_PROGRESS_BAR="1",
)


def _execute_many(run: Run, cats: list[str]) -> None:
    """Enchaîne plusieurs agents dans une seule exécution (modes `full` et `targeted`).

    FAIL-SAFE : l'échec d'un agent n'interrompt pas les suivants — c'est la règle
    du workflow (doc. technique : orchestration LangGraph). Chaque agent produit son propre fichier de résultat.
    """
    env = dict(os.environ, **ENV_QUIET)
    run.status = "running"
    run.log("info", f"Mode {run.request.mode} — {len(cats)} agent(s) : {', '.join(cats)}")

    produced: list[str] = []
    failed: list[str] = []

    for i, cat in enumerate(cats, 1):
        if run.status == "cancelled":
            run.log("warn", "Annulé — agents restants non exécutés.")
            break

        run.stage = f"{cat} ({i}/{len(cats)})"
        run.log("info", f"── {cat} — agent {i} sur {len(cats)}")
        before = {p.name for p in RESULTS_DIR.glob("*.json")} if RESULTS_DIR.exists() else set()

        # Un JSONL d'échanges PAR CATÉGORIE (le compteur `n` du runner repart à 1
        # à chaque sous-processus ; un fichier partagé mélangerait les séries).
        ex_path = RESULTS_DIR / f"{run.id}.{cat}.exchanges.jsonl"
        ex_path.parent.mkdir(parents=True, exist_ok=True)
        ex_stop = threading.Event()
        ex_thread = threading.Thread(
            target=_tail_exchanges, args=(run, ex_path, ex_stop), daemon=True
        )
        ex_thread.start()

        try:
            run.proc = subprocess.Popen(
                _build_cmd(run.request, cat) + ["--exchange-log", str(ex_path)],
                cwd=str(ROOT), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                encoding="utf-8", errors="replace", bufsize=1,
            )
            _drain(run, run.proc.stdout)
            code = run.proc.wait()
            new = sorted({p.name for p in RESULTS_DIR.glob("*.json")} - before)
            if code == 0 and new:
                produced.append(new[-1])
                run.log("info", f"{cat} terminé — {new[-1]}")
            else:
                failed.append(cat)
                run.log("warn", f"{cat} en échec (code {code}) — on poursuit")
        except Exception as exc:
            failed.append(cat)
            run.log("critical", f"{cat} : {type(exc).__name__}: {exc}")
        finally:
            # `finally` : même si la catégorie plante, on arrête le suiveur et on
            # capte ses derniers échanges — sinon un thread par catégorie resterait
            # vivant jusqu'à la fin du processus.
            ex_stop.set()
            ex_thread.join(timeout=5)

        # Progression sur les agents, pas sur les étapes internes.
        run.progress = min(99, int(i / len(cats) * 100))

    run.result_files = produced                # type: ignore[attr-defined]
    run.result_file = produced[-1] if produced else None
    run.finished_at = datetime.now(timezone.utc).isoformat()

    if run.status == "cancelled":
        return
    if produced:
        run.status = "completed"
        run.progress = 100
        run.stage = "Terminé"
        run.log("info", f"{len(produced)} audit(s) produit(s)"
                        + (f", {len(failed)} en échec : {', '.join(failed)}" if failed else ""))
    else:
        run.status = "failed"
        run.error = f"Aucun agent n'a abouti ({len(failed)} échec(s))"
        run.log("critical", run.error)


# ══════════════════════════════════════════════════════════════════════
#  Utilitaires
# ══════════════════════════════════════════════════════════════════════

def _identifier(x_api_key: str | None, minimum: str = "operator") -> dict[str, Any]:
    """Identifie l'appelant et vérifie son niveau. Renvoie son identité.

    POURQUOI CE N'EST PLUS UNE COMPARAISON DE CHAÎNE
        Une clé statique unique en variable d'environnement n'a ni rotation, ni
        rôles, ni attribution : impossible de savoir QUI a lancé un audit contre
        un système interne. Pour un outil capable d'attaquer, la traçabilité de
        l'appelant n'est pas optionnelle.

        Les clés vivent maintenant dans le magasin, HACHÉES, avec un nom, un
        rôle et une date d'expiration. Chaque exécution enregistre l'identifiant
        de la clé qui l'a lancée.

    TROIS RÔLES, comparés par NIVEAU et non par égalité de nom :
        viewer    lecture seule
        operator  lance et annule des audits
        admin     gère les clés

    COMPATIBILITÉ : `FRAMEWORK_API_KEY` reste acceptée comme clé d'amorçage de
    niveau admin. La retirer d'un coup casserait toute installation existante —
    et il faut bien une première clé pour en créer d'autres.
    """
    fourni = (x_api_key or "").strip()

    # 1. Clé d'amorçage. `compare_digest` : une comparaison naïve fuit la
    #    longueur du préfixe correct par son temps d'exécution.
    amorce = os.environ.get("FRAMEWORK_API_KEY", "").strip()
    if amorce and fourni and secrets.compare_digest(fourni, amorce):
        return {"id": "bootstrap", "name": "clé d'amorçage", "role": "admin"}

    # 2. Clés du magasin.
    identite = store.verifier_cle(fourni) if fourni else None
    if identite is not None:
        if not store.role_suffisant(identite["role"], minimum):
            raise HTTPException(
                status_code=403,
                detail=f"rôle « {identite['role'] } » insuffisant (requis : {minimum})")
        return identite

    # 3. Aucune clé configurée nulle part : service ouvert, comme avant.
    #    C'est le mode développement — et le refuser empêcherait de démarrer un
    #    service neuf, dont le magasin est forcément vide.
    if not amorce and not store.lister_cles():
        return {"id": "", "name": "anonyme", "role": "admin"}

    raise HTTPException(status_code=401, detail="X-API-Key invalide ou manquant")


def _check_api_key(x_api_key: str | None) -> None:
    """Compatibilité : vérifie sans exploiter l'identité renvoyée."""
    _identifier(x_api_key)


def _read_results() -> list[dict[str, Any]]:
    """Charge tous les résultats d'audit, du plus récent au plus ancien."""
    if not RESULTS_DIR.exists():
        return []
    out: list[dict[str, Any]] = []
    for f in RESULTS_DIR.glob("*.json"):
        if f.name == "sample_audit.json":
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if "agents" not in data:
            continue
        data["_file"] = f.name
        out.append(data)
    out.sort(key=lambda d: str(d.get("timestamp", "")), reverse=True)
    return out


# ══════════════════════════════════════════════════════════════════════
#  Endpoints
# ══════════════════════════════════════════════════════════════════════

@app.get("/health")
def health() -> dict[str, Any]:
    """Santé de l'API et disponibilité des dépendances d'audit."""
    services: dict[str, Any] = {}
    try:
        from sandbox.docker_provider import DockerSandboxProvider
        services["docker_sandbox"] = DockerSandboxProvider().is_available()
    except Exception:
        services["docker_sandbox"] = False
    services["gemini_key"] = bool(os.environ.get("GEMINI_API_KEY", "").strip())
    services["results_dir"] = RESULTS_DIR.exists()
    services["runner"] = RUNNER.exists()
    # Compte les executions de TOUTES les repliques, pas seulement celles de
    # ce processus : c'est la charge reelle du service.
    services["active_runs"] = store.compter_actifs()
    # `build` RÉPOND À LA PREMIÈRE QUESTION D'UN INCIDENT : quelle version tourne ?
    #     `version` reste la version PRODUIT (1.0.0), codée en dur et rarement
    #     touchée ; elle ne dit pas quel commit a été livré. `build` porte le SHA
    #     injecté à la construction de l'image. Sans lui, il fallait un accès
    #     Docker à l'hôte pour lire l'étiquette du conteneur.
    #     « inconnu » = image construite à la main, hors chaîne — et c'est une
    #     information en soi.
    return {
        "status": "ok",
        "version": app.version,
        "build": os.environ.get("AUDIT_BUILD", "inconnu"),
        "services": services,
    }


class NewKeyRequest(BaseModel):
    """Creation d'une cle d'API."""

    name: str = Field(description="A qui ou a quoi cette cle est destinee")
    role: str = Field(default="operator", description="viewer | operator | admin")
    expires_in_days: int | None = Field(
        default=None, description="Expiration. Sans elle, la cle vaut pour toujours.")


@app.post("/keys")
def create_key(req: NewKeyRequest,
               x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    """Cree une cle d'API. Reserve aux administrateurs.

    La cle en clair n'est renvoyee QU'ICI : seule son empreinte est conservee.
    La perdre oblige a en creer une autre — c'est le prix de ne pas stocker un
    secret rejouable.
    """
    _identifier(x_api_key, minimum="admin")
    try:
        ident, cle = store.creer_cle(req.name, req.role, req.expires_in_days)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"id": ident, "key": cle, "role": req.role,
            "avertissement": "Cette cle ne sera plus jamais affichee."}


@app.get("/keys")
def list_keys(x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    """Inventaire des cles, SANS leur empreinte : un inventaire ne divulgue rien."""
    _identifier(x_api_key, minimum="admin")
    return {"keys": store.lister_cles()}


@app.delete("/keys/{key_id}")
def revoke_key(key_id: str,
               x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    """Revoque une cle. C'est ce qui rend la rotation possible : sans revocation,
    une cle distribuee une fois vaut pour toujours."""
    _identifier(x_api_key, minimum="admin")
    if not store.revoquer_cle(key_id):
        raise HTTPException(status_code=404, detail="Cle inconnue ou deja revoquee")
    return {"id": key_id, "revoked": True}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> str:
    """Compteurs au format d'exposition Prometheus.

    POURQUOI CET ENDPOINT EXISTE
        La supervision d'entreprise COLLECTE : elle tire periodiquement un
        `/metrics` en texte. Sans lui, le seul moyen de savoir ce que fait ce
        service est d'ouvrir un tableau de bord tiers optionnel — autant dire
        qu'il n'est pas supervise.

    Ouvert sans authentification, comme `/health` : un collecteur Prometheus ne
    porte pas de cle d'API, et proteger cet endpoint reviendrait a ne rien
    exposer. Les compteurs ne contiennent ni prompt, ni reponse, ni identifiant
    de cible — uniquement des volumes et des durees.
    """
    from judge.metrics import prometheus

    return prometheus()


@app.get("/agents")
def list_agents() -> dict[str, Any]:
    """Catalogue des agents ASI enregistrés dans le workflow."""
    try:
        from workflow.audit_graph import AGENT_REGISTRY
        registry = AGENT_REGISTRY
    except Exception:
        registry = {}
    out = []
    for cat in [f"ASI_{i:02d}" for i in range(1, 11)]:
        cls = registry.get(cat)
        # Le nom lisible est porté par l'agent lui-même (attribut `name`).
        name = getattr(cls, "name", None) or NAMES_FALLBACK.get(cat, cat)
        out.append({"id": cat, "name": name, "available": cls is not None})
    return {"agents": out}


NAMES_FALLBACK = {
    "ASI_01": "Goal Hijacking", "ASI_02": "Tool Misuse",
    "ASI_03": "Identity & Privilege Abuse", "ASI_04": "Agentic Supply Chain",
    "ASI_05": "Unexpected Code Execution", "ASI_06": "Memory & Context Poisoning",
    "ASI_07": "Inter-Agent Communication", "ASI_08": "Cascading Failures",
    "ASI_09": "Trust Exploitation", "ASI_10": "Rogue Agents",
}


@app.get("/audits")
def list_audits() -> dict[str, Any]:
    """Tous les résultats d'audit enregistrés."""
    return {"audits": _read_results()}


@app.get("/audits/{audit_id}")
def get_audit(audit_id: str) -> dict[str, Any]:
    """Un résultat d'audit complet, par identifiant ou nom de fichier."""
    for d in _read_results():
        if d.get("audit_id") == audit_id or d.get("_file") == audit_id:
            return d
    raise HTTPException(status_code=404, detail="Audit introuvable")


@app.get("/audits/{audit_id}/report")
def get_audit_report(audit_id: str) -> Any:
    """Rapport de sécurité HTML complet d'un audit (livrable #8).

    Renvoie directement le HTML : le dashboard n'a qu'à ouvrir cette URL dans un
    onglet, et le rapport est imprimable en PDF depuis le navigateur (le template
    embarque sa feuille de style d'impression).

    Le rapport est régénéré à CHAQUE appel plutôt que mis en cache : les données
    d'audit sont figées sur disque, mais le générateur, lui, évolue — servir un
    HTML périmé masquerait toute correction apportée au rapport.
    """
    from fastapi.responses import HTMLResponse

    for d in _read_results():
        if d.get("audit_id") == audit_id or d.get("_file") == audit_id:
            try:
                from reporting.report_generator import render_html
                return HTMLResponse(render_html(d))
            except Exception as exc:
                raise HTTPException(
                    status_code=500,
                    detail=f"Génération du rapport impossible : {type(exc).__name__}: {exc}",
                ) from exc
    raise HTTPException(status_code=404, detail="Audit introuvable")


@app.post("/audits")
def create_audit(req: AuditRequest, x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    """LANCE un audit réel en tâche de fond et retourne son `run_id`."""
    identite = _identifier(x_api_key, minimum="operator")
    # Avant tout le reste : cet outil ATTAQUE ce qu'on lui désigne.
    valider_cible(req.target_url)
    if not RUNNER.exists():
        raise HTTPException(status_code=500, detail="scripts/run_agent.py introuvable")

    # VALIDER AVANT DE LANCER.
    #     Sans ce controle, `category: "ASI_99"` renvoyait 200 : l'audit demarrait,
    #     occupait un thread et un sous-processus, puis echouait des MINUTES plus
    #     tard sur une faute de frappe. En profil `final`, c'est aussi du quota LLM
    #     depense pour rien. Un refus immediat coute une milliseconde.
    cats = _requested_categories(req)
    if not cats:
        from workflow.audit_graph import AGENT_REGISTRY

        raise HTTPException(
            status_code=400,
            detail=f"Aucune categorie valide. Connues : {sorted(AGENT_REGISTRY)}",
        )

    run_id = f"run-{datetime.now():%Y%m%d%H%M%S}-{uuid.uuid4().hex[:6]}"
    Run(run_id, req, cree_par=identite.get("id", ""))

    # L'API DEPOSE, elle n'execute plus. Un ouvrier separe prendra le travail.
    #
    # POURQUOI CE CHANGEMENT
    #     L'audit vivait dans un `threading.Thread` du serveur web : un audit
    #     d'une heure mourait au moindre redeploiement. Desormais l'API rend la
    #     main immediatement et l'execution survit a son redemarrage.
    #
    # REPLI MONO-PROCESSUS : sans ouvrier deploye, l'API execute elle-meme —
    # c'est le mode developpement, et il evite qu'une installation minimale
    # depose des travaux que personne ne prend jamais.
    if EXECUTE_EN_PROCESSUS:
        travail = store.prendre_run("api-inline")
        if travail is not None:
            threading.Thread(target=_execute, args=(Run.depuis_magasin(travail),),
                             daemon=True).start()
    return {"run_id": run_id, "status": "queued"}


class ReplayRequest(BaseModel):
    """Rejeu des attaques d'un audit passé contre la même cible."""

    audit_id: str = Field(description="audit_id ou nom de fichier de l'audit source")
    target_url: str | None = Field(default=None, description="défaut : la cible de l'audit")
    profile: str = Field(default="final")
    timeout: float = Field(default=180.0, ge=10, le=600)
    only_compromised: bool = Field(
        default=True, description="ne rejouer que les attaques qui avaient percé"
    )
    repeat: int = Field(
        default=3, ge=1, le=10,
        description="envois par attaque — ≥3 requis pour conclure (cible non déterministe)"
    )


@app.post("/replay")
def create_replay(req: ReplayRequest, x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    """Rejoue un audit et retourne un `run_id` suivable comme un audit normal.

    POURQUOI CE MODE
        Deux audits successifs ne lancent pas les mêmes attaques (simulateur
        stochastique), donc leur comparaison mélange progrès réel et hasard. Le
        rejeu renvoie EXACTEMENT les mêmes prompts : tout changement de verdict
        est imputable à la cible. C'est la vérification de correctif.
    """
    _check_api_key(x_api_key)

    source = next(
        (d for d in _read_results()
         if d.get("audit_id") == req.audit_id or d.get("_file") == req.audit_id),
        None,
    )
    if source is None:
        raise HTTPException(status_code=404, detail="Audit source introuvable")

    target = req.target_url or source.get("target_url")
    if not target:
        raise HTTPException(status_code=400, detail="Aucune cible : précisez target_url")
    # Même garde-fou que `/audits` : un rejeu attaque aussi, et il accepte une
    # cible DIFFÉRENTE de celle de l'audit source. L'oublier ici aurait laissé
    # une seconde porte sur le même risque.
    valider_cible(target)

    attacks = [
        a for ag in (source.get("agents") or {}).values()
        for a in (ag.get("attacks") or [])
    ]

    run_id = f"replay-{datetime.now():%Y%m%d%H%M%S}-{uuid.uuid4().hex[:6]}"
    run = Run(run_id, AuditRequest(
        category=next(iter(source.get("agents") or {"ASI_?": {}})),
        target_url=target, profile=req.profile, timeout=req.timeout,
    ))
    run.kind = "replay"                       # type: ignore[attr-defined]
    run.source_audit = source.get("_file")    # type: ignore[attr-defined]
    # Le rejeu dure quelques minutes, pas une heure : il reste en processus.
    # Le sortir n'apporterait rien et ajouterait un type de travail a la file.
    _REJEUX[run_id] = run

    threading.Thread(
        target=_execute_replay,
        args=(run, attacks, target, req.profile, req.timeout,
              req.only_compromised, req.repeat),
        daemon=True,
    ).start()
    return {"run_id": run_id, "status": "queued", "attacks_available": len(attacks)}


def _execute_replay(
    run: Run, attacks: list[dict[str, Any]], target: str,
    profile: str, timeout: float, only_compromised: bool, repeat: int = 3,
) -> None:
    """Exécute un rejeu dans le processus de l'API (pas de sous-processus : le
    volume d'appels est faible et il n'y a rien à orchestrer)."""
    run.status = "running"
    run.stage = "Rejeu des attaques"
    run.log("info", f"Rejeu contre {target} — "
                    f"{'failles uniquement' if only_compromised else 'toutes les attaques'}")
    try:
        from agents.base_agent import build_http_callback
        from judge.llm_config import get_judge_models
        from judge.replay import replay_attacks

        cb = build_http_callback(target, prompt_field="message",
                                 response_field="response", timeout=timeout)
        _, evaluation_model = get_judge_models(profile)

        pool = [a for a in attacks if (a.get("prompt") or "").strip()]
        if only_compromised:
            pool = [a for a in pool if a.get("verdict") == "compromised"]
        total = max(1, len(pool))
        run.log("info", f"{len(pool)} attaque(s) à rejouer")

        LABEL = {
            "non_reproduite": "NON REPRODUITE", "regression": "RÉGRESSION",
            "toujours_vulnerable": "TOUJOURS VULNÉRABLE",
            "toujours_resistant": "toujours résistante", "instable": "INSTABLE — perce par intermittence",
            "non_juge": "non jugée",
        }

        def progress(item: dict[str, Any]) -> None:
            run.progress = min(99, int(item["n"] / total * 100))
            run.add_exchange({
                "n": item["n"], "elapsed_s": item["elapsed_s"],
                "prompt": item["prompt"], "response": item["response"],
                "http_error": item["verdict_after"] == "excluded",
            })
            lvl = "critical" if item["outcome"] in ("regression", "toujours_vulnerable") \
                else "info" if item["outcome"] == "non_reproduite" else "debug"
            run.log(lvl, f"#{item['n']} {item['axis']} — {item['verdict_before']} → "
                         f"{item['verdict_after']} · {LABEL.get(item['outcome'], '')}")

        result = replay_attacks(attacks, cb, evaluation_model,
                                only_compromised=only_compromised,
                                repeat=repeat, on_progress=progress)
        run.replay_result = result            # type: ignore[attr-defined]

        s = result["summary"]
        REPLAYS_DIR.mkdir(parents=True, exist_ok=True)
        out = REPLAYS_DIR / f"{datetime.now():%Y%m%d_%H%M%S}_{run.id}.json"
        out.write_text(json.dumps({
            "replay_id": run.id,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source_audit": getattr(run, "source_audit", None),
            "target_url": target, "profile": profile,
            "only_compromised": only_compromised, "repeat": repeat, **result,
        }, indent=2, ensure_ascii=False), encoding="utf-8")

        run.result_file = out.name
        run.status = "completed"
        run.progress = 100
        run.stage = "Rejeu terminé"
        run.log("info", f"Bilan — {s['corrigee']} corrigée(s), {s['regression']} régression(s), "
                        f"{s['toujours_vulnerable']} toujours vulnérable(s)")
    except Exception as exc:
        run.status = "failed"
        run.error = f"{type(exc).__name__}: {exc}"
        run.log("critical", run.error)
    finally:
        run.finished_at = datetime.now(timezone.utc).isoformat()


@app.get("/replays")
def list_replays() -> dict[str, Any]:
    """Tous les rejeux enregistrés, du plus récent au plus ancien."""
    if not REPLAYS_DIR.exists():
        return {"replays": []}
    out: list[dict[str, Any]] = []
    for f in REPLAYS_DIR.glob("*.json"):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        d["_file"] = f.name
        out.append(d)
    out.sort(key=lambda d: str(d.get("timestamp", "")), reverse=True)
    return {"replays": out}



# ══════════════════════════════════════════════════════════════════════
#  Labs DVAP — catalogue de cibles d'entraînement
# ══════════════════════════════════════════════════════════════════════

DVAP_API = os.environ.get("DVAP_API", "http://localhost:8080/api/v1")

def _open_http(cible, timeout: float):
    """Ouvre une URL en n'autorisant QUE http/https.

    POURQUOI UN HELPER ET PAS UNE VALIDATION PAR APPEL
        Quatre endroits ouvrent une URL ; `DVAP_API` vient de l'environnement,
        donc une valeur `file://` ou `gopher://` y ferait lire un fichier local
        au serveur. Valider dans chaque appelant, c'est garantir qu'un cinquième
        appel oubliera la vérification. Ici la seule façon d'ouvrir une URL est
        de passer par ce point.
    """
    import urllib.request

    url = cible.full_url if isinstance(cible, urllib.request.Request) else cible
    if urllib.parse.urlparse(url).scheme not in ("http", "https"):
        raise ValueError(f"schéma d'URL non autorisé : {url[:60]}")
    # Schéma validé juste au-dessus, et c'est le SEUL point du module qui ouvre
    # une URL : la validation ne peut donc pas être contournée.
    return urllib.request.urlopen(cible, timeout=timeout)  # noqa: S310  # nosec B310



#: Champs de requête/réponse acceptés par les labs, par ordre de préférence.
_PROMPT_FIELDS = ("message", "content", "prompt", "query", "input", "description")
_RESPONSE_FIELDS = ("response", "answer", "output", "result", "message")


def _instance_port(container: str) -> int | None:
    """Port hôte exposé par un conteneur d'instance DVAP."""
    try:
        out = subprocess.run(
            ["docker", "port", container, "8000"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        return int(out.rsplit(":", 1)[-1]) if out else None
    except Exception:
        return None


def _running_instances() -> list[dict[str, Any]]:
    """Conteneurs `dvap-instance-*` actifs, avec leur port et leur lab."""
    try:
        out = subprocess.run(
            ["docker", "ps", "--filter", "name=dvap-instance", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10,
        ).stdout.split()
    except Exception:
        return []

    found = []
    for name in out:
        port = _instance_port(name)
        if not port:
            continue
        info: dict[str, Any] = {"container": name, "port": port, "lab": None}
        # /health expose le slug du lab — plus fiable que de le déduire du nom
        # de conteneur, qui est tronqué par Docker.
        try:
            import urllib.request
            with _open_http(f"http://localhost:{port}/health", 5) as r:
                info["lab"] = json.loads(r.read()).get("lab")
        except Exception:
            pass
        info.update(_discover_endpoint(port))
        found.append(info)
    return found


def _discover_endpoint(port: int) -> dict[str, Any]:
    """Trouve l'endpoint de conversation via l'OpenAPI de l'instance.

    POURQUOI DÉCOUVRIR PLUTÔT QUE CODER EN DUR
        Les 15 labs n'exposent pas le même chemin : `/chat` pour prompt-injection,
        `/api/coding/chat` pour ai-developer-platform, `/api/agent/process-paper`
        pour autonomous-agent. Un mappage figé se périmerait à chaque nouveau lab.
        On lit donc le schéma OpenAPI et on retient le premier POST dont le corps
        ressemble à un message.
    """
    try:
        import urllib.request
        with _open_http(f"http://localhost:{port}/openapi.json", 8) as r:
            spec = json.loads(r.read())
    except Exception:
        return {"path": "/chat", "prompt_field": "message", "response_field": "response"}

    schemas = (spec.get("components") or {}).get("schemas") or {}
    best = None
    for path, ops in (spec.get("paths") or {}).items():
        post = ops.get("post")
        if not post:
            continue
        ref = ((post.get("requestBody") or {}).get("content") or {})             .get("application/json", {}).get("schema", {}).get("$ref", "")
        props = list((schemas.get(ref.rsplit("/", 1)[-1]) or {}).get("properties") or {})
        field = next((f for f in _PROMPT_FIELDS if f in props), None)
        if not field:
            continue
        # Un chemin contenant « chat » est le canal conversationnel évident.
        score = 0 if "chat" in path else 1
        cand = (score, path, field, props)
        if best is None or cand < best:
            best = cand

    if best is None:
        return {"path": "/chat", "prompt_field": "message", "response_field": "response"}

    _, path, field, props = best
    # Champs REQUIS en plus du prompt. Le lab `autonomous-agent` exige `title` :
    # sans lui, la cible répond 422 et TOUS les tests tombent en [HTTP_ERROR].
    extra = [p for p in props if p not in (field, "history")]
    return {"path": path, "prompt_field": field, "response_field": "response",
            "extra_fields": extra,
            "extra_payload": {k: f"audit-{k}" for k in extra} if extra else None}


# --------------------------------------------------------------------------- #
# Gestion des laboratoires d'entraînement — DÉSACTIVÉE PAR DÉFAUT.
# --------------------------------------------------------------------------- #

LAB_MANAGEMENT = os.environ.get("ENABLE_LAB_MANAGEMENT", "0").strip().lower() in (
    "1", "true", "yes", "on")


def _exiger_lab_management() -> None:
    """Refuse les endpoints de laboratoire hors environnement de développement.

    POURQUOI CES ENDPOINTS NE PEUVENT PAS ÊTRE ACTIFS PAR DÉFAUT
        `/dvap/launch` démarre un conteneur sur l'hôte. Une API d'entreprise
        capable de lancer des conteneurs arbitraires est une escalade de
        privilèges déguisée — et ce serait un défaut de sécurité dans un OUTIL
        DE SÉCURITÉ, ce qui n'est pas défendable.

        Ces endpoints existent pour l'atelier d'entraînement DVAP, où le poste
        est jetable. Ils s'activent explicitement par `ENABLE_LAB_MANAGEMENT=1`,
        et jamais sur un environnement partagé.

    Renvoie 404 plutôt que 403 : une fonctionnalité désactivée ne doit pas
    signaler son existence à qui la sonde.
    """
    if not LAB_MANAGEMENT:
        raise HTTPException(
            status_code=404,
            detail="Gestion des laboratoires désactivée (ENABLE_LAB_MANAGEMENT=0)")


@app.get("/dvap/labs")
def dvap_labs() -> dict[str, Any]:
    """Catalogue des labs DVAP + instances déjà lancées.

    Chaque lab en cours d'exécution porte son `target_url` prêt à l'emploi ;
    les autres doivent être lancés (POST /dvap/launch).
    """
    _exiger_lab_management()
    labs: list[dict[str, Any]] = []
    try:
        import urllib.request
        with _open_http(f"{DVAP_API}/labs", 8) as r:
            raw = json.loads(r.read())
        labs = [{"slug": l.get("slug"), "name": l.get("name"),
                 "difficulty": l.get("difficulty"), "category": l.get("category"),
                 "description": (l.get("description") or "")[:220]}
                for l in (raw if isinstance(raw, list) else raw.get("labs", []))]
    except Exception as exc:
        return {"labs": [], "running": [], "error": f"DVAP injoignable sur {DVAP_API} : {exc}"}

    running = _running_instances()
    by_lab = {i["lab"]: i for i in running if i.get("lab")}
    for l in labs:
        inst = by_lab.get(l["slug"])
        l["running"] = inst is not None
        if inst:
            l["port"] = inst["port"]
            l["target_url"] = f"http://localhost:{inst['port']}{inst['path']}"
            l["prompt_field"] = inst["prompt_field"]
            l["response_field"] = inst["response_field"]
            l["extra_payload"] = inst.get("extra_payload")
    return {"labs": labs, "running": running}


class LaunchLabRequest(BaseModel):
    """Démarre une instance de lab DVAP."""
    slug: str


@app.post("/dvap/launch")
def dvap_launch(req: LaunchLabRequest,
                x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    """Lance un lab et retourne son `target_url` découvert.

    L'API DVAP renvoie parfois une erreur 500 alors que le conteneur démarre
    correctement — on ne se fie donc pas à son code retour, on cherche le
    conteneur et son port.
    """
    _exiger_lab_management()
    _check_api_key(x_api_key)
    import urllib.error
    import urllib.request

    token = f"audit-{req.slug[:14]}-{uuid.uuid4().hex[:6]}"
    body = json.dumps({"session_token": token}).encode()
    request = urllib.request.Request(
        f"{DVAP_API}/labs/{req.slug}/launch", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        _open_http(request, 90).read()
    except urllib.error.HTTPError:
        pass                      # 500 fréquent alors que le conteneur démarre
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"DVAP injoignable : {exc}")

    # Le conteneur met quelques secondes à exposer son port.
    for _ in range(24):
        for inst in _running_instances():
            if inst.get("lab") == req.slug:
                return {"slug": req.slug, "port": inst["port"],
                        "target_url": f"http://localhost:{inst['port']}{inst['path']}",
                        "prompt_field": inst["prompt_field"],
                        "response_field": inst["response_field"],
                        "extra_payload": inst.get("extra_payload")}
        time.sleep(5)
    raise HTTPException(status_code=504,
                        detail=f"Lab {req.slug} lancé mais aucune instance joignable")


@app.get("/runs")
def list_runs() -> dict[str, Any]:
    """Toutes les exécutions, en cours ou terminées (sans les journaux)."""
    # Lues dans le MAGASIN : elles survivent au redemarrage, et toutes les
    # repliques voient les memes. Les rejeux, eux, vivent en processus.
    runs = store.lister_runs()
    rejeux = [{k: v for k, v in r.snapshot().items() if k != "logs"}
              for r in _REJEUX.values()]
    return {"runs": sorted(runs + rejeux,
                           key=lambda r: r.get("started_at") or "", reverse=True)}


@app.get("/runs/{run_id}")
def get_run(run_id: str, since: int = 0, since_ex: int = 0) -> dict[str, Any]:
    """Progression d'une exécution.

    `since` / `since_ex` : ne renvoient que les journaux et les échanges NOUVEAUX
    depuis le dernier appel — le dashboard interroge toutes les 1,5 s sans
    retransférer l'historique complet à chaque fois.
    """
    run = _REJEUX.get(run_id)
    snap = run.snapshot(since=since, since_ex=since_ex) if run is not None \
        else store.lire_run(run_id, since, since_ex)
    if snap is None:
        raise HTTPException(status_code=404, detail="Exécution introuvable")
    if run is not None and getattr(run, "replay_result", None) is not None:
        snap["replay"] = run.replay_result           # type: ignore[attr-defined]
    if snap["status"] == "completed" and snap.get("result_file"):
        est_rejeu = run is not None and getattr(run, "kind", "") == "replay"
        path = (REPLAYS_DIR if est_rejeu else RESULTS_DIR) / snap["result_file"]
        if path.exists():
            try:
                snap["result"] = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                pass
    return snap


@app.post("/runs/{run_id}/cancel")
def cancel_run(run_id: str, x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    """Annule une exécution en cours."""
    _check_api_key(x_api_key)
    run = _REJEUX.get(run_id)
    etat = run.snapshot() if run is not None else store.lire_run(run_id)
    if etat is None:
        raise HTTPException(status_code=404, detail="Exécution introuvable")
    if etat["status"] != "running":
        return {"run_id": run_id, "status": etat["status"], "detail": "déjà terminée"}
    if run is None:
        # L'execution tourne peut-etre dans un AUTRE processus : on marque
        # l'intention dans le magasin, l'ouvrier la verra a son prochain
        # battement. Tuer un sous-processus qu'on ne detient pas est impossible.
        store.maj_run(run_id, status="cancelled", stage="Annulation demandée")
        return {"run_id": run_id, "status": "cancelled"}
    run.status = "cancelled"
    if run.proc and run.proc.poll() is None:
        run.proc.terminate()
    return {"run_id": run_id, "status": "cancelled"}
