"""
tracing.py — Observabilité LangFuse des appels LLM (NOTES.md §2 / §7).

CE QUE ÇA TRACE, ET POURQUOI ÇA MANQUAIT
    Un audit produit des scores, mais rien ne permettait de répondre à « pourquoi
    ce verdict ? » après coup : quel prompt exact est parti au juge, qu'a-t-il
    répondu, combien de temps, combien d'appels. Les enquêtes de cette semaine —
    le juge qui répondait `False` à tout, puis le prompt cassé par son propre
    formatage — ont dû être menées en rejouant des appels à la main. Avec un
    traçage, elles se lisaient dans un tableau de bord.

    Chaque appel des juges devient une observation LangFuse : nom du modèle,
    prompt, réponse, durée, et le rôle (`severity` / `compliance` / `cross_validation`).

PRINCIPE : TOTALEMENT OPTIONNEL, ET SILENCIEUX
    Le traçage ne doit JAMAIS faire échouer un audit. S'il manque une clé, si le
    serveur LangFuse est éteint, si le paquet n'est pas installé — on n'active
    rien et le framework se comporte exactement comme avant. Une observabilité qui
    casse la production est pire que pas d'observabilité.

ACTIVATION
    LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, LANGFUSE_HOST (défaut :
    http://localhost:3000, le service du docker-compose). Sans ces variables, le
    module est inerte — c'est le cas par défaut.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger(__name__)

_client: Any = None
_checked = False

# Contexte courant, attaché à CHAQUE observation.
#
# POURQUOI C'EST INDISPENSABLE — constaté sur le premier run réel
#     52 traces sont arrivées, toutes nommées `judge.simulator`, sans le moindre
#     lien vers l'audit ou la catégorie qui les avait produites. Un tableau de
#     bord de 200 traces anonymes ne répond à aucune des questions pour
#     lesquelles on trace : « quels prompts ASI_07 a-t-il envoyés ? », « pourquoi
#     ce verdict-là ? ». L'observabilité sans contexte n'est qu'un compteur.
#
#     Le SDK 4.14 n'expose ni `session_id` ni `tags` sur une observation : on
#     passe donc par le NOM (lisible d'un coup d'œil) et les MÉTADONNÉES
#     (filtrables dans l'interface).
# DEUX PORTÉES, ET C'EST INDISPENSABLE.
#
#     `_audit` — valeurs communes à tout le processus (identifiant d'audit,
#     profil), posées une fois par le runner.
#
#     `_local` — valeurs propres à un THREAD : la catégorie. En mode LangGraph,
#     cinq agents tournent EN PARALLÈLE dans autant de threads. Avec un seul
#     dictionnaire global, le dernier `set_context` gagnait : les appels d'ASI_01
#     pouvaient être étiquetés ASI_05. Un traçage qui attribue les prompts au
#     mauvais agent est pire qu'un traçage absent — il fait chercher au mauvais
#     endroit. (Attrapé par la suite de tests, pas en production.)
_audit: dict[str, str] = {}
_local = threading.local()


def set_context(audit_id: str = "", category: str = "", profile: str = "") -> None:
    """Déclare à quel audit et à quelle catégorie appartiennent les traces suivantes.

    `audit_id` et `profile` valent pour tout le processus ; `category` ne vaut que
    pour le thread courant — c'est ce qui permet à cinq agents parallèles de ne
    pas se voler leurs étiquettes.

    Les valeurs vides sont ignorées : un appel partiel ne perd rien de ce qui est
    déjà posé.
    """
    for cle, valeur in (("audit_id", audit_id), ("profile", profile)):
        if valeur:
            _audit[cle] = str(valeur)
    if category:
        _local.category = str(category)


def current_context() -> dict[str, str]:
    """Contexte effectif du thread courant : commun + propre au thread."""
    ctx = dict(_audit)
    categorie = getattr(_local, "category", "")
    if categorie:
        ctx["category"] = categorie
    return ctx


def clear_context() -> None:
    """Repart d'un contexte vide (entre deux audits d'un même processus, et entre
    deux tests — sans quoi une catégorie fuit d'un cas à l'autre)."""
    _audit.clear()
    if hasattr(_local, "category"):
        del _local.category


@contextmanager
def audit_context(audit_id: str = "", profile: str = ""):
    """Délimite un audit : le contexte est POSÉ à l'entrée et RESTAURÉ à la sortie.

    POURQUOI UN BLOC ET PAS UN `clear_context()` A APPELER
        `set_context()` est purement additif : une valeur posée y reste pour
        toujours. Un second audit dans le même processus héritait donc de la
        catégorie du dernier agent du premier — mesuré : `audit_id=AUDIT-2` avec
        `category=ASI_01`. Des prompts se retrouvaient étiquetés sur la mauvaise
        catégorie, c'est-à-dire le défaut même que la portée par thread avait
        corrigé entre agents, reproduit entre audits.

        Confier le nettoyage a un `clear_context()` que chaque runner doit penser
        à appeler reproduit la fragilité d'origine : le jour où quelqu'un ajoute
        un troisième runner, la fuite revient. Ici c'est le langage qui garantit
        la restauration — `finally` s'exécute même sur exception ou interruption.

    Le bloc restaure l'état PRÉCÉDENT (et non un état vide) : un audit imbriqué
    dans un autre ne détruit pas le contexte de son parent.
    """
    ancien_audit = dict(_audit)
    ancienne_categorie = getattr(_local, "category", None)
    try:
        _audit.clear()
        if hasattr(_local, "category"):
            del _local.category
        set_context(audit_id=audit_id, profile=profile)
        yield
    finally:
        _audit.clear()
        _audit.update(ancien_audit)
        if ancienne_categorie is None:
            if hasattr(_local, "category"):
                del _local.category
        else:
            _local.category = ancienne_categorie


def get_client() -> Any:
    """Retourne le client LangFuse, ou None si le traçage n'est pas configuré.

    Résolu UNE fois : un audit fait des centaines d'appels, on ne retente pas une
    connexion morte à chacun.
    """
    global _client, _checked
    if _checked:
        return _client
    _checked = True

    public, secret = os.environ.get("LANGFUSE_PUBLIC_KEY"), os.environ.get("LANGFUSE_SECRET_KEY")
    if not public or not secret:
        return None
    try:
        from langfuse import Langfuse

        client = Langfuse(
            public_key=public, secret_key=secret,
            host=os.environ.get("LANGFUSE_HOST", "http://localhost:3000"),
        )
        # `auth_check` évite d'accumuler des appels vers un serveur injoignable
        # pendant des heures d'audit pour les découvrir perdus à la fin.
        if not client.auth_check():
            logger.warning("LangFuse : authentification refusée — traçage désactivé")
            return None
        _client = client
        logger.info("LangFuse : traçage actif")
    except Exception as exc:  # paquet absent, serveur éteint, version incompatible
        logger.warning("LangFuse indisponible (%s) — traçage désactivé", exc)
    return _client


def is_enabled() -> bool:
    """Le traçage est-il actif ? (utile pour l'afficher dans un rapport)"""
    return get_client() is not None


def trace_llm_call(role: str, model: Any, prompt: str, response: Any,
                   duration_s: float, error: str = "") -> None:
    """Enregistre un appel LLM. Ne lève JAMAIS et ne ralentit pas l'audit.

    role : `severity` | `compliance` | `cross_validation` | `pass_analysis`…
    """
    client = get_client()
    if client is None:
        return
    try:
        name = getattr(model, "get_model_name", lambda: str(model))()
        # Le nom porte la catégorie : dans une liste de 200 traces, « ASI_07 ·
        # simulator » se repère instantanément là où « judge.simulator » ne dit rien.
        contexte = current_context()
        categorie = contexte.get("category", "")
        titre = f"{categorie} · {role}" if categorie else f"judge.{role}"
        with client.start_as_current_observation(name=titre, as_type="generation") as obs:
            obs.update(
                model=str(name),
                input=prompt[:4000],
                output=str(response)[:4000],
                metadata={"role": role, "duration_s": round(duration_s, 2),
                          **contexte,
                          **({"error": error} if error else {})},
            )
    except Exception as exc:  # l'observabilité ne casse pas la production
        logger.debug("LangFuse : trace ignorée (%s)", exc)


def flush() -> None:
    """Vide la file d'envoi — à appeler en fin d'audit, sinon les dernières
    observations sont perdues à la sortie du processus."""
    client = get_client()
    if client is not None:
        try:
            client.flush()
        except Exception as exc:
            logger.debug("LangFuse : flush ignoré (%s)", exc)


def traced_model(model: Any, role: str) -> Any:
    """Enveloppe une instance de modèle pour tracer CHACUN de ses appels.

    POURQUOI ICI ET PAS DANS `structured()`
        `structured()` ne voit que les appels des JUGES — une poignée par audit.
        La très grande majorité des appels LLM vient de DeepTeam (100-200 par run,
        cf. §15) et de PyRIT, qui utilisent les mêmes instances de modèles mais ne
        passent jamais par notre code. Tracer au niveau de l'INSTANCE couvre donc
        tout le monde, sans toucher ni DeepTeam ni PyRIT : ils appellent
        `generate()` comme avant, l'observation part toute seule.

        C'est la même règle que partout ailleurs dans ce projet : instrumenter la
        racine commune plutôt que chaque appelant.

    Renvoie le modèle INCHANGÉ si le traçage n'est pas configuré : aucun surcoût,
    aucun risque quand LangFuse est absent.
    """
    if get_client() is None or model is None or getattr(model, "_lf_traced", False):
        return model

    for nom in ("generate", "a_generate"):
        original = getattr(model, nom, None)
        if original is None:
            continue
        setattr(model, nom, _wrap(original, role, model, is_async=nom.startswith("a_")))
    try:
        model._lf_traced = True     # évite un double enveloppement
    except Exception:
        pass
    return model


def _wrap(original: Any, role: str, model: Any, *, is_async: bool) -> Any:
    """Construit la version tracée d'un `generate` / `a_generate`."""
    if is_async:
        async def enveloppe_async(prompt, *args, **kwargs):
            debut = time.time()
            try:
                resultat = await original(prompt, *args, **kwargs)
            except Exception as exc:
                trace_llm_call(role, model, str(prompt), "", time.time() - debut, str(exc))
                raise
            trace_llm_call(role, model, str(prompt), _sortie(resultat), time.time() - debut)
            return resultat

        return enveloppe_async

    def enveloppe(prompt, *args, **kwargs):
        debut = time.time()
        try:
            resultat = original(prompt, *args, **kwargs)
        except Exception as exc:
            trace_llm_call(role, model, str(prompt), "", time.time() - debut, str(exc))
            raise
        trace_llm_call(role, model, str(prompt), _sortie(resultat), time.time() - debut)
        return resultat

    return enveloppe


def _sortie(resultat: Any) -> str:
    """Les modèles deepeval renvoient `(réponse, coût)` — on ne trace que la réponse."""
    if isinstance(resultat, tuple) and resultat:
        return str(resultat[0])
    return str(resultat)


def graph_callbacks() -> list[Any]:
    """Callbacks LangFuse pour tracer L'ORCHESTRATION LangGraph elle-même.

    CE QUE ÇA AJOUTE, ET EN QUOI C'EST DIFFÉRENT
        `traced_model` trace les APPELS LLM : prompts, réponses, durées. Ceci
        trace le GRAPHE : quel nœud a démarré quand, combien de temps a duré
        chaque agent, dans quel ordre les deux vagues se sont enchaînées, et où
        une reprise a repris. Deux vues complémentaires — l'une dit ce qui a été
        demandé aux modèles, l'autre comment l'audit s'est déroulé.

        LangGraph appartient à la famille LangChain : son mécanisme de callbacks
        est donc directement exploitable, sans instrumenter nos nœuds.

    Renvoie une liste VIDE si LangFuse n'est pas configuré — `config={"callbacks": []}`
    est parfaitement valide pour LangGraph, donc l'appelant n'a rien à tester.
    """
    if get_client() is None:
        return []
    try:
        from langfuse.langchain import CallbackHandler

        return [CallbackHandler()]
    except Exception as exc:  # version incompatible, dépendance LangChain absente
        logger.warning("LangFuse : traçage du graphe indisponible (%s)", exc)
        return []


class timed:
    """Chronomètre un appel LLM et le trace à la sortie du bloc.

    Utilisé par `judge.severity_judge.structured()`, donc les TROIS juges en
    bénéficient sans que chacun ait à instrumenter ses appels.

        with timed("severity", model, prompt) as t:
            resp = model.generate(prompt, schema=Schema)
            t.response = resp
    """

    def __init__(self, role: str, model: Any, prompt: str) -> None:
        self.role, self.model, self.prompt = role, model, prompt
        self.response: Any = None
        self._t0 = 0.0

    def __enter__(self) -> "timed":
        self._t0 = time.time()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        trace_llm_call(self.role, self.model, self.prompt, self.response,
                       time.time() - self._t0, error=str(exc) if exc else "")
        return False  # ne masque jamais l'exception d'origine


def demo() -> None:
    """Auto-test : sans clé, le module est inerte et ne lève rien."""
    global _client, _checked
    _client, _checked = None, False
    saved = {k: os.environ.pop(k, None) for k in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY")}
    try:
        assert get_client() is None and is_enabled() is False
        # Aucune de ces opérations ne doit lever, ni ralentir, sans traçage actif.
        trace_llm_call("severity", object(), "prompt", "reponse", 0.1)
        flush()
        with timed("severity", object(), "p") as t:
            t.response = "ok"
        # Le contexte ne doit pas AVALER une exception applicative.
        leve = False
        try:
            with timed("severity", object(), "p"):
                raise ValueError("erreur applicative")
        except ValueError:
            leve = True
        assert leve, "le traceur ne doit jamais masquer une exception"
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
        _client, _checked = None, False

        # ---- Chemin ACTIF : jusqu'ici seul le cas « pas de cle » etait verifie ---- #
    observations: list[dict] = []

    class FauxSpan:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def update(self, **kw): observations.append(kw)

    class FauxClient:
        flushed = 0
        def start_as_current_observation(self, **kw):
            observations.append({"_name": kw.get("name")})
            return FauxSpan()
        def flush(self): FauxClient.flushed += 1

    _client, _checked = FauxClient(), True
    clear_context()          # un test precedent a pu laisser une categorie
    try:
        # Un modele deepeval renvoie (reponse, cout) : on ne trace que la reponse.
        class Modele:
            def get_model_name(self): return "modele-test"
            def generate(self, prompt, schema=None): return ("reponse", 0.0)

        m = traced_model(Modele(), "simulator")
        assert m.generate("attaque") == ("reponse", 0.0), "l'enveloppe ne doit RIEN changer au retour"
        noms = [o.get("_name") for o in observations if o.get("_name")]
        assert noms == ["judge.simulator"], noms
        trace = next(o for o in observations if "input" in o)
        assert trace["input"] == "attaque" and trace["output"] == "reponse"
        assert trace["model"] == "modele-test"

        # Une exception du modele est TRACEE puis RELANCEE (jamais avalee).
        class Casse:
            def get_model_name(self): return "casse"
            def generate(self, prompt, schema=None): raise RuntimeError("panne")

        c = traced_model(Casse(), "evaluation")
        leve = False
        try:
            c.generate("p")
        except RuntimeError:
            leve = True
        assert leve, "le tracage ne doit pas masquer une panne du modele"
        assert any("panne" in str(o.get("metadata", {})) for o in observations)

        # Double enveloppement impossible (sinon chaque appel serait trace N fois).
        avant = len(observations)
        m2 = traced_model(m, "simulator")
        m2.generate("x")
        assert len(observations) - avant == 2, "un appel = une observation"

        # Le CONTEXTE doit atteindre le nom ET les metadonnees : sans lui, une
        # trace ne dit pas a quel audit ni a quelle categorie elle appartient.
        observations.clear()
        set_context(audit_id="ASI_07-20260827", category="ASI_07", profile="ollama")
        traced_model(Modele(), "simulator").generate("attaque contextualisee")
        assert [o.get("_name") for o in observations if o.get("_name")] == ["ASI_07 · simulator"]
        meta = next(o for o in observations if "metadata" in o)["metadata"]
        assert meta["category"] == "ASI_07" and meta["audit_id"] == "ASI_07-20260827"
        assert meta["profile"] == "ollama" and meta["role"] == "simulator"

        # PARALLELISME : deux threads, deux categories. Sans portee par thread, le
        # dernier `set_context` gagnait et les appels d'un agent portaient
        # l'etiquette d'un autre — bug reel du mode LangGraph (5 agents en vagues).
        import threading

        observations.clear()
        clear_context()
        set_context(audit_id="GLOBAL-1", profile="ollama")
        vus: dict[str, str] = {}

        def agent(cat):
            set_context(category=cat)
            traced_model(Modele(), "simulator").generate(f"attaque {cat}")
            vus[cat] = current_context().get("category", "")

        fils = [threading.Thread(target=agent, args=(c,)) for c in ("ASI_01", "ASI_05")]
        for f in fils:
            f.start()
        for f in fils:
            f.join()
        assert vus == {"ASI_01": "ASI_01", "ASI_05": "ASI_05"}, vus
        noms = sorted(o["_name"] for o in observations if o.get("_name"))
        assert noms == ["ASI_01 · simulator", "ASI_05 · simulator"], noms
        # L'audit reste commun aux deux threads.
        for o in observations:
            if "metadata" in o:
                assert o["metadata"]["audit_id"] == "GLOBAL-1"

        clear_context()
        set_context(audit_id="ASI_07-20260827", category="ASI_07", profile="ollama")
        observations.clear()
        traced_model(Modele(), "simulator").generate("x")
        meta = next(o for o in observations if "metadata" in o)["metadata"]
        assert meta["category"] == "ASI_07"

        # Un appel partiel n'ecrase pas ce qui est deja pose.
        set_context(category="ASI_09")
        observations.clear()
        traced_model(Modele(), "evaluation").generate("x")
        meta = next(o for o in observations if "metadata" in o)["metadata"]
        assert meta["category"] == "ASI_09" and meta["audit_id"] == "ASI_07-20260827"
        # PORTEE D'AUDIT : aucune fuite d'un audit vers le suivant, et la
        # restauration tient meme si le bloc part en exception.
        clear_context()
        with audit_context(audit_id="AUDIT-1", profile="ollama"):
            set_context(category="ASI_01")
            assert current_context()["category"] == "ASI_01"
        with audit_context(audit_id="AUDIT-2", profile="final"):
            ctx = current_context()
            assert ctx["audit_id"] == "AUDIT-2" and "category" not in ctx, ctx
        assert current_context() == {}, "le contexte doit etre rendu a son etat d'origine"

        # Une exception dans le bloc ne doit pas laisser le contexte pollue.
        try:
            with audit_context(audit_id="AUDIT-3"):
                set_context(category="ASI_09")
                raise RuntimeError("panne en plein audit")
        except RuntimeError:
            pass
        assert current_context() == {}, "le `finally` doit restaurer meme sur exception"

        # Un audit imbrique restitue le contexte de son parent (et ne le detruit pas).
        with audit_context(audit_id="PARENT"):
            set_context(category="ASI_02")
            with audit_context(audit_id="ENFANT"):
                assert current_context()["audit_id"] == "ENFANT"
            assert current_context() == {"audit_id": "PARENT", "category": "ASI_02"}
        clear_context()

        flush()
        assert FauxClient.flushed == 1
        print("tracing : 19/19 controles OK (inerte sans cle, actif avec, "
              "n'avale aucune exception)")
    finally:
        _client, _checked = None, False



if __name__ == "__main__":
    demo()
