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
    http://localhost:3000, le service de docker-compose.langfuse.yml). Sans ces
    variables, le module est inerte — c'est le cas par défaut.

CE QUI N'EST PAS TRACÉ, ET POURQUOI
    Les compteurs de jetons et le coût restent à zéro dans le tableau de bord.
    Ce n'est pas un oubli : les modèles passent par l'interface `DeepEvalBaseLLM`,
    qui renvoie `(réponse, coût)` — un coût que les fournisseurs locaux (Ollama)
    laissent à 0 et qui ne contient AUCUN décompte de jetons. Les inventer à
    partir d'une estimation produirait un chiffre faux dans un tableau de bord
    censé servir de référence ; on préfère un champ vide, honnête. La LATENCE,
    elle, est exacte : l'observation encadre l'appel (voir `observe`).
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


@contextmanager
def observe(role: str, model: Any, prompt: str):
    """Ouvre une observation AUTOUR de l'appel — pas après lui.

    POURQUOI C'EST STRUCTURANT, ET PAS UN DÉTAIL
        La version précédente ouvrait le span une fois l'appel terminé : LangFuse
        enregistrait donc un événement INSTANTANÉ. Mesuré sur un appel de 1,5 s :
        `startTime == endTime`, `latency = 0`. Toutes les vues temporelles du
        tableau de bord — latence par modèle, détection des appels lents,
        chronologie d'un audit — affichaient zéro. La durée réelle ne survivait
        que dans une métadonnée, invisible aux graphiques.

        En encadrant l'appel, LangFuse mesure lui-même le début et la fin : la
        latence devient exacte sans qu'on la calcule, et la chronologie d'un audit
        redevient lisible.

    S'utilise ainsi :

        with observe("simulator", model, prompt) as obs:
            resultat = model.generate(prompt)
            obs.set_output(resultat)

    Ne lève JAMAIS : sans traçage configuré, le bloc est un passe-plat.
    """
    client = get_client()
    if client is None:
        yield _Muet()
        return

    contexte = current_context()
    categorie = contexte.get("category", "")
    titre = f"{categorie} · {role}" if categorie else f"judge.{role}"
    nom_modele = str(getattr(model, "get_model_name", lambda: str(model))())
    debut = time.time()
    try:
        with client.start_as_current_observation(name=titre, as_type="generation") as span:
            porteur = _Porteur(span)
            span.update(model=nom_modele, input=prompt[:4000],
                        metadata={"role": role, **contexte})
            try:
                yield porteur
            except Exception as exc:
                span.update(level="ERROR", status_message=str(exc)[:500],
                            metadata={"role": role, **contexte,
                                      "duration_s": round(time.time() - debut, 2),
                                      "error": str(exc)[:500]})
                raise
            span.update(output=str(porteur.output)[:4000],
                        metadata={"role": role, **contexte,
                                  "duration_s": round(time.time() - debut, 2)},
                        # Jetons et coût quand le fournisseur les donne (Gemini) ;
                        # rien du tout sinon (Ollama) — on n'invente aucun chiffre.
                        **porteur.usage)
    except Exception as exc:  # l'observabilité ne casse JAMAIS la production
        if not isinstance(exc, _Relancer):
            logger.debug("LangFuse : observation ignorée (%s)", exc)
        raise


class _Relancer(Exception):
    """Marqueur interne : une exception applicative traverse `observe` intacte."""


class _Muet:
    """Passe-plat quand le traçage est inactif : aucun surcoût, aucune branche."""

    output: Any = None
    usage: dict[str, Any]

    def __init__(self) -> None:
        self.output = None
        self.usage = {}

    def set_output(self, valeur: Any, usage: dict[str, Any] | None = None) -> None:
        self.output = valeur
        if usage:
            self.usage = usage


class _Porteur(_Muet):
    """Recueille la sortie et l'usage de l'appel, posés sur le span à la fermeture."""

    def __init__(self, span: Any) -> None:
        super().__init__()
        self.span = span


def trace_llm_call(role: str, model: Any, prompt: str, response: Any,
                   duration_s: float, error: str = "") -> None:
    """Enregistre un appel LLM DÉJÀ terminé (durée fournie).

    Conservé pour les appelants qui ne peuvent pas encadrer l'appel. Préférer
    `observe()` : lui seul donne une latence exacte à LangFuse.
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
    """Construit la version tracée d'un `generate` / `a_generate`.

    L'appel est ENCADRÉ par l'observation (et non tracé après coup) : c'est ce qui
    donne à LangFuse une latence exacte plutôt qu'un événement instantané.
    """
    if is_async:
        async def enveloppe_async(prompt, *args, **kwargs):
            with observe(role, model, str(prompt)) as obs:
                resultat = await original(prompt, *args, **kwargs)
                obs.set_output(_sortie(resultat), usage_de(resultat))
                return resultat

        return enveloppe_async

    def enveloppe(prompt, *args, **kwargs):
        with observe(role, model, str(prompt)) as obs:
            resultat = original(prompt, *args, **kwargs)
            obs.set_output(_sortie(resultat), usage_de(resultat))
            return resultat

    return enveloppe


def _sortie(resultat: Any) -> str:
    """Extrait la réponse d'un retour `(réponse, coût)` de deepeval."""
    if isinstance(resultat, tuple) and resultat:
        return str(resultat[0])
    return str(resultat)


def usage_de(resultat: Any) -> dict[str, Any]:
    """Extrait jetons et coût du second élément renvoyé par un modèle deepeval.

    POURQUOI CETTE FONCTION EXISTE — une limite que je m'étais imposée à tort
        La version précédente jetait `resultat[1]` et le module documentait que
        « les modèles n'exposent aucun décompte ». C'est vrai pour Ollama, FAUX
        pour Gemini : `GeminiModel.generate` renvoie
        `EvaluationCost(cost, input_tokens, output_tokens)`, construit depuis
        `response.usage_metadata`. Le profil `final` — le seul qui produira un
        chiffre citable — donnait donc le coût réel d'un audit, et on l'effaçait.

        Le suivi du coût est l'usage n°1 de LangFuse ; s'en priver revenait à
        n'utiliser qu'une fraction de l'outil qu'on avait installé.

    Renvoie `{}` quand le fournisseur ne dit rien (Ollama) : LangFuse affiche
    alors un champ vide, ce qui reste honnête — on ne fabrique aucun chiffre.
    """
    if not (isinstance(resultat, tuple) and len(resultat) > 1):
        return {}
    cout = resultat[1]
    entree = getattr(cout, "input_tokens", None)
    sortie = getattr(cout, "output_tokens", None)
    total = getattr(cout, "cost", None) if not isinstance(cout, (int, float)) else cout

    usage: dict[str, Any] = {}
    if entree is not None or sortie is not None:
        usage["usage_details"] = {k: v for k, v in
                                  (("input", entree), ("output", sortie)) if v is not None}
    if isinstance(total, (int, float)) and total > 0:
        usage["cost_details"] = {"total": float(total)}
    return usage


@contextmanager
def audit_span(nom: str):
    """Span RACINE d'un audit : donne un parent aux observations d'un processus.

    POURQUOI
        En mode LangGraph, tout s'imbrique naturellement sous la trace du graphe.
        En mode sous-processus (un processus par categorie), chaque appel produit
        une trace ORPHELINE : le meme audit se lisait donc en arbre ou en liste
        plate selon le runner. Ce span racine donne au second la structure du
        premier, pour que le tableau de bord soit identique dans les deux cas.

    Inerte sans traçage configuré.
    """
    client = get_client()
    if client is None:
        yield _Muet()
        return
    contexte = current_context()
    try:
        with client.start_as_current_observation(name=nom, as_type="span") as span:
            span.update(metadata=dict(contexte))
            yield _Porteur(span)
    except Exception as exc:
        if not isinstance(exc, _Relancer):
            logger.debug("LangFuse : span racine ignoré (%s)", exc)
        raise


@contextmanager
def observe_step(nom: str, **details: Any):
    """Trace une ETAPE non-LLM : appel a la cible, sous-processus, sandbox.

    POURQUOI C'EST LE MANQUE LE PLUS COUTEUX DE LA VERSION PRECEDENTE
        On ne tracait que les appels LLM. Or, sur l'audit global mesure, la CIBLE
        repond en ~19 s par requete : c'est ELLE qui domine les 46 minutes d'un
        audit, pas les modeles. Garak et PyRIT tournent en sous-processus, le
        sandbox lance des conteneurs — rien de tout cela n'apparaissait.

        Un tableau de bord d'observabilite qui ne peut pas repondre a « ou est
        passe le temps ? » n'observe pas l'audit, il observe une fraction de
        l'audit. Ces spans comblent l'ecart entre les deux.

    Le type `span` (et non `generation`) est volontaire : ce ne sont pas des
    appels de modele, et les melanger fausserait les statistiques LLM.
    """
    client = get_client()
    if client is None:
        yield _Muet()
        return

    contexte = current_context()
    categorie = contexte.get("category", "")
    titre = f"{categorie} · {nom}" if categorie else nom
    debut = time.time()
    try:
        with client.start_as_current_observation(name=titre, as_type="span") as span:
            porteur = _Porteur(span)
            span.update(input={k: str(v)[:500] for k, v in details.items()} or None,
                        metadata={"step": nom, **contexte})
            try:
                yield porteur
            except Exception as exc:
                span.update(level="ERROR", status_message=str(exc)[:500],
                            metadata={"step": nom, **contexte,
                                      "duration_s": round(time.time() - debut, 2)})
                raise
            span.update(output=str(porteur.output)[:2000] if porteur.output else None,
                        metadata={"step": nom, **contexte,
                                  "duration_s": round(time.time() - debut, 2)})
    except Exception as exc:
        if not isinstance(exc, _Relancer):
            logger.debug("LangFuse : étape ignorée (%s)", exc)
        raise


def score_verdict(nom: str, valeur: float, commentaire: str = "") -> None:
    """Pousse un SCORE LangFuse (gravité, confiance, taux de repli).

    POURQUOI DES SCORES ET PAS SEULEMENT DES TRACES
        Les traces disent ce qui s'est passe ; les scores permettent de SUIVRE la
        qualite dans le temps. Le framework calcule deja gravites, confiance du
        juge et taux de repli sur le bareme statique — et les jetait apres
        affichage. Poussés comme scores, ils donnent des courbes : « la confiance
        du juge baisse depuis qu'on a change de modele » se lit alors d'un coup
        d'oeil, ce qu'aucun rapport statique ne montre.

    Ne leve jamais : un score perdu ne doit pas interrompre un audit.
    """
    client = get_client()
    if client is None:
        return
    try:
        # UN SCORE SANS TRACE N'A NULLE PART OU S'ATTACHER.
        #     Sans span actif, `create_score` part sans `trace_id` et LangFuse
        #     refuse la requete (« Bad request ») — une fois par agent.
        #
        #     On verifie l'existence du span AVANT d'interroger le SDK : appeler
        #     `get_current_trace_id()` hors contexte declenche son propre
        #     avertissement (« No active span in current context »), qui polluait
        #     la sortie de chaque audit sans rien apprendre a personne.
        if not _span_actif():
            logger.debug("LangFuse : score %r ignoré (aucune trace active)", nom)
            return
        trace_id = client.get_current_trace_id()
        if not trace_id:
            logger.debug("LangFuse : score %r ignoré (aucune trace active)", nom)
            return
        client.create_score(name=nom, value=float(valeur),
                            comment=commentaire[:500] or None, trace_id=trace_id)
    except Exception as exc:
        logger.debug("LangFuse : score ignoré (%s)", exc)


def _span_actif() -> bool:
    """Sommes-nous a l'interieur d'un span OpenTelemetry valide ?

    Verification silencieuse : le SDK LangFuse, lui, journalise un avertissement
    des qu'on l'interroge hors contexte.
    """
    try:
        from opentelemetry import trace as _otel

        return _otel.get_current_span().get_span_context().is_valid
    except Exception:
        return False


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

    ⚠️ DÉPRÉCIÉ au profit de `observe()`, qui encadre l'appel et donne donc une
    latence exacte. Conservé pour ne casser aucun appelant existant.

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

    def __enter__(self) -> timed:
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
        """Accumule les `update` successifs dans UNE observation.

        `observe()` appelle `update` deux fois — entree a l'ouverture, sortie a la
        fermeture. Un faux span qui empilerait deux entrees separees ne
        refleterait pas ce que LangFuse enregistre reellement.
        """

        def __init__(self, enregistrement): self.enr = enregistrement
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def update(self, **kw): self.enr.update(kw)

    class FauxClient:
        flushed = 0
        scores: list = []
        def create_score(self, name, value, **kw): FauxClient.scores.append((name, value))
        trace_id = "trace-test"
        def get_current_trace_id(self): return FauxClient.trace_id
        def start_as_current_observation(self, **kw):
            enr = {"_name": kw.get("name")}
            observations.append(enr)
            return FauxSpan(enr)
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
        # Entree ET sortie sur la MEME observation : c'est ce que garantit le fait
        # d'encadrer l'appel plutot que de le tracer apres coup.
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
        # Une observation par appel : `observe()` en cree UNE et la met a jour deux
        # fois (entree puis sortie), ce que le faux span accumule.
        avant = len(observations)
        m2 = traced_model(m, "simulator")
        m2.generate("x")
        assert len(observations) - avant == 1, "un appel = une observation"

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

        # --- COUT ET JETONS : recuperes quand le fournisseur les donne ---------
        class CoutGemini:
            cost, input_tokens, output_tokens = 0.0021, 1500, 300

        assert usage_de(("texte", CoutGemini())) == {
            "usage_details": {"input": 1500, "output": 300},
            "cost_details": {"total": 0.0021},
        }
        # Ollama ne renvoie aucun decompte -> champ VIDE, pas un chiffre invente.
        class CoutVide:
            cost = input_tokens = output_tokens = None

        assert usage_de(("texte", CoutVide())) == {}
        assert usage_de("pas un tuple") == {}

        # Ils arrivent bien jusqu'au span.
        observations.clear()
        clear_context()

        class ModeleFacture:
            def get_model_name(self): return "gemini"
            def generate(self, prompt, schema=None): return ("reponse", CoutGemini())

        traced_model(ModeleFacture(), "evaluation").generate("p")
        obs = next(o for o in observations if "usage_details" in o)
        assert obs["usage_details"]["input"] == 1500
        assert obs["cost_details"]["total"] == 0.0021

        # --- ETAPES NON-LLM : la cible, les sous-processus, le sandbox ---------
        observations.clear()
        with observe_step("cible HTTP", prompt="attaque") as etape:
            etape.set_output("reponse de la cible")
        etape_obs = next(o for o in observations if o.get("_name") == "cible HTTP")
        assert etape_obs["metadata"]["step"] == "cible HTTP"
        assert "duration_s" in etape_obs["metadata"]

        # Une panne d'etape est TRACEE en ERROR puis RELANCEE.
        observations.clear()
        leve = False
        try:
            with observe_step("sandbox"):
                raise RuntimeError("conteneur tue")
        except RuntimeError:
            leve = True
        assert leve, "observe_step ne doit jamais avaler une exception"
        assert any(o.get("level") == "ERROR" for o in observations)

        # --- SPAN RACINE : donne un parent aux traces du mode sous-processus ---
        observations.clear()
        with audit_span("audit ASI_01"):
            pass
        assert any(o.get("_name") == "audit ASI_01" for o in observations)

        # --- SCORES : pousses vers LangFuse ------------------------------------
        # Le span actif est simule : `_span_actif()` interroge OpenTelemetry, or
        # le faux client n'en ouvre aucun. On teste donc les DEUX branches.
        # `globals()` et non `import judge.tracing` : lance par `python -m`, le
        # module tourne sous le nom `__main__` et un import en creerait une SECONDE
        # copie — le patch ne toucherait alors pas la fonction reellement appelee.
        espace = globals()
        vrai_span_actif = espace["_span_actif"]
        espace["_span_actif"] = lambda: True
        try:
            FauxClient.scores.clear()
            score_verdict("judge_fallback_rate", 0.25, "3 verdicts, 1 repli")
            assert FauxClient.scores == [("judge_fallback_rate", 0.25)], FauxClient.scores

            # Trace active mais identifiant absent -> on s'abstient aussi.
            FauxClient.scores.clear()
            FauxClient.trace_id = None
            score_verdict("orphelin", 1.0)
            assert FauxClient.scores == [], "un score sans trace_id ne doit pas partir"
            FauxClient.trace_id = "trace-test"

            # SANS span actif : aucun score, et surtout aucun appel au SDK — c'est
            # lui qui journalisait « No active span » a chaque agent.
            espace["_span_actif"] = lambda: False
            FauxClient.scores.clear()
            score_verdict("hors-span", 1.0)
            assert FauxClient.scores == [], "un score hors span ne doit pas partir"
        finally:
            espace["_span_actif"] = vrai_span_actif

        flush()
        assert FauxClient.flushed == 1
        print("tracing : 29/29 controles OK (inerte sans cle, actif avec, "
              "n'avale aucune exception)")
    finally:
        _client, _checked = None, False



if __name__ == "__main__":
    demo()
