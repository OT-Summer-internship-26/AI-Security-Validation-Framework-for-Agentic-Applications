"""
audit_graph.py — Orchestration de l'audit : runner multi-agents + score global /100.

`run_audit()` (point d'entrée robuste) instancie chaque agent enregistré, lui fournit
le callback HTTP de la cible, exécute `agent.run()`, consolide les scores par catégorie
(/10) en un score global /100 (workflow.scoring, renormalisé sur les catégories jouées),
agrège toutes les vulnérabilités, et renvoie un `AuditState`.

FAIL-SAFE : un agent qui plante → score 0 pour sa catégorie, les autres continuent.

`build_audit_graph()` construit le StateGraph LangGraph en DEUX VAGUES PARALLÈLES
(§7) : ASI01-05, puis ASI06-10, puis consolidation. Le merge concurrent repose sur les
reducers d'`AuditState`. `run_audit()` reste le point d'entrée séquentiel recommandé
quand la cible ne supporte pas cinq conversations simultanées.

REGISTRE : seuls les agents PRODUCTION-READY sont enregistrés (ASI01→ASI05).
ASI06→ASI10 seront ajoutés à leur construction (une ligne dans AGENT_REGISTRY).
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any

from agents.asi01_goal_hijacking import ASI01GoalHijackingAgent
from agents.asi02_tool_misuse import ASI02ToolMisuseAgent
from agents.asi03_identity_abuse import ASI03IdentityAbuseAgent
from agents.asi04_supply_chain import ASI04SupplyChainAgent
from agents.asi05_code_execution import ASI05CodeExecutionAgent
from agents.asi06_memory_poisoning import ASI06MemoryPoisoningAgent
from agents.asi07_interagent_comms import ASI07InterAgentCommsAgent
from agents.asi08_cascading_failures import ASI08CascadingFailuresAgent
from agents.asi09_trust_exploitation import ASI09TrustExploitationAgent
from agents.asi10_rogue_agents import ASI10RogueAgentsAgent
from agents.base_agent import build_http_callback
from workflow.scoring import calculate_global_score, get_risk_level
from workflow.state import AuditState

# Catégorie ASI → classe d'agent (extensible : ajouter ASI06→ASI10 ici).
AGENT_REGISTRY: dict[str, type] = {
    "ASI_01": ASI01GoalHijackingAgent,
    "ASI_02": ASI02ToolMisuseAgent,
    "ASI_03": ASI03IdentityAbuseAgent,
    "ASI_04": ASI04SupplyChainAgent,
    "ASI_05": ASI05CodeExecutionAgent,
    "ASI_06": ASI06MemoryPoisoningAgent,
    "ASI_07": ASI07InterAgentCommsAgent,
    "ASI_08": ASI08CascadingFailuresAgent,
    "ASI_09": ASI09TrustExploitationAgent,
    "ASI_10": ASI10RogueAgentsAgent,
}


def _build_callback(target_url: str, cfg: dict[str, Any]):
    """Construit le callback HTTP de la cible depuis la config (format, headers, tools)."""
    return build_http_callback(
        target_url,
        headers=cfg.get("headers"),
        method=cfg.get("method", "POST"),
        prompt_field=cfg.get("prompt_field", "prompt"),
        response_field=cfg.get("response_field", "response"),
        timeout=float(cfg.get("http_timeout", 30.0)),
        extra_payload=cfg.get("extra_payload"),
        tools_field=cfg.get("tools_field"),  # ASI02/03 : signal tool_calls (Q2)
    )


# Reprise sur échec (NOTES.md §7). Deux tentatives, pause doublée entre chaque.
MAX_ATTEMPTS = int(os.environ.get("AUDIT_MAX_ATTEMPTS", "2"))
BACKOFF_SECONDS = float(os.environ.get("AUDIT_BACKOFF_SECONDS", "5"))


def _run_one(category: str, target_callback, agent_config: dict[str, Any]) -> Any:
    """Exécute UN agent de façon fail-safe → AgentResult (jamais d'exception propagée).

    REPRISE SUR ÉCHEC
        Un audit dure des heures et la plupart des échecs sont TRANSITOIRES : cible
        momentanément saturée, quota LLM atteint sur une minute, coupure réseau.
        Abandonner une catégorie entière sur un incident de quelques secondes coûte
        beaucoup plus cher que d'attendre. On retente donc `MAX_ATTEMPTS` fois avec
        un backoff exponentiel — la pause double à chaque essai, pour ne pas
        aggraver une saturation qu'on vient peut-être de provoquer.

        L'échec définitif reste FAIL-SAFE : score 0 pour cette catégorie, l'audit
        continue. Un agent ne peut jamais emporter les autres (§7).
    """
    from agents.base_agent import AgentResult

    cls = AGENT_REGISTRY.get(category)
    if cls is None:
        return AgentResult(asi_category=category, name=category,
                           status="failed", error="catégorie non enregistrée")

    last_error = ""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            agent = cls(target_callback=target_callback, config=agent_config)
            return agent.run()
        except Exception as exc:  # fail-safe : un agent ne crashe jamais l'audit
            last_error = str(exc)
            print(f"[workflow] {category} a échoué (tentative {attempt}/{MAX_ATTEMPTS}) : {exc}")
            if attempt < MAX_ATTEMPTS:
                pause = BACKOFF_SECONDS * (2 ** (attempt - 1))
                print(f"[workflow] nouvelle tentative dans {pause:.0f}s…")
                time.sleep(pause)

    return AgentResult(asi_category=category, name=getattr(cls, "name", category),
                       score=0.0, status="failed",
                       error=f"{last_error} (après {MAX_ATTEMPTS} tentatives)")


def consolidate(scores: dict[str, float]) -> dict[str, Any]:
    """Score global + niveau de risque — LE point de calcul, pour tout le projet.

    POURQUOI CENTRALISER UN APPEL DE DEUX LIGNES
        Il etait ecrit SIX fois (noeud du graphe, run_audit, trois endroits dans le
        runner global, run_agent). Le jour ou la ponderation change — ou simplement
        l'arrondi — cinq copies restent en arriere, et deux surfaces du meme audit
        affichent deux scores differents sans que rien ne le signale. C'est le meme
        defaut que l'agregation des juges ecrite deux fois (§35.3).
    """
    score = calculate_global_score(scores)
    return {"global_score": score, "risk_level": get_risk_level(score)}


def run_audit(target_url: str, target_config: dict[str, Any] | None = None,
              categories: list[str] | None = None) -> AuditState:
    """Lance un audit complet et renvoie l'`AuditState` consolidé (score global /100).

    target_url    : endpoint de l'agent cible.
    target_config : format (prompt_field/response_field), headers, llm_profile,
                    attacks_per_type, source_path/requirements_path (couches statiques),
                    tools_field, etc. Propagé à chaque agent (+ `target_url` injecté).
    categories    : sous-ensemble ASI à jouer (défaut = tous les agents enregistrés).
    """
    cfg = dict(target_config or {})
    cats = categories or list(AGENT_REGISTRY.keys())
    state = AuditState(target_url=target_url, target_config=cfg)

    callback = _build_callback(target_url, cfg)
    # Chaque agent lit sa config (garak a besoin de target_url dedans).
    agent_config = {**cfg, "target_url": target_url}

    for cat in cats:
        print(f"[workflow] ▶ {cat} …")
        result = _run_one(cat, callback, agent_config)
        state.results[cat] = result
        # Un agent dont RIEN n'a pu etre mesure n'entre pas dans le score global :
        # son 0 se lirait « categorie totalement compromise » alors qu'aucune
        # attaque n'a abouti a un verdict (mesure du 2026-08-26 : -5.4 points).
        if getattr(result, "measured", True):
            state.scores[cat] = float(result.score)
        state.vulnerabilities.extend(result.vulnerabilities)
        print(f"[workflow] ✔ {cat} : score={result.score}/10 "
              f"({len(result.vulnerabilities)} vuln., {result.status})")

    state.global_score = consolidate(state.scores)["global_score"]
    state.status = "completed"
    state.completed_at = datetime.now(timezone.utc)
    print(f"[workflow] SCORE GLOBAL : {state.global_score}/100 "
          f"— {get_risk_level(state.global_score)} "
          f"({len(state.vulnerabilities)} vulnérabilités, {len(state.scores)} catégories)")
    return state


def build_audit_graph(categories: list[str] | None = None):
    """Construit le StateGraph LangGraph : DEUX VAGUES PARALLÈLES → consolidation (§7).

    Chaque nœud ne renvoie QUE sa propre écriture ; ce sont les reducers d'`AuditState`
    qui fusionnent les écritures concurrentes. Renvoyer l'état complet fonctionnerait
    aussi, mais masquerait le rôle des reducers — donc la raison pour laquelle des
    nœuds parallèles ne s'écrasent pas entre eux.

    Les nœuds sont PURS : ils exécutent un agent et renvoient leur écriture. Aucun
    effet de bord, aucun crochet — la progression et la persistance sont l'affaire
    de `run_audit_graph()`, qui consomme le flux de mises à jour. Un nœud qui
    écrirait lui-même sur disque devrait se protéger d'un verrou (il tourne en
    parallèle) et deviendrait intestable sans système de fichiers.

    `categories` : sous-ensemble à auditer (défaut : tous les agents enregistrés).
    Le graphe ne contient QUE ces nœuds. L'ancienne version acceptait le paramètre
    et le laissait tomber en silence — `--categories ASI_01,ASI_05` lançait les
    dix, soit des heures et du quota LLM dépensés sur huit catégories que personne
    n'avait demandées, sans un seul avertissement.

    `run_audit()` reste le point d'entrée SÉQUENTIEL, à préférer quand la cible ne
    supporte pas cinq conversations simultanées.
    """
    from langgraph.graph import END, START, StateGraph

    graph = StateGraph(AuditState)

    def _make_node(cat: str):
        def _node(state: AuditState) -> dict[str, Any]:
            cb = _build_callback(state.target_url, state.target_config)
            res = _run_one(cat, cb, {**state.target_config, "target_url": state.target_url})
            # Seulement le DELTA : les reducers d'AuditState fusionnent. Renvoyer
            # `{**state.results, ...}` recopierait l'etat de depart de chaque noeud
            # parallele et rendrait invisible ce qui protege des ecritures perdues.
            return {
                "results": {cat: res},
                # Meme regle que `run_audit` : un agent non mesure sort du score.
                "scores": ({cat: float(res.score)} if getattr(res, "measured", True) else {}),
                "vulnerabilities": list(res.vulnerabilities),
            }
        return _node

    def _consolidate(state: AuditState) -> dict[str, Any]:
        return {
            "global_score": consolidate(state.scores)["global_score"],
            "status": "completed",
            "completed_at": datetime.now(timezone.utc),
        }

    known = list(AGENT_REGISTRY.keys())
    cats = [c for c in known if c in set(categories)] if categories else known
    if not cats:
        raise ValueError(f"aucune categorie connue parmi {categories!r}")
    for cat in cats:
        graph.add_node(cat, _make_node(cat))
    graph.add_node("consolidate", _consolidate)

    # DEUX VAGUES PARALLÈLES (NOTES.md §7), et pas dix nœuds en parallèle.
    #
    # POURQUOI DEUX VAGUES ET NON TOUT D'UN COUP
    #     Le goulot d'étranglement n'est ni le CPU ni le réseau : c'est la CIBLE
    #     (un agent LLM qui répond en ~20 s) et le quota du juge. Lancer dix agents
    #     ensemble sature la cible, fait exploser les timeouts, et les réponses
    #     lentes reviennent en `[HTTP_ERROR]` — donc des tests EXCLUS du scoring.
    #     On y perdrait en couverture ce qu'on gagnerait en horloge. Deux vagues de
    #     cinq gardent la charge tenable tout en divisant la durée.
    #
    #     La barrière entre les deux vagues est implicite : `consolidate` (et la
    #     vague 2) n'attendent pas un ordre, mais la CONVERGENCE des arêtes —
    #     LangGraph ne déclenche un nœud que lorsque tous ses prédécesseurs ont fini.
    #
    #     Le merge concurrent est assuré par les reducers d'`AuditState`
    #     (`workflow/state.py`) : sans eux, cinq écritures simultanées sur `results`
    #     n'en laisseraient qu'une, et quatre agents disparaîtraient du rapport.
    # Les vagues suivent le decoupage du §7 (ASI01-05 / ASI06-10), INTERSECTE avec
    # ce qui est demande. Un sous-ensemble entierement dans la premiere moitie
    # tourne en une seule vague, au lieu d'une vague vide qui bloquerait le graphe.
    first_half = set(known[:5])
    wave1 = [c for c in cats if c in first_half]
    wave2 = [c for c in cats if c not in first_half]
    if not wave1:
        wave1, wave2 = wave2, []

    for cat in wave1:
        graph.add_edge(START, cat)          # la vague 1 démarre en éventail
    for cat in wave2:
        for previous in wave1:
            graph.add_edge(previous, cat)   # la vague 2 attend TOUTE la vague 1
    for cat in (wave2 or wave1):
        graph.add_edge(cat, "consolidate")  # consolidation après la dernière vague
    graph.add_edge("consolidate", END)
    return graph


# ---------------------------------------------------------------------------- #
# Orchestration LangGraph — le chemin d'exécution principal (NOTES.md §1 / §7).
# ---------------------------------------------------------------------------- #

# Types de l'état à autoriser explicitement à la relecture d'un checkpoint.
# LangGraph bloquera bientôt toute désérialisation non déclarée ; sans cette
# liste, un audit repris depuis le disque reviendrait vide sans lever d'erreur.
_CHECKPOINT_TYPES = {
    ("workflow.state", "AuditState"),
    ("agents.base_agent", "AgentResult"),
    ("agents.base_agent", "LayerResult"),
    ("agents.base_agent", "Vulnerability"),
}
# ⚠️ OUBLIER UN SEUL TYPE CASSE LA REPRISE EN SILENCE. Mesuré : sans `AuditState`,
# LangGraph refusait de relire l'état — il ne levait pas d'erreur, il repartait de
# zéro et rejouait les dix agents. Le checkpoint existait pourtant, complet.

# Base de reprise. Un fichier, pas une base serveur : l'audit tourne sur un poste.
CHECKPOINT_DB = os.environ.get(
    "AUDIT_CHECKPOINT_DB",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "checkpoints.sqlite"),
)


def run_audit_graph(
    target_url: str,
    target_config: dict[str, Any] | None = None,
    categories: list[str] | None = None,
    thread_id: str | None = None,
    on_agent_done: Any = None,
) -> AuditState:
    """Exécute l'audit via LangGraph : deux vagues parallèles, reprise sur incident.

    CE QUE CE CHEMIN APPORTE PAR RAPPORT À `run_audit()`
        · **Parallélisme** : cinq agents à la fois au lieu de dix à la suite.
        · **Reprise** : l'état est écrit dans un checkpoint SQLite. Relancer avec
          le même `thread_id` NE REJOUE PAS les agents dont l'écriture a été
          validée. Sur un audit de plusieurs heures, c'est la différence entre
          reprendre et tout recommencer.

          GRANULARITÉ RÉELLE, MESURÉE (ne pas la surestimer) : LangGraph valide
          par SUPER-ÉTAPE, pas par nœud. Un processus tué au milieu d'une vague
          rejoue les agents de CETTE vague ; ceux des vagues déjà validées sont
          sautés. Test de crash : 8 agents ré-exécutés sur 10, deux sautés.
          Les RÉSULTATS, eux, ne sont jamais perdus — le consommateur du flux
          écrit chaque agent terminé sur disque (voir `run_audit_global.py`).
        · **Progression au fil de l'eau** : `on_agent_done(catégorie, résultat)`
          est appelé depuis le CONSOMMATEUR du flux, donc dans un seul thread —
          l'appelant n'a aucun verrou à gérer.

    POURQUOI `stream()` ET PAS UN CROCHET DANS LES NŒUDS
        Un nœud qui notifie lui-même tourne en parallèle des autres : il faudrait
        le protéger d'un verrou, et le graphe ne serait plus testable sans effet de
        bord. `stream(stream_mode="updates")` livre une mise à jour par nœud
        terminé, dans un seul flux : la sérialisation est offerte par LangGraph.

    thread_id : identifiant de reprise. `None` → nouvel audit (horodaté).
    """
    from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
    from langgraph.checkpoint.sqlite import SqliteSaver

    cfg = dict(target_config or {})
    cats = categories or list(AGENT_REGISTRY.keys())
    thread = thread_id or f"audit-{datetime.now(timezone.utc):%Y%m%d%H%M%S}"
    os.makedirs(os.path.dirname(CHECKPOINT_DB), exist_ok=True)

    state = AuditState(target_url=target_url, target_config=cfg)
    from judge.tracing import graph_callbacks

    run_config = {"configurable": {"thread_id": thread},
                  # Un audit complet dépasse largement la limite par défaut (25) :
                  # 10 nœuds + consolidation, plus les reprises éventuelles.
                  "recursion_limit": 50,
                  # Traçage de L'ORCHESTRATION (durée de chaque nœud, ordre des
                  # vagues, reprises) — distinct du traçage des appels LLM. Liste
                  # vide si LangFuse n'est pas configuré.
                  "callbacks": graph_callbacks()}

    with SqliteSaver.from_conn_string(CHECKPOINT_DB) as saver:
        saver.serde = JsonPlusSerializer(allowed_msgpack_modules=_CHECKPOINT_TYPES)
        graph = build_audit_graph(cats).compile(checkpointer=saver)

        # REPRISE : passer `None` en entrée, et NON un état neuf.
        #     Fournir un état d'entrée dit à LangGraph « voici le point de départ » :
        #     il écrase ce qu'il avait mémorisé et rejoue tout. `None` signifie
        #     « continue là où tu en étais ». Mesuré : avec un état neuf, les dix
        #     agents étaient rejoués malgré un checkpoint valide — la reprise
        #     n'existait que sur le papier.
        snapshot = graph.get_state(run_config)
        done = (snapshot.values or {}).get("results") or {}
        resuming = bool(done) or bool(snapshot.next)
        if resuming:
            print(f"[workflow] reprise de « {thread} » — {len(done)} catégorie(s) "
                  f"déjà terminée(s), non rejouée(s)", flush=True)

        print(f"[workflow] LangGraph — 2 vagues parallèles · thread « {thread} »", flush=True)
        for update in graph.stream(None if resuming else state, run_config,
                                   stream_mode="updates"):
            for node, delta in (update or {}).items():
                if node == "consolidate" or not isinstance(delta, dict):
                    continue
                for category, result in (delta.get("results") or {}).items():
                    if on_agent_done is not None:
                        on_agent_done(category, result)

        final = graph.get_state(run_config).values

    merged = AuditState(target_url=target_url, target_config=cfg)
    merged.results = final.get("results", {})
    merged.scores = final.get("scores", {})
    merged.vulnerabilities = final.get("vulnerabilities", [])
    merged.global_score = final.get("global_score", 0.0)
    merged.status = final.get("status", "completed")
    merged.completed_at = final.get("completed_at")
    merged.thread_id = thread
    print(f"[workflow] SCORE GLOBAL : {merged.global_score}/100 — "
          f"{get_risk_level(merged.global_score)} "
          f"({len(merged.vulnerabilities)} vulnérabilités, {len(merged.scores)} catégories)")
    return merged
