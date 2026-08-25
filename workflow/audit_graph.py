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
        state.scores[cat] = float(result.score)
        state.vulnerabilities.extend(result.vulnerabilities)
        print(f"[workflow] ✔ {cat} : score={result.score}/10 "
              f"({len(result.vulnerabilities)} vuln., {result.status})")

    state.global_score = calculate_global_score(state.scores)
    state.status = "completed"
    state.completed_at = datetime.now(timezone.utc)
    print(f"[workflow] SCORE GLOBAL : {state.global_score}/100 "
          f"— {get_risk_level(state.global_score)} "
          f"({len(state.vulnerabilities)} vulnérabilités, {len(state.scores)} catégories)")
    return state


def build_audit_graph():
    """Construit un StateGraph LangGraph : un nœud par agent (séquentiel) → consolidation.

    Chaque nœud lit l'état courant et renvoie un état ÉTENDU (merge manuel des dicts) →
    correct sans reducer concurrent (nœuds chaînés, pas parallèles). `run_audit()` reste
    le point d'entrée recommandé ; ce graph existe pour l'intégration workflow (§7).
    """
    from langgraph.graph import END, START, StateGraph

    graph = StateGraph(AuditState)

    def _make_node(cat: str):
        def _node(state: AuditState) -> dict[str, Any]:
            cb = _build_callback(state.target_url, state.target_config)
            res = _run_one(cat, cb, {**state.target_config, "target_url": state.target_url})
            return {
                "results": {**state.results, cat: res},
                "scores": {**state.scores, cat: float(res.score)},
                "vulnerabilities": state.vulnerabilities + list(res.vulnerabilities),
            }
        return _node

    def _consolidate(state: AuditState) -> dict[str, Any]:
        return {
            "global_score": calculate_global_score(state.scores),
            "status": "completed",
            "completed_at": datetime.now(timezone.utc),
        }

    cats = list(AGENT_REGISTRY.keys())
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
    wave1, wave2 = cats[:5], cats[5:]

    for cat in wave1:
        graph.add_edge(START, cat)          # la vague 1 démarre en éventail
    for cat in wave2:
        for previous in wave1:
            graph.add_edge(previous, cat)   # la vague 2 attend TOUTE la vague 1
    for cat in (wave2 or wave1):
        graph.add_edge(cat, "consolidate")  # consolidation après la dernière vague
    graph.add_edge("consolidate", END)
    return graph
