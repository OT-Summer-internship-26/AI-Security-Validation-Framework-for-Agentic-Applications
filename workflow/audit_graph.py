"""
audit_graph.py — Orchestration de l'audit : runner multi-agents + score global /100.

`run_audit()` (point d'entrée robuste) instancie chaque agent enregistré, lui fournit
le callback HTTP de la cible, exécute `agent.run()`, consolide les scores par catégorie
(/10) en un score global /100 (workflow.scoring, renormalisé sur les catégories jouées),
agrège toutes les vulnérabilités, et renvoie un `AuditState`.

FAIL-SAFE : un agent qui plante → score 0 pour sa catégorie, les autres continuent.

`build_audit_graph()` construit le StateGraph LangGraph équivalent (nœuds séquentiels →
consolidation) pour l'intégration workflow (§7). Le parallélisme 2-vagues reste une
optimisation Phase 2 (nécessite des reducers d'état concurrents ; le séquentiel est
correct et suffisant, et limite la charge simultanée sur la cible + les LLM-as-Judge).

REGISTRE : seuls les agents PRODUCTION-READY sont enregistrés (ASI01→ASI05).
ASI06→ASI10 seront ajoutés à leur construction (une ligne dans AGENT_REGISTRY).
"""

from __future__ import annotations

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


def _run_one(category: str, target_callback, agent_config: dict[str, Any]) -> Any:
    """Exécute UN agent de façon fail-safe → AgentResult (jamais d'exception propagée)."""
    from agents.base_agent import AgentResult

    cls = AGENT_REGISTRY.get(category)
    if cls is None:
        return AgentResult(asi_category=category, name=category,
                           status="failed", error="catégorie non enregistrée")
    try:
        agent = cls(target_callback=target_callback, config=agent_config)
        return agent.run()
    except Exception as exc:  # fail-safe : un agent ne crashe jamais l'audit global
        print(f"[workflow] {category} a échoué : {exc}")
        return AgentResult(asi_category=category, name=getattr(cls, "name", category),
                           score=0.0, status="failed", error=str(exc))


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

    graph.add_edge(START, cats[0])
    for a, b in zip(cats, cats[1:]):
        graph.add_edge(a, b)
    graph.add_edge(cats[-1], "consolidate")
    graph.add_edge("consolidate", END)
    return graph
