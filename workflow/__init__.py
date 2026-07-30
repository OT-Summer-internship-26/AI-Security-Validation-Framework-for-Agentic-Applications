"""
Package `workflow` — orchestration LangGraph des 10 agents de sécurité.

Contient :
    - state.py        : AuditState (état partagé entre les nœuds)
    - audit_graph.py  : StateGraph (2 vagues parallèles + consolidation)
    - scoring.py      : score global pondéré /100
"""
