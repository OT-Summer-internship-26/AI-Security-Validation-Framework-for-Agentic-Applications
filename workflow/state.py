"""
state.py — AuditState : l'état partagé entre les nœuds du StateGraph LangGraph.

POURQUOI CE FICHIER
    LangGraph passe un unique objet d'état d'un nœud à l'autre. `AuditState`
    centralise tout ce dont l'audit a besoin : cible, résultats par catégorie,
    scores, vulnérabilités, statut et horodatage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class AuditState:
    """État partagé d'un audit (voir NOTES.md §7)."""

    target_url: str
    target_config: dict[str, Any] = field(default_factory=dict)

    # Résultats par catégorie ASI — valeur = AgentResult (agents.base_agent).
    results: dict[str, Any] = field(default_factory=dict)
    # Scores par catégorie (0-10).
    scores: dict[str, float] = field(default_factory=dict)
    # Score global /100.
    global_score: float = 0.0
    # Toutes les vulnérabilités trouvées (list[Vulnerability]).
    vulnerabilities: list[Any] = field(default_factory=list)

    status: str = "running"  # "running" | "completed" | "failed"
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
