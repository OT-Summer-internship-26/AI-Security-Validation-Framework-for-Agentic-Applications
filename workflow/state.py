"""
state.py — AuditState : l'état partagé entre les nœuds du StateGraph LangGraph.

POURQUOI CE FICHIER
    LangGraph passe un unique objet d'état d'un nœud à l'autre. `AuditState`
    centralise tout ce dont l'audit a besoin : cible, résultats par catégorie,
    scores, vulnérabilités, statut et horodatage.
"""

from __future__ import annotations

import operator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Annotated, Any


def _merge_dicts(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Fusionne deux dictionnaires d'état — reducer des nœuds PARALLÈLES.

    POURQUOI UN REDUCER
        En exécution séquentielle, chaque nœud lit l'état complet et renvoie une
        version étendue : une simple affectation suffit. Dès que des nœuds tournent
        EN PARALLÈLE, ils partent tous du même état initial et renvoient chacun leur
        écriture ; sans reducer, LangGraph refuse la mise à jour concurrente — et
        sans lui, la dernière écriture écraserait les autres, donc quatre agents sur
        cinq disparaîtraient silencieusement du rapport.
    """
    return {**left, **right}


@dataclass
class AuditState:
    """État partagé d'un audit (voir NOTES.md §7).

    Les champs alimentés par les nœuds parallèles portent un reducer : c'est ce qui
    autorise les deux vagues d'agents à écrire dans le même état sans se piétiner.
    """

    target_url: str
    target_config: dict[str, Any] = field(default_factory=dict)

    # Résultats par catégorie ASI — valeur = AgentResult (agents.base_agent).
    results: Annotated[dict[str, Any], _merge_dicts] = field(default_factory=dict)
    # Scores par catégorie (0-10).
    scores: Annotated[dict[str, float], _merge_dicts] = field(default_factory=dict)
    # Score global /100.
    global_score: float = 0.0
    # Toutes les vulnérabilités trouvées (list[Vulnerability]) — concaténées.
    vulnerabilities: Annotated[list[Any], operator.add] = field(default_factory=list)

    status: str = "running"  # "running" | "completed" | "failed"
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
