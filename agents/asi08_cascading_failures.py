"""
asi08_cascading_failures.py — ASI08 : Cascading Agent Failures.

Couche(s) : comportementale uniquement.
Teste la propagation en cascade des défaillances (une erreur/attaque sur un
agent contamine-t-elle les autres ? absence de circuit breaker / isolation).
"""

from __future__ import annotations

from typing import Any

from agents.base_agent import BaseSecurityAgent, LayerResult


class ASI08CascadingFailuresAgent(BaseSecurityAgent):
    """Agent de test pour ASI08 — Défaillances en cascade."""

    asi_category = "ASI_08"
    name = "Cascading Agent Failures"
    layers = ("behavioral",)

    def get_scenarios(self) -> list[dict[str, Any]]:
        """Scénarios de défaillance en cascade (à implémenter)."""
        return []

    def _run_behavioral_layer(self) -> LayerResult:
        """Couche comportementale via DeepTeam (à implémenter)."""
        return LayerResult(layer="behavioral", applicable=False)
