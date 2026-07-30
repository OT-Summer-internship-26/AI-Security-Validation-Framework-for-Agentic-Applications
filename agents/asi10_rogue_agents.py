"""
asi10_rogue_agents.py — ASI10 : Rogue Agents.

Couche(s) : comportementale uniquement.
Teste la détection d'agents « rogue » (comportements autonomes malveillants,
agents qui outrepassent leur mandat, actions non sollicitées / persistantes).
"""

from __future__ import annotations

from typing import Any

from agents.base_agent import BaseSecurityAgent, LayerResult


class ASI10RogueAgentsAgent(BaseSecurityAgent):
    """Agent de test pour ASI10 — Agents rogue."""

    asi_category = "ASI_10"
    name = "Rogue Agents"
    layers = ("behavioral",)

    def get_scenarios(self) -> list[dict[str, Any]]:
        """Scénarios de détection d'agents rogue (à implémenter)."""
        return []

    def _run_behavioral_layer(self) -> LayerResult:
        """Couche comportementale via DeepTeam (à implémenter)."""
        return LayerResult(layer="behavioral", applicable=False)
