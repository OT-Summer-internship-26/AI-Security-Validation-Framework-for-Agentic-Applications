"""
asi07_interagent_comms.py — ASI07 : Insecure Inter-Agent Communication.

Couche(s) : comportementale uniquement.
Teste la sécurité des communications entre agents (messages non authentifiés,
injection via un agent intermédiaire, absence de validation des échanges).
"""

from __future__ import annotations

from typing import Any

from agents.base_agent import BaseSecurityAgent, LayerResult


class ASI07InterAgentCommsAgent(BaseSecurityAgent):
    """Agent de test pour ASI07 — Communication inter-agents non sécurisée."""

    asi_category = "ASI_07"
    name = "Insecure Inter-Agent Communication"
    layers = ("behavioral",)

    def get_scenarios(self) -> list[dict[str, Any]]:
        """Scénarios de communication inter-agents (à implémenter)."""
        return []

    def _run_behavioral_layer(self) -> LayerResult:
        """Couche comportementale via DeepTeam (à implémenter)."""
        return LayerResult(layer="behavioral", applicable=False)
