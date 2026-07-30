"""
recommendation_engine.py — Génération de recommandations via LLM.

POURQUOI CE FICHIER
    Au-delà de « voici la faille », on génère une remédiation actionnable et
    contextualisée pour chaque vulnérabilité (contrôle à ajouter, config à
    durcir, référence OWASP correspondante).
"""

from __future__ import annotations

from typing import Any


class RecommendationEngine:
    """Génère des recommandations de remédiation intelligentes via un LLM."""

    def __init__(self, model: str = "gpt-4o-mini") -> None:
        self.model = model

    def generate(self, vulnerability: Any, context: dict[str, Any] | None = None) -> str:
        """Retourne une recommandation textuelle (à implémenter en Phase 2)."""
        raise NotImplementedError("RecommendationEngine.generate() — Phase 2")
