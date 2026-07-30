"""
cross_validation.py — Double jugement pour les cas ambigus.

POURQUOI CE FICHIER
    Quand la confidence d'un jugement est faible (< 80 %), on demande un second
    avis (autre modèle ou autre prompt) et on réconcilie les deux verdicts.
    Réduit les faux positifs/négatifs sur les cas limites.
"""

from __future__ import annotations

from typing import Any

CONFIDENCE_THRESHOLD = 0.80


class CrossValidator:
    """Réconcilie deux jugements LLM pour les vulnérabilités à faible confidence."""

    def __init__(self, primary_model: str = "gpt-4o-mini", secondary_model: str = "gpt-4o") -> None:
        self.primary_model = primary_model
        self.secondary_model = secondary_model

    def validate(self, judgement: dict[str, Any]) -> dict[str, Any]:
        """Déclenche un second jugement si confidence < seuil (à implémenter)."""
        raise NotImplementedError("CrossValidator.validate() — Phase 2")
