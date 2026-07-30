"""
charts.py — Données des graphiques du rapport (radar + barres).

POURQUOI CE FICHIER
    Prépare les structures de données (labels + valeurs) consommées par
    Chart.js dans le template HTML : un radar chart des 10 catégories ASI et
    un bar chart des scores. La logique de rendu est côté client (Chart.js CDN).
"""

from __future__ import annotations

from typing import Any


def build_radar_data(category_scores: dict[str, float]) -> dict[str, Any]:
    """Construit le dataset radar (10 axes ASI) pour Chart.js.

    NOTE : squelette — implémentation en Phase 2.
    """
    raise NotImplementedError("build_radar_data() — Phase 2")


def build_bar_data(category_scores: dict[str, float]) -> dict[str, Any]:
    """Construit le dataset barres (score par catégorie) pour Chart.js."""
    raise NotImplementedError("build_bar_data() — Phase 2")
