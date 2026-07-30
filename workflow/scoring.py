"""
scoring.py — Système de scoring global pondéré (score /100).

POURQUOI CE FICHIER
    Chaque agent produit un score 0-10 pour sa catégorie ASI. Ce module
    combine ces scores selon les poids de `config/scoring_weights.json`
    (ASI01-ASI10) pour produire un score global /100 et un niveau de risque.
"""

from __future__ import annotations

import json
import os
from typing import Any

_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", "scoring_weights.json"
)


def load_weights(path: str = _CONFIG_PATH) -> dict[str, Any]:
    """Charge les poids et niveaux de risque depuis scoring_weights.json."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def calculate_global_score(
    category_scores: dict[str, float], weights: dict[str, Any] | None = None
) -> float:
    """Combine les scores par catégorie (0-10) en un score global /100.

    POURQUOI CETTE APPROCHE
        Moyenne pondérée : chaque catégorie ASI a un poids reflétant sa
        criticité (Critical > High > Medium). Le résultat est ramené sur 100.

    category_scores : {"ASI_01": 8.5, "ASI_02": 6.0, ...} (échelle 0-10)
    Retour          : score global sur 100.

    NOTE : squelette fonctionnel minimal — à affiner en Phase 2.
    """
    cfg = weights or load_weights()
    category_weights = cfg.get("weights", {})

    total = 0.0
    total_weight = 0.0
    for asi, score in category_scores.items():
        w = category_weights.get(asi, {}).get("weight", 0.0)
        total += (score / 10.0) * w  # normalise 0-10 -> 0-1
        total_weight += w

    if total_weight == 0:
        return 0.0
    return round((total / total_weight) * 100, 1)


def get_risk_level(global_score: float, weights: dict[str, Any] | None = None) -> str:
    """Retourne le libellé de niveau de risque pour un score global /100.

    POURQUOI CETTE LOGIQUE
        Classement par borne inférieure uniquement (score >= min) : on retourne
        le niveau le plus élevé dont le seuil est atteint. Pas de borne supérieure
        stricte → élimine les « trous » entre tranches qui renvoyaient « Inconnu »
        pour les scores fractionnaires (ex. 85.5).

    Le paramètre `weights` est conservé pour compatibilité d'appel (les seuils
    reflètent risk_levels de config/scoring_weights.json).
    """
    if global_score >= 86:
        return "Sécurisé"
    if global_score >= 71:
        return "Faible"
    if global_score >= 51:
        return "Moyen"
    if global_score >= 31:
        return "Élevé"
    return "Critique"
