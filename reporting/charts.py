"""
charts.py — Prépare les données des graphiques du rapport (Chart.js).

POURQUOI CE FICHIER
    Le rendu est fait côté client par Chart.js, mais les DONNÉES sont préparées
    ici, en Python : le template reste déclaratif et la logique (ordre des
    catégories, catégories non auditées, couleurs par gravité) est testable.

RÈGLE APPLIQUÉE PARTOUT — une catégorie NON AUDITÉE vaut `None`, jamais 0.
    Un 0 sur le radar se lit « cette catégorie est catastrophique ». Une
    catégorie non jouée doit laisser un TROU, pas un point au centre. C'est la
    même règle que le socle applique aux axes exclus : jamais de chiffre inventé.
"""

from __future__ import annotations

from typing import Any

#: Les 10 catégories OWASP ASI, dans l'ordre du référentiel.
ASI_ORDER: list[tuple[str, str]] = [
    ("ASI_01", "Goal Hijacking"),
    ("ASI_02", "Tool Misuse"),
    ("ASI_03", "Identity Abuse"),
    ("ASI_04", "Supply Chain"),
    ("ASI_05", "Code Execution"),
    ("ASI_06", "Memory Poisoning"),
    ("ASI_07", "Inter-Agent Comms"),
    ("ASI_08", "Cascading Failures"),
    ("ASI_09", "Trust Exploitation"),
    ("ASI_10", "Rogue Agents"),
]

#: Gravités, de la plus forte à la plus faible, avec leur couleur de rapport.
SEVERITY_ORDER: list[str] = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_COLOR: dict[str, str] = {
    "Critical": "#b4232c",
    "High": "#d9772b",
    "Medium": "#c9a227",
    "Low": "#3f7d54",
    "Info": "#5b6b7c",
}

#: Axes comportementaux et ce que chacun mesure réellement.
AXIS_LABEL: dict[str, str] = {
    "deepteam": "DeepTeam",
    "pyrit": "PyRIT",
    "garak": "Garak",
    "microsoft": "Microsoft Arcanum",
    "static": "Analyse statique",
    "dynamic": "Sandbox dynamique",
}


def build_radar_data(category_scores: dict[str, float | None]) -> dict[str, Any]:
    """Dataset radar des 10 catégories ASI (score /10).

    `category_scores` : {"ASI_01": 5.52, ...}. Une catégorie absente ou à `None`
    produit un trou dans le tracé (Chart.js gère `null` nativement) plutôt qu'un
    zéro trompeur.
    """
    return {
        "labels": [f"{code.replace('_', '')} · {name}" for code, name in ASI_ORDER],
        "values": [category_scores.get(code) for code, _ in ASI_ORDER],
        "audited": [category_scores.get(code) is not None for code, _ in ASI_ORDER],
    }


def build_severity_data(vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
    """Répartition des vulnérabilités par gravité, ordonnée du plus grave au moins."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for v in vulnerabilities:
        sev = str(v.get("severity") or "Info")
        counts[sev] = counts.get(sev, 0) + 1
    return {
        "labels": SEVERITY_ORDER,
        "values": [counts[s] for s in SEVERITY_ORDER],
        "colors": [SEVERITY_COLOR[s] for s in SEVERITY_ORDER],
        "counts": counts,
        "total": sum(counts.values()),
    }


def build_axis_data(per_category_axes: dict[str, dict[str, float | None]]) -> dict[str, Any]:
    """Dataset barres : score de chaque AXE, par catégorie auditée.

    Sert la section qui montre D'OÙ vient le score — un même score global peut
    recouvrir des profils très différents selon l'axe qui a cédé.
    """
    axes = [a for a in AXIS_LABEL if any(a in v for v in per_category_axes.values())]
    return {
        "categories": list(per_category_axes),
        "axes": [AXIS_LABEL[a] for a in axes],
        "series": [
            {"axis": AXIS_LABEL[a],
             "values": [per_category_axes[c].get(a) for c in per_category_axes]}
            for a in axes
        ],
    }
