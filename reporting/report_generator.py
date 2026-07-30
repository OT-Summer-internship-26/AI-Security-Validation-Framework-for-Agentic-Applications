"""
report_generator.py — Génère le rapport de sécurité (HTML + PDF).

POURQUOI CE FICHIER
    Transforme un AuditState final en rapport lisible : HTML via Jinja2
    (template report_template.html) et PDF via WeasyPrint. Le rapport inclut
    le score global, le détail par catégorie ASI, les vulnérabilités et les
    recommandations.
"""

from __future__ import annotations

import os
from typing import Any

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


def render_html(audit_state: Any, template_name: str = "report_template.html") -> str:
    """Rend le rapport en HTML depuis l'AuditState (à implémenter en Phase 2).

    Utilise Jinja2 avec le template `templates/report_template.html`.
    """
    raise NotImplementedError("render_html() — Phase 2")


def render_pdf(audit_state: Any, output_path: str) -> str:
    """Exporte le rapport en PDF via WeasyPrint (à implémenter en Phase 2)."""
    raise NotImplementedError("render_pdf() — Phase 2")
