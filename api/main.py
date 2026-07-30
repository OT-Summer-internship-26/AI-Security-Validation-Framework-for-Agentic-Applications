"""
main.py — API REST FastAPI du framework d'audit.

ENDPOINTS (voir NOTES.md §8)
    POST /audit                      → lance un audit, retourne un audit_id
    GET  /audit/{audit_id}           → statut + progression (0-100 %)
    GET  /audit/{audit_id}/report    → rapport final (format=html|pdf)
    GET  /health                     → santé de l'API et des services

AUTHENTIFICATION : clé d'API dans le header `X-API-Key`.

NOTE : squelette Phase 1 — la logique réelle (lancement du workflow LangGraph,
stockage des audits, génération du rapport) sera branchée en Phase 2.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="AI Security Audit Framework",
    description="Audit automatisé OWASP Top 10 for Agentic Applications 2026",
    version="0.1.0-placeholder",
)

# Stockage en mémoire des audits — à remplacer par une vraie persistance (Phase 2).
_AUDITS: dict[str, dict[str, Any]] = {}


class AuditRequest(BaseModel):
    """Corps de requête pour POST /audit."""

    target_url: str
    target_config: dict[str, Any] = {}


def _check_api_key(x_api_key: str | None) -> None:
    """Vérifie la clé d'API (à implémenter réellement en Phase 2)."""
    # TODO Phase 2 : comparer à FRAMEWORK_API_KEY (variable d'environnement).
    if x_api_key is None:
        raise HTTPException(status_code=401, detail="X-API-Key manquant")


@app.post("/audit")
def create_audit(request: AuditRequest, x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    """Lance un nouvel audit et retourne son identifiant.

    NOTE : squelette — ne lance pas encore le workflow LangGraph.
    """
    _check_api_key(x_api_key)
    audit_id = str(uuid.uuid4())
    _AUDITS[audit_id] = {"status": "queued", "progress": 0, "request": request.model_dump()}
    # TODO Phase 2 : déclencher workflow.audit_graph.run_audit(...) en tâche de fond.
    return {"audit_id": audit_id, "status": "queued"}


@app.get("/audit/{audit_id}")
def get_audit_status(audit_id: str, x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    """Retourne le statut et la progression d'un audit."""
    _check_api_key(x_api_key)
    audit = _AUDITS.get(audit_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="Audit introuvable")
    return {"audit_id": audit_id, "status": audit["status"], "progress": audit["progress"]}


@app.get("/audit/{audit_id}/report")
def get_audit_report(
    audit_id: str, format: str = "html", x_api_key: str | None = Header(default=None)
) -> dict[str, Any]:
    """Retourne le rapport final (format=html|pdf).

    NOTE : squelette — la génération réelle sera branchée sur reporting/.
    """
    _check_api_key(x_api_key)
    if audit_id not in _AUDITS:
        raise HTTPException(status_code=404, detail="Audit introuvable")
    # TODO Phase 2 : appeler reporting.report_generator.render_html / render_pdf.
    return {"audit_id": audit_id, "format": format, "detail": "PLACEHOLDER — rapport non généré"}


@app.get("/health")
def health() -> dict[str, Any]:
    """Santé de l'API et des services dépendants."""
    # TODO Phase 2 : vérifier LangFuse, LLM, Docker sandbox.
    return {"status": "ok", "version": app.version, "services": {}}
