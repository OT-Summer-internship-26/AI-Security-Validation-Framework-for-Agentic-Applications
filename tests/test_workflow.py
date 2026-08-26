"""
test_workflow.py — Orchestration LangGraph : parallelisme, merge, reprise.

POURQUOI CE FICHIER
    Chacun des defauts verrouilles ici a REELLEMENT ete livre puis mesure comme
    faux : des noeuds qui renvoyaient l'etat complet et dupliquaient les
    vulnerabilites, une reprise qui rejouait les dix agents parce qu'on lui
    passait un etat neuf, un type absent de l'allowlist qui vidait le checkpoint
    en silence. Aucun ne levait d'exception — ils produisaient un chiffre
    plausible. Seule une reference les revele.

AUCUN RESEAU, AUCUN LLM : profil `dry_run`, checkpoints dans un dossier temporaire.
"""

from __future__ import annotations

import os
import tempfile

import pytest

DRY = {"llm_profile": "dry_run"}
CIBLE = "http://cible-factice/chat"


@pytest.fixture()
def checkpoint_db(monkeypatch):
    """Base de reprise isolee : les tests ne touchent pas celle du projet."""
    db = os.path.join(tempfile.mkdtemp(), "cp.sqlite")
    monkeypatch.setenv("AUDIT_CHECKPOINT_DB", db)
    import workflow.audit_graph as ag

    monkeypatch.setattr(ag, "CHECKPOINT_DB", db)
    return db


def test_graphe_deux_vagues():
    """La vague 2 ne demarre qu'apres TOUTE la vague 1 (barriere de convergence)."""
    from workflow.audit_graph import build_audit_graph

    edges = [(e.source, e.target) for e in build_audit_graph().compile().get_graph().edges]
    vague1 = sorted(t for s, t in edges if s == "__start__")
    assert vague1 == ["ASI_01", "ASI_02", "ASI_03", "ASI_04", "ASI_05"]
    # Chaque agent de la vague 2 depend des CINQ de la vague 1.
    for cat in ("ASI_06", "ASI_10"):
        parents = sorted(s for s, t in edges if t == cat)
        assert parents == vague1, f"{cat} peut demarrer trop tot : {parents}"


def test_graphe_equivaut_au_sequentiel(checkpoint_db):
    """Les deux orchestrations doivent donner le MEME resultat.

    Le bug qu'il attrape : des noeuds renvoyant l'etat complet faisaient
    concatener cinq copies de la vague 1 par le reducer — 35 vulnerabilites au
    lieu de 10, chiffre qui passait pour une reussite.
    """
    from workflow.audit_graph import run_audit, run_audit_graph

    seq = run_audit(CIBLE, DRY)
    par = run_audit_graph(CIBLE, DRY)
    assert len(par.results) == len(seq.results) == 10, "une ecriture a ete perdue"
    assert len(par.vulnerabilities) == len(seq.vulnerabilities), "doublons au merge"
    assert par.global_score == seq.global_score


def test_reprise_ne_rejoue_pas_les_agents_termines(checkpoint_db, monkeypatch):
    """Relancer le meme thread ne doit RE-EXECUTER aucun agent deja termine.

    Le bug qu'il attrape : passer un etat neuf en entree ecrase le checkpoint et
    rejoue tout. La reprise n'existait alors que sur le papier.
    """
    import workflow.audit_graph as ag

    executes: list[str] = []
    vrai = ag._run_one
    monkeypatch.setattr(ag, "_run_one",
                        lambda cat, cb, cfg: (executes.append(cat), vrai(cat, cb, cfg))[1])

    premier = ag.run_audit_graph(CIBLE, DRY)
    assert len(executes) == 10, executes

    executes.clear()
    repris = ag.run_audit_graph(CIBLE, DRY, thread_id=premier.thread_id)
    assert executes == [], f"agents rejoues alors que le checkpoint est complet : {executes}"
    # ... et l'etat repris est COMPLET : un audit repris ne doit pas rendre 0.
    assert len(repris.results) == 10 and repris.global_score == premier.global_score


def test_allowlist_couvre_tous_les_types_de_l_etat(checkpoint_db):
    """Un type absent de l'allowlist vide le checkpoint SANS lever d'erreur.

    C'est ainsi que `AuditState` manquait : la reprise repartait de zero, en
    silence. Ce test relit l'etat depuis le disque et exige des objets typés.
    """
    from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
    from langgraph.checkpoint.sqlite import SqliteSaver

    from workflow.audit_graph import _CHECKPOINT_TYPES, build_audit_graph, run_audit_graph

    state = run_audit_graph(CIBLE, DRY)
    config = {"configurable": {"thread_id": state.thread_id}}
    with SqliteSaver.from_conn_string(checkpoint_db) as saver:
        saver.serde = JsonPlusSerializer(allowed_msgpack_modules=_CHECKPOINT_TYPES)
        relu = build_audit_graph().compile(checkpointer=saver).get_state(config).values

    assert len(relu.get("results") or {}) == 10, "le checkpoint est revenu vide"
    resultat = next(iter(relu["results"].values()))
    assert type(resultat).__name__ == "AgentResult"
    assert resultat.score > 0 and hasattr(resultat, "vulnerabilities")


def test_retry_rend_la_main_apres_les_tentatives(monkeypatch):
    """Un agent definitivement en echec ne bloque pas l'audit (fail-safe §7)."""
    import workflow.audit_graph as ag

    monkeypatch.setattr(ag, "MAX_ATTEMPTS", 2)
    monkeypatch.setattr(ag, "BACKOFF_SECONDS", 0)  # pas d'attente dans un test

    class Casse:
        name = "casse"

        def __init__(self, **kw):
            raise RuntimeError("panne simulee")

    monkeypatch.setitem(ag.AGENT_REGISTRY, "ASI_01", Casse)
    res = ag._run_one("ASI_01", lambda p: "ok", {})
    assert res.status == "failed" and res.score == 0.0
    assert "2 tentatives" in (res.error or "")
