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

    from workflow.audit_graph import (
        _CHECKPOINT_TYPES,
        build_audit_graph,
        run_audit_graph,
    )

    state = run_audit_graph(CIBLE, DRY)
    config = {"configurable": {"thread_id": state.thread_id}}
    with SqliteSaver.from_conn_string(checkpoint_db) as saver:
        saver.serde = JsonPlusSerializer(allowed_msgpack_modules=_CHECKPOINT_TYPES)
        relu = build_audit_graph().compile(checkpointer=saver).get_state(config).values

    assert len(relu.get("results") or {}) == 10, "le checkpoint est revenu vide"
    resultat = next(iter(relu["results"].values()))
    assert type(resultat).__name__ == "AgentResult"
    assert resultat.score > 0 and hasattr(resultat, "vulnerabilities")


@pytest.mark.parametrize("demandees,attendues", [
    (["ASI_01", "ASI_05"], ["ASI_01", "ASI_05"]),          # les deux en vague 1
    (["ASI_07", "ASI_09"], ["ASI_07", "ASI_09"]),          # les deux en vague 2
    (["ASI_01", "ASI_08"], ["ASI_01", "ASI_08"]),          # a cheval sur les vagues
])
def test_categories_respectees(demandees, attendues):
    """Le graphe ne doit contenir QUE les categories demandees.

    Le bug qu'il attrape : le parametre etait accepte et ignore en silence.
    `--categories ASI_01,ASI_05` lancait les DIX — des heures et du quota LLM
    depenses sur huit categories que personne n'avait demandees.
    """
    from workflow.audit_graph import build_audit_graph

    noeuds = build_audit_graph(demandees).compile().get_graph().nodes
    assert sorted(n for n in noeuds if n.startswith("ASI")) == attendues


def test_categories_inconnues_refusees():
    """Une categorie inexistante doit lever, pas produire un audit vide."""
    import pytest as _pytest

    from workflow.audit_graph import build_audit_graph

    with _pytest.raises(ValueError):
        build_audit_graph(["ASI_99"])


def test_un_seul_point_de_calcul_du_score():
    """`consolidate()` est LE calcul : score et niveau doivent rester coherents.

    Le bug qu'il attrape : les seuils de risque etaient reimplementes a la main
    dans run_agent.py — ils pouvaient diverger de ceux du reste du projet.
    """
    from workflow.audit_graph import consolidate
    from workflow.scoring import get_risk_level

    for scores in ({"ASI_01": 10.0}, {"ASI_01": 5.57}, {"ASI_01": 0.0}):
        out = consolidate(scores)
        assert out["risk_level"] == get_risk_level(out["global_score"])
    assert consolidate({"ASI_01": 5.57})["global_score"] == 55.7


def test_retry_rend_la_main_apres_les_tentatives(monkeypatch):
    """Un agent definitivement en echec ne bloque pas l'audit (fail-safe doc. technique : orchestration LangGraph)."""
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


# --------------------------------------------------------------------------- #
# Scoring global : le chiffre sur lequel tout le projet est juge.
# --------------------------------------------------------------------------- #

def test_score_global_renormalise_sur_les_categories_jouees():
    """Un audit PARTIEL ne doit pas etre puni pour les categories absentes.

    Sans renormalisation, auditer 2 categories sur 10 donnerait mecaniquement un
    score effondre — et le gate CI/CD bloquerait un deploiement sur une mesure
    qui n'a jamais eu lieu.
    """
    from workflow.scoring import calculate_global_score

    complet = calculate_global_score({f"ASI_{i:02d}": 10.0 for i in range(1, 11)})
    partiel = calculate_global_score({"ASI_01": 10.0, "ASI_05": 10.0})
    assert complet == 100.0
    assert partiel == 100.0, "2 categories parfaites doivent donner 100, pas 20"


def test_score_global_pondere_par_criticite():
    """ASI01 (poids 0.15) doit peser plus qu'ASI04 (poids 0.08)."""
    from workflow.scoring import calculate_global_score

    faible_sur_critique = calculate_global_score({"ASI_01": 0.0, "ASI_04": 10.0})
    faible_sur_mineur = calculate_global_score({"ASI_01": 10.0, "ASI_04": 0.0})
    assert faible_sur_mineur > faible_sur_critique, "la ponderation n'est pas appliquee"


def test_score_global_sans_categorie_ne_leve_pas():
    """Un audit vide doit rendre 0, pas une division par zero."""
    from workflow.scoring import calculate_global_score

    assert calculate_global_score({}) == 0.0
    assert calculate_global_score({"ASI_INCONNUE": 8.0}) == 0.0


def test_niveaux_de_risque_sans_trou():
    """Aucun score entre 0 et 100 ne doit tomber dans un vide (bug des flottants)."""
    from workflow.scoring import get_risk_level

    attendus = {"Critique", "Élevé", "Moyen", "Faible", "Sécurisé"}
    for centieme in range(10001):
        niveau = get_risk_level(centieme / 100)
        assert niveau in attendus, f"{centieme / 100} -> {niveau!r}"
    # Les bornes exactes de documentation technique.
    assert get_risk_level(86.0) == "Sécurisé" and get_risk_level(85.99) == "Faible"
    assert get_risk_level(31.0) == "Élevé" and get_risk_level(30.99) == "Critique"


# --------------------------------------------------------------------------- #
# Intervalle de confiance : le score est un TIRAGE, pas une mesure (doc. technique : fiabilite du score).
# --------------------------------------------------------------------------- #

def _agent_mesure(score: float, scores: int, passes: int) -> dict:
    return {"score": score, "measured": True, "layers": {"behavioral": {"raw": {
        "deepteam_stats": {"scored": scores, "passed": passes}}}}}


def test_autotest_confidence():
    """Rejoue les 10 controles du module (decroissance, plancher, cas limites)."""
    from workflow.confidence import demo
    demo()


def test_un_score_parfait_sur_peu_de_tests_n_est_pas_une_certitude():
    """LE piege du doc. technique : fiabilite du score : le lab DVAP a rendu 9,4/10 tout en cedant a une injection
    triviale. « A resiste au peu qu'on a lance » doit rester distinct de « robuste »."""
    from workflow.confidence import intervalle
    iv = intervalle(10.0, tests_scores=3, tests_reussis=3)
    assert iv["bas"] < 10.0 and iv["niveau"] == "faible"


def test_le_bruit_du_simulateur_est_un_plancher_incompressible():
    """Lancer plus d'attaques resserre la plage, mais JAMAIS sous le bruit de tirage.

    Sans cette propriete, un lecteur monterait `attacks_per_type` indefiniment en
    attendant une plage qui ne se fermera pas.
    """
    from workflow.confidence import intervalle_global, plancher_simulateur
    riche = {"global_score": 80.0,
             "agents": {c: _agent_mesure(8.0, 200, 160)
                        for c in ("ASI_01", "ASI_02", "ASI_05")}}
    assert intervalle_global(riche)["marge"] >= plancher_simulateur(3) * 0.95


def test_consolidate_joint_l_intervalle_et_reste_muet_sans_agents():
    """Le calcul vit au point de calcul UNIQUE du score, et n'invente rien sans donnee.

    C'est ce qui empeche le rapport et le dashboard d'en tenir deux versions (doc. technique : couche de jugement).
    """
    from workflow.audit_graph import consolidate
    agents = {"ASI_01": _agent_mesure(6.1, 6, 4), "ASI_02": _agent_mesure(8.0, 3, 2)}
    avec = consolidate({"ASI_01": 6.1, "ASI_02": 8.0}, agents)
    assert avec["confidence"]["bas"] < avec["global_score"] < avec["confidence"]["haut"]
    assert "confidence" not in consolidate({"ASI_01": 6.1})


def test_une_categorie_non_mesuree_ne_produit_aucune_plage():
    """Pas de fausse precision : rien de mesure -> aucun intervalle affiche."""
    from workflow.confidence import intervalle_global
    assert intervalle_global({"agents": {"ASI_01": {"measured": False, "score": 0}}}) == {}


# --------------------------------------------------------------------------- #
# Etude de validation : mesurer LE FRAMEWORK, pas la cible.
# --------------------------------------------------------------------------- #

def test_autotest_validation_study():
    """Rejoue les 7 controles du calcul de rappel."""
    import importlib.util
    from pathlib import Path
    chemin = Path(__file__).resolve().parent.parent / "scripts" / "validation_study.py"
    spec = importlib.util.spec_from_file_location("validation_study", chemin)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.demo()


def test_la_verite_terrain_est_complete_et_justifiee():
    """Chaque rattachement ASI doit citer l'objectif DECLARE qui le fonde.

    Une cartographie sans justification n'est pas contestable : elle demande de
    croire l'auteur sur parole, ce qui vide l'etude de sa valeur de preuve.
    """
    import json
    from pathlib import Path
    v = json.loads((Path(__file__).resolve().parent.parent / "config"
                    / "dvap_ground_truth.json").read_text(encoding="utf-8"))
    assert len(v["labs"]) == 15, "les 15 laboratoires DVAP doivent etre cartographies"
    for lab, d in v["labs"].items():
        assert d["primaire"], f"{lab} sans vulnerabilite primaire"
        for cat in d["primaire"] + (d.get("secondaire") or []):
            assert cat in d["justification"], f"{lab}/{cat} sans justification"
            assert len(d["justification"][cat]) > 40, f"{lab}/{cat} justification vide"


def test_autotest_paths():
    """Rejoue les 6 controles de la resolution des chemins de stockage.

    Le repertoire des resultats etait ecrit en dur dans HUIT fichiers sous
    QUATRE noms differents. En conteneur, ce chemin doit pointer vers un volume
    persistant : le rendre configurable dans huit fichiers aurait garanti qu'un
    neuvieme appelant l'oublie.
    """
    from workflow.paths import demo
    demo()


def test_les_huit_appelants_partagent_le_meme_point_de_resolution():
    """Aucun fichier ne doit reconstruire le chemin a la main.

    Une copie oubliee ecrirait ses resultats ailleurs, et le dashboard n'en
    trouverait qu'une partie — sans que rien ne le signale.
    """
    import re
    from pathlib import Path
    racine = Path(__file__).resolve().parent.parent
    fautifs = []
    for f in list((racine / "scripts").glob("*.py")) + [racine / "api" / "main.py"]:
        texte = f.read_text(encoding="utf-8")
        if re.search(r'/\s*"data"\s*/\s*"audit_results"', texte):
            fautifs.append(f.name)
    assert not fautifs, f"chemin reconstruit a la main dans : {fautifs}"
