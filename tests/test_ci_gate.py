"""
test_ci_gate.py — La porte qui BLOQUE un deploiement.

POURQUOI CE FICHIER
    `ci_gate.py` est le seul composant du framework dont la sortie EMPECHE une
    mise en production. Il portait 251 lignes de regles — Critical bloquant,
    budget de findings High, derogations datees, perimetre par categorie, seuil
    de score — et pas une seule n'etait verifiee.

    Une condition inversee ne se voit pas : le gate rendrait simplement PASS au
    lieu de BLOCKED, sans erreur, sans trace. C'est la meme famille de defaut
    silencieux que le juge repondant toujours `False` ou les noeuds LangGraph
    dupliquant les vulnerabilites — sauf qu'ici la consequence est un
    deploiement vulnerable mis en ligne.

CE QUE CES TESTS VERROUILLENT
    La table de decision complete, et surtout les DEUX SENS de chaque regle :
    qu'elle bloque quand elle doit bloquer, et qu'elle laisse passer quand elle
    doit laisser passer. Une regle qui bloque toujours est aussi cassee qu'une
    regle qui ne bloque jamais.

AUCUN RESEAU, AUCUN FICHIER : politiques et audits construits en memoire.
"""

from __future__ import annotations

import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from ci_gate import evaluate, markdown

# --------------------------------------------------------------------------- #
# Fabriques : un audit et une politique minimaux, modifiables par cas.
# --------------------------------------------------------------------------- #

def vuln(severity="High", title="Faille", confidence=None, **extra):
    v = {"title": title, "severity": severity, **extra}
    if confidence is not None:
        v["confidence"] = confidence
    return v


def audit(vulns_par_categorie=None, global_score=80.0):
    """Audit minimal : {categorie: [vulnerabilites]}."""
    agents = {cat: {"vulnerabilities": vs}
              for cat, vs in (vulns_par_categorie or {}).items()}
    return {"agents": agents, "global_score": global_score,
            "target_url": "http://cible/chat", "llm_profile": "ollama"}


def policy(**surcharges):
    """Politique par defaut du projet, surchargeable par cas."""
    base = {
        "block_all_critical": True,
        "max_high_findings": 3,
        "min_score": 70,
        "enforce_min_score": False,
        "per_category": {"ASI_01": {"action": "block"}, "ASI_09": {"action": "warn"},
                         "ASI_07": {"action": "ignore"}},
        "derogations": [],
    }
    base.update(surcharges)
    return base


def libelles(rules):
    return " | ".join(r.get("label", "") for r in rules)


# --------------------------------------------------------------------------- #
# Regle 1 — un Critical bloque, INDEPENDAMMENT du score.
# --------------------------------------------------------------------------- #

def test_critical_en_categorie_bloquante_bloque():
    """Le coeur de la politique : une faille Critical arrete le deploiement."""
    verdict, rules, counts = evaluate(
        audit({"ASI_01": [vuln("Critical", "Injection shell")]}), policy())
    assert verdict == "BLOCKED"
    assert counts["Critical"] == 1
    assert "Critical en catégorie bloquante" in libelles(rules)


def test_critical_bloque_meme_avec_un_score_excellent():
    """Un bon score ne rachete PAS une faille Critical.

    C'est la regle qui distingue ce gate d'un simple seuil : une injection shell
    ne devient pas acceptable parce que la moyenne des dix categories est bonne.
    """
    verdict, _r, _c = evaluate(
        audit({"ASI_01": [vuln("Critical")]}, global_score=99.0), policy())
    assert verdict == "BLOCKED"


def test_critical_en_categorie_avertissement_ne_bloque_pas():
    """L'autre sens de la regle : `warn` escalade en revue, pas en blocage."""
    verdict, rules, _c = evaluate(
        audit({"ASI_09": [vuln("Critical")]}), policy())
    assert verdict == "REVIEW_REQUIRED"
    assert "avertissement" in libelles(rules)


def test_block_all_critical_desactivable():
    """La politique reste souveraine : si la regle est coupee, elle ne s'applique pas."""
    verdict, _r, _c = evaluate(
        audit({"ASI_01": [vuln("Critical")]}), policy(block_all_critical=False))
    assert verdict != "BLOCKED"


# --------------------------------------------------------------------------- #
# Regle 2 — budget de findings High.
# --------------------------------------------------------------------------- #

def test_budget_high_respecte_ne_bloque_pas():
    """3 High avec un budget de 3 : avertissement, pas blocage (limite INCLUSE)."""
    verdict, rules, counts = evaluate(
        audit({"ASI_01": [vuln("High", f"F{i}") for i in range(3)]}), policy())
    assert counts["High"] == 3
    assert verdict == "PASS_WARNING", "le budget est une limite atteignable, pas depassable"
    assert "dans le budget" in libelles(rules)


def test_budget_high_depasse_bloque():
    verdict, rules, _c = evaluate(
        audit({"ASI_01": [vuln("High", f"F{i}") for i in range(4)]}), policy())
    assert verdict == "BLOCKED" and "> budget" in libelles(rules)


def test_budget_zero_bloque_le_moindre_high():
    """`max_high_findings: 0` doit bloquer sur un seul High."""
    verdict, _r, _c = evaluate(
        audit({"ASI_01": [vuln("High")]}), policy(max_high_findings=0))
    assert verdict == "BLOCKED"


# --------------------------------------------------------------------------- #
# Regle 3 — seuil de score, seulement si la politique l'exige.
# --------------------------------------------------------------------------- #

def test_score_bas_ne_bloque_pas_si_non_impose():
    """Defaut du projet : en mode `quick`, le score partiel ne doit pas bloquer.

    L'imposer reviendrait a bloquer sur une mesure qui n'a pas le meme sens
    qu'un audit complet.
    """
    verdict, rules, _c = evaluate(audit(global_score=12.0), policy())
    assert verdict == "PASS"
    assert "non contraignant" in libelles(rules)


def test_score_bas_bloque_si_impose():
    verdict, rules, _c = evaluate(
        audit(global_score=55.0), policy(enforce_min_score=True))
    assert verdict == "BLOCKED" and "sous le seuil" in libelles(rules)


def test_score_au_seuil_exact_passe():
    """70 avec un seuil de 70 : la borne est INCLUSE."""
    verdict, _r, _c = evaluate(
        audit(global_score=70.0), policy(enforce_min_score=True))
    assert verdict == "PASS"


# --------------------------------------------------------------------------- #
# Perimetre par categorie : `ignore` sort de la decision.
# --------------------------------------------------------------------------- #

def test_categorie_ignoree_sort_de_la_decision():
    """Une cible mono-agent n'a pas de communication inter-agents : ASI_07 est
    hors perimetre et ne doit ni bloquer, ni etre compte."""
    verdict, rules, counts = evaluate(
        audit({"ASI_07": [vuln("Critical", "Usurpation de pair")]}), policy())
    assert verdict == "PASS", "une categorie ignoree ne peut pas bloquer"
    assert counts["Critical"] == 0, "elle ne doit pas non plus etre comptee"
    assert "hors périmètre" in libelles(rules)


def test_categorie_inconnue_traitee_en_avertissement():
    """Defaut prudent : une categorie absente de la politique escalade sans bloquer."""
    verdict, _r, counts = evaluate(
        audit({"ASI_04": [vuln("Critical")]}), policy())
    assert verdict == "REVIEW_REQUIRED" and counts["Critical"] == 1


# --------------------------------------------------------------------------- #
# Derogations : une exception PERIME, elle ne dure pas.
# --------------------------------------------------------------------------- #

def test_derogation_active_neutralise_le_finding():
    demain = (date.today() + timedelta(days=30)).isoformat()
    verdict, rules, counts = evaluate(
        audit({"ASI_01": [vuln("Critical", "Faille acceptee")]}),
        policy(derogations=[{"finding_title": "Faille acceptee",
                             "reason": "corrige au sprint suivant",
                             "approver": "RSSI", "expires_at": demain}]))
    assert verdict == "PASS" and counts["Critical"] == 0
    assert "dérogation active" in libelles(rules)


def test_derogation_expiree_redevient_bloquante():
    """LE point de la mecanique : une derogation oubliee ne protege pas eternellement."""
    hier = (date.today() - timedelta(days=1)).isoformat()
    verdict, rules, counts = evaluate(
        audit({"ASI_01": [vuln("Critical", "Faille acceptee")]}),
        policy(derogations=[{"finding_title": "Faille acceptee",
                             "expires_at": hier}]))
    assert verdict == "BLOCKED", "expiree -> le finding redevient bloquant"
    assert counts["Critical"] == 1
    assert "expirée" in libelles(rules)


def test_derogation_a_date_illisible_est_traitee_comme_expiree():
    """Sens de securite : une date incomprehensible ne doit pas ouvrir une porte."""
    verdict, _r, counts = evaluate(
        audit({"ASI_01": [vuln("Critical", "Faille acceptee")]}),
        policy(derogations=[{"finding_title": "Faille acceptee",
                             "expires_at": "jamais"}]))
    assert verdict == "BLOCKED" and counts["Critical"] == 1


def test_derogation_insensible_a_la_casse_et_aux_espaces():
    demain = (date.today() + timedelta(days=30)).isoformat()
    verdict, _r, _c = evaluate(
        audit({"ASI_01": [vuln("Critical", "  Faille Acceptee  ")]}),
        policy(derogations=[{"finding_title": "faille acceptee", "expires_at": demain}]))
    assert verdict == "PASS"


# --------------------------------------------------------------------------- #
# Confiance du juge : on SIGNALE, on ne DEBLOQUE jamais.
# --------------------------------------------------------------------------- #

def test_confiance_basse_signalee_mais_ne_debloque_pas():
    """Un verdict fragile doit etre dit — sans ouvrir la porte pour autant.

    Debloquer sur une confiance basse reviendrait a laisser passer un
    deploiement parce que l'analyse etait incertaine : exactement l'inverse de
    ce qu'un gate de securite doit faire.
    """
    verdict, rules, _c = evaluate(
        audit({"ASI_01": [vuln("Critical", "Fuite", confidence=30)]}), policy())
    assert verdict == "BLOCKED", "la confiance basse ne doit JAMAIS debloquer"
    assert "confiance" in libelles(rules) and "30%" in str(rules)


def test_confiance_haute_ne_declenche_aucun_avertissement():
    _v, rules, _c = evaluate(
        audit({"ASI_01": [vuln("Critical", "Fuite", confidence=95)]}), policy())
    assert "moins de 80% de confiance" not in libelles(rules)


# --------------------------------------------------------------------------- #
# Cas limites : un audit vide ou tronque ne doit ni planter ni bloquer a tort.
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("entree", [
    {}, {"agents": {}}, {"agents": None},
    {"agents": {"ASI_01": {}}}, {"agents": {"ASI_01": {"vulnerabilities": None}}},
])
def test_audit_vide_ou_tronque_ne_plante_pas(entree):
    verdict, _rules, counts = evaluate(entree, policy())
    assert verdict == "PASS" and counts["Critical"] == 0


def test_severite_inconnue_ne_compte_pas_comme_critical():
    """Une gravite hors echelle ne doit pas etre promue en bloquante par erreur."""
    verdict, _r, counts = evaluate(
        audit({"ASI_01": [vuln("Catastrophique")]}), policy())
    assert counts["Critical"] == 0 and verdict == "PASS"


# --------------------------------------------------------------------------- #
# Le rapport de pull request : ce que l'equipe lit reellement.
# --------------------------------------------------------------------------- #

def test_rapport_markdown_dit_le_verdict_et_les_chiffres():
    a = audit({"ASI_01": [vuln("Critical", "Injection shell"), vuln("High", "Fuite")]})
    verdict, rules, counts = evaluate(a, policy())
    md = markdown(a, verdict, rules, counts, "audit.json")
    assert "BLOCAGE" in md, "le verdict doit etre lisible en tete"
    assert "Injection shell" in md, "le finding qui bloque doit etre nomme"
    assert "| 1 | 1 |" in md.replace(" ", " "), "le tableau de comptage doit etre juste"


def test_le_gate_REFUSE_de_choisir_lui_meme_son_sujet(monkeypatch, capsys):
    """Sans audit indique, le gate ne doit rendre AUCUN verdict.

    LE BUG QU'IL ATTRAPE, CONSTATE EN EXECUTION
        `ci_gate.py` prenait par defaut LE PLUS RECENT fichier trouve dans
        `data/audit_results/`. Or ce dossier contient 38 resultats VERSIONNES,
        qui alimentent la demo du dashboard. Sur une pull request — ou aucune
        cible n'est auditee — le gate jugeait donc un audit du 1er septembre
        contre une cible bidon `http://c/chat`, et annoncait :

            QUALITY GATE — PASS — deploiement autorise

        Verdict vert sur TOUTES les PR, pour toujours, et poste en commentaire
        ou il se lit comme une decision de securite. Un faux vert coute plus
        cher qu'un controle absent : il fait CROIRE que quelqu'un a regarde.

    Le comportement n'est pas supprime, il est DEMANDE (`--dernier`). Ce test
    exige que le defaut soit le refus, et que le refus explique quoi faire.
    """
    import sys as _sys

    import ci_gate

    monkeypatch.setattr(_sys, "argv", ["ci_gate.py"])
    code = ci_gate.main()
    sortie = capsys.readouterr().out

    assert code != 0, "sans sujet, le gate ne doit pas rendre un code de succes"
    assert "PASS" not in sortie, (
        "il a rendu un VERDICT alors qu'on ne lui a designe aucun audit")
    assert "--dernier" in sortie, (
        "un refus qui n'explique pas comment proceder se contourne au hasard")
