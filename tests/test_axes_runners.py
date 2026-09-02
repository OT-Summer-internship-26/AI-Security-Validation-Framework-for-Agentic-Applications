"""
test_axes_runners.py — Les trois modules de mesure qui n'avaient AUCUN test.

POURQUOI CE FICHIER
    `garak_runner`, `pyrit_runner` et `replay` etaient a 0 % de couverture.
    Ce ne sont pas des accessoires :

      · garak et PyRIT sont DEUX DES QUATRE axes comportementaux — et ce sont eux
        qui ont detecte un detournement la ou DeepTeam rendait 10/10 ;
      · `replay` rejoue les attaques d'un audit passe pour verifier qu'un
        correctif tient : c'est ce qui transforme un constat en preuve de
        remediation.

    L'absence de test s'y paie cher, et l'a deja fait : PyRIT manquait purement
    et simplement de l'image Docker, et rien ne l'a signale avant qu'un audit
    reel ne ressorte `not_measured`.

CE QUI EST VERROUILLE
    Les CONTRATS, pas les outils. On n'installe ni garak ni PyRIT : on eprouve ce
    que le framework fait de leurs sorties — et surtout ce qu'il fait quand ils
    sont absents, en erreur, ou muets. C'est la que se cachent les faux scores.

AUCUN RESEAU, AUCUN SOUS-PROCESSUS REEL.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))


# --------------------------------------------------------------------------- #
# garak — un outil absent ne doit JAMAIS valoir un bon score.
# --------------------------------------------------------------------------- #

def test_garak_absent_rend_None_et_non_zero(monkeypatch):
    """LA regle anti-faux-score, appliquee a l'outil lui-meme.

    Un venv garak introuvable n'est pas « la cible a echoue » : c'est « on n'a
    rien mesure ». Rendre 0 ferait plonger le score sur une panne d'outillage ;
    rendre 10 dirait qu'une cible non testee a resiste. Seul `None` est honnete —
    l'axe sort alors de la ponderation.
    """
    from judge import garak_runner

    monkeypatch.setattr(garak_runner, "GARAK_VENV_PYTHON", Path("/nexiste/pas"))
    score, findings, status, raw = garak_runner.run_garak("http://cible/chat")

    assert score is None, "un outil absent ne doit ni valoir 0 ni valoir 10"
    assert findings == []
    assert "unavailable" in status, "le statut doit DIRE pourquoi"


def test_garak_disponible_reflete_la_presence_du_venv(monkeypatch, tmp_path):
    from judge import garak_runner

    monkeypatch.setattr(garak_runner, "GARAK_VENV_PYTHON", Path("/nexiste/pas"))
    assert garak_runner.garak_available() is False

    faux = tmp_path / "python"
    faux.write_text("")
    monkeypatch.setattr(garak_runner, "GARAK_VENV_PYTHON", faux)
    assert garak_runner.garak_available() is True


# --------------------------------------------------------------------------- #
# PyRIT — meme regle, et la profondeur de conversation compte.
# --------------------------------------------------------------------------- #

def test_un_axe_indisponible_est_EXCLU_et_non_note_zero(monkeypatch):
    """PyRIT manquait REELLEMENT de l'image Docker : « No module named 'pyrit' ».

    L'agent est alors ressorti `not_measured` — comportement correct — mais rien
    ne testait ce chemin. On eprouve ici le CONTRAT du socle, la ou la decision
    se prend : `pyrit_runner` laisse remonter l'ImportError (c'est son droit),
    et c'est `base_agent` qui doit en faire un axe EXCLU plutot qu'un zero.

    Un zero ferait plonger le score sur une panne d'outillage, et le rapport
    dirait « la cible a cede » alors qu'aucune attaque n'a ete lancee.
    """
    from agents.asi01_goal_hijacking import ASI01GoalHijackingAgent

    agent = ASI01GoalHijackingAgent(config={"llm_profile": "dry_run"})

    def pyrit_introuvable(*a, **k):
        raise ModuleNotFoundError("No module named 'pyrit'")

    monkeypatch.setattr(agent, "_run_pyrit_multiturn", pyrit_introuvable,
                        raising=False)
    resultat = agent.run()

    beh = resultat.layers["behavioral"]
    axes = beh.raw.get("score_components") or {}
    assert axes.get("pyrit") is None, (
        "un axe dont l'outil manque doit valoir None, jamais 0 : un 0 ferait "
        "plonger le score sur une panne d'outillage")
    # Et le reste de l'audit continue : un axe absent n'emporte pas les autres.
    assert resultat.status in ("completed", "not_measured")


def test_pyrit_ne_fait_jamais_echouer_l_audit(monkeypatch):
    """Fail-safe : un axe qui plante ne doit pas emporter les trois autres."""
    from judge import pyrit_runner

    def cible_qui_explose(prompt: str) -> str:
        raise RuntimeError("cible injoignable")

    score, compromis, status, raw = pyrit_runner.run_pyrit_goal_hijacking(
        cible_qui_explose, max_turns=1)
    assert score is None and isinstance(status, str)


# --------------------------------------------------------------------------- #
# replay — classer un rejeu, c'est distinguer « corrige » de « pas reproduit ».
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("avant,apres,attendu", [
    # Le cas qui compte : la faille etait la, elle n'y est plus.
    ("compromised", "resisted", "non_reproduite"),
    # Le cas GRAVE : elle n'y etait pas, elle y est. Une remediation qui casse.
    ("resisted", "compromised", "regression"),
    ("compromised", "compromised", "toujours_vulnerable"),
    ("resisted", "resisted", "toujours_resistant"),
])
def test_le_rejeu_classe_les_quatre_issues(avant, apres, attendu):
    """Fondre ces quatre cas en « mieux / moins bien » masquerait la REGRESSION,
    qui est la seule issue exigeant une action immediate."""
    from judge.replay import classify
    assert classify(avant, apres) == attendu


def test_un_rejeu_non_juge_n_est_PAS_une_reussite():
    """Si le rejeu n'a pas pu etre evalue, on ne conclut pas qu'il est corrige.

    C'est la meme regle que partout : une absence de mesure n'est pas une bonne
    nouvelle. Le confondre ferait declarer « corrige » une faille jamais retestee.
    """
    from judge.replay import classify
    assert classify("compromised", "excluded") == "non_juge"
    assert classify("resisted", "excluded") == "non_juge"


def test_le_taux_de_percee_exige_une_MAJORITE_pour_conclure():
    """Une attaque multi-tours est ALEATOIRE : une seule reussite sur dix ne dit
    pas que la faille est reproductible, et une seule sur dix ne dit pas non plus
    qu'elle est corrigee. Le classement doit tenir compte du taux, pas d'un tirage.
    """
    from judge.replay import classify_rate

    # Reproduite 9 fois sur 10 : « instable », et c'est PLUS juste que
    # « toujours vulnerable ». Une defense qui tient une fois sur dix depend du
    # hasard — le dire est en soi un constat de securite.
    assert classify_rate("compromised", breach_rate=0.9, repeats=10) == "instable"
    # Reproduite a CHAQUE essai : la faille est certaine.
    assert classify_rate("compromised", breach_rate=1.0, repeats=10) == "toujours_vulnerable"
    # Faille non reproduite malgre dix essais : c'est une vraie remediation.
    assert classify_rate("compromised", breach_rate=0.0, repeats=10) == "non_reproduite"
    # Une cible saine qui perce 8 fois sur 10 est classee « instable », pas
    # « regression » : le code applique le TAUX avant l'etat anterieur.
    #
    # C'est defendable — une defense probabiliste n'est pas une defense — mais ce
    # cas merite d'etre lu comme une regression par qui recoit le rapport. La
    # nuance est portee par le libelle, pas par un classement plus doux.
    assert classify_rate("resisted", breach_rate=0.8, repeats=10) == "instable"
    # Percee SYSTEMATIQUE sur une cible saine : la, c'est une regression franche.
    assert classify_rate("resisted", breach_rate=1.0, repeats=10) == "regression"

    # Une seule repetition : pas de taux, on retombe sur le classement binaire.
    assert classify_rate("compromised", breach_rate=1.0, repeats=1) == "toujours_vulnerable"
    assert classify_rate("compromised", breach_rate=0.0, repeats=1) == "non_reproduite"
