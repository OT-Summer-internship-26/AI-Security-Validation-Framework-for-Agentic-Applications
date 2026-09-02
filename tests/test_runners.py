"""
test_runners.py — Les points d'entree REELS du framework, jamais testes.

POURQUOI CE FICHIER
    `run_agent.py` et `run_audit_global.py` sont ce qu'on lance en production :
    la CI les appelle, l'ouvrier les invoque, un operateur les tape a la main.
    Ils etaient a 0 % de couverture.

    Trois defauts sont deja passes par la, et aucun n'a ete vu avant un audit
    REEL : les sondes de perception comptees comme des attaques, l'affichage du
    chemin de sortie qui tuait le runner APRES une heure de travail reussi, et
    l'axe PyRIT absent de l'image. Tous trois vivaient dans ces fichiers ou
    juste a cote.

CE QUI EST EPROUVE
    Le CABLAGE : ce que le runner assemble et transmet aux agents. Aucun audit
    n'est lance — c'est deja couvert ailleurs, et le lancer ici rendrait la suite
    dependante d'un reseau et d'un modele.

    C'est le cablage qui casse en silence : une option ignoree ne leve aucune
    erreur, elle produit simplement un audit qui ne teste pas ce qu'on croit.

AUCUN RESEAU, AUCUN LLM.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))


def _charger(nom: str):
    """Charge un script de `scripts/` comme module (ils ne sont pas un paquet)."""
    spec = importlib.util.spec_from_file_location(
        f"{nom}_sous_test", RACINE / "scripts" / f"{nom}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# Le cablage : ce que le runner transmet REELLEMENT a l'agent.
# --------------------------------------------------------------------------- #

def _config_produite(monkeypatch, argv: list[str]) -> dict:
    """Lance `run_agent.main()` en interceptant l'agent, et rend sa config.

    On arrete le runner juste apres l'assemblage : c'est le seul endroit ou une
    option peut etre perdue, et une option perdue ne leve aucune erreur.
    """
    runner = _charger("run_agent")
    capture: dict = {}

    class AgentEspion:
        def __init__(self, target_callback=None, config=None):
            capture.update(config or {})
            raise SystemExit(0)          # on n'ira pas plus loin

    from workflow import audit_graph
    monkeypatch.setitem(audit_graph.AGENT_REGISTRY, "ASI_01", AgentEspion)
    monkeypatch.setattr(sys, "argv", ["run_agent.py", *argv])
    with pytest.raises(SystemExit):
        runner.main()
    return capture


BASE = ["ASI_01", "--target", "http://cible/chat", "--profile", "dry_run"]


def test_les_options_de_la_ligne_de_commande_atteignent_l_agent(monkeypatch):
    """Une option ignoree ne leve AUCUNE erreur : elle produit un audit qui ne
    teste pas ce qu'on croit, avec un score qui a l'air normal."""
    cfg = _config_produite(monkeypatch, BASE + [
        "--attacks-per-type", "7", "--pyrit-max-turns", "5",
        "--prompt-field", "question", "--response-field", "answer",
        "--timeout", "42",
    ])
    assert cfg["attacks_per_type"] == 7
    assert cfg["pyrit_max_turns"] == 5
    assert cfg["prompt_field"] == "question"
    assert cfg["response_field"] == "answer"
    assert cfg["llm_profile"] == "dry_run"


def test_le_mode_agentique_est_bien_transmis(monkeypatch):
    """`--mode agentic` change la NATURE de l'audit : reglages adaptes par un
    modele, score minimum des passages. S'il se perdait en route, le runner
    produirait un audit deterministe en annoncant l'autre."""
    cfg = _config_produite(monkeypatch, BASE + ["--mode", "agentic",
                                                "--agentic-passes", "3"])
    assert cfg["mode"] == "agentic" and cfg["agentic_passes"] == 3

    # Et le defaut reste le mode CERTIFIABLE.
    assert _config_produite(monkeypatch, BASE)["mode"] == "standard"


def test_une_charge_supplementaire_invalide_est_refusee_AVANT_l_audit(monkeypatch):
    """`--extra-payload` mal forme doit etre refuse tout de suite.

    Sinon l'audit demarre, tourne des minutes, et echoue sur une faute de frappe
    qu'une validation immediate aurait attrapee.
    """
    runner = _charger("run_agent")
    monkeypatch.setattr(sys, "argv", ["run_agent.py", *BASE,
                                      "--extra-payload", '["pas", "un", "objet"]'])
    with pytest.raises(SystemExit) as exc:
        runner.main()
    assert exc.value.code != 0, "un JSON non-objet doit faire echouer le runner"


def test_une_charge_supplementaire_valide_est_transmise(monkeypatch):
    cfg = _config_produite(monkeypatch, BASE +
                           ["--extra-payload", '{"tenant": "ooredoo"}'])
    assert cfg["extra_payload"] == {"tenant": "ooredoo"}


def test_l_identite_de_pair_ASI07_est_transmise(monkeypatch):
    """Sans elle, l'usurpation reste du langage naturel et la cible peut refuser
    a cause de la FORME du message, pas de l'identite — un faux negatif."""
    cfg = _config_produite(monkeypatch, BASE + ["--peer-agent-id", "orchestrator-01"])
    # Le runner ne transmet pas l'identifiant brut : il construit l'ENVELOPPE de
    # message inter-agents, que le socle applique a tous les axes.
    assert cfg["peer_identity"] == {"agent_id": "orchestrator-01", "format": "json"}


def test_les_axes_se_desactivent_sur_l_INSTANCE_et_non_par_config(monkeypatch):
    """Couper un axe doit couper CET axe, pas un autre.

    Le runner agit sur l'INSTANCE (`agent.use_pyrit = False`) et non par la
    config : c'est un detail d'implementation, mais il decide OU verifier. Le
    tester au mauvais endroit donnerait un test qui passe sans rien prouver.
    """
    import re
    src = (RACINE / "scripts" / "run_agent.py").read_text(encoding="utf-8")
    for option, attribut in (("no_pyrit", "use_pyrit"), ("no_garak", "use_garak"),
                             ("no_microsoft", "use_microsoft_probes")):
        motif = rf"if args\.{option}:\s*\s*agent\.{attribut} = False"
        assert re.search(motif, src), (
            f"--{option.replace('_', '-')} doit couper {attribut}, et lui seul")


# --------------------------------------------------------------------------- #
# Sortie : le runner ne doit plus planter APRES un audit reussi.
# --------------------------------------------------------------------------- #

def test_le_chemin_de_sortie_suit_la_configuration(monkeypatch, tmp_path):
    """En conteneur, les resultats vivent sur un VOLUME, hors du depot.

    Le runner affichait `chemin.relative_to(RACINE)`, ce qui levait ValueError
    des que la sortie sortait du depot — APRES une heure d'audit reussi. Le
    fichier etait bien ecrit ; seul l'affichage tuait le processus.
    """
    monkeypatch.setenv("AUDIT_RESULTS_DIR", str(tmp_path / "volume"))
    from workflow.paths import affichable, results_dir

    assert results_dir() == (tmp_path / "volume").resolve()
    # Un chemin HORS depot reste affichable au lieu de faire planter le runner.
    assert affichable(results_dir() / "x.json").endswith("x.json")


# --------------------------------------------------------------------------- #
# Runner global : identification de la cible et selection des categories.
# --------------------------------------------------------------------------- #

def test_le_slug_du_laboratoire_est_lu_sans_jamais_faire_echouer_l_audit():
    """Le slug sert a rattacher un audit a sa verite terrain (etude DVAP).

    Une cible d'entreprise n'expose evidemment pas ce champ : son absence ne doit
    rien empecher, et une URL non HTTP ne doit pas etre interrogee du tout.
    """
    runner = _charger("run_audit_global")
    assert runner._slug_cible("file:///etc/passwd") is None, (
        "un schema non HTTP ne doit pas etre interroge")
    assert runner._slug_cible("http://hote-inexistant.invalid/chat") is None


def test_les_categories_inconnues_sont_refusees(monkeypatch):
    """Une faute de frappe doit etre attrapee AVANT de lancer des heures d'audit."""
    runner = _charger("run_audit_global")
    monkeypatch.setattr(sys, "argv", ["run_audit_global.py", "--target",
                                      "http://cible/chat", "--profile", "dry_run",
                                      "--categories", "ASI_99"])
    with pytest.raises(SystemExit) as exc:
        runner.main()
    assert exc.value.code != 0


def test_les_compteurs_sont_remis_a_zero_au_demarrage(monkeypatch):
    """Deux audits dans le meme processus additionneraient leurs couts, et le
    second afficherait la facture des deux."""
    from judge import metrics

    metrics.record_llm("severity", 1.0, cout=0.5)
    assert metrics.snapshot()["cout_usd"] == 0.5

    runner = _charger("run_audit_global")
    monkeypatch.setattr(sys, "argv", ["run_audit_global.py", "--target",
                                      "http://cible/chat", "--categories", "ASI_99"])
    with pytest.raises(SystemExit):
        runner.main()
    assert metrics.snapshot() == {}, "les compteurs doivent repartir de zero"
