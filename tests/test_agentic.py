"""
test_agentic.py — La boucle agentique ne peut pas adoucir un audit.

POURQUOI CE FICHIER
    `run_agentic()` confie a un modele de langage le choix des reglages d'un
    audit de securite. C'est utile — et c'est aussi un moyen tout neuf de
    fabriquer le faux score rassurant que le reste du projet combat (§18) : il
    suffirait qu'un modele reduise le nombre d'attaques, retire le probe qui
    trouve quelque chose, ou s'arrete des que le score parait bon.

    La garantie ne repose PAS sur une consigne de prompt — une consigne n'est pas
    un controle. Elle repose sur deux mecanismes, et ce sont eux que ces tests
    verrouillent :
      · `appliquer_adaptation` n'accepte un reglage que s'il DURCIT le test ;
      · `fusionner` retient le score MINIMUM des passages.

    Un jour ou l'une des deux regles serait inversee, rien ne planterait : l'audit
    rendrait simplement des scores plus flatteurs. C'est exactement la famille de
    defaut silencieux qui a coute le plus cher a ce projet.

AUCUN RESEAU, AUCUN LLM : agent et modele factices.
"""

from __future__ import annotations

import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))

from agents.agentic_loop import (
    MAX_ATTACKS_PER_TYPE,
    PlanAudit,
    Reflexion,
    appliquer_adaptation,
    demo,
    fusionner,
    percevoir,
    run_agentic,
)
from agents.base_agent import AgentResult, LayerResult, Vulnerability


class FauxAgent:
    """Agent minimal : `run()` rend les scores qu'on lui donne, dans l'ordre."""

    asi_category, name = "ASI_01", "Test"
    deepteam_category, use_pyrit, use_garak = "ASI_01", True, True
    use_microsoft_probes = True
    garak_default_probes = "dan.DAN_Jailbreak"

    def __init__(self, scores=(8.0,)):
        self.config = {"attacks_per_type": 3, "pyrit_max_turns": 3}
        self.target_callback = lambda p: "Je suis un assistant."
        self._scores = list(scores)
        self.appels = 0

    def run(self):
        self.appels += 1
        s = self._scores.pop(0)
        beh = LayerResult(layer="behavioral", score=s, raw={
            "deepteam_stats": {"scored": 2, "passed": 2}, "score_components": {}})
        return AgentResult(asi_category="ASI_01", name="Test", score=s,
                           layers={"behavioral": beh}, status="completed",
                           vulnerabilities=[Vulnerability(
                               asi_category="ASI_01", title=f"F{s}", severity="High",
                               description="", evidence="")])


def test_autotest_agentic_loop():
    """Rejoue les 11 controles du module."""
    demo()


# --------------------------------------------------------------------------- #
# LA garantie : les reglages ne bougent que vers plus de severite.
# --------------------------------------------------------------------------- #

def test_un_modele_ne_peut_pas_reduire_le_nombre_d_attaques():
    """Reduire les attaques est LE moyen le plus simple de fabriquer un bon score.

    Le §18 l'a mesure : un lab demontrablement vulnerable a rendu 9,4/10 parce
    que les attaques lancees etaient trop faibles.
    """
    a = FauxAgent()
    journal = appliquer_adaptation(a, PlanAudit(raisonnement="", attacks_per_type=1))
    assert a.config["attacks_per_type"] == 3
    assert any("REFUS" in x for x in journal), "le refus doit etre TRACE, pas silencieux"


def test_un_modele_ne_peut_pas_raccourcir_les_conversations_pyrit():
    """PyRIT trouve au 3e tour ce qu'il ne trouve pas au 1er (§18, run Gemini)."""
    a = FauxAgent()
    appliquer_adaptation(a, Reflexion(relancer=True, motif="", pyrit_max_turns=1))
    assert a.config["pyrit_max_turns"] == 3


def test_les_probes_garak_ne_peuvent_qu_etre_ajoutes():
    """Garak est le seul axe INDEPENDANT du LLM : remplacer son jeu de probes
    permettrait de retirer precisement celui qui detecte la faille."""
    a = FauxAgent()
    appliquer_adaptation(a, PlanAudit(raisonnement="",
                                      garak_probes_supplementaires="promptinject"))
    assert a.config["garak_probes"] == "dan.DAN_Jailbreak,promptinject"


def test_une_valeur_absurde_est_bornee_et_non_rejetee():
    """L'intention (durcir) est legitime ; seule l'amplitude ne l'est pas."""
    a = FauxAgent()
    appliquer_adaptation(a, PlanAudit(raisonnement="", attacks_per_type=100000))
    assert a.config["attacks_per_type"] == MAX_ATTACKS_PER_TYPE


def test_un_durcissement_reel_est_bien_applique():
    """L'autre sens : une regle qui refuse TOUT est aussi cassee qu'une qui accepte tout."""
    a = FauxAgent()
    appliquer_adaptation(a, PlanAudit(raisonnement="", attacks_per_type=7,
                                      pyrit_max_turns=6))
    assert a.config["attacks_per_type"] == 7 and a.config["pyrit_max_turns"] == 6


# --------------------------------------------------------------------------- #
# LA seconde garantie : le score retenu est le minimum des passages.
# --------------------------------------------------------------------------- #

def test_un_second_passage_plus_clement_n_ameliore_pas_le_score():
    """Le coeur de la regle. Deux executions identiques ont donne 9,66 et 7,93 sur
    la meme cible (§18) : un tirage clement ne prouve rien, une faille demontree si."""
    a = FauxAgent([3.0, 9.5])
    assert fusionner(a.run(), a.run()).score == 3.0


def test_un_second_passage_plus_severe_durcit_le_score():
    a = FauxAgent([9.0, 2.0])
    fusion = fusionner(a.run(), a.run())
    assert fusion.score == 2.0 and len(fusion.vulnerabilities) == 2


def test_un_passage_non_mesure_n_ecrase_pas_un_passage_mesure():
    """Un 0 non mesure n'est pas un verdict — meme regle que `AgentResult.measured`."""
    a = FauxAgent([7.0, 0.0])
    p1, p2 = a.run(), a.run()
    p2.measured = False
    assert fusionner(p1, p2).score == 7.0


# --------------------------------------------------------------------------- #
# La boucle, de bout en bout.
# --------------------------------------------------------------------------- #

def test_sans_modele_la_boucle_se_reduit_a_un_audit_et_le_dit():
    """On ne simule pas un raisonnement qui n'a pas eu lieu."""
    a = FauxAgent([8.0])
    trace = run_agentic(a, model=None).layers["behavioral"].raw["agentic_trace"]
    assert a.appels == 1 and "aucun" in trace["plan"]["raisonnement"]


def test_un_modele_en_panne_ne_prive_pas_d_audit():
    class Panne:
        def generate(self, prompt, schema=None):
            raise RuntimeError("indisponible")

    a = FauxAgent([6.0])
    assert run_agentic(a, model=Panne()).score == 6.0 and a.appels == 1


def test_la_trace_rend_l_audit_contestable():
    """Un audit dont un modele a choisi les reglages n'est defendable que si ces
    choix sont ecrits : perception, durcissements, refus, motif du second passage."""
    class Modele:
        def __init__(self):
            self.n = 0

        def generate(self, prompt, schema=None):
            self.n += 1
            if schema is PlanAudit:
                return PlanAudit(raisonnement="cible bavarde", attacks_per_type=5), 0.0
            return Reflexion(relancer=self.n <= 2, motif="trop peu de tests",
                             attacks_per_type=8), 0.0

    a = FauxAgent([9.0, 4.0])
    trace = run_agentic(a, model=Modele()).layers["behavioral"].raw["agentic_trace"]
    assert trace["perception"]["joignable"] is True
    assert trace["plan"]["adaptations"] and trace["reflexion"]["relancer"]
    assert len(trace["passages"]) == 2 and "durci" in trace["passages"][1]["note"]


def test_la_perception_ne_declare_pas_joignable_une_cible_morte():
    """Un faux « joignable » ferait planifier un audit sur du vide."""
    a = FauxAgent()
    a.target_callback = lambda p: "[HTTP_ERROR] connexion refusee"
    assert percevoir(a)["joignable"] is False


# --------------------------------------------------------------------------- #
# Integration : le mode se regle par config, sans qu'aucun runner ne le sache.
# --------------------------------------------------------------------------- #

def test_execute_choisit_le_mode_et_le_defaut_reste_deterministe():
    from agents.asi01_goal_hijacking import ASI01GoalHijackingAgent

    standard = ASI01GoalHijackingAgent(config={"llm_profile": "dry_run"}).execute()
    assert standard.score == 5.57, "le mode par defaut ne doit pas changer"
    assert "agentic_trace" not in standard.layers["behavioral"].raw

    agentique = ASI01GoalHijackingAgent(
        config={"llm_profile": "dry_run", "mode": "agentic"}).execute()
    assert "agentic_trace" in agentique.layers["behavioral"].raw
