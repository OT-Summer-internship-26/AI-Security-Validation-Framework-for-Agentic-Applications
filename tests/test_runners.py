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


# --------------------------------------------------------------------------- #
# Cible AUTHENTIFIEE : le parametre existait, le cablage non.
# --------------------------------------------------------------------------- #

def test_les_en_tetes_atteignent_la_cible_depuis_la_CLI(monkeypatch):
    """`--headers` doit arriver jusqu'a `build_http_callback`.

    LE TROU QU'IL FERME
        `build_http_callback` acceptait `headers` depuis toujours, et
        `workflow/audit_graph._build_callback` le lisait dans `cfg["headers"]`.
        Mais AUCUN chemin ne le remplissait — ni la CLI, ni le modele de requete
        de l'API. Une cible derriere `Authorization: Bearer …` etait donc
        inauditable : le parametre existait, le cablage non.

        Et l'echec etait DISCRET. La cible repond 401, `build_http_callback` rend
        `[HTTP_ERROR] statut 401`, l'axe est EXCLU du score — ni 0, ni 10/10.
        Honnete au niveau du calcul, mais l'operateur voit un audit qui se
        termine « normalement » sur une cible qu'il n'a jamais atteinte.
    """
    runner = _charger("run_agent")
    vus: dict = {}

    import agents.base_agent as socle

    vrai = socle.build_http_callback

    def espion(target, **kw):
        vus.update(kw)
        return vrai(target, **kw)

    monkeypatch.setattr(socle, "build_http_callback", espion)

    class AgentEspion:
        def __init__(self, target_callback=None, config=None):
            raise SystemExit(0)

    from workflow import audit_graph

    monkeypatch.setitem(audit_graph.AGENT_REGISTRY, "ASI_01", AgentEspion)
    monkeypatch.setattr(sys, "argv", ["run_agent.py", *BASE,
                                      "--headers", '{"Authorization": "Bearer jeton"}'])
    with pytest.raises(SystemExit):
        runner.main()

    assert vus.get("headers") == {"Authorization": "Bearer jeton"}, (
        "les en-tetes se perdent entre la ligne de commande et la cible")


def test_des_en_tetes_mal_formes_sont_refuses_AVANT_l_audit(monkeypatch):
    """Un JSON invalide doit echouer tout de suite, pas au premier 401.

    Meme raison que pour `--extra-payload` : sinon l'audit demarre, tourne des
    minutes, et se termine sur un axe exclu — sans que personne relie l'exclusion
    a une faute de frappe dans un jeton.
    """
    runner = _charger("run_agent")
    monkeypatch.setattr(sys, "argv", ["run_agent.py", *BASE, "--headers", "pas du json"])
    with pytest.raises((SystemExit, ValueError)):
        runner.main()


def test_les_en_tetes_entrent_dans_la_config_du_workflow(monkeypatch, tmp_path):
    """Chemin `run_audit_global` : les en-tetes doivent atterrir dans `cfg`.

    C'est `cfg["headers"]` que `_build_callback` lit — une cle absente ne leve
    rien, elle produit juste un audit qui n'atteint pas sa cible.
    """
    runner = _charger("run_audit_global")
    capture: dict = {}

    import workflow.audit_graph as ag

    def faux_graphe(target_url, cfg, **kw):
        capture.update(cfg)
        raise SystemExit(0)

    monkeypatch.setattr(ag, "run_audit_graph", faux_graphe)
    monkeypatch.setenv("AUDIT_RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", [
        "run_audit_global.py", "--target", "http://cible/chat",
        "--profile", "dry_run", "--categories", "ASI_01",
        "--headers", '{"X-API-Key": "abc"}'])
    with pytest.raises(SystemExit):
        runner.main()

    assert capture.get("headers") == {"X-API-Key": "abc"}


def test_le_jeton_de_la_cible_atteint_le_runner_SANS_passer_par_le_journal(
        monkeypatch, tmp_path):
    """Les en-tetes arrivent au runner, jamais dans sa ligne de commande.

    `_build_cmd` posait `--headers {"Authorization": "Bearer …"}`, et `_execute`
    journalise cette ligne (`$ …`) dans `run_logs` — que `GET /runs/{id}` rend a
    tout `viewer`. `masquer_secrets` masquait `request.headers` partout, sauf la.
    On lance donc `_execute` pour de bon, sous-processus remplace par un faux.
    """
    import io
    import subprocess

    monkeypatch.setenv("AUDIT_STATE_DB", str(tmp_path / "s.sqlite"))
    monkeypatch.setenv("AUDIT_TARGET_HEADERS", '{"X-Herite": "du-service"}')
    import api.main as main
    from api import store

    store.fermer()
    store.init()
    secret = "Bearer jeton-de-la-cible"
    lances: list[tuple[list[str], dict]] = []

    class FauxRunner:
        def __init__(self, cmd, env=None, **_):
            lances.append((cmd, env))
            self.stdout = io.StringIO("")

        def wait(self):
            return 1

    monkeypatch.setattr(subprocess, "Popen", FauxRunner)
    try:
        for entetes in ({"Authorization": secret}, None):
            req = main.AuditRequest(category="ASI_01", target_url="http://cible/chat",
                                    headers=entetes)
            run = main.Run(f"run-{len(lances)}", req)
            main._execute(run)
            # Exactement ce que `GET /runs/{id}` rend a un `viewer`.
            rendu = json.dumps(main.masquer_secrets(store.lire_run(run.id)))
            assert "$ " in rendu, "la ligne de commande n'est plus journalisee"
            assert secret not in rendu, "jeton de la cible lisible dans le suivi"

        (cmd, env), (_, env_sans) = lances
        assert secret not in " ".join(cmd), "jeton de la cible dans la ligne de commande"
        assert json.loads(env["AUDIT_TARGET_HEADERS"]) == {"Authorization": secret}, (
            "l'API accepte les en-tetes et ne les transmet pas")
        assert "AUDIT_TARGET_HEADERS" not in env_sans, (
            "une valeur heritee du service part vers une cible qui ne l'a pas demandee")
    finally:
        store.fermer()


def test_le_runner_lit_les_en_tetes_dans_l_environnement(monkeypatch):
    """Le pendant cote runner : `AUDIT_TARGET_HEADERS` vaut `--headers`."""
    runner = _charger("run_agent")
    vus: dict = {}

    import agents.base_agent as socle

    monkeypatch.setattr(socle, "build_http_callback",
                        lambda target, **kw: vus.update(kw) or (lambda p: ""))

    class AgentEspion:
        def __init__(self, target_callback=None, config=None):
            raise SystemExit(0)

    from workflow import audit_graph

    monkeypatch.setitem(audit_graph.AGENT_REGISTRY, "ASI_01", AgentEspion)
    monkeypatch.setenv("AUDIT_TARGET_HEADERS", '{"Authorization": "Bearer env"}')
    monkeypatch.setattr(sys, "argv", ["run_agent.py", *BASE])
    with pytest.raises(SystemExit):
        runner.main()

    assert vus.get("headers") == {"Authorization": "Bearer env"}


# --------------------------------------------------------------------------- #
# L'allowlist : elle doit borner LA CIBLE, pas seulement l'API.
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("runner,argv", [
    ("run_agent", ["ASI_01", "--target", "http://169.254.169.254/latest/meta-data/",
                   "--profile", "dry_run"]),
    ("run_audit_global", ["--target", "http://169.254.169.254/latest/meta-data/",
                          "--profile", "dry_run"]),
    # `--subprocess` ne passe PAS par le graphe. Tant que la validation vivait
    # dans `_run_via_graph`, ce chemin ne validait rien du tout.
    ("run_audit_global", ["--target", "http://169.254.169.254/latest/meta-data/",
                          "--profile", "dry_run", "--subprocess"]),
])
def test_une_cible_HORS_LISTE_est_refusee_par_LES_DEUX_runners(
        monkeypatch, capsys, runner, argv):
    """Le refus doit tomber en CLI, sur les deux runners, AVANT tout audit.

    LE TROU QUE CE TEST FERME
        `valider_cible` a ete sortie d'`api/main.py` vers `workflow/cibles.py`
        precisement pour que les runners l'appliquent aussi. Le branchement
        etait la, verifie A LA MAIN une fois — mais aucun test ne le tenait :
        la branche `except CibleRefusee` des deux runners n'etait jamais
        parcourue. Un remaniement qui la supprimerait aurait laisse la suite
        VERTE, et l'allowlist serait silencieusement redevenue ce qu'elle
        etait : une garde d'API, pas une garde de cible.

        Ce qui est en jeu n'est pas theorique. Les reponses de la cible sont
        conservees dans `run_exchanges` et relues par `/runs/{id}` : une cible
        hors liste, c'est un SSRF dont le resultat ressort par le transcript.

    Les DEUX runners, parametres, et non un seul : c'est la divergence entre
    chemins d'execution qui avait cree le trou d'origine.
    """
    monkeypatch.setenv("AUDIT_TARGET_ALLOWLIST", "localhost")
    module = _charger(runner)
    monkeypatch.setattr(sys, "argv", [f"{runner}.py", *argv])

    with pytest.raises(SystemExit) as exc:
        module.main()

    assert exc.value.code != 0, "une cible hors liste ne doit pas lancer d'audit"
    # Un refus qui ne nomme pas l'hote laisse l'operateur deviner ce qu'il doit
    # ajuster — il finit par elargir la liste au hasard, ou par la desactiver.
    sortie = capsys.readouterr()
    assert "169.254.169.254" in sortie.err + sortie.out
    assert "AUDIT_TARGET_ALLOWLIST" in sortie.err + sortie.out
