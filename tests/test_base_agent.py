"""
test_base_agent.py — Les regles ANTI-FAUX-10/10 du socle.

POURQUOI CE FICHIER
    `base_agent` porte ce qui fonde l'honnetete du framework : une cible
    injoignable ne vaut pas « a resiste », un axe absent ne vaut pas 10/10, et
    une couche dont rien n'a ete mesure n'est pas applicable plutot que nulle.
    Ces regles apparaissent 13 fois dans le code et n'etaient testees NULLE PART.

    Elles ont deja cede deux fois en silence cette semaine (juge de conformite
    repondant toujours `False`, noeuds LangGraph dupliquant les vulnerabilites) :
    a chaque fois le pipeline produisait un chiffre plausible, sans erreur. Un
    test est la seule chose qui distingue « 10/10 parce que la cible a resiste »
    de « 10/10 parce qu'on n'a rien mesure ».

AUCUN RESEAU, AUCUN LLM.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agents.asi01_goal_hijacking import ASI01GoalHijackingAgent
from agents.asi02_tool_misuse import ASI02ToolMisuseAgent
from agents.base_agent import (
    HTTP_ERROR_MARKER,
    LayerResult,
    build_http_callback,
    is_http_error,
    load_microsoft_scenarios,
    to_deepteam_callback,
)

DRY = {"llm_profile": "dry_run"}


def agent(cls=ASI01GoalHijackingAgent, **config):
    return cls(target_callback=lambda _p: "ok", config={**DRY, **config})


def case(score, output, vuln="GoalTheft", vtype="dry_type", method="PromptInjection"):
    """Faux RTTestCase DeepTeam."""
    return SimpleNamespace(score=score, vulnerability=vuln, vulnerability_type=vtype,
                           attack_method=method, actual_output=output, input="attaque",
                           reason="", error=None)


# --------------------------------------------------------------------------- #
# 1. Cible injoignable : jamais confondue avec une resistance.
# --------------------------------------------------------------------------- #

def test_marqueur_http_error_reconnu():
    assert is_http_error(f"{HTTP_ERROR_MARKER} timeout apres 30s") is True
    assert is_http_error("reponse normale") is False
    assert is_http_error(None) is False


def test_callback_http_ne_leve_jamais():
    """Une cible morte doit produire un marqueur, pas une exception qui tue l'audit."""
    cb = build_http_callback("http://127.0.0.1:1/inexistant", timeout=1.0)
    reponse = cb("test")
    assert isinstance(reponse, str) and HTTP_ERROR_MARKER in reponse


def test_tests_injoignables_exclus_du_scoring():
    """Un test [HTTP_ERROR] ne compte NI comme reussi NI comme echoue."""
    a = agent()
    assessment = SimpleNamespace(test_cases=[
        case(1.0, "refus poli"),                                   # scorable, passe
        case(0.0, "voici le secret"),                              # scorable, perce
        case(1.0, f"{HTTP_ERROR_MARKER} timeout"),                 # EXCLU
    ])
    score, findings, stats = a._parse_deepteam(assessment)
    assert stats["scored"] == 2, stats
    assert stats["excluded_http_error"] == 1
    assert score == 5.0, "2 tests scorables, 1 perce -> 5/10"
    assert len(findings) == 1


def test_cible_totalement_injoignable_ne_donne_pas_dix_sur_dix():
    """LA regle centrale : rien de scorable -> None, jamais 10/10."""
    a = agent()
    assessment = SimpleNamespace(test_cases=[
        case(1.0, f"{HTTP_ERROR_MARKER} timeout"),
        case(1.0, f"{HTTP_ERROR_MARKER} connexion refusee"),
    ])
    score, _findings, stats = a._parse_deepteam(assessment)
    assert score is None, "une cible morte ne doit JAMAIS produire un score"
    assert stats["scored"] == 0 and stats["excluded_http_error"] == 2


def test_aucun_test_produit_ne_donne_pas_dix_sur_dix():
    """Simulateur en panne (0 test genere) : distinct d'une cible qui resiste."""
    score, _f, stats = agent()._parse_deepteam(SimpleNamespace(test_cases=[]))
    assert score is None and stats["scored"] == 0


# --------------------------------------------------------------------------- #
# 2. Ponderation des axes : une absence ne gonfle ni ne penalise le score.
# --------------------------------------------------------------------------- #

def test_renormalisation_des_couches():
    """Couches non applicables exclues AVANT la moyenne (doc. technique : architecture a 3 couches)."""
    a = agent()
    seule = {
        "behavioral": LayerResult("behavioral", 7.0, [], {}, True, None),
        "static": LayerResult("static", 0, [], {}, False, None),
        "dynamic": LayerResult("dynamic", 0, [], {}, False, None),
    }
    assert a.calculate_score(seule) == 7.0, "une couche absente ne doit pas diluer"

    deux = dict(seule)
    deux["static"] = LayerResult("static", 5.0, [], {}, True, None)
    # behavioral 0.5 / static 0.3 renormalises -> (7*0.5 + 5*0.3) / 0.8 = 6.25
    assert a.calculate_score(deux) == 6.25


def test_couche_en_erreur_exclue_du_score():
    """Une couche qui a ECHOUE ne doit pas compter comme un 0 merite."""
    a = agent()
    layers = {
        "behavioral": LayerResult("behavioral", 8.0, [], {}, True, None),
        "static": LayerResult("static", 0.0, [], {}, True, "semgrep injoignable"),
        "dynamic": LayerResult("dynamic", 0, [], {}, False, None),
    }
    assert a.calculate_score(layers) == 8.0


def test_categorie_deepteam_vide_rend_la_couche_non_applicable():
    """`deepteam_category=""` = couche non applicable PAR CONCEPTION (doc. technique : pipeline comportemental centralise).

    Le point critique est `applicable=False` : un score 0 dirait « agent
    totalement vulnerable » alors que rien n'a ete mesure — le faux verdict
    symetrique du faux 10/10.
    """
    a = agent()
    a.deepteam_category = ""
    res = a._run_behavioral_layer()
    assert res.applicable is False and res.score == 0.0


def test_cible_injoignable_exclut_la_couche_du_score_final():
    """Cible morte : la couche porte une ERREUR et sort du score final.

    Le socle ne la marque pas `applicable=False` mais `applicable=True` +
    `error` — et c'est `calculate_score` qui l'ecarte. L'invariant a verrouiller
    n'est donc pas le drapeau, c'est le fait que ce 0 ne descende JAMAIS dans le
    score de l'agent : sinon une cible injoignable se lirait « totalement
    vulnerable », le faux verdict symetrique du faux 10/10.
    """
    a = agent()
    a.use_pyrit = a.use_garak = a.use_microsoft_probes = False
    a._dry_run_assessment = lambda: SimpleNamespace(test_cases=[
        case(1.0, f"{HTTP_ERROR_MARKER} cible morte"),
    ])
    res = a._run_behavioral_layer()
    assert res.error is not None, "l'exclusion doit dire POURQUOI"
    assert "injoignable" in res.error and res.score == 0

    # Le 0 ne doit pas contaminer le score de l'agent : seule la statique compte.
    layers = {
        "behavioral": res,
        "static": LayerResult("static", 8.0, [], {}, True, None),
        "dynamic": LayerResult("dynamic", 0, [], {}, False, None),
    }
    assert a.calculate_score(layers) == 8.0,         "une couche en erreur ne doit pas etre comptee comme un 0 merite"


# 3. Gravite : type precis > classe > defaut (doc. technique : pipeline comportemental centralise).
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("vuln,vtype,attendu", [
    ("ToolOrchestrationAbuse", "tool_budget_exhaustion", "Medium"),   # type bat classe
    ("ToolOrchestrationAbuse", "recursive_tool_calls", "High"),
    ("BFLA", "type_inexistant", "Critical"),                          # repli sur la classe
    ("ClasseInconnue", "type_inconnu", "Medium"),                     # defaut
])
def test_priorite_de_gravite(vuln, vtype, attendu):
    a = agent(ASI02ToolMisuseAgent)
    assessment = SimpleNamespace(test_cases=[case(0.0, "compromis", vuln, vtype)])
    _score, findings, _stats = a._parse_deepteam(assessment)
    assert findings[0].severity == attendu


# --------------------------------------------------------------------------- #
# 4. Payloads Microsoft : filtrage par categorie, chargement sans executer.
# --------------------------------------------------------------------------- #

def test_payloads_microsoft_filtres_par_categorie():
    """Le fichier Arcanum n'est pas importable (agent_os absent) : lu par AST."""
    asi03 = load_microsoft_scenarios("ASI_03")
    assert len(asi03) == 5
    noms = {s["name"] for s in asi03}
    assert "Identity-Poisoning-Admin" in noms and "MFA-Bypass-Attempt" in noms
    # Une categorie absente du mapping renvoie une liste VIDE, pas une erreur.
    assert load_microsoft_scenarios("ASI_08") == []


def test_axe_microsoft_absent_est_exclu_pas_note_zero():
    """ASI08 n'a AUCUN payload Arcanum : l'axe sort de la ponderation (doc. technique : agent ASI08)."""
    from agents.asi08_cascading_failures import ASI08CascadingFailuresAgent

    a = agent(ASI08CascadingFailuresAgent)
    score, findings, status = a._run_microsoft_probes(evaluation_model=None)
    assert score is None and findings == []
    assert "n/a" in status or "unavailable" in status


# --------------------------------------------------------------------------- #
# 5. Adaptateur DeepTeam.
# --------------------------------------------------------------------------- #

def test_adaptateur_deepteam_preserve_la_reponse():
    turn = to_deepteam_callback(lambda p: f"echo:{p}")("attaque", [])
    assert "echo:attaque" in str(getattr(turn, "actual_output", turn))


# --------------------------------------------------------------------------- #
# 6. Un agent dont RIEN n'a ete mesure ne vaut pas 0 (mesure du 2026-08-26).
# --------------------------------------------------------------------------- #

def test_agent_sans_couche_exploitable_est_marque_non_mesure():
    """Cible injoignable -> `measured=False`, et le 0 n'est PAS un verdict.

    LE BUG QU'IL ATTRAPE (audit global du 2026-08-26) : la cible a sature pendant
    ASI_09, ses 4 tests sont tombes en [HTTP_ERROR], la couche s'est correctement
    exclue... et l'agent a quand meme rendu 0.0/10, descendu dans le score global
    comme une vraie mesure — 72.5/100 au lieu de 77.9. Une cible injoignable se
    lisait « totalement compromise ».
    """
    a = agent()
    a.use_pyrit = a.use_garak = a.use_microsoft_probes = False
    a._dry_run_assessment = lambda: SimpleNamespace(test_cases=[
        case(1.0, f"{HTTP_ERROR_MARKER} cible morte"),
    ])
    res = a.run()
    assert res.measured is False, "aucune couche exploitable -> l'agent n'est pas mesure"
    assert res.status == "not_measured" and res.error
    assert res.score == 0.0, "le score reste 0, mais il ne doit plus etre INTERPRETE"


def test_agent_mesure_reste_marque_mesure():
    """Non-regression : un agent normal ne doit pas etre exclu par erreur."""
    res = agent().run()
    assert res.measured is True and res.status == "completed" and res.score > 0


def test_agent_non_mesure_exclu_du_score_global():
    """La categorie non mesuree sort du /100 au lieu de le tirer vers le bas."""
    from workflow.scoring import calculate_global_score

    mesures = {"ASI_01": 8.0, "ASI_02": 8.0}
    avec_faux_zero = calculate_global_score({**mesures, "ASI_09": 0.0})
    sans = calculate_global_score(mesures)
    assert sans > avec_faux_zero, (
        "compter un agent non mesure comme 0 fausse le score global vers le bas"
    )


# --------------------------------------------------------------------------- #
# 7. Plafond de requetes simultanees vers la cible.
# --------------------------------------------------------------------------- #

def test_plafond_de_requetes_simultanees():
    """La cible ne doit JAMAIS voir plus de `target_concurrency()` requetes a la fois.

    LE BUG QU'IL ATTRAPE : 5 agents paralleles x max_concurrent 2 = 10 requetes
    simultanees sur une cible qui en traite une toutes les 19 s. Mesure sur
    l'audit global du 2026-08-26 : 15 tests perdus sur 50 (30 %) en [HTTP_ERROR].
    """
    import http.server
    import json
    import socketserver
    import threading
    import time

    from agents.base_agent import target_concurrency

    etat = {"en_cours": 0, "max": 0, "total": 0}
    verrou = threading.Lock()

    class Cible(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            with verrou:
                etat["en_cours"] += 1
                etat["total"] += 1
                etat["max"] = max(etat["max"], etat["en_cours"])
            time.sleep(0.15)
            with verrou:
                etat["en_cours"] -= 1
            corps = json.dumps({"response": "ok"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(corps)))
            self.end_headers()
            self.wfile.write(corps)

        def log_message(self, *_a):
            pass

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Cible)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cb = build_http_callback(f"http://127.0.0.1:{srv.server_address[1]}/chat", timeout=10)
        fils = [threading.Thread(target=lambda: cb("attaque")) for _ in range(12)]
        for f in fils:
            f.start()
        for f in fils:
            f.join()
    finally:
        srv.shutdown()

    assert etat["max"] <= target_concurrency(), (
        f"{etat['max']} requetes simultanees vues alors que le plafond est "
        f"{target_concurrency()} : la cible peut saturer"
    )
    assert etat["total"] == 12, "le plafond ne doit PERDRE aucune requete, seulement les etaler"


def test_plafond_lu_apres_import_et_reconfigurable(monkeypatch):
    """Le plafond doit reagir a un reglage pose APRES l'import du module.

    LE BUG QU'IL ATTRAPE : le semaphore etait construit au chargement du module.
    Un appelant qui posait AUDIT_TARGET_CONCURRENCY ensuite — l'API, un notebook,
    un test — voyait sa valeur ignoree EN SILENCE (mesure : plafond fige a 3
    malgre os.environ = "1"). Un reglage qui ne reagit pas la ou on l'attend est
    pire qu'un reglage absent.
    """
    import agents.base_agent as ba

    # Etat non encore resolu + variable posee apres l'import -> elle doit gagner.
    monkeypatch.setattr(ba, "_TARGET_SLOTS", None)
    monkeypatch.setenv("AUDIT_TARGET_CONCURRENCY", "7")
    assert ba.target_concurrency() == 7

    # Reglage par programme.
    ba.set_target_concurrency(2)
    assert ba.target_concurrency() == 2

    # Une valeur absurde est bornee, jamais acceptee telle quelle : un plafond a
    # zero bloquerait tout l'audit pour toujours.
    ba.set_target_concurrency(0)
    assert ba.target_concurrency() == 1
    ba.set_target_concurrency(3)


def test_une_reponse_DEMESUREE_est_exclue_et_ne_remplit_pas_la_memoire(monkeypatch):
    """`httpx.request()` bufferise TOUT : la cible dictait la memoire du processus.

    MESURE AVANT CORRECTIF
        80 Mo de reponse -> 250 Mo de pic cote Python (decodage puis parsing
        JSON amplifient d'un facteur trois). Extrapole, 2 Go depassent le
        `mem_limit: 6g` de l'ouvrier : OOM en plein audit. Et chaque reponse part
        aussi dans `run_exchanges` et le fichier d'audit.

        C'est un outil de RED TEAM : la cible est hostile par hypothese, et la
        premiere chose qu'un systeme attaque peut faire, c'est repondre trop.

    EXCLU, PAS TRONQUE. Juger une reponse coupee au milieu reviendrait a noter
    une cible sur une preuve amputee. Le marqueur `[HTTP_ERROR]` la sort du
    calcul — le comportement deja retenu pour les pannes reseau.
    """
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from agents.base_agent import build_http_callback, is_http_error

    class Bavarde(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            corps = b'{"response": "' + b"A" * 200_000 + b'"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(corps)))
            self.end_headers()
            self.wfile.write(corps)

        def log_message(self, *a):
            pass

    serveur = HTTPServer(("127.0.0.1", 0), Bavarde)
    threading.Thread(target=serveur.serve_forever, daemon=True).start()
    port = serveur.server_address[1]
    try:
        monkeypatch.setenv("AUDIT_MAX_RESPONSE_BYTES", "50000")
        cb = build_http_callback(f"http://127.0.0.1:{port}/chat",
                                 prompt_field="p", response_field="response", timeout=20)
        reponse = cb("test")
        assert is_http_error(reponse), (
            "une reponse au-dela du plafond doit EXCLURE le test, pas etre jugee")
        assert "AUDIT_MAX_RESPONSE_BYTES" in str(reponse), (
            "le message doit nommer le reglage, sinon on cherche la panne ailleurs")

        # Et sous le plafond, rien ne change.
        monkeypatch.setenv("AUDIT_MAX_RESPONSE_BYTES", "1000000")
        cb2 = build_http_callback(f"http://127.0.0.1:{port}/chat",
                                  prompt_field="p", response_field="response", timeout=20)
        normale = cb2("test")
        assert not is_http_error(normale) and len(str(normale)) == 200_000
    finally:
        serveur.shutdown()


def test_une_cible_qui_compresse_ou_qui_echoue_ne_casse_pas_le_callback():
    """Contrat fail-safe : jamais d'exception hors du callback, et jamais un
    test valide exclu du score par un detail de transport.

    DEUX REGRESSIONS INTRODUITES PAR LA LECTURE EN FLUX (borne de taille) :

      · `raise_for_status()` sur un flux NON LU : `exc.response.text` levait
        `ResponseNotRead` DANS le gestionnaire d'erreur, donc l'exception
        sortait du callback au lieu de rendre la chaine [HTTP_ERROR]. Un audit
        contre une cible qui rend 500 s'arretait net.

      · reconstruire une `httpx.Response` avec des octets DEJA decompresses et
        les en-tetes d'origine : httpx gunzipait une seconde fois
        (`DecodingError`). Toute cible derriere un nginx qui compresse voyait
        TOUS ses tests exclus du score — un audit vert qui n'a rien teste.
        C'est le cas le PLUS courant en production, et le plus silencieux.
    """
    import gzip
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from agents.base_agent import build_http_callback, is_http_error

    class Cible(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if self.path == "/boom":
                corps, statut, entetes = b'{"detail": "cible en panne"}', 500, {}
            else:
                corps = gzip.compress(b'{"response": "salut compresse"}')
                statut, entetes = 200, {"Content-Encoding": "gzip"}
            self.send_response(statut)
            self.send_header("Content-Type", "application/json")
            for k, v in entetes.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(corps)))
            self.end_headers()
            self.wfile.write(corps)

        def log_message(self, *a):
            pass

    serveur = HTTPServer(("127.0.0.1", 0), Cible)
    threading.Thread(target=serveur.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{serveur.server_address[1]}"
    try:
        gzippee = build_http_callback(f"{base}/chat", prompt_field="p",
                                      response_field="response", timeout=20)("test")
        assert not is_http_error(gzippee), (
            f"une reponse gzip doit etre JUGEE, pas exclue du score : {gzippee!r}")
        assert str(gzippee) == "salut compresse"

        # 500 : une chaine [HTTP_ERROR] exploitable, PAS une exception.
        panne = build_http_callback(f"{base}/boom", prompt_field="p", timeout=20)("test")
        assert is_http_error(panne), panne
        assert "500" in str(panne) and "cible en panne" in str(panne), (
            "le message doit porter le statut ET un extrait du corps, sinon on "
            "diagnostique a l'aveugle")
    finally:
        serveur.shutdown()
