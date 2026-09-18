"""
test_api.py — Les 13 endpoints de l'API d'audit.

POURQUOI CE FICHIER
    L'API porte le livrable #4 du sujet (« framework d'audit reutilisable ») :
    c'est par elle qu'un tiers declenche un audit, suit sa progression et
    recupere le rapport. Elle declarait 13 endpoints et **aucun n'avait jamais
    ete appele** — ni en test, ni en demonstration. On ne savait donc pas si
    `POST /audits` fonctionnait.

    `TestClient` de FastAPI execute l'application en memoire : pas de serveur a
    lancer, pas de port a reserver, et les tests tournent en CI comme le reste.

CE QUI EST VERROUILLE
    Le CONTRAT de chaque endpoint — code de retour, forme de la reponse — et
    surtout les deux regles de securite : la cle d'API protege bien ce qu'elle
    doit proteger, et un identifiant inconnu renvoie 404 plutot que 500.

AUCUN AUDIT N'EST REELLEMENT LANCE : le lancement est intercepte, sinon chaque
execution de la suite demarrerait des sous-processus de plusieurs minutes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))


@pytest.fixture()
def client(monkeypatch, tmp_path):
    """Application en memoire, sans cle d'API et sans lancement reel d'audit."""
    from fastapi.testclient import TestClient

    monkeypatch.delenv("FRAMEWORK_API_KEY", raising=False)
    from api import main

    # Le lancement d'un audit demarre un thread + un sous-processus de plusieurs
    # minutes : on l'intercepte pour tester le CONTRAT de l'endpoint, pas
    # l'execution d'un audit (deja couverte par les tests du workflow).
    monkeypatch.setattr(main, "_execute", lambda run: None)
    return TestClient(main.app)


@pytest.fixture()
def client_protege(monkeypatch):
    """Meme application, mais avec une cle d'API configuree."""
    from fastapi.testclient import TestClient

    monkeypatch.setenv("FRAMEWORK_API_KEY", "cle-secrete")
    from api import main

    monkeypatch.setattr(main, "_execute", lambda run: None)
    return TestClient(main.app)


# --------------------------------------------------------------------------- #
# Lecture : disponibles sans authentification.
# --------------------------------------------------------------------------- #

def test_health_repond(client):
    """L'endpoint de sante doit repondre meme si tout le reste est casse."""
    r = client.get("/health")
    assert r.status_code == 200 and isinstance(r.json(), dict)


def test_agents_liste_les_dix_categories(client):
    """Le registre expose doit correspondre aux 10 agents construits."""
    r = client.get("/agents")
    assert r.status_code == 200
    corps = json.dumps(r.json())
    for cat in ("ASI_01", "ASI_05", "ASI_10"):
        assert cat in corps, f"{cat} absent de /agents"


def test_audits_liste_sans_planter(client):
    r = client.get("/audits")
    assert r.status_code == 200 and isinstance(r.json(), dict)


def test_audit_inconnu_renvoie_404_pas_500(client):
    """Un identifiant inexistant est une erreur du CLIENT, pas du serveur.

    Un 500 ferait croire a une panne de l'API et declencherait une astreinte
    pour une simple faute de frappe.
    """
    r = client.get("/audits/identifiant-qui-nexiste-pas")
    assert r.status_code == 404


def test_rapport_d_audit_inconnu_renvoie_404(client):
    r = client.get("/audits/inexistant/report")
    assert r.status_code == 404


def test_runs_et_replays_listent_sans_planter(client):
    for chemin in ("/runs", "/replays"):
        r = client.get(chemin)
        assert r.status_code == 200, f"{chemin} -> {r.status_code}"


def test_run_inconnu_renvoie_404(client):
    assert client.get("/runs/run-inexistant").status_code == 404


# --------------------------------------------------------------------------- #
# Ecriture : lancement d'audit.
# --------------------------------------------------------------------------- #

def test_lancer_un_audit_renvoie_un_identifiant_suivable(client):
    """Le contrat de `POST /audits` : un `run_id` immediatement interrogeable.

    L'audit dure des heures ; l'appel doit donc rendre la main tout de suite avec
    de quoi suivre, sinon aucun client HTTP ne tiendrait la connexion.
    """
    r = client.post("/audits", json={"mode": "targeted", "category": "ASI_01",
                                     "target_url": "http://cible/chat"})
    assert r.status_code == 200, r.text
    corps = r.json()
    assert corps.get("run_id"), "un run_id est indispensable pour suivre l'audit"
    assert corps.get("status") in ("queued", "running")

    # ... et cet identifiant doit etre immediatement interrogeable.
    suivi = client.get(f"/runs/{corps['run_id']}")
    assert suivi.status_code == 200


def test_mode_full_accepte_les_dix_categories(client):
    r = client.post("/audits", json={"mode": "full", "target_url": "http://cible/chat"})
    assert r.status_code == 200 and r.json().get("run_id")


def test_categorie_inconnue_refusee(client):
    """Une categorie inexistante doit etre refusee AVANT de lancer quoi que ce soit.

    Sinon l'audit demarre, tourne, et echoue des minutes plus tard sur une faute
    de frappe qu'une validation immediate aurait attrapee.
    """
    r = client.post("/audits", json={"mode": "targeted", "category": "ASI_99",
                                     "target_url": "http://cible/chat"})
    assert r.status_code in (400, 404, 422), f"attendu un refus, recu {r.status_code}"


def test_rejeu_d_un_audit_inconnu_renvoie_404(client):
    r = client.post("/replay", json={"audit_id": "inexistant"})
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# Securite : la cle protege les endpoints d'ECRITURE.
# --------------------------------------------------------------------------- #

def test_sans_cle_l_ecriture_est_refusee(client_protege):
    """Cle configuree + requete sans cle = 401.

    C'est la seule barriere entre un tiers et le lancement d'audits sur
    l'infrastructure : si elle cede, n'importe qui declenche des heures de calcul.
    """
    r = client_protege.post("/audits", json={"mode": "targeted", "category": "ASI_01",
                                             "target_url": "http://cible/chat"})
    assert r.status_code == 401


def test_mauvaise_cle_refusee(client_protege):
    r = client_protege.post("/audits",
                            headers={"X-API-Key": "mauvaise-cle"},
                            json={"mode": "targeted", "category": "ASI_01",
                                  "target_url": "http://cible/chat"})
    assert r.status_code == 401


def test_bonne_cle_acceptee(client_protege):
    r = client_protege.post("/audits",
                            headers={"X-API-Key": "cle-secrete"},
                            json={"mode": "targeted", "category": "ASI_01",
                                  "target_url": "http://cible/chat"})
    assert r.status_code == 200 and r.json().get("run_id")


def test_la_lecture_reste_ouverte_meme_avec_une_cle(client_protege):
    """`/health` doit repondre sans cle : une sonde de supervision n'en a pas.

    Proteger la sante de l'API rendrait le service indistinguable d'un service
    mort pour tout systeme de monitoring.
    """
    assert client_protege.get("/health").status_code == 200


# --------------------------------------------------------------------------- #
# Gestion des laboratoires : desactivee par defaut.
# --------------------------------------------------------------------------- #

def test_les_endpoints_de_laboratoire_sont_fermes_par_defaut(client):
    """`/dvap/launch` demarre un CONTENEUR sur l'hote.

    Une API d'entreprise capable de lancer des conteneurs arbitraires est une
    escalade de privileges deguisee — et ce serait un defaut de securite dans un
    OUTIL DE SECURITE. Ces endpoints existent pour l'atelier d'entrainement ; ils
    doivent rester fermes tant que personne ne les a explicitement ouverts.

    404 et non 403 : une fonctionnalite desactivee ne signale pas son existence.
    """
    assert client.get("/dvap/labs").status_code == 404
    assert client.post("/dvap/launch", json={"slug": "prompt-injection"}).status_code == 404


def test_l_activation_explicite_rouvre_les_endpoints(monkeypatch):
    """L'autre sens : une garde qui refuse TOUT est aussi cassee qu'une absente."""
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ENABLE_LAB_MANAGEMENT", "1")
    monkeypatch.delenv("FRAMEWORK_API_KEY", raising=False)
    import importlib

    import api.main as main
    importlib.reload(main)
    try:
        monkeypatch.setattr(main, "_execute", lambda run: None)
        # L'endpoint repond (le contenu depend de la presence de DVAP, pas nous).
        assert TestClient(main.app).get("/dvap/labs").status_code != 404
    finally:
        monkeypatch.delenv("ENABLE_LAB_MANAGEMENT", raising=False)
        importlib.reload(main)


# --------------------------------------------------------------------------- #
# Emplacement des resultats : configurable pour la production.
# --------------------------------------------------------------------------- #

def test_le_repertoire_de_resultats_suit_la_configuration(monkeypatch, tmp_path):
    """Dans un conteneur, le disque du depot est EPHEMERE : un audit d'une heure
    disparaitrait au redemarrage du pod. Le chemin doit pouvoir pointer vers un
    volume persistant, et ce depuis UN seul point de resolution."""
    monkeypatch.setenv("AUDIT_RESULTS_DIR", str(tmp_path / "volume"))
    from workflow.paths import results_dir
    assert results_dir() == (tmp_path / "volume").resolve()
    assert results_dir().is_absolute()


# --------------------------------------------------------------------------- #
# Supervision : compteurs et journal structure.
# --------------------------------------------------------------------------- #

def test_metrics_repond_au_format_prometheus(client):
    """La supervision d'entreprise COLLECTE : elle tire un /metrics en texte.

    Sans cet endpoint, le seul moyen de savoir ce que fait ce service est
    d'ouvrir un tableau de bord tiers OPTIONNEL — autant dire qu'il n'est pas
    supervise.
    """
    r = client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert "# HELP " in r.text and "# TYPE " in r.text


def test_metrics_repond_meme_sans_aucune_mesure(client):
    """Un collecteur qui recoit une page blanche marque la cible en panne."""
    from judge.metrics import reset
    reset()
    r = client.get("/metrics")
    assert r.status_code == 200 and r.text.strip()


def test_metrics_reste_ouvert_avec_une_cle_d_api(client_protege):
    """Un collecteur Prometheus ne porte pas de cle. Proteger cet endpoint
    reviendrait a ne rien exposer."""
    assert client_protege.get("/metrics").status_code == 200


def test_autotest_journal_structure():
    """Rejoue les 6 controles du formateur JSON."""
    from api.logging_config import configurer, demo
    try:
        demo()
    finally:
        configurer(force_json=False)


# --------------------------------------------------------------------------- #
# Authentification a roles : rotation, niveaux, attribution.
# --------------------------------------------------------------------------- #

@pytest.fixture()
def client_admin(monkeypatch, tmp_path):
    """Application avec un magasin neuf et une cle d'amorcage admin."""
    from fastapi.testclient import TestClient

    monkeypatch.setenv("AUDIT_STATE_DB", str(tmp_path / "auth.sqlite"))
    monkeypatch.setenv("FRAMEWORK_API_KEY", "amorce-admin")
    import api.main as main
    from api import store

    store.fermer()
    store.init()
    monkeypatch.setattr(main, "_execute", lambda run: None)
    yield TestClient(main.app)
    store.fermer()


def test_une_cle_creee_permet_de_lancer_un_audit(client_admin):
    """Le cycle complet : un admin cree une cle d'operateur, qui lance un audit."""
    r = client_admin.post("/keys", headers={"X-API-Key": "amorce-admin"},
                          json={"name": "equipe secu", "role": "operator"})
    assert r.status_code == 200
    cle = r.json()["key"]
    assert cle.startswith("aisec_")

    lance = client_admin.post("/audits", headers={"X-API-Key": cle},
                              json={"mode": "targeted", "category": "ASI_01",
                                    "target_url": "http://cible/chat"})
    assert lance.status_code == 200 and lance.json().get("run_id")


def test_un_viewer_ne_peut_pas_lancer_d_audit(client_admin):
    """Les roles se comparent par NIVEAU : lire n'autorise pas a attaquer."""
    cle = client_admin.post("/keys", headers={"X-API-Key": "amorce-admin"},
                            json={"name": "lecteur", "role": "viewer"}).json()["key"]
    r = client_admin.post("/audits", headers={"X-API-Key": cle},
                          json={"mode": "targeted", "category": "ASI_01",
                                "target_url": "http://cible/chat"})
    assert r.status_code == 403, "un viewer doit etre refuse, pas accepte"


def test_un_operateur_ne_peut_pas_gerer_les_cles(client_admin):
    """Lancer des audits n'autorise pas a s'octroyer des droits."""
    cle = client_admin.post("/keys", headers={"X-API-Key": "amorce-admin"},
                            json={"name": "op", "role": "operator"}).json()["key"]
    assert client_admin.get("/keys", headers={"X-API-Key": cle}).status_code == 403
    assert client_admin.post("/keys", headers={"X-API-Key": cle},
                             json={"name": "x", "role": "admin"}).status_code == 403


def test_une_cle_revoquee_ne_lance_plus_rien(client_admin):
    """LA rotation. Sans revocation, une cle distribuee une fois vaut pour
    toujours — et rien ne signale qu'elle circule encore."""
    cree = client_admin.post("/keys", headers={"X-API-Key": "amorce-admin"},
                             json={"name": "temporaire"}).json()
    corps = {"mode": "targeted", "category": "ASI_01", "target_url": "http://c/chat"}
    assert client_admin.post("/audits", headers={"X-API-Key": cree["key"]},
                             json=corps).status_code == 200

    assert client_admin.delete(f"/keys/{cree['id']}",
                               headers={"X-API-Key": "amorce-admin"}).status_code == 200
    assert client_admin.post("/audits", headers={"X-API-Key": cree["key"]},
                             json=corps).status_code == 401


def test_l_inventaire_des_cles_ne_divulgue_aucune_cle(client_admin):
    """Seule l'empreinte est conservee : un inventaire ne doit rien rendre."""
    cle = client_admin.post("/keys", headers={"X-API-Key": "amorce-admin"},
                            json={"name": "secrete"}).json()["key"]
    inventaire = client_admin.get("/keys", headers={"X-API-Key": "amorce-admin"})
    assert inventaire.status_code == 200
    assert cle not in inventaire.text


def test_un_audit_enregistre_QUI_l_a_lance(client_admin):
    """Pour un outil capable d'attaquer des systemes internes, la tracabilite de
    l'appelant n'est pas optionnelle."""
    from api import store

    cree = client_admin.post("/keys", headers={"X-API-Key": "amorce-admin"},
                             json={"name": "equipe A"}).json()
    run_id = client_admin.post("/audits", headers={"X-API-Key": cree["key"]},
                               json={"mode": "targeted", "category": "ASI_01",
                                     "target_url": "http://c/chat"}).json()["run_id"]
    assert store.lire_run(run_id)["created_by"] == cree["id"]


def test_un_role_inconnu_est_refuse_avec_400(client_admin):
    r = client_admin.post("/keys", headers={"X-API-Key": "amorce-admin"},
                          json={"name": "x", "role": "superadmin"})
    assert r.status_code == 400


def test_le_suivi_d_execution_survit_a_un_nouvel_objet_api(client_admin):
    """La preuve de la persistance vue de l'API : l'execution se relit dans le
    magasin, sans qu'aucun objet Python ne la detienne."""
    from api import store

    run_id = client_admin.post("/audits", headers={"X-API-Key": "amorce-admin"},
                               json={"mode": "targeted", "category": "ASI_01",
                                     "target_url": "http://c/chat"}).json()["run_id"]
    store.fermer()                          # « redemarrage » : plus rien en memoire
    # La clef est desormais EXIGEE en lecture : ce test la fournit, et celui qui
    # suit verifie qu'elle est bien exigee.
    r = client_admin.get(f"/runs/{run_id}", headers={"X-API-Key": "amorce-admin"})
    assert r.status_code == 200 and r.json()["run_id"] == run_id


def test_un_rejeu_n_est_JAMAIS_pris_par_l_ouvrier(client_admin, monkeypatch):
    """Un rejeu tourne dans l'API ; la file ne doit JAMAIS le rendre a un ouvrier.

    LE BUG
        `POST /replay` persistait son execution en `queued`, sans rien qui la
        distingue d'un audit. L'ouvrier la prenait et lancait un AUDIT COMPLET de
        la cible — attaques reelles, quota LLM, fichier de resultat que personne
        n'avait demande. Et un rejeu ne bat jamais : `reprendre_abandonnes` le
        voyait abandonne des le premier balayage et le remettait en file.
    """
    import api.main as main
    from api import store

    source = {"_file": "source.json", "target_url": "http://c/chat",
              "agents": {"ASI_01": {"attacks": [{"prompt": "x", "verdict": "compromised"}]}}}
    monkeypatch.setattr(main, "_read_results", lambda: [source])
    # Le rejeu ne demarre pas : sa ligne reste `queued`, le pire cas pour la file.
    monkeypatch.setattr(main, "_execute_replay", lambda *a, **k: None)

    r = client_admin.post("/replay", headers={"X-API-Key": "amorce-admin"},
                          json={"audit_id": "source.json"})
    assert r.status_code == 200
    rejeu = r.json()["run_id"]
    store.creer_run("audit-apres", {"mode": "targeted", "category": "ASI_01"})

    pris = store.prendre_run("ouvrier")
    assert pris is not None and pris["run_id"] == "audit-apres", (
        f"l'ouvrier a pris {pris and pris['run_id']} : un rejeu lance comme un audit")
    assert store.prendre_run("ouvrier") is None

    # Un rejeu en cours n'a pas de battement : il ne doit pas etre « repris ».
    store.maj_run(rejeu, status="running")
    assert store.reprendre_abandonnes(limite_s=0) == 1, "seul l'audit est repris"
    assert store.lire_run(rejeu)["status"] == "running"


@pytest.fixture()
def magasin_neuf(monkeypatch, tmp_path):
    """Magasin temporaire, API ouverte (aucune cle) : `cancel_run` s'appelle direct."""
    monkeypatch.setenv("AUDIT_STATE_DB", str(tmp_path / "annul.sqlite"))
    import api.main as main
    from api import store

    # APRES l'import : `api.main` charge `.env` a l'import, qui reposerait la cle.
    monkeypatch.delenv("FRAMEWORK_API_KEY", raising=False)

    store.fermer()
    store.init()
    monkeypatch.setattr(main, "ANNULATION_S", 0.05)
    yield main, store
    store.fermer()


def test_annuler_un_audit_en_cours_ARRETE_vraiment_le_runner(magasin_neuf, monkeypatch):
    """L'annulation traverse les processus : l'API ecrit, l'executant s'arrete.

    LE BUG
        `cancel_run` ecrivait `cancelled` dans le magasin et repondait « annule ».
        Personne ne relisait ce statut : l'ouvrier poursuivait l'audit (attaques,
        quota) puis ecrivait `completed` par-dessus. En mode mono-processus,
        meme chose — l'audit n'etait pas dans `_REJEUX`, donc jamais tue.
    """
    import io
    import subprocess
    import threading

    main, store = magasin_neuf

    class RunnerSansFin:
        """Un runner qui ne s'arrete QUE si on le tue."""
        vivants: list = []

        def __init__(self, cmd, **_):
            self.stdout, self.fini, self.tue = io.StringIO(""), threading.Event(), False
            RunnerSansFin.vivants.append(self)

        def poll(self):
            return -15 if self.fini.is_set() else None

        def terminate(self):
            self.tue = True
            self.fini.set()

        def wait(self):
            self.fini.wait(20)
            return -15

    monkeypatch.setattr(subprocess, "Popen", RunnerSansFin)
    req = main.AuditRequest(category="ASI_01", target_url="http://cible/chat")
    main.Run("run-long", req)
    execution = main.Run.depuis_magasin(store.prendre_run("ouvrier"))   # comme l'ouvrier
    fil = threading.Thread(target=main._execute, args=(execution,), daemon=True)
    fil.start()
    for _ in range(100):
        if RunnerSansFin.vivants:
            break
        threading.Event().wait(0.02)

    # Depuis l'API — un AUTRE objet, comme un autre processus : `_REJEUX` l'ignore.
    assert main.cancel_run("run-long", None)["status"] == "cancelled"
    fil.join(timeout=5)

    assert not fil.is_alive(), "l'audit annule tourne toujours"
    assert RunnerSansFin.vivants[0].tue, "le runner n'a jamais recu terminate()"
    fin = store.lire_run("run-long")
    assert fin["status"] == "cancelled", f"l'executant a ecrase l'annulation : {fin['status']}"
    assert fin["finished_at"], "une execution arretee doit porter sa date de fin"


def test_un_audit_EN_FILE_s_annule_et_n_est_plus_pris(magasin_neuf):
    """« deja terminee » etait la reponse pour un audit en file — puis l'ouvrier
    le prenait et l'executait quand meme."""
    main, store = magasin_neuf
    main.Run("run-attente", main.AuditRequest(category="ASI_01",
                                              target_url="http://cible/chat"))
    assert main.cancel_run("run-attente", None)["status"] == "cancelled"
    assert store.prendre_run("ouvrier") is None, "un audit annule a ete pris"
    assert store.lire_run("run-attente")["finished_at"]


def test_cancelled_est_TERMINAL_mais_les_autres_champs_s_ecrivent(magasin_neuf):
    """L'executant ecrit `completed` en fin d'audit : il ne doit pas effacer une
    annulation arrivee entre-temps — mais sa date de fin, si."""
    _, store = magasin_neuf
    store.creer_run("run-t", {"mode": "targeted"})
    store.maj_run("run-t", status="cancelled")
    store.maj_run("run-t", status="completed", finished_at="2026-09-18T12:00:00+00:00")
    r = store.lire_run("run-t")
    assert r["status"] == "cancelled"
    assert r["finished_at"] == "2026-09-18T12:00:00+00:00"


def test_la_migration_reconnait_les_rejeux_DEJA_en_base(monkeypatch, tmp_path):
    """Un volume de production porte des rejeux d'avant la colonne `kind`."""
    import sqlite3

    from api import store

    base = tmp_path / "v1.sqlite"
    monkeypatch.setenv("AUDIT_STATE_DB", str(base))
    monkeypatch.setattr(store, "SCHEMA_VERSION", 1)
    monkeypatch.setattr(store, "_MIGRATIONS", store._MIGRATIONS[:1])
    store.fermer()
    store.init()
    for ident in ("replay-20260901-abc", "run-20260901-def"):
        store._conn().execute(
            "INSERT INTO runs (id, status, request, started_at) "
            "VALUES (?, 'queued', '{}', '2026-09-01')", (ident,))
    store.fermer()
    monkeypatch.undo()
    monkeypatch.setenv("AUDIT_STATE_DB", str(base))
    try:
        store.init()
        assert store.prendre_run("ouvrier")["run_id"] == "run-20260901-def"
        assert store.prendre_run("ouvrier") is None, "un ancien rejeu repart comme audit"
    finally:
        store.fermer()
    assert (sqlite3.connect(base).execute("PRAGMA user_version").fetchone()[0]
            == store.SCHEMA_VERSION)


# --------------------------------------------------------------------------- #
# La cible d'un audit : cet outil ATTAQUE ce qu'on lui designe.
# --------------------------------------------------------------------------- #

def test_un_schema_non_http_est_refuse():
    """`file://` ou `gopher://` ferait lire un fichier local au runner."""
    from fastapi import HTTPException

    from api import main

    with pytest.raises(HTTPException) as e:
        main.valider_cible("file:///etc/passwd")
    assert e.value.status_code == 400


def test_sans_liste_toute_cible_passe_MAIS_l_outil_le_dit(monkeypatch, caplog):
    """Le defaut reste permissif — c'est le mode developpement — mais pas muet.

    Une installation de production laissee ouverte par ignorance est le scenario
    a eviter : sans avertissement, personne ne decouvre l'etat avant l'incident.
    """
    import logging

    from api import main

    monkeypatch.delenv("AUDIT_TARGET_ALLOWLIST", raising=False)
    monkeypatch.setattr(main, "_ALERTE_CIBLE_LIBRE_EMISE", False)
    with caplog.at_level(logging.WARNING, logger="api.main"):
        assert main.valider_cible("http://169.254.169.254/latest")
    assert "AUDIT_TARGET_ALLOWLIST" in caplog.text, (
        "un mode permissif qui ne s'annonce pas se decouvre le jour de l'incident")


def test_une_cible_hors_liste_est_refusee(monkeypatch):
    """LE cas qui compte : cle operateur fuitee -> SSRF vers les metadonnees.

    ON POSE LA VRAIE VARIABLE, PAS UN ATTRIBUT DE MODULE.
        La premiere version surchargeait `main.TARGET_ALLOWLIST` — elle aurait
        donc passe meme si le code avait lu l'environnement A L'IMPORT, cas ou
        un operateur qui configure la variable n'obtient RIEN. C'est le piege
        deja corrige deux fois dans ce depot. En posant `AUDIT_TARGET_ALLOWLIST`,
        ce test eprouve ce qu'un operateur configure reellement.

    Les reponses de la cible sont enregistrees dans `run_exchanges` puis
    relisibles par `/runs/{id}` : sans bornage, l'outil devient un SSRF
    authentifie AVEC exfiltration par le transcript d'audit.
    """
    from fastapi import HTTPException

    from api import main

    monkeypatch.setenv("AUDIT_TARGET_ALLOWLIST", "localhost")
    with pytest.raises(HTTPException) as e:
        main.valider_cible("http://169.254.169.254/latest/meta-data/")
    assert e.value.status_code == 403
    assert "169.254.169.254" in e.value.detail, "le refus doit NOMMER la cible refusee"


def test_le_motif_a_point_couvre_le_sous_domaine_mais_PAS_le_domaine_nu(monkeypatch):
    """`.interne.exemple.com` n'autorise pas `interne.exemple.com`.

    Le domaine nu peut appartenir a un tiers, ou etre servi par un frontal
    different de celui qu'on a voulu autoriser. Elargir « pour faire simple »
    serait exactement la permissivite qu'on essaie de retirer.
    """
    from fastapi import HTTPException

    from api import main

    monkeypatch.setenv("AUDIT_TARGET_ALLOWLIST", ".interne.exemple.com")
    assert main.valider_cible("http://api.interne.exemple.com/chat")
    with pytest.raises(HTTPException):
        main.valider_cible("http://interne.exemple.com/chat")


def test_les_DEUX_portes_qui_acceptent_une_cible_la_valident():
    """`/audits` ET `/replay` doivent passer par le point unique de validation.

    Le rejeu accepte une cible DIFFERENTE de celle de l'audit source : l'oublier
    aurait laisse une seconde porte sur le meme risque. Ce test lit l'AST plutot
    que de monter un audit source complet — il repond a la seule question qui
    compte : ces deux fonctions appellent-elles `valider_cible` ?
    """
    import ast
    from pathlib import Path

    source = (Path(__file__).resolve().parent.parent / "api" / "main.py").read_text(
        encoding="utf-8")
    arbre = ast.parse(source)

    for nom_fonction in ("create_audit", "create_replay"):
        fonction = next(
            (n for n in ast.walk(arbre)
             if isinstance(n, ast.FunctionDef) and n.name == nom_fonction), None)
        assert fonction is not None, f"{nom_fonction} introuvable"
        appels = {n.func.id for n in ast.walk(fonction)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        assert "valider_cible" in appels, (
            f"{nom_fonction}() accepte une cible SANS la valider — seconde porte")


def test_un_echec_de_persistance_ne_TUE_pas_l_audit(monkeypatch, tmp_path):
    """Le gestionnaire cense absorber l'echec levait un NameError.

    LE BUG QU'IL ATTRAPE
        `Run.__setattr__`, `log` et `add_exchange` appelaient `logger.debug(...)`
        dans leur `except` — mais `logger` n'etait defini NULLE PART dans le
        module. Ces blocs levaient donc un `NameError` au lieu d'ecrire une
        ligne. Or `__setattr__` est sur le CHEMIN CHAUD : chaque mise a jour de
        statut y passe. Des que `store.maj_run` echouait — base verrouillee,
        disque plein, schema en desaccord — le filet cense rattraper tuait
        l'audit. Le seul cas ou il servait etait celui ou il cassait.
    """
    import uuid

    from api import main, store

    # Base isolee : ce test ne doit RIEN ecrire dans celle du projet.
    monkeypatch.setenv("AUDIT_STATE_DB", str(tmp_path / "panne.sqlite"))
    store.fermer()
    store.init()
    run = main.Run(f"run-essai-{uuid.uuid4().hex[:8]}",
                   main.AuditRequest(profile="dry_run"))

    def store_en_panne(*a, **k):
        raise RuntimeError("base indisponible")

    # La panne est injectee APRES la construction : on eprouve les trois
    # gestionnaires d'erreur, pas la creation de l'execution.
    monkeypatch.setattr(main.store, "maj_run", store_en_panne)
    monkeypatch.setattr(main.store, "ajouter_log", store_en_panne)
    monkeypatch.setattr(main.store, "ajouter_echange", store_en_panne)
    object.__setattr__(run, "_persiste", True)

    run.status = "running"          # passe par __setattr__ -> maj_run en panne
    run.log("INFO", "coucou")
    run.add_exchange({"a": 1})
    assert run.status == "running", "l'objet en memoire doit rester coherent"


# --------------------------------------------------------------------------- #
# Le transcript d'un audit n'est pas public, et les secrets de la cible non plus.
# --------------------------------------------------------------------------- #

def test_le_transcript_d_un_audit_n_est_PAS_lisible_sans_clef(client_admin):
    """`GET /runs/{id}` rendait 200 SANS aucune clef, avec le transcript complet.

    LE TROU, MESURE
        Ces reponses portent chaque prompt envoye et chaque REPONSE DE LA CIBLE.
        Sur une cible interne, c'est exactement le canal d'exfiltration que
        l'allowlist pretendait fermer — et il etait ouvert a qui pouvait joindre
        l'API. Dix points d'entree en lecture etaient dans ce cas.

        Sans clef configuree nulle part, `_identifier` rend un anonyme admin :
        le developpement local ne change pas. C'est le deploiement AVEC clef qui
        etait ouvert, et c'est le pire des deux.
    """
    run_id = client_admin.post("/audits", headers={"X-API-Key": "amorce-admin"},
                               json={"mode": "targeted", "category": "ASI_01",
                                     "target_url": "http://c/chat"}).json()["run_id"]

    for chemin in (f"/runs/{run_id}", "/runs", "/audits"):
        assert client_admin.get(chemin).status_code == 401, (
            f"{chemin} se lit encore sans clef")
        assert client_admin.get(
            chemin, headers={"X-API-Key": "amorce-admin"}).status_code == 200


def test_les_identifiants_de_la_CIBLE_ne_sont_jamais_rendus(client_admin):
    """`AuditRequest.headers` porte le `Bearer` d'acces a la cible.

    LE TROU, MESURE
        La requete complete etait stockee en clair dans `runs.request` et rendue
        par `/runs/{id}`. Un jeton d'acces a un systeme interne se retrouvait donc
        dans une base ET dans une reponse HTTP. Verifie en direct avant
        correctif : 200 et le jeton en clair.

    Ce test exige les DEUX moities : rien ne fuit, et l'information utile — qu'un
    audit visait une cible authentifiee — reste lisible.
    """
    jeton = "Bearer JETON-QUI-NE-DOIT-PAS-FUIR"
    run_id = client_admin.post(
        "/audits", headers={"X-API-Key": "amorce-admin"},
        json={"mode": "targeted", "category": "ASI_01",
              "target_url": "http://c/chat",
              "headers": {"Authorization": jeton}}).json()["run_id"]

    corps = client_admin.get(f"/runs/{run_id}",
                             headers={"X-API-Key": "amorce-admin"}).text
    assert "JETON-QUI-NE-DOIT-PAS-FUIR" not in corps, (
        "les identifiants de la cible ressortent par l'API")
    assert "masqué" in corps, (
        "la PRESENCE d'en-tetes doit rester visible : savoir qu'un audit visait "
        "une cible authentifiee aide a relire son resultat")

    # EN REVANCHE, LE MAGASIN LE GARDE — ET C'EST VOULU.
    #     Premiere version de ce test : exiger qu'il n'y soit pas non plus. Elle
    #     etait fausse. L'ouvrier RECHARGE la requete en `AuditRequest` pour
    #     executer l'audit plus tard : sans la vraie valeur, un audit mis en file
    #     ne pourrait plus jamais tourner. On aurait remplace une fuite par une
    #     panne de production.
    #
    #     Ce test verrouille donc le contrat REEL : la valeur vit en base, elle
    #     ne sort jamais de l'API. Le secret au repos est une limite assumee,
    #     inscrite au registre — les cles du framework, elles, sont hachees ; un
    #     secret de cible ne peut pas l'etre, il doit etre rejoue.
    from api import store
    assert "JETON-QUI-NE-DOIT-PAS-FUIR" in str(store.lire_run(run_id)), (
        "l'ouvrier ne pourrait plus executer un audit mis en file")
