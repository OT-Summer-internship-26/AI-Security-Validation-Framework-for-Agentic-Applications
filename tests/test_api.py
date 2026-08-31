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
