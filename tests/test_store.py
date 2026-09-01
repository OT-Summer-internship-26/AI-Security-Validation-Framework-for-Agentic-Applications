"""
test_store.py — L'etat des audits survit au processus, et les cles ont un role.

POURQUOI CE FICHIER
    Trois defauts de production tenaient a la meme cause : l'API EXECUTAIT au
    lieu d'orchestrer.

      · l'etat vivait dans un `dict` du processus web — un redemarrage perdait
        le suivi de tous les audits, et deux repliques ne voyaient pas les memes ;
      · les audits d'une heure tournaient dans un fil du serveur web, tues au
        moindre redeploiement ;
      · une seule cle statique : pas de rotation, pas de roles, aucune
        attribution de qui a lance un audit contre un systeme interne.

    Ces tests verrouillent les garanties qui les remplacent. Aucune ne se voit a
    la lecture du code : une file non atomique fait simplement tourner un audit
    DEUX fois, et une cle revoquee qui marche encore ne leve aucune erreur.

AUCUN RESEAU, AUCUN LLM : base SQLite temporaire.
"""

from __future__ import annotations

import collections
import sys
import threading
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))


@pytest.fixture()
def magasin(monkeypatch, tmp_path):
    """Magasin isole dans une base temporaire, ferme apres le test."""
    from api import store

    monkeypatch.setenv("AUDIT_STATE_DB", str(tmp_path / "essai.sqlite"))
    store.fermer()
    store.init()
    yield store
    store.fermer()


REQUETE = {"mode": "targeted", "category": "ASI_01", "target_url": "http://cible/chat"}


# --------------------------------------------------------------------------- #
# Persistance : c'est tout l'objet du module.
# --------------------------------------------------------------------------- #

def test_une_execution_survit_a_la_perte_de_connexion(magasin):
    """Un redemarrage de l'API ne doit plus perdre le suivi d'un audit en cours.

    On simule le redemarrage en fermant la connexion : l'execution doit se
    relire integralement, journal et attribution compris.
    """
    magasin.creer_run("run-1", REQUETE, cree_par="key-secu")
    magasin.ajouter_log("run-1", "info", "demarrage")
    magasin.fermer()                       # « redemarrage »

    r = magasin.lire_run("run-1")
    assert r is not None and r["status"] == "queued"
    assert r["created_by"] == "key-secu", "l'attribution doit survivre aussi"
    assert r["logs"][0]["text"] == "demarrage"


def test_le_suivi_se_lit_de_maniere_incrementale(magasin):
    """Le dashboard interroge toutes les 1,5 s : retransferer tout le journal a
    chaque fois le rendrait inutilisable sur un audit d'une heure."""
    magasin.creer_run("run-1", REQUETE)
    for i in range(5):
        magasin.ajouter_log("run-1", "info", f"ligne {i}")
    assert len(magasin.lire_run("run-1", depuis_log=3)["logs"]) == 2
    assert magasin.lire_run("run-1")["log_count"] == 5


# --------------------------------------------------------------------------- #
# La file : deux ouvriers ne peuvent pas prendre le meme travail.
# --------------------------------------------------------------------------- #

def test_deux_ouvriers_ne_prennent_pas_le_meme_travail(magasin):
    """LA garantie de la file. Sans elle, l'audit tourne DEUX fois : deux fois le
    cout, et deux fichiers de resultat concurrents pour la meme execution."""
    magasin.creer_run("run-1", REQUETE)
    assert magasin.prendre_run("worker-a")["run_id"] == "run-1"
    assert magasin.prendre_run("worker-b") is None


def test_la_file_resiste_a_huit_ouvriers_concurrents(magasin):
    """Le sequentiel ne prouve rien ici : c'est la course qu'il faut eprouver."""
    for i in range(20):
        magasin.creer_run(f"run-{i:02d}", REQUETE)

    pris: list[str] = []
    verrou = threading.Lock()

    def ouvrier(n: int) -> None:
        magasin.fermer()                   # chaque fil ouvre SA connexion
        magasin.init()
        while (r := magasin.prendre_run(f"w{n}")) is not None:
            with verrou:
                pris.append(r["run_id"])

    fils = [threading.Thread(target=ouvrier, args=(i,)) for i in range(8)]
    for f in fils:
        f.start()
    for f in fils:
        f.join()

    doublons = [k for k, v in collections.Counter(pris).items() if v > 1]
    assert len(pris) == 20 and not doublons, f"pris deux fois : {doublons}"


def test_un_ouvrier_mort_ne_bloque_pas_un_audit_pour_toujours(magasin):
    """Un pod evince au milieu d'un audit doit voir son travail repris.

    C'est ce qui distingue une file d'une simple table.
    """
    magasin.creer_run("run-1", REQUETE)
    magasin.prendre_run("worker-mort")
    assert magasin.reprendre_abandonnes(limite_s=10_000) == 0, "un vivant est laisse"
    assert magasin.reprendre_abandonnes(limite_s=0) == 1
    assert magasin.lire_run("run-1")["status"] == "queued"


def test_le_battement_de_coeur_protege_un_travail_qui_avance(magasin):
    """Un audit passe de longues minutes sans rien emettre — DeepTeam ne trace
    qu'en fin de categorie. Sans battement, on lui retirerait son travail."""
    magasin.creer_run("run-1", REQUETE)
    magasin.prendre_run("worker-a")
    magasin.battre("run-1")
    assert magasin.reprendre_abandonnes(limite_s=10_000) == 0


# --------------------------------------------------------------------------- #
# Cles : rotation, roles, attribution.
# --------------------------------------------------------------------------- #

def test_la_cle_en_clair_n_est_visible_qu_a_la_creation(magasin):
    """Seule l'empreinte est conservee : un inventaire ne doit rien divulguer."""
    import json
    ident, cle = magasin.creer_cle("equipe secu")
    assert cle.startswith("aisec_")
    assert cle not in json.dumps(magasin.lister_cles())
    assert magasin.verifier_cle(cle)["id"] == ident


def test_une_cle_revoquee_est_refusee(magasin):
    """C'est ce qui rend la rotation possible. Sans revocation, une cle
    distribuee une fois vaut pour toujours."""
    ident, cle = magasin.creer_cle("temporaire")
    assert magasin.verifier_cle(cle) is not None
    assert magasin.revoquer_cle(ident) is True
    assert magasin.verifier_cle(cle) is None
    assert magasin.revoquer_cle(ident) is False, "revoquer deux fois n'est pas un succes"


def test_une_cle_expiree_est_refusee(magasin):
    _, cle = magasin.creer_cle("hier", expire_dans_jours=-1)
    assert magasin.verifier_cle(cle) is None


def test_les_roles_se_comparent_par_niveau_et_non_par_nom(magasin):
    """Comparer par egalite obligerait a lister tous les roles superieurs a
    chaque point de controle — et a en oublier un le jour d'un ajout."""
    assert magasin.role_suffisant("admin", "operator")
    assert magasin.role_suffisant("operator", "operator")
    assert not magasin.role_suffisant("viewer", "operator")
    assert not magasin.role_suffisant("role-inconnu", "viewer")


def test_un_role_inconnu_est_refuse_a_la_creation(magasin):
    with pytest.raises(ValueError):
        magasin.creer_cle("x", role="superadmin")


def test_autotest_store(magasin):
    """Rejoue les 10 controles du module."""
    magasin.demo()
