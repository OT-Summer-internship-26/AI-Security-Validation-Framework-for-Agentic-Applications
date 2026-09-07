"""
test_worker.py — L'ouvrier qui execute TOUS les audits en production.

POURQUOI CE FICHIER
    `scripts/worker.py` est le composant qui execute reellement les audits
    depuis que l'API s'est mise a orchestrer. Il etait NEUF, CRITIQUE, et
    couvert par ZERO test — un diagnostic de couverture l'a montre.

    Ce qu'un silence ici coute : une boucle qui ne prend rien, un arret qui
    n'arrete pas, une reprise qui ne reprend pas. Aucun de ces trois ne leve
    d'erreur — le service tourne, et plus aucun audit n'avance.

AUCUN RESEAU, AUCUN LLM : l'execution reelle est interceptee, on eprouve la
BOUCLE et non l'audit (deja couvert ailleurs).
"""

from __future__ import annotations

import importlib.util
import sys
import threading
import time
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))


def _charger_worker():
    """Charge `scripts/worker.py` comme module (il n'est pas dans un paquet)."""
    spec = importlib.util.spec_from_file_location(
        "worker_sous_test", RACINE / "scripts" / "worker.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def ouvrier(monkeypatch, tmp_path):
    """Ouvrier branche sur un magasin temporaire, sans execution reelle."""
    from api import store

    monkeypatch.setenv("AUDIT_STATE_DB", str(tmp_path / "w.sqlite"))
    store.fermer()
    store.init()
    w = _charger_worker()
    w._ARRET.clear()
    yield w
    w._ARRET.set()
    store.fermer()


REQUETE = {"mode": "targeted", "category": "ASI_01", "target_url": "http://c/chat"}


def test_l_ouvrier_prend_et_termine_un_travail(ouvrier, monkeypatch):
    """La boucle nominale. Si elle ne prend rien, le service tourne et plus aucun
    audit n'avance — sans qu'aucune erreur ne soit levee."""
    from api import store

    executes: list[str] = []
    monkeypatch.setattr(ouvrier, "traiter",
                        lambda t: executes.append(t["run_id"]))

    store.creer_run("run-1", REQUETE)
    assert ouvrier.boucle(une_seule=True) == 0
    assert executes == ["run-1"]
    assert store.lire_run("run-1")["status"] == "running", (
        "la prise doit marquer l'execution AVANT de la traiter")


def test_une_file_vide_ne_bloque_pas_le_mode_une_seule(ouvrier):
    """`--once` sert en CI : il doit rendre la main, pas attendre indefiniment."""
    assert ouvrier.boucle(une_seule=True) == 0


def test_l_ouvrier_reprend_les_travaux_abandonnes_AU_DEMARRAGE(ouvrier, monkeypatch):
    """LE moment utile de la reprise : un pod qui redemarre doit reprendre ce
    qu'il avait laisse. Sans cela, un travail abandonne reste bloque pour
    toujours et personne ne le voit."""
    from api import store

    store.creer_run("run-1", REQUETE)
    store.prendre_run("ouvrier-mort")
    store._conn().execute("UPDATE runs SET heartbeat=? WHERE id='run-1'",
                          (time.time() - 100_000,))

    pris: list[str] = []
    monkeypatch.setattr(ouvrier, "traiter", lambda t: pris.append(t["run_id"]))
    ouvrier.boucle(une_seule=True)
    assert pris == ["run-1"], "le travail abandonne doit etre repris au demarrage"


def test_une_execution_qui_echoue_est_marquee_ET_journalisee(ouvrier, monkeypatch):
    """Un audit qui plante ne doit pas rester « running » pour toujours : il
    serait repris en boucle par chaque ouvrier qui demarre."""
    from api import store

    # On fait echouer la RECONSTRUCTION de l'execution, pas le module entier.
    #
    # Une premiere version remplacait `sys.modules["api.main"]`. Elle passait
    # isolee et echouait en suite complete — le pire cas : `import api.main as
    # api` lit l'ATTRIBUT du paquet parent des que celui-ci est deja importe,
    # pas `sys.modules`. Le vrai `_execute` tournait alors pour de bon.
    import api.main as api_reelle

    def refuse(travail):
        raise RuntimeError("cible injoignable")

    monkeypatch.setattr(api_reelle.Run, "depuis_magasin", staticmethod(refuse))
    store.creer_run("run-1", REQUETE)
    travail = store.prendre_run("w1")
    ouvrier.traiter(travail)

    r = store.lire_run("run-1")
    assert r["status"] == "failed"
    assert "cible injoignable" in (r["error"] or "")
    assert any("cible injoignable" in l["text"] for l in r["logs"]), (
        "la cause doit apparaitre dans le journal de l'execution, pas seulement "
        "dans la sortie standard de l'ouvrier"
    )


def test_le_battement_de_coeur_tourne_PENDANT_le_traitement(ouvrier, monkeypatch):
    """Un audit passe de longues minutes sans rien emettre. Sans battement, un
    autre ouvrier lui retirerait son travail alors qu'il avance tres bien."""
    from api import store

    monkeypatch.setattr(ouvrier, "BATTEMENT_S", 0.05)
    store.creer_run("run-1", REQUETE)
    store.prendre_run("w1")
    store._conn().execute("UPDATE runs SET heartbeat=? WHERE id='run-1'", (0.0,))

    stop = threading.Event()
    fil = threading.Thread(target=ouvrier._battre_en_boucle, args=("run-1", stop),
                           daemon=True)
    fil.start()
    time.sleep(0.25)
    stop.set()
    fil.join(timeout=2)

    assert store._conn().execute(
        "SELECT heartbeat FROM runs WHERE id='run-1'").fetchone()[0] > 0.0


def test_l_arret_demande_sort_de_la_boucle(ouvrier, monkeypatch):
    """SIGTERM (ce que Kubernetes envoie) doit faire cesser de PRENDRE de
    nouveaux travaux. Une boucle qui l'ignore serait tuee de force, et son
    travail en cours perdu au lieu d'etre repris proprement."""
    from api import store

    monkeypatch.setattr(ouvrier, "INTERVALLE_S", 0.01)
    store.creer_run("run-1", REQUETE)

    def traiter_puis_arreter(travail):
        ouvrier._ARRET.set()

    monkeypatch.setattr(ouvrier, "traiter", traiter_puis_arreter)
    fil = threading.Thread(target=ouvrier.boucle, daemon=True)
    fil.start()
    fil.join(timeout=5)
    assert not fil.is_alive(), "la boucle doit sortir quand l'arret est demande"


def test_deux_ouvriers_ne_traitent_pas_le_meme_travail(ouvrier, monkeypatch):
    """La garantie de la file, vue depuis l'ouvrier : ce qui compte n'est pas que
    `prendre_run` soit atomique, mais que la BOUCLE en herite."""
    from api import store

    store.creer_run("run-1", REQUETE)
    traites: list[str] = []
    verrou = threading.Lock()

    def traiter(travail):
        with verrou:
            traites.append(travail["run_id"])

    monkeypatch.setattr(ouvrier, "traiter", traiter)
    monkeypatch.setattr(ouvrier, "_identite", lambda: "w-partage")

    fils = [threading.Thread(target=ouvrier.boucle, kwargs={"une_seule": True})
            for _ in range(4)]
    for f in fils:
        f.start()
    for f in fils:
        f.join(timeout=10)

    assert traites == ["run-1"], f"traite plusieurs fois : {traites}"


def test_l_identite_de_l_ouvrier_est_lisible_dans_le_suivi(ouvrier, monkeypatch):
    """« repris par worker-7f3a » dit quelque chose ; « worker » non."""
    monkeypatch.setenv("AUDIT_WORKER_ID", "ouvrier-de-nuit")
    assert ouvrier._identite() == "ouvrier-de-nuit"
    monkeypatch.delenv("AUDIT_WORKER_ID")
    assert ouvrier._identite().startswith("worker-")


def test_le_menage_REPASSE_pendant_que_l_ouvrier_tourne(ouvrier, monkeypatch):
    """La purge ne doit pas dependre d'un redemarrage pour avoir lieu.

    Elle ne tournait qu'au demarrage de la boucle. Un ouvrier en
    `restart: always` qui ne tombe jamais ne purgeait donc JAMAIS — et c'est
    exactement celui qui tourne depuis six mois qui a le plus a purger. Le
    volume repartait alors en croissance non bornee sans qu'aucune erreur ne
    soit levee : le service tourne, le disque se remplit.
    """
    from api import store

    appels: list[float] = []

    def purger_espion(*a, **k):
        appels.append(time.time())
        if len(appels) >= 2:          # demarrage + au moins un passage en boucle
            ouvrier._ARRET.set()
        return {"jours": 30, "runs": 0, "logs": 0, "echanges": 0}

    monkeypatch.setattr(store, "purger", purger_espion)
    monkeypatch.setattr(ouvrier, "MENAGE_S", 0.0)
    monkeypatch.setattr(ouvrier, "INTERVALLE_S", 0.01)

    fil = threading.Thread(target=ouvrier.boucle, daemon=True)
    fil.start()
    fil.join(timeout=5)

    assert not fil.is_alive(), "la boucle n'est pas sortie"
    assert len(appels) >= 2, (
        "la purge n'a eu lieu qu'au demarrage : un ouvrier qui ne redemarre "
        "jamais ne purge jamais")
