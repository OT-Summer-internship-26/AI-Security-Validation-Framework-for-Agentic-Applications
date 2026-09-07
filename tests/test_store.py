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


def test_la_condition_atomique_du_UPDATE_protege_vraiment(magasin, monkeypatch):
    """La prise repose sur DEUX barrieres, et le sequentiel n'en eprouve qu'une.

    `prendre_run` filtre d'abord par `SELECT ... WHERE status='queued'`, puis
    verrouille par `UPDATE ... WHERE id=? AND status='queued'`. En sequentiel le
    SELECT suffit : retirer la condition du UPDATE ne casse rien de visible.
    Une premiere version de ce test ecrivait son PROPRE UPDATE — elle eprouvait
    donc SQLite, pas `prendre_run`. Un test de mutation l'a montre.

    C'est pourtant la seconde barriere qui compte : en concurrence, deux ouvriers
    passent le SELECT ensemble avant que l'un des deux n'ecrive. On reproduit
    exactement cette fenetre en forcant le SELECT a designer une execution DEJA
    prise ; `prendre_run` doit alors rendre None, sinon l'audit tourne deux fois.
    """
    magasin.creer_run("run-1", REQUETE)
    assert magasin.prendre_run("worker-a")["run_id"] == "run-1"   # elle est 'running'

    vrai_conn = magasin._conn

    class ConnexionQuiRejoueLaCourse:
        """Fait voir au SELECT une execution que `worker-a` vient de prendre."""

        def __init__(self, reelle):
            self._reelle = reelle

        def execute(self, sql, params=()):
            if sql.lstrip().upper().startswith("SELECT ID FROM RUNS"):
                # La fenetre de course : le SELECT a lu AVANT l'ecriture d'autrui.
                return self._reelle.execute("SELECT id FROM runs WHERE id='run-1'")
            return self._reelle.execute(sql, params)

        def __getattr__(self, nom):
            return getattr(self._reelle, nom)

    monkeypatch.setattr(magasin, "_conn",
                        lambda: ConnexionQuiRejoueLaCourse(vrai_conn()))

    assert magasin.prendre_run("worker-b") is None, (
        "sans la condition `status='queued'` dans le UPDATE, worker-b prendrait "
        "une execution deja detenue par worker-a — l'audit tournerait deux fois")

    monkeypatch.undo()
    assert magasin.lire_run("run-1")["worker"] == "worker-a"


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
    import time

    magasin.creer_run("run-1", REQUETE)
    magasin.prendre_run("worker-mort")
    assert magasin.reprendre_abandonnes(limite_s=10_000) == 0, "un vivant est laisse"

    # LA FRONTIERE, fixee EXACTEMENT plutot que laissee au hasard de l'horloge.
    #
    # Une premiere version appelait `reprendre_abandonnes(limite_s=0)` : quelques
    # microsecondes s'etant ecoulees depuis la prise, `heartbeat < seuil` etait
    # vrai et le test passait AUSSI avec la comparaison stricte — il ne
    # protegeait donc pas le correctif. Un test de mutation l'a montre.
    #
    # Ici, on pose un battement EGAL au seuil : c'est le cas que la resolution
    # d'horloge de Windows (~15 ms) produit reellement, et le seul qui distingue
    # `<` de `<=`.
    fige = time.time() - 100.0
    magasin._conn().execute("UPDATE runs SET heartbeat=? WHERE id='run-1'", (fige,))

    class HorlogeFigee:
        """Rend `time.time()` exactement egal au battement + la limite."""

        @staticmethod
        def time() -> float:
            return fige + 100.0

    vrai_time = magasin.time
    magasin.time = HorlogeFigee                     # type: ignore[assignment]
    try:
        repris = magasin.reprendre_abandonnes(limite_s=100)
    finally:
        magasin.time = vrai_time                    # type: ignore[assignment]

    assert repris == 1, (
        "un battement EXACTEMENT au seuil est perime : avec `<` il ne l'est pas, "
        "et le travail reste bloque pour toujours")
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


# --------------------------------------------------------------------------- #
# Fonctions que le diagnostic de couverture avait trouvees SANS aucun test.
# --------------------------------------------------------------------------- #

def test_maj_run_persiste_chaque_champ_de_suivi(magasin):
    """`Run.__setattr__` appelle cette fonction a CHAQUE changement d'etat :
    c'est le coeur de la persistance, et rien ne la testait.

    Les listes doivent etre serialisees, sinon SQLite refuse le parametre et le
    suivi s'arrete en silence — un audit resterait bloque a « Demarrage ».
    """
    magasin.creer_run("run-1", REQUETE)
    magasin.maj_run("run-1", status="running", progress=40, stage="DeepTeam",
                    categories=["ASI_01", "ASI_05"],
                    result_files=["a.json", "b.json"], error=None)
    r = magasin.lire_run("run-1")
    assert r["status"] == "running" and r["progress"] == 40
    assert r["categories"] == ["ASI_01", "ASI_05"], "les listes doivent revenir en LISTES"
    assert r["result_files"] == ["a.json", "b.json"]

    # Un appel sans champ ne doit pas produire de SQL invalide.
    magasin.maj_run("run-1")
    assert magasin.lire_run("run-1")["progress"] == 40


def test_les_echanges_avec_la_cible_sont_persistes_et_lus_par_curseur(magasin):
    """Le dashboard affiche les echanges EN DIRECT : ils doivent survivre au
    processus comme le reste, et se lire de maniere incrementale."""
    magasin.creer_run("run-1", REQUETE)
    for i in range(4):
        magasin.ajouter_echange("run-1", {"n": i, "prompt": f"p{i}", "response": "r"})
    magasin.fermer()                        # « redemarrage »

    r = magasin.lire_run("run-1")
    assert r["exchange_count"] == 4
    assert r["exchanges"][0]["prompt"] == "p0"
    assert len(magasin.lire_run("run-1", depuis_echange=3)["exchanges"]) == 1


def test_lister_runs_rend_les_plus_recents_sans_les_journaux(magasin):
    """`GET /runs` sert la liste : y joindre les journaux la rendrait enorme sur
    un audit d'une heure (des milliers de lignes par execution)."""
    import time
    for i in range(3):
        magasin.creer_run(f"run-{i}", REQUETE, cree_par=f"key-{i}")
        magasin.ajouter_log(f"run-{i}", "info", "x" * 100)
        time.sleep(0.01)                    # horodatages distincts

    runs = magasin.lister_runs()
    assert [r["run_id"] for r in runs] == ["run-2", "run-1", "run-0"], "plus recent d'abord"
    assert all("logs" not in r for r in runs), "la liste ne doit pas porter les journaux"
    assert runs[0]["created_by"] == "key-2", "l'attribution reste visible dans la liste"
    assert len(magasin.lister_runs(limite=2)) == 2


def test_compter_actifs_voit_TOUTES_les_repliques(magasin):
    """`/health` expose ce compteur : il doit refleter la charge REELLE du
    service, pas seulement celle du processus qui repond."""
    magasin.creer_run("run-1", REQUETE)     # queued
    magasin.creer_run("run-2", REQUETE)
    magasin.prendre_run("w1")               # -> running
    assert magasin.compter_actifs() == 2, "queued ET running comptent comme actifs"

    magasin.maj_run("run-1", status="completed")
    magasin.maj_run("run-2", status="failed")
    assert magasin.compter_actifs() == 0


def test_le_chemin_de_la_base_suit_la_configuration(magasin, monkeypatch, tmp_path):
    """En conteneur, la base doit vivre sur le VOLUME, pas sur le disque
    ephemere. Et elle doit rester avec les resultats : une instance qui voit les
    executions sans voir les fichiers afficherait des audits termines dont le
    rapport est introuvable."""
    monkeypatch.setenv("AUDIT_STATE_DB", str(tmp_path / "ailleurs" / "s.sqlite"))
    assert magasin.db_path() == (tmp_path / "ailleurs" / "s.sqlite").resolve()

    monkeypatch.delenv("AUDIT_STATE_DB")
    monkeypatch.setenv("AUDIT_DATA_DIR", str(tmp_path / "volume"))
    from workflow.paths import results_dir
    assert magasin.db_path().parent == results_dir().parent, (
        "la base doit vivre avec les resultats d'audit")


# --------------------------------------------------------------------------- #
# Schéma versionné : ce qui rend le RETOUR ARRIÈRE sur état durable.
# --------------------------------------------------------------------------- #

def test_une_base_neuve_est_estampillee(monkeypatch, tmp_path):
    """Sans estampille, aucune migration future ne saurait quoi appliquer."""
    from api import store

    monkeypatch.setenv("AUDIT_STATE_DB", str(tmp_path / "neuve.sqlite"))
    store.fermer()
    try:
        store.init()
        assert store.version_schema() == store.SCHEMA_VERSION
    finally:
        store.fermer()


def test_un_volume_ANTERIEUR_est_adopte_sans_perte(monkeypatch, tmp_path):
    """Les bases d'avant ce mecanisme portent les tables et AUCUNE estampille.

    Le piege qu'il ecarte : estampiller en RECREANT, ce qui perdrait les
    executions et les cles d'un volume de production. La migration 1 est en
    `IF NOT EXISTS` exactement pour ca — appliquee a une base existante, elle ne
    fait rien, et la base est simplement reconnue.
    """
    import sqlite3

    from api import store

    base = tmp_path / "ancienne.sqlite"
    c = sqlite3.connect(base)
    c.executescript(
        "CREATE TABLE runs (id TEXT PRIMARY KEY, status TEXT NOT NULL, "
        "progress INTEGER NOT NULL DEFAULT 0, stage TEXT NOT NULL DEFAULT '', "
        "request TEXT NOT NULL, created_by TEXT NOT NULL DEFAULT '', "
        "started_at TEXT NOT NULL, claimed_at TEXT, heartbeat REAL, worker TEXT, "
        "finished_at TEXT, result_file TEXT, result_files TEXT, categories TEXT, "
        "error TEXT);")
    c.execute("INSERT INTO runs (id, status, request, started_at) "
              "VALUES ('avant-migration', 'completed', '{}', '2026-01-01')")
    c.commit()
    c.close()
    assert sqlite3.connect(base).execute("PRAGMA user_version").fetchone()[0] == 0

    monkeypatch.setenv("AUDIT_STATE_DB", str(base))
    store.fermer()
    try:
        store.init()
        assert store.version_schema() == store.SCHEMA_VERSION, "la base n'a pas ete estampillee"
        garde = store._conn().execute(
            "SELECT id FROM runs WHERE id = 'avant-migration'").fetchone()
        assert garde is not None, (
            "une execution d'un volume de PRODUCTION a disparu a la migration")
    finally:
        store.fermer()


def test_une_base_PLUS_RECENTE_que_le_code_REFUSE_de_demarrer(monkeypatch, tmp_path):
    """Le retour arriere dangereux doit echouer AU DEMARRAGE, pas en production.

    POURQUOI CE TEST EXISTE
        La chaine publie des images etiquetees par SHA pour permettre le retour
        arriere. Mais revenir a une image ANCIENNE devant une base RECENTE est le
        scenario symetrique de celui qu'on vient de corriger, et il etait tout
        aussi silencieux : `CREATE TABLE IF NOT EXISTS` ne dit rien, et la panne
        arrive a la premiere requete qui touche une colonne absente — des heures
        plus tard, en pleine execution, jamais au healthcheck.

        Un conteneur qui refuse de demarrer se voit. Une requete qui echoue a
        3 h du matin, non.
    """
    import sqlite3

    from api import store

    base = tmp_path / "future.sqlite"
    c = sqlite3.connect(base)
    c.execute(f"PRAGMA user_version = {store.SCHEMA_VERSION + 1}")
    c.commit()
    c.close()

    monkeypatch.setenv("AUDIT_STATE_DB", str(base))
    store.fermer()
    try:
        with pytest.raises(RuntimeError) as erreur:
            store.init()
        message = str(erreur.value)
        assert "PLUS ANCIENNE" in message, "le message doit dire QUI est en retard"
        assert "backup_volume" in message, (
            "un refus qui ne dit pas quoi faire se contourne au hasard")
    finally:
        store.fermer()


def test_deux_demarrages_SIMULTANES_ne_migrent_pas_deux_fois(monkeypatch, tmp_path):
    """`docker compose` lance l'API et l'ouvrier EN MEME TEMPS.

    LE BUG QU'IL ATTRAPE, MESURE
        La premiere version lisait `user_version` AVANT la transaction : deux
        processus lisaient donc « 0 » et appliquaient la meme migration deux
        fois. Invisible tant que la migration 1 est en `IF NOT EXISTS` — mais
        toutes les suivantes seront des `ALTER TABLE`. Mesure avec une migration
        non idempotente : 6 demarrages simultanes -> echec
        `duplicate column name`. Ca se serait produit exactement le jour du
        deploiement qui change le schema, sur l'un des deux services.

        Le correctif : `BEGIN IMMEDIATE` prend le verrou d'ecriture, et la
        version est RELUE dedans. Le second processus attend, puis ne fait rien.

    POURQUOI PLUSIEURS TOURS, ET PAS UN SEUL
        Une course ne se reproduit pas a coup sur. Avec un seul tour, ce test
        laissait passer la regression environ une fois sur sept — constate en
        rejouant le controle de mutation : « 17/17, 16/17, 17/17 ». Un filet qui
        n'attrape que parfois est un filet decoratif avec de la chance.

        Cinq tours sur cinq bases neuves ramenent la probabilite de rater la
        regression sous le millieme, sans rendre le test lent (quelques dizaines
        de millisecondes par tour, en memoire).
    """
    import threading

    from api import store

    def un_tour(numero: int) -> list[str]:
        """Une base neuve, une migration NON idempotente, six demarrages d'un coup."""
        monkeypatch.setenv("AUDIT_STATE_DB", str(tmp_path / f"course{numero}.sqlite"))
        store.fermer()
        store.init()

        version_suivante = store.SCHEMA_VERSION + 1
        monkeypatch.setattr(
            store, "_MIGRATIONS",
            [*store._MIGRATIONS,
             (version_suivante, "ALTER TABLE runs ADD COLUMN essai_course TEXT;")])
        monkeypatch.setattr(store, "SCHEMA_VERSION", version_suivante)

        erreurs: list[str] = []
        depart = threading.Barrier(6)

        def demarre():
            try:
                store.fermer()
                depart.wait(timeout=5)   # tous partent au meme instant
                store.init()
            except threading.BrokenBarrierError:
                pass
            except Exception as exc:
                erreurs.append(f"{type(exc).__name__}: {exc}")

        fils = [threading.Thread(target=demarre) for _ in range(6)]
        for f in fils:
            f.start()
        for f in fils:
            f.join()

        colonnes = [r[1] for r in store._conn().execute("PRAGMA table_info(runs)")]
        if colonnes.count("essai_course") != 1:
            erreurs.append(f"colonne ajoutee {colonnes.count('essai_course')} fois")
        if store.version_schema() != version_suivante:
            erreurs.append(f"version {store.version_schema()} au lieu de {version_suivante}")

        # La version du module a ete relevee par le monkeypatch de ce tour ; on la
        # remet pour que le tour suivant reparte de la vraie valeur.
        monkeypatch.undo()
        return erreurs

    try:
        for tour in range(5):
            erreurs = un_tour(tour)
            assert not erreurs, f"tour {tour} : migration appliquee plusieurs fois — {erreurs[:2]}"
    finally:
        store.fermer()


def test_la_purge_retire_le_VOLUME_et_garde_la_TRACE(magasin):
    """`run_logs` et `run_exchanges` n'etaient JAMAIS nettoyes.

    Chaque audit y depose un transcript complet — chaque prompt, chaque reponse
    de la cible. Croissance non bornee sur le volume persistant, exactement ce
    qu'on a corrige pour les journaux Docker avec `max-size`.

    CE QUE CE TEST EXIGE, ET LES TROIS CAS COMPTENT
      · une execution TERMINEE et ANCIENNE perd son detail ;
      · une execution recente le garde ;
      · une execution EN COURS n'est jamais touchee — purger un audit qui tourne
        lui ferait perdre son suivi sous les pieds de l'operateur.

    Et la ligne `runs` survit dans les trois cas : c'est elle qui dit QUI a lance
    QUOI contre QUELLE cible. La perdre effacerait la tracabilite qui justifie
    les cles a roles.
    """
    from datetime import datetime, timedelta, timezone

    vieux = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    cas = [("ancien", vieux), ("recent", datetime.now(timezone.utc).isoformat()),
           ("en_cours", None)]
    for rid, fin in cas:
        magasin.creer_run(rid, REQUETE, "op")
        for i in range(5):
            magasin.ajouter_log(rid, "info", f"ligne {i}")
            magasin.ajouter_echange(rid, {"n": i, "prompt": "p", "response": "r"})
        if fin:
            magasin.maj_run(rid, finished_at=fin, status="completed")

    bilan = magasin.purger(jours=30)
    assert bilan["runs"] == 1 and bilan["logs"] == 5 and bilan["echanges"] == 5

    c = magasin._conn()
    avec_detail = {r[0] for r in c.execute("SELECT DISTINCT run_id FROM run_logs")}
    assert avec_detail == {"recent", "en_cours"}, (
        "la purge a touche une execution recente ou en cours")
    lignes = {r[0] for r in c.execute("SELECT id FROM runs")}
    assert lignes == {"ancien", "recent", "en_cours"}, (
        "la purge a efface la TRACE, pas seulement le volume")


def test_la_retention_est_desactivable(magasin):
    """`AUDIT_RETENTION_JOURS=0` doit tout garder.

    Une purge qu'on ne peut pas arreter est une perte de donnees qu'on subit :
    un audit conteste six mois plus tard a besoin de son transcript.
    """
    from datetime import datetime, timedelta, timezone

    magasin.creer_run("tres-vieux", REQUETE, "op")
    magasin.ajouter_log("tres-vieux", "info", "x")
    magasin.maj_run("tres-vieux", status="completed",
                    finished_at=(datetime.now(timezone.utc) - timedelta(days=900)).isoformat())

    assert magasin.purger(jours=0)["logs"] == 0
    assert magasin._conn().execute(
        "SELECT COUNT(*) FROM run_logs").fetchone()[0] == 1
