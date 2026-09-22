"""
store.py — L'état des exécutions et des clés, sur disque partagé.

LES TROIS PROBLÈMES QU'IL RÉSOUT, ET POURQUOI C'EST LE MÊME
    1. **L'état vivait en mémoire** (`_RUNS: dict`). Un redémarrage — déploiement,
       éviction de pod, simple `restart` — perdait le suivi de tous les audits.
       Deux répliques ne voyaient pas les mêmes exécutions, donc `GET /runs/{id}`
       répondait 404 une fois sur deux derrière un répartiteur.
    2. **Les audits tournaient dans un fil du processus web.** Un audit dure une
       heure ; le moindre redéploiement le tuait.
    3. **Une seule clé d'API statique** : pas de rotation, pas de rôles, aucune
       attribution. Impossible de savoir QUI a lancé un audit contre un système
       interne.

    Les trois disparaissent en sortant l'état du processus. L'API cesse
    d'EXÉCUTER pour ORCHESTRER : elle dépose un travail ici, un ouvrier séparé
    le prend, et l'état survit à tout le monde.

POURQUOI SQLITE ET PAS REDIS
    Redis est le choix habituel, et il ajoute un service à déployer, superviser
    et sauvegarder. Or ce framework monte DÉJÀ un volume partagé pour les
    résultats d'audit : y poser une base SQLite ne coûte aucune infrastructure
    nouvelle, et le mode WAL autorise plusieurs lecteurs pendant qu'un écrivain
    travaille — exactement notre forme d'usage (beaucoup de lectures de
    progression, peu d'écritures).

    PLAFOND ASSUMÉ : SQLite sur un volume RÉSEAU (NFS, EFS) verrouille mal. Pour
    quelques instances sur un volume local ou un disque bloc attaché, c'est sûr
    et éprouvé. Au-delà — dizaines d'ouvriers, volume réseau — il faut PostgreSQL
    ou Redis, et seule cette classe change : l'API et l'ouvrier n'en savent rien.

LA FILE D'ATTENTE
    Pas de courtier de messages : une table, et une prise de travail ATOMIQUE
    (`UPDATE … WHERE status='queued'`). Deux ouvriers ne peuvent pas prendre la
    même exécution — c'est la base de données qui l'interdit, pas une convention.

    Un ouvrier qui meurt laisserait son travail « en cours » pour toujours : il
    bat donc le cœur, et une exécution sans battement depuis un délai est remise
    en file. Sans cela, un pod évincé bloquerait un audit indéfiniment.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Au-delà de ce silence, l'ouvrier est présumé mort et son travail est repris.
# Généreux à dessein : un audit passe de longues minutes sans rien émettre
# (DeepTeam ne trace qu'en fin de catégorie), et reprendre trop tôt relancerait
# un travail qui avance très bien.
BATTEMENT_MAX_S = int(os.environ.get("AUDIT_WORKER_HEARTBEAT_MAX", "900"))

# Rôles, du moins au plus permissif. La comparaison se fait sur l'INDEX : ajouter
# un rôle intermédiaire ne demande alors de modifier aucun appelant.
ROLES = ("viewer", "operator", "admin")

_LOCAL = threading.local()


def db_path() -> Path:
    """Emplacement de la base. Sur le volume partagé, avec les résultats.

    Les séparer serait une erreur : une instance qui voit les exécutions sans
    voir les fichiers produits afficherait des audits terminés dont le rapport
    est introuvable.
    """
    from workflow.paths import data_dir

    brut = (os.environ.get("AUDIT_STATE_DB") or "").strip()
    return Path(brut).expanduser().resolve() if brut else data_dir() / "state.sqlite"


def _conn() -> sqlite3.Connection:
    """Connexion propre au fil d'exécution courant.

    Une connexion SQLite ne se partage pas entre fils. Uvicorn en utilise
    plusieurs ; une connexion unique donnerait des `ProgrammingError`
    intermittents, c'est-à-dire le pire des cas — ça marche en développement et
    ça casse sous charge.
    """
    c = getattr(_LOCAL, "conn", None)
    if c is not None:
        return c

    chemin = db_path()
    chemin.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(chemin, timeout=30, isolation_level=None,
                        check_same_thread=False)
    c.row_factory = sqlite3.Row
    # WAL : plusieurs lecteurs pendant qu'un écrivain travaille. Sans lui, chaque
    # lecture de progression bloquerait l'ouvrier qui écrit son journal.
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=30000")
    c.execute("PRAGMA synchronous=NORMAL")
    _LOCAL.conn = c
    return c


# --------------------------------------------------------------------------- #
# Schéma : versionné DANS la base, et migré explicitement
# --------------------------------------------------------------------------- #
#
# POURQUOI CE MÉCANISME EXISTE
#     Le schéma était créé par un simple `CREATE TABLE IF NOT EXISTS`. Tant qu'on
#     n'ajoute rien, ça marche. Le jour où une colonne s'ajoute à `runs` ou
#     `api_keys`, le `IF NOT EXISTS` **passe son chemin** sur un volume existant :
#     l'ancienne table survit, et ça casse à la PREMIÈRE REQUÊTE qui utilise la
#     colonne. Pas au démarrage, donc pas au healthcheck : en pleine production,
#     sur un `sqlite3.OperationalError: no such column`.
#
# ET SURTOUT : ÇA REND LE RETOUR ARRIÈRE SÛR.
#     La chaîne publie des images étiquetées par SHA précisément pour pouvoir
#     revenir en arrière (voir integration_guide §6). Mais revenir à une image
#     ANCIENNE devant une base RÉCENTE est le scénario symétrique, et il était
#     tout aussi silencieux. `init()` refuse désormais de démarrer dans ce cas,
#     avec un message qui dit quoi faire. Un conteneur qui ne démarre pas est
#     visible ; une requête qui échoue trois heures plus tard ne l'est pas.
#
# COMMENT AJOUTER UNE MIGRATION
#     1. écrire le SQL dans `_MIGRATIONS` avec le numéro suivant ;
#     2. incrémenter `SCHEMA_VERSION` ;
#     3. ne JAMAIS modifier une migration déjà publiée — les bases déployées
#        l'ont déjà appliquée, la réécrire ne les rattraperait pas.
#     Chaque migration s'exécute dans UNE transaction avec son estampillage :
#     une coupure de courant laisse la base soit avant, soit après, jamais entre.
SCHEMA_VERSION = 2

_MIGRATIONS: list[tuple[int, str]] = [
    # 1 — socle. Volontairement en `IF NOT EXISTS` : les volumes antérieurs à ce
    #     mécanisme portent déjà ces tables avec `user_version = 0`. Les appliquer
    #     ne fait rien, et la base est simplement estampillée — aucune reprise
    #     manuelle, aucune perte.
    (1, """
        CREATE TABLE IF NOT EXISTS runs (
            id            TEXT PRIMARY KEY,
            status        TEXT NOT NULL,
            progress      INTEGER NOT NULL DEFAULT 0,
            stage         TEXT NOT NULL DEFAULT '',
            request       TEXT NOT NULL,
            created_by    TEXT NOT NULL DEFAULT '',
            started_at    TEXT NOT NULL,
            claimed_at    TEXT,
            heartbeat     REAL,
            worker        TEXT,
            finished_at   TEXT,
            result_file   TEXT,
            result_files  TEXT,
            categories    TEXT,
            error         TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status, started_at);

        CREATE TABLE IF NOT EXISTS run_logs (
            run_id TEXT NOT NULL, seq INTEGER NOT NULL,
            t TEXT NOT NULL, level TEXT NOT NULL, text TEXT NOT NULL,
            PRIMARY KEY (run_id, seq)
        );
        CREATE TABLE IF NOT EXISTS run_exchanges (
            run_id TEXT NOT NULL, seq INTEGER NOT NULL, payload TEXT NOT NULL,
            PRIMARY KEY (run_id, seq)
        );
        CREATE TABLE IF NOT EXISTS api_keys (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            hash        TEXT NOT NULL UNIQUE,
            role        TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            expires_at  TEXT,
            revoked_at  TEXT,
            last_used   TEXT
        );
    """),
    # 2 — la NATURE du travail. Les rejeux sont persistes pour etre suivis, mais
    #     s'executent dans le processus de l'API : sans ce champ, l'ouvrier les
    #     prenait dans la file et lancait un AUDIT COMPLET de la cible. Les rejeux
    #     deja en base se reconnaissent a leur prefixe d'identifiant.
    (2, """
        ALTER TABLE runs ADD COLUMN kind TEXT NOT NULL DEFAULT 'audit';
        UPDATE runs SET kind = 'replay' WHERE id LIKE 'replay-%';
    """),
]


def version_schema() -> int:
    """Version du schéma portée par la base (0 = jamais migrée)."""
    return int(_conn().execute("PRAGMA user_version").fetchone()[0])


def _instructions(script: str):
    """Découpe un script SQL en instructions, sans se tromper sur les littéraux.

    `sqlite3.complete_statement` est la fonction de la bibliothèque standard qui
    répond à « ce texte forme-t-il une instruction complète ? » — elle connaît
    les chaînes et les commentaires. Découper naïvement sur `;` casserait sur le
    premier point-virgule dans un littéral.

    POURQUOI NE PAS UTILISER `executescript`
        `executescript` émet un COMMIT avant de démarrer : il mettrait fin à la
        transaction qui protège la migration, et c'est précisément cette
        transaction qui empêche deux processus de migrer en même temps.
    """
    tampon = ""
    for ligne in script.splitlines(keepends=True):
        tampon += ligne
        if sqlite3.complete_statement(tampon):
            instruction = tampon.strip()
            if instruction:
                yield instruction
            tampon = ""
    reste = tampon.strip()
    if reste:
        yield reste


def init() -> None:
    """Crée ou met à jour le schéma. Appelé au démarrage de l'API ET de l'ouvrier.

    Idempotent, concurrent-safe, et surtout : REFUSE une base plus récente que le
    code.

    TOUTE LA PHASE EST SOUS UN VERROU D'ÉCRITURE, ET LA VERSION EST RELUE DEDANS.
        `docker compose` lance l'API et l'ouvrier EN MÊME TEMPS : les deux
        appellent `init()` à la seconde près. Une première version lisait la
        version AVANT la transaction — les deux processus lisaient donc « 0 » et
        appliquaient la même migration deux fois.

        Invisible aujourd'hui, parce que la migration 1 est en `IF NOT EXISTS`.
        Mesuré avec une migration non idempotente (un `ALTER TABLE`, c'est-à-dire
        toutes les suivantes) : 6 démarrages simultanés → 1 échec
        `duplicate column name`. Ça se serait produit exactement le jour du
        déploiement qui change le schéma, sur l'un des deux services.

        `BEGIN IMMEDIATE` prend le verrou d'écriture tout de suite : le second
        processus attend, puis relit une version déjà à jour et ne fait rien.
    """
    c = _conn()

    c.execute("BEGIN IMMEDIATE")
    try:
        actuelle = int(c.execute("PRAGMA user_version").fetchone()[0])
        _verifier_version(actuelle)
        for version, sql in _MIGRATIONS:
            if version <= actuelle:
                continue
            for instruction in _instructions(sql):
                c.execute(instruction)
            c.execute(f"PRAGMA user_version = {int(version)}")
        c.execute("COMMIT")
    except BaseException:
        c.execute("ROLLBACK")
        raise


def _verifier_version(actuelle: int) -> None:
    """Refuse une base plus récente que le code. Voir le bloc ci-dessus."""
    if actuelle > SCHEMA_VERSION:
        raise RuntimeError(
            f"Base de données en version de schéma {actuelle}, "
            f"code en version {SCHEMA_VERSION} : cette image est PLUS ANCIENNE "
            f"que la base ({db_path()}).\n"
            "  Démarrer quand même corromprait les données ou échouerait en pleine "
            "exécution, pas au démarrage.\n"
            "  → redéployer une image au moins aussi récente, OU restaurer la "
            "sauvegarde d'avant la montée de version :\n"
            "       python scripts/backup_volume.py --lister\n"
            "       python scripts/backup_volume.py --restaurer <archive>"
        )



# --------------------------------------------------------------------------- #
# Exécutions
# --------------------------------------------------------------------------- #

def retention_jours() -> int:
    """Age au-dela duquel journaux et echanges sont purges. 0 = jamais.

    `AUDIT_RETENTION_JOURS`, 30 par defaut. Lu A L'APPEL.
    """
    brut = os.environ.get("AUDIT_RETENTION_JOURS", "").strip()
    try:
        return max(int(brut), 0) if brut else 30
    except ValueError:
        return 30


def purger(jours: int | None = None) -> dict[str, int]:
    """Supprime journaux et echanges des executions TERMINEES et anciennes.

    POURQUOI CETTE PURGE EXISTE
        `run_logs` et `run_exchanges` n'etaient JAMAIS nettoyes. Chaque audit y
        depose un transcript complet — chaque prompt, chaque reponse de la
        cible. Croissance non bornee sur le volume persistant, comme les
        journaux Docker avant qu'on ne leur pose `max-size`.

        Et depuis la borne sur la taille des reponses (base_agent), on sait a
        quel point une seule cible bavarde peut peser : c'etait 80 Mo par
        echange avant qu'on ne la pose.

    CE QU'ON GARDE, ET POURQUOI
        La LIGNE `runs` survit : statut, dates, ouvrier, fichier de resultat.
        C'est l'historique, il est petit, et le perdre effacerait la trace de QUI
        a lance QUOI contre QUELLE cible — la tracabilite qui justifie les cles a
        roles. Ce qui part, c'est le volume : le detail tour par tour.

        Le fichier d'audit lui-meme, sur le volume, n'est pas touche : c'est le
        livrable, il a sa propre retention (voir docs/ci_limites_connues.md).

    JAMAIS les executions en cours : on ne purge que `finished_at` non nul.
    """
    jours = retention_jours() if jours is None else jours
    if jours <= 0:
        return {"jours": 0, "runs": 0, "logs": 0, "echanges": 0}

    limite = (datetime.now(timezone.utc) - timedelta(days=jours)).isoformat()
    c = _conn()
    # SOUS-REQUETE, PAS UNE LISTE D'IDS EN PYTHON : un `IN (?,?,...)` construit
    # avec un marqueur par execution se heurte a la limite de variables liees de
    # SQLite (`SQLITE_MAX_VARIABLE_NUMBER`) — la purge cesserait de fonctionner
    # exactement quand il y a le plus a purger. C'est aussi moins de code.
    vieux = "SELECT id FROM runs WHERE finished_at IS NOT NULL AND finished_at < ?"
    n = c.execute(f"SELECT COUNT(*) FROM ({vieux})", (limite,)).fetchone()[0]
    logs = c.execute(f"DELETE FROM run_logs WHERE run_id IN ({vieux})", (limite,)).rowcount
    ech = c.execute(f"DELETE FROM run_exchanges WHERE run_id IN ({vieux})", (limite,)).rowcount
    return {"jours": jours, "runs": n, "logs": logs, "echanges": ech}


def creer_run(run_id: str, requete: dict[str, Any], cree_par: str = "",
              kind: str = "audit") -> None:
    """Dépose une exécution en file. Elle survit désormais au processus.

    `kind` : seul `audit` est pris par un ouvrier. Un `replay` est persisté
    pour être suivi, mais exécuté par le processus qui l'a créé.
    """
    _conn().execute(
        "INSERT INTO runs (id, status, request, created_by, started_at, stage, kind) "
        "VALUES (?, 'queued', ?, ?, ?, ?, ?)",
        (run_id, json.dumps(requete, default=str), cree_par,
         datetime.now(timezone.utc).isoformat(), "En file d'attente", kind))


def prendre_run(worker: str) -> dict[str, Any] | None:
    """Prend ATOMIQUEMENT la plus ancienne exécution en file, ou None.

    POURQUOI CE N'EST PAS UN `SELECT` PUIS UN `UPDATE`
        Entre les deux, un autre ouvrier prendrait la même exécution et l'audit
        tournerait deux fois — deux fois le coût, et deux fichiers de résultat
        concurrents. La condition `status='queued'` dans le `UPDATE` rend
        l'opération indivisible : c'est la base qui arbitre, pas une convention.
    """
    maintenant = time.time()
    c = _conn()
    c.execute("BEGIN IMMEDIATE")
    try:
        ligne = c.execute(
            "SELECT id FROM runs WHERE status='queued' AND kind='audit' "
            "ORDER BY started_at LIMIT 1"
        ).fetchone()
        if ligne is None:
            c.execute("COMMIT")
            return None
        pris = c.execute(
            "UPDATE runs SET status='running', worker=?, claimed_at=?, heartbeat=?, "
            "stage='Démarrage' WHERE id=? AND status='queued'",
            (worker, datetime.now(timezone.utc).isoformat(), maintenant, ligne["id"]))
        c.execute("COMMIT")
        if pris.rowcount == 0:              # un autre ouvrier a été plus rapide
            return None
    except Exception:
        c.execute("ROLLBACK")
        raise
    return lire_run(ligne["id"])


def battre(run_id: str) -> None:
    """Signale que l'ouvrier est vivant. Sans cela, son travail serait repris."""
    _conn().execute("UPDATE runs SET heartbeat=? WHERE id=?", (time.time(), run_id))


def reprendre_abandonnes(limite_s: int = BATTEMENT_MAX_S) -> int:
    """Remet en file les exécutions dont l'ouvrier ne bat plus. Renvoie le compte.

    C'est ce qui distingue une file d'une simple table : un pod évincé au milieu
    d'un audit ne doit pas bloquer ce travail pour toujours.
    """
    # `<=` et non `<` : la resolution d'horloge de Windows (~15 ms) rend
    # frequemment `heartbeat == seuil`, et un battement exactement au seuil EST
    # perime. Avec `<`, une execution abandonnee restait bloquee.
    #
    # `kind='audit'` : un rejeu ne bat JAMAIS (aucun ouvrier ne le porte), donc
    # `heartbeat IS NULL` le designait comme abandonne des le premier balayage —
    # remis en file, puis execute comme un audit complet.
    seuil = time.time() - limite_s
    cur = _conn().execute(
        "UPDATE runs SET status='queued', worker=NULL, claimed_at=NULL, "
        "heartbeat=NULL, stage='Repris après abandon' "
        "WHERE status='running' AND kind='audit' "
        "AND (heartbeat IS NULL OR heartbeat <= ?)", (seuil,))
    return cur.rowcount


def maj_run(run_id: str, **champs: Any) -> None:
    """Met à jour les champs d'une exécution. Les listes sont sérialisées."""
    if not champs:
        return
    for cle in ("result_files", "categories"):
        if cle in champs and champs[cle] is not None:
            champs[cle] = json.dumps(champs[cle])
    # `cancelled` EST TERMINAL. L'annulation arrive d'un AUTRE processus (l'API)
    # pendant que l'executant ecrit son propre statut : `running` au demarrage,
    # `completed` a la fin. Sans cette garde, il effacait l'annulation — et le
    # guetteur de `_execute`, qui relit ce statut, ne la voyait jamais.
    # Les AUTRES champs passent : `finished_at` doit s'ecrire apres annulation.
    sets = ", ".join(
        "status = CASE WHEN status = 'cancelled' THEN status ELSE ? END"
        if k == "status" else f"{k}=?" for k in champs)
    _conn().execute(f"UPDATE runs SET {sets} WHERE id=?",
                    (*champs.values(), run_id))


def statut(run_id: str) -> str | None:
    """Statut seul d'une exécution — la lecture du guetteur d'annulation, qui
    interroge toutes les deux secondes : `lire_run` y ajouterait les journaux."""
    r = _conn().execute("SELECT status FROM runs WHERE id=?", (run_id,)).fetchone()
    return r["status"] if r else None


def ajouter_log(run_id: str, level: str, text: str) -> None:
    """Ajoute une ligne de journal, numérotée pour la lecture incrémentale."""
    c = _conn()
    seq = c.execute("SELECT COALESCE(MAX(seq), -1) + 1 FROM run_logs WHERE run_id=?",
                    (run_id,)).fetchone()[0]
    c.execute("INSERT INTO run_logs (run_id, seq, t, level, text) VALUES (?,?,?,?,?)",
              (run_id, seq, datetime.now(timezone.utc).isoformat(), level, text[:4000]))


def ajouter_echange(run_id: str, entree: dict[str, Any]) -> None:
    """Ajoute un échange avec la cible, capté en direct."""
    c = _conn()
    seq = c.execute("SELECT COALESCE(MAX(seq), -1) + 1 FROM run_exchanges WHERE run_id=?",
                    (run_id,)).fetchone()[0]
    c.execute("INSERT INTO run_exchanges (run_id, seq, payload) VALUES (?,?,?)",
              (run_id, seq, json.dumps(entree, default=str)))


def lire_run(run_id: str, depuis_log: int = 0,
             depuis_echange: int = 0) -> dict[str, Any] | None:
    """État complet d'une exécution, journaux et échanges depuis un curseur."""
    c = _conn()
    r = c.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if r is None:
        return None

    logs = [{"t": x["t"], "level": x["level"], "text": x["text"]}
            for x in c.execute(
                "SELECT t, level, text FROM run_logs WHERE run_id=? AND seq>=? "
                "ORDER BY seq", (run_id, depuis_log))]
    n_logs = c.execute("SELECT COUNT(*) FROM run_logs WHERE run_id=?",
                       (run_id,)).fetchone()[0]
    ech = [json.loads(x["payload"]) for x in c.execute(
        "SELECT payload FROM run_exchanges WHERE run_id=? AND seq>=? ORDER BY seq",
        (run_id, depuis_echange))]
    n_ech = c.execute("SELECT COUNT(*) FROM run_exchanges WHERE run_id=?",
                      (run_id,)).fetchone()[0]

    return {
        "run_id": r["id"], "status": r["status"], "progress": r["progress"],
        "stage": r["stage"], "started_at": r["started_at"],
        "finished_at": r["finished_at"], "result_file": r["result_file"],
        "error": r["error"], "request": json.loads(r["request"]),
        "created_by": r["created_by"], "worker": r["worker"],
        "logs": logs, "log_count": n_logs,
        "exchanges": ech, "exchange_count": n_ech,
        "categories": json.loads(r["categories"]) if r["categories"] else None,
        "result_files": json.loads(r["result_files"]) if r["result_files"] else None,
    }


def lister_runs(limite: int = 100) -> list[dict[str, Any]]:
    """Exécutions les plus récentes, sans leurs journaux (trop volumineux)."""
    return [{"run_id": r["id"], "status": r["status"], "progress": r["progress"],
             "stage": r["stage"], "started_at": r["started_at"],
             "finished_at": r["finished_at"], "created_by": r["created_by"],
             "worker": r["worker"], "request": json.loads(r["request"])}
            for r in _conn().execute(
                "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limite,))]


def compter_actifs() -> int:
    return _conn().execute(
        "SELECT COUNT(*) FROM runs WHERE status IN ('queued','running')").fetchone()[0]


# --------------------------------------------------------------------------- #
# Clés d'API — rotation, rôles, attribution
# --------------------------------------------------------------------------- #

def _hacher(cle: str) -> str:
    """Empreinte d'une clé. La clé en clair n'est JAMAIS stockée.

    SHA-256 et non bcrypt : une clé d'API est un secret de 256 bits tiré au
    hasard, pas un mot de passe humain. Le durcissement lent protège d'une
    attaque par dictionnaire, qui n'a aucun sens ici — et coûterait à chaque
    requête.
    """
    return hashlib.sha256(cle.encode()).hexdigest()


def creer_cle(nom: str, role: str = "operator",
              expire_dans_jours: int | None = None) -> tuple[str, str]:
    """Crée une clé. Renvoie `(identifiant, clé en clair)` — la SEULE occasion
    de voir la clé, puisque seule son empreinte est conservée."""
    if role not in ROLES:
        raise ValueError(f"rôle inconnu : {role} (attendu : {', '.join(ROLES)})")
    cle = "aisec_" + secrets.token_urlsafe(32)
    ident = "key-" + secrets.token_hex(6)
    expire = None
    if expire_dans_jours:
        expire = datetime.fromtimestamp(
            time.time() + expire_dans_jours * 86400, timezone.utc).isoformat()
    _conn().execute(
        "INSERT INTO api_keys (id, name, hash, role, created_at, expires_at) "
        "VALUES (?,?,?,?,?,?)",
        (ident, nom, _hacher(cle), role,
         datetime.now(timezone.utc).isoformat(), expire))
    return ident, cle


def verifier_cle(cle: str) -> dict[str, Any] | None:
    """Identité derrière une clé, ou None. Met à jour la date de dernier usage.

    Une clé RÉVOQUÉE ou EXPIRÉE est refusée : c'est ce qui rend la rotation
    possible. Sans expiration, une clé distribuée une fois vaut pour toujours.
    """
    if not cle:
        return None
    r = _conn().execute("SELECT * FROM api_keys WHERE hash=?",
                        (_hacher(cle),)).fetchone()
    if r is None or r["revoked_at"]:
        return None
    if r["expires_at"] and r["expires_at"] < datetime.now(timezone.utc).isoformat():
        return None
    _conn().execute("UPDATE api_keys SET last_used=? WHERE id=?",
                    (datetime.now(timezone.utc).isoformat(), r["id"]))
    return {"id": r["id"], "name": r["name"], "role": r["role"]}


def revoquer_cle(ident: str) -> bool:
    """Révoque une clé. Renvoie False si elle n'existe pas ou l'était déjà."""
    cur = _conn().execute(
        "UPDATE api_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
        (datetime.now(timezone.utc).isoformat(), ident))
    return cur.rowcount > 0


def lister_cles() -> list[dict[str, Any]]:
    """Clés connues, SANS leur empreinte — un inventaire ne divulgue rien."""
    return [{"id": r["id"], "name": r["name"], "role": r["role"],
             "created_at": r["created_at"], "expires_at": r["expires_at"],
             "revoked_at": r["revoked_at"], "last_used": r["last_used"]}
            for r in _conn().execute("SELECT * FROM api_keys ORDER BY created_at DESC")]


def role_suffisant(role: str, minimum: str) -> bool:
    """Le rôle atteint-il le niveau requis ? Comparaison par INDEX, pas par nom."""
    try:
        return ROLES.index(role) >= ROLES.index(minimum)
    except ValueError:
        return False


def fermer() -> None:
    """Ferme la connexion du fil courant (tests, arrêt propre)."""
    c = getattr(_LOCAL, "conn", None)
    if c is not None:
        c.close()
        _LOCAL.conn = None


def demo() -> None:
    """Auto-test : persistance, file atomique, reprise, cles. Base temporaire."""
    import tempfile

    ancien = os.environ.get("AUDIT_STATE_DB")
    tmp = tempfile.mkdtemp()
    os.environ["AUDIT_STATE_DB"] = str(Path(tmp) / "essai.sqlite")
    fermer()
    try:
        init()

        # 1. PERSISTANCE : c'est tout l'objet du module. On simule un
        #    redemarrage en fermant la connexion — l'execution doit survivre.
        creer_run("run-1", {"mode": "targeted", "category": "ASI_01"}, cree_par="key-a")
        ajouter_log("run-1", "info", "demarrage")
        fermer()
        r = lire_run("run-1")
        assert r is not None and r["status"] == "queued"
        assert r["logs"][0]["text"] == "demarrage"
        assert r["created_by"] == "key-a", "l'attribution doit survivre aussi"

        # 2. FILE ATOMIQUE : deux ouvriers, une seule execution. Le second doit
        #    repartir les mains vides — sinon l'audit tourne DEUX fois, pour deux
        #    fois le cout et deux fichiers concurrents.
        pris_a = prendre_run("worker-a")
        pris_b = prendre_run("worker-b")
        assert pris_a is not None and pris_a["run_id"] == "run-1"
        assert pris_b is None, "deux ouvriers ne peuvent pas prendre le meme travail"
        assert lire_run("run-1")["worker"] == "worker-a"

        # 3. REPRISE : un ouvrier mort ne doit pas bloquer un audit pour toujours.
        assert reprendre_abandonnes(limite_s=10_000) == 0, "un ouvrier vivant est laisse"
        assert reprendre_abandonnes(limite_s=0) == 1
        assert lire_run("run-1")["status"] == "queued"

        # 4. Le battement de coeur protege un travail qui avance.
        prendre_run("worker-a")
        battre("run-1")
        assert reprendre_abandonnes(limite_s=10_000) == 0

        # 5. Lecture incrementale : le suivi ne doit pas retelecharger tout le
        #    journal a chaque interrogation.
        ajouter_log("run-1", "info", "deuxieme")
        assert len(lire_run("run-1", depuis_log=1)["logs"]) == 1
        assert lire_run("run-1")["log_count"] == 2

        # 6. Fin d'execution.
        maj_run("run-1", status="completed", progress=100,
                result_files=["a.json", "b.json"])
        r = lire_run("run-1")
        assert r["status"] == "completed" and r["result_files"] == ["a.json", "b.json"]
        assert compter_actifs() == 0

        # 7. CLES : la clé en clair n'est visible QU'A la creation.
        ident, cle = creer_cle("equipe secu", role="operator")
        assert cle.startswith("aisec_")
        assert all(cle not in json.dumps(k) for k in lister_cles()), (
            "un inventaire de cles ne doit rien divulguer")
        identite = verifier_cle(cle)
        assert identite["role"] == "operator" and identite["id"] == ident

        # 8. ROLES : la comparaison se fait par niveau, pas par egalite de nom.
        assert role_suffisant("admin", "operator") and role_suffisant("operator", "operator")
        assert not role_suffisant("viewer", "operator")
        assert not role_suffisant("inconnu", "viewer")

        # 9. ROTATION : une cle revoquee est refusee. Sans cela, une cle
        #    distribuee une fois vaut pour toujours.
        assert revoquer_cle(ident) is True
        assert verifier_cle(cle) is None
        assert revoquer_cle(ident) is False, "revoquer deux fois n'est pas un succes"

        # 10. EXPIRATION : meme mecanisme, declenche par le temps.
        _, cle_expiree = creer_cle("temporaire", expire_dans_jours=-1)
        assert verifier_cle(cle_expiree) is None
        assert verifier_cle("aisec_inexistante") is None and verifier_cle("") is None

        print("api.store : 10/10 controles OK")
    finally:
        fermer()
        if ancien is None:
            os.environ.pop("AUDIT_STATE_DB", None)
        else:
            os.environ["AUDIT_STATE_DB"] = ancien


if __name__ == "__main__":
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    demo()
