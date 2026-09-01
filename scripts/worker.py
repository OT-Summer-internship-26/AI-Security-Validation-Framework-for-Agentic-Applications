#!/usr/bin/env python
"""
worker.py — L'ouvrier qui exécute les audits, hors du processus web.

LE PROBLÈME QU'IL RÉSOUT
    Un audit dure une heure et vivait dans un `threading.Thread` de l'API. Le
    moindre redéploiement, la moindre éviction de pod le tuait — et comme l'état
    vivait en mémoire, on ne savait même pas qu'il avait existé.

    Séparer les deux règle le problème à la racine :
      · l'API DÉPOSE un travail et rend la main tout de suite ;
      · l'ouvrier le PREND, l'exécute, et écrit sa progression dans le magasin ;
      · redémarrer l'API n'interrompt aucun audit ;
      · redémarrer l'ouvrier remet son travail en file (battement de cœur), il
        est repris — par lui-même ou par un autre.

POURQUOI PAS CELERY NI RQ
    Les deux exigent Redis. Ce framework monte déjà un volume partagé, et la
    file tient dans une table SQLite avec une prise atomique (`api/store.py`).
    Ajouter un courtier de messages pour une file qui voit quelques dizaines de
    travaux par jour, c'est un service de plus à déployer, superviser et
    sauvegarder pour un problème qui n'existe pas encore.

    Le jour où il existera, seul `api/store.py` change : ni l'API ni cet ouvrier
    ne savent où vit la file.

MISE À L'ÉCHELLE
    Lancer plusieurs ouvriers suffit — la prise est atomique, deux ouvriers ne
    peuvent pas se disputer un travail. En revanche ils partagent le quota du
    modèle : au-delà de deux ou trois, le limiteur de débit devient le goulot et
    rien n'est gagné.

USAGE
    python scripts/worker.py                 # boucle jusqu'à interruption
    python scripts/worker.py --once          # traite un travail puis sort (CI)
    AUDIT_WORKER_ID=w2 python scripts/worker.py
"""

from __future__ import annotations

import argparse
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))

# Intervalle d'interrogation de la file. Court : un opérateur qui lance un audit
# depuis le tableau de bord ne doit pas attendre. Le coût est une requête SQLite
# toutes les deux secondes, c'est-à-dire rien.
INTERVALLE_S = float(os.environ.get("AUDIT_WORKER_POLL", "2"))

# Rythme du battement de cœur. Très inférieur au délai d'abandon, sinon un
# ouvrier bien vivant se ferait retirer son travail entre deux battements.
BATTEMENT_S = 30.0

_ARRET = threading.Event()


def _identite() -> str:
    """Nom de l'ouvrier, visible dans le suivi d'exécution.

    Le nom d'hôte suffit en conteneur (il est unique par pod) et rend le journal
    lisible : « repris par worker-7f3a » dit quelque chose, « worker » non.
    """
    return os.environ.get("AUDIT_WORKER_ID") or f"worker-{socket.gethostname()[:16]}"


def _battre_en_boucle(run_id: str, stop: threading.Event) -> None:
    """Signale périodiquement que l'ouvrier est vivant.

    POURQUOI UN FIL DÉDIÉ
        L'exécution d'un audit passe de longues minutes sans rien émettre —
        DeepTeam ne trace qu'en fin de catégorie. Battre depuis la boucle
        principale laisserait donc des silences de plusieurs minutes, et le
        travail serait repris alors qu'il avance très bien.
    """
    from api import store

    store.init()
    while not stop.wait(BATTEMENT_S):
        try:
            store.battre(run_id)
        except Exception as exc:            # une panne de battement n'arrête rien
            print(f"[worker] battement impossible : {exc}", flush=True)


def traiter(travail: dict) -> None:
    """Exécute un travail pris dans la file.

    Réutilise `_execute` de l'API : c'est le MÊME code qui tournait dans le fil
    du serveur web. Le dupliquer ici aurait créé deux comportements d'audit qui
    divergent — le défaut qui a déjà coûté deux runners incompatibles.
    """
    import api.main as api

    run_id = travail["run_id"]
    stop = threading.Event()
    coeur = threading.Thread(target=_battre_en_boucle, args=(run_id, stop), daemon=True)
    coeur.start()
    try:
        run = api.Run.depuis_magasin(travail)
        api._execute(run)
    except Exception as exc:
        from api import store

        store.maj_run(run_id, status="failed", error=str(exc)[:2000])
        store.ajouter_log(run_id, "error", f"ouvrier : {exc}")
        print(f"[worker] {run_id} a échoué : {exc}", flush=True)
    finally:
        stop.set()


def boucle(une_seule: bool = False) -> int:
    from api import store

    store.init()
    moi = _identite()
    print(f"[worker] {moi} — file : {store.db_path()}", flush=True)

    # Au démarrage, on récupère les travaux abandonnés par un ouvrier disparu.
    # C'est LE moment utile : un pod qui redémarre reprend ce qu'il avait laissé.
    repris = store.reprendre_abandonnes()
    if repris:
        print(f"[worker] {repris} exécution(s) abandonnée(s) remise(s) en file",
              flush=True)

    dernier_balayage = time.time()
    while not _ARRET.is_set():
        travail = store.prendre_run(moi)
        if travail is not None:
            print(f"[worker] prise de {travail['run_id']}", flush=True)
            traiter(travail)
            print(f"[worker] {travail['run_id']} terminé", flush=True)
            if une_seule:
                return 0
            continue

        if une_seule:
            print("[worker] file vide", flush=True)
            return 0

        # Balayage périodique : un ouvrier mort PENDANT que celui-ci tourne doit
        # aussi voir son travail repris, pas seulement au prochain démarrage.
        if time.time() - dernier_balayage > store.BATTEMENT_MAX_S / 3:
            dernier_balayage = time.time()
            n = store.reprendre_abandonnes()
            if n:
                print(f"[worker] {n} exécution(s) reprise(s) après abandon", flush=True)

        _ARRET.wait(INTERVALLE_S)

    print("[worker] arrêt demandé", flush=True)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--once", action="store_true",
                    help="traite un seul travail puis sort (utile en CI)")
    args = ap.parse_args()

    # Arrêt propre : sur SIGTERM (ce que Kubernetes envoie), on cesse de PRENDRE
    # de nouveaux travaux. Celui en cours continue jusqu'au délai de grâce ;
    # s'il est coupé, son battement s'arrête et il est repris. Rien n'est perdu.
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, lambda *_: _ARRET.set())
        except (ValueError, AttributeError):   # pas de signaux hors fil principal
            pass

    return boucle(une_seule=args.once)


if __name__ == "__main__":
    raise SystemExit(main())
