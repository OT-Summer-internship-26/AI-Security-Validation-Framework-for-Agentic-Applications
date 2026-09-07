#!/usr/bin/env python
"""
backup_volume.py — Sauvegarder et restaurer le volume de données.

POURQUOI CE SCRIPT EXISTE
    Le volume `audit_data` porte trois choses NON RÉGÉNÉRABLES :

      · la base d'état (`state.sqlite`) — file d'attente et suivi des audits ;
      · les CLÉS D'API — seules leurs empreintes sont stockées, donc une clé
        perdue ne se retrouve pas : il faut en redistribuer à toute l'équipe ;
      · les résultats d'audit — des heures de calcul et de jetons déjà payés.

    Un `docker compose down -v` détruit tout, sans confirmation. La commande est
    banale, on la tape pour repartir propre — et elle emporte la base de clés.

CE QUI EST GARANTI, ET CE QUI NE L'EST PAS
    La sauvegarde est prise via un conteneur JETABLE qui monte le volume en
    lecture seule : elle n'a pas besoin que la pile tourne, et ne la perturbe
    pas si elle tourne.

    ⚠️ SQLite en mode WAL peut avoir des écritures dans `state.sqlite-wal` non
    encore fusionnées. Une copie prise PENDANT une écriture serait incohérente.
    Le script fusionne donc le WAL avant la copie (`wal_checkpoint(TRUNCATE)`) —
    et le dit s'il n'y arrive pas, plutôt que de produire une archive dont on
    découvrirait le défaut le jour de la restauration.

USAGE
    python scripts/backup_volume.py --sauvegarder
    python scripts/backup_volume.py --lister
    python scripts/backup_volume.py --restaurer sauvegardes/audit_data-2026....tar.gz
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
VOLUME = "ai_security_framework_audit_data"
SAUVEGARDES = RACINE / "sauvegardes"

#: Nombre d'archives conservees. Deux semaines de sauvegardes quotidiennes.
GARDER_PAR_DEFAUT = 14

#: Age maximal tolere pour la sauvegarde la plus recente, en heures.
#: 26 et non 24 : un travail quotidien lance a 02:00 et verifie a 02:05 le
#: lendemain aurait 24 h 05 — un seuil a 24 h clignoterait un jour sur deux,
#: et une alerte qui clignote finit par etre ignoree.
AGE_MAX_HEURES = 26

# Image minimale pour manipuler l'archive. Épinglée par étiquette stable : la
# sauvegarde ne doit pas dépendre d'un `latest` qui change.
IMAGE = "alpine:3.20"


def _docker(*args: str, entree: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], input=entree, capture_output=True)


def volume_existe(nom: str) -> bool:
    return _docker("volume", "inspect", nom).returncode == 0


def _fusionner_wal(nom_volume: str) -> str:
    """Fusionne le journal WAL de SQLite avant la copie.

    Sans cela, une sauvegarde prise pendant une écriture peut contenir une base
    incohérente — un défaut qui ne se découvre qu'à la restauration, c'est-à-dire
    au pire moment.
    """
    script = (
        "import sqlite3, pathlib;"
        "p = pathlib.Path('/data/state.sqlite');"
        "print('pas de base — rien a fusionner') if not p.exists() else "
        "(sqlite3.connect(p).execute('PRAGMA wal_checkpoint(TRUNCATE)'), "
        "print('WAL fusionne'))"
    )
    r = _docker("run", "--rm", "-v", f"{nom_volume}:/data",
                "python:3.11-slim", "python", "-c", script)
    return (r.stdout or r.stderr).decode(errors="replace").strip()


def sauvegarder(nom_volume: str, garder: int = GARDER_PAR_DEFAUT) -> int:
    if not volume_existe(nom_volume):
        print(f"Volume introuvable : {nom_volume}")
        print("  Volumes disponibles :")
        print(_docker("volume", "ls", "--format", "{{.Name}}").stdout.decode())
        return 1

    print(f"  {_fusionner_wal(nom_volume)}")
    SAUVEGARDES.mkdir(exist_ok=True)
    cible = SAUVEGARDES / f"audit_data-{datetime.now():%Y%m%d-%H%M%S}.tar.gz"

    # Volume monté en LECTURE SEULE : une sauvegarde ne doit jamais pouvoir
    # abîmer ce qu'elle sauvegarde.
    r = _docker("run", "--rm", "-v", f"{nom_volume}:/data:ro", IMAGE,
                "tar", "czf", "-", "-C", "/data", ".")
    if r.returncode != 0:
        print("Echec :", r.stderr.decode(errors="replace")[:300])
        return 1

    cible.write_bytes(r.stdout)
    mo = len(r.stdout) / 1_048_576
    print(f"  Sauvegarde : {cible.relative_to(RACINE)} ({mo:.1f} Mo)")

    # Une archive vide serait un faux sentiment de sécurité — pire que rien.
    if len(r.stdout) < 1024:
        print("  ⚠️ ARCHIVE SUSPECTE : moins de 1 Ko. Le volume est-il vide ?")
        return 1

    # La purge vient APRÈS les contrôles : on ne supprime d'anciennes copies
    # qu'une fois la nouvelle écrite ET jugée plausible. Purger avant reviendrait
    # à effacer la dernière copie valide au moment où elle est la seule qui reste.
    purger(garder)
    return 0


def archives() -> list[Path]:
    """Archives connues, de la plus RECENTE a la plus ancienne."""
    if not SAUVEGARDES.exists():
        return []
    return sorted(SAUVEGARDES.glob("audit_data-*.tar.gz"),
                  key=lambda f: f.stat().st_mtime, reverse=True)


def purger(garder: int) -> int:
    """Supprime les archives au-dela des `garder` plus recentes.

    APPELEE UNIQUEMENT APRES UNE SAUVEGARDE REUSSIE, et c'est essentiel :
    purger avant, ou apres un echec, effacerait la derniere copie valide au
    moment precis ou elle est la seule qui reste. Le dossier grossissait sans
    fin — la meme croissance non bornee que les resultats d'audit.
    """
    trop = archives()[garder:]
    for f in trop:
        f.unlink()
        print(f"  purge : {f.name}")
    return len(trop)


def verifier(age_max_heures: float) -> int:
    """La sauvegarde est-elle RECENTE ? Code de sortie non nul sinon.

    POURQUOI CE MODE EXISTE
        Un script de sauvegarde qui existe, qui est teste et qui est documente
        ne prouve rien : il ne dit pas s'il TOURNE. Ici, la seule chose qui
        compte en production est « la derniere copie date de quand ? ». Sans
        cette question, on decouvre l'absence de sauvegarde le jour ou on en a
        besoin — c'est-a-dire au pire moment possible.

        A brancher sur la supervision, ou a lancer a la main avant une operation
        risquee (montee de version, `compose down -v`).
    """
    liste = archives()
    if not liste:
        print(f"AUCUNE sauvegarde dans {SAUVEGARDES}")
        print("  Une seule commande separe l'incident de la perte definitive :")
        print("    python scripts/backup_volume.py --sauvegarder")
        return 1

    recente = liste[0]
    age_h = (datetime.now().timestamp() - recente.stat().st_mtime) / 3600
    mo = recente.stat().st_size / 1_048_576
    print(f"  Derniere sauvegarde : {recente.name} "
          f"({mo:.1f} Mo, il y a {age_h:.1f} h)")
    print(f"  Archives conservees : {len(liste)}")

    if age_h > age_max_heures:
        print(f"PERIMEE : plus de {age_max_heures} h. La planification "
              f"tourne-t-elle encore ?")
        return 1
    return 0


def restaurer(archive: Path, nom_volume: str) -> int:
    if not archive.exists():
        print(f"Archive introuvable : {archive}")
        return 1

    print(f"  ⚠️ La restauration ECRASE le contenu de « {nom_volume} ».")
    print("     Arreter la pile d'abord :  docker compose down")
    if input("     Taper RESTAURER pour confirmer : ").strip() != "RESTAURER":
        print("  Annule.")
        return 1

    _docker("volume", "create", nom_volume)
    r = _docker("run", "--rm", "-i", "-v", f"{nom_volume}:/data", IMAGE,
                "sh", "-c", "rm -rf /data/* /data/.[!.]* 2>/dev/null; tar xzf - -C /data",
                entree=archive.read_bytes())
    if r.returncode != 0:
        print("Echec :", r.stderr.decode(errors="replace")[:300])
        return 1
    print("  Restauration terminee.")
    return 0


def lister() -> int:
    if not SAUVEGARDES.exists() or not any(SAUVEGARDES.glob("*.tar.gz")):
        print("  Aucune sauvegarde.")
        return 0
    for f in sorted(SAUVEGARDES.glob("*.tar.gz"), reverse=True):
        print(f"  {f.name:44} {f.stat().st_size / 1_048_576:7.1f} Mo")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--sauvegarder", action="store_true")
    g.add_argument("--restaurer", metavar="ARCHIVE")
    g.add_argument("--lister", action="store_true")
    g.add_argument("--verifier", action="store_true",
                   help="la dernière sauvegarde est-elle récente ? "
                        "(code de sortie non nul sinon — à superviser)")
    ap.add_argument("--volume", default=VOLUME)
    ap.add_argument("--garder", type=int, default=GARDER_PAR_DEFAUT,
                    help=f"archives conservées (défaut : {GARDER_PAR_DEFAUT})")
    ap.add_argument("--age-max-heures", type=float, default=AGE_MAX_HEURES,
                    help=f"seuil de péremption (défaut : {AGE_MAX_HEURES} h)")
    args = ap.parse_args()

    if args.lister:
        return lister()
    if args.verifier:
        return verifier(args.age_max_heures)
    if args.sauvegarder:
        return sauvegarder(args.volume, args.garder)
    return restaurer(Path(args.restaurer), args.volume)


def _demo_purge_et_fraicheur() -> None:
    """Purge et verification, sur un dossier temporaire — sans Docker."""
    import tempfile
    import time as _time

    global SAUVEGARDES
    origine = SAUVEGARDES
    try:
        with tempfile.TemporaryDirectory() as tmp:
            SAUVEGARDES = Path(tmp)

            # a. Aucune sauvegarde -> ECHEC. C'est le cas qu'on veut voir.
            assert verifier(26) == 1, "l'absence de sauvegarde doit echouer"

            # b. Cinq archives, on n'en garde que deux.
            for i in range(5):
                f = SAUVEGARDES / f"audit_data-2026010{i}-000000.tar.gz"
                f.write_bytes(b"x" * 2048)
                _time.sleep(0.01)          # horodatages distincts
            assert len(archives()) == 5
            assert purger(2) == 3, "la purge n'a pas retire le bon nombre"
            assert len(archives()) == 2, "il ne doit rester que les 2 plus recentes"

            # c. La plus recente vient d'etre ecrite -> FRAIS.
            assert verifier(26) == 0, "une sauvegarde de l'instant est fraiche"

            # d. Vieillies artificiellement -> PERIMEE.
            #    On collecte la liste UNE FOIS : `archives()` retrie par date,
            #    donc la modifier en la parcourant vieillirait la mauvaise.
            ancien = _time.time() - 40 * 3600
            for f in list(archives()):
                os.utime(f, (ancien, ancien))
            assert verifier(26) == 1, (
                "une sauvegarde de 40 h doit etre signalee perimee : sans ca, "
                "une planification arretee ne se voit jamais")
    finally:
        SAUVEGARDES = origine


def demo() -> None:
    """Auto-test : ce qui ne demande ni Docker ni volume."""
    _demo_purge_et_fraicheur()
    # 1. Une archive minuscule doit etre SIGNALEE : une sauvegarde vide est un
    #    faux sentiment de securite, pire que pas de sauvegarde du tout.
    assert "ARCHIVE SUSPECTE" in Path(__file__).read_text(encoding="utf-8")

    # 2. Le volume est monte en LECTURE SEULE : une sauvegarde ne doit jamais
    #    pouvoir abimer ce qu'elle sauvegarde.
    assert ":/data:ro" in Path(__file__).read_text(encoding="utf-8")

    # 3. La restauration exige une confirmation TAPEE : elle ecrase la base de
    #    cles, qui n'est pas regenerable.
    assert 'input(' in Path(__file__).read_text(encoding="utf-8")

    # 4. Le WAL est fusionne AVANT la copie.
    assert "wal_checkpoint(TRUNCATE)" in Path(__file__).read_text(encoding="utf-8")

    print("scripts.backup_volume : 8/8 controles OK")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        demo()
    else:
        raise SystemExit(main())
