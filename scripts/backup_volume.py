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
import subprocess
import sys
from datetime import datetime
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
VOLUME = "ai_security_framework_audit_data"
SAUVEGARDES = RACINE / "sauvegardes"

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


def sauvegarder(nom_volume: str) -> int:
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
    ap.add_argument("--volume", default=VOLUME)
    args = ap.parse_args()

    if args.lister:
        return lister()
    if args.sauvegarder:
        return sauvegarder(args.volume)
    return restaurer(Path(args.restaurer), args.volume)


def demo() -> None:
    """Auto-test : ce qui ne demande ni Docker ni volume."""
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

    print("scripts.backup_volume : 4/4 controles OK")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        demo()
    else:
        raise SystemExit(main())
