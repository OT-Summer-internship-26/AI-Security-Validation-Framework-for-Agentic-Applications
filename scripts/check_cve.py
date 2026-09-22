#!/usr/bin/env python
"""
check_cve.py — Les CVE des dépendances LIVRÉES bloquent, sauf dérogation datée.

POURQUOI CE SCRIPT EXISTE
    `pip-audit` tournait en `continue-on-error` : il imprimait ses CVE et ne
    bloquait jamais. Mesuré le 2026-09-18 : le verrou en portait DEUX — celle de
    `click`, compromis documenté dans `requirements.txt`, et une CVE `weasyprint`
    corrigeable que personne n'avait vue. Un contrôle qui ne peut pas échouer ne
    signale rien : il décore.

LA RÈGLE
    Toute vulnérabilité signalée bloque, sauf si une dérogation ACTIVE de
    `config/cve_derogations.json` la couvre (par identifiant ou alias). Les
    dates suivent exactement celles des dérogations du gate
    (`ci_gate.partager_derogations`) : au jour près, une date illisible vaut
    expirée — et une dérogation expirée ne couvre plus rien.

    Un rapport ABSENT ou VIDE bloque aussi : un scan qui n'a pas tourné ne se
    lit pas « aucune CVE ».

USAGE
    pip-audit -r requirements.lock --no-deps --disable-pip --format json --output pipaudit.json
    python scripts/check_cve.py pipaudit.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_gate import partager_derogations  # noqa: E402

DEROGATIONS = RACINE / "config" / "cve_derogations.json"


def verifier(rapport: dict, derogations: list[dict]) -> tuple[list[str], list[str]]:
    """(bloquants, informations). Ne lève pas : une entrée mal formée est ignorée."""
    actives, expirees = partager_derogations(derogations)
    ident = lambda d: str(d.get("id", "")).strip().upper()   # noqa: E731
    couvertes = {ident(d): d for d in actives}
    perimees = {ident(d): d for d in expirees}

    bloquants, infos, signales = [], [], set()
    for dep in rapport.get("dependencies") or []:
        for v in dep.get("vulns") or []:
            ids = {str(v.get("id", "")).upper(), *(str(a).upper() for a in v.get("aliases") or [])}
            signales |= ids
            correctif = ", ".join(v.get("fix_versions") or []) or "aucun publié"
            libelle = f"{dep.get('name')} {dep.get('version')} — {v.get('id')} (corrigé en {correctif})"
            if ids & couvertes.keys():
                d = couvertes[next(iter(ids & couvertes.keys()))]
                infos.append(f"sous dérogation jusqu'au {d.get('expires_at')} : {libelle}")
            elif ids & perimees.keys():
                d = perimees[next(iter(ids & perimees.keys()))]
                bloquants.append(f"{libelle} — dérogation EXPIRÉE ({d.get('expires_at')!s})")
            else:
                bloquants.append(libelle)

    # Une dérogation qui ne couvre plus rien doit partir : laissée en place, elle
    # couvrirait en silence la RÉAPPARITION de la même faille.
    for d in [*actives, *expirees]:
        if ident(d) not in signales:
            infos.append(f"dérogation sans objet, à retirer : {d.get('id')}")
    return bloquants, infos


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print("usage : python scripts/check_cve.py <rapport pip-audit JSON>")
        return 2
    try:
        rapport = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"❌ rapport pip-audit illisible ou absent ({exc}) — le scan n'a pas "
              "abouti, on ne conclut pas à « aucune CVE ».")
        return 1
    if not rapport.get("dependencies"):
        print("❌ rapport pip-audit VIDE — aucune dépendance auditée, rien ne peut en être conclu.")
        return 1

    derogations = []
    if DEROGATIONS.exists():
        derogations = json.loads(DEROGATIONS.read_text(encoding="utf-8")).get("derogations", [])

    bloquants, infos = verifier(rapport, derogations)
    print(f"pip-audit : {len(rapport['dependencies'])} dépendance(s) auditée(s), "
          f"{len(bloquants)} CVE bloquante(s)")
    for ligne in bloquants:
        print(f"  🔴 {ligne}")
    for ligne in infos:
        print(f"  ⚪ {ligne}")
    if bloquants:
        print("→ corriger la version dans requirements.lock, ou déclarer une dérogation "
              "DATÉE et justifiée dans config/cve_derogations.json.")
    return 1 if bloquants else 0


if __name__ == "__main__":
    raise SystemExit(main())
