"""
check_dashboard_contract.py — Vérifie que les VRAIES données d'audit alimentent
réellement le dashboard.

POURQUOI CE SCRIPT EXISTE
    Le dashboard a été écrit contre des données d'exemple. Chaque fois qu'un vrai
    audit arrivait, un champ manquait — et on ne s'en apercevait qu'en regardant
    une page vide. Les trous se découvraient un par un, à l'usage.

    Ce script fait l'inverse : il inspecte tous les audits produits et signale
    d'un coup tout ce que le dashboard attend et qui n'est pas là. À lancer après
    un changement de format côté runner, socle ou API.

USAGE
    python scripts/check_dashboard_contract.py            # tous les audits
    python scripts/check_dashboard_contract.py --last 3   # les 3 plus récents

Sortie : un rapport lisible + code de sortie 1 si un contrôle échoue (utilisable en CI).
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Champs racine lus par l'adaptateur du dashboard (dashboard/src/data/adapter.ts).
# `requis` : son absence casse ou vide une page. `optionnel` : toléré, signalé.
ROOT_REQUIRED = ["audit_id", "target_url", "global_score", "risk_level", "llm_profile",
                 "model", "timestamp", "duration_seconds", "agents"]
ROOT_OPTIONAL = ["cost_tokens", "cost_usd", "status"]

# Axes comportementaux attendus dans raw.score_components.
AXES = ["deepteam", "pyrit", "garak", "microsoft"]

# Clés d'une entrée d'attack_log, consommées par la page Attaques.
ATTACK_KEYS = ["prompt", "response", "verdict", "technique", "axis", "layer"]


def check_audit(path: str) -> tuple[list[str], list[str], dict] | None:
    """Retourne (erreurs, avertissements, resume), ou None si le fichier n'est pas
    un audit exposé au dashboard.

    LE FILTRE DOIT COLLER À CELUI DE L'API (`api.main._read_results`) : elle ignore
    `sample_audit.json` et tout fichier sans clé `agents` (les rapports de REJEU ont
    une autre forme). Signaler ces fichiers ferait crier au loup pour des données que
    le dashboard ne lit jamais — et un contrôle qui crie au loup finit ignoré.
    """
    errs: list[str] = []
    warns: list[str] = []
    try:
        d = json.load(open(path, encoding="utf-8"))
    except Exception as exc:
        return [f"illisible : {type(exc).__name__}: {exc}"], [], {}

    if Path(path).name == "sample_audit.json" or "agents" not in d:
        return None

    for k in ROOT_REQUIRED:
        if d.get(k) is None:
            errs.append(f"champ racine manquant : {k}")
    for k in ROOT_OPTIONAL:
        if k not in d:
            warns.append(f"champ racine optionnel absent : {k}")

    agents = d.get("agents") or {}
    if not agents:
        errs.append("aucun agent dans l'audit")

    n_attacks = n_vulns = n_axes = 0
    for cat, ag in agents.items():
        if ag.get("status") != "completed":
            continue
        layers = ag.get("layers") or {}
        beh = layers.get("behavioral") or {}
        raw = beh.get("raw") or {}

        comps = raw.get("score_components") or raw.get("components") or {}
        if not comps:
            errs.append(f"{cat}: aucun score_components — la comparaison par axe sera vide")
        else:
            present = [a for a in AXES if comps.get(a) is not None]
            n_axes += len(present)
            if not present:
                errs.append(f"{cat}: tous les axes sont exclus (score_components vides)")

        # Attaques : la page Attaques et la comparaison par attaque en dépendent.
        log = raw.get("attack_log") or ag.get("attacks") or []
        n_attacks += len(log)
        if not log:
            errs.append(f"{cat}: attack_log vide — la page Attaques n'affichera rien")
        else:
            missing = [k for k in ATTACK_KEYS if k not in log[0]]
            if missing:
                errs.append(f"{cat}: entrée d'attaque sans {missing}")
            # Un prompt qui n'est qu'un résumé (ex. « AttackOutcome.SUCCESS ») ne
            # permet pas de rejouer ni de comprendre l'attaque.
            # En dry_run les attaques sont factices (aucun réseau) : un prompt vide
            # y est NORMAL. Le signaler noierait les vrais défauts.
            if d.get("llm_profile") not in ("dry_run", "dry-run", "ci"):
                vides = sum(1 for e in log if not str(e.get("prompt", "")).strip())
                if vides:
                    errs.append(f"{cat}: {vides} attaque(s) sans prompt")
            pyrit = [e for e in log if e.get("axis") == "PyRIT"]
            if pyrit and all("AttackOutcome" in str(e.get("response", "")) for e in pyrit):
                errs.append(f"{cat}: PyRIT ne journalise que son verdict, pas les tours")

        n_vulns += len(ag.get("vulnerabilities") or [])

    return errs, warns, {"agents": len(agents), "attaques": n_attacks,
                         "vulns": n_vulns, "axes_notes": n_axes,
                         "score": d.get("global_score"), "profil": d.get("llm_profile")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--last", type=int, default=0, help="ne vérifier que les N plus récents")
    args = ap.parse_args()

    files = sorted(glob.glob(str(ROOT / "data" / "**" / "*.json"), recursive=True),
                   key=os.path.getmtime, reverse=True)
    files = [f for f in files if "exchanges" not in f]
    if args.last:
        files = files[: args.last]
    if not files:
        print("Aucun audit trouvé dans data/ — rien à vérifier.")
        return 0

    total_err = 0
    ignores = 0
    for f in files:
        res = check_audit(f)
        if res is None:      # rejeu / échantillon : jamais lu par le dashboard
            ignores += 1
            continue
        errs, warns, s = res
        if not s:
            print(f"\n[X] {Path(f).name}")
            for e in errs:
                print(f"     ERREUR  {e}")
            total_err += len(errs)
            continue
        mark = "[X]" if errs else ("[!]" if warns else "[OK]")
        print(f"\n{mark} {Path(f).name}")
        print(f"     profil={s['profil']} score={s['score']} · {s['agents']} agent(s) · "
              f"{s['attaques']} attaque(s) · {s['vulns']} vuln(s) · {s['axes_notes']} axe(s) noté(s)")
        for e in errs:
            print(f"     ERREUR  {e}")
        for w in warns:
            print(f"     avert.  {w}")
        total_err += len(errs)

    print(f"\n{'=' * 60}")
    print(f"{len(files) - ignores} audit(s) vérifié(s) — {total_err} erreur(s)"
          + (f"  ({ignores} fichier(s) hors périmètre ignoré(s))" if ignores else ""))
    return 1 if total_err else 0


if __name__ == "__main__":
    sys.exit(main())
