"""
compare_audits.py — Compare deux audits de la meme cible : avant / apres correctif.

Usage :
    python scripts/compare_audits.py                       # les 2 audits les plus recents
    python scripts/compare_audits.py AVANT.json APRES.json
    python scripts/compare_audits.py --category ASI_05     # derniers audits de cette categorie
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Point de resolution UNIQUE du repertoire de resultats : en production
# il pointe vers un volume persistant (AUDIT_RESULTS_DIR).
from workflow.paths import affichable, results_dir

RESULTS = results_dir()
REPORTS = ROOT / "data" / "reports"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _latest(category: str | None, n: int = 2) -> list[Path]:
    """Les n audits les plus recents, filtres par categorie si demande."""
    files = [p for p in RESULTS.glob("*.json") if "dry_run" not in p.name]
    if category:
        files = [p for p in files if category in p.name]
    return sorted(files, key=lambda p: p.stat().st_mtime)[-n:]


def main() -> int:
    ap = argparse.ArgumentParser(description="Comparaison avant / apres de deux audits")
    ap.add_argument("before", nargs="?", help="audit AVANT (defaut : l'avant-dernier)")
    ap.add_argument("after", nargs="?", help="audit APRES (defaut : le plus recent)")
    ap.add_argument("--category", help="restreindre a une categorie, ex. ASI_05")
    ap.add_argument("--out", help="fichier HTML de sortie")
    args = ap.parse_args()

    from reporting.comparison import compare_audits, render_comparison

    if args.before and args.after:
        paths = [Path(args.before), Path(args.after)]
    else:
        paths = _latest(args.category)
        if len(paths) < 2:
            ap.error("moins de deux audits disponibles — preciser les fichiers a comparer")
    for p in paths:
        if not p.exists():
            ap.error(f"introuvable : {p}")

    before, after = _load(paths[0]), _load(paths[1])
    print(f"AVANT : {paths[0].name}\nAPRES : {paths[1].name}\n")

    c = compare_audits(before, after)
    print(f"  score global : {c['global_before']} -> {c['global_after']} "
          f"({c['global_delta']:+.1f})   confiance {c['confidence']}")
    for r in c["categories"]:
        if r["delta"]:
            print(f"    {r['category']:8} {r['before']} -> {r['after']}  ({r['delta']:+.2f})")
    print(f"\n  corrigees {len(c['fixed'])} · persistantes {len(c['persistent'])} · "
          f"nouvelles {len(c['new'])} · aggravees {len(c['worsened'])} · "
          f"attenuees {len(c['improved'])}")
    print(f"\n  {c['verdict']}\n")

    out = Path(args.out) if args.out else (
        REPORTS / f"comparaison_{datetime.now():%Y%m%d_%H%M%S}.html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_comparison(c), encoding="utf-8")
    print(f"Rapport : {affichable(out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
