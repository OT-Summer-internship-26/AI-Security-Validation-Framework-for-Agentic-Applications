"""
rebuild_attacks.py — Reconstruit la liste d'attaques d'un audit déjà produit.

POURQUOI
    Les enregistrements par test (`layers.behavioral.raw.deepteam_stats.records`)
    contiennent déjà prompt, réponse, verdict et analyse du juge. Si le champ
    `attacks[]` d'un audit a été écrit avant que le journal unifié n'existe, il
    ne contient que la trace réseau brute, sans verdict. Ce script régénère
    `attacks[]` à partir des enregistrements — SANS relancer d'audit, donc sans
    consommer ni tokens ni temps.

USAGE
    python scripts/rebuild_attacks.py                 # tous les audits
    python scripts/rebuild_attacks.py <fichier.json>  # un seul
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = Path(__file__).resolve().parent.parent
# Ce script n'importait rien du projet : la racine doit etre ajoutee
# explicitement pour atteindre `workflow.paths`.
sys.path.insert(0, str(ROOT))
# Point de resolution UNIQUE du repertoire de resultats : en production
# il pointe vers un volume persistant (AUDIT_RESULTS_DIR).
from workflow.paths import results_dir

RESULTS = results_dir()


def axis_of(title: str) -> str | None:
    """Déduit l'axe d'une vulnérabilité comportementale depuis son titre."""
    if title.startswith("Garak"):
        return "Garak"
    if "PyRIT" in title:
        return "PyRIT"
    if "Arcanum" in title or "Microsoft" in title:
        return "Microsoft"
    return None


def rebuild(path: Path) -> bool:
    data = json.loads(path.read_text(encoding="utf-8"))
    changed = False

    for cat, agent in (data.get("agents") or {}).items():
        beh = ((agent.get("layers") or {}).get("behavioral") or {})
        raw = beh.get("raw") or {}
        records = ((raw.get("deepteam_stats") or {}).get("records")) or []
        if not records:
            print(f"  {cat}: aucun enregistrement par test — audit trop ancien, ignoré")
            continue

        log = [dict(r) for r in records]

        # Une entrée par vulnérabilité des autres axes (leur preuve est le matériau).
        for v in agent.get("vulnerabilities") or []:
            if v.get("layer") != "behavioral":
                continue
            axis = axis_of(v.get("title") or "")
            if axis is None:
                continue
            log.append({
                "prompt": "", "response": (v.get("evidence") or "")[:2000],
                "verdict": "compromised", "vulnerability": v.get("title", ""),
                "vulnerability_type": "", "technique": v.get("title", ""),
                "axis": axis, "layer": "behavioral", "severity": v.get("severity"),
                "judge_reason": (v.get("recommendation") or "")[:800],
            })

        raw["attack_log"] = log
        beh["raw"] = raw
        agent["attacks"] = log
        changed = True

        counts: dict[str, int] = {}
        for a in log:
            counts[a.get("verdict", "?")] = counts.get(a.get("verdict", "?"), 0) + 1
        print(f"  {cat}: {len(log)} attaques reconstruites → {counts}")

    if changed:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return changed


def main() -> int:
    targets = (
        [Path(sys.argv[1])] if len(sys.argv) > 1
        else sorted(p for p in RESULTS.glob("*.json") if p.name != "sample_audit.json")
    )
    done = 0
    for p in targets:
        if not p.exists():
            print(f"introuvable : {p}")
            continue
        print(f"\n{p.name}")
        if rebuild(p):
            done += 1
    print(f"\n{done} audit(s) mis à jour.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
