"""
run_audit_global.py — Audit GLOBAL : les 10 catégories ASI sur une même cible → score /100.

POURQUOI CE SCRIPT EXISTE
    `workflow.run_audit()` consolide bien un AuditState, mais il ne PERSISTE rien :
    un audit de plusieurs heures qui se termine sans écrire sur disque est perdu si
    quoi que ce soit tombe. Ce script enchaîne les catégories via `run_agent.py` —
    le runner déjà éprouvé, celui qu'utilise aussi l'API — et RÉÉCRIT le fichier
    global après CHAQUE agent. Un plantage au 8e agent laisse les 7 premiers.

POURQUOI PAS UN NOUVEAU RUNNER
    Un sous-processus par agent donne le fail-safe (§7) gratuitement : un agent qui
    plante ne peut pas emporter les autres, et chaque agent produit déjà son propre
    fichier lisible par le dashboard. On ne réimplémente donc ni le run, ni le format.

Usage :
    python scripts/run_audit_global.py --target http://localhost:8090/api/chat \
        --profile final --attacks-per-type 1
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

OUT_DIR = ROOT / "data" / "audit_results"
RUNNER = ROOT / "scripts" / "run_agent.py"


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit global 10 catégories → score /100")
    ap.add_argument("--target", required=True)
    ap.add_argument("--profile", default="final", choices=["dev", "ollama", "final", "dry_run"])
    ap.add_argument("--prompt-field", default="message")
    ap.add_argument("--response-field", default="response")
    ap.add_argument("--extra-payload", default=None)
    ap.add_argument("--attacks-per-type", type=int, default=1)
    ap.add_argument("--pyrit-max-turns", type=int, default=2)
    ap.add_argument("--max-concurrent", type=int, default=2)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--garak-probes", default="dan.DAN_Jailbreak")
    ap.add_argument("--categories", default=None,
                    help="sous-ensemble, ex. 'ASI_01,ASI_05' (défaut : les 10)")
    ap.add_argument("--source-path", default=None, help="couche statique (ASI02/04/05)")
    ap.add_argument("--requirements-path", default=None, help="pip-audit (ASI04)")
    args = ap.parse_args()

    from workflow.audit_graph import AGENT_REGISTRY
    from workflow.scoring import calculate_global_score, get_risk_level

    cats = ([c.strip() for c in args.categories.split(",")] if args.categories
            else list(AGENT_REGISTRY))

    stamp = datetime.now()
    out = OUT_DIR / f"{stamp:%Y%m%d_%H%M%S}_GLOBAL_{args.profile}.json"
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    record: dict = {
        "audit_id": f"GLOBAL-{stamp:%Y%m%d%H%M%S}",
        "timestamp": stamp.astimezone().isoformat(),
        "target_url": args.target,
        "target_name": f"{args.target} (audit global)",
        "llm_profile": args.profile,
        "global_score": 0.0,
        "risk_level": "—",
        "status": "running",
        "categories_requested": cats,
        "agents": {},
        "transcript": [],
    }

    common = [
        "--target", args.target,
        "--prompt-field", args.prompt_field,
        "--response-field", args.response_field,
        "--profile", args.profile,
        "--attacks-per-type", str(args.attacks_per_type),
        "--pyrit-max-turns", str(args.pyrit_max_turns),
        "--max-concurrent", str(args.max_concurrent),
        "--timeout", str(args.timeout),
        "--garak-probes", args.garak_probes,
    ]
    for flag, val in (("--extra-payload", args.extra_payload),
                      ("--source-path", args.source_path),
                      ("--requirements-path", args.requirements_path)):
        if val:
            common += [flag, val]

    t0 = time.time()
    for i, cat in enumerate(cats, 1):
        print(f"\n{'='*70}\n[{i}/{len(cats)}] {cat}\n{'='*70}", flush=True)
        before = {p.name for p in OUT_DIR.glob("*.json")}
        rc = subprocess.run([sys.executable, str(RUNNER), cat, *common], cwd=str(ROOT)).returncode

        # Le runner nomme son fichier à l'heure de FIN : on repère celui qui est apparu.
        new = [p for p in OUT_DIR.glob(f"*_{cat}_*.json") if p.name not in before]
        if not new:
            record["agents"][cat] = {"name": cat, "status": "failed", "score": 0.0,
                                     "error": f"aucun résultat produit (rc={rc})"}
        else:
            per_agent = json.loads(max(new, key=lambda p: p.stat().st_mtime)
                                   .read_text(encoding="utf-8"))
            record["agents"].update(per_agent.get("agents", {}))
            record["transcript"] += per_agent.get("transcript", [])

        # Consolidation APRÈS CHAQUE agent : le fichier global est toujours à jour.
        scores = {c: float(a.get("score") or 0.0) for c, a in record["agents"].items()}
        record["global_score"] = calculate_global_score(scores)
        record["risk_level"] = get_risk_level(record["global_score"])
        record["duration_seconds"] = int(time.time() - t0)
        out.write_text(json.dumps(record, indent=2, ensure_ascii=False, default=str),
                       encoding="utf-8")
        print(f"[global] {cat} → {scores.get(cat)}/10 · "
              f"cumul {record['global_score']}/100 ({record['risk_level']})", flush=True)

    record["status"] = "completed"
    out.write_text(json.dumps(record, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    print(f"\n{'='*70}")
    for cat, a in record["agents"].items():
        print(f"  {cat}  {a.get('score')}/10   {a.get('status')}")
    print(f"\n  SCORE GLOBAL : {record['global_score']}/100 — {record['risk_level']}")
    print(f"  seuil CI/CD 70 → {'PASSE' if record['global_score'] >= 70 else 'BLOQUE'}")
    print(f"  {len(record['agents'])} catégories · {record['duration_seconds']}s")
    print(f"\nEnregistré : {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
