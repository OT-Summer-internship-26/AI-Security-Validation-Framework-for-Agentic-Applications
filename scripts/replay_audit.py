"""
replay_audit.py — Rejoue les attaques d'un audit passé contre la même cible.

À QUOI ÇA SERT
    Vérifier qu'un correctif fonctionne. On renvoie EXACTEMENT les prompts qui
    avaient percé et on regarde si l'agent tient désormais. Contrairement à un
    nouvel audit, aucune place au hasard : mêmes attaques, donc toute différence
    de verdict est imputable à la cible, pas au simulateur.

USAGE
    python scripts/replay_audit.py <audit.json>                 # que les failles
    python scripts/replay_audit.py <audit.json> --all           # toutes les attaques
    python scripts/replay_audit.py <audit.json> --target <url>  # autre cible
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Point de resolution UNIQUE du repertoire de resultats : en production
# il pointe vers un volume persistant (AUDIT_RESULTS_DIR).
from workflow.paths import results_dir

RESULTS = results_dir()
REPLAYS = ROOT / "data" / "replays"
G, R, Y, B, D, X = "\033[92m", "\033[91m", "\033[93m", "\033[1m", "\033[90m", "\033[0m"

OUTCOME_LABEL = {
    "non_reproduite": (G, "NON REPRODUITE"),
    "regression": (R, "RÉGRESSION"),
    "toujours_vulnerable": (R, "TOUJOURS VULNÉRABLE"),
    "toujours_resistant": (D, "toujours résistante"),
    "instable": (Y, "INSTABLE — perce par intermittence"),
    "non_juge": (Y, "non jugée"),
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("audit", help="fichier d'audit à rejouer (nom ou chemin)")
    ap.add_argument("--target", default=None, help="cible (défaut : celle de l'audit)")
    ap.add_argument("--profile", default="final", choices=["dev", "ollama", "openai", "final", "dry_run"])
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("--repeat", type=int, default=3,
                help="envois par attaque (>=3 recommande : la cible est non deterministe)")
    ap.add_argument("--all", action="store_true",
                    help="rejouer TOUTES les attaques (défaut : seulement celles qui avaient percé)")
    args = ap.parse_args()

    path = Path(args.audit)
    if not path.exists():
        path = RESULTS / args.audit
    if not path.exists():
        print(f"Audit introuvable : {args.audit}")
        return 1

    data = json.loads(path.read_text(encoding="utf-8"))
    target = args.target or data.get("target_url")
    if not target:
        print("Aucune cible : précisez --target")
        return 1

    attacks = [a for ag in (data.get("agents") or {}).values() for a in (ag.get("attacks") or [])]
    print(f"\n{B}REJEU{X}  {path.name}")
    print(f"{D}cible {target} · profil {args.profile} · "
          f"{'toutes les attaques' if args.all else 'seulement les failles'}{X}\n")

    from agents.base_agent import build_http_callback
    from judge.llm_config import get_judge_models
    from judge.replay import replay_attacks

    cb = build_http_callback(target, prompt_field="message",
                             response_field="response", timeout=args.timeout)
    _, evaluation_model = get_judge_models(args.profile)

    def show(item: dict) -> None:
        color, label = OUTCOME_LABEL.get(item["outcome"], (D, item["outcome"]))
        print(f"{Y}── #{item['n']}{X} {D}{item['axis']} · {item['technique'][:40]} "
              f"({item['elapsed_s']}s){X}")
        rate = "n/d" if item['breach_rate'] is None else f"{item['breach_rate']}%"
        print(f"  {D}avant{X} {item['verdict_before']:<12} → {color}{label}{X}"
              f"   {D}percee {item['breaches']}/{item['judged']} ({rate}){X}")
        print(f"  {D}{item['judge_reason'][:160]}{X}\n")

    res = replay_attacks(attacks, cb, evaluation_model,
                         only_compromised=not args.all, repeat=args.repeat, on_progress=show)
    s = res["summary"]

    print(f"{B}══ BILAN ══{X}")
    print(f"  rejouées            {s['total']}  (jugées : {s['judged']})")
    print(f"  {G}non reproduites     {s['non_reproduite']}{X}")
    print(f"  {R}régressions         {s['regression']}{X}")
    print(f"  {R}toujours vulnérables {s['toujours_vulnerable']}{X}")
    print(f"  {D}toujours résistantes {s['toujours_resistant']}{X}")
    print(f"  {Y}instables (percent parfois) {s['instable']}{X}")
    if s.get("caveat"):
        print(f"\n  {Y}{s['caveat']}{X}")
    if s.get("not_reproduced_rate") is not None:
        print(f"\n  {B}Non reproduites : {s['not_reproduced_rate']} %{X}")
    print(f"  {D}appels utilisés {s['calls_used']} au lieu de "
          f"{s['calls_without_early_stop']} (économie {s['calls_saved']}){X}")

    REPLAYS.mkdir(parents=True, exist_ok=True)
    out = REPLAYS / f"{datetime.now():%Y%m%d_%H%M%S}_replay_{path.stem}.json"
    out.write_text(json.dumps({
        "replay_id": out.stem,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_audit": path.name,
        "target_url": target,
        "profile": args.profile,
        "only_compromised": not args.all,
        "repeat": args.repeat,
        **res,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n{G}Enregistré :{X} {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
