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
    ap.add_argument("--subprocess", action="store_true",
                    help="orchestration par SOUS-PROCESSUS au lieu de LangGraph : un "
                         "processus isole par categorie. Plus lent et sans reprise, mais "
                         "un arret brutal (OOM, kill) n'emporte que l'agent en cours.")
    ap.add_argument("--resume", metavar="THREAD_ID",
                    help="reprend un audit interrompu : les agents deja termines ne sont "
                         "pas rejoues. L'identifiant est affiche au lancement.")
    args = ap.parse_args()

    from workflow.audit_graph import AGENT_REGISTRY
    from workflow.audit_graph import consolidate

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

    # LangGraph est le chemin par DEFAUT (§1 : « Workflow LangGraph orchestre les
    # 10 agents »). Les sous-processus restent disponibles pour l'isolation.
    if not args.subprocess:
        return _run_via_graph(args, cats, record, out, t0)

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
        from judge.summary import build_judge_summary

        js = build_judge_summary(record["agents"])
        if js:
            record["judge_summary"] = js
        # Les agents non mesures (cible injoignable, tous axes exclus) sortent du
        # score : compter leur 0 dirait « totalement compromis » sans preuve.
        scores = {c: float(a.get("score") or 0.0) for c, a in record["agents"].items()
                  if a.get("measured", True)}
        record.update(consolidate(scores))
        record["duration_seconds"] = int(time.time() - t0)
        out.write_text(json.dumps(record, indent=2, ensure_ascii=False, default=str),
                       encoding="utf-8")
        print(f"[global] {cat} → {scores.get(cat)}/10 · "
              f"cumul {record['global_score']}/100 ({record['risk_level']})", flush=True)

    # Vide la file LangFuse : sans flush, les dernieres observations meurent avec
    # le processus. Le chemin LangGraph est le mode PAR DEFAUT — c'est donc ici
    # qu'il manquait, `run_agent.py` (sous-processus) l'ayant deja.
    from judge.tracing import flush as _flush_traces

    _flush_traces()
    record["status"] = "completed"
    out.write_text(json.dumps(record, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    print(f"\n{'='*70}")
    for cat, a in record["agents"].items():
        print(f"  {cat}  {a.get('score')}/10   {a.get('status')}")
    print(f"\n  SCORE GLOBAL : {record['global_score']}/100 — {record['risk_level']}")
    print(f"  seuil CI/CD 70 → {'PASSE' if record['global_score'] >= 70 else 'BLOQUE'}")
    record.setdefault("duration_seconds", int(time.time() - t0))
    print(f"  {len(record['agents'])} catégories · {record['duration_seconds']}s")
    print(f"\nEnregistré : {out.relative_to(ROOT)}")
    return 0




def _run_via_graph(args, cats, record, out, t0) -> int:
    """Orchestration LangGraph : deux vagues paralleles, meme fichier de sortie.
    POURQUOI CE MODE EXISTE
        Le §1 du projet annonce que LangGraph orchestre les dix agents. Tant que
        rien ne l'appelait, c'etait du code que personne n'executait — et une
        promesse que le projet ne tenait pas.

    LA PERSISTANCE EST LA MEME QUE POUR LES SOUS-PROCESSUS
        Le crochet `on_agent_done` reecrit le fichier global des qu'un agent
        termine. Un plantage au huitieme agent laisse donc les sept premiers, comme
        dans l'autre mode. Ce n'etait pas une limite de LangGraph, seulement une
        limite de ce qu'on ecrivait autour.

    CE QUI RESTE DIFFERENT, ET QU'IL FAUT SAVOIR
        Les dix agents partagent UN processus. `_run_one` capture les exceptions,
        donc un agent qui echoue n'emporte pas les autres — mais un arret brutal
        (memoire saturee, kill) tue tout le run, la ou des sous-processus isolent.
        C'est le seul avantage restant du mode par defaut.
    """
    from judge.summary import build_judge_summary
    from workflow.audit_graph import run_audit_graph
    from workflow.audit_graph import consolidate
    from workflow.serialization import build_agent_entry

    # Le thread de reprise est ecrit AVANT le premier agent, pas a la fin.
    # Sinon il n'existe dans le fichier que si l'audit va jusqu'au bout — donc
    # jamais dans le cas ou l'on en a besoin : celui ou l'audit a ete interrompu.
    record["thread_id"] = args.resume or f"audit-{datetime.now():%Y%m%d%H%M%S}"
    print(f"Thread de reprise : {record['thread_id']}"
          f"\n  (reprendre avec --resume {record['thread_id']})\n", flush=True)

    def persiste(category: str, result) -> None:
        """Ecrit le fichier global des qu'un agent termine.

        Appele depuis le CONSOMMATEUR du flux LangGraph, donc dans un seul
        thread : aucun verrou necessaire. C'est cette ecriture qui garantit que
        les RESULTATS ne sont jamais perdus, meme pour un agent dont le
        checkpoint n'a pas ete valide avant un arret brutal.
        """
        record["agents"][category] = build_agent_entry(category, result)
        # Les agents non mesures (cible injoignable, tous axes exclus) sortent du
        # score : compter leur 0 dirait « totalement compromis » sans preuve.
        scores = {c: float(a.get("score") or 0.0) for c, a in record["agents"].items()
                  if a.get("measured", True)}
        record.update(consolidate(scores))
        record["duration_seconds"] = int(time.time() - t0)
        out.write_text(json.dumps(record, indent=2, ensure_ascii=False, default=str),
                       encoding="utf-8")
        print(f"[global] {category} → {result.score}/10 · "
              f"cumul {record['global_score']}/100 ({record['risk_level']})", flush=True)

    cfg = {
        "llm_profile": args.profile, "prompt_field": args.prompt_field,
        "response_field": args.response_field,
        "extra_payload": json.loads(args.extra_payload) if args.extra_payload else None,
        "attacks_per_type": args.attacks_per_type, "max_concurrent": args.max_concurrent,
        "pyrit_max_turns": args.pyrit_max_turns, "http_timeout": args.timeout,
        "garak_probes": args.garak_probes, "garak_request_timeout": int(args.timeout),
    }
    if args.source_path:
        cfg["source_path"] = args.source_path
    if args.requirements_path:
        cfg["requirements_path"] = args.requirements_path

    from judge.tracing import set_context

    set_context(audit_id=record["audit_id"], profile=args.profile)
    state = run_audit_graph(args.target, cfg, categories=cats,
                            thread_id=record["thread_id"], on_agent_done=persiste)

    # REPRISE : les agents deja termines ne sont pas rejoues, donc `persiste` n'a
    # pas ete appele pour eux — sans ce comblement, un audit repris produirait un
    # fichier VIDE et un score 0, ce qui se lirait comme une cible parfaitement
    # compromise. On recopie depuis l'etat restitue par le checkpoint.
    for category, result in (state.results or {}).items():
        if category not in record["agents"]:
            record["agents"][category] = build_agent_entry(category, result)
    if state.results:
        # Les agents non mesures (cible injoignable, tous axes exclus) sortent du
        # score : compter leur 0 dirait « totalement compromis » sans preuve.
        scores = {c: float(a.get("score") or 0.0) for c, a in record["agents"].items()
                  if a.get("measured", True)}
        record.update(consolidate(scores))

    # Vide la file LangFuse : sans flush, les dernieres observations meurent avec
    # le processus. Le chemin LangGraph est le mode PAR DEFAUT — c'est donc ici
    # qu'il manquait, `run_agent.py` (sous-processus) l'ayant deja.
    from judge.tracing import flush as _flush_traces

    _flush_traces()
    record["status"] = "completed"
    out.write_text(json.dumps(record, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    print(f"\n{'='*70}")
    for cat, a in record["agents"].items():
        print(f"  {cat}  {a.get('score')}/10   {a.get('status')}")
    print(f"\n  SCORE GLOBAL : {record['global_score']}/100 — {record['risk_level']}")
    print(f"  seuil CI/CD 70 → {'PASSE' if record['global_score'] >= 70 else 'BLOQUE'}")
    record.setdefault("duration_seconds", int(time.time() - t0))
    print(f"  {len(record['agents'])} catégories · {record['duration_seconds']}s")
    print(f"\nEnregistré : {out.relative_to(ROOT)}")
    return 0




if __name__ == "__main__":
    raise SystemExit(main())
