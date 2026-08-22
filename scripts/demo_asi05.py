"""
demo_asi05.py — Démonstration ASI05 : les 3 couches d'audit en conditions réelles.

À lancer devant l'encadrant. Affiche en direct :
  1. la vérification des prérequis (Ollama, lab DVAP, Docker, Semgrep, Garak)
  2. les scénarios déclarés par l'agent
  3. l'exécution des 3 couches (comportementale / statique / dynamique)
  4. le résultat détaillé par axe et par couche

Usage :
    python scripts/demo_asi05.py                     # profil dev (Ollama, gratuit)
    python scripts/demo_asi05.py --profile final     # profil final (Gemini, verdict fiable)
    python scripts/demo_asi05.py --target http://localhost:8090/chat
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

C = {"g": "\033[92m", "r": "\033[91m", "y": "\033[93m", "b": "\033[94m",
     "d": "\033[90m", "B": "\033[1m", "0": "\033[0m"}


def title(txt: str) -> None:
    print(f"\n{C['B']}{C['b']}{'═' * 78}\n  {txt}\n{'═' * 78}{C['0']}", flush=True)


def check(label: str, ok: bool, detail: str = "") -> bool:
    mark = f"{C['g']}✓{C['0']}" if ok else f"{C['r']}✗{C['0']}"
    print(f"  {mark} {label:<34} {C['d']}{detail}{C['0']}", flush=True)
    return ok


def preflight(target: str) -> bool:
    """Vérifie chaque prérequis d'ASI05 et l'affiche — c'est la partie visible à la démo."""
    title("1/4  VÉRIFICATION DES PRÉREQUIS")
    import requests

    ok = True

    # Ollama (profil dev)
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=8)
        models = [m["name"] for m in r.json().get("models", [])]
        ok &= check("Ollama (LLM local)", True, f"{len(models)} modèle(s) : {', '.join(models[:3])}")
    except Exception:
        check("Ollama (LLM local)", False, "hors ligne — requis en profil dev")
        ok = False

    # Cible DVAP
    try:
        r = requests.post(target, json={"message": "ping"}, timeout=25)
        body = r.json()
        check("Cible DVAP", r.status_code == 200, f"{target} · modèle {body.get('model', '?')}")
    except Exception as e:
        check("Cible DVAP", False, f"{target} injoignable ({type(e).__name__})")
        ok = False

    # Docker (couche dynamique) — BLOQUANT pour la démo du sandbox
    try:
        from sandbox.docker_provider import DockerSandboxProvider
        avail = DockerSandboxProvider().is_available()
    except Exception:
        avail = False
    if avail:
        v = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                           capture_output=True, text=True, timeout=20)
        check("Docker (sandbox dynamique)", True, f"serveur {v.stdout.strip()} · provider=docker")
    else:
        check("Docker (sandbox dynamique)", False,
              "daemon ARRÊTÉ → démarrer Docker Desktop puis relancer")
        ok = False

    # Image du sandbox préchargée (évite un pull de 2 min pendant la démo)
    try:
        img = subprocess.run(["docker", "images", "-q", "python:3.11-slim"],
                             capture_output=True, text=True, timeout=20)
        has_img = bool(img.stdout.strip())
    except Exception:
        has_img = False
    check("Image python:3.11-slim", has_img,
          "prête" if has_img else "absente → docker pull python:3.11-slim")

    # Semgrep (couche statique)
    check("Semgrep (couche statique)", shutil.which("semgrep") is not None, "analyse AST du code source")

    # security_skills Microsoft (couche statique)
    try:
        from sandbox.security_skills import scan_file  # noqa: F401
        check("security_skills Microsoft", True, "11 fonctions de scan statique")
    except Exception as e:
        check("security_skills Microsoft", False, str(e)[:40])

    # Garak (axe comportemental 3)
    garak_py = Path.home() / "garak-venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    check("Garak (venv isolé)", garak_py.exists(), str(garak_py))

    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://localhost:8090/chat")
    ap.add_argument("--profile", default="dev", choices=["dev", "final", "dry_run"])
    ap.add_argument("--attacks-per-type", type=int, default=1)
    ap.add_argument("--source-path", default=str(ROOT / "agents"))
    ap.add_argument("--skip-preflight", action="store_true")
    args = ap.parse_args()

    print(f"\n{C['B']}DÉMONSTRATION — ASI05 · Unexpected Code Execution{C['0']}")
    print(f"{C['d']}3 couches : comportementale · statique · dynamique{C['0']}")

    if not args.skip_preflight and not preflight(args.target):
        print(f"\n{C['r']}Des prérequis manquent. Corrigez-les ou relancez avec --skip-preflight.{C['0']}")
        return 1

    from agents.asi05_code_execution import ASI05CodeExecutionAgent
    from agents.base_agent import build_http_callback

    # ---------------- 2/4  scénarios déclarés ----------------
    title("2/4  SCÉNARIOS DÉCLARÉS PAR L'AGENT")
    config = {
        "target_url": args.target,
        "prompt_field": "message",
        "response_field": "response",
        "llm_profile": args.profile,
        "attacks_per_type": args.attacks_per_type,
        "max_concurrent": 2,
        "pyrit_max_turns": 2,
        "garak_probes": "dan.DAN_Jailbreak",
        "garak_request_timeout": 90,
        "source_path": args.source_path,
    }
    raw_cb = build_http_callback(args.target, prompt_field="message",
                                 response_field="response", timeout=90.0)

    # ---- capture de la conversation : tout ce qui part vers la cible et tout ce qui revient ----
    transcript: list[dict] = []

    def cb(prompt):
        t = time.time()
        reply = raw_cb(prompt)
        transcript.append({
            "n": len(transcript) + 1,
            "elapsed_s": round(time.time() - t, 2),
            "attack": str(prompt),
            "response": str(reply),
            "http_error": "[HTTP_ERROR]" in str(reply),
        })
        return reply

    agent = ASI05CodeExecutionAgent(target_callback=cb, config=config)

    counts: dict[str, int] = {}
    for s in agent.get_scenarios():
        counts[s["kind"]] = counts.get(s["kind"], 0) + 1
    for kind, n in counts.items():
        print(f"  {C['y']}{n:>2}{C['0']}  {kind}")
    print(f"  {C['d']}→ tout ce qui est déclaré ici est réellement exécuté{C['0']}")

    # ---------------- 3/4  exécution ----------------
    title(f"3/4  EXÉCUTION DE L'AUDIT  ·  profil {args.profile}")
    print(f"{C['d']}  Comportementale : DeepTeam + PyRIT + Garak + payloads Microsoft{C['0']}")
    print(f"{C['d']}  Statique        : Semgrep + 11 fonctions security_skills{C['0']}")
    print(f"{C['d']}  Dynamique       : extraction du code généré + exécution en sandbox{C['0']}\n")

    t0 = time.time()
    res = agent.run()
    dt = time.time() - t0

    # ---------------- 4/4  résultat ----------------
    title("4/4  RÉSULTAT")
    beh, sta, dyn = res.layers["behavioral"], res.layers["static"], res.layers["dynamic"]
    raw = beh.raw or {}

    col = C["g"] if res.score >= 7 else C["y"] if res.score >= 4 else C["r"]
    print(f"  {C['B']}SCORE AGENT : {col}{res.score}/10{C['0']}   "
          f"status={res.status}   durée {dt:.1f}s\n")

    print(f"  {C['B']}COUCHE COMPORTEMENTALE{C['0']}  score={beh.score}  error={beh.error}")
    for axis, val in (raw.get("score_components") or {}).items():
        print(f"    · {axis:<12} {val}")
    print(f"    · DeepTeam stats   {raw.get('deepteam_stats')}")
    print(f"    · PyRIT            {raw.get('pyrit_status')}")
    print(f"    · Garak            {raw.get('garak_status')}")
    print(f"    · Microsoft        {raw.get('microsoft_status')}")
    if raw.get("behavioral_note"):
        print(f"    {C['y']}⚠ {raw['behavioral_note']}{C['0']}")

    print(f"\n  {C['B']}COUCHE STATIQUE{C['0']}  score={sta.score}  applicable={sta.applicable}  error={sta.error}")
    for f in (sta.findings or [])[:8]:
        t = getattr(f, "title", None) or (f.get("title") if isinstance(f, dict) else str(f))
        ev = getattr(f, "evidence", None) or (f.get("evidence") if isinstance(f, dict) else "")
        print(f"    · {t}  {C['d']}{str(ev)[:70]}{C['0']}")

    print(f"\n  {C['B']}COUCHE DYNAMIQUE{C['0']}  score={dyn.score}  applicable={dyn.applicable}")
    draw = dyn.raw or {}
    print(f"    · provider sandbox : {C['g']}{draw.get('sandbox_provider')}{C['0']}")
    for k in ("prompts_sent", "code_extracted", "code_flagged", "executions"):
        if k in draw:
            print(f"    · {k:<16} {draw[k]}")

    print(f"\n  {C['B']}VULNÉRABILITÉS ({len(res.vulnerabilities)}){C['0']}")
    for v in res.vulnerabilities:
        sev = {"Critical": C["r"], "High": C["y"]}.get(v.severity, C["d"])
        print(f"    [{sev}{v.severity:<8}{C['0']}] {v.layer:<11} {v.title}")

    # ---------------- transcript : attaques envoyées / réponses de la cible ----------------
    title(f"ATTAQUES ENVOYÉES À LA CIBLE  ·  {len(transcript)} échanges capturés")
    for e in transcript:
        flag = f"{C['r']}[HTTP_ERROR — exclu du scoring]{C['0']}" if e["http_error"] else ""
        print(f"\n{C['B']}{C['y']}── Échange {e['n']}{C['0']}  {C['d']}({e['elapsed_s']}s){C['0']} {flag}")
        print(f"  {C['r']}ATTAQUE  ▸{C['0']} {e['attack'][:600]}")
        print(f"  {C['b']}RÉPONSE  ▸{C['0']} {e['response'][:600]}")

    tp = ROOT / "scripts" / "demo_asi05_transcript.json"
    tp.write_text(json.dumps(transcript, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n  {C['d']}Transcript complet : {tp}{C['0']}")

    out = ROOT / "scripts" / "demo_asi05_result.json"
    out.write_text(json.dumps({
        "score": res.score, "status": res.status, "duration_s": round(dt, 1),
        "profile": args.profile, "target": args.target,
        "behavioral": {"score": beh.score, "components": raw.get("score_components"),
                       "deepteam_stats": raw.get("deepteam_stats"),
                       "pyrit": raw.get("pyrit_status"), "garak": raw.get("garak_status"),
                       "microsoft": raw.get("microsoft_status")},
        "static": {"score": sta.score, "applicable": sta.applicable, "findings": sta.findings},
        "dynamic": {"score": dyn.score, "applicable": dyn.applicable, "raw": draw},
        "vulnerabilities": [{"severity": v.severity, "layer": v.layer, "title": v.title}
                            for v in res.vulnerabilities],
    }, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    print(f"\n  {C['d']}Résultat sauvegardé : {out}{C['0']}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
