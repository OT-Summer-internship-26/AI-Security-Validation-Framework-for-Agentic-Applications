"""
demo_sandbox.py — Prouve en direct les 5 propriétés du sandbox Docker.

Chaque test exécute RÉELLEMENT du code dans un conteneur éphémère durci
et affiche ce que le conteneur a répondu.

Usage :  python scripts/demo_sandbox.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from sandbox.docker_provider import DockerSandboxProvider
from sandbox.sandbox_provider import SandboxConfig

G, R, Y, D, B, X = "\033[92m", "\033[91m", "\033[93m", "\033[90m", "\033[1m", "\033[0m"

TESTS = [
    ("1. Le code s'exécute réellement",
     "print('hello from container')",
     "exit_code == 0 et sortie visible"),
    ("2. --network none bloque l'exfiltration",
     "import socket; socket.create_connection(('example.com', 443), timeout=4)",
     "échec de résolution DNS, exit_code != 0"),
    ("3. Le timeout tue les boucles infinies",
     "while True: pass",
     "killed = True, kill_reason = timeout"),
    ("4. Filesystem en lecture seule",
     "open('/etc/backdoor', 'w').write('pwned')",
     "Read-only file system"),
    ("5. Exécution non-root",
     "import os; print('uid =', os.getuid())",
     "uid = 1000, jamais 0"),
]


def main() -> int:
    p = DockerSandboxProvider()
    print(f"\n{B}SANDBOX DOCKER — 5 PREUVES EN CONDITIONS RÉELLES{X}")
    print(f"{D}image python:3.11-slim · --network none · --read-only · --user 1000:1000")
    print(f"--cap-drop ALL · --security-opt no-new-privileges · timeout 5 s{X}\n")

    if not p.is_available():
        print(f"{R}Docker indisponible — démarrer Docker Desktop puis relancer.{X}")
        return 1

    cfg = SandboxConfig(timeout_seconds=5, memory_mb=128, cpu_limit=0.5,
                        network_enabled=False, read_only_fs=True)
    ok_count = 0

    for label, code, expected in TESTS:
        print(f"{B}{label}{X}")
        print(f"  {D}code    {X}{code}")
        print(f"  {D}attendu {X}{expected}")
        t0 = time.time()
        res = p.run(agent_id="demo", command=["python", "-c", code], config=cfg)
        dt = time.time() - t0

        out = (res.stdout or "").strip()
        err = (res.stderr or "").strip()
        detail = (out or err).replace("\n", " ")[:110]
        verdict_ok = {
            1: res.exit_code == 0,
            2: res.exit_code != 0,
            3: bool(res.killed),
            4: res.exit_code != 0,
            5: "uid = 1000" in out,
        }[int(label[0])]
        ok_count += verdict_ok

        color = G if verdict_ok else R
        print(f"  {D}obtenu  {X}exit={res.exit_code} killed={res.killed} "
              f"reason={res.kill_reason} ({dt:.2f}s)")
        if detail:
            print(f"  {D}sortie  {X}{color}{detail}{X}")
        print(f"  {color}{'✓ PREUVE VALIDÉE' if verdict_ok else '✗ ÉCHEC'}{X}\n")

    color = G if ok_count == len(TESTS) else Y
    print(f"{B}{color}{ok_count}/{len(TESTS)} preuves validées{X}\n")
    return 0 if ok_count == len(TESTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
