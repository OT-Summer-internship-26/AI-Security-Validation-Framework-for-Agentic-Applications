"""
docker_provider.py — DockerSandboxProvider : sandbox Docker éphémère RÉELLEMENT isolé.

CORRIGE la limite du SubprocessSandboxProvider (Windows : pas d'isolation réseau/fs
réelle). Ici `docker run` applique VRAIMENT l'isolation voulue par §6 :
    --network none      → aucun accès réseau (VÉRIFIÉ : la résolution DNS échoue
                          dans le conteneur → le code d'exfiltration plante)
    --memory / --cpus   → limites ressources strictes (+ --memory-swap = pas de swap)
    --read-only + tmpfs → filesystem en lecture seule sauf /tmp (16 Mo)
    --user 1000:1000    → exécution NON-root
    --cap-drop ALL / --security-opt no-new-privileges / --pids-limit → durcissement

Hérite de `SandboxProvider` (ABC) → interchangeable avec SubprocessSandboxProvider.
Pas de dépendance au SDK python `docker` : on invoque `docker run` par subprocess.
Timeout : le conteneur est NOMMÉ puis `docker rm -f` le tue si le client dépasse le délai
(tuer le client `docker run` ne suffit pas à arrêter le conteneur).
"""

from __future__ import annotations

import subprocess
import time
import uuid

from sandbox.sandbox_provider import SandboxConfig, SandboxProvider, SandboxResult

DOCKER_IMAGE = "python:3.11-slim"


class DockerSandboxProvider(SandboxProvider):
    """Exécute une commande dans un conteneur Docker éphémère et durci."""

    def __init__(self, image: str = DOCKER_IMAGE) -> None:
        self.image = image

    def is_available(self) -> bool:
        """Vrai si le daemon Docker répond ET l'image est présente localement."""
        try:
            r = subprocess.run(
                ["docker", "image", "inspect", self.image],
                capture_output=True, timeout=20,
            )
            return r.returncode == 0
        except Exception:
            return False

    def run(self, agent_id: str, command: list[str],
            config: SandboxConfig | None = None) -> SandboxResult:
        cfg = config or SandboxConfig()
        name = f"asi05-{uuid.uuid4().hex[:12]}"
        net = "bridge" if cfg.network_enabled else "none"
        docker_cmd = [
            "docker", "run", "--rm", "--name", name,
            "--network", net,
            "--memory", f"{cfg.memory_mb}m",
            "--memory-swap", f"{cfg.memory_mb}m",   # pas de swap
            "--cpus", str(cfg.cpu_limit),
            "--pids-limit", "64",
            "--user", "1000:1000",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
        ]
        if cfg.read_only_fs:
            docker_cmd += ["--read-only", "--tmpfs", "/tmp:size=16m,exec"]
        docker_cmd += [self.image] + list(command)

        t0 = time.time()
        # Marge pour le démarrage du conteneur ; au-delà, on force la mort du conteneur.
        client_timeout = float(cfg.timeout_seconds) + 10.0
        try:
            proc = subprocess.run(
                docker_cmd, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=client_timeout,
            )
            return SandboxResult(
                success=(proc.returncode == 0),
                exit_code=proc.returncode, stdout=proc.stdout or "",
                stderr=proc.stderr or "", killed=False, kill_reason="",
                duration_seconds=time.time() - t0,
            )
        except subprocess.TimeoutExpired:
            # Le client a dépassé le délai → tuer le conteneur récalcitrant.
            try:
                subprocess.run(["docker", "rm", "-f", name],
                               capture_output=True, timeout=20)
            except Exception:
                pass
            return SandboxResult(
                success=False, exit_code=-1, stdout="", stderr="timeout",
                killed=True, kill_reason="timeout",
                duration_seconds=time.time() - t0,
            )
        except Exception as exc:
            return SandboxResult(
                success=False, exit_code=-1, stdout="", stderr=f"docker error: {exc}",
                killed=False, kill_reason="error", duration_seconds=time.time() - t0,
            )
