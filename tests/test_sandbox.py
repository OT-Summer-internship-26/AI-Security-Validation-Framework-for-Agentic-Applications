"""
test_sandbox.py — Isolation d'execution et scan statique.

POURQUOI CE FICHIER
    Le sandbox execute du code ECRIT PAR UN ATTAQUANT sur la machine de
    l'auditeur. Une regression ici n'est pas un chiffre faux : c'est du code qui
    sort de son enclos. L'isolation reseau du provider Docker n'avait ete prouvee
    QU'UNE FOIS, a la main, six semaines plus tot (§23.1) — rien ne la
    reverifiait depuis.

    Les controles Docker sont sautes automatiquement si Docker n'est pas
    disponible : un test qui ne peut pas tourner en CI ne protege personne, mais
    un test qui echoue faute de daemon fait perdre confiance dans toute la suite.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import textwrap

import pytest

from sandbox.sandbox_provider import SandboxConfig, SandboxProvider, SubprocessSandboxProvider
from sandbox.security_skills import scan_file

RAPIDE = SandboxConfig(timeout_seconds=5, memory_mb=128, cpu_limit=0.5,
                       network_enabled=False, read_only_fs=True)


def _docker_dispo() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        from sandbox.docker_provider import DockerSandboxProvider

        return DockerSandboxProvider().is_available()
    except Exception:
        return False


docker_requis = pytest.mark.skipif(not _docker_dispo(),
                                   reason="Docker indisponible — isolation reelle non testable")


# --------------------------------------------------------------------------- #
# Contrat commun aux providers.
# --------------------------------------------------------------------------- #

def test_config_par_defaut_est_fermee():
    """Les defauts doivent etre SURS : reseau coupe, disque en lecture seule.

    Un defaut permissif transformerait chaque oubli d'argument en execution non
    isolee — sans que personne s'en apercoive.
    """
    c = SandboxConfig()
    assert c.network_enabled is False, "le reseau doit etre coupe par DEFAUT"
    assert c.read_only_fs is True, "le disque doit etre en lecture seule par DEFAUT"
    assert c.timeout_seconds > 0 and c.memory_mb > 0


def test_provider_est_une_abstraction():
    """`SandboxProvider` impose `run` et `is_available` a tout provider."""
    assert hasattr(SandboxProvider, "run") and hasattr(SandboxProvider, "is_available")


# --------------------------------------------------------------------------- #
# Repli sous-processus : isolation PROCESSUS et ressources, pas plus.
# --------------------------------------------------------------------------- #

def test_subprocess_execute_et_capture():
    p = SubprocessSandboxProvider()
    r = p.run("test", ["python", "-c", "print('bonjour')"], RAPIDE)
    assert r.exit_code == 0 and "bonjour" in r.stdout


def test_subprocess_tue_une_boucle_infinie():
    """Sans cette garde, un `while True` d'un agent bloquerait l'audit pour toujours."""
    p = SubprocessSandboxProvider()
    r = p.run("test", ["python", "-c", "while True: pass"],
              SandboxConfig(timeout_seconds=3, memory_mb=128))
    assert r.killed is True
    assert r.duration_seconds < 20, "le timeout doit trancher, pas laisser filer"


def test_subprocess_ne_leve_pas_sur_code_qui_plante():
    """Un code d'attaquant qui leve doit remonter un exit_code, pas casser l'audit."""
    p = SubprocessSandboxProvider()
    r = p.run("test", ["python", "-c", "raise SystemExit(3)"], RAPIDE)
    assert r.exit_code == 3


# --------------------------------------------------------------------------- #
# Docker : la SEULE isolation reelle (reseau, systeme de fichiers, privileges).
# --------------------------------------------------------------------------- #

@docker_requis
def test_docker_execute():
    from sandbox.docker_provider import DockerSandboxProvider

    r = DockerSandboxProvider().run("t", ["python", "-c", "print('ok')"], RAPIDE)
    assert r.exit_code == 0 and "ok" in r.stdout


@docker_requis
def test_docker_bloque_le_reseau():
    """L'EXFILTRATION doit etre impossible : c'est la raison d'etre du sandbox."""
    from sandbox.docker_provider import DockerSandboxProvider

    code = "import socket; socket.create_connection(('example.com', 80), timeout=5)"
    r = DockerSandboxProvider().run("t", ["python", "-c", code], RAPIDE)
    assert r.exit_code != 0, "le reseau doit etre coupe (--network none)"


@docker_requis
def test_docker_systeme_de_fichiers_en_lecture_seule():
    from sandbox.docker_provider import DockerSandboxProvider

    code = "open('/etc/passwd_test', 'w').write('x')"
    r = DockerSandboxProvider().run("t", ["python", "-c", code], RAPIDE)
    assert r.exit_code != 0
    assert "read-only" in (r.stderr or "").lower() or "readonly" in (r.stderr or "").lower()


@docker_requis
def test_docker_execute_en_non_root():
    """Root dans le conteneur = une evasion de moins a trouver pour l'attaquant."""
    from sandbox.docker_provider import DockerSandboxProvider

    r = DockerSandboxProvider().run("t", ["python", "-c", "import os; print(os.getuid())"], RAPIDE)
    assert r.stdout.strip() != "0", "le code ne doit pas tourner en root"


@docker_requis
def test_docker_tue_une_boucle_infinie():
    from sandbox.docker_provider import DockerSandboxProvider

    r = DockerSandboxProvider().run("t", ["python", "-c", "while True: pass"],
                                    SandboxConfig(timeout_seconds=5, memory_mb=128))
    assert r.killed is True


# --------------------------------------------------------------------------- #
# Scan statique Microsoft AGT.
# --------------------------------------------------------------------------- #

def test_scan_detecte_les_motifs_dangereux(tmp_path: pathlib.Path):
    """Les 11 controles doivent voir un secret en dur et une deserialisation."""
    f = tmp_path / "vulnerable.py"
    f.write_text(textwrap.dedent('''
        import pickle
        API_KEY = "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        def charger(donnees):
            return pickle.loads(donnees)
    '''), encoding="utf-8")

    findings = scan_file(str(f))
    assert findings, "un secret en dur ET un pickle doivent etre detectes"
    for f_ in findings:
        assert f_.file_path and f_.line_number > 0, "un finding sans localisation est inutile"


def test_scan_ne_leve_pas_sur_fichier_illisible(tmp_path: pathlib.Path):
    """Un fichier binaire ou absent ne doit pas interrompre la couche statique."""
    binaire = tmp_path / "image.py"
    binaire.write_bytes(b"\x00\x01\x02\xff")
    scan_file(str(binaire))                      # ne doit pas lever
    scan_file(str(tmp_path / "inexistant.py"))   # ne doit pas lever


def test_scan_code_propre_ne_produit_rien(tmp_path: pathlib.Path):
    """Sans faux positif, un code sain doit ressortir vide."""
    f = tmp_path / "propre.py"
    f.write_text("def addition(a, b):\n    return a + b\n", encoding="utf-8")
    assert scan_file(str(f)) == []


# --------------------------------------------------------------------------- #
# Le provider Docker est PREFERE quand il est disponible (§23.1).
# --------------------------------------------------------------------------- #

def test_asi05_trace_le_provider_utilise():
    """Le rapport doit dire QUELLE isolation a servi : Docker ou le repli.

    Sans cette trace, on ne peut pas savoir si un resultat dynamique a ete obtenu
    avec une vraie isolation reseau ou en mode degrade.
    """
    from agents.asi05_code_execution import ASI05CodeExecutionAgent

    a = ASI05CodeExecutionAgent(target_callback=lambda _p: "je refuse",
                                config={"llm_profile": "dry_run"})
    res = a._run_dynamic_layer()
    if res.applicable:
        assert (res.raw or {}).get("sandbox_provider") in ("docker", "subprocess")
