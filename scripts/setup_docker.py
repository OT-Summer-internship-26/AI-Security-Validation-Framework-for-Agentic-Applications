#!/usr/bin/env python
"""
setup_docker.py — Prépare Docker pour cette pile. Idempotent.

POURQUOI CE SCRIPT EXISTE
    Trois pièges ont coûté une demi-journée de diagnostic. Aucun ne produit un
    message clair : la construction échoue sur « name resolution », ou un
    service refuse de démarrer sur « permission denied ». Les documenter n'aurait
    pas suffi — une note de bas de page ne se relit pas sous la pression.

    Ce script les rend REPRODUCTIBLES. Il crée ce qu'il faut, vérifie que ça
    marche, et refuse de mentir : si un contrôle échoue, il le dit et sort.

LES TROIS PIÈGES

    1. LE RÉSEAU `bridge` PRÉEXISTANT NE PREND PAS IPv6
       Activer `"ipv6": true` dans daemon.json et redémarrer Docker ne suffit
       pas : le réseau `bridge` a été créé AVANT, et il persiste tel quel. Il
       faut un réseau créé APRÈS. C'est pourquoi un redémarrage semble n'avoir
       servi à rien — le symptôme reste identique.

    2. BUILDKIT IGNORE `network:` DANS COMPOSE
       Compose accepte la clé et BuildKit la refuse (« network mode not
       supported by buildkit »). Les CONSTRUCTIONS utilisent donc le bridge par
       défaut, sans IPv6 : `apk` et `pip` y échouent. Il faut un constructeur
       buildx lié au réseau (`--driver-opt network=...`).

    3. LA SYNTAXE LONGUE `type: tmpfs` N'APPLIQUE PAS `mode`
       Le montage arrive appartenant à root, et un service non privilégié échoue
       sur « permission denied ». Seule la forme courte `tmpfs: [/tmp:mode=1777]`
       fonctionne. Déjà corrigé dans docker-compose.yml ; ce script le VÉRIFIE,
       pour qu'un retour en arrière soit détecté ici plutôt qu'en production.

QUAND L'UTILISER
    Une fois par machine, et après tout redémarrage de Docker Desktop qui aurait
    perdu les objets créés.

        python scripts/setup_docker.py
        docker compose up -d --build
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent

RESEAU = "net6"
CONSTRUCTEUR = "builder6"
SOUS_RESEAU_V6 = "fd00:beef:1::/64"

VERT, ROUGE, JAUNE, RAZ = "\033[92m", "\033[91m", "\033[93m", "\033[0m"


def _docker(*args: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          timeout=timeout)


def _ok(msg: str) -> None:
    print(f"  {VERT}OK{RAZ}     {msg}")


def _echec(msg: str) -> None:
    print(f"  {ROUGE}ECHEC{RAZ}  {msg}")


def _info(msg: str) -> None:
    print(f"  {JAUNE}·{RAZ}      {msg}")


# --------------------------------------------------------------------------- #
# 1. Le démon accepte-t-il IPv6 ?
# --------------------------------------------------------------------------- #

def verifier_demon() -> bool:
    """Le daemon.json déclare-t-il IPv6 ? Sans cela, rien d'autre ne marchera."""
    cfg = Path.home() / ".docker" / "daemon.json"
    if not cfg.exists():
        _echec(f"{cfg} absent")
        return False
    try:
        d = json.loads(cfg.read_text(encoding="utf-8"))
    except Exception as exc:
        _echec(f"daemon.json illisible : {exc}")
        return False

    manquants = [c for c in ("ipv6", "ip6tables") if not d.get(c)]
    if manquants:
        _echec(f"daemon.json : {', '.join(manquants)} absent(s) ou faux")
        print(f"""
    Ajouter dans {cfg}, puis REDEMARRER Docker Desktop :

      "ipv6": true,
      "ip6tables": true,
      "experimental": true,
      "fixed-cidr-v6": "fd00:dead:beef::/64"

    ATTENTION : le prefixe n'accepte que des caracteres HEXADECIMAUX (0-9 a-f).
    Un « k » ou un « z » fait refuser le demarrage du demon, avec un message
    peu explicite.
""")
        return False
    _ok("daemon.json declare ipv6 et ip6tables")
    return True


# --------------------------------------------------------------------------- #
# 2. Réseau IPv6 — créé APRÈS le démarrage du démon.
# --------------------------------------------------------------------------- #

def creer_reseau(recreer: bool = False) -> bool:
    existe = _docker("network", "inspect", RESEAU).returncode == 0
    if existe and recreer:
        _docker("network", "rm", RESEAU)
        existe = False

    if not existe:
        r = _docker("network", "create", "--ipv6", "--subnet", SOUS_RESEAU_V6, RESEAU)
        if r.returncode != 0:
            _echec(f"creation du reseau : {r.stderr.strip()[:160]}")
            return False
        _info(f"reseau {RESEAU} cree")

    v6 = _docker("network", "inspect", RESEAU,
                 "--format", "{{.EnableIPv6}}").stdout.strip()
    if v6 != "true":
        _echec(f"le reseau {RESEAU} n'a pas IPv6 (EnableIPv6={v6})")
        return False
    _ok(f"reseau {RESEAU} : IPv6 actif")
    return True


# --------------------------------------------------------------------------- #
# 3. Constructeur buildx lié au réseau.
# --------------------------------------------------------------------------- #

def creer_constructeur(recreer: bool = False) -> bool:
    if recreer:
        _docker("buildx", "rm", CONSTRUCTEUR)

    if _docker("buildx", "inspect", CONSTRUCTEUR).returncode != 0:
        r = _docker("buildx", "create", "--name", CONSTRUCTEUR,
                    "--driver", "docker-container",
                    "--driver-opt", f"network={RESEAU}", "--use", timeout=300)
        if r.returncode != 0:
            _echec(f"creation du constructeur : {r.stderr.strip()[:160]}")
            return False
        _info(f"constructeur {CONSTRUCTEUR} cree")

    _docker("buildx", "use", CONSTRUCTEUR)
    r = _docker("buildx", "inspect", CONSTRUCTEUR, "--bootstrap", timeout=300)
    if r.returncode != 0:
        _echec(f"demarrage du constructeur : {r.stderr.strip()[:160]}")
        return False
    _ok(f"constructeur {CONSTRUCTEUR} actif sur {RESEAU}")
    return True


# --------------------------------------------------------------------------- #
# 4. Le contrôle qui compte : une construction atteint-elle vraiment PyPI ?
# --------------------------------------------------------------------------- #

def verifier_reseau_construction() -> bool:
    """Un `pip download` DANS une construction. C'est le seul controle qui
    prouve la chaine entiere — le reste ne fait que la rendre plausible."""
    dockerfile = "FROM python:3.11-slim\nRUN pip download --no-deps -d /tmp packaging\n"
    r = subprocess.run(["docker", "buildx", "build", "--builder", CONSTRUCTEUR,
                        "--no-cache", "-f", "-", "."],
                       input=dockerfile, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        _echec("une CONSTRUCTION ne joint pas PyPI")
        for l in (r.stderr or "").splitlines()[-4:]:
            print(f"         {l[:120]}")
        return False
    _ok("une construction joint PyPI (le reseau du constructeur fonctionne)")
    return True


# --------------------------------------------------------------------------- #
# 5. La forme courte de tmpfs n'a pas été réintroduite en syntaxe longue.
# --------------------------------------------------------------------------- #

def verifier_tmpfs() -> bool:
    """`type: tmpfs` n'applique pas `mode` : le montage arrive en root et un
    service non privilegie echoue. On refuse le retour en arriere."""
    brut = (RACINE / "docker-compose.yml").read_text(encoding="utf-8")
    # Les COMMENTAIRES sont retires : le fichier explique justement pourquoi ne
    # pas utiliser `type: tmpfs`, et un controle naif se declencherait dessus.
    t = "\n".join(l for l in brut.splitlines()
                   if not l.lstrip().startswith("#"))
    if "type: tmpfs" in t:
        _echec("docker-compose.yml utilise `type: tmpfs` — `mode` ne sera PAS applique")
        _info("remplacer par la forme courte :  tmpfs:\\n      - /tmp:mode=1777")
        return False
    if "mode=1777" not in t:
        _echec("aucun tmpfs avec mode=1777 : les services non privilegies echoueront")
        return False
    _ok("tmpfs en forme courte, avec mode=1777")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--recreer", action="store_true",
                    help="detruit et recree reseau et constructeur")
    ap.add_argument("--sans-reseau", action="store_true",
                    help="saute le controle de construction (long)")
    args = ap.parse_args()

    print("\nPreparation de Docker pour la pile d'audit\n")

    etapes = [
        ("configuration du demon", verifier_demon),
        ("reseau IPv6", lambda: creer_reseau(args.recreer)),
        ("constructeur buildx", lambda: creer_constructeur(args.recreer)),
        ("syntaxe tmpfs", verifier_tmpfs),
    ]
    if not args.sans_reseau:
        etapes.append(("acces reseau en construction", verifier_reseau_construction))

    for nom, fn in etapes:
        try:
            if not fn():
                print(f"\n{ROUGE}Arret a l'etape « {nom} ».{RAZ} "
                      "Corriger ci-dessus, puis relancer.\n")
                return 1
        except subprocess.TimeoutExpired:
            _echec(f"{nom} : delai depasse")
            return 1
        except Exception as exc:
            _echec(f"{nom} : {exc}")
            return 1

    print(f"\n{VERT}Docker est pret.{RAZ}  Suite :  docker compose up -d --build\n")
    return 0


def demo() -> None:
    """Auto-test : ce qui ne demande pas Docker."""
    # 1. Le controle tmpfs doit REFUSER la syntaxe longue, qui n'applique pas
    #    `mode` — c'est le piege qui empechait nginx de demarrer.
    import tempfile
    compose = RACINE / "docker-compose.yml"
    original = compose.read_text(encoding="utf-8")
    assert verifier_tmpfs(), "le compose actuel doit passer"
    try:
        compose.write_text(original.replace("tmpfs:\n      - /tmp:mode=1777",
                                            "volumes:\n      - type: tmpfs"),
                           encoding="utf-8")
        assert not verifier_tmpfs(), "la syntaxe longue doit etre REFUSEE"
    finally:
        compose.write_text(original, encoding="utf-8")

    # 2. Les constantes sont coherentes avec le compose et le daemon.
    assert SOUS_RESEAU_V6.startswith("fd00:"), "prefixe ULA (prive, non route)"
    assert all(c in "0123456789abcdef:/" for c in SOUS_RESEAU_V6), (
        "un prefixe IPv6 n'accepte que des caracteres hexadecimaux — un « k » "
        "fait refuser le demarrage du demon")

    print("scripts.setup_docker : 2/2 controles OK")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        demo()
    else:
        raise SystemExit(main())
