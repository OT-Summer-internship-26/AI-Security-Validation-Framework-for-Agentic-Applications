#!/usr/bin/env python
"""
check_lock.py — Le verrou couvre-t-il TOUT ce que requirements.txt declare ?

POURQUOI CE SCRIPT EXISTE
    L'image s'installe avec `pip install --no-deps -r requirements.lock`. Le
    `--no-deps` est deliberé — le verrou est l'arbre complet, laisser pip
    re-resoudre le viderait de son sens — mais il a une consequence brutale :
    CE QUI N'EST PAS DANS LE VERROU N'EXISTE PAS DANS L'IMAGE. Une dependance
    ajoutee a `requirements.txt` sans regeneration du verrou disparait en
    silence, et l'image se construit tres bien sans elle.

    Ce n'est pas theorique, c'est arrive DEUX FOIS :

      · `pyrit` — declare dans requirements.txt, absent du verrou. L'axe
        comportemental entier ressortait `not_measured` dans l'image, alors que
        c'est lui qui avait detecte un detournement note 10/10 par DeepTeam.
      · `langgraph-checkpoint-sqlite` — jamais declare nulle part, alors que
        `workflow/audit_graph.py` l'importe. Le chemin d'audit PAR DEFAUT
        (LangGraph) plantait dans l'image au premier appel.

    Un controle existait : il regenerait le verrou entier avec `pip-compile` et
    comparait. Il ne servait a rien pour deux raisons — il emettait un
    `::warning::` qui ne bloque aucun job, et il comparait une resolution neuve
    a un verrou incremental, donc il criait toujours. Mesure ici : cette
    resolution complete prend une TRENTAINE DE MINUTES. Un controle lent qui
    crie toujours n'est pas un controle, c'est un bruit de fond.

DEUX QUESTIONS, PAS UNE — ET LA PREMIERE NE SUFFIT PAS
    (1) mode par defaut : tout ce que requirements.txt DECLARE est-il epingle
        dans le verrou ? Instantane, sans reseau, tourne partout.

    (2) `--imports` : tout ce que le code IMPORTE est-il resolvable ?

    LA QUESTION (1) SEULE AURAIT LAISSE PASSER `langgraph-checkpoint-sqlite`.
    Verifie, pas suppose : en retirant ce paquet des DEUX fichiers — l'etat
    exact d'avant la panne — le controle (1) repond « OK ». Il compare declare
    et epingle ; il ne regarde jamais ce que le code importe. Un paquet que
    PERSONNE n'a declare lui est invisible, et c'est ainsi que la panne est nee.

    La question (2) lit les `import` du code — Y COMPRIS ceux places dans des
    fonctions, ou vivaient les DEUX pannes — et exige que chacun se resolve.
    Elle n'a de sens que dans un environnement CENSE etre complet : l'image, ou
    un poste installe depuis le verrou. Dans la porte de qualite CI, dont
    l'environnement est volontairement partiel, elle ne veut rien dire — c'est
    pourquoi elle n'y tourne pas, et pourquoi elle tourne dans l'image.

    NE FAIT NI L'UN NI L'AUTRE : re-resoudre l'arbre transitif. Une version
    transitive qui a vieilli ne casse pas l'image — le verrou reste la source de
    verite. La procedure complete est documentee dans le Dockerfile.

USAGE
    python scripts/check_lock.py             # declare -> epingle
    python scripts/check_lock.py --imports   # importe -> resolvable (dans l'image)
    python scripts/check_lock.py --self-test
"""
from __future__ import annotations

import ast
import importlib.util
import re
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent

# Un nom de paquet s'arrete au premier caractere de specification de version,
# d'extra ou de commentaire. `uvicorn[standard]`, `mcp>=1.28.1  # CVE-...` et
# `click==8.1.8` doivent tous rendre le nom seul.
_FIN_DU_NOM = re.compile(r"[\[<>=!~;#\s]")


def normaliser(nom: str) -> str:
    """Normalisation PEP 503 : `Sentry-SDK`, `sentry_sdk` et `sentry.sdk` sont un
    seul et meme paquet pour pip. Comparer les chaines brutes ferait passer un
    paquet absent pour present, ou l'inverse."""
    return re.sub(r"[-_.]+", "-", nom.strip()).lower()


def declarees(texte: str) -> list[str]:
    """Dependances DIRECTES d'un requirements.txt, normalisees.

    Les lignes commentees sont ignorees — c'est ainsi que `garak` est
    volontairement tenu hors de cet environnement : il epingle `openai<1.0.0`
    quand le reste de la pile exige openai 2.x. Il vit dans un venv dedie, que
    l'image construit dans un etage a part (voir le Dockerfile). Absent du
    verrou, donc, mais PAS absent de l'image — la nuance compte.
    """
    noms = []
    for ligne in texte.splitlines():
        ligne = ligne.strip()
        if not ligne or ligne.startswith(("#", "-")):
            continue
        coupe = _FIN_DU_NOM.split(ligne, 1)[0]
        if coupe:
            noms.append(normaliser(coupe))
    return noms


def epinglees(texte: str) -> set[str]:
    """Paquets epingles dans le verrou, normalises."""
    return {
        normaliser(m.group(1))
        for m in re.finditer(r"^([A-Za-z0-9._-]+)==", texte, re.MULTILINE)
    }


def manquantes(req_txt: str, lock_txt: str) -> list[str]:
    verrou = epinglees(lock_txt)
    return [nom for nom in declarees(req_txt) if nom not in verrou]


# --------------------------------------------------------------------------- #
# (2) Ce que le code IMPORTE est-il resolvable ?
# --------------------------------------------------------------------------- #

# Dossiers COPIES dans l'image. `tests/` en est exclu : sa suite est hors-ligne
# et n'a pas a contraindre l'image. `dashboard/` aussi : c'est une autre image.
DOSSIERS_LIVRES = ("agents", "api", "judge", "workflow", "sandbox", "reporting",
                   "scripts", "config")

# Absences DELIBEREES, avec leur motif. Toute autre absence est un defaut.
# `garak` n'y figure pas : le code ne l'importe jamais, il le lance en
# sous-processus depuis un venv isole (openai 0.28.1 incompatible avec le reste).
ABSENCES_VOULUES: dict[str, str] = {}


def _noms_locaux() -> set[str]:
    """Noms de premier niveau qui appartiennent AU DEPOT, pas a PyPI."""
    locaux = {c.name for c in RACINE.iterdir() if c.is_dir() and not c.name.startswith(".")}
    locaux |= {c.stem for c in RACINE.glob("*.py")}
    locaux |= {c.stem for c in (RACINE / "scripts").glob("*.py")}
    return locaux


def imports_du_code(source: str) -> set[str]:
    """Modules importes par un fichier, chemin pointe COMPLET.

    Les imports places DANS des fonctions comptent autant que ceux du haut de
    fichier — les deux pannes vivaient precisement la : le `from
    langgraph.checkpoint.sqlite import SqliteSaver` est a l'interieur de
    `run_audit_graph()`. `ast.walk` les voit tous sans executer une ligne.
    """
    trouves = set()
    for noeud in ast.walk(ast.parse(source)):
        if isinstance(noeud, ast.Import):
            trouves.update(a.name for a in noeud.names)
        elif isinstance(noeud, ast.ImportFrom) and noeud.level == 0 and noeud.module:
            trouves.add(noeud.module)
    return trouves


def imports_tiers() -> set[str]:
    """Tous les imports TIERS du code livre : ni stdlib, ni modules du depot."""
    locaux, tiers = _noms_locaux(), set()
    for dossier in DOSSIERS_LIVRES:
        for fichier in (RACINE / dossier).rglob("*.py"):
            if "__pycache__" in fichier.parts:
                continue
            for nom in imports_du_code(fichier.read_text(encoding="utf-8")):
                racine = nom.split(".")[0]
                if racine in sys.stdlib_module_names or racine in locaux:
                    continue
                tiers.add(nom)
    return tiers


def non_resolvables(modules: set[str]) -> list[str]:
    """Modules que l'environnement COURANT ne sait pas localiser."""
    absents = []
    for nom in sorted(modules):
        if nom.split(".")[0] in ABSENCES_VOULUES:
            continue
        try:
            if importlib.util.find_spec(nom) is None:
                absents.append(nom)
        except (ImportError, AttributeError, ValueError):
            absents.append(nom)
    return absents


def demo() -> None:
    """Auto-controles. Le script se prouve sur des cas ecrits a la main, puis sur
    les fichiers REELS du depot — les deux comptent : le premier verifie
    l'analyse, le second verifie l'etat du depot au moment ou on lance."""
    # 1. Les formes reelles rencontrees dans requirements.txt.
    req = (
        "# commentaire\n"
        "langgraph\n"
        "uvicorn[standard]\n"
        "mcp>=1.28.1              # CVE-2026-52870\n"
        "click==8.1.8\n"
        "# garak   # <- volontairement commente\n"
        "sentry-sdk\n"
    )
    lock = "langgraph==1.2.11\nuvicorn==0.42.0\nmcp==1.28.1\nclick==8.1.8\nsentry_sdk==2.68.1\n"
    assert manquantes(req, lock) == [], "extras, specificateurs ou normalisation mal geres"

    # 2. Un paquet commente ne doit JAMAIS etre exige.
    assert "garak" not in declarees(req), "une ligne commentee a ete prise pour une dependance"

    # 3. Le cas qui est reellement arrive : declare, non epingle.
    assert manquantes("pyrit\n", "langgraph==1.2.11\n") == ["pyrit"], (
        "la panne de production ne serait PAS detectee")

    # 4. Normalisation PEP 503 dans les deux sens.
    assert manquantes("Sentry_SDK\n", "sentry-sdk==2.68.1\n") == []

    # 5. Les fichiers reels du depot.
    reels = manquantes(_lire("requirements.txt"), _lire("requirements.lock"))
    assert reels == [], f"le verrou ne couvre pas : {', '.join(reels)}"

    # 6. Le scanner voit-il les imports CACHES DANS DES FONCTIONS ?
    #    C'est la seule chose qui distingue ce controle du precedent : le module
    #    qui a casse la production n'apparait nulle part en haut d'un fichier.
    dedans = imports_du_code(chr(10).join([
        "def f():",
        "    from langgraph.checkpoint.sqlite import SqliteSaver",
        "    import sentry_sdk",
    ]))
    assert "langgraph.checkpoint.sqlite" in dedans, (
        "les imports places dans une fonction echappent au scanner : les DEUX "
        "pannes de production etaient exactement de cette forme")

    # 7. Sur le code REEL : le module qui a casse l'image doit etre vu.
    assert "langgraph.checkpoint.sqlite" in imports_tiers(), (
        "le scanner ne voit plus l'import qui a plante l'audit par defaut")

    print(f"scripts.check_lock : 7/7 controles OK "
          f"({len(epinglees(_lire('requirements.lock')))} paquets epingles, "
          f"{len(imports_tiers())} imports tiers)")


def _lire(nom: str) -> str:
    return (RACINE / nom).read_text(encoding="utf-8")


def main() -> int:
    if "--self-test" in sys.argv:
        demo()
        return 0

    if "--imports" in sys.argv:
        return _mode_imports()

    absents = manquantes(_lire("requirements.txt"), _lire("requirements.lock"))
    if absents:
        print("requirements.lock NE COUVRE PAS ces dependances declarees :")
        for nom in absents:
            print(f"  · {nom}")
        print("\nL'image installe le verrou avec `--no-deps` : ces paquets n'y")
        print("seront PAS, et rien ne le signalera a la construction.")
        print("Regenerer le verrou (procedure exacte : voir le Dockerfile).")
        return 1

    print(f"requirements.lock couvre les {len(declarees(_lire('requirements.txt')))} "
          f"dependances declarees.")
    return 0


def _mode_imports() -> int:
    """A LANCER DANS UN ENVIRONNEMENT CENSE ETRE COMPLET (l'image).

    Ailleurs — porte de qualite CI, poste sans le verrou complet — les absences
    signalees seraient normales, et le controle ne voudrait rien dire.
    """
    tiers = imports_tiers()
    absents = non_resolvables(tiers)
    if absents:
        print("Le code IMPORTE des modules que cet environnement n'a pas :")
        for nom in absents:
            print(f"  · {nom}")
        print()
        print("Si cet environnement est l'image, ces imports plantent A")
        print("L'EXECUTION, pas a la construction — comme")
        print("`langgraph.checkpoint.sqlite`, qui n'etait declare nulle part.")
        print("Declarer le paquet fournisseur dans requirements.txt, regenerer le")
        print("verrou, ou l'inscrire dans ABSENCES_VOULUES avec son motif.")
        return 1

    print(f"Les {len(tiers)} imports tiers du code livre se resolvent tous.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
