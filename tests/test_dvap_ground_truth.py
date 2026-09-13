"""
test_dvap_ground_truth.py — La verite terrain de l'etude DVAP dit-elle vrai ?

POURQUOI CE FICHIER
    `docs/etude_validation_dvap.md` repose sur une affirmation :
    « chaque rattachement cite l'objectif source, donc la cartographie est
    contestable ligne par ligne ». Toute l'etude en depend — si un objectif
    cite n'existe pas dans le laboratoire, le rappel mesure un accord avec une
    verite terrain inventee.

    Personne n'avait verifie. Fait le 2026-09-14 : 43 citations, 43 presentes
    dans le fichier source de LEUR propre laboratoire.

    Une verification faite une fois vieillit en silence : DVAP peut reformuler
    un objectif, et la citation cesserait de correspondre sans que rien ne le
    signale. D'ou ce test.

OU VIVENT LES OBJECTIFS — le piege qui a coute une fausse alerte
    PAS dans `~/dvap/labs/<nom>/`, qui ne contient que l'application jouable
    (Dockerfile, app.py, static/). Les objectifs DECLARES sont dans
    `~/dvap/backend/app/data/labs/*.json`. Chercher au mauvais endroit rend
    « 43 absents sur 43 » — un resultat si net qu'il accuse la methode, pas la
    donnee.

IGNORE SI DVAP EST ABSENT : le depot DVAP n'est pas une dependance du projet,
il est clone a cote. Meme convention que `test_sandbox.py` sans Docker.
"""

from __future__ import annotations

import glob
import json
import os
import re
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))

#: Surchargeable : `DVAP_PATH=/chemin/vers/dvap pytest tests/test_dvap_ground_truth.py`
DVAP = Path(os.environ.get("DVAP_PATH", Path.home() / "dvap"))
SOURCES = DVAP / "backend" / "app" / "data" / "labs"


def _normaliser(texte: str) -> str:
    """Espaces reduits et minuscules : une citation peut differer par la mise en forme."""
    return re.sub(r"\s+", " ", texte).strip().lower()


@pytest.fixture(scope="module")
def sources_dvap() -> dict[str, str]:
    if not SOURCES.is_dir():
        pytest.skip(f"DVAP absent ({SOURCES}) — verite terrain non verifiable ici")
    fichiers = {
        os.path.basename(p): _normaliser(Path(p).read_text(encoding="utf-8", errors="replace"))
        for p in glob.glob(str(SOURCES / "*.json"))
    }
    if not fichiers:
        pytest.skip(f"aucune definition de laboratoire dans {SOURCES}")
    return fichiers


@pytest.fixture(scope="module")
def verite() -> dict:
    return json.loads((RACINE / "config" / "dvap_ground_truth.json").read_text(encoding="utf-8"))["labs"]


def _fichier_du_labo(lab: str, sources: dict[str, str]) -> tuple[str, str] | tuple[None, None]:
    """`prompt-injection` -> `01_prompt_injection.json`. DVAP numerote ses fichiers."""
    cle = lab.replace("-", "_")
    for nom, texte in sources.items():
        if cle in nom.lower():
            return nom, texte
    return None, None


def test_chaque_laboratoire_DVAP_a_sa_verite_terrain(verite, sources_dvap):
    """Aucun laboratoire ne doit manquer — un labo non cartographie sort
    silencieusement du denominateur et gonfle le rappel."""
    sur_disque = {d.name for d in (DVAP / "labs").iterdir() if d.is_dir()}
    manquants = sur_disque - set(verite)
    en_trop = set(verite) - sur_disque
    assert not manquants, f"laboratoires DVAP sans verite terrain : {sorted(manquants)}"
    assert not en_trop, f"verite terrain pour des laboratoires inexistants : {sorted(en_trop)}"


def test_chaque_objectif_CITE_existe_VRAIMENT_dans_son_laboratoire(verite, sources_dvap):
    """LE CONTROLE CENTRAL DE L'ETUDE.

    Une citation absente signifierait que la cartographie a ete ecrite de
    memoire. Le rappel mesurerait alors un accord avec une verite inventee —
    un chiffre plausible sans mesure derriere, exactement ce que ce framework
    combat.

    Une citation presente MAIS DANS UN AUTRE LABORATOIRE est refusee aussi :
    c'est une erreur d'attribution, et elle fausse le detail par laboratoire.
    """
    tout = " ".join(sources_dvap.values())
    absents: list[str] = []
    mal_attribues: list[str] = []
    verifies = 0

    for lab in sorted(verite):
        _, texte = _fichier_du_labo(lab, sources_dvap)
        assert texte is not None, f"aucun fichier source DVAP pour « {lab} »"
        for asi, justification in verite[lab].get("justification", {}).items():
            for citation in re.findall(r'[«"]\s*([^»"]{12,})\s*[»"]', justification):
                c = _normaliser(citation)
                if c in texte:
                    verifies += 1
                elif c in tout:
                    mal_attribues.append(f"{lab} [{asi}] : {citation[:60]}")
                else:
                    absents.append(f"{lab} [{asi}] : {citation[:60]}")

    assert not absents, (
        f"{len(absents)} objectif(s) cite(s) INTROUVABLE(S) dans DVAP — la "
        f"cartographie ne serait plus contestable ligne par ligne :\n  "
        + "\n  ".join(absents))
    assert not mal_attribues, (
        f"{len(mal_attribues)} objectif(s) rattache(s) au MAUVAIS laboratoire :\n  "
        + "\n  ".join(mal_attribues))
    assert verifies >= 40, (
        f"seulement {verifies} citations verifiees — la cartographie s'est videe "
        "de ses justifications, ou le motif de citation ne les reconnait plus")


def test_toute_categorie_citee_est_une_ASI_connue(verite):
    """Une faute de frappe (`ASI_11`, `ASI1`) sortirait la ligne du calcul sans
    rien casser : le rappel monterait, faute de denominateur."""
    connues = {f"ASI_{n:02d}" for n in range(1, 11)}
    for lab, donnees in verite.items():
        for champ in ("primaire", "secondaire"):
            inconnues = set(donnees.get(champ, [])) - connues
            assert not inconnues, f"{lab}.{champ} : categorie(s) inconnue(s) {sorted(inconnues)}"
        orphelines = set(donnees.get("justification", {})) - set(
            donnees.get("primaire", []) + donnees.get("secondaire", []))
        assert not orphelines, (
            f"{lab} : justification pour {sorted(orphelines)}, qui n'est ni primaire ni secondaire")
