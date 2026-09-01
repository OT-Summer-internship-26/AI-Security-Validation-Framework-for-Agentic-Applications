"""
paths.py — Les emplacements de stockage, résolus à UN seul endroit.

LE PROBLÈME QU'IL RÉSOUT
    Le répertoire des résultats était écrit en dur dans HUIT fichiers, sous
    quatre noms différents (`RESULTS_DIR`, `RESULTS`, `OUT_DIR`, `RESULTATS`).
    Tant que tout tourne depuis le dépôt cloné, cela fonctionne — et cesse de
    fonctionner dès la première mise en production :

    · dans un conteneur, le disque du dépôt est ÉPHÉMÈRE : un audit d'une heure
      disparaît au redémarrage du pod ;
    · deux instances de l'API ne voient pas les mêmes fichiers, donc
      `GET /audits/{id}` répond 404 une fois sur deux derrière un répartiteur ;
    · aucun volume persistant ne peut être monté ailleurs qu'à cet emplacement.

    Rendre le chemin configurable dans huit fichiers aurait garanti qu'un
    neuvième appelant l'oublie. Il est donc résolu ICI, et nulle part ailleurs.

CONFIGURATION
    `AUDIT_DATA_DIR`     racine des données (défaut : `<dépôt>/data`)
    `AUDIT_RESULTS_DIR`  résultats d'audit — prime sur la précédente

    En production, pointer ces variables vers un volume persistant ou un point
    de montage partagé entre les instances.
"""

from __future__ import annotations

import os
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent


def _depuis_env(variable: str, defaut: Path) -> Path:
    """Chemin issu de l'environnement, sinon le défaut. Jamais relatif au CWD.

    POURQUOI RÉSOUDRE EN ABSOLU
        Les runners sont lancés depuis des répertoires courants variés (dépôt,
        `/app` dans un conteneur, un dossier de tâche planifiée). Un chemin
        relatif ferait écrire les résultats à un endroit différent selon
        l'appelant — et le dashboard n'en trouverait qu'une partie.
    """
    valeur = (os.environ.get(variable) or "").strip()
    return Path(valeur).expanduser().resolve() if valeur else defaut


def data_dir() -> Path:
    """Racine des données du framework."""
    return _depuis_env("AUDIT_DATA_DIR", RACINE / "data")


def results_dir(create: bool = False) -> Path:
    """Répertoire des résultats d'audit.

    `create=True` uniquement chez qui ÉCRIT. Un lecteur qui créerait le dossier
    masquerait une erreur de configuration : un chemin mal orthographié
    donnerait un répertoire vide et un « aucun audit » silencieux, au lieu d'une
    absence visible.
    """
    chemin = _depuis_env("AUDIT_RESULTS_DIR", data_dir() / "audit_results")
    if create:
        chemin.mkdir(parents=True, exist_ok=True)
    return chemin


def reports_dir(create: bool = False) -> Path:
    """Répertoire des rapports HTML/PDF générés."""
    chemin = _depuis_env("AUDIT_REPORTS_DIR", data_dir() / "reports")
    if create:
        chemin.mkdir(parents=True, exist_ok=True)
    return chemin


def checkpoints_path() -> Path:
    """Base SQLite des points de reprise LangGraph.

    Elle doit vivre avec les résultats : reprendre un audit suppose de retrouver
    À LA FOIS son point de reprise et les catégories déjà écrites. Les séparer
    ferait rejouer des agents dont les résultats existent déjà.
    """
    return _depuis_env("AUDIT_CHECKPOINTS", data_dir() / "checkpoints.sqlite")


def affichable(chemin: Path) -> str:
    """Chemin à montrer à l'utilisateur : relatif au dépôt quand c'est possible.

    POURQUOI CETTE FONCTION EXISTE
        Les runners affichaient `chemin.relative_to(RACINE)`, ce qui suppose que
        la sortie vit SOUS le dépôt. Dès que les résultats pointent vers un
        volume — le cas normal en conteneur — cet appel lève `ValueError` et
        fait planter le runner À LA TOUTE FIN, après un audit d'une heure
        réussi. Panne constatée en exécutant un audit dans l'image.

        Un chemin absolu est parfaitement lisible ; un plantage ne l'est pas.
    """
    try:
        return str(chemin.relative_to(RACINE))
    except ValueError:
        return str(chemin)


def demo() -> None:
    """Auto-test : défauts, surcharge, résolution absolue. Aucun effet de bord."""
    import tempfile

    # 1. Sans configuration : tout est sous le dépôt, et cohérent entre les
    #    fonctions (un audit et son point de reprise doivent rester ensemble).
    for var in ("AUDIT_DATA_DIR", "AUDIT_RESULTS_DIR", "AUDIT_REPORTS_DIR",
                "AUDIT_CHECKPOINTS"):
        os.environ.pop(var, None)
    assert results_dir() == RACINE / "data" / "audit_results"
    assert reports_dir() == RACINE / "data" / "reports"
    assert checkpoints_path().parent == data_dir()

    with tempfile.TemporaryDirectory() as tmp:
        # 2. Deplacer la RACINE deplace tout ce qui en depend.
        os.environ["AUDIT_DATA_DIR"] = tmp
        try:
            assert results_dir() == Path(tmp).resolve() / "audit_results"
            assert reports_dir() == Path(tmp).resolve() / "reports"

            # 3. Le chemin specifique PRIME sur la racine : un volume dedie aux
            #    resultats doit pouvoir etre monte independamment.
            os.environ["AUDIT_RESULTS_DIR"] = str(Path(tmp) / "ailleurs")
            assert results_dir() == Path(tmp).resolve() / "ailleurs"
            assert reports_dir() == Path(tmp).resolve() / "reports", (
                "surcharger les resultats ne doit pas deplacer les rapports")
        finally:
            os.environ.pop("AUDIT_DATA_DIR", None)
            os.environ.pop("AUDIT_RESULTS_DIR", None)

    # 4. Un chemin relatif est resolu en ABSOLU : les runners sont lances depuis
    #    des repertoires courants differents.
    os.environ["AUDIT_RESULTS_DIR"] = "resultats-relatifs"
    try:
        assert results_dir().is_absolute()
    finally:
        os.environ.pop("AUDIT_RESULTS_DIR", None)

    # 5. Une valeur VIDE vaut « non configure » : une variable d'environnement
    #    definie a "" dans un manifeste ne doit pas envoyer les resultats a la
    #    racine du systeme de fichiers.
    os.environ["AUDIT_RESULTS_DIR"] = "   "
    try:
        assert results_dir() == RACINE / "data" / "audit_results"
    finally:
        os.environ.pop("AUDIT_RESULTS_DIR", None)

    # 6. Un LECTEUR ne cree pas le repertoire : un chemin mal orthographie doit
    #    rester visible, pas produire un dossier vide et un « aucun audit ».
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["AUDIT_RESULTS_DIR"] = str(Path(tmp) / "jamais-cree")
        try:
            assert not results_dir().exists()
            assert results_dir(create=True).exists()
        finally:
            os.environ.pop("AUDIT_RESULTS_DIR", None)

    # 7. Un chemin HORS du depot reste affichable au lieu de faire planter le
    #    runner a la toute fin d'un audit d'une heure.
    assert affichable(RACINE / "data" / "x.json") == str(Path("data") / "x.json")
    assert affichable(Path("/var/lib/ai-security/x.json")).endswith("x.json")

    print("workflow.paths : 7/7 controles OK")


if __name__ == "__main__":
    demo()
