"""
cibles.py — Ce que cet outil a le droit d'attaquer. POINT UNIQUE.

POURQUOI CE MODULE EXISTE
    La validation vivait dans `api/main.py`, donc elle ne protégeait QUE l'API.
    `scripts/run_agent.py` et `scripts/run_audit_global.py` visaient n'importe
    quoi — `169.254.169.254`, une adresse interne, ce qu'on veut.

    On peut défendre ce choix : la CLI suppose déjà un accès shell à la machine,
    et qui peut lancer `run_agent.py` peut lancer `curl`. Mais l'allowlist était
    présentée comme bornant « ce que target_url a le droit d'atteindre », et
    c'était faux — elle bornait ce que l'API a le droit d'atteindre. Une garantie
    à moitié vraie est une garantie sur laquelle on se repose à tort.

    Ici, la règle est écrite une fois. `api/main.py` la traduit en réponse HTTP,
    les runners en refus de ligne de commande. Aucun des deux ne peut diverger.

CE QU'ON N'INTERDIT PAS, ET POURQUOI
    Les adresses privées restent atteignables : auditer un service interne qu'on
    POSSÈDE est exactement le métier de cet outil, et la cible par défaut est
    `http://localhost:8090`. Interdire casserait l'usage légitime. On BORNE :
    une installation déclare ce qu'elle a le droit d'attaquer, et le reste est
    refusé.

LE DÉFAUT EST PERMISSIF, MAIS IL NE SE TAIT PAS
    Sans `AUDIT_TARGET_ALLOWLIST`, toute cible est acceptée — mode
    développement. L'appelant est chargé de le signaler une fois, pour qu'une
    mise en production ne reste pas ouverte par simple ignorance.
"""

from __future__ import annotations

import os
import urllib.parse


class CibleRefusee(ValueError):
    """Cible rejetée. `http_status` : 400 (malformée) ou 403 (hors liste).

    Une `ValueError` et non une `HTTPException` : ce module ne doit rien savoir
    de FastAPI, sinon les runners ne pourraient pas l'utiliser — c'est
    précisément ce qui avait cantonné la règle à l'API.
    """

    def __init__(self, message: str, http_status: int = 400) -> None:
        super().__init__(message)
        self.http_status = http_status


def cibles_autorisees() -> tuple[str, ...]:
    """Hôtes autorisés, LUS À L'APPEL. Vide = aucune restriction.

    Ex. : AUDIT_TARGET_ALLOWLIST=localhost,127.0.0.1,.interne.exemple.com

    POURQUOI PAS UNE CONSTANTE DE MODULE
        Une première version lisait l'environnement À L'IMPORT. C'est le piège
        déjà corrigé deux fois dans ce dépôt — `AUDIT_TARGET_CONCURRENCY` figé à
        l'import, puis le chemin de checkpoint. Une variable posée après le
        chargement du module (test, ouvrier, conteneur reconfiguré) était
        silencieusement ignorée.
    """
    brut = os.environ.get("AUDIT_TARGET_ALLOWLIST", "")
    return tuple(h.strip().lower() for h in brut.split(",") if h.strip())


def valider_cible(url: str) -> str:
    """Rend l'URL, ou lève `CibleRefusee`.

    POURQUOI CE GARDE-FOU EXISTE
        `target_url` partait directement du corps de la requête à la ligne de
        commande du runner, sans la moindre vérification. Un opérateur
        authentifié pouvait viser les métadonnées cloud, `localhost`, n'importe
        quelle adresse interne. Et comme les réponses de la cible sont
        enregistrées dans `run_exchanges` puis relisibles par `/runs/{id}` et le
        dashboard, une clé opérateur fuitée devenait un SSRF authentifié **avec
        exfiltration par le transcript d'audit**.
    """
    decoupe = urllib.parse.urlparse(url)
    hote = (decoupe.hostname or "").lower()

    if decoupe.scheme not in ("http", "https"):
        raise CibleRefusee(
            f"schéma de cible non autorisé : {decoupe.scheme or '(aucun)'} "
            "— attendu http ou https", 400)
    if not hote:
        raise CibleRefusee(f"cible sans hôte : {url[:80]}", 400)

    liste = cibles_autorisees()
    if not liste:
        return url

    # Un motif couvre l'hôte exact ; commençant par un point, il couvre aussi les
    # sous-domaines (`.interne.exemple.com`) mais JAMAIS le domaine nu —
    # `.exemple.com` n'autorise pas `exemple.com`, qui peut appartenir à un tiers.
    autorise = any(
        hote == motif or (motif.startswith(".") and hote.endswith(motif))
        for motif in liste
    )
    if not autorise:
        raise CibleRefusee(
            f"cible « {hote} » hors de la liste autorisée ({', '.join(liste)}). "
            "Ajustez AUDIT_TARGET_ALLOWLIST si cette cible vous appartient.", 403)
    return url


def avertissement_si_libre() -> str | None:
    """Message à émettre UNE FOIS quand aucune restriction n'est configurée.

    Rendu plutôt qu'imprimé : l'API le passe à son journal structuré, les
    runners à stderr. Une fois par processus et non par audit — une alerte
    répétée à chaque appel finit par être filtrée, donc par ne plus rien dire.
    """
    if cibles_autorisees():
        return None
    return ("AUDIT_TARGET_ALLOWLIST n'est pas définie : TOUTE cible est acceptée "
            "(mode développement). En production, déclarez les hôtes autorisés — "
            "sinon une clé opérateur permet d'atteindre n'importe quelle adresse "
            "interne, et les réponses sont conservées dans le journal d'échanges.")


def demo() -> None:
    """Auto-contrôles. Aucun effet de bord, aucun réseau."""
    import contextlib

    @contextlib.contextmanager
    def liste(valeur: str | None):
        avant = os.environ.get("AUDIT_TARGET_ALLOWLIST")
        if valeur is None:
            os.environ.pop("AUDIT_TARGET_ALLOWLIST", None)
        else:
            os.environ["AUDIT_TARGET_ALLOWLIST"] = valeur
        try:
            yield
        finally:
            os.environ.pop("AUDIT_TARGET_ALLOWLIST", None)
            if avant is not None:
                os.environ["AUDIT_TARGET_ALLOWLIST"] = avant

    # 1. Sans liste : tout passe, mais l'avertissement existe.
    with liste(None):
        assert valider_cible("http://n-importe-quoi/chat")
        assert avertissement_si_libre() is not None

    # 2. Le schéma est refusé AVANT la liste : `file://` ne doit jamais passer,
    #    même en mode développement. Et un schéma VALIDE ne suffit pas : sans
    #    hôte, il n'y a rien à comparer à la liste — `http://` la traverserait
    #    donc sans être bornée par quoi que ce soit.
    with liste(None):
        for mauvaise in ("file:///etc/passwd", "gopher://x/", "sans-schema",
                         "http://", "https:///chemin-sans-hote"):
            try:
                valider_cible(mauvaise)
                raise AssertionError(f"{mauvaise} aurait dû être refusée")
            except CibleRefusee as exc:
                assert exc.http_status == 400

    # 3. LE CAS QUI COMPTE : clé opérateur fuitée -> métadonnées cloud.
    with liste("localhost"):
        assert valider_cible("http://localhost:8090/chat")
        try:
            valider_cible("http://169.254.169.254/latest/meta-data/")
            raise AssertionError("les métadonnées cloud auraient dû être refusées")
        except CibleRefusee as exc:
            assert exc.http_status == 403
        assert avertissement_si_libre() is None

    # 4. Le motif à point couvre les sous-domaines, PAS le domaine nu — qui peut
    #    appartenir à quelqu'un d'autre.
    with liste(".interne.exemple.com"):
        assert valider_cible("http://api.interne.exemple.com/chat")
        for refusee in ("http://interne.exemple.com/chat", "http://exemple.com/chat"):
            try:
                valider_cible(refusee)
                raise AssertionError(f"{refusee} aurait dû être refusée")
            except CibleRefusee:
                pass

    print("workflow.cibles : 4/4 controles OK")


if __name__ == "__main__":
    demo()
