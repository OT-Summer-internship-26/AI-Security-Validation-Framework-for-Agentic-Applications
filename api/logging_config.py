"""
logging_config.py — Journal structuré, pour une supervision qui lit des machines.

LE PROBLÈME QU'IL RÉSOUT
    Le framework écrivait des lignes destinées à un humain devant un terminal :
        [ASI_01] DeepTeam OK — score=5.00/10, 1 vulnérabilité(s)

    Une chaîne de collecte d'entreprise (Loki, Elasticsearch, CloudWatch) ne sait
    rien en faire. Pour retrouver « tous les audits où la cible a saturé », il
    faudrait une expression régulière sur une phrase française — qui casse au
    premier reformulage. Les champs doivent être des CHAMPS.

POURQUOI PAS DU JSON PARTOUT, TOUT LE TEMPS
    Sur un poste de développement, le JSON est illisible et ralentit le travail.
    Le format se choisit donc par l'environnement (`LOG_FORMAT=json`), texte par
    défaut. C'est le déploiement qui sait de quoi il a besoin, pas le code.

CE QUI EST AJOUTÉ À CHAQUE LIGNE
    L'identifiant d'audit, la catégorie ASI et le profil de modèle, pris du
    contexte de traçage. Sans eux, cinq agents parallèles produisent un journal
    entrelacé où l'on ne sait plus qui a écrit quoi — le défaut qui rend un
    journal inutilisable exactement quand on en a besoin.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import sys
from typing import Any

# Attributs internes de `LogRecord` : tout le reste est un champ métier ajouté
# par l'appelant, et mérite d'apparaître dans la sortie.
_STANDARD = {
    "args", "asctime", "created", "exc_info", "exc_text", "filename", "funcName",
    "levelname", "levelno", "lineno", "module", "msecs", "message", "msg", "name",
    "pathname", "process", "processName", "relativeCreated", "stack_info",
    "thread", "threadName", "taskName",
}


class FormateurJSON(logging.Formatter):
    """Une ligne = un objet JSON, sur une seule ligne.

    Le collecteur découpe par saut de ligne : un objet indenté sur plusieurs
    lignes serait lu comme plusieurs entrées tronquées.
    """

    def format(self, record: logging.LogRecord) -> str:
        entree: dict[str, Any] = {
            "ts": _dt.datetime.fromtimestamp(
                record.created, _dt.timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        # Contexte d'audit : c'est lui qui rend un journal parallèle lisible.
        try:
            from judge.tracing import current_context

            entree.update({k: v for k, v in current_context().items() if v})
        except Exception:
            pass

        if record.exc_info:
            entree["exc"] = self.formatException(record.exc_info)

        # Champs métier passés par `logger.info("…", extra={"score": 5.57})`.
        entree.update({k: v for k, v in record.__dict__.items()
                       if k not in _STANDARD and not k.startswith("_")})

        # `default=str` : une valeur non sérialisable ne doit jamais faire
        # disparaître la ligne de journal, ce qui est pire que la tronquer.
        return json.dumps(entree, ensure_ascii=False, default=str)


def configurer(force_json: bool | None = None) -> str:
    """Installe le format de journal. Renvoie le format retenu.

    Idempotent : appelé deux fois (import du module puis démarrage d'uvicorn),
    il ne doit pas empiler deux gestionnaires — sinon chaque ligne est écrite en
    double, et un opérateur croit à deux événements.
    """
    json_actif = (force_json if force_json is not None
                  else os.environ.get("LOG_FORMAT", "").strip().lower() == "json")

    racine = logging.getLogger()
    for h in list(racine.handlers):
        if getattr(h, "_aisec", False):
            racine.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    handler._aisec = True                            # type: ignore[attr-defined]
    handler.setFormatter(
        FormateurJSON() if json_actif
        else logging.Formatter("%(asctime)s %(levelname)-7s %(name)s : %(message)s",
                               datefmt="%H:%M:%S"))
    racine.addHandler(handler)
    racine.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

    # Uvicorn installe ses propres gestionnaires : sans cela, ses lignes d'accès
    # restent en texte au milieu d'un flux JSON, et le collecteur les rejette.
    for nom in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        lg = logging.getLogger(nom)
        lg.handlers.clear()
        lg.propagate = True

    return "json" if json_actif else "texte"


def demo() -> None:
    """Auto-test : forme de la sortie, champs metier, contexte, idempotence."""
    import io

    configurer(force_json=True)
    racine = logging.getLogger()
    handler = next(h for h in racine.handlers if getattr(h, "_aisec", False))
    tampon = io.StringIO()
    handler.stream = tampon

    from judge.tracing import clear_context, set_context

    set_context(audit_id="audit-42", category="ASI_05", profile="openai")
    try:
        logging.getLogger("essai").warning("cible saturee", extra={"http_status": 500})
    finally:
        clear_context()

    ligne = tampon.getvalue().strip()
    # 1. UNE ligne, UN objet : le collecteur decoupe par saut de ligne.
    assert "\n" not in ligne, "un objet indente serait lu comme plusieurs entrees"
    d = json.loads(ligne)

    # 2. Les champs sont des CHAMPS, pas une phrase a decouper a l'expression
    #    reguliere — c'est tout l'objet du format.
    assert d["level"] == "WARNING" and d["msg"] == "cible saturee"
    assert d["http_status"] == 500

    # 3. Le contexte d'audit accompagne CHAQUE ligne : sans lui, cinq agents
    #    paralleles produisent un journal entrelace illisible.
    assert d["audit_id"] == "audit-42" and d["category"] == "ASI_05"
    assert d["ts"].endswith("+00:00"), "horodatage en UTC, comparable entre machines"

    # 4. Idempotence : deux appels ne doivent pas doubler chaque ligne.
    configurer(force_json=True)
    configurer(force_json=True)
    assert sum(1 for h in logging.getLogger().handlers
               if getattr(h, "_aisec", False)) == 1

    # 5. Une valeur non serialisable ne fait pas DISPARAITRE la ligne.
    handler = next(h for h in racine.handlers if getattr(h, "_aisec", False))
    tampon = io.StringIO()
    handler.stream = tampon
    logging.getLogger("essai").info("objet", extra={"obj": object()})
    assert json.loads(tampon.getvalue().strip())["msg"] == "objet"

    # 6. Le mode texte reste le defaut : le JSON ralentit le travail local.
    assert configurer(force_json=False) == "texte"

    print("api.logging_config : 6/6 controles OK")


if __name__ == "__main__":
    import pathlib
    import sys as _s

    _s.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
    demo()
