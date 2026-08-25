"""
tracing.py — Observabilité LangFuse des appels LLM (NOTES.md §2 / §7).

CE QUE ÇA TRACE, ET POURQUOI ÇA MANQUAIT
    Un audit produit des scores, mais rien ne permettait de répondre à « pourquoi
    ce verdict ? » après coup : quel prompt exact est parti au juge, qu'a-t-il
    répondu, combien de temps, combien d'appels. Les enquêtes de cette semaine —
    le juge qui répondait `False` à tout, puis le prompt cassé par son propre
    formatage — ont dû être menées en rejouant des appels à la main. Avec un
    traçage, elles se lisaient dans un tableau de bord.

    Chaque appel des juges devient une observation LangFuse : nom du modèle,
    prompt, réponse, durée, et le rôle (`severity` / `compliance` / `cross_validation`).

PRINCIPE : TOTALEMENT OPTIONNEL, ET SILENCIEUX
    Le traçage ne doit JAMAIS faire échouer un audit. S'il manque une clé, si le
    serveur LangFuse est éteint, si le paquet n'est pas installé — on n'active
    rien et le framework se comporte exactement comme avant. Une observabilité qui
    casse la production est pire que pas d'observabilité.

ACTIVATION
    LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, LANGFUSE_HOST (défaut :
    http://localhost:3000, le service du docker-compose). Sans ces variables, le
    module est inerte — c'est le cas par défaut.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

logger = logging.getLogger(__name__)

_client: Any = None
_checked = False


def get_client() -> Any:
    """Retourne le client LangFuse, ou None si le traçage n'est pas configuré.

    Résolu UNE fois : un audit fait des centaines d'appels, on ne retente pas une
    connexion morte à chacun.
    """
    global _client, _checked
    if _checked:
        return _client
    _checked = True

    public, secret = os.environ.get("LANGFUSE_PUBLIC_KEY"), os.environ.get("LANGFUSE_SECRET_KEY")
    if not public or not secret:
        return None
    try:
        from langfuse import Langfuse

        client = Langfuse(
            public_key=public, secret_key=secret,
            host=os.environ.get("LANGFUSE_HOST", "http://localhost:3000"),
        )
        # `auth_check` évite d'accumuler des appels vers un serveur injoignable
        # pendant des heures d'audit pour les découvrir perdus à la fin.
        if not client.auth_check():
            logger.warning("LangFuse : authentification refusée — traçage désactivé")
            return None
        _client = client
        logger.info("LangFuse : traçage actif")
    except Exception as exc:  # paquet absent, serveur éteint, version incompatible
        logger.warning("LangFuse indisponible (%s) — traçage désactivé", exc)
    return _client


def is_enabled() -> bool:
    """Le traçage est-il actif ? (utile pour l'afficher dans un rapport)"""
    return get_client() is not None


def trace_llm_call(role: str, model: Any, prompt: str, response: Any,
                   duration_s: float, error: str = "") -> None:
    """Enregistre un appel LLM. Ne lève JAMAIS et ne ralentit pas l'audit.

    role : `severity` | `compliance` | `cross_validation` | `pass_analysis`…
    """
    client = get_client()
    if client is None:
        return
    try:
        name = getattr(model, "get_model_name", lambda: str(model))()
        with client.start_as_current_observation(name=f"judge.{role}", as_type="generation") as obs:
            obs.update(
                model=str(name),
                input=prompt[:4000],
                output=str(response)[:4000],
                metadata={"role": role, "duration_s": round(duration_s, 2),
                          **({"error": error} if error else {})},
            )
    except Exception as exc:  # l'observabilité ne casse pas la production
        logger.debug("LangFuse : trace ignorée (%s)", exc)


def flush() -> None:
    """Vide la file d'envoi — à appeler en fin d'audit, sinon les dernières
    observations sont perdues à la sortie du processus."""
    client = get_client()
    if client is not None:
        try:
            client.flush()
        except Exception as exc:
            logger.debug("LangFuse : flush ignoré (%s)", exc)


class timed:
    """Chronomètre un appel LLM et le trace à la sortie du bloc.

    Utilisé par `judge.severity_judge.structured()`, donc les TROIS juges en
    bénéficient sans que chacun ait à instrumenter ses appels.

        with timed("severity", model, prompt) as t:
            resp = model.generate(prompt, schema=Schema)
            t.response = resp
    """

    def __init__(self, role: str, model: Any, prompt: str) -> None:
        self.role, self.model, self.prompt = role, model, prompt
        self.response: Any = None
        self._t0 = 0.0

    def __enter__(self) -> "timed":
        self._t0 = time.time()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        trace_llm_call(self.role, self.model, self.prompt, self.response,
                       time.time() - self._t0, error=str(exc) if exc else "")
        return False  # ne masque jamais l'exception d'origine


def demo() -> None:
    """Auto-test : sans clé, le module est inerte et ne lève rien."""
    global _client, _checked
    _client, _checked = None, False
    saved = {k: os.environ.pop(k, None) for k in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY")}
    try:
        assert get_client() is None and is_enabled() is False
        # Aucune de ces opérations ne doit lever, ni ralentir, sans traçage actif.
        trace_llm_call("severity", object(), "prompt", "reponse", 0.1)
        flush()
        with timed("severity", object(), "p") as t:
            t.response = "ok"
        # Le contexte ne doit pas AVALER une exception applicative.
        leve = False
        try:
            with timed("severity", object(), "p"):
                raise ValueError("erreur applicative")
        except ValueError:
            leve = True
        assert leve, "le traceur ne doit jamais masquer une exception"
        print("tracing : 4/4 controles OK (inerte sans cle, n'avale aucune exception)")
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
        _client, _checked = None, False


if __name__ == "__main__":
    demo()
