# syntax=docker/dockerfile:1
#
# Image de l'API d'audit de sécurité IA.
#
# POURQUOI UNE CONSTRUCTION EN DEUX ÉTAGES
#     Les dépendances de ce projet tirent une chaîne de compilation (weasyprint,
#     pydantic-core, les extensions de deepeval). La garder dans l'image finale
#     ajouterait plusieurs centaines de mégaoctets et surtout un compilateur C
#     dans un conteneur exposé — exactement ce qu'un attaquant cherche après une
#     exécution de code. On compile dans un étage jeté, on n'embarque que le
#     résultat.
#
# CE QUE CETTE IMAGE NE FAIT PAS
#     Elle ne contient PAS de client Docker. La couche dynamique (sandbox ASI05)
#     exige `docker run`, donc l'accès au démon de l'hôte — ce qu'une équipe
#     sécurité refuse à juste titre : monter /var/run/docker.sock dans un
#     conteneur revient à lui donner la racine de l'hôte.
#     Sans lui, le framework dégrade proprement : la couche dynamique se déclare
#     non applicable, elle n'est ni notée 0 ni comptée comme réussie.
#     Pour l'activer, voir « Contraintes de déploiement » dans
#     docs/architecture_technique.md — un exécuteur isolé (gVisor, Kata, ou un
#     nœud dédié) est la seule voie acceptable en cluster partagé.

# --------------------------------------------------------------------------- #
# Étage 1 — compilation des dépendances
# --------------------------------------------------------------------------- #
FROM python:3.11-slim AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Chaîne de compilation, présente UNIQUEMENT dans cet étage.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .

# Les paquets vont dans un préfixe isolé, recopié tel quel dans l'image finale.
RUN pip install --prefix=/deps -r requirements.txt


# --------------------------------------------------------------------------- #
# Étage 2 — image d'exécution
# --------------------------------------------------------------------------- #
FROM python:3.11-slim AS runtime

# Bibliothèques natives exigées à l'EXÉCUTION par weasyprint (rendu PDF des
# rapports). Sans elles, l'import réussit et la génération de PDF échoue au
# premier appel — une panne qui n'apparaîtrait qu'en production.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libcairo2 \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        shared-mime-info \
        fonts-dejavu-core \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /deps /usr/local

# Utilisateur non privilégié. Un outil qui attaque des systèmes ne tourne pas en
# root : si sa cible le compromet en retour, l'escalade doit s'arrêter là.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin audit

WORKDIR /app
COPY --chown=audit:audit . /app

# Les résultats vivent HORS de /app : le disque du conteneur est éphémère, un
# audit d'une heure disparaîtrait au redémarrage du pod. Ce chemin est celui à
# monter sur un volume persistant, partagé si plusieurs instances tournent.
ENV AUDIT_DATA_DIR=/var/lib/ai-security \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1

RUN mkdir -p /var/lib/ai-security/audit_results /var/lib/ai-security/reports \
    && chown -R audit:audit /var/lib/ai-security

VOLUME ["/var/lib/ai-security"]

USER audit
EXPOSE 8000

# La sonde interroge /health, qui répond sans authentification par conception :
# protéger la santé rendrait le service indistinguable d'un service mort pour
# tout système de supervision.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

# Un seul worker : l'état des exécutions vit en mémoire du processus
# (`_RUNS` dans api/main.py). Deux workers ne verraient pas les mêmes
# exécutions, et `GET /runs/{id}` répondrait 404 une fois sur deux.
# Passer à plusieurs instances exige d'abord un état partagé — c'est un chantier
# d'industrialisation identifié, pas un réglage.
CMD ["python", "-m", "uvicorn", "api.main:app", \
     "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
