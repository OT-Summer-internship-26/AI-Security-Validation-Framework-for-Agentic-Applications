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
# IMAGE DE BASE ÉPINGLÉE PAR EMPREINTE
#     `python:3.11-slim` est une étiquette MOBILE : elle change à chaque
#     correctif Debian. Figer 168 paquets Python et laisser flotter tout le
#     système d'exploitation serait incohérent — la moitié de la reproductibilité
#     seulement. L'empreinte fige les deux.
#
#     METTRE À JOUR (à faire délibérément, pas subir) :
#         docker pull python:3.11-slim
#         docker inspect python:3.11-slim --format '{{index .RepoDigests 0}}'
#     puis reporter l'empreinte ici ET rejouer la suite de tests.
FROM python:3.11-slim@sha256:d1e9ca7c4e78d1e8ecadb5d44bfc8e956e7a65b659a9950f569f243d72b326d0 AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Chaîne de compilation, présente UNIQUEMENT dans cet étage.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# `requirements.lock` fige les 167 paquets de l'arbre complet, versions exactes.
#
# POURQUOI LE VERROU ET NON `requirements.txt`
#     `requirements.txt` ne contraint que les dépendances DIRECTES. Le résolveur
#     choisit le reste au moment du build — donc une image construite dans six
#     mois n'embarque pas les versions qui ont été testées. Ce n'est pas une
#     hypothèse : le premier build de cette image a échoué parce que le
#     résolveur avait pris un exportateur OpenTelemetry dont la dépendance
#     exacte n'était plus disponible.
#
# RÉGÉNÉRER LE VERROU (à faire sous Linux, jamais sous Windows où semgrep ne
# se construit pas) :
#     docker run --rm -v "$PWD":/w -w /w python:3.11-slim sh -c '
#       pip install -q pip-tools &&
#       pip-compile --strip-extras --output-file=requirements.lock requirements.txt'
COPY requirements.lock .

# `--no-deps` : le verrou est déjà l'arbre COMPLET et résolu. Laisser pip
# re-résoudre lui permettrait de tirer autre chose, ce qui viderait le verrou de
# son sens.
RUN pip install --prefix=/deps --no-deps -r requirements.lock


# --------------------------------------------------------------------------- #
# Étage 2 — image d'exécution
# --------------------------------------------------------------------------- #
# Même empreinte que l'étage de compilation : les deux doivent bouger ensemble,
# sinon les bibliothèques natives ne correspondent plus aux paquets compilés.
FROM python:3.11-slim@sha256:d1e9ca7c4e78d1e8ecadb5d44bfc8e956e7a65b659a9950f569f243d72b326d0 AS runtime

# Bibliothèques natives exigées à l'EXÉCUTION par weasyprint (rendu PDF des
# rapports). Sans elles, l'import réussit et la génération de PDF échoue au
# premier appel — une panne qui n'apparaîtrait qu'en production.
RUN apt-get update && apt-get install -y --no-install-recommends \
        tini \
        libcairo2 \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        shared-mime-info \
        fonts-dejavu-core \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /deps /usr/local

# L'outillage pip (pip, setuptools, wheel) porte ses propres vulnérabilités : le
# scan de l'image signalait `wheel`, `jaraco.context` et `setuptools` en HIGH,
# tous corrigeables. Ils ne viennent pas de nos dépendances.
#
# ⚠️ CETTE LIGNE DOIT VENIR APRÈS LE `COPY` — jamais avant.
#    Placée au-dessus, la copie du préfixe /deps réinstallait par-dessus la
#    version vulnérable, et le scan continuait de signaler `setuptools`. Le
#    correctif « fonctionnait » sans rien corriger : trouvé en rescannant, pas
#    en relisant.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# PIP EST ENSUITE RETIRÉ DE L'IMAGE D'EXÉCUTION.
#
# POURQUOI
#     1. Sécurité de surface : une image applicative n'installe rien à chaud.
#        Laisser pip, c'est laisser à qui obtient l'exécution de code un moyen
#        commode de télécharger la suite.
#     2. pip EMBARQUE ses propres dépendances vendorisées (`pip/_vendor/…`), qui
#        portent leurs propres vulnérabilités : le scan de l'image signalait
#        `msgpack 1.1.2` alors que la version INSTALLÉE était 1.2.2. Deux jours
#        d'investigation évités à qui lira le rapport de scan.
#
# `setuptools` et `wheel` restent : certaines bibliothèques les importent à
# l'exécution (`pkg_resources`).
RUN pip uninstall -y pip && rm -rf /usr/local/lib/python3.11/site-packages/pip*

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
# PID 1 = tini, pas Python.
#
# POURQUOI
#     1. Un processus Python en PID 1 ne recolte pas les ORPHELINS. Or garak,
#        semgrep, PyRIT et le sandbox tournent en SOUS-PROCESSUS : sur un
#        ouvrier de longue duree, la table des processus se remplit de zombies.
#     2. La propagation des signaux devient fiable : SIGTERM atteint vraiment
#        l'application, qui s'arrete proprement au lieu d'etre tuee.
#     Vaut aussi pour l'ouvrier, qui remplace ce CMD par le sien.
ENTRYPOINT ["/usr/bin/tini", "--"]

CMD ["python", "-m", "uvicorn", "api.main:app", \
     "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
