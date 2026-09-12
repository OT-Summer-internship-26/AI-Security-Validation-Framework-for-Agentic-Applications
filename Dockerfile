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

# `requirements.lock` fige les 214 paquets de l'arbre complet, versions exactes.
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
# Étage 1bis — garak, dans un venv ISOLÉ et MINIMAL
# --------------------------------------------------------------------------- #
# POURQUOI UN VENV SÉPARÉ ET NON `requirements.txt`
#     garak épingle `openai<1.0.0` ; le reste de la pile (deepteam, deepeval,
#     langchain-openai) exige openai 2.x. Les deux ne peuvent pas coexister dans
#     un même site-packages. Un venv dédié annule le conflit : deux résolutions
#     indépendantes, un seul interpréteur de base.
#
# POURQUOI `--no-deps` SUR GARAK, ET LA LISTE À LA MAIN
#     garak DECLARE torch, transformers, datasets, nltk, accelerate,
#     sentencepiece. Installé normalement, son venv pèse **1,4 Go** (mesuré sur
#     le poste de développement). Mais ces paquets servent aux générateurs
#     HuggingFace LOCAUX — que ce framework n'utilise pas : il attaque une cible
#     HTTP via `rest.RestGenerator`.
#
#     La liste ci-dessous n'est pas devinée. Elle a été ÉTABLIE en installant
#     garak `--no-deps`, puis en ajoutant UNE PAR UNE les dépendances que
#     l'exécution réclame vraiment, jusqu'à ce qu'un scan REST complet aboutisse.
#
#     RÉSULTAT VÉRIFIÉ, via `judge/garak_runner.py` contre une cible bidon :
#       venv de référence (1,4 Go, avec torch) → score 5.0, « ok (1/2 passés) »
#       venv minimal      (  91 Mo, sans torch) → score 5.0, « ok (1/2 passés) »
#     Mêmes compteurs bruts. **15 fois plus petit, même verdict.**
#
#     Si un jour un axe garak exige un détecteur ML (classifieur de toxicité),
#     l'exécution échouera sur un ModuleNotFoundError EXPLICITE, pas en silence :
#     `run_garak` rend alors `excluded`, jamais un faux 10/10.
#
# LA VERSION EST CELLE QUE LE RUNNER SAIT PILOTER
#     `judge/garak_runner.py` construit une ligne de commande `--model_type` /
#     `--probes` que garak 0.16 a dépréciée (vérifié : « Expected plugin name in
#     format category.module_name.class_name »). Monter de version demande de
#     réécrire le runner — c'est un autre chantier, pas celui-ci.
FROM python:3.11-slim@sha256:d1e9ca7c4e78d1e8ecadb5d44bfc8e956e7a65b659a9950f569f243d72b326d0 AS garak

RUN mkdir -p /home/audit && python -m venv /home/audit/garak-venv
# L'OUTILLAGE DU VENV EST REMONTE, ET C'EST UN CORRECTIF DE SECURITE.
#     Un venv neuf embarque le setuptools de base, dont les dependances
#     VENDORISEES (`setuptools/_vendor/`) trainaient deux CVE HIGH corrigeables :
#     `jaraco.context 5.3.0` (CVE-2026-23949) et `wheel 0.45.1` (CVE-2026-24049).
#     L'image PRINCIPALE etait saine — c'est cet etage-ci qui les reintroduisait,
#     et seul un scan de l'image assemblee pouvait le montrer. Trouve en mesurant
#     avant de rendre le scan bloquant, pas en relisant le Dockerfile.
RUN /home/audit/garak-venv/bin/pip install --no-cache-dir -q --upgrade pip setuptools wheel
RUN /home/audit/garak-venv/bin/pip install --no-cache-dir -q --no-deps garak==0.9.0.11.post1
# Ces onze-là AVEC leurs propres dépendances (httpx tire httpcore/anyio, requests
# tire urllib3/idna/certifi…). Toutes légères : `--no-deps` ici ferait échouer
# l'exécution sur un import transitif, ce qui est exactement la panne qu'on corrige.
RUN /home/audit/garak-venv/bin/pip install --no-cache-dir -q pyyaml xdg_base_dirs colorama requests httpx aiohttp numpy tqdm backoff markdown jinja2

# PIP ET SETUPTOOLS SONT RETIRES DU VENV — MEME RAISON QUE POUR L'IMAGE.
#     L'image d'execution retire deja pip (voir plus bas) : il embarque ses
#     dependances VENDORISEES (`pip/_vendor/`), que les scanners signalent meme
#     quand la version reellement installee est saine. Le venv garak, lui,
#     gardait le sien : mesure sur l'image assemblee, il portait `msgpack 1.1.2`
#     et `setuptools 70.3.0` — les DEUX SEULS HIGH corrigeables restants.
#
#     Ce venv ne sert qu'a `python -m garak` : il n'installe plus rien apres la
#     construction, donc pip et setuptools n'y ont aucun role. Les retirer
#     supprime les findings ET reduit la surface, exactement comme pour l'image.
RUN /home/audit/garak-venv/bin/pip uninstall -y -q pip setuptools wheel 2>/dev/null || true;     rm -rf /home/audit/garak-venv/lib/python3.11/site-packages/pip*            /home/audit/garak-venv/lib/python3.11/site-packages/setuptools*            /home/audit/garak-venv/lib/python3.11/site-packages/pkg_resources            /home/audit/garak-venv/lib/python3.11/site-packages/wheel*


# --------------------------------------------------------------------------- #
# Étage 2 — image d'exécution
# --------------------------------------------------------------------------- #
# Même empreinte que l'étage de compilation : les deux doivent bouger ensemble,
# sinon les bibliothèques natives ne correspondent plus aux paquets compilés.
FROM python:3.11-slim@sha256:d1e9ca7c4e78d1e8ecadb5d44bfc8e956e7a65b659a9950f569f243d72b326d0 AS runtime

# Bibliothèques natives exigées à l'EXÉCUTION par weasyprint (rendu PDF des
# rapports). Sans elles, l'import réussit et la génération de PDF échoue au
# premier appel — une panne qui n'apparaîtrait qu'en production.
#
# ⚠️ MÊME PIÈGE QUE DANS dashboard/Dockerfile, ET IL N'A PAS ENCORE MORDU ICI.
#     Cette couche `apt-get` est mise en cache comme les autres : réutilisée
#     telle quelle, elle cesse d'apporter les correctifs de sécurité Debian sans
#     que rien ne le signale. L'image du dashboard a montré ce que ça donne —
#     7 HIGH accumulés derrière un `apk upgrade` qui ne tournait plus, alors que
#     la ligne était bien là. Recevoir le SHA du commit fait rejouer la couche à
#     chaque `push`. L'étage de compilation, lui, reste en cache.
ARG AUDIT_BUILD=inconnu

# `upgrade` ET PAS SEULEMENT `install` — LE PIÈGE A MORDU, ET VOICI OÙ.
#     Le cache-busting ci-dessus fonctionnait : la couche se rejouait bien à
#     chaque push. Mais `apt-get install` n'installe que les paquets NOMMÉS. Or
#     l'image de base est épinglée PAR CONDENSÉ — c'est voulu, c'est ce qui rend
#     la construction reproductible — donc elle est FIGÉE : ses paquets ne
#     reçoivent jamais les correctifs Debian publiés depuis.
#
#     Résultat, mesuré par la barrière Trivy de `images.yml` : 12 failles
#     corrigeables (9 HIGH, 3 CRITICAL) sur `gzip`, `libpcre2-8-0`,
#     `libsqlite3-0` et `perl` — aucun de ces quatre paquets n'est dans la liste
#     ci-dessous. Ils viennent tous de la base, et rien ne les touchait.
#
#     `upgrade` les remonte toutes. La combinaison reste cohérente : condensé
#     épinglé pour la REPRODUCTIBILITÉ, `upgrade` pour les CORRECTIFS. L'un
#     n'exclut pas l'autre, il fallait les deux.
#
#     `DEBIAN_FRONTEND=noninteractive` EST OBLIGATOIRE DÈS QU'ON `upgrade`.
#     `install` sur des paquets choisis ne posait aucune question ; `upgrade`
#     touche `perl`, `libc` et consorts, dont les mainteneurs peuvent demander
#     quoi faire d'un fichier de configuration modifié. Sans cette variable, la
#     construction ATTENDRAIT une réponse que personne ne peut donner — jusqu'au
#     `timeout-minutes: 30` du job. Posée en ligne et non en `ENV` : elle ne doit
#     valoir que pendant cette couche, pas à l'exécution du conteneur.
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
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
# `jaraco.context` nomme explicitement : il arrive VENDORISE avec setuptools, et
# le nommer garantit qu'il reste au-dessus de CVE-2026-23949 meme si un jour
# setuptools regressait sa version vendorisee.
#
# HONNETETE SUR LA CAUSE : ce n'est PAS cette ligne qui a corrige les deux HIGH
# du scan. L'image principale etait deja saine (jaraco_context 6.1.2, wheel
# 0.48.0) ; les versions vulnerables venaient de l'etage `garak`, dont le venv
# embarquait son propre setuptools plus ancien. Cherche du mauvais cote pendant
# une reconstruction complete, trouve en listant les fichiers DANS l'image.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel "jaraco.context>=6.1.0"

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

# Le venv garak, après `useradd` : c'est lui qui crée /home/audit.
# Le chemin n'est pas arbitraire — `judge/garak_runner.py` cherche par défaut
# `<dossier personnel>/garak-venv/bin/python`, donc exactement celui-ci pour
# l'utilisateur `audit`. Aucune variable d'environnement à poser ; poser
# `GARAK_VENV_PYTHON` reste possible pour désigner un autre venv.
#
# AVANT CE BLOC, L'IMAGE N'AVAIT AUCUN GARAK. `garak_available()` rendait
# False, l'axe sortait « unavailable » — traité comme un axe exclu, jamais
# comme un défaut d'installation. Le SEUL axe indépendant du LLM manquait à
# tous les audits de production, sans que rien ne le dise.
COPY --from=garak --chown=audit:audit /home/audit/garak-venv /home/audit/garak-venv

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

# Un seul worker — MAIS PLUS POUR LA RAISON QUI ÉTAIT ÉCRITE ICI.
#
# Ce commentaire disait que l'état des exécutions vivait en mémoire (`_RUNS`
# dans api/main.py) et qu'un second worker répondrait 404 une fois sur deux.
# C'était vrai ; ça ne l'est plus : `api/store.py` tient l'état dans SQLite,
# en WAL, avec `busy_timeout`, une connexion par fil, une prise de travail
# atomique (`WHERE id=? AND status='queued'`) et la reprise des travaux
# abandonnés par battement. Plusieurs processus partagent donc le même état.
#
# Laisser écrit « chantier d'industrialisation identifié » aurait fait renoncer
# à monter en charge pour un obstacle disparu : c'est le genre de commentaire
# périmé qui coûte plus cher qu'une absence de commentaire.
#
# CE QUI CONTRAINT RÉELLEMENT AUJOURD'HUI
#     · Sur UN nœud, plusieurs workers sont possibles — non mesuré sous charge,
#       donc pas encore le défaut livré. À valider avant de monter.
#     · Sur PLUSIEURS nœuds, non : WAL exige un système de fichiers local et ne
#       tient pas ses garanties sur un volume réseau partagé. Ce palier-là
#       demande un vrai serveur de base, et lui reste un chantier.
# PID 1 = tini, pas Python.
#
# POURQUOI
#     1. Un processus Python en PID 1 ne recolte pas les ORPHELINS. Or garak,
#        semgrep, PyRIT et le sandbox tournent en SOUS-PROCESSUS : sur un
#        ouvrier de longue duree, la table des processus se remplit de zombies.
#     2. La propagation des signaux devient fiable : SIGTERM atteint vraiment
#        l'application, qui s'arrete proprement au lieu d'etre tuee.
#     Vaut aussi pour l'ouvrier, qui remplace ce CMD par le sien.
# Identifiant de la construction — PLACÉ ICI, ET C'EST DEUX FOIS DÉLIBÉRÉ.
#
# CE QUE ÇA CORRIGE
#     `/health` annonçait « version 1.0.0 », valeur codée en dur dans
#     `api/main.py`. Elle ne bougeait ni avec le tag git ni avec le SHA publié :
#     impossible de savoir, depuis l'extérieur, QUEL build répond. Sur un
#     incident, la première question est « quelle version tourne ? » — il fallait
#     aller lire l'étiquette du conteneur, donc avoir un accès Docker à l'hôte.
#
# POURQUOI SI BAS DANS LE FICHIER
#     Un `ARG` qui change à chaque commit INVALIDE tout ce qui le suit dans le
#     cache de couches. Placé en tête, il ferait reconstruire l'installation des
#     214 paquets à chaque push. Ici, seules les dernières couches bougent.
#
# `org.opencontainers.image.revision` est l'étiquette standard : les scanners et
# les registres savent la lire sans rien connaître de ce projet.
ARG AUDIT_BUILD=inconnu
ENV AUDIT_BUILD=${AUDIT_BUILD}
LABEL org.opencontainers.image.revision="${AUDIT_BUILD}"

ENTRYPOINT ["/usr/bin/tini", "--"]

CMD ["python", "-m", "uvicorn", "api.main:app", \
    "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
