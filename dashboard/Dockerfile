# syntax=docker/dockerfile:1
#
# Image du tableau de bord d'audit.
#
# DEUX ÉTAGES, POUR UNE RAISON PRÉCISE
#     Node et les 139 Mo de `node_modules` ne servent QU'À la construction. Les
#     embarquer livrerait un environnement de développement complet dans un
#     conteneur exposé au réseau — une surface d'attaque offerte, pour rien.
#     L'image finale ne contient que des fichiers statiques et nginx.

# --------------------------------------------------------------------------- #
# Étage 1 — construction du paquet Vite
# --------------------------------------------------------------------------- #
# Épinglé par empreinte : `node:22-alpine` est une étiquette mobile, et figer
# les dépendances tout en laissant flotter l'environnement de construction ne
# donnerait qu'une moitié de reproductibilité.
FROM node@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS build

WORKDIR /build

# Les manifestes d'abord : tant qu'ils ne changent pas, Docker réutilise la
# couche d'installation. Copier tout le source en premier réinstallerait les
# dépendances à chaque modification d'un composant.
COPY package.json package-lock.json ./

# `npm ci` et non `npm install` : il installe EXACTEMENT le verrou et échoue si
# le manifeste et le verrou divergent. `npm install` réécrirait le verrou en
# silence, ce qui reviendrait à ne pas en avoir.
RUN npm ci --no-audit --no-fund

COPY . .

# L'URL de l'API est un CHEMIN RELATIF, jamais un hôte : Vite la compile dans le
# paquet livré. Une adresse en dur obligerait à reconstruire une image par
# environnement, alors qu'une image doit être promue telle quelle. C'est nginx
# qui sait où joindre l'API (voir nginx.conf).
ENV VITE_API_BASE=/api

RUN npm run build


# --------------------------------------------------------------------------- #
# Étage 2 — service des fichiers statiques
# --------------------------------------------------------------------------- #
# Épinglé par empreinte, comme l'étage de construction.
#
# ⚠️ UNE EMPREINTE FIGE AUSSI LES VULNÉRABILITÉS. C'est le revers de la
#    reproductibilité : `nginx:1.27-alpine` portait 35 vulnérabilités HIGH ou
#    CRITICAL corrigeables, `nginx:1.29-alpine` 13, `nginx:alpine` 4 — mesuré,
#    pas supposé. Une empreinte doit donc être RAFRAÎCHIE délibérément, et le
#    scan de la chaîne d'intégration est ce qui rend l'oubli visible.
FROM nginx@sha256:db35bfc6b2951e7f8a72db5db120288c127ffaeeb4a6d4b95a26fead017d5913 AS runtime

# Les 4 vulnérabilités restantes de l'image de base (libcrypto3, libssl3,
# libexpat) ont un correctif publié côté Alpine. Une image d'outil de sécurité
# ne les laisse pas passer pour économiser dix secondes de construction.
# ⚠️ CE `ARG` EXISTE POUR CASSER LE CACHE DE LA LIGNE SUIVANTE.
#
#     `apk upgrade` / `apt-get upgrade` dans une couche MISE EN CACHE cessent
#     silencieusement de mettre à jour quoi que ce soit : la couche est réutilisée
#     telle qu'elle était le jour de sa construction, correctifs de sécurité
#     compris — c'est-à-dire non compris.
#
#     MESURÉ, PAS SUPPOSÉ : l'image du dashboard portait **7 HIGH** (util-linux /
#     libuuid, TOCTOU sur `mount`) alors que `apk upgrade --no-cache` était déjà
#     dans ce fichier depuis longtemps. Reconstruite avec `--no-cache` : **0**.
#     La ligne n'était pas fausse — elle ne s'exécutait simplement plus.
#
#     En CI, `cache-from: type=gha` rend le problème PERMANENT : la couche ne
#     serait plus jamais rejouée. Recevoir le SHA du commit ici la fait rejouer à
#     chaque `push`. Placé dans l'étage d'exécution, qui est petit : la
#     construction de l'application, elle, reste en cache.
ARG AUDIT_BUILD=inconnu
RUN apk upgrade --no-cache

# Configuration du site. La configuration par défaut est retirée : la laisser
# ferait servir la page d'accueil nginx sur le port 80 à côté du dashboard.
RUN apk add --no-cache tini && rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf security-headers.conf /etc/nginx/conf.d/
COPY --from=build /build/dist /usr/share/nginx/html

# Exécution non privilégiée. L'image nginx officielle fournit déjà l'utilisateur
# `nginx` ; il faut lui donner les répertoires d'écriture, sinon le processus
# démarre en root ou échoue sur ses fichiers temporaires.
RUN touch /var/run/nginx.pid \
    && chown -R nginx:nginx /var/run/nginx.pid /var/cache/nginx /usr/share/nginx/html

# Port NON PRIVILÉGIÉ (8080 et non 80) : un processus non root ne peut pas
# écouter sous 1024.
EXPOSE 8080
USER nginx

# `/healthz` interroge nginx lui-même, pas l'API : un tableau de bord servi
# correctement alors que l'API est en panne doit rester « sain ». Confondre les
# deux ferait redémarrer le dashboard à cause d'une panne d'API.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q --spider http://127.0.0.1:8080/healthz || exit 1

# Meme raison que pour l'API : PID 1 doit recolter les orphelins et
# propager les signaux. nginx en engendre a chaque rechargement.
ENTRYPOINT ["/sbin/tini", "--"]

CMD ["nginx", "-g", "daemon off;"]
