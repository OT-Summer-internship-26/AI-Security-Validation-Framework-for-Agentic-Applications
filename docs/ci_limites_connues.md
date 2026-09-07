# CI/CD — limites connues

> **Ce document est un registre vivant, pas un bilan.**
> Règle de tenue : **chaque correction de la CI ajoute ici ce qu'elle ne ferme pas.**
> Un correctif qui ne laisse rien derrière lui l'écrit aussi — « rien » est une
> information. Ce qui n'est pas écrit ici est réputé couvert : si vous découvrez
> un trou absent de cette liste, c'est ce fichier qu'il faut corriger d'abord.
>
> Pourquoi ce registre existe : cinq contrôles de cette chaîne ont été trouvés
> **décoratifs** — présents, verts, et ne vérifiant rien. Un `::warning::` qui ne
> bloque pas, un gate qui jugeait un artefact périmé, cinq tests de sécurité qui
> ne tournaient nulle part, un garde-fou dont le job ne se déclenchait pas, un
> scan de CVE portant sur autre chose que ce qui est livré. Le point commun :
> personne n'avait écrit noir sur blanc ce qu'ils ne couvraient pas.

Mesures prises sur poste de développement, caches tièdes. Un runner GitHub est
plus lent — les ordres de grandeur tiennent, pas les secondes.

---

## A. Portée volontairement limitée

### A1. Le gate ne rend un verdict que s'il y a une cible auditée
`scripts/ci_gate.py` n'est appelé que sous `workflow_dispatch` avec `target_url`.

**Pourquoi** : sans argument, il prend **le fichier d'audit le plus récent trouvé
sur disque**. Comme 38 résultats sont versionnés, il jugeait sur une pull request
un artefact du 1er septembre contre une cible bidon `http://c/chat`, et rendait
invariablement `PASS — déploiement autorisé`, posté en commentaire de PR. Un faux
vert coûte plus cher qu'un contrôle absent : il fait croire que quelqu'un a regardé.

**Ce qui protège une PR à la place** : suite hors-ligne, test de mutation,
auto-contrôles d'infrastructure, Semgrep, pip-audit.

**Ce qui fermerait** : produire un audit réel par PR — donc une cible joignable
et du temps de calcul. Non retenu.

### A2. PyRIT n'est pas installé dans la porte de qualité
**Mesuré : 4 min 44** d'installation. Sur une porte qui doit rendre son verdict
vite, c'est disqualifiant. Ce n'est **pas** une incompatibilité : `requirements.lock`
le résout avec `click==8.1.8` et l'image l'embarque.

**Conséquence exacte** : `test_pyrit_ne_fait_jamais_echouer_l_audit` se met en
`importorskip` dans la porte. Il s'exécute pour de vrai dans le job d'image, où la
suite tourne DANS le conteneur. Le contrat « outil absent → axe EXCLU, jamais 0 »
reste couvert partout par le test voisin, qui simule l'absence par monkeypatch.

### A3. Aucun score stochastique ne bloque
DeepTeam et PyRIT donnent des scores non reproductibles — **9,66 et 7,93 sur deux
runs identiques, même cible**. Bloquer un développeur là-dessus serait indéfendable.
La porte ne fait tourner que du déterministe.

---

## B. Couverture incomplète, et de combien

### B1. ~~`ci_gate.py` garde son piège en usage local~~ — **FERMÉ**
Le script refuse désormais de juger quoi que ce soit sans qu'on lui désigne un
audit : sortie **2** et un message qui explique. Le comportement d'avant reste
disponible, mais **il faut le demander** (`--dernier`).

**Ce qui subsiste, et c'est délibéré** : `--dernier` peut toujours désigner un
résultat versionné si on le lance dans un dépôt propre. La différence est qu'on
l'a écrit — un verdict qui se trompe de sujet parce qu'on le lui a demandé n'est
plus un piège, c'est une erreur de l'opérateur. Adossé à un test et au contrôle
de mutation.

### B2. 38 résultats d'audit sont versionnés
`data/audit_results/` est suivi par git : **54 fichiers**, dont **38 résultats
d'audit** (`.json`) et 15 transcriptions d'échanges (`.exchanges.jsonl`). C'est ce
corpus qui a rendu le gate menteur — et c'est aussi lui qui alimente la démo du
dashboard quand l'API est éteinte (voir B6). Il a donc une vraie fonction.

**Ce qui fermerait** : les déplacer hors de `workflow.paths.results_dir()`, pour que
rien ne puisse les confondre avec un audit courant — au prix de casser la démo,
qui les lit par ce même chemin. Non retenu tant que les deux consommateurs
(`ci_gate` et le dashboard) disent clairement ce qu'ils affichent, ce qui est
désormais le cas.

### B3. Les probes garak à détecteur ML ne tournent pas sur le venv allégé
Le venv livré dans l'image fait **91 Mo** au lieu de 1,4 Go (garak déclare `torch`,
`transformers`, `datasets`… qui servent aux générateurs HuggingFace **locaux**,
inutilisés ici). Les probes par défaut — `dan.AntiDAN`, `dan.DAN_Jailbreak`, à
détecteurs textuels — rendent un verdict **identique** au venv complet, compteurs
bruts compris. Une probe à détecteur ML (`realtoxicityprompts`) ne peut pas tourner.

**Ce que ça donne** : garak attrape l'import manquant, saute le détecteur et sort
en **code 0**. L'axe est exclu — jamais 0, jamais 10/10 — et depuis le correctif le
message **nomme le détecteur** et précise que la cible n'est pas en cause.

**Ce qui fermerait** : installation complète (1,4 Go, résolution > 45 min mesurées).

### B4. PyRIT n'est pas éprouvé contre une vraie cible LLM
Vérifié : il s'importe dans l'image, et son test de fail-safe y passe. Un run réel
demande une clé.

**Ce qui fermerait** : une clé AI Studio (`AIza…`, gratuite) et un run planifié
contre un lab DVAP, comparé au score de référence.

### B5. L'arbre transitif n'est jamais re-résolu automatiquement
`scripts/check_lock.py` répond à deux questions — *déclaré → épinglé* et
*importé → résolvable* — et à aucune troisième. Une version transitive qui vieillit
ne casse pas l'image : le verrou reste la source de vérité. Mais elle ne sera pas
signalée.

**Mesuré** : une régénération complète prend **une trentaine de minutes**. C'est
pourquoi elle n'est pas dans une porte de PR.

**Ce qui fermerait** : un workflow **planifié** (hebdomadaire) qui régénère le
verrou et ouvre une PR s'il bouge.

### B6. Le dashboard sert un jeu de démonstration quand l'API est éteinte
C'est **voulu** : un dashboard vide ne se démontre pas. Quatre audits d'exemple,
datés de juillet 2026.

**Ce qui était cassé, et qui ne l'est plus** : rien ne le disait. `DataGate`
n'affichait son écran « API injoignable » que si la liste était VIDE — condition
que ce repli rend impossible, puisqu'il la remplit. Aucun composant ne lisait
`source === 'demo'`, malgré une docstring qui affirmait le contraire. L'historique
montrait donc quatre audits de juillet comme s'ils étaient les vôtres.

Un bandeau persistant, en tête de page, le dit maintenant — avec la commande pour
tout démarrer (`start-dashboard.bat` lance l'API **et** le dashboard ;
`run-dashboard.bat` ne lance que le dashboard, ce que son en-tête précise désormais).

**Ce qui fermerait complètement** : ne servir aucune donnée de démo et laisser
l'écran d'erreur seul. Non retenu — la démo a une valeur, tant qu'elle ne se fait
pas passer pour autre chose.

### B7. Rien ne vérifie automatiquement les commandes DOCUMENTÉES
Les workflows sont exécutables et vérifiés. Les blocs `bash` des documents, non.

**Constaté** : changer le contrat de `ci_gate.py` (il refuse désormais de choisir
son sujet) a cassé sur-le-champ la commande de `integration_guide.md`, sans que
rien ne le signale. Et `architecture_technique.md` documentait `--audit` et
`--policy` — **deux drapeaux qui n'ont jamais existé**. Une documentation fausse
se découvre quand quelqu'un la suit, c'est-à-dire au pire moment.

**Palliatif en place** : après tout changement d'interface, exécuter les commandes
des workflows *et* celles des documents. Les 12 commandes des workflows passent
(vérifié une par une).

**Ce qui fermerait** : extraire les blocs `bash` des documents et les exécuter en
CI. Non retenu — la plupart exigent une cible, une clé ou une pile démarrée ; le
peu qui reste ne justifie pas la machinerie.

---

## C. Écarts CI ↔ production résiduels

### C1. Python correctif et système de base diffèrent
Runner : dernier 3.11 disponible · image : **3.11.16**. Runner : ubuntu · image :
debian-slim.

**Couverture indirecte, mais réelle** : la suite hors-ligne tourne **aussi dans
l'image** (job `api`). Un écart de plateforme qui casserait quelque chose y
rougirait.

### C2. Cinq tests de bac à sable sautent dans l'image
Ils exigent un socket Docker, que le conteneur n'a pas — **par décision de
sécurité assumée** : monter `/var/run/docker.sock` revient à donner la racine de
l'hôte. Ils tournent sur le runner, où un `docker pull python:3.11-slim` les réveille
(sans lui, ils ne tournaient **nulle part**).

---

## D. Livraison (CD)

La CI publie sur GHCR **l'objet exact qui a été testé** — réétiqueté, pas
reconstruit. Deux étiquettes, deux promesses distinctes :

* `sha-<7>` sort du job qui a construit et éprouvé l'image. Immuable, traçable ;
  le publier tôt ne coûte rien — personne ne déploie un SHA par accident.
* `<version>` est le nom par lequel on **déploie**. Il n'existe qu'après le job
  `pile`, donc après validation de l'API, de l'ouvrier, de la file et du
  dashboard ensemble. Un job `promouvoir` (`needs: [api, dashboard, pile]`) copie
  `sha-<7>` vers `<version>` par manifeste — **même condensé**.
* Jamais de `latest` : le retour arrière exige des étiquettes immuables.

Le job `pile` **tire les images publiées** et lance `up --no-build` : le test de
pile est donc aussi le test de la procédure de déploiement documentée
(`docs/integration_guide.md` §6).

S'y ajoutent, depuis : un **SBOM** CycloneDX de l'image testée (artefact du job,
90 jours), la publication du **condensé** — épinglable via `AUDIT_REF_*`, seule
référence réellement immuable — une **signature par clé** sans journal de
transparence public, et une **rétention hebdomadaire** du registre qui préserve
les étiquettes de version.

Ce qui n'est **pas** couvert :

### D0. Un `sha-<7>` peut exister sans que la pile ait validé
Les jobs d'image publient avant que `pile` ne s'exécute — c'est structurel : `pile`
a besoin des deux images pour tourner.

**Assumé, et borné** : un SHA non promu sert au diagnostic et au retour arrière.
**Aucune étiquette déployable n'est jamais créée sans validation complète** — c'est
tout l'objet de la promotion. Un opérateur qui déploie un SHA le fait délibérément.

**Ce qui fermerait** : exporter l'image en artefact (`docker save`, ~2,3 Go) pour
la publier depuis un job postérieur. Le coût de transfert ne vaut pas la nuance.

### D1. ~~Trivy ne BLOQUE pas la publication~~ — **FERMÉ, sans risque accepté**
Le scan est bloquant sur les deux images (`exit-code: 1`, HIGH/CRITICAL,
`ignore-unfixed`). **Aucun `.trivyignore`** : il n'y a rien à ignorer.

**L'hypothèse qui justifiait de ne pas le faire était fausse.** J'avais écrit que
bloquer « arrêterait la chaîne sur la CVE `click` déjà acceptée ». Mesuré : Trivy
ne signale pas `click` — c'est pip-audit qui la voit, via une autre base. Une
limite écrite sans mesure avait donc gelé la décision pendant des jours.

**Trois mesures ont été nécessaires, chacune corrigeant la précédente** :

| Mesure | Trouvé | Cause réelle |
|---|---|---|
| 1 | `jaraco.context 5.3.0`, `wheel 0.45.1` | pas `click` |
| 2 | mêmes deux | l'étage `garak`, pas l'image principale |
| 3 | `msgpack 1.1.2`, `setuptools 70.3.0` | le **pip vendorisé** du venv garak |

Corrigé en appliquant au venv garak ce que l'image principale se applique déjà :
retirer pip et setuptools. Vérifié que garak fonctionne toujours — scan réel dans
l'image, score 5.0, « ok (2/4 passés) », identique. Résultat : **0 finding**.

### D1b. Le dashboard portait 7 HIGH derrière un `apk upgrade` qui ne tournait plus
Trouvé en scannant la seconde image, qui ne l'avait jamais été.
`RUN apk upgrade --no-cache` était présent depuis longtemps — et **mis en cache**,
donc réutilisé tel qu'il était le jour de sa construction, correctifs compris,
c'est-à-dire non compris. Reconstruit avec `--no-cache` : **0**.

En CI, `cache-from: type=gha` rendait le problème permanent. Les deux Dockerfiles
reçoivent désormais le SHA du commit en `ARG` **juste avant** la couche de mise à
jour système, ce qui la fait rejouer à chaque `push` sans invalider la
construction applicative. Vérifié : avec un SHA différent, **0 couche
`apk upgrade` réutilisée du cache**.

**Ce que ça dit du reste** : une ligne juste dans un Dockerfile n'est pas une
ligne qui s'exécute. Seul le scan de l'image ASSEMBLÉE le montre.

### D2. ~~Publier n'est pas déployer~~ — **MÉCANIQUE FERMÉE, cible à vous**
`.github/workflows/deploiement.yml` porte désormais la seule porte par laquelle
une image entre en production. Ce qu'il apporte, et qu'une procédure manuelle ne
peut pas garantir :

1. **Une approbation** — le job cible un *GitHub Environment*. Attachez-y une
   règle de protection (Settings → Environments) et personne ne déploie sans
   qu'un humain ait cliqué. C'est la seule barrière qui résiste à la fatigue.
2. **Une vérification de signature AVANT de déployer** — c'est le moment où la
   signature sert enfin à quelque chose. Signer sans jamais vérifier revient à
   poser un cadenas en laissant la clé sur la porte. Une image dont la signature
   ou l'attestation SBOM ne se vérifie pas **n'est pas déployée**.
3. **Un déploiement par CONDENSÉ** — le workflow résout l'étiquette en condensé
   et déploie celui-ci. On ne déploie pas « la dernière », on déploie celle-là.
4. **Une confirmation post-déploiement** — `/health` rend le champ `build` ; le
   workflow exige qu'il corresponde à la version demandée. Sans ça, un
   `up -d` qui ne recrée rien passerait pour un déploiement réussi.

**Ce qui reste à vous, et c'est délibéré** : l'hôte, l'accès et la fenêtre. Le
transport SSH est **inert** tant que `DEPLOY_HOST` / `DEPLOY_SSH_KEY` n'existent
pas — le workflow rend alors les commandes exactes, signature déjà vérifiée et
condensés déjà résolus. Même principe que la signature, restée inactive jusqu'à
ce que la clé existe.

### D2b. Sans `DEPLOY_HOST_KEY`, l'empreinte de l'hôte est acceptée sans contrôle
`ssh-keyscan` seul, c'est de la confiance au premier contact — et un runner
GitHub est **toujours** neuf, donc c'est une fenêtre d'interception à chaque
exécution. Pour un outil de sécurité qui déploie sa propre chaîne, c'est le
mauvais endroit où être approximatif.

**Atténué, pas fermé** : si `DEPLOY_HOST_KEY` existe (sortie de `ssh-keyscan`
faite UNE fois depuis un poste de confiance), l'empreinte est imposée. Sinon, le
workflow scanne **et émet un `::warning::`** — l'état dégradé s'annonce.

**Ce qui fermerait** : rendre le secret obligatoire. Non retenu tant que le
transport lui-même est optionnel — exiger une empreinte pour un hôte qu'on n'a
pas encore serait un garde-fou sans porte.

### D6. ~~Le déploiement épingle les IMAGES, pas la TOPOLOGIE~~ — **FERMÉ**
`deploiement.yml` extrait `docker-compose.yml` **du commit dont viennent les
images** (`git show <commit>:docker-compose.yml`) et l'envoie avec elles. Ports,
volumes, limites mémoire, `healthcheck`, `stop_grace_period` : tout provient
désormais du même commit que les octets exécutés.

**Aucune hypothèse sur la gestion de l'hôte** — c'est ce qui bloquait la
fermeture. Le dépôt est déjà présent sur le runner ; `git show` suffit, et la
cible n'a besoin ni de git, ni d'Ansible, ni de quoi que ce soit.

**Refus explicite si le commit est introuvable** : déployer sous un compose
inconnu serait pire que ne pas déployer. Et si le compose du commit diffère de
celui de la branche courante, le diff est affiché en avertissement — c'est le
genre d'écart qu'on veut voir AVANT.

Vérifié sur le dépôt réel : `sha-c346fb5` → commit résolu, compose de 270 lignes
extrait.

### D7. AUCUN de ces quatre workflows n'a jamais tourné
C'est la limite la plus honnête de tout ce document. Tout ce qui pouvait être
éprouvé hors ligne l'a été — 34 scripts shell passés à `bash -n`, cycle complet
signature + attestation + vérification rejoué sur un registre local, images
construites et scannées, `pile` et retour arrière simulés. Trois défauts y ont
été trouvés qui auraient cassé le premier `push` (`--format` ignoré,
`--tlog-upload` rejeté, tirets lus comme des soustractions).

**Ce qui reste inconnu, et que seul un vrai `push` dira** : le collage correct
des secrets, le comportement des actions tierces sur un runner, les permissions
GHCR réelles, et le déclenchement des filtres `paths`.

**Ce qui fermerait** : le premier `push` sur `main`, et la lecture des journaux.

### D4. ~~La signature est INACTIVE tant que la clé n'existe pas~~ — **FERMÉ**
Les secrets `COSIGN_KEY` et `COSIGN_PASSWORD` existent depuis le 2026-09-06 : la
condition qui justifiait la tolérance est levée. L'étape **échoue** désormais si
la clé manque, au lieu d'émettre un avis que personne ne lit.

**Le raisonnement, parce qu'il se rediscutera** : une image NON SIGNÉE qui part
quand même est pire qu'une construction rouge. La seconde se voit et se corrige
en cinq minutes ; la première circule en se faisant passer pour vérifiée. Le coût
d'un secret mal collé est un job rouge — celui d'une signature silencieusement
absente est de ne plus savoir ce qui a été livré.

**Éprouvé avant d'être écrit** : cycle complet signature + vérification rejoué en
local sur un registre jetable — *« The signatures were verified against the
specified public key »*. Deux défauts y ont été trouvés, qui auraient cassé le
premier `push` : `imagetools inspect --format` **ignoré en silence** par buildx
v0.30.1 (le condensé se calcule désormais par `--raw | sha256sum`), et
`--tlog-upload=false` **rejeté** par le cosign courant (d'où le pin `v2.4.1`).

### D5. ~~Le SBOM est un artefact, pas une attestation attachée à l'image~~ — **FERMÉ**
`cosign attest --predicate … --key` le pousse désormais **à côté de l'image**,
signé, sans rien reconstruire — la garantie « on publie l'objet testé » reste
entière.

**`attest` et non `attach sbom`, et c'est l'essai qui l'a dicté.** J'avais écrit
`attach sbom`. En l'éprouvant sur un registre local, cosign a répondu deux
avertissements sans appel : la commande est **dépréciée** (retrait annoncé), et
surtout **elle ne signe pas** le SBOM. Un inventaire non signé accroché à une
image signée est une demi-mesure : qui a l'écriture sur le registre peut le
remplacer sans laisser de trace.

Vérification côté consommateur :
`cosign verify-attestation --key cosign.pub --type cyclonedx --insecure-ignore-tlog=true <image>@<condensé>`
— éprouvé de bout en bout : *« The signatures were verified against the specified
public key »*.

**L'artefact du job est conservé malgré tout**, et ce n'est pas une redondance :
il se lit sans accès au registre, ce qui compte le jour où une CVE tombe un
dimanche et où l'on veut juste savoir si on embarque le paquet concerné.

### D3. ~~`/health` ne dit pas QUEL build tourne~~ — **FERMÉ**
`/health` rend un champ **`build`** portant le SHA injecté à la construction
(`ARG AUDIT_BUILD`, également publié en `org.opencontainers.image.revision`).
`version` reste la version PRODUIT — les deux ne répondent pas à la même
question, et c'est pour ça qu'elles coexistent.

Sur un incident, « quelle version tourne ? » se répond désormais par un `curl`,
sans accès Docker à l'hôte.

**Détail qui compte** : l'`ARG` est placé tout en bas du Dockerfile. En tête, il
aurait invalidé le cache de couches à chaque commit et fait réinstaller les 214
paquets à chaque `push`. `build: "inconnu"` signale une image construite à la
main, hors chaîne — et c'est une information en soi.

---

## E. Budget de temps

Porte de qualité, plafond **20 min**, contenu mesuré à **9–10 min** :

| Étape | Mesure |
|---|---|
| install semgrep + pip-audit | ~60 s |
| install deps de test (`-c requirements.lock`) | 100 s |
| `docker pull` du bac à sable | ~15 s |
| suite pytest | 66 s |
| auto-contrôles d'infrastructure | ~15 s |
| **test de mutation** | **153 s** |
| Semgrep (dépôt entier, 2 jeux de règles) | 24 s |
| pip-audit sur le verrou | ~30 s |

Le poste le plus lourd est le test de mutation, et c'est assumé : il casse chaque
correctif pour exiger que son test rougisse. C'est lui qui distingue un filet réel
d'un filet décoratif — le sujet de tout ce document.
