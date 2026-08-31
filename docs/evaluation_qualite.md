# Évaluation de la qualité du projet

**Framework d'audit de sécurité pour applications IA agentiques** — Ooredoo Tunisie
Évaluation réalisée le 2026-08-31 · 17 310 lignes Python (dont 1 847 de tests) · 146 tests
**Deux mesures : avant correctifs, puis après application des 3 actions prioritaires.**

---

## Récapitulatif

| # | Dimension | Outil | Avant | Après | Score |
|---|---|---|---|---|---|
| 1 | Qualité du code | Ruff 0.16.5 | 260 signalements | **194** (−25 %) | 7,0 → **7,5** |
| 2 | Sécurité du code | Bandit 1.9.4 | 0 HIGH · **5 MEDIUM** | 0 HIGH · **1 MEDIUM** | 8,5 → **9,5** |
| 3 | Complexité | Radon 6.0.1 | B (5,90) · `base_agent` maintenabilité **C** | inchangé (refactor écarté) | **5,5** |
| 4 | Dépendances | pip-audit | 0 CVE directe · 1 CVE assumée non tracée | 0 CVE directe · **CVE assumée documentée** | 9,0 → **9,5** |
| 5 | Architecture | analyse | 10 livrables · 10 agents cohérents | inchangé | **8,0** |
| 6 | Tests | pytest + coverage | 146 tests · 57 % | **146 tests, tous verts après correctifs** | **7,0** |

### Score global : **73 → 75 / 100**

```
architecture 25 % · tests 20 % · complexité 20 % · qualité 15 % · sécurité 15 % · dépendances 5 %

avant : 8,0×2,5 + 7,0×2,0 + 5,5×2,0 + 7,0×1,5 + 8,5×1,5 + 9,0×0,5 = 72,75  →  73/100
après : 8,0×2,5 + 7,0×2,0 + 5,5×2,0 + 7,5×1,5 + 9,5×1,5 + 9,5×0,5 = 75,25  →  75/100
```

> **Le plafond est la dimension 3.** Les correctifs appliqués touchent la surface
> (style, schémas d'URL, documentation d'une CVE) ; ils ne pouvaient pas déplacer
> la complexité, qui pèse 20 % à elle seule. Passer 75 → 82 demanderait de
> découper `base_agent.py` — un refactor **délibérément écarté** avant la
> soutenance (voir *Améliorations post-stage*).

---

## Ce qui a été corrigé

| Correctif | Mesure avant | Mesure après |
|---|---|---|
| `ruff check --fix` | 260 signalements | **194** — 77 corrigés (imports non triés, imports morts, annotations obsolètes). 146 tests toujours verts. |
| **Helper `_open_http()`** dans `api/main.py` | 4 × `B310` (urlopen sans validation de schéma) | **0.** Les 4 appels passent par un point unique qui refuse tout schéma hors `http`/`https`. Vérifié : `file:///C:/Windows/win.ini` → `ValueError`. |
| **CVE `click` documentée** dans `requirements.txt` | Pin invisible, présent uniquement dans les instructions d'installation | Pin **explicite** avec CVE-2026-7246 nommée, la raison du compromis, l'impact réel (arguments CLI de l'opérateur, jamais une entrée distante) et la condition de levée. |

**Choix de conception sur le 2ᵉ correctif** : un helper unique plutôt que quatre
validations recopiées. Valider dans chaque appelant, c'est garantir qu'un
cinquième appel oubliera la vérification — c'est l'anti-pattern que ce projet
combat partout ailleurs (doc. technique : couche de jugement). `DVAP_API` venant de l'environnement, le risque
n'était pas théorique : une valeur `file://` y faisait lire un fichier local du
serveur.

**Le MEDIUM restant est un faux positif assumé** : Bandit signale `/tmp` en dur
dans `sandbox/docker_provider.py:64`, alors qu'il s'agit du drapeau
`--tmpfs /tmp:size=16m,exec` passé à `docker run` — le point de montage *dans le
conteneur*, c'est-à-dire la mesure de durcissement elle-même. Le supprimer
affaiblirait le sandbox.

---

## Dimension 1 — Qualité du code (Ruff) : 7,0 → **7,5**/10

**260 → 194 signalements** après `--fix` (77 corrigés, 146 tests toujours verts).

### Fichiers les plus chargés

| Fichier | Avant | Après |
|---|---|---|
| `api/main.py` | 35 | 37 \* |
| `agents/base_agent.py` | 27 | **24** |
| `reporting/interpretation.py` | 18 | 18 |
| `judge/llm_config.py` | 15 | **< 6** |
| `reporting/report_generator.py` | 12 | **10** |
| `judge/tracing.py` | 11 | **10** |

\* `api/main.py` monte de 2 : le helper `_open_http()` ajoute des lignes. Un
signalement de style contre une classe de vulnérabilité éliminée — bon échange.

### Classement par gravité RÉELLE (et non par nombre)

| Gravité | Règle | N | Verdict |
|---|---|---|---|
| 🟠 Réelle | `PLW1510` subprocess sans `check` | 11 | **À corriger** : un `docker`/`semgrep`/`garak` qui échoue passe inaperçu. Le projet a des garde-fous ailleurs (parsing du code retour), mais la règle pointe un vrai risque de faux négatif silencieux — le défaut que ce projet combat partout. |
| 🟠 Réelle | `S110`/`S112` `except: pass` / `continue` | 20 | **À examiner au cas par cas** : légitime dans un fail-safe, dangereux si l'erreur n'est pas comptée. |
| ✅ **Corrigé** | `I001` imports non triés, `F401` inutilisés, `UP*` | 51 → **0** | Éliminés par `ruff check --fix`. |
| 🟢 Faux positif assumé | `BLE001` blind-except | **83** (32 %) | **À ignorer** : c'est le principe fail-safe documenté (doc. technique : conventions de code de documentation technique) — aucune couche ne doit faire tomber l'audit. Le supprimer dégraderait le design. |
| 🟢 Faux positif | `RUF012` mutable-class-default | 15 | Attributs de configuration des agents, jamais mutés en place. |
| 🟢 Négligeable | `DTZ005` datetime sans fuseau | 16 | Horodatage de rapport local. |

> **Lecture** : sur les 194 restants, **83 (43 %) sont le principe fail-safe assumé**
> (`BLE001`) et 29 un motif de formatage de chaînes. Le vrai résidu actionnable tient
> en ~30 lignes : les 11 `subprocess` sans `check` et les 20 `except: pass`, à examiner
> un par un plutôt qu'en masse.

---

## Dimension 2 — Sécurité du code source (Bandit) : 8,5 → **9,5**/10

Analyse de `agents/ judge/ workflow/ api/ sandbox/` — **8 756 lignes**.

| Sévérité | Avant | Après |
|---|---|---|
| **HIGH** | **0** | **0** |
| MEDIUM | 5 | **1** |
| LOW | 213 (dont **171 `assert`** d'auto-tests — non applicable) | 213 |

### Les 5 MEDIUM, et leur traitement

| Lieu | Règle | Traitement |
|---|---|---|
| `api/main.py` × 4 | `B310` urlopen sans validation de schéma | ✅ **CORRIGÉ.** Les 4 appels passent par `_open_http()`, qui refuse tout schéma hors `http`/`https`. Le risque n'était pas théorique : `DVAP_API` vient de l'environnement, donc une valeur `file://` faisait lire un fichier local du serveur. Vérifié : `file:///C:/Windows/win.ini` → `ValueError`. |
| `sandbox/docker_provider.py:64` | `B108` chemin `/tmp` en dur | ⬜ **Conservé — faux positif.** C'est le drapeau `--tmpfs /tmp:size=16m,exec` de `docker run` : le point de montage **dans le conteneur**, c'est-à-dire la mesure de durcissement. Le « corriger » affaiblirait le sandbox. |

### Sur l'ironie « un framework de sécurité vulnérable »

**Elle ne s'applique pas.** Zéro HIGH avant comme après, et l'unique MEDIUM restant
est une mesure de sécurité que l'outil ne sait pas reconnaître.

Formulation défendable en soutenance :
> « Bandit a été passé sur le framework lui-même : 0 HIGH, et l'unique MEDIUM
> résiduel est le drapeau `--tmpfs` qui durcit notre propre sandbox. La seule vraie
> classe de vulnérabilité trouvée — 4 ouvertures d'URL sans validation de schéma — a
> été corrigée par un point de passage unique. »

---

## Dimension 3 — Complexité et maintenabilité (Radon) : 5,5/10

**C'est la dimension la plus faible du projet.**

Complexité cyclomatique moyenne : **B (5,90)** sur 318 blocs — bon. Mais la distribution est très déséquilibrée.

### Blocs de grade D ou pire

| Fonction | Grade | CC | Commentaire |
|---|---|---|---|
| `base_agent._run_behavioral_layer` | **F** | **48** | Orchestre 4 axes + pondération + dry-run. Le cœur du framework. |
| `base_agent._parse_deepteam` | **F** | **47** | Parsing + exclusions + 3 juges + statistiques. |
| `judge/tracing.demo` | F | 66 | Auto-test (19 contrôles) — sans impact. |
| `judge/replay.replay_attacks` | F | 41 | |
| `reporting.build_context` | E | 38 | Assemblage du rapport. |
| `_run_semgrep`, `_run_pyrit_multiturn`, `_verifier`, `build_judge_summary`, `_build_limits`, `_discover_endpoint`, 3 × `demo` | D | 21-26 | |

**Maintenabilité par fichier** : tout le projet est en **A**, sauf deux exceptions —
- `agents/base_agent.py` → **C (4,47)** ⚠️
- `api/main.py` → B (15,23)

### Ce code est-il maintenable par quelqu'un d'autre ? — Réponse honnête

**Oui pour 90 % du projet, non pour `base_agent.py`.**

- **En faveur** : chaque module a un docstring expliquant *pourquoi* et pas seulement *quoi* ; les décisions non évidentes sont commentées à l'endroit du code ; `documentation technique` tient le journal des raisonnements, y compris des erreurs. Un nouvel arrivant comprend les intentions — c'est rare et c'est un vrai atout.
- **Contre** : `base_agent.py` fait **687 lignes de logique** avec deux fonctions à CC 47-48. Modifier `_run_behavioral_layer` sans rien casser demande de tenir en tête 48 chemins d'exécution. La densité de commentaires compense la lisibilité, elle ne compense pas le risque de régression.

**Le paradoxe est assumé et documenté** : cette centralisation est ce qui rend les 10 agents minces (doc. technique : pipeline comportemental centralise). La dette est concentrée en un point plutôt que dupliquée dix fois — c'est le bon arbitrage, mais la dette existe.

---

## Dimension 4 — Vulnérabilités des dépendances (pip-audit) : 9,0 → **9,5**/10

> ⚠️ `pip-audit -r requirements.txt` **échoue sur Windows** : `semgrep` ne se construit pas (limitation amont connue). L'audit a porté sur **l'environnement installé** (406 paquets) — plus fidèle, puisqu'il voit les versions réellement en service.

| Périmètre | CVE |
|---|---|
| **18 dépendances directes du projet** | **0** ✅ |
| Environnement Python complet (406 paquets) | 79 CVE sur 20 paquets |

### Les CVE de l'environnement, classées

| Criticité pour le projet | Paquets | Décision |
|---|---|---|
| 🟢 **Hors périmètre** | `jupyterlab` (7), `jupyter-server` (2), `scikit-learn` (2), `nltk`, `datasets`, `mistune` (19), `pypdf` (15) | Aucun n'est importé par le framework. Ce sont des résidus de l'installation Python globale. **À isoler dans un venv, pas à corriger.** |
| 🟠 **Transitives réelles** | `aiohttp` 3.14.1 (3), `werkzeug` 3.0.6 (3), `tornado` 6.5.5 (4), `cryptography` 49.0.0, `h2`, `idna` (2) | Tirées par FastAPI/LangChain/LangFuse. Correctifs disponibles, montée de version mineure. **Acceptable à court terme, à traiter avant une mise en production.** |
| ✅ **Documenté** | `click` 8.1.8 → 8.3.3 | **Épinglé volontairement** (doc. technique : socle reutilisable) pour protéger deepeval/semgrep. La **CVE-2026-7246 est désormais nommée dans `requirements.txt`**, avec la raison du compromis, l'impact réel (click ne traite ici que des arguments CLI de l'opérateur, jamais une entrée distante) et la condition de levée. Une CVE assumée et écrite n'est plus une CVE oubliée. |

**1 seule CVE sans correctif disponible** sur les 79.

---

## Dimension 5 — Évaluation architecturale : 8,0/10

### a) Complétude vis-à-vis du sujet — **10/10 livrables présents et fonctionnels**

| # | Livrable | État |
|---|---|---|
| 1-3 | Étude OWASP, cartographie, base de connaissances | ✅ |
| 4 | Framework réutilisable | ✅ API + workflow + CLI |
| 5 | 10 agents spécialisés | ✅ chacun ≥ 1 run réel |
| 6 | Jeux de tests | ✅ 146 tests + runs DVAP |
| 7 | Scoring des risques | ✅ multi-couches renormalisé + intervalle de confiance |
| 8 | Rapports automatisés | ✅ HTML/PDF + dashboard React |
| 9 | Catalogue de recommandations | ✅ |
| 10 | Documentation + CI/CD | ✅ |

**Une seule réserve, mais elle compte** : le doc. technique : objectifs du framework promet un score `/100` bloquant à 70. Un audit global 10 catégories n'a **jamais été produit sur cible réelle en profil fiable** (bloqué par la clé Gemini, pas par le code). La promesse centrale est implémentée et testée, non démontrée.

### b) Cohérence de l'architecture — forte

| Agent | Lignes | Méthodes de couche surchargées |
|---|---|---|
| ASI01, 03, 06, 07, 08, 09, 10 | 120-226 | **0** — agents purement déclaratifs |
| ASI02 | 236 | 1 (couche statique Semgrep) |
| ASI04 | 251 | 2 (pip-audit + Semgrep) |
| ASI05 | 390 | 2 (statique + sandbox dynamique) |

**7 agents sur 10 sont de purs réglages d'attributs.** Les 3 exceptions correspondent exactement aux catégories qui ont des couches supplémentaires selon le référentiel — ce n'est pas une dérive, c'est la spécification.

### c) Réutilisabilité — vérifiée

`base_agent.py` ne contient **aucune logique conditionnée par une catégorie** : les 12 occurrences de `ASI_0x` sont toutes dans des commentaires ou des exemples de docstring. Ajouter un 11ᵉ agent = une sous-classe déclarative + une ligne au registre. **Aucune modification du socle.**

Pointer le framework vers un nouvel agent cible se fait entièrement par configuration (`target_url`, `prompt_field`, `response_field`, `extra_payload`, `tools_field`).

### d) Production-readiness chez Ooredoo — ce qui manque réellement

| Manque | Impact |
|---|---|
| **Clé LLM de production** | 🔴 Bloquant. Le profil `final` exige Gemini/Vertex ; la clé actuelle est expirée. Le profil `ollama` ne produit **pas** un verdict fiable (doc. technique : fiabilite du score / pipeline comportemental centralise). |
| **Isolation des dépendances** | 🟠 Aucun venv ni image figée : l'environnement porte 79 CVE hors projet. |
| **Authentification** | 🟠 Une seule clé API statique en variable d'environnement. Pas de rotation, pas de rôles. |
| **Persistance** | 🟠 Résultats en fichiers JSON sur disque. Pas de base, pas de rétention, pas de sauvegarde. |
| **Durée d'un audit** | 🟠 ~1 h pour 10 catégories en profil fiable. Acceptable en nocturne, pas en gate de PR synchrone. |
| **Semgrep sur Windows** | 🟡 Non installable ; la couche statique exige Linux/WSL/Docker. |

**Verdict** : déployable en **interne, sur un poste maîtrisé, par son auteur**. Pas encore un service que l'équipe sécurité opère sans lui.

### e) Points forts réels et mesurables

1. **Une doctrine anti-faux-score appliquée systématiquement, pas déclarée.** Cible injoignable → exclue ; axe absent → `None`, jamais 10/10 ; catégorie sans mesure → `measured=False` hors du score ; boucle agentique → réglages uniquement durcissables et score = minimum des passages. Chaque règle a son test de non-régression.
2. **Quatre défauts silencieux trouvés et corrigés par la mesure, pas par la relecture** : juge répondant `False` à tout (prompt en français), LangGraph dupliquant 35 vulnérabilités au lieu de 10, faux zéro polluant le score global, dérogation CI à date illisible traitée comme active. Aucun ne levait d'exception — tous produisaient un chiffre plausible.
3. **Aucun calcul dupliqué entre Python et TypeScript.** Score, agrégats de juges, intervalle de confiance et synthèse sont calculés une fois côté Python et **écrits dans le JSON** ; rapport et dashboard les lisent.
4. **Architecture multi-axes empiriquement justifiée** : DeepTeam seul donnait 10/10 sur une cible où PyRIT et Garak ont détecté le détournement (doc. technique : fiabilite du score). Le score est passé de « faux 9,4 » à 6,0 → CI/CD bloque.
5. **146 tests sans réseau ni LLM**, exécutables en CI sur une machine nue.
6. **Un journal de décisions techniques de 39 sections**, incluant les hypothèses invalidées. Rare à ce niveau.

### f) Points faibles réels

| Faiblesse | Impact |
|---|---|
| `base_agent.py` : 2 fonctions à CC 47-48, maintenabilité C | 🔴 **Élevé** — c'est le fichier que tout modifie |
| Aucun audit global sur cible réelle en profil fiable | 🔴 **Élevé** — la promesse du doc. technique : objectifs du framework reste non démontrée |
| Runners et scripts non testés (0 % de couverture) | 🟠 Moyen — ce sont les points d'entrée réels |
| `api/main.py` : 558 lignes, 38 % couverts, 35 signalements Ruff | 🟠 Moyen |
| Injection indirecte testée en simulation, pas via un vrai canal de données | 🟡 Faible — limite assumée et documentée (doc. technique : limites assumees) |
| `judge/replay.py` et `garak_runner.py` : 0 % de couverture | 🟡 Faible |

---

## Dimension 6 — Positionnement industriel

| Référence | Situation du projet |
|---|---|
| **Stage de fin d'études standard** | **Nettement au-dessus.** Un stage typique livre un prototype qui fonctionne sur une démo. Ici : 10 agents, orchestration parallèle avec reprise sur checkpoint, observabilité distribuée, CI/CD, dashboard, 146 tests. Le volume seul (17 k lignes) est celui d'un projet d'équipe. |
| **Développeur junior en entreprise (1ʳᵉ année)** | **Au niveau, voire au-dessus sur la rigueur.** La discipline de test et la traçabilité des décisions dépassent ce qu'on attend d'un junior. En dessous sur l'ingénierie logicielle pure : deux fonctions à CC 48 ne passeraient pas une revue de code stricte. |
| **Outil de production réel** | **Environ 70 % du chemin.** Le cœur fonctionnel y est. Manquent : l'isolation des dépendances, l'authentification robuste, la persistance, et surtout **la preuve de fiabilité** — un audit global validé et une étude précision/rappel. Un outil de sécurité qu'on n'a pas mesuré ne se déploie pas. |

**Formulation défendable en soutenance** :
> « Un prototype de recherche abouti, à un pas de l'outil interne. Ce qui le sépare de la production n'est pas du code manquant, c'est de la validation empirique manquante. »

---

## Actions prioritaires avant soutenance

| # | Action | Impact | Effort |
|---|---|---|---|
| **1** | **Obtenir une clé LLM fonctionnelle et lancer UN audit global 10 catégories sur cible réelle.** Une clé AI Studio gratuite (`AIza…`) suffit — le code détecte le préfixe et bascule seul. | 🔴 **Maximal.** C'est la promesse centrale du doc. technique : objectifs du framework. Sans ce run, le score `/100` et le blocage CI/CD restent théoriques, et le jury le verra. | 1 h + ~1 h de run |
| **2** | **Préparer la réponse sur `base_agent.py`.** La question « pourquoi une fonction à complexité 48 ? » viendra. La réponse existe déjà (doc. technique : pipeline comportemental centralise : dette concentrée en un point plutôt que dupliquée dix fois) — il faut l'avoir formulée, pas l'improviser. | 🟠 Élevé | 20 min |
| ~~3~~ | ~~`ruff check --fix`~~ | ✅ **FAIT** — 260 → 194 signalements | — |
| ~~4~~ | ~~Valider le schéma des 4 `urlopen`~~ | ✅ **FAIT** — Bandit MEDIUM 5 → 1 | — |
| ~~5~~ | ~~Documenter la CVE `click` assumée~~ | ✅ **FAIT** — nommée dans `requirements.txt` | — |

**Il ne reste que les actions 1 et 2**, et seule la 1 pèse vraiment : les trois
correctifs techniques sont appliqués, mesurés et vérifiés (146 tests verts).

---

## Améliorations post-stage

| Sujet | Bénéfice |
|---|---|
| **Étude de validation DVAP** (précision/rappel sur les 15 labs) | Transforme « j'ai construit un outil » en « je l'ai mesuré ». Le plus fort différenciateur restant. |
| **Découper `_run_behavioral_layer` et `_parse_deepteam`** | Fait passer la maintenabilité de C à A sur le fichier central. Doit être fait **avec** la suite de tests, jamais sans. |
| **Tests des runners** (`run_agent.py`, `run_audit_global.py`, actuellement à 0 %) | Ce sont les points d'entrée réels du framework. |
| **Isolation en venv + image Docker figée** | Élimine 79 CVE d'un coup et rend l'installation reproductible. |
| **Hook d'injection indirecte réelle** (`config["rag_inject"]`) | Lève la limite assumée du doc. technique : limites assumees : tester le canal de données, pas seulement le prompt. |
| **Persistance en base + rétention** | Prérequis à un usage multi-utilisateur. |
| **Réduire la durée d'un audit** (parallélisme plus fin, cache des attaques) | Rend possible un gate de PR synchrone. |

---

*Rapport produit à partir de : Ruff 0.16.5, Bandit 1.9.4, Radon 6.0.1, pip-audit 2.9.0, pytest 8 + coverage. Aucune appréciation n'est donnée sans le chiffre qui la fonde.*
