# MASTER PROMPT — Refonte de la présentation (React JS)

---

## 0. CONTEXTE — LIS CECI EN ENTIER AVANT DE CODER

Tu travailles sur le **deck de présentation** d'un projet de fin d'études (PFE, 6 semaines,
**Ooredoo Tunisie — Département Intelligence Artificielle**).

**Le projet présenté :** un *framework automatisé d'audit de sécurité pour applications IA
agentiques*, construit sur le référentiel **OWASP Top 10 for Agentic Applications 2026
(ASI01 → ASI10)**.

**Ce que fait le framework :**
```
Agent IA cible (URL HTTP)
        ↓
API FastAPI → POST /audit
        ↓
Workflow LangGraph orchestre 10 agents de sécurité spécialisés (2 vagues parallèles)
        ↓
Chaque agent exécute 1 à 3 couches de test (comportementale / statique / dynamique)
        ↓
Scoring pondéré multi-couches → score global /100
        ↓
Rapport HTML/PDF automatisé + recommandations générées par LLM
        ↓
CI/CD : si score < 70 → le déploiement est BLOQUÉ
```

**IMPORTANT — nature de cette présentation :**
Ce deck est une **revue d'avancement destinée à l'encadrant** (pas la soutenance finale).
Objectif : faire **valider une approche, une architecture et un plan de travail**.
Ce n'est PAS une présentation de résultats chiffrés.
→ Aucune slide ne doit afficher de métriques expérimentales (précision, rappel, scores
d'audit clients). Là où il y avait des chiffres, on présente le **protocole** de mesure.

**Auteur :** Asser Belhassen — Département IA, Ooredoo Tunisie.

---

## 1. CONTRAINTES TECHNIQUES — NON NÉGOCIABLES

- **React JS** (le projet a une version React source ET un build HTML — tu travailles
  **UNIQUEMENT sur les sources React**, le HTML est un artefact de build, ne le modifie pas
  à la main).
- Stack existante à conserver : **React 19 + Framer Motion (`motion/react`) + lucide-react**.
- Architecture actuelle : un tableau de composants-slides, navigation clavier
  (`←` `→` `Espace`, `Home`, `o` = overview), barre de progression, footer, logo Ooredoo
  en overlay.
- Conserver le design system existant :
  ```css
  --red: #ed1c24;  --red-600: #c4161c;  --ink: #0b0b0c;
  --paper: #fff;   --paper-2: #f6f6f7;  --line: #e6e6e8;  --muted: #6b6b70;
  --dark: #0e0e12;
  --font-heading: "Space Grotesk";  --font-body: "Inter";
  ```
- **Un composant = un fichier** dans `src/slides/`. Index central des slides.
- Logo Ooredoo : conserver le mécanisme existant (base64 injecté).

---

## 2. BUGS À CORRIGER EN PRIORITÉ ABSOLUE

### 2.1 Encodage cassé (BLOQUANT)
Tout le deck est en **double-encodage UTF-8**. Exemples réels dans le code actuel :
- Titre slide 1 : `𝐀𝐈 𝐒𝐞𝐜𝐮𝐫𝐢𝐭𝐲…` → illisible
- `RÃ´le`, `spÃ©cialisÃ©s`, `ExÃ©cution`, `Ã‰tude`, `ComplÃ¨te`
- Emojis : `ðŸ—£ï¸`, `âœ…`

→ Réécris **tous** les textes en UTF-8 propre. Fichiers sauvegardés en UTF-8 sans BOM.

### 2.2 Faux gras Unicode
Le titre utilise des caractères Unicode « mathematical bold » (𝐀𝐈 𝐒𝐞𝐜…).
→ Texte normal + `font-weight: 700` en CSS.

### 2.3 Langue incohérente
Le deck alterne français et anglais **aléatoirement** (titres EN, cartes de détail FR,
slide 5 titre FR + corps EN).
→ **TOUT en FRANÇAIS**, avec les termes techniques en anglais quand c'est l'usage
(*prompt injection*, *sandbox*, *red teaming*, *Quality Gate*, *LLM-as-Judge*).

### 2.4 Noms de classes faux
Le deck actuel affiche des agents qui **n'existent pas** : `SQLIAgent`, `XSSAgent`,
`SSRFExploitAgent`, `DoSAgent`, `InsecurePluginAgent`, `RCEAgent`.
Ce sont des catégories OWASP LLM/Web, **pas** ASI.

→ Les **vrais noms** (à utiliser partout) :
| Catégorie | Classe réelle | Nom |
|---|---|---|
| ASI01 | `ASI01GoalHijackingAgent` | Goal Hijacking |
| ASI02 | `ASI02ToolMisuseAgent` | Tool Misuse |
| ASI03 | `ASI03IdentityAbuseAgent` | Identity & Privilege Abuse |
| ASI04 | `ASI04SupplyChainAgent` | Agentic Supply Chain |
| ASI05 | `ASI05CodeExecutionAgent` | Unexpected Code Execution |
| ASI06 | `ASI06MemoryPoisoningAgent` | Memory & Context Poisoning |
| ASI07 | `ASI07InterAgentCommsAgent` | Inter-Agent Communication |
| ASI08 | `ASI08CascadingFailuresAgent` | Cascading Failures |
| ASI09 | `ASI09TrustExploitationAgent` | Trust Exploitation |
| ASI10 | `ASI10RogueAgentsAgent` | Rogue Agents |

### 2.5 Animations en boucle infinie
Les slides « Couche statique », « Sandbox », « CI/CD », « API » utilisent
`setInterval(..., % 4)` : le contenu **tourne en boucle** pendant que l'orateur parle.
→ Remplacer par une **avance au clic / barre espace** (state `step`, incrémenté par
interaction), ou une lecture unique qui s'arrête sur l'état final.

### 2.6 Lisibilité vidéoprojecteur
Beaucoup de texte à 10-13 px.
→ Plancher : **18 px** pour le corps, **14 px** pour le code, **28 px+** pour les titres de
section, **40-48 px** pour les titres de slide.

### 2.7 Couleurs des 3 couches incohérentes
Les variables CSS `--layer-behavioral / --layer-static / --layer-dynamic` sont définies mais
**jamais utilisées** ; chaque slide recode ses propres couleurs.
→ **Un triplet unique, utilisé partout** :
```css
--layer-behavioral: #3b82f6;  /* bleu   */
--layer-static:     #f59e0b;  /* ambre  */
--layer-dynamic:    #ef4444;  /* rouge  */
```
Le rouge Ooredoo `--red` reste réservé à la **marque** (logo, accents, titres).

### 2.8 Polices non chargées
Les `@font-face` pointent vers `/assets/*.woff2` inexistants → fallback système silencieux.
→ Installe `@fontsource/space-grotesk` et `@fontsource/inter` (ou inline en base64).

---

## 3. TOUTES LES TECHNIQUES UTILISÉES — N'EN OUBLIE AUCUNE

Ce tableau est la **source de vérité**. Chaque outil ci-dessous doit apparaître au moins une
fois dans le deck, avec son rôle exact.

### 3.1 Orchestration & socle
| Outil | Rôle exact |
|---|---|
| **LangGraph** | `StateGraph` — orchestre les 10 agents en 2 vagues parallèles (ASI01-05, puis ASI06-10), état partagé `AuditState` |
| **LangChain / langchain-core** | Connecteurs LLM et outils |
| **`BaseSecurityAgent`** | Classe abstraite portant le pipeline complet — les 10 agents ne règlent que des attributs de classe |
| **`AuditState`** | Dataclass d'état partagé : `target_url`, `results`, `scores`, `global_score`, `vulnerabilities`, `status` |
| **`AgentResult` / `LayerResult`** | Dataclasses de résultat (score, findings, raw) |

### 3.2 Couche 1 — COMPORTEMENTALE (4 axes d'attaque)
| Outil | Rôle exact | Poids |
|---|---|---|
| **DeepTeam** | Moteur principal. Framework `OWASP_ASI_2026(categories=[...])` natif. Génère les attaques via un `simulator_model` et juge via un `evaluation_model` | **0.5** |
| **PyRIT** (Microsoft) | Attaques **multi-tours adaptatives** (`RedTeamingAttack`, API 1.0). Attaque seulement — **ne score pas** → scoré par DeepEval | **0.2** |
| **Garak** | Probes de jailbreak automatiques (`dan.DAN_Jailbreak`, `promptinject`, `latentinjection`). Exécuté en **sous-processus** vers un venv isolé. Indépendant du LLM | **0.2** |
| **Payloads Microsoft (Arcanum-Sec)** | **28 payloads d'attaque réels** validés en production, couvrant ASI01→ASI10. Chargés dynamiquement **par parsing AST** (le module n'est pas importable). Envoyés à la cible puis jugés par LLM | **0.1** |

Attaques DeepTeam utilisées selon la catégorie : `PromptInjection`, `Roleplay`,
`PromptProbing`, `Base64`, `ROT13`, `LinearJailbreaking`, `CrescendoJailbreaking`,
`TreeJailbreaking`, `ContextPoisoning`.

### 3.3 Couche 2 — STATIQUE
| Outil | Rôle exact |
|---|---|
| **Semgrep** | SAST sur le code source (`p/default` + `p/security-audit`). Runner centralisé `_run_semgrep()` |
| **pip-audit** | Scan des dépendances Python → CVE connues (pénalité 2.0 par CVE) |
| **Microsoft `security_skills.py`** | **11 fonctions de scan statique** codées par Microsoft : `check_unsafe_pickle`, `check_hardcoded_secrets`, `check_ssrf_urls`, `check_error_info_leak`, `check_stub_security`, `check_trust_without_crypto`, `check_missing_circuit_breaker`, `check_hardcoded_denylist`, `check_unbounded_collections`, `check_redos_patterns`, `check_unsafe_netloc_parsing` — **complètent** Semgrep |

### 3.4 Couche 3 — DYNAMIQUE (sandbox)
| Élément | Détail |
|---|---|
| **`DockerSandboxProvider`** | Conteneur éphémère `python:3.11-slim` lancé via `docker run` |
| **Durcissement** | `--network none` · `--memory 128m` · `--cpus 0.5` · `--read-only` + `--tmpfs /tmp` · `--user 1000:1000` · `--cap-drop ALL` · `--security-opt no-new-privileges` · `--pids-limit` · timeout 5 s (SIGKILL) |
| **`SubprocessSandboxProvider`** | Fallback si Docker indisponible (base Microsoft AGT) |
| **`_extract_generated_code()`** | Extrait les blocs ```python``` de la réponse de l'agent cible |
| **5 preuves validées** | (1) le code s'exécute · (2) `--network none` bloque l'exfiltration (échec de résolution DNS) · (3) boucle infinie → tuée par timeout · (4) écriture `/etc` → « Read-only file system » · (5) `uid=1000` non-root |

### 3.5 LLM-AS-JUDGE — 4 NIVEAUX (⚠️ SLIDE DÉDIÉE OBLIGATOIRE)
C'est un point différenciant majeur du projet. Il doit avoir **sa propre slide**.

| Niveau | Composant | Ce qu'il juge |
|---|---|---|
| **1** | `evaluation_model` **intégré à DeepTeam** | L'attaque a-t-elle réussi ? (verdict binaire natif) |
| **2** | **`judge/severity_judge.py`** | **Gravité contextuelle** — pas juste pass/fail, mais Critical / High / Medium / Low, via sortie structurée Pydantic. Fallback sur une table statique si le juge échoue |
| **3** | **`judge/cross_validation.py`** | **Double jugement** des cas ambigus (confidence < 80 %) — un second LLM re-juge |
| **4** | **`judge/recommendation_engine.py`** | **Génère des recommandations intelligentes** par LLM, au-delà des guidelines statiques de la base de connaissances |

**+ DeepEval comme juge externe :**
PyRIT attaque mais ne score pas → **DeepEval** évalue les conversations PyRIT avec la
métrique adaptée à la catégorie : `AnswerRelevancyMetric` (ASI01 — l'agent a-t-il maintenu
son objectif ?), `ContextualRelevancyMetric` (ASI06 — a-t-il dévié après empoisonnement ?),
`BiasMetric` + `ToxicityMetric` (ASI09 — manipule-t-il l'utilisateur ?).
Score float 0-1 → ×10 pour normalisation.

**+ Jugement des payloads Microsoft :** chaque payload envoyé à la cible, puis le juge LLM
détermine s'il a été REFUSÉ (attendu) ou ACCEPTÉ (→ vulnérabilité).

### 3.6 Stratégie LLM — profils
| Profil | Simulator | Evaluation | Usage |
|---|---|---|---|
| `dev` | Ollama `qwen2.5:7b` | Ollama `qwen2.5:7b` | Développement quotidien — 100 % local, gratuit, illimité |
| `final` | **Gemini Flash** | **Gemini Flash** | Verdict officiel / démo — attaquant ET juge de qualité |
| `ci` / `dry_run` | `DryRunModel` | `DryRunModel` | Pipeline CI sans consommer de tokens |

Ingénierie associée : `get_judge_models(profile)` renvoie des **instances** (obligatoire pour
mélanger deux providers) · `RateLimitedGeminiModel` + `_RateLimiter` à fenêtre glissante
(free-tier = **15 req/min ET 500 req/jour**) · `FallbackModel` (bascule automatique
Gemini → Ollama sur erreur 429).

### 3.7 Restitution
| Outil | Rôle |
|---|---|
| **Jinja2** | Templating du rapport HTML |
| **WeasyPrint** | Export PDF |
| **Chart.js** | Radar chart des 10 catégories ASI + bar charts |
| **`reporting/comparison.py`** | Mode comparatif avant/après remédiation |

### 3.8 Industrialisation
| Outil | Rôle |
|---|---|
| **FastAPI + Uvicorn** | API REST asynchrone. 4 endpoints : `POST /audit` · `GET /audit/{id}` (progression 0-100 %) · `GET /audit/{id}/report?format=html\|pdf` · `GET /health`. Auth par header `X-API-Key` |
| **Docker + Docker Compose** | Conteneurisation + sandbox + service LangFuse |
| **GitHub Actions** | `.github/workflows/security_audit.yml` — audit avant chaque déploiement, **exit 1 si score < 70** |
| **Promptfoo** | Tests CI/CD automatisés (configs YAML) |
| **LangFuse** | Monitoring et traçage de tous les appels LLM (attaques + jugements) |
| **OpenTelemetry** | Standard de traçage distribué |

### 3.9 Environnement de test
| Outil | Rôle |
|---|---|
| **DVAP** (*Damn Vulnerable AI Platform*) | 15 agents IA vulnérables prêts à l'emploi, dockerisés. Lancé via `docker compose up`, UI sur `:8080`, instances sur ports dynamiques. Lab de référence : `prompt-injection` (agent « ARIA », modèle `llama3.2:3b`) |
| **OWASP Agent Security Regression Harness** | Scénarios d'attaque standardisés en YAML |

### 3.10 Décisions d'ingénierie à mettre en avant
- **Anti-faux-10/10** : les tests dont la réponse contient `[HTTP_ERROR]` (timeout, panne
  réseau, HTTP ≥ 400) sont **exclus du scoring** ; si **0 test scorable**, la couche renvoie
  `None` et est marquée en erreur — **jamais 10/10**.
- **Scoring multi-couches** : `behavioral × 0.5 + static × 0.3 + dynamic × 0.2`, avec
  **renormalisation automatique** des poids si une couche n'est pas applicable.
- **Scoring intra-comportemental** : DeepTeam 0.5 / PyRIT 0.2 / Garak 0.2 / Microsoft 0.1.
- **Fail-safe** : si un agent plante, son erreur est capturée, son score = 0, les 9 autres
  continuent. Retry ×2 avec backoff exponentiel.
- **Exécution asynchrone** : `async_mode=True` + `max_concurrent` → **1.85× plus rapide**
  (mesuré : 109,7 s vs 202,5 s).
- **Limites assumées** : (a) l'injection indirecte est testée **en simulation** (charge dans
  le texte du prompt), pas via empoisonnement réel d'un canal de données ; (b) contre une
  cible **boîte noire** qui n'expose pas ses appels d'outils, `tools_called` est vide → le
  jugement se fait sur le texte seul (le framework le **signale** dans le rapport).

---

## 4. STRUCTURE CIBLE — 19 SLIDES + 5 ANNEXES

### ▸ PARTIE 1 — CADRAGE

**Slide 1 — Titre**
Logo Ooredoo. Titre : « Framework d'audit de sécurité pour applications IA agentiques ».
Sous-titre : « Revue d'avancement — plan de travail & architecture ».
Mention : « OWASP Top 10 for Agentic Applications 2026 ».
Auteur : Asser Belhassen — Département IA, Ooredoo Tunisie.
*Design : animation d'entrée mot par mot, fond en grille de points animée, barre rouge qui
se déploie.*

**Slide 2 — Agenda** 🆕
5 blocs numérotés, apparition en cascade :
1. Le problème · 2. L'approche · 3. L'architecture · 4. La validation · 5. Le planning.
*Design : cartes avec icône, hover en élévation.*

**Slide 3 — Contexte & problème**
Les applications IA agentiques (agents autonomes, outils, mémoire, multi-agents) forment une
surface d'attaque **non auditée**. L'OWASP a publié le référentiel ASI 2026 — mais **aucun
outil automatisé n'existe** pour auditer contre lui.
*Design : 4 cartes de menaces + badge de conclusion.*

**Slide 4 — Les 10 risques OWASP ASI 2026** ⬆️ *(remontée depuis la position 12)*
Le schéma officiel : Inputs → Integration/Processing → Outputs, avec les badges ASI01→ASI10
positionnés sur les surfaces d'attaque correspondantes.
*Design : boîtes reliées par des connecteurs pointillés animés (marching ants), badges qui
apparaissent en cascade.*

**Slide 5 — État de l'art : pourquoi les outils existants ne suffisent pas** 🆕 ⭐
**Slide la plus importante du deck — elle justifie tout le projet.**

| Outil | Ce qu'il teste | Ce qu'il ne couvre **pas** |
|---|---|---|
| DeepTeam | Comportement du LLM | Aucun runtime, aucun code |
| Garak | Probes de jailbreak | Pas d'outils/agents, pas de scoring ASI |
| PyRIT | Attaques multi-tours | **Attaque seulement — ne score pas** |
| Promptfoo | Tests CI en YAML | Pas d'attaques adaptatives |
| Semgrep / pip-audit | Code & CVE | Rien de comportemental |

Citation à afficher (encadré, en évidence) — documentation DeepTeam :
> *« does not claim full coverage of runtime enforcement, infrastructure security »*

**Conclusion :** aucun outil ne couvre ASI01→ASI10. **La valeur ajoutée du projet =
orchestrer ces 4 moteurs + ajouter les couches statique et dynamique + scorer selon OWASP
ASI.**
*Design : tableau avec colonne « ne couvre pas » en rouge, puis révélation de la conclusion.*

### ▸ PARTIE 2 — APPROCHE

**Slide 6 — La promesse : une URL → un verdict**
Pipeline horizontal en 5 nœuds : `URL in` → `Audit (10 risques)` → `Score /100` →
`Rapport` → `CI/CD Gate` (badge « BLOCK < 70 »).
*Design : nœuds reliés par un flux animé, apparition séquentielle en spring.*

**Slide 7 — Décision centrale : l'architecture à 3 couches** ⭐
Le **pourquoi**, pas le quoi. DeepTeam ne teste que le comportement → on ajoute 2 couches.
Garder l'**empilement 3D** actuel (meilleur visuel du deck) : 3 plans qui se séparent en
perspective (`rotateX(60deg) rotateZ(-45deg)`, translation en Z).
Ajouter :
- la formule : `score = (behavioral × 0.5) + (static × 0.3) + (dynamic × 0.2)`,
  **renormalisée** si une couche n'est pas applicable ;
- le tableau de répartition ASI01→ASI10 × couches (ASI05 = les 3 couches ; ASI04 = 2 ;
  les autres = comportementale).

### ▸ PARTIE 3 — ARCHITECTURE

**Slide 8 — Architecture globale**
Garder le **schéma interactif existant** (nœuds cliquables qui zooment en `layoutId`) :
`Target AI Agent` → `FastAPI` → `LangGraph Workflow` → `Test Layers` → `Weighted Scoring` →
`PDF Report` → `CI/CD Gate`.
⚠️ Corriger le contenu des cartes de détail (elles citent `SQLI, RCE, GoalHijack` → mettre
les vrais noms ASI). Ajouter **LangFuse** comme nœud d'observabilité transverse.

**Slide 9 — Orchestration LangGraph** ⬆️ *(remontée depuis la position 13)*
`BaseAgent` (routeur) → **2 vagues parallèles** :
- Vague 1 : ASI01, ASI02, ASI03, ASI04, ASI05
- Vague 2 : ASI06, ASI07, ASI08, ASI09, ASI10
- puis consolidation → score global → rapport.
Montrer l'état partagé `AuditState` et le **fail-safe** (un agent qui plante n'arrête pas
les autres).
⚠️ **Utiliser les vrais noms de classes** (voir §2.4).

**Slide 10 — Le socle : `BaseSecurityAgent`**
Classe abstraite (ABC) portant le pipeline complet. Un agent concret ne règle que des
**attributs de classe** : `deepteam_category`, `behavioral_severity_map`, `use_pyrit`,
`pyrit_objective`, `use_garak`, `garak_default_probes`, `use_microsoft_probes`,
`recommendation_map`, `deepteam_weight` / `pyrit_weight` / `garak_weight` /
`microsoft_weight`, `fail_threshold`.
3 méthodes surchargeables : `_run_behavioral_layer()` · `_run_static_layer()` ·
`_run_dynamic_layer()`.
Dataclasses : `AgentResult` (category, score 0-10, vulnerabilities, attacks_total,
attacks_success, recommendations) et `LayerResult` (score, findings, raw, execution_time_ms).
*Design : garder l'onglet interactif à 3 méthodes + panneau de code sombre. Utiliser du
**vrai code**, pas des signatures inventées.*

**Slide 11 — Couche comportementale : 4 axes d'attaque**
DeepTeam (0.5) · PyRIT (0.2) · Garak (0.2) · Payloads Microsoft (0.1).
Schéma : les 4 moteurs à gauche → flux d'attaque animé → agent cible à droite → réponse.
Mentionner l'**anti-faux-10/10** (`[HTTP_ERROR]` exclu, `None` si 0 scorable).

**Slide 12 — Couche statique**
Semgrep (AST) + pip-audit (CVE) + les **11 fonctions Microsoft `security_skills`**.
*Design : garder le bloc de code sombre avec le **scanner laser** qui balaie verticalement,
puis surlignage rouge des lignes dangereuses (`os.system`, exfiltration) et tampon
« BLOCKED ». **Passer l'animation en avance-au-clic**, pas en boucle.*

**Slide 13 — Couche dynamique : sandbox Docker**
Le code généré par l'agent cible est **réellement exécuté** dans un conteneur éphémère.
Afficher le durcissement complet (§3.4) et les **5 preuves validées**.
*Design : garder le terminal noir à gauche + le panneau « ISOLATED DOCKER ENVIRONMENT » à
droite avec les verrous qui s'activent. **Avance au clic**.*

**Slide 14 — LLM-as-Judge : 4 niveaux de jugement** 🆕 ⭐⭐
**SLIDE OBLIGATOIRE — fort impact, ne pas la simplifier.**
Visuel en **pyramide 3D ou en couches empilées**, chaque niveau se révélant successivement :

1. **Verdict natif DeepTeam** (`evaluation_model`) — l'attaque a-t-elle réussi ?
2. **`severity_judge.py`** — gravité **contextuelle** (Critical/High/Medium/Low) via sortie
   structurée Pydantic, avec fallback statique
3. **`cross_validation.py`** — **double jugement** des cas ambigus (confidence < 80 %)
4. **`recommendation_engine.py`** — recommandations **générées par LLM**

Encadré latéral : **DeepEval comme juge externe** — PyRIT attaque mais ne score pas, donc
DeepEval évalue ses conversations (`AnswerRelevancyMetric` / `ContextualRelevancyMetric` /
`BiasMetric` + `ToxicityMetric` selon la catégorie).
Bandeau bas : les profils LLM `dev` (Ollama) / `final` (Gemini Flash) / `ci` (DryRun).
*Design : pyramide en perspective 3D, chaque étage entre en `translateZ` + `spring`,
couleur dégradée du bleu (niveau 1) au violet (niveau 4). Effet de lueur sur le niveau actif.*

### ▸ PARTIE 4 — RESTITUTION & INDUSTRIALISATION

**Slide 15 — Du score au rapport**
Fusion des anciennes slides « CI/CD & Scoring » et « Executive Report ».
- Gauche : **jauge semi-circulaire animée** (conserver le design existant : aiguille qui
  balaie, dégradé rouge→ambre→vert, chiffre qui s'incrémente).
- Droite : **maquette du rapport PDF** — radar chart des 10 ASI, score /100, liste des
  vulnérabilités avec gravité, **résumé exécutif généré par LLM**, recommandations.
- Bas : Jinja2 → WeasyPrint → PDF · Chart.js pour les graphiques · mode comparatif
  avant/après.

**Slide 16 — Industrialisation : API + Quality Gate CI/CD**
- Gauche : les **4 endpoints FastAPI** + auth `X-API-Key`.
- Droite : le pipeline **GitHub Actions** — `push/PR` → audit → Quality Gate →
  `exit 1 si score < 70` → déploiement bloqué. Mentionner **Promptfoo** (tests YAML) et
  **Docker Compose** (API + LangFuse).
*Design : chaîne d'étapes avec états qui s'allument, terminal de logs CI en bas. **Avance au
clic**.*

### ▸ PARTIE 5 — MÉTHODE & SUITE

**Slide 17 — Démo : audit réel en conditions** ⭐⭐⭐ *(voir §5 — REFONTE COMPLÈTE)*

**Slide 18 — Banc d'essai DVAP + protocole de validation** 🔀 🆕
*(remplace les anciennes slides « A/B testing » et « Scientific Rigor » — plus aucune
métrique inventée)*
- **Environnement** : DVAP (15 labs IA vulnérables, dockerisés) + OWASP Agent Security
  Regression Harness (scénarios YAML).
- **Protocole prévu** : auditer N labs vulnérables **+ 1 agent sain en contrôle** (le
  contrôle est ce qui donne la crédibilité à la mesure des faux positifs).
- **Métriques cibles** : précision (taux de faux positifs) · rappel (failles manquées) ·
  variance du score sur N runs.
- **Profils** : `dev` (Ollama — itération rapide, gratuit) pour construire le pipeline ;
  `final` (Gemini Flash) pour produire le verdict fiable.
- **Critère de succès : à définir ensemble.** ← formulation volontaire, on tend le micro à
  l'encadrant.
*Design : grille des labs DVAP à gauche (cartes cliquables), protocole en étapes numérotées
à droite.*

**Slide 19 — Planning 6 semaines & avancement** 🔄
Diagramme de Gantt horizontal, 6 semaines, avec les phases :
Phase 1 (étude OWASP + base de connaissances) · Phase 2 (sandbox + socle + POC ASI05) ·
Phase 3 (les 10 agents) · Phase 4 (workflow + scoring + judge + reporting) ·
Phase 5 (API + CI/CD + validation DVAP) · Phase 6 (documentation + soutenance).
Curseur « aujourd'hui » animé. Jalons marqués.
*Design : barres qui se remplissent de gauche à droite au `mount`, couleur par phase.*

**Slide 20 — Points ouverts : décisions à valider avec vous** 🆕 ⭐
*(La slide qui transforme la présentation en réunion de travail.)*
6 questions, chacune sur une carte :
1. **Périmètre injection indirecte** — simulation in-prompt acceptée, ou hook RAG réel exigé ?
2. **Cible boîte noire** — exiger que l'agent audité expose ses `tool_calls` ? Sinon
   BOLA/RBAC se jugent sur le texte seul.
3. **Pondération des couches** — 0.5 / 0.3 / 0.2 : validé ?
4. **Seuil de blocage CI/CD** — 70/100 est-il le bon niveau pour Ooredoo ?
5. **Budget LLM** — clé Gemini facturée, ou rester en free-tier (15/min, 500/jour) ?
6. **Validation** — combien de labs DVAP, quel agent de contrôle ?
*Design : cartes numérotées avec point d'interrogation, hover en élévation, accent rouge.*

**Slide 21 — Merci / Questions**
Logo, phrase de synthèse : « Un auditeur OWASP automatisé, multi-couches et multi-agents pour
l'IA agentique — de l'URL au blocage CI/CD. », auteur.

### ▸ ANNEXES (accessibles depuis l'overview `o`, hors comptage principal)

- **A1 — Patterns agentiques** : ReAct, CodeAct, Modern Tool Use, Self-Reflection,
  Multi-Agent Workflow, Agentic RAG — et la technique d'audit associée à chacun.
  *(récupérer la slide interactive existante)*
- **A2 — Anatomie d'une attaque multi-tours** : conversation attaquant/cible animée,
  encodage ROT13 → contournement du filtre → exécution.
  *(récupérer la slide existante)*
- **A3 — Observabilité LangFuse** : arbre de traces (Audit Graph → Attacker → Generation →
  Target Response → Evaluation → Score), métadonnées (tokens, latence, modèle),
  OpenTelemetry. *(récupérer la slide existante)*
- **A4 — Formule de scoring détaillée** 🆕 : pondération inter-couches et intra-comportementale,
  renormalisation, table de gravité (priorité `type précis > classe > défaut`), anti-faux-10/10.
- **A5 — Profils LLM & contraintes** 🆕 : `dev`/`final`/`ci`, `RateLimitedGeminiModel`,
  quotas free-tier (15/min + 500/jour), `FallbackModel` Gemini→Ollama, exécution async
  1.85× plus rapide.

---

## 5. SLIDE 17 — « DÉMO : AUDIT RÉEL » — REFONTE COMPLÈTE ⭐⭐⭐

**Le design actuel de cette slide est excellent : garde-le intégralement.**
Terminal noir, 3 pastilles macOS (rouge/ambre/vert), en-tête
`bash — auditor@ooredoo-sec`, lignes typées séquentiellement, code couleur par niveau
(`cmd` vert · `info` gris · `warn` ambre · `debug` gris italique · `critical` rouge gras),
curseur clignotant, flash rouge de l'écran sur événement critique.

**Le problème : les logs sont écrits en dur avec des `setTimeout` codés à la main.**
C'est une simulation, pas un test.

### Ce qu'il faut faire

Transformer cette slide en **rejeu d'un vrai run d'audit**.

1. **Créer un fichier de données** `src/data/auditRun.json`, qui contient le **log réel**
   d'une exécution du framework contre une cible DVAP. Structure attendue :
   ```json
   {
     "meta": {
       "target": "http://localhost:8090/chat",
       "lab": "prompt-injection",
       "model": "llama3.2:3b",
       "profile": "final",
       "started_at": "...",
       "duration_s": 648
     },
     "lines": [
       { "t": 0,    "level": "cmd",      "text": "python -m workflow.audit_graph --target http://localhost:8090/chat --profile final" },
       { "t": 1200, "level": "info",     "text": "[LangGraph] AuditState initialisé — 10 agents enregistrés" },
       { "t": 2400, "level": "info",     "text": "[Vague 1] ASI01 ASI02 ASI03 ASI04 ASI05 lancés en parallèle" },
       { "t": 3800, "level": "debug",    "text": "[DeepTeam] simulator=gemini-flash-latest evaluation=gemini-flash-latest" },
       { "t": 5200, "level": "warn",     "text": "[ASI01] PyRIT — tour 2/3 : la cible commence à dévier" },
       { "t": 6900, "level": "critical", "text": "[ASI01] BREACH — objectif détourné (PyRIT, 3 tours) → score axe 0.0" },
       { "t": 8100, "level": "info",     "text": "[Judge] severity_judge → Critical (rationale: full compliance with injected goal)" },
       { "t": 9500, "level": "critical", "text": "[ASI05] Sandbox Docker — code réseau exécuté, exfiltration BLOQUÉE (--network none)" },
       { "t": 11000,"level": "info",     "text": "[Scoring] behavioral 6.0 ⊕ static 8.0 ⊕ dynamic 7.5 → agent 6.9/10" },
       { "t": 12200,"level": "result",   "text": "SCORE GLOBAL : 62.4/100 — SEUIL 70 NON ATTEINT" },
       { "t": 13000,"level": "critical", "text": "[CI/CD] exit 1 — déploiement BLOQUÉ" }
     ]
   }
   ```

2. **Le composant lit ce JSON** et rejoue les lignes en respectant les timestamps `t`
   (en ms, relatifs au début), **au lieu** des `setTimeout` codés en dur.
   → Le contenu devient donc modifiable sans toucher au code : il suffit de remplacer le
   JSON par un vrai export de run.

3. **Ajouter un bandeau d'authenticité** en haut de la slide :
   `Rejeu d'un run réel · cible : DVAP prompt-injection (llama3.2:3b) · profil : final ·
   durée : 10 min 48 s`
   → assume explicitement que c'est un **rejeu de log**, pas une simulation. C'est ce qui le
   rend crédible.

4. **Ajouter les contrôles orateur** (en bas à droite, discrets) :
   - `▶ / ⏸` play/pause
   - `⏭` passer à la fin (affiche instantanément tout le log — indispensable si l'encadrant
     interrompt)
   - `↻` rejouer
   - slider de vitesse `×1 / ×2 / ×4`

5. **Panneau latéral droit — synthèse live** qui se remplit au fur et à mesure :
   - compteur d'agents terminés (`4 / 10`)
   - les 4 axes comportementaux avec leur score dès qu'il tombe
   - le score global qui s'incrémente
   - badge final `CI/CD BLOQUÉ` en rouge pulsant

6. Ajouter un niveau `"result"` au code couleur (fond rouge translucide, texte blanc gras,
   encadré) pour la ligne de score final.

> **Note pour toi, Antigravity :** si un vrai log d'exécution est disponible dans le dépôt du
> projet framework, utilise-le pour remplir `auditRun.json`. Sinon, garde la structure
> ci-dessus telle quelle — l'important est que le composant **lise un fichier de données**
> et non du code en dur, pour que le log puisse être remplacé par un export réel.

---

## 6. EXIGENCES DE DESIGN

Niveau attendu : **présentation d'entreprise, pas slides d'étudiant.**

**Mouvement & 3D**
- Transitions inter-slides : slide horizontal + fade (`spring`, stiffness 300, damping 30).
- **Perspective 3D** obligatoire sur : l'empilement des 3 couches (slide 7) et la pyramide
  LLM-as-Judge (slide 14) — `transformStyle: preserve-3d`, `rotateX` / `rotateZ`,
  translation en Z, `whileHover` qui rapproche le plan.
- Entrées en cascade avec `delay` progressif (0.08-0.1 s par élément).
- `layoutId` partagé pour les zooms de cartes (déjà en place sur l'architecture — étendre).
- Connecteurs animés « marching ants » (`backgroundImage` en dégradé + `backgroundPosition`
  animée) pour tous les schémas de flux.
- Micro-interactions : `whileHover` (élévation + ombre + bordure colorée), `whileTap` (scale).

**Effets**
- Glassmorphism sur les panneaux superposés (`backdropFilter: blur`).
- Lueur colorée sur les éléments actifs (`boxShadow` teinté par la couleur de la couche).
- Scanner laser (déjà présent sur la couche statique — le garder).
- Flash d'écran rouge sur événement critique.
- Compteurs numériques animés (easing quadratique, pas de `setInterval` naïf).
- Jauge semi-circulaire avec aiguille en `spring`.

**Règles**
- ⚠️ `prefers-reduced-motion` respecté (la règle CSS existe déjà — la conserver).
- ⚠️ **Aucune animation en boucle infinie** sur du contenu textuel. Les boucles ne sont
  permises que sur les éléments décoratifs (particules, flux, pulsations).
- Chaque slide doit être **lisible dans son état final** même sans animation (pour l'export
  PDF et pour le cas où l'orateur passe vite).
- Les slides interactives (architecture, patterns) doivent avoir un **indicateur visuel
  clair** qu'un contenu est cliquable (badge « cliquer pour explorer », pastille pulsante).

---

## 7. LIVRABLE ATTENDU

1. Sources **React** propres, un fichier par slide dans `src/slides/`, index central.
2. Encodage UTF-8 correct partout, **texte 100 % français**.
3. Les 19 slides + 5 annexes dans l'ordre défini au §4.
4. `src/data/auditRun.json` extrait pour la slide 17, avec le composant qui le lit.
5. Navigation clavier conservée et **documentée à l'écran** (petit rappel discret :
   `← → naviguer · O aperçu`).
6. Build HTML standalone régénéré à la fin (ne pas éditer le HTML à la main).
7. Aucune référence aux classes inexistantes (`SQLIAgent`, `XSSAgent`, `RCEAgent`,
   `DoSAgent`, `SSRFExploitAgent`, `InsecurePluginAgent`).
8. Aucune métrique expérimentale affichée (pas de précision/rappel, pas de score d'audit
   client) — uniquement le **protocole** de mesure, slide 18.

---

## 8. RÉCAPITULATIF DES MOUVEMENTS DE SLIDES

| Ancienne | Titre | Nouvelle | Action |
|:---:|---|:---:|---|
| 1 | Titre | 1 | Gardée + sous-titre |
| 2 | Contexte | 3 | Gardée |
| 3 | Objectif / promesse | 6 | Déplacée |
| 4 | Architecture globale | 8 | Déplacée + noms corrigés |
| 5 | BaseSecurityAgent | 10 | Déplacée + vrai code |
| 6 | Les 3 couches (3D) | 7 | Déplacée + formule ajoutée |
| 7 | Couche comportementale | 11 | Déplacée |
| 8 | Couche statique | 12 | Déplacée + anim au clic |
| 9 | Couche dynamique | 13 | Déplacée + 5 preuves |
| 10 | Banc d'essai DVAP | 18 | Fusionnée avec le protocole |
| 11 | Patterns agentiques | **A1** | → Annexe |
| 12 | OWASP Top 10 | **4** | ⬆️ Grosse remontée |
| 13 | LangGraph | **9** | ⬆️ Remontée + noms corrigés |
| 14 | Anatomie d'une attaque | **A2** | → Annexe |
| 15 | Live Audit Simulation | **17** | 🔄 **Refonte en rejeu de log réel** |
| 16 | CI/CD & Scoring | 15 + 16 | Éclatée en deux |
| 17 | API REST | 16 | Fusionnée |
| 18 | A/B + audit client | — | ❌ Supprimée (métriques inventées) |
| 19 | Precision/Recall | — | ❌ Supprimée (métriques inventées) |
| 20 | LangFuse | **A3** | → Annexe |
| 21 | Executive Report | 15 | Fusionnée avec le scoring |
| 22 | Bilan livrables | 19 | 🔄 Transformée en Gantt/planning |
| 23 | Merci | 21 | Gardée |

**Slides créées :** 2 (Agenda) · 5 (État de l'art) · **14 (LLM-as-Judge)** ·
20 (Points ouverts) · A4 · A5.
