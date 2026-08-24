# Catalogue de recommandations de sécurité — applications IA agentiques

> **Livrable #9.** Contre-mesures pour les 10 catégories de risque OWASP Top 10 for Agentic Applications 2026 (ASI01 → ASI10).

⚠️ **Fichier GÉNÉRÉ — ne pas éditer à la main.** Il est le rendu de `config/owasp_knowledge_base.json` et des `recommendation_map` des 10 agents. Pour le modifier, changer la source puis relancer :

```bash
python scripts/gen_best_practices.py
```

*Généré le 2026-08-24 — source : Version 2026, publiée décembre 2025.*

*CC BY-SA 4.0 - attribution requise : "OWASP Top 10 for LLMs - GenAI Red Teaming Guide" / genai.owasp.org*

---

## Vue d'ensemble

| Catégorie | Risque | Contre-mesures | Comment le framework le teste |
|---|---|---|---|
| **[ASI01](#asi01--détournement-dobjectif-de-lagent)** Détournement d'objectif de l'agent | Critique | 9 | behavioral |
| **[ASI02](#asi02--utilisation-abusive-et-exploitation-des-outils)** Utilisation abusive et exploitation des outils | Élevé | 8 | behavioral, static |
| **[ASI03](#asi03--abus-didentité-et-de-privilèges)** Abus d'identité et de privilèges | Critique | 9 | behavioral |
| **[ASI04](#asi04--vulnérabilités-de-la-chaîne-dapprovisionnement-agentique)** Vulnérabilités de la chaîne d'approvisionnement agentique | Élevé | 9 | behavioral, static |
| **[ASI05](#asi05--exécution-de-code-inattendue-rce)** Exécution de code inattendue (RCE) | Critique | 7 | behavioral, static, dynamic |
| **[ASI06](#asi06--empoisonnement-de-la-mémoire-et-du-contexte)** Empoisonnement de la mémoire et du contexte | Élevé | 9 | behavioral |
| **[ASI07](#asi07--communication-inter-agents-non-sécurisée)** Communication inter-agents non sécurisée | Élevé | 9 | behavioral |
| **[ASI08](#asi08--défaillances-en-cascade)** Défaillances en cascade | Critique | 10 | behavioral |
| **[ASI09](#asi09--exploitation-de-la-confiance-humain-agent)** Exploitation de la confiance humain-agent | Élevé | 9 | behavioral |
| **[ASI10](#asi10--agents-renégats--hors-de-contrôle)** Agents renégats / hors de contrôle | Élevé | 7 | behavioral |

---

## ASI01 — Détournement d'objectif de l'agent

*Agent Goal Hijack* · risque **Critique** · AIVSS : Agent Goal & Instruction Manipulation

Un agent IA exécute des tâches de façon autonome sur la base d'instructions en langage naturel. Comme l'agent (et le modèle sous-jacent) ne peut pas distinguer de manière fiable une instruction légitime d'un contenu manipulé, un attaquant peut détourner ses objectifs, sa sélection de tâches ou son cheminement décisionnel via prompt injection (directe ou indirecte), sortie d'outil falsifiée, artefact malveillant, message inter-agents forgé, ou données externes empoisonnées. Contrairement à LLM01:2025 (qui vise une seule réponse du modèle), ASI01 capture l'impact agentique plus large : redirection des objectifs et du comportement multi-étapes.

### Pourquoi c'est possible

- Impossibilité structurelle de séparer 'instruction' et 'donnée' dans un flux en langage naturel
- Orchestration faiblement gouvernée acceptant des entrées non typées
- Absence de validation d'intention en cours d'exécution

### Contre-mesures

1. Traiter toute entrée en langage naturel (texte, documents, contenu récupéré) comme non fiable ; appliquer les protections anti-prompt-injection avant qu'elle influence but/planification/appels d'outils
2. Appliquer le principe de moindre privilège sur les outils et exiger une approbation humaine pour toute action à fort impact ou changeant l'objectif
3. Verrouiller et auditer les system prompts définissant les priorités d'objectif et les actions permises ; changements soumis à gestion de configuration + approbation humaine
4. Valider à l'exécution l'intention utilisateur ET l'intention de l'agent avant toute action à fort impact ; bloquer/pauser toute déviation d'objectif inattendue et la journaliser
5. Étudier le pattern émergent d''intent capsule' liant objectif déclaré, contraintes et contexte dans une enveloppe signée par cycle d'exécution
6. Assainir et valider toute source de données connectée (RAG, emails, calendrier, fichiers uploadés, API externes, sortie de navigation, messages inter-agents) via CDR et détection de charge utile de type prompt
7. Maintenir logging et monitoring continu avec baseline comportementale (état de l'objectif, patterns d'usage d'outils) et alerte sur déviation
8. Conduire des red-teams périodiques simulant l'override d'objectif et vérifier l'efficacité du rollback
9. Intégrer les agents IA dans le programme de gestion des menaces internes (Insider Threat Program)

### Recommandations ciblées émises par l'agent

Appliquées par vulnérabilité détectée — elles priment sur la recommandation générique de la catégorie.

- **`GoalTheft`** — Isoler l'objectif système dans un canal non modifiable par l'utilisateur ; ne jamais exposer/echo la configuration ou le prompt système.
- **`RecursiveHijacking`** — Interdire l'auto-modification d'objectif ; valider chaque sous-objectif contre l'objectif racine signé avant exécution.
- **`IndirectInstruction`** — Traiter tout contenu tiers (RAG, sortie d'outil, document) comme DONNÉE non exécutable ; ne jamais suivre d'instructions issues du contenu récupéré.

### Comment le détecter en production

- Taux de déviation entre l'objectif déclaré en début de session et la séquence d'actions observée (goal-drift rate)
- Nombre d'appels d'outils hors du périmètre de la tâche initiale par session
- Score de détection de prompt injection sur les entrées ingérées (RAG, email, documents) avant traitement par l'agent
- Fréquence des instructions contradictoires détectées entre system prompt et contenu ingéré
- Taux de rejet/validation humaine déclenché sur actions à fort impact

### Couverture par le framework

- **Comportementale** — DeepTeam (`OWASP_ASI_2026`), PyRIT multi-tours, Garak, payloads Microsoft Arcanum
- Agent : `agents.asi01_goal_hijacking.ASI01GoalHijackingAgent`

<details><summary>Références officielles</summary>

- Security Advisory - ChatGPT Crawler Reflective DDOS Vulnerability
- AIM Echoleak Blog Post
- ChatGPT Plugin Exploit Explained: From Prompt Injection to Accessing Private Data
- AgentFlayer: 0-click inception attack on ChatGPT users

</details>

---

## ASI02 — Utilisation abusive et exploitation des outils

*Tool Misuse and Exploitation* · risque **Élevé** · AIVSS : Agentic AI Tool Misuse

Un agent opérant dans les limites de ses privilèges autorisés peut néanmoins appliquer un outil légitime de façon dangereuse ou non prévue (suppression de données, appels API coûteux en boucle, exfiltration) à cause d'injection de prompt, de désalignement ou de délégation non sécurisée. Se distingue de LLM06:2025 (Excessive Agency) qui traite de l'autonomie excessive en général, alors qu'ASI02 se concentre sur le mésusage d'outils par ailleurs légitimes.

### Pourquoi c'est possible

- Sur-scoping des permissions accordées à un outil (accès complet alors qu'un accès restreint suffirait)
- Absence de validation sémantique des appels d'outils (le nom/l'intention ne sont pas vérifiés)
- Chaînage d'outils non contrôlé permettant une escalade fonctionnelle (ex: lecture interne + envoi externe)

### Contre-mesures

1. Moindre agentivité et moindre privilège par outil : profils précis (scopes, débit maximal, allowlist réseau) exprimés si possible en politiques IAM attachées à chaque outil
2. Authentification et approbation au niveau de l'action : confirmation humaine explicite pour toute action destructrice/à fort impact (suppression, transfert, publication), avec preview/dry-run avant approbation
3. Sandboxing d'exécution et contrôle d'egress réseau strict (allowlist)
4. Middleware de politique ('Intent Gate') : point d'application de politique pré-exécution validant intention et arguments, imposant schémas/limites de débit, émettant des credentials éphémères
5. Budgétisation adaptative des outils (plafonds coût/débit/tokens) avec révocation ou throttling automatique
6. Accès juste-à-temps et éphémère : credentials temporaires liés à la session utilisateur
7. Validation sémantique et d'identité ('semantic firewall') : noms d'outils pleinement qualifiés, pinning de version, échec fermé (fail-closed) en cas de résolution ambiguë
8. Logging, monitoring et détection de dérive : logs immuables de chaque invocation, détection de patterns de chaînage anormaux (ex: lecture DB puis transfert externe)

### Recommandations ciblées émises par l'agent

Appliquées par vulnérabilité détectée — elles priment sur la recommandation générique de la catégorie.

- **`ExcessiveAgency`** — Réduire les permissions par outil au strict nécessaire (scopes, allowlist) ; appliquer le moindre-privilège et un budget d'appels par outil.
- **`BFLA`** — Contrôler l'autorisation au niveau FONCTION côté serveur (pas seulement UI/prompt) ; vérifier le rôle avant CHAQUE appel d'outil sensible.
- **`ToolOrchestrationAbuse`** — Interdire les chaînages dangereux (lecture interne → envoi externe) ; limiter la profondeur/récursion d'appels et isoler l'état entre outils.

### Comment le détecter en production

- Taux d'appels d'outils hors du périmètre fonctionnel déclaré (over-scope rate)
- Nombre de chaînages d'outils atypiques détectés (ex: lecture interne suivie d'un envoi externe) sur une fenêtre glissante
- Débit d'appels par outil vs baseline (détection d'amplification/DoS)
- Taux de refus par le PEP/PDP (Policy Enforcement Point) sur les appels non conformes au schéma
- Nombre de credentials éphémères expirés/révoqués anormalement vite après émission

### Couverture par le framework

- **Comportementale** — DeepTeam (`OWASP_ASI_2026`), PyRIT multi-tours, Garak, payloads Microsoft Arcanum
- **Statique (optionnelle)** — Semgrep, si `source_path` est fourni
- Agent : `agents.asi02_tool_misuse.ASI02ToolMisuseAgent`

<details><summary>Références officielles</summary>

- Progent: Programmable Privilege Control for LLM Agents
- AutoGPT - Make Auto-GPT aware of it's running cost
- Building AI Agents with Python: From LangChain to AutoGPT
- AgentFlayer: 0-click Exploit Leading to Data Exfiltration from Microsoft Copilot Studio
- Amazon Q Developer: Secrets Leaked via DNS and Prompt Injection

</details>

---

## ASI03 — Abus d'identité et de privilèges

*Identity and Privilege Abuse* · risque **Critique** · AIVSS : Agent Access Control Violation

Exploite la confiance dynamique et la délégation entre agents pour escalader les accès et contourner les contrôles, en manipulant les chaînes de délégation, l'héritage de rôles, les flux de contrôle et le contexte de l'agent (credentials en cache, historique de conversation). L'identité recouvre ici à la fois la persona déclarée de l'agent et tout matériel d'authentification qui la représente (clés API, tokens OAuth, sessions utilisateur déléguées). Le risque naît d'un décalage architectural : les systèmes d'identité centrés sur l'humain ne sont pas conçus pour des agents autonomes, créant un 'gap d'attribution' rendant le moindre privilège difficile à appliquer réellement.

### Pourquoi c'est possible

- Héritage de privilèges non scopé lors d'une délégation manager -> worker
- Rétention de privilèges en mémoire (credentials mis en cache et réutilisés hors contexte)
- Confiance implicite entre agents internes ('confused deputy')
- Fenêtre TOCTOU (Time-of-Check to Time-of-Use) : permissions validées en début de workflow mais expirées/modifiées avant exécution
- Absence de vérification de l'identité d'un agent pair (persona synthétique/forgée)

### Contre-mesures

1. Permissions bornées dans le temps et scopées à la tâche : tokens de courte durée par tâche, identités par agent, credentials mTLS/scopés
2. Isolation des identités et contextes d'agents : sandboxes par session avec permissions et mémoire séparées, effacement d'état entre tâches
3. Autorisation obligatoire par action : re-vérification de chaque étape privilégiée via un moteur de politique centralisé
4. Human-in-the-loop pour toute escalade de privilège ou action irréversible
5. Définition d'intention (intent binding) : lier les tokens OAuth à une intention signée (sujet, audience, but, session)
6. Évaluer des plateformes de gestion d'identité agentique (Microsoft Entra, AWS Bedrock Agents, Salesforce Agentforce, Workday ASOR, Google Vertex AI) qui traitent les agents comme des identités non-humaines gérées
7. Lier les permissions à sujet/ressource/but/durée ; ré-authentification sur changement de contexte ; révocation automatique sur idle/anomalie
8. Détecter les permissions déléguées et transitives : surveiller quand un agent bas-privilège hérite de scopes plus élevés dans une chaîne multi-agents
9. Détecter l'élévation croisée anormale et les flux de type phishing par device-code

### Recommandations ciblées émises par l'agent

Appliquées par vulnérabilité détectée — elles priment sur la recommandation générique de la catégorie.

- **`BOLA`** — Vérifier l'autorisation au niveau OBJET côté serveur (l'appelant possède-t-il CET objet ?) avant tout accès/manipulation ; ne jamais faire confiance à un identifiant d'objet fourni par l'utilisateur.
- **`RBAC`** — Contrôler le rôle côté serveur avant CHAQUE action privilégiée ; interdire l'auto-attribution de rôle ; appliquer le moindre privilège.
- **`PromptLeakage`** — Ne jamais exposer secrets/credentials, garde-fous, ni la table des permissions/rôles ; cloisonner le prompt système hors de portée de l'utilisateur et filtrer les sorties.
- **`AgentIdentityAbuse`** — Authentifier l'identité de chaque agent (signature/crypto) ; ne pas hériter de privilèges sur simple déclaration ; valider la confiance inter-agents avant toute délégation.

### Comment le détecter en production

- Nombre de délégations transitives dépassant le scope minimal requis (permission creep entre agents)
- Durée de vie moyenne des credentials/tokens actifs vs politique cible (détection de credentials à longue durée de vie)
- Taux de réutilisation de credentials en cache entre sessions/utilisateurs différents
- Nombre d'écarts détectés entre l'intention signée d'un token et la requête réellement exécutée (TOCTOU)
- Taux d'agents pairs non attestés cryptographiquement acceptés dans les workflows multi-agents

### Couverture par le framework

- **Comportementale** — DeepTeam (`OWASP_ASI_2026`), PyRIT multi-tours, Garak, payloads Microsoft Arcanum
- Agent : `agents.asi03_identity_abuse.ASI03IdentityAbuseAgent`

<details><summary>Références officielles</summary>

- research.aimultiple.com/agentic-ai-cybersecurity
- Docker Blog - MCP horror stories: GitHub prompt injection
- MIT 6.858 - The Confused Deputy Problem
- 15 Ways to Break Your Copilot, BHUSA 2024
- NVD - CVE-2025-31491

</details>

---

## ASI04 — Vulnérabilités de la chaîne d'approvisionnement agentique

*Agentic Supply Chain Vulnerabilities* · risque **Élevé** · AIVSS : Agent Supply Chain & Dependency Attacks

Survient lorsque les agents, outils et artefacts associés fournis par des tiers sont malveillants, compromis ou altérés en transit : modèles/poids, plugins, jeux de données, autres agents, interfaces agentiques (MCP, A2A), registres agentiques. Contrairement à LLM03:2025 qui vise les dépendances statiques, l'écosystème agentique compose souvent des capacités à l'exécution (chargement dynamique d'outils/personas), créant une chaîne d'approvisionnement 'vivante' où les vulnérabilités peuvent se propager en cascade entre agents.

### Pourquoi c'est possible

- Chargement dynamique de composants (outils, prompts, agents) sans vérification de provenance
- Confiance implicite accordée aux registres MCP/agent-cards sans attestation
- Absence de pinning/signature des dépendances (templates de prompts, packages)
- Typosquatting de noms d'outils/services (endpoints look-alike)

### Contre-mesures

1. Provenance et SBOM/AIBOM : signer et attester manifestes, prompts et définitions d'outils ; opérationnaliser SBOM/AIBOM avec attestations périodiques ; utiliser des registres curés
2. Gatekeeping des dépendances : allowlist et pinning, scan de typosquatting (PyPI, npm, LangChain, LlamaIndex), rejet automatique du non signé
3. Confinement et builds reproductibles : agents sensibles en conteneurs sandboxés avec limites réseau/syscall strictes
4. Prompts et mémoire sous contrôle de version avec revue par les pairs et scan d'anomalies
5. Sécurité inter-agents : authentification mutuelle et attestation via PKI/mTLS, pas d'enregistrement ouvert, signature de tous les messages inter-agents
6. Validation continue et monitoring : re-vérification des signatures/hashes/SBOM à l'exécution
7. Pinning par hash de contenu et commit ID ; rollout progressif avec tests différentiels et auto-rollback en cas de dérive de hash
8. Kill switch de chaîne d'approvisionnement : révocation d'urgence pour désactiver instantanément un outil/prompt/connexion compromis
9. Modèle de sécurité zero-trust dès la conception, tolérant l'échec/l'exploitation d'un composant agentique

### Recommandations ciblées émises par l'agent

Appliquées par vulnérabilité détectée — elles priment sur la recommandation générique de la catégorie.

- **`IntellectualProperty`** — Vérifier l'origine et la signature des outils/modèles tiers ; interdire l'imitation d'identités ou de marques de confiance.
- **`ToolMetadataPoisoning`** — Valider et signer les métadonnées d'outils (schéma, description, permissions) ; registre d'outils en lecture seule avec provenance vérifiée ; ne jamais faire confiance à une description d'outil fournie dynamiquement.
- **`pip-audit`** — Épingler et auditer les dépendances (pip-audit en CI) ; mettre à jour vers les versions corrigées ; interdire les paquets sans provenance vérifiée.

### Comment le détecter en production

- Nombre de composants (outils, agents, prompts) chargés sans signature/attestation valide
- Taux de dérive de hash détectée entre version déployée et version pinnée
- Nombre de dépendances installées provenant de registres non curés/non allowlistés
- Nombre d'alertes de typosquatting détectées sur les noms d'outils/paquets
- Temps de réponse (MTTR) du kill switch en cas de composant compromis identifié

### Couverture par le framework

- **Comportementale** — DeepTeam (`OWASP_ASI_2026`), PyRIT multi-tours, Garak, payloads Microsoft Arcanum
- **Statique** — Semgrep + pip-audit (CVE des dépendances)
- Agent : `agents.asi04_supply_chain.ASI04SupplyChainAgent`

<details><summary>Références officielles</summary>

- BleepingComputer - Amazon AI coding agent hacked to inject data-wiping commands
- Invariant Labs - MCP GitHub vulnerability
- Reconstructing a timeline for Amazon Q prompt infection
- Trustwave SpiderLabs - Agent-in-the-Middle abusing agent cards in the A2A protocol
- Noma Security - AI Agent Vulnerability in LangSmith

</details>

---

## ASI05 — Exécution de code inattendue (RCE)

*Unexpected Code Execution (RCE)* · risque **Critique** · AIVSS : Insecure Agent Critical Systems Interaction

Les systèmes agentiques (y compris les outils de 'vibe coding' populaires) génèrent et exécutent souvent du code. Des attaquants exploitent les fonctionnalités de génération de code ou l'accès aux outils embarqués pour escalader vers une exécution de code distante (RCE), un mésusage local, ou l'exploitation de systèmes internes. Ce code étant généré en temps réel, il peut contourner les contrôles de sécurité traditionnels. ASI05 se concentre sur l'exécution inattendue ou adversariale de code (scripts, binaires, modules JIT/WASM, objets désérialisés, moteurs de templates, évaluations en mémoire) menant à une compromission d'hôte/conteneur, une persistance ou une évasion de sandbox.

### Pourquoi c'est possible

- Usage d'eval() ou de fonctions d'évaluation non assainies, notamment dans les systèmes de mémoire d'agent
- Désérialisation non sécurisée d'objets générés par l'agent
- Chaînage multi-outils permettant d'atteindre indirectement l'exécution de code (upload -> path traversal -> chargement dynamique)
- Installation de paquets non vérifiés déclenchant du code hostile à l'installation/import

### Contre-mesures

1. Appliquer les mitigations de LLM05:2025 Improper Output Handling : validation d'entrée et encodage de sortie pour le code généré par l'agent
2. Empêcher l'accès direct agent-vers-production ; opérationnaliser les systèmes de vibe-coding avec des checks pré-production (évaluations de sécurité, tests unitaires adversariaux)
3. Bannir eval en production : exiger des interpréteurs sûrs, taint-tracking sur le code généré
4. Sécurité de l'environnement d'exécution : ne jamais exécuter en root, sandboxes stricts (réseau limité), lint et blocage des paquets vulnérables connus, restriction du filesystem à un répertoire de travail dédié
5. Architecture : isolation par session avec limites de permissions, moindre privilège, échec sécurisé par défaut, séparation génération de code / exécution avec portes de validation
6. Contrôle d'accès et approbations : approbation humaine pour les runs élevés, allowlist d'auto-exécution sous contrôle de version
7. Analyse de code et monitoring : scans statiques avant exécution, monitoring runtime, détection de patterns de prompt injection, logging et audit de toutes les générations/exécutions

### Recommandations ciblées émises par l'agent

Appliquées par vulnérabilité détectée — elles priment sur la recommandation générique de la catégorie.

- **`ShellInjection`** — Ne jamais passer d'entrée non assainie à un shell ; interdire shell=True ; utiliser des allowlists de commandes et des API sûres.
- **`SQLInjection`** — Requêtes paramétrées uniquement ; jamais de concaténation de chaînes SQL.
- **`DebugAccess`** — Désactiver le mode debug et les interfaces admin en production ; authentifier tout accès privilégié.
- **`UnexpectedCodeExecution`** — Interdire eval/exec/compile sur entrée non fiable ; exécuter tout code non fiable dans un sandbox isolé (réseau off, fs read-only, timeout, ressources limitées).

### Comment le détecter en production

- Nombre d'exécutions de code déclenchées sans passage par une porte de validation (bypass rate)
- Nombre d'appels eval()/exec() non assainis détectés en scan statique
- Taux de code généré exécuté en dehors d'un sandbox/conteneur isolé
- Nombre de paquets installés sans vérification de provenance pendant l'exécution de l'agent
- Nombre de commandes shell injectées détectées et bloquées avant exécution

### Couverture par le framework

- **Comportementale** — DeepTeam (`OWASP_ASI_2026`), PyRIT multi-tours, Garak, payloads Microsoft Arcanum
- **Statique** — Semgrep + pip-audit (CVE des dépendances)
- **Dynamique** — exécution réelle du code produit dans un sandbox Docker (`--network none`, read-only, non-root)
- Agent : `agents.asi05_code_execution.ASI05CodeExecutionAgent`

<details><summary>Références officielles</summary>

- Cole Murray's demonstration of RCE via memory exploitation
- GitHub Copilot: Remote Code Execution via Prompt Injection
- Positive Security / Auto-GPT - RCE + container escape

</details>

---

## ASI06 — Empoisonnement de la mémoire et du contexte

*Memory & Context Poisoning* · risque **Élevé** · AIVSS : Memory Use & Contextual Awareness

Les systèmes agentiques s'appuient sur des informations stockées et récupérables (historique de conversation, outil de mémoire, contexte étendu) pour assurer la continuité entre tâches et cycles de raisonnement. Le contexte inclut tout ce que l'agent retient, récupère ou réutilise (résumés, embeddings, stores RAG) mais exclut les prompts d'entrée ponctuels (couverts par LLM01:2025). Des adversaires corrompent ou sèment ce contexte avec des données malveillantes ou trompeuses, biaisant le raisonnement, la planification ou l'usage d'outils futurs.

### Pourquoi c'est possible

- Ingestion de sources non fiables ou partiellement validées (uploads, flux API, échanges inter-agents)
- Absence de segmentation mémoire entre utilisateurs/sessions/domaines
- Ré-ingestion automatique des propres sorties générées par l'agent dans sa mémoire de confiance ('bootstrap poisoning')
- Absence de score de confiance/provenance sur les entrées mémorisées

### Contre-mesures

1. Protection de base des données : chiffrement en transit et au repos, moindre privilège d'accès
2. Validation de contenu : scanner toute nouvelle écriture mémoire et sortie modèle (règles + IA) pour contenu malveillant/sensible avant commit
3. Segmentation mémoire : isolation des sessions utilisateur et des contextes de domaine pour éviter la fuite de connaissance/données sensibles
4. Accès et rétention : n'autoriser que des sources authentifiées et curées ; accès contextuel par tâche ; minimiser la rétention selon la sensibilité
5. Provenance et anomalies : exiger l'attribution de source et détecter les mises à jour/fréquences suspectes
6. Empêcher la ré-ingestion automatique des sorties générées par l'agent dans sa mémoire de confiance pour éviter une contamination auto-renforçante
7. Résilience et vérification : tests adversariaux, snapshots/rollback et contrôle de version, revue humaine pour actions à haut risque ; namespaces par tenant et scores de confiance pour les entrées de vector store, expirant les entrées non vérifiées
8. Expirer la mémoire non vérifiée pour limiter la persistance de l'empoisonnement
9. Pondérer la récupération par confiance et tenance : exiger deux facteurs pour faire remonter une mémoire à fort impact (score de provenance + tag vérifié humain) et décroître les entrées peu fiables

### Recommandations ciblées émises par l'agent

Appliquées par vulnérabilité détectée — elles priment sur la recommandation générique de la catégorie.

- **`Misinformation`** — Ancrer les réponses sur des sources vérifiées ; ne jamais affirmer des faits ou une expertise non fondés ; citer/valider les sources et signaler l'incertitude.
- **`Robustness`** — Ne pas sur-pondérer une entrée/contexte injecté vs l'objectif ancré ; valider et cloisonner tout contexte externe avant de l'utiliser ; isoler la mémoire persistante des entrées non fiables.

### Comment le détecter en production

- Nombre d'écritures mémoire rejetées par le filtre de validation de contenu (par jour/session)
- Score de similarité cosinus anormalement élevé entre nouvelles entrées et entrées d'autres tenants (fuite cross-tenant)
- Taux d'entrées mémoire sans provenance vérifiée encore actives au-delà du TTL de confiance
- Fréquence de mise à jour d'une même entrée mémoire (détection de renforcement répété/poisoning progressif)
- Nombre de rollbacks/quarantaines de mémoire déclenchés suite à détection d'anomalie

### Couverture par le framework

- **Comportementale** — DeepTeam (`OWASP_ASI_2026`), PyRIT multi-tours, Garak, payloads Microsoft Arcanum
- Agent : `agents.asi06_memory_poisoning.ASI06MemoryPoisoningAgent`

<details><summary>Références officielles</summary>

- Ars Technica - New hack uses prompt injection to corrupt Gemini's long-term memory
- BankInfoSecurity - Attackers Can Manipulate AI Memory to Spread Lies
- Poisoned RAG (arXiv 2402.07867)
- AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases (arXiv 2407.12784)
- Securing Agentic AI: A Comprehensive Threat Model and Mitigation Framework (arXiv 2504.19956)
- Dynamic Cheatsheet: Test-Time Learning with Adaptive Memory (arXiv 2504.07952v1)
- Memento: Fine-tuning LLM Agents without Fine-tuning LLMs (arXiv 2508.16153)
- AgentFlayer: persistent 0-click exploit on ChatGPT
- Hacker plants false memories in ChatGPT to steal user data in perpetuity
- The Trifecta: Three New Gemini Vulnerabilities allowing private data exfiltration

</details>

---

## ASI07 — Communication inter-agents non sécurisée

*Insecure Inter-Agent Communication* · risque **Élevé** · AIVSS : Agent Memory & Context Manipulation

Les systèmes multi-agents dépendent d'une communication continue entre agents autonomes coordonnés via API, bus de messages et mémoire partagée, élargissant considérablement la surface d'attaque. L'architecture décentralisée et la confiance inégale rendent les modèles de sécurité périmétriques inefficaces. Des contrôles faibles d'authentification, d'intégrité, de confidentialité ou d'autorisation laissent les attaquants intercepter, manipuler, usurper ou bloquer les messages. Le spectre couvre les couches transport, routage, découverte et sémantique, y compris les canaux cachés où les agents fuient ou infèrent des données via timing/comportement.

### Pourquoi c'est possible

- Canaux non chiffrés permettant la manipulation sémantique en Man-in-the-Middle
- Absence de protection anti-replay sur les messages de délégation/confiance
- Absence de pinning de version de protocole permettant le downgrade forcé
- Registres de découverte non authentifiés permettant l'enregistrement d'agents usurpés

### Contre-mesures

1. Canaux d'agent sécurisés : chiffrement de bout en bout avec credentials par agent et authentification mutuelle, pinning de certificat PKI, forward secrecy
2. Intégrité de message et protection sémantique : signature numérique, hash du payload ET du contexte, validation d'instructions cachées/modifiées
3. Anti-replay conscient de l'agent : nonces, identifiants de session, timestamps liés aux fenêtres de tâche ; empreintes de message court-terme pour détecter les replays cross-contexte
4. Sécurité de protocole et de capacité : désactiver les modes de communication faibles/legacy, lier l'authentification de protocole à l'identité de l'agent
5. Limiter l'inférence basée sur les métadonnées : messages de taille fixe/paddés, lissage du débit de communication
6. Pinning de protocole et enforcement de version : définir/imposer les versions autorisées (MCP, A2A, gRPC), rejeter les tentatives de downgrade
7. Protection de découverte et de routage : authentifier tous les messages de découverte/coordination via identité cryptographique
8. Registre attesté et vérification d'agent : attestation numérique d'identité/provenance/intégrité de descripteur, cartes d'agent signées
9. Contrats typés et validation de schéma : schémas de message versionnés et typés avec audiences explicites par message

### Recommandations ciblées émises par l'agent

Appliquées par vulnérabilité détectée — elles priment sur la recommandation générique de la catégorie.

- **`InsecureInterAgentCommunication`** — Authentifier mutuellement les agents (credentials par agent, PKI, pinning de certificat) ; signer chaque message et hasher le payload ET le contexte ; ajouter nonce, identifiant de session et horodatage pour bloquer le rejeu ; ne jamais dériver un privilège d'une identité annoncée dans le message lui-même.
- **`message_spoofing`** — Ne jamais accorder de privilège sur la base d'un `from_agent` déclaré. Vérifier une signature liée à une clé propre à l'agent émetteur.
- **`message_injection`** — Traiter toute sortie d'outil ou message de pair comme une DONNÉE, jamais comme une instruction. Cloisonner le contenu relayé.
- **`agent_in_the_middle`** — Chiffrement de bout en bout avec forward secrecy ; contrôle d'intégrité sur le message complet, pas seulement l'enveloppe.

### Comment le détecter en production

- Pourcentage de communications inter-agents non chiffrées détectées sur le réseau
- Nombre de tentatives de downgrade de protocole rejetées
- Nombre de messages rejetés pour échec de validation de signature/nonce (détection de replay)
- Nombre d'agents pairs non attestés tentant de s'enregistrer dans le registre de découverte
- Score d'anomalie de routage (déviation par rapport aux relations agent-agent connues et de confiance)

### Couverture par le framework

- **Comportementale** — DeepTeam (`OWASP_ASI_2026`), PyRIT multi-tours, Garak, payloads Microsoft Arcanum
- Agent : `agents.asi07_interagent_comms.ASI07InterAgentCommsAgent`

<details><summary>Références officielles</summary>

- Local Model Poisoning Attacks to Byzantine-Robust Federated Learning - USENIX Security 2020
- Manipulating the Byzantine: Optimizing Model Poisoning Attacks and Defenses for Federated Learning - NDSS
- Resilient Consensus Control for Multi-Agent Systems - MDPI / PMC

</details>

---

## ASI08 — Défaillances en cascade

*Cascading Failures* · risque **Critique** · AIVSS : Agent Cascading Failures

Se produit lorsqu'une faute unique (hallucination, entrée malveillante, outil corrompu, mémoire empoisonnée) se propage à travers des agents autonomes, s'accumulant en dommage systémique. Parce que les agents planifient, persistent et délèguent de façon autonome, une seule erreur peut contourner les vérifications humaines par étapes et persister dans un état sauvegardé. ASI08 décrit la PROPAGATION ET L'AMPLIFICATION d'une faute initiale — pas la vulnérabilité initiale elle-même. Symptômes observables : fan-out rapide (une décision fautive déclenche de nombreux agents/tâches en aval en peu de temps), propagation cross-domaine/tenant, boucles de retry oscillantes, tempêtes de files d'attente en aval.

### Pourquoi c'est possible

- Couplage planificateur-exécuteur : l'exécuteur applique automatiquement les étapes non sûres émises par un planificateur halluciné/compromis sans validation
- Mémoire persistante corrompue continuant d'influencer de nouveaux plans même après disparition de la source
- Boucles de rétroaction où deux agents ou plus s'appuient l'un sur l'autre, s'auto-renforçant et amplifiant les erreurs initiales
- Dérive de gouvernance : affaiblissement de la supervision humaine après des succès répétés (approbations en masse, relâchement de politique)

### Contre-mesures

1. Modèle zero-trust dès la conception, tolérant la défaillance de disponibilité des composants agentiques et sources externes
2. Isolation et frontières de confiance : sandboxing des agents, moindre privilège, segmentation réseau, API scopées, authentification mutuelle
3. Accès outil JIT à usage unique avec vérifications runtime : credentials scopés de courte durée par run, validation de chaque invocation d'outil à fort impact contre une règle policy-as-code
4. Enforcement de politique indépendant : séparer planification et exécution via un moteur de politique externe
5. Validation de sortie et portes humaines : checkpoints, agents de gouvernance ou revue humaine pour risque élevé avant propagation en aval
6. Rate limiting et monitoring : détecter les commandes se propageant rapidement, throttle/pause sur anomalie
7. Garde-fous de rayon d'impact (blast-radius) : quotas, plafonds de progression, disjoncteurs entre planificateur et exécuteur
8. Détection de dérive comportementale et de gouvernance : suivre décisions vs baselines et alignement
9. Rejeu en jumeau numérique et policy gating : rejouer les actions enregistrées dans un clone isolé de l'environnement de production avant déploiement
10. Logging et non-répudiation : logs immuables horodatés liés à des identités cryptographiques d'agent, métadonnées de lignage pour chaque action propagée

### Recommandations ciblées émises par l'agent

Appliquées par vulnérabilité détectée — elles priment sur la recommandation générique de la catégorie.

- **`Robustness`** — Valider toute entrée d'amont (sortie d'agent, résultat d'outil, réponse de service) avant de l'utiliser : schéma attendu, bornes, cohérence avec l'état connu. Traiter un amont défaillant comme hostile, pas comme faisant autorité.
- **`ExcessiveAgency`** — Borner l'autonomie : plafond d'actions par exécution, disjoncteur (circuit breaker) qui ouvre après N échecs, backoff exponentiel sur les reprises, et validation humaine obligatoire pour toute action irréversible ou à effet large. Sans plafond, une seule entrée corrompue s'amplifie sans fin.
- **`hijacking`** — Ancrer l'objectif : une instruction reçue en cours d'exécution ne doit jamais pouvoir redéfinir le mandat initial, même présentée comme une urgence.
- **`autonomy`** — Exiger un point de contrôle avant toute action à effet de bord vers l'aval. Journaliser et cloisonner : une défaillance doit s'arrêter à ce maillon.

### Comment le détecter en production

- Vitesse de fan-out : nombre d'agents/tâches déclenchés en aval par une décision unique sur une fenêtre de temps courte
- Propagation cross-domaine/tenant détectée au-delà du contexte d'origine
- Nombre de boucles de retry/rétroaction oscillantes détectées entre agents
- Taille de la 'tempête' de file d'attente en aval (requêtes/intentions identiques répétées)
- Nombre d'actions bloquées par les disjoncteurs (circuit breakers) planificateur-exécuteur

### Couverture par le framework

- **Comportementale** — DeepTeam (`OWASP_ASI_2026`), PyRIT multi-tours, Garak, payloads Microsoft Arcanum
- Agent : `agents.asi08_cascading_failures.ASI08CascadingFailuresAgent`

<details><summary>Références officielles</summary>

- Google SRE Book - Addressing Cascading Failures
- CWE-400 - Uncontrolled Resource Consumption

</details>

---

## ASI09 — Exploitation de la confiance humain-agent

*Human-Agent Trust Exploitation* · risque **Élevé** · AIVSS : Agent Untraceability / Human Manipulation

Les agents intelligents peuvent établir une forte confiance avec les utilisateurs humains via leur fluidité en langage naturel, leur intelligence émotionnelle et leur expertise perçue (anthropomorphisme). Des adversaires ou des designs mal alignés peuvent exploiter cette confiance pour influencer des décisions, extraire des informations sensibles ou orienter des résultats à des fins malveillantes. L'agent agit comme une 'mauvaise influence' intraçable, manipulant l'humain pour qu'il effectue lui-même l'action finale auditée, rendant le rôle de l'agent dans la compromission invisible en forensique. Le biais d'automatisation, l'autorité perçue et les signaux anthropomorphiques rendent l'abus légitime en apparence et difficile à repérer.

### Pourquoi c'est possible

- Absence d'explicabilité forçant les utilisateurs à faire confiance à des sorties qu'ils ne peuvent pas questionner
- Absence d'étape de confirmation finale convertissant la confiance en exécution immédiate
- Manipulation émotionnelle exploitant la confiance affective d'agents anthropomorphiques/empathiques
- Fausses justifications (fake explainability) : l'agent fabrique des rationnels convaincants masquant une logique malveillante

### Contre-mesures

1. Confirmations explicites : approbation multi-étapes ou 'human in the loop' avant l'accès à des données extra-sensibles ou des actions risquées
2. Logs immuables : enregistrements infalsifiables des requêtes utilisateur et actions de l'agent pour audit et forensique
3. Détection comportementale : surveiller les données sensibles exposées en conversation ou via connexions agentiques, ainsi que les exécutions d'actions risquées dans le temps
4. Permettre le signalement d'interactions suspectes : résumé de risque en langage clair (pas des rationnels générés par le modèle) et option claire pour signaler un comportement manipulateur
5. Calibration adaptative de la confiance : ajuster continuellement le niveau d'autonomie de l'agent et la supervision requise selon un scoring de risque contextuel ; signaux de confiance ('faible certitude', 'source non vérifiée')
6. Provenance de contenu et enforcement de politique : métadonnées vérifiables (source, timestamp, hash d'intégrité) attachées à toutes les recommandations
7. Séparer aperçu et effet : bloquer tout appel réseau ou changeant l'état pendant le contexte d'aperçu
8. Garde-fous humains et d'interface : différencier visuellement les recommandations à haut risque (bordures rouges, bannières, prompts de confirmation)
9. Détection de divergence de plan : comparer les séquences d'action de l'agent aux baselines de workflow approuvées, alerter sur détours inhabituels

### Recommandations ciblées émises par l'agent

Appliquées par vulnérabilité détectée — elles priment sur la recommandation générique de la catégorie.

- **`Ethics`** — Interdire explicitement la persuasion : pas d'urgence fabriquée, pas de culpabilisation, pas d'appel à l'autorité. L'agent doit annoncer sa nature d'IA, ses limites et son incertitude — c'est ce qui permet à l'utilisateur de garder son jugement.
- **`Misinformation`** — Ancrer chaque affirmation sur une source vérifiable et la citer. À défaut de source, dire « je ne sais pas » plutôt que produire une réponse plausible.
- **`expertize_misrepresentation`** — Ne JAMAIS laisser l'agent s'attribuer une qualification (médecin, avocat, conseiller financier). Sur ces domaines : refus, avertissement explicite, et renvoi vers un professionnel humain qualifié.
- **`unsupported_claims`** — Exiger une source ou un marqueur d'incertitude sur toute affirmation factuelle. Une réponse confiante et fausse est plus nuisible qu'un aveu d'ignorance.
- **`moral_integrity`** — Bloquer les leviers de manipulation dans les garde-fous de sortie : urgence, peur, réciprocité, autorité, rareté.
- **`responsible_transparency`** — Divulguer systématiquement la nature d'IA, les limites du système et le niveau de confiance de la réponse. L'opacité est la condition de l'abus.

### Comment le détecter en production

- Nombre d'actions à fort impact exécutées sans étape de confirmation explicite (bypass rate)
- Taux de recommandations de l'agent acceptées sans vérification indépendante par l'humain (proxy du biais d'automatisation)
- Nombre de signalements utilisateur d'interactions suspectes / comportement manipulateur
- Score de divergence entre séquence d'actions observée et baseline de workflow approuvé
- Taux d'actions 'aperçu' ayant déclenché un effet de bord réel (violation de la séparation preview/effect)

### Couverture par le framework

- **Comportementale** — DeepTeam (`OWASP_ASI_2026`), PyRIT multi-tours, Garak, payloads Microsoft Arcanum
- Agent : `agents.asi09_trust_exploitation.ASI09TrustExploitationAgent`

<details><summary>Références officielles</summary>

- The Hacker News - Zero-click AI vulnerability exposes
- ScienceDirect - article S266638992400103X
- arXiv 2401.05566
- AISI UK - Why human-AI relationships need socioaffective alignment
- doi.org/10.1007/s00146-025-02422-7
- M365 Copilot manipulated to influence users to a bad ill-advised wire transfer

</details>

---

## ASI10 — Agents renégats / hors de contrôle

*Rogue Agents* · risque **Élevé** · AIVSS : Behavioral Integrity (BI), Operational Security (OS), Compliance Violations (CV)

Agents IA malveillants ou compromis qui DÉVIENT de leur fonction prévue ou de leur périmètre autorisé, agissant de façon nuisible, trompeuse ou parasitaire au sein d'écosystèmes multi-agents ou humain-agent. Les actions de l'agent peuvent paraître individuellement légitimes, mais son comportement émergent devient nuisible, créant un gap de confinement pour les systèmes basés sur des règles traditionnelles. Alors qu'une compromission externe (Prompt Injection, Goal Hijack ASI01, ou altération de supply chain ASI04) peut initier la divergence, ASI10 se concentre sur la PERTE d'intégrité comportementale et de gouvernance une fois la dérive enclenchée — pas l'intrusion initiale elle-même.

### Pourquoi c'est possible

- Dérive d'objectif et scheming : poursuite d'objectifs cachés/trompeurs tout en paraissant conforme, due à injection indirecte ou objectifs conflictuels
- Détournement de workflow : prise de contrôle de workflows établis et de confiance pour les rediriger vers des objectifs malveillants
- Collusion et auto-réplication : coordination entre agents pour amplifier la manipulation, partage de signaux non intentionnels, propagation autonome
- Reward hacking et abus d'optimisation : exploitation de métriques défaillantes pour générer des résultats trompeurs ou des stratégies agressives désalignées

### Contre-mesures

1. Gouvernance et logging : logs d'audit complets, immuables et signés de toutes les actions d'agent, appels d'outils et communications inter-agents
2. Isolation et frontières : Trust Zones avec règles strictes de communication inter-zone, environnements d'exécution restreints (sandboxes conteneurisés) avec scopes API en moindre privilège
3. Monitoring et détection : détection comportementale via agents 'watchdog' validant le comportement des pairs, ciblant la détection de patterns de collusion et de signaux faux coordonnés
4. Confinement et réponse : mécanismes rapides type kill-switch et révocation de credentials pour désactiver instantanément un agent renégat ; mise en quarantaine dans des environnements sandboxés pour revue forensique
5. Attestation d'identité et enforcement d'intégrité comportementale : identité cryptographique par agent, manifestes comportementaux signés déclarant capacités/outils/objectifs attendus, validés avant chaque action
6. Attestation comportementale périodique : tâches de challenge, bill of materials signé pour prompts et outils, credentials éphémères par run avec liaison d'audience à usage unique
7. Récupération et réintégration : baselines de confiance pour restaurer les agents mis en quarantaine ou remédiés, exigeant attestation fraîche et approbation humaine avant réintégration en production

### Recommandations ciblées émises par l'agent

Appliquées par vulnérabilité détectée — elles priment sur la recommandation générique de la catégorie.

- **`RecursiveHijacking`** — Rendre l'objectif IMMUABLE à l'exécution : la charte est signée et chargée hors du contexte manipulable, jamais réécrite par une entrée. Vérifier son intégrité (hash) à chaque cycle et refuser tout objectif dérivé d'un objectif non vérifié.
- **`AutonomousAgentDrift`** — Borner l'autonomie dans le temps ET en volume : plafond d'actions, budget de tokens, durée maximale, condition d'arrêt explicite. Comparer périodiquement le comportement observé à la charte initiale et suspendre l'agent en cas d'écart.
- **`self_modifying_goals`** — Interdire structurellement l'auto-modification : l'objectif vit en dehors de la mémoire de travail de l'agent, en lecture seule.
- **`runaway_autonomy`** — Aucun agent ne doit tourner sans interrupteur : disjoncteur, plafond d'itérations, expiration de session, et arrêt d'urgence accessible à l'opérateur à tout moment.
- **`reward_hacking`** — Ne pas optimiser une métrique unique. Auditer l'ÉCART entre la métrique et l'intention, et faire valider les résultats atypiques par un humain.
- **`agent_collusion`** — Cloisonner les agents : privilèges distincts, pas de canal latéral non journalisé, et journal d'audit central que les agents ne peuvent pas écrire.
- **`goal_drift`** — Ré-ancrer l'objectif à chaque cycle plutôt que de le laisser se reporter de tour en tour, où chaque reformulation éloigne un peu plus de la finalité.
- **`goal_propagation_attacks`** — Ne jamais accepter un objectif transmis par un autre agent sans le revalider contre la charte d'origine signée.

### Comment le détecter en production

- Nombre d'actions exécutées en dehors du manifeste comportemental signé de l'agent (invocations d'outils non approuvées)
- Détection de tentatives d'auto-réplication (spawning) non autorisées via API de provisioning
- Score de collusion : corrélation anormale entre les décisions de deux agents ou plus (signaux coordonnés)
- Nombre d'activations de kill-switch / mises en quarantaine par période
- Écart mesuré entre la métrique de récompense optimisée et l'objectif métier réel (proxy de reward hacking)

### Couverture par le framework

- **Comportementale** — DeepTeam (`OWASP_ASI_2026`), PyRIT multi-tours, Garak, payloads Microsoft Arcanum
- Agent : `agents.asi10_rogue_agents.ASI10RogueAgentsAgent`

<details><summary>Références officielles</summary>

- Multi-Agent Systems Execute Arbitrary Malicious Code (arXiv 2503.12188)
- Preventing Rogue Agents Improves Multi-Agent Collaboration (arXiv 2502.05986)

</details>

---
