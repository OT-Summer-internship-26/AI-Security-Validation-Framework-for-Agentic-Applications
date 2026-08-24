# Analyse d'architecture agentique — surfaces d'attaque par composant

> **Livrable #1 (volet architecture).** Décomposition d'une application IA agentique
> en composants, et pour chacun : ce qui constitue une surface d'attaque, quelles
> catégories OWASP ASI s'y appliquent, et ce que l'audit boîte noire peut réellement
> en observer.

---

## Pourquoi décomposer par composant et pas par catégorie

Le référentiel OWASP classe les **risques**. Un développeur, lui, corrige un
**composant**. Les deux vues ne se recouvrent pas : ASI01 (détournement d'objectif)
touche le canal d'entrée, le RAG, la mémoire *et* le bus inter-agents ; inversement
la couche « outils » concentre à elle seule ASI02, ASI04 et ASI05.

Ce document est la traduction entre les deux. Il sert aussi à cadrer honnêtement ce
que l'audit voit : le framework s'adresse à la cible par **un seul endpoint HTTP**,
donc certaines surfaces sont testées de l'extérieur, et d'autres pas du tout.

---

## Vue d'ensemble

```
                        ┌─────────────────────────────────┐
   utilisateur ────────▶│  1. Canal d'entrée              │
   (ou système amont)   └───────────────┬─────────────────┘
                                        ▼
   ┌──────────────┐      ┌──────────────────────────────┐      ┌──────────────┐
   │ 5. RAG / KB  │─────▶│  3. Prompt système + garde-  │◀─────│ 4. Mémoire   │
   └──────────────┘      │     fous  ·  2. Modèle LLM   │      └──────────────┘
                         └───────────────┬──────────────┘
                                         ▼
                         ┌──────────────────────────────┐
                         │  6. Orchestrateur / planif.  │
                         └───┬───────────┬───────────┬──┘
                             ▼           ▼           ▼
                     ┌────────────┐ ┌─────────┐ ┌──────────────┐
                     │ 7. Outils  │ │ 8. Bus  │ │ 9. Exécution │
                     │   / MCP    │ │ inter-  │ │    de code   │
                     └─────┬──────┘ │ agents  │ └──────────────┘
                           │        └─────────┘
                           ▼
                  ┌─────────────────┐        ┌──────────────────────┐
                  │ 10. Identité &  │        │ 11. Chaîne d'appro.  │
                  │  autorisations  │        │ (deps, modèles, reg.)│
                  └─────────────────┘        └──────────────────────┘
                           │
                           ▼
                  ┌─────────────────┐        ┌──────────────────────┐
                  │ 12. Sortie vers │        │ 13. Observabilité    │
                  │    l'humain     │        │      / journaux      │
                  └─────────────────┘        └──────────────────────┘
```

| # | Composant | Catégories ASI | Vu par l'audit boîte noire |
|---|---|---|---|
| 1 | Canal d'entrée | ASI01 | ✅ intégralement |
| 2 | Modèle LLM | ASI01, ASI06, ASI09 | ⚠️ par son comportement seulement |
| 3 | Prompt système / garde-fous | ASI01, ASI03 | ⚠️ par extraction |
| 4 | Mémoire | ASI06 | ⚠️ en simulation |
| 5 | RAG / base de connaissances | ASI01, ASI06 | ❌ canal non atteignable |
| 6 | Orchestrateur / planificateur | ASI01, ASI08, ASI10 | ⚠️ par ses effets |
| 7 | Outils / function calling / MCP | ASI02, ASI04 | ⚠️ sans `tools_called` |
| 8 | Bus inter-agents | ASI07 | ✅ côté récepteur |
| 9 | Exécution de code | ASI05 | ✅ y compris exécution réelle |
| 10 | Identité & autorisations | ASI03 | ⚠️ sans signal d'outil |
| 11 | Chaîne d'approvisionnement | ASI04 | ✅ si le code source est fourni |
| 12 | Sortie vers l'humain | ASI09 | ✅ intégralement |
| 13 | Observabilité | transverse | ❌ hors périmètre |

---

## 1. Canal d'entrée

**Surface.** Tout ce qui entre en langage naturel. La vulnérabilité fondatrice de
l'agentique est structurelle : dans un flux de texte, rien ne distingue une
*instruction* d'une *donnée*. Un agent qui lit « ignore tes consignes » ne peut pas
savoir si c'est un ordre ou une citation.

**ASI.** ASI01 principalement ; c'est aussi le vecteur d'entrée de presque toutes
les autres chaînes d'attaque.

**Audit.** Surface la mieux couverte : c'est le canal même de l'audit. DeepTeam,
PyRIT (multi-tours adaptatif), Garak et les payloads Microsoft y passent tous.

**Contre-mesure.** Traiter toute entrée comme non fiable, y compris celle qui vient
d'un système interne. Le catalogue détaillé : [security_best_practices.md](security_best_practices.md).

---

## 2. Modèle LLM

**Surface.** Le modèle lui-même : sa tendance à obéir, à halluciner une expertise,
à céder sous une pression progressive. Un même prompt système donne des garanties
très différentes selon le modèle qui l'exécute.

**ASI.** ASI01 (obéissance), ASI06 (surconfiance dans le contexte fourni), ASI09
(fausse expertise, ton autoritaire).

**Audit.** Observable uniquement par le comportement. Le framework ne connaît ni les
poids, ni la température, ni le fournisseur. **Conséquence pratique :** un changement
de modèle en production invalide l'audit précédent — il faut re-auditer.

---

## 3. Prompt système et garde-fous

**Surface.** Le prompt système contient souvent le périmètre, les règles métier et
parfois des secrets. Deux risques distincts : son **extraction** (il révèle la
logique de défense), et son **contournement**.

**ASI.** ASI03 (`PromptLeakage` : secrets, rôles, garde-fous exposés), ASI01.

**Audit.** Testé par sondage (`PromptProbing`). Une extraction réussie est un
résultat exploitable ; une extraction ratée ne prouve rien sur la solidité des règles.

**Contre-mesure.** Ne jamais faire porter au prompt une décision d'autorisation :
le prompt est une consigne, pas un contrôle d'accès. Les secrets n'y ont pas leur place.

---

## 4. Mémoire (court terme et persistante)

**Surface.** Ce qui distingue la mémoire du prompt, c'est la **persistance**. Une
mémoire corrompue rejoue l'erreur à chaque session suivante, pour tous les
utilisateurs, sans nouvelle attaque. Le coût d'une compromission unique se
multiplie dans le temps.

**ASI.** ASI06.

**Audit — limite assumée.** Testé **en simulation** : la charge est placée dans le
prompt (attaque `ContextPoisoning`). Empoisonner la vraie mémoire persistante
exigerait un hook d'écriture sur la cible (`config["memory_inject"]`), hors du
périmètre boîte noire. Un agent peut donc réussir ASI06 et rester vulnérable à un
empoisonnement par son magasin de mémoire réel.

**Contre-mesure.** Empreinte cryptographique par entrée, piste d'audit sur chaque
écriture, détection de motifs d'injection et d'Unicode malveillant à l'écriture —
mécanismes documentés dans `docs/references/memory_guard_reference.py`.

---

## 5. RAG / base de connaissances

**Surface.** La plus dangereuse en pratique, parce que l'attaquant n'a pas besoin de
parler à l'agent : il empoisonne un document que l'agent **ira lire de lui-même**.
C'est le mécanisme des scénarios EchoLeak et AgentFlayer.

**ASI.** ASI01 (injection indirecte), ASI06 (persistance).

**Audit — limite assumée.** ❌ **Le framework ne peut pas empoisonner ce canal.** Il
n'a accès ni à l'indexeur, ni au magasin vectoriel, ni aux sources ingérées. La
vulnérabilité `IndirectInstruction` de DeepTeam délivre sa charge dans le **texte du
prompt** — c'est une approximation, pas une injection indirecte réelle.

**Ce que ça implique.** Un score ASI01 excellent ne dit **rien** sur la robustesse du
pipeline d'ingestion. Cette surface se traite par revue d'architecture, pas par cet audit.

---

## 6. Orchestrateur / planificateur

**Surface.** Le composant qui décide de la séquence d'actions. Trois défauts
distincts : accepter une entrée amont sans la valider (propagation), agir sans point
d'arrêt (emballement), et laisser l'objectif se réécrire (dérive).

**ASI.** ASI08 (cascade), ASI10 (dérive auto-entretenue), ASI01 (détournement ponctuel).

**Audit — limite assumée.** ⚠️ L'audit ne voit qu'**un maillon**. Il vérifie si la
cible valide son amont et si elle agit ensuite de son propre chef, mais il ne peut
pas mettre en scène une cascade réelle entre N agents, ni observer une dérive qui se
mesure en jours.

**La distinction à retenir.** ASI01 : retirez l'attaquant, l'agent revient à sa tâche.
ASI10 : la déviation persiste sans lui. C'est la persistance qui fait le « rogue »,
pas l'ampleur de l'écart initial.

---

## 7. Outils / function calling / MCP

**Surface.** C'est ici que la conversation devient **action sur le système
d'information**. Trois surfaces empilées : l'outil lui-même (que fait-il vraiment ?),
sa **description** (le schéma ment-il sur son comportement ?), et l'enchaînement
(peut-on composer des appels légitimes pour un effet illégitime ?).

**ASI.** ASI02 (abus), ASI04 (métadonnées empoisonnées, registre), ASI05 (si l'outil exécute du code).

**Audit — limite assumée.** ⚠️ Les métriques `ExcessiveAgency`, `BFLA` et
`ToolOrchestrationAbuse` lisent le champ `tools_called`. La plupart des cibles ne
l'exposent pas : le jugement se fait alors sur le **texte** de la réponse. Le rapport
le signale (`raw["behavioral_note"]`, compteur `tools_called_seen`). Pour un audit
fidèle, câbler `build_http_callback(tools_field=…)`.

**Contre-mesure.** Un contrôle porté par l'interface conversationnelle n'est pas un
contrôle : il doit vivre dans l'API appelée, qui ne fait pas confiance à l'agent.

---

## 8. Bus inter-agents

**Surface.** Dès qu'un orchestrateur délègue, l'**identité de l'émetteur devient un
contrôle de sécurité**. Un message non signé prétendant venir d'un agent de confiance
suffit à déclencher une action privilégiée.

**ASI.** ASI07.

**Audit.** ✅ Testé du côté **récepteur** : l'audit s'adresse à la cible en se faisant
passer pour un pair (enveloppe non signée `peer_identity`, ou champ protocolaire natif
de la cible). Si elle exécute sans vérifier, l'usurpation est démontrée.

**Limite assumée.** L'agent-en-milieu (relais entre deux agents réels) n'est pas
testable : il faudrait instrumenter le bus de la cible.

**Contre-mesure.** Signer les messages, et ne jamais dériver un niveau de confiance
d'un champ auto-déclaré (`from_agent`, `trust_level`).

---

## 9. Exécution de code

**Surface.** La seule catégorie où l'écart entre « l'agent a accepté » et « le code a
réellement agi » peut être mesuré. Un agent qui accepte d'écrire un script dangereux
n'est pas encore une RCE ; un script exécuté sans isolation, si.

**ASI.** ASI05.

**Audit.** ✅ La seule surface couverte par les **trois couches** : comportementale
(l'agent accepte-t-il ?), statique (Semgrep + les 11 contrôles Microsoft sur le code
source), dynamique (**le code produit est réellement exécuté** dans un conteneur
éphémère `--network none`, read-only, non-root, avec limites CPU/mémoire et timeout).

**Limite.** Sans Docker, repli sur un bac à sable sous-processus : il isole le
processus et les ressources, mais **pas** le réseau ni le système de fichiers.
Le provider réellement utilisé est tracé dans `raw["sandbox_provider"]`.

---

## 10. Identité et autorisations

**Surface.** Deux questions séparées et souvent confondues : *au nom de qui* l'agent
agit-il (identité déléguée), et *jusqu'où* peut-il aller (privilèges). Un agent qui
hérite des droits d'un administrateur pour rendre service à un utilisateur standard
détruit toute la chaîne d'autorisation.

**ASI.** ASI03 (BOLA, RBAC, usurpation d'identité d'agent, héritage de privilèges).

**Audit — limite assumée.** ⚠️ Même dépendance à `tools_called` que le composant 7 :
sans lui, l'audit constate ce que l'agent *dit* faire, pas ce qu'il *fait*.

**Contre-mesure.** Le privilège minimal par tâche, pas par agent ; l'autorisation
vérifiée côté ressource, jamais déduite du contexte conversationnel.

---

## 11. Chaîne d'approvisionnement

**Surface.** Modèles téléchargés, dépendances, serveurs MCP, registres d'outils,
fichiers de configuration. Sa particularité : le rayon d'action ne dépend pas du cas
d'usage mais du **nombre d'agents partageant le composant**.

**ASI.** ASI04.

**Audit.** ✅ Couverture réelle et **déterministe** dès que le code source est fourni :
`pip-audit` (CVE des dépendances) et Semgrep. Ce sont les seuls axes dont le résultat
ne dépend d'aucun LLM — donc reproductibles, donc utilisables comme critère de blocage en CI.

---

## 12. Sortie vers l'humain

**Surface.** L'abus ne vise pas le système mais la **personne**. Un agent portant la
marque d'une entreprise est cru par construction : une consigne de paiement ou un
lien venant de lui a une force de conviction qu'un canal tiers n'a pas.

**ASI.** ASI09.

**Audit.** ✅ Bien couvert, y compris par les payloads Microsoft les mieux alignés du
jeu (détournement de paiement, usurpation d'interlocuteur prioritaire, prétexte
d'urgence, lien d'hameçonnage).

**Le critère qui compte.** Ce n'est pas que l'agent ait tort, c'est qu'il soit **cru**.
D'où la gravité maximale sur la fausse expertise revendiquée, et une gravité moindre
sur une affirmation fausse sans autorité invoquée — l'utilisateur garde la possibilité
de douter.

---

## 13. Observabilité et journaux

**Surface.** Sans trace des décisions et des appels d'outils, aucune enquête n'est
possible après incident — et une dérive lente reste invisible jusqu'à ses effets.

**ASI.** Transverse : c'est la condition de détection de toutes les catégories.

**Audit.** ❌ Hors périmètre : l'audit teste la résistance, pas la capacité de détection.

**Contre-mesure.** Les métriques à instrumenter sont listées par catégorie dans
[security_best_practices.md](security_best_practices.md), section « Comment le
détecter en production ».

---

## Ce que cette analyse implique pour la lecture d'un rapport

Trois surfaces majeures — le **pipeline RAG** (5), la **mémoire persistante** (4) et
l'**observabilité** (13) — sont hors d'atteinte d'un audit boîte noire, et deux autres
(7, 10) sont dégradées tant que la cible n'expose pas ses appels d'outils.

Un bon score n'est donc pas un certificat : c'est le résultat d'une pression exercée
sur les surfaces atteignables depuis un endpoint HTTP. Les surfaces restantes relèvent
de la revue d'architecture et de l'instrumentation, pas du test dynamique.
