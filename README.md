<div align="center">

# AI Security Audit Framework

**Audit de sécurité automatisé pour applications IA agentiques**
*OWASP Top 10 for Agentic Applications 2026 — ASI01 → ASI10*

[![Audit de sécurité IA](https://github.com/OT-Summer-internship-26/AI-Security-Validation-Framework-for-Agentic-Applications/actions/workflows/security_audit.yml/badge.svg)](https://github.com/OT-Summer-internship-26/AI-Security-Validation-Framework-for-Agentic-Applications/actions/workflows/security_audit.yml)
[![Images de conteneur](https://github.com/OT-Summer-internship-26/AI-Security-Validation-Framework-for-Agentic-Applications/actions/workflows/images.yml/badge.svg)](https://github.com/OT-Summer-internship-26/AI-Security-Validation-Framework-for-Agentic-Applications/actions/workflows/images.yml)
![Python](https://img.shields.io/badge/python-3.11-blue)
![Tests](https://img.shields.io/badge/tests-291%20passants-brightgreen)
![Mutation](https://img.shields.io/badge/mutation-23%2F23-brightgreen)
![Images](https://img.shields.io/badge/images-signées%20%2B%20SBOM-blueviolet)

Stage — Ooredoo Tunisie, Département Intelligence Artificielle

</div>

---

## Le problème

Un agent IA n'est pas une API comme une autre. Il suit des instructions, appelle des
outils, garde une mémoire — et chacune de ces capacités est une surface d'attaque que
les scanners classiques ne voient pas. Un pentest web ne dit rien d'un agent qu'on
convainc de virer de l'argent en lui parlant poliment.

Ce framework prend **n'importe quel agent exposé en HTTP**, l'attaque sur les 10
catégories OWASP ASI, produit un score et un rapport, et **bloque un déploiement** si
le résultat n'est pas acceptable.

```
Agent IA (URL)  ──▶  10 agents d'attaque  ──▶  score /100  ──▶  rapport  ──▶  gate CI/CD
                     ASI01 … ASI10                                            bloque ou laisse passer
```

## Pourquoi quatre axes d'attaque et pas un

La leçon vient d'une mesure, pas d'une intuition :

> Sur un laboratoire **démontrablement vulnérable**, DeepTeam seul donnait **10/10**.
> PyRIT (multi-tours) et Garak ont détourné le même agent → score final **6,0/10**,
> sous le seuil, déploiement bloqué.
>
> **Un seul axe aurait signé un faux « sûr ».**

La couche comportementale croise donc quatre sources indépendantes — DeepTeam `0.5`,
PyRIT `0.2`, Garak `0.2`, payloads Microsoft Arcanum `0.1`. Un axe indisponible vaut
`None` et sort de la pondération, renormalisée sur les axes restants : **une absence ne
devient jamais un 10/10**.

## Trois couches, parce que le comportement ne suffit pas

DeepTeam teste ce que la cible **répond**. Ça ne dit rien de ce que son code **est**, ni
de ce qu'il **ferait**.

| Couche | Outils | Question posée | Catégories |
|---|---|---|---|
| **Comportementale** | DeepTeam · PyRIT · Garak · Microsoft Arcanum | L'agent se laisse-t-il manipuler ? | ASI01 → ASI10 |
| **Statique** | Semgrep · pip-audit · 11 contrôles maison | Le code produit contient-il des motifs dangereux ? | ASI02, ASI04, ASI05 |
| **Dynamique** | Sandbox Docker (`--network none`, read-only, non-root) | Que fait *réellement* ce code une fois exécuté ? | ASI05 |

## Démarrage

### Docker — recommandé

```bash
python scripts/setup_docker.py     # une fois par machine : réseau, buildx, accès PyPI
cp .env.example .env               # au minimum : FRAMEWORK_API_KEY + une clé de modèle
docker compose up -d --build

curl http://localhost:8000/health  # API
open http://localhost:8080         # tableau de bord
```

Trois services démarrent : l'**API** qui orchestre, un **ouvrier** qui exécute les
audits hors du processus web, et le **tableau de bord**.

> ⚠️ **`FRAMEWORK_API_KEY` n'est pas optionnelle en production.** Sans elle, et tant
> qu'aucune clé n'existe en base, l'API accorde le rôle `admin` à un appelant anonyme —
> c'est le mode développement, assumé et documenté.

### Lancer un audit

```bash
# Créer une clé d'opérateur (l'admin est FRAMEWORK_API_KEY)
curl -X POST http://localhost:8000/keys -H "X-API-Key: $ADMIN" \
  -H "Content-Type: application/json" \
  -d '{"name":"equipe secu","role":"operator","expires_in_days":90}'

# Déposer un audit — l'API rend la main tout de suite, l'ouvrier exécute
curl -X POST http://localhost:8000/audits -H "X-API-Key: $CLE" \
  -H "Content-Type: application/json" \
  -d '{"mode":"targeted","category":"ASI_01","target_url":"http://cible/chat",
       "prompt_field":"message","response_field":"response","profile":"final"}'

curl http://localhost:8000/runs/$RUN_ID -H "X-API-Key: $CLE"
```

### Sans Docker — pour développer

```bash
pip install -r requirements.txt
pytest tests/ -q                                       # 291 tests, sans réseau ni LLM
python scripts/run_agent.py ASI_01 --profile dry_run   # doit rendre 5.57

python scripts/run_audit_global.py --target http://localhost:8090/api/chat --profile final
```

### Exploitation

```bash
python scripts/backup_volume.py --sauvegarder   # AVANT toute opération
python scripts/backup_volume.py --verifier      # à brancher sur la supervision
python scripts/mutation_check.py                # les tests protègent-ils vraiment ?
curl http://localhost:8000/metrics              # compteurs Prometheus
```

## Chaîne d'approvisionnement

La chaîne CI/CD ne se contente pas de construire : elle **éprouve l'objet qu'elle
livre**, puis le signe.

| Étape | Garantie |
|---|---|
| Construction | Image de base épinglée **par condensé** + `apt-get upgrade` à chaque push |
| Épreuve | Un **audit réel tourne dans l'image**, la suite hors-ligne aussi |
| Scan | Trivy **bloquant** sur HIGH/CRITICAL corrigeable — sans aucun `.trivyignore` |
| Inventaire | SBOM CycloneDX de l'image **testée** |
| Signature | `cosign` **par condensé**, SBOM **attesté** |
| Publication | GHCR — l'objet publié est celui qui a été éprouvé, jamais une reconstruction |
| Déploiement | Signature **vérifiée avant** de déployer ; sinon on ne déploie pas |

Vérification côté consommateur :

```bash
cosign verify --key cosign.pub --insecure-ignore-tlog=true <image>@<condensé>
cosign verify-attestation --key cosign.pub --type cyclonedx \
  --insecure-ignore-tlog=true <image>@<condensé>
```

> Cette barrière n'est pas décorative : à sa première exécution réelle, elle a arrêté la
> publication d'une image portant **12 vulnérabilités corrigeables** (9 HIGH, 3 CRITICAL)
> héritées de l'image de base.

## Qualité — chiffres mesurés

| Mesure | Valeur | Comment |
|---|---|---|
| Tests | **291 passants**, 5 ignorés | hors-ligne, ni réseau ni LLM |
| Mutation | **23 / 23** | chaque correctif est cassé, son test doit rougir |
| Agents ASI | **10 / 10** | chacun avec au moins un run réel |
| Audit global sur cible réelle | **oui** — `global_score: 72.8` | profil OpenAI, 2026-09-01 |
| Vérité terrain DVAP | **43 / 43** objectifs vérifiés | chaque citation confrontée à sa source |

Un test qui passe ne prouve rien tant qu'on ne l'a pas vu échouer :
`scripts/mutation_check.py` casse chaque correctif de sécurité et exige que son test
devienne rouge. Les auto-tests orphelins sont détectés automatiquement — la liste ne
s'étend pas toute seule, la découverte si.

## État du projet

| | Statut |
|---|---|
| 10 agents ASI01 → ASI10 | ✅ chacun avec au moins un run réel |
| Pipeline 3 couches, scoring /100, API, ouvrier, dashboard, rapport | ✅ |
| Audit global des 10 catégories sur cible réelle | ✅ `global_score: 72.8` |
| CI/CD — construction, épreuve, scan, signature, SBOM, publication | ✅ vert |
| Observabilité LangFuse | ✅ câblée *(inactive sans clés — par conception)* |
| Étude de validation DVAP | 🟡 **1 / 15** laboratoires — vérité terrain vérifiée |
| Déploiement automatisé | 🟡 écrit et testé, **inerte** sans les secrets `DEPLOY_*` |
| Licence | ⬜ à trancher — sans fichier `LICENSE`, « tous droits réservés » |

## Documentation

| Document | Contenu |
|---|---|
| [integration_guide.md](docs/integration_guide.md) | Utilisation, profils, lecture du score, CI/CD, déploiement |
| [architecture_technique.md](docs/architecture_technique.md) | Architecture, choix de conception, contraintes de déploiement |
| [journal_decisions_techniques.md](docs/journal_decisions_techniques.md) | Chaque décision technique et **sa raison** |
| [ci_limites_connues.md](docs/ci_limites_connues.md) | **Ce que la CI ne couvre pas** — registre daté, fermetures tracées |
| [etude_validation_dvap.md](docs/etude_validation_dvap.md) | Mesure du *framework* lui-même contre des failles connues |
| [evaluation_qualite.md](docs/evaluation_qualite.md) | Couverture, mutation, maintenabilité |
| [agentic_architecture_analysis.md](docs/agentic_architecture_analysis.md) | Les 13 composants d'une application agentique et leurs surfaces |
| [security_best_practices.md](docs/security_best_practices.md) | Contre-mesures par catégorie *(généré depuis la KB)* |
| [garak_isolated_env.md](docs/garak_isolated_env.md) | Pourquoi garak vit dans un environnement isolé |
| [REPRISE.md](docs/REPRISE.md) | Point de reprise : état mesuré, ce qui reste, faiblesses nommées |
| [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | Composants tiers embarqués et leurs licences |
| [config/owasp_knowledge_base.json](config/owasp_knowledge_base.json) | Base de connaissances OWASP ASI01 → ASI10 |
| [config/threat_mapping.json](config/threat_mapping.json) | Cartographie menaces ↔ contexte opérateur télécom |

## Limites assumées

Elles sont **écrites**, pas tues — un outil de sécurité qui cache ses angles morts est
plus dangereux qu'un outil absent.

- **L'audit est en boîte noire.** Le pipeline RAG, la mémoire persistante et
  l'observabilité de la cible sont hors d'atteinte. Les métriques d'usage d'outils sont
  dégradées si la cible n'expose pas ses appels.
- **Les données auditées sortent vers un fournisseur tiers** (profils `final` /
  `openai`). À arbitrer avant toute cible interne — voir *Contraintes de déploiement*
  dans l'architecture technique.
- **Le score est un tirage, pas une mesure.** Les attaques multi-tours sont aléatoires :
  deux exécutions donnent des chiffres différents.
- **Le multi-tours n'atteint pas la cible avec son historique** — `CrescendoJailbreaking`
  et `ContextPoisoning` sont dégradés en mono-tour côté cible. La limite est *affichée*
  dans le rapport et le dashboard, elle n'est pas *levée*.
- **`api/main.py` : 1495 lignes, 50 % de couverture.** C'est le point faible structurel
  du dépôt, et il est nommé.

Détail complet : [section Limites du guide](docs/integration_guide.md#7-limites-assumées)
et [registre CI](docs/ci_limites_connues.md).
