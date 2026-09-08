# AI Security Audit Framework

> Framework automatisé d'audit de sécurité pour applications IA agentiques,
> basé sur **OWASP Top 10 for Agentic Applications 2026 (ASI01 → ASI10)**.

Stage — Ooredoo Tunisie, Département Intelligence Artificielle.

---

## Ce que ça fait

Prend n'importe quel agent IA exposé en HTTP, l'attaque sur les 10 catégories de
risques agentiques, produit un score et un rapport, et bloque un déploiement en CI/CD
si le résultat n'est pas acceptable.

```
Agent IA (URL) ──▶ 10 agents de sécurité ──▶ score /100 ──▶ rapport HTML ──▶ gate CI/CD
```

## Démarrage

### Avec Docker — la façon recommandée

```bash
# 1. Préparer Docker (une fois par machine). Crée le réseau IPv6 et le
#    constructeur buildx, puis VÉRIFIE qu'une construction joint bien PyPI.
python scripts/setup_docker.py

# 2. Configurer
cp .env.example .env          # y mettre au moins une clé de modèle

# 3. Lancer
docker compose up -d --build

# 4. Vérifier
curl http://localhost:8000/health
open http://localhost:8080                # tableau de bord
```

Trois services démarrent : l'**API** qui orchestre, un **ouvrier** qui exécute
les audits hors du processus web, et le **tableau de bord**.

### Lancer un audit

```bash
# Créer une clé d'opérateur (l'admin utilise FRAMEWORK_API_KEY)
curl -X POST http://localhost:8000/keys -H "X-API-Key: $ADMIN"      -H "Content-Type: application/json"      -d '{"name":"equipe secu","role":"operator","expires_in_days":90}'

# Déposer un audit — l'API rend la main tout de suite, l'ouvrier exécute
curl -X POST http://localhost:8000/audits -H "X-API-Key: $CLE"      -H "Content-Type: application/json"      -d '{"mode":"targeted","category":"ASI_01","target_url":"http://cible/chat",
          "prompt_field":"message","response_field":"response","profile":"openai"}'

# Suivre
curl http://localhost:8000/runs/$RUN_ID
```

### Sans Docker — pour développer

```bash
pip install -r requirements.txt
pytest tests/ -q                                   # 208 tests, sans réseau ni LLM
python scripts/run_agent.py ASI_01 --profile dry_run   # doit rendre 5.57
```

### Exploitation

```bash
python scripts/backup_volume.py --sauvegarder   # AVANT toute operation
python scripts/mutation_check.py                # les tests protegent-ils vraiment ?
curl http://localhost:8000/metrics              # compteurs Prometheus
```

> **Avant une mise en production**, lire la section « Contraintes de
> déploiement » de [docs/architecture_technique.md](docs/architecture_technique.md).
> Elle dit ce qui bloque, ce qui est une décision, et ce qui est déjà résolu —
> à commencer par le fait que **les données auditées sortent vers un fournisseur
> tiers**.

## Comment ça marche

### Trois couches de test

DeepTeam ne teste que le **comportement** de la cible. Ça ne dit pas si son code est
dangereux, ni ce que ce code ferait réellement. D'où deux couches supplémentaires :

| Couche | Outils | Ce qu'elle teste | Catégories |
|---|---|---|---|
| Comportementale | DeepTeam, PyRIT, Garak, payloads Microsoft Arcanum | L'agent se laisse-t-il manipuler ? | ASI01 → ASI10 |
| Statique | Semgrep, pip-audit | Patterns dangereux, CVE des dépendances | ASI02, ASI04, ASI05 |
| Dynamique | Sandbox Docker (`--network none`, read-only, non-root) | Que fait *réellement* le code produit ? | ASI05 |

### Quatre axes, pas un seul

La couche comportementale croise quatre sources d'attaque indépendantes
(DeepTeam 0.5 · PyRIT 0.2 · Garak 0.2 · Microsoft 0.1). Ce n'est pas de la
redondance — c'est la leçon d'un run réel :

> Sur un lab démontrablement vulnérable, **DeepTeam seul donnait 10/10**.
> PyRIT (multi-tours) et Garak ont détourné le même agent → score final **6,0/10**,
> sous le seuil, déploiement bloqué. Un seul axe aurait signé un faux « sûr ».

Un axe indisponible vaut `None` et sort de la pondération, renormalisée sur les axes
restants : **une absence ne devient jamais un 10/10**.

## Quick start

```bash
pip install -r requirements.txt
cp .env.example .env          # renseigner les clés

# une catégorie
python scripts/run_agent.py ASI_01 --target http://localhost:8090/api/chat \
  --prompt-field message --response-field response --profile final

# les 10 catégories → score /100
python scripts/run_audit_global.py --target http://localhost:8090/api/chat --profile final

# API + dashboard
uvicorn api.main:app --reload
```

Installation complète, profils LLM, options et intégration CI/CD :
**[docs/integration_guide.md](docs/integration_guide.md)**.

## Documentation

| Document | Contenu |
|---|---|
| [docs/agentic_architecture_analysis.md](docs/agentic_architecture_analysis.md) | Les 13 composants d'une application agentique et leurs surfaces d'attaque |
| [docs/security_best_practices.md](docs/security_best_practices.md) | Catalogue des contre-mesures par catégorie *(généré depuis la KB)* |
| [docs/integration_guide.md](docs/integration_guide.md) | Utilisation, lecture du score, CI/CD, déploiement, limites |
| [docs/architecture_technique.md](docs/architecture_technique.md) | Architecture, choix de conception, contraintes de déploiement |
| [docs/ci_limites_connues.md](docs/ci_limites_connues.md) | **Ce que la chaîne CI/CD ne couvre pas** — registre tenu à jour, fermetures datées |
| [docs/evaluation_qualite.md](docs/evaluation_qualite.md) | Mesures de qualité : couverture, mutation, maintenabilité |
| [docs/etude_validation_dvap.md](docs/etude_validation_dvap.md) | Étude de validation contre les laboratoires DVAP |
| [docs/garak_isolated_env.md](docs/garak_isolated_env.md) | Pourquoi garak vit dans un environnement isolé |
| [config/owasp_knowledge_base.json](config/owasp_knowledge_base.json) | Base de connaissances OWASP ASI01→ASI10 |
| [config/threat_mapping.json](config/threat_mapping.json) | Cartographie menaces ↔ contexte opérateur télécom |
| [docs/journal_decisions_techniques.md](docs/journal_decisions_techniques.md) | Journal de conception : chaque décision technique et sa raison |

## État

| | Statut |
|---|---|
| 10 agents ASI01→ASI10 | ✅ construits, chacun avec au moins un run réel |
| Pipeline 3 couches, scoring /100, API, dashboard, rapport HTML | ✅ |
| CI/CD (axes déterministes + politique de blocage versionnée) | ✅ |
| Audit global des 10 catégories sur une cible réelle | ⬜ jamais lancé |
| Étude de validation (précision / rappel sur les labs DVAP) | ⬜ |
| `judge/cross_validation.py`, `judge/recommendation_engine.py` | ⬜ stubs |
| Observabilité LangFuse | ⬜ non câblée |

**À lire avant d'interpréter un score.** L'audit est en boîte noire : le pipeline RAG,
la mémoire persistante et l'observabilité de la cible sont hors d'atteinte, et les
métriques d'usage d'outils sont dégradées si la cible n'expose pas ses appels. Le détail
est dans [la section Limites du guide](docs/integration_guide.md#7-limites-assumées).
