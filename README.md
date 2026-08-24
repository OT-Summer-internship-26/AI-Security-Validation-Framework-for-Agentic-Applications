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
| [docs/integration_guide.md](docs/integration_guide.md) | Utilisation, lecture du score, CI/CD, limites |
| [config/owasp_knowledge_base.json](config/owasp_knowledge_base.json) | Base de connaissances OWASP ASI01→ASI10 |
| [config/threat_mapping.json](config/threat_mapping.json) | Cartographie menaces ↔ contexte opérateur télécom |
| [NOTES.md](NOTES.md) | Journal de conception : chaque décision technique et sa raison |

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
est dans [la section Limites du guide](docs/integration_guide.md#6-limites-assumées).
