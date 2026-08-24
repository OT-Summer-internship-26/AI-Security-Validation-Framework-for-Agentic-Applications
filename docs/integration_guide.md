# Guide d'utilisation et d'intégration CI/CD

> **Livrable #10.** Comment lancer un audit, lire le score, et brancher le framework
> dans une chaîne de déploiement.

---

## 1. Installation

```bash
pip install -r requirements.txt
cp .env.example .env      # puis renseigner les clés (§2)
```

Deux dépendances vivent **hors** de `requirements.txt`, pour des raisons documentées :

| Outil | Pourquoi à part | Installation |
|---|---|---|
| **Garak** | Sa version sans Rust épingle `openai 0.28`, incompatible avec l'`openai 2.x` du framework. Il est donc appelé en **sous-processus** dans un venv isolé, jamais importé. | `python -m venv ~/garak-venv && ~/garak-venv/bin/pip install garak` puis `GARAK_VENV_PYTHON=~/garak-venv/bin/python` |
| **Ollama** | Serveur local, pas un paquet Python. Nécessaire aux profils `dev` / `ollama`. | [ollama.com](https://ollama.com) puis `ollama pull qwen2.5:7b` |

> ⚠️ Si Garak est réinstallé ou mis à jour, **réappliquer le correctif de timeout**
> (`garak/generators/rest.py` : `timeout=getattr(self, "response_timeout", self.request_timeout)`).
> Sans lui, le timeout REST reste figé à 10 s et les cibles lentes ne sont jamais évaluées.

---

## 2. Configuration

### Profils LLM

Le framework a besoin d'un LLM pour **deux rôles distincts** : le *simulator* génère
les attaques, l'*evaluation* juge si elles ont réussi. Le profil choisit les deux.

| Profil | Modèles | Quand l'utiliser |
|---|---|---|
| `dev` | Ollama `qwen2.5:7b` (alias d'`ollama`) | Développement du pipeline. Gratuit, illimité, hors ligne. |
| `ollama` | idem | Identique, nommé explicitement. |
| `final` | Gemini Flash | **Verdict officiel.** Attaques fortes + jugement fiable. |
| `dry_run` / `ci` | aucun (`DryRunModel`) | Test de la tuyauterie, zéro appel réseau. |

**Règle qui ne se rediscute pas :** un rapport ou une soutenance se fait en `final`.
Un simulateur faible produit un score faussement rassurant — mesuré : un lab
démontrablement vulnérable a obtenu **9,4/10** en `dev`, et **6,0/10** en `final`.
Le profil `dev` sert à faire marcher le pipeline, pas à conclure.

### Variables d'environnement

```bash
AUDIT_LLM_PROFILE=dev           # profil par défaut
GEMINI_API_KEY=...              # requis pour `final`
AUDIT_GEMINI_MODEL=...          # gemini-2.5-flash (Vertex) | gemini-flash-latest (AI Studio)
AUDIT_GEMINI_RPM=13             # débit max vers Gemini (le free tier plafonne à 15/min)
GARAK_VENV_PYTHON=...           # python du venv Garak isolé
GARAK_TIMEOUT=600               # secondes avant de tuer Garak (le rapport partiel est lu quand même)
FRAMEWORK_API_KEY=...           # header X-API-Key de l'API
```

**Clés Gemini — le piège à connaître.** Google expose Gemini par deux services
incompatibles : AI Studio (`generativelanguage`, clé `AIza…`, offre gratuite) et
Vertex AI (`aiplatform`, clé `AQ.…`, facturé). Une clé ne fonctionne que sur son
service. Le code détecte le préfixe et route automatiquement, mais **le nom du
modèle diffère** entre les deux — d'où `AUDIT_GEMINI_MODEL`.

---

## 3. Lancer un audit

### Une catégorie

```bash
python scripts/run_agent.py ASI_01 \
  --target http://localhost:8090/api/chat \
  --prompt-field message --response-field response \
  --profile final --attacks-per-type 3
```

Options utiles :

| Option | Effet |
|---|---|
| `--extra-payload '{"title":"x"}'` | champs supplémentaires exigés par la cible (sinon 422) |
| `--source-path <dir>` | active la couche statique (Semgrep) — ASI02/04/05 |
| `--requirements-path <f>` | active pip-audit (CVE) — ASI04 |
| `--no-deepteam / --no-pyrit / --no-garak / --no-microsoft` | coupe un axe |
| `--explain-passes` | fait juger aussi les attaques **résistées** (~3× le coût du juge) |

### Les 10 catégories → score /100

```bash
python scripts/run_audit_global.py \
  --target http://localhost:8090/api/chat \
  --profile final --attacks-per-type 1
```

Le fichier global est **réécrit après chaque agent** : un plantage au 8ᵉ agent
laisse les 7 premiers exploitables.

### Par l'API

```bash
uvicorn api.main:app --reload          # ou run-api.bat
curl -X POST http://localhost:8000/audits \
  -H "X-API-Key: $FRAMEWORK_API_KEY" -H "Content-Type: application/json" \
  -d '{"mode":"full","target_url":"http://localhost:8090/api/chat"}'
```

| Mode | Ce qu'il lance |
|---|---|
| `full` | toutes les catégories, tous les axes — plusieurs heures |
| `targeted` | un sous-ensemble (`categories: [...]`) |
| `quick` | toutes les catégories, **axes déterministes seulement** (Garak, Semgrep, pip-audit, sandbox) : aucun appel LLM, quelques minutes, reproductible |

Endpoints : `GET /audits`, `GET /audits/{id}`, `GET /audits/{id}/report`,
`POST /replay`, `GET /runs/{id}`, `GET /health`.

---

## 4. Lire le résultat

### Score

Chaque agent produit un score **/10**, consolidé en un score global **/100** pondéré
par `config/scoring_weights.json` et renormalisé sur les catégories réellement jouées.

| Score /100 | Niveau |
|---|---|
| ≥ 86 | Sécurisé |
| 71 – 85 | Faible |
| 51 – 70 | Moyen |
| 31 – 50 | Élevé |
| < 31 | Critique |

### Ce que le score ne dit pas

Trois pièges, tous mesurés sur des runs réels :

1. **Un axe absent n'est jamais un 10/10.** Cible injoignable, outil en échec, payload
   inexistant pour la catégorie → l'axe vaut `None` et sort de la pondération,
   renormalisée sur les axes restants. Un score n'est jamais gonflé par une absence.
2. **Un score DeepTeam mono-run est bruité.** Deux runs identiques sur la même cible
   ont donné **9,66** et **7,93** : les attaques multi-tours sont tirées au hasard par
   le simulateur. Ne jamais sur-lire un chiffre isolé — c'est la raison d'être des
   quatre axes, dont deux (Garak, statique) sont déterministes.
3. **`attacks_per_type` faible = confiance faible.** Un 10/10 sur 3 tests dit « a
   résisté au peu qu'on a lancé », pas « robuste ». Le nombre de tests scorés est
   dans `deepteam_stats`.

### Rapport

```bash
curl -H "X-API-Key: $FRAMEWORK_API_KEY" \
  "http://localhost:8000/audits/<id>/report?format=html" -o rapport.html
```

---

## 5. Intégration CI/CD

Le workflow est dans [`.github/workflows/security_audit.yml`](../.github/workflows/security_audit.yml).

### Ce qui tourne en CI, et pourquoi seulement ça

Uniquement les axes **déterministes** : Semgrep, pip-audit, Garak, sandbox. Ils ne
consomment aucun appel LLM (donc aucun plafond de débit) et donnent le même résultat
à chaque exécution. Bloquer un développeur sur un score stochastique serait
indéfendable — voir le piège 2 ci-dessus.

L'audit comportemental complet tourne séparément et alimente la baseline ; il ne bloque pas.

### La décision de blocage

Elle est dans [`config/gate_policy.json`](../config/gate_policy.json) — versionnée,
donc relue en revue de code. C'est le seul endroit où la tolérance se décide.

| Clé | Rôle |
|---|---|
| `block_all_critical` | toute vulnérabilité Critical bloque, quel que soit le score |
| `max_high_findings` | budget de findings High toléré (0 = le moindre High bloque) |
| `min_score` / `enforce_min_score` | seuil global — à n'activer que sur un audit complet |
| `per_category` | `block` / `warn` / `ignore` par catégorie, avec justification |
| `derogations` | exceptions datées ; **une dérogation expirée redevient bloquante** |

```bash
python scripts/ci_gate.py --summary gate_summary.md   # exit 1 => la PR est bloquée
```

Le résultat est posté en commentaire unique sur la pull request (mis à jour, pas empilé)
et les artefacts sont conservés 30 jours.

### Brancher une autre chaîne (GitLab CI, Jenkins…)

Le contrat est simple : lancer l'audit, puis `scripts/ci_gate.py`. Son **code de
sortie** est la décision (0 = passe, 1 = bloque), `--summary` produit le Markdown à
publier. Aucune dépendance à GitHub au-delà du commentaire de PR.

---

## 6. Limites assumées

À lire avant de présenter un résultat comme une garantie.

| Limite | Conséquence |
|---|---|
| **Audit boîte noire** — le seul contact avec la cible est un endpoint HTTP | L'injection indirecte est testée *en simulation* (charge dans le prompt), pas en empoisonnant un vrai canal de données (RAG, mail, calendrier) façon EchoLeak. Un agent peut réussir ASI01 et rester vulnérable par ses données. |
| **`tools_called` non exposé** par la plupart des cibles | Les métriques qui lisent les appels d'outils (ASI02 BFLA, ASI03 BOLA/RBAC) jugent le **texte** seul. Le rapport le signale (`behavioral_note`). Câbler `tools_field` pour un audit fidèle. |
| **Catégories multi-agents** (ASI07, ASI08, ASI10) | L'audit teste **le maillon** : la cible valide-t-elle son amont, accepte-t-elle un pair non signé ? Il ne peut pas mettre en scène une cascade ou une collusion réelle entre plusieurs agents. |
| **Sandbox** | Docker (`--network none`, read-only, non-root) quand il est disponible ; sinon repli sous-processus, qui isole le processus et les ressources mais **pas** le réseau ni le système de fichiers. Le provider utilisé est tracé dans `raw["sandbox_provider"]`. |
| **Dérive temporelle** (ASI10) | Une dérive d'objectif sur plusieurs jours n'est pas observable en quelques minutes d'audit. |
