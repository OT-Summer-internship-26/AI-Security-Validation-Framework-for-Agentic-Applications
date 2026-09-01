# Point de reprise — 2026-09-01

Document de passation. Il dit **où on s'est arrêté**, **pourquoi**, et **par quoi
reprendre**. À supprimer une fois le point 1 traité.

---

## 🔴 Le sujet en cours : deux axes d'audit manquent dans l'image Docker

**Constaté en lançant un audit ASI_02 réel par l'API, dans la pile conteneurisée :**

```
comportementale score=0  error=No module named 'pyrit'
→ agent ASI_02 : not_measured, 0 constat, 0 appel LLM
```

### La cause

`pyrit` et `garak` n'ont **jamais figuré dans `requirements.txt`**. Ils avaient
été installés à la main pendant le développement (`pip install pyrit`, et garak
dans un venv isolé `~/garak-venv`). Sur le poste, tout marchait. Dans l'image,
ils sont absents.

Vérifié dans le conteneur :

| Module | État dans l'image |
|---|---|
| `deepteam` | ✅ |
| `semgrep` | ✅ |
| `pyrit` | ❌ absent |
| `garak` | ❌ absent |

### Pourquoi c'est grave

Ce sont **les deux axes qui ont détecté un détournement là où DeepTeam rendait
10/10**. Une image sans eux est un auditeur dégradé — et elle ne le dit pas :
elle rend `not_measured`, ce qui est honnête, mais un exploitant croira à un
problème de cible.

### Où on s'est arrêté

`requirements.txt` est **modifié mais non commité** : `pyrit` et `garak` y sont
ajoutés, avec le commentaire expliquant la panne. La résolution des dépendances
sous Linux **n'a pas encore été testée** — c'est l'étape suivante.

### Reprendre ici

```bash
# 1. La résolution tient-elle ? (garak avait des conflits connus avec deepeval,
#    d'où son venv isolé — à vérifier, le conflit était peut-être Windows-only)
docker run --rm -v "$PWD":/w -w /w python:3.11-slim sh -c \
  "pip install -q pip-tools && \
   pip-compile --strip-extras --output-file=/tmp/n.lock requirements.txt"

# 2a. Si OK  : régénérer requirements.lock, reconstruire, revérifier dans l'image
# 2b. Si conflit : garder garak dans un venv isolé DANS l'image (second étage
#     du Dockerfile), et n'ajouter que pyrit aux dépendances principales

# 3. Contrôle final : relancer l'audit ASI_02 par l'API et vérifier que les
#    QUATRE axes rendent une valeur (deepteam, pyrit, garak, microsoft)
docker compose up -d --build
# puis créer une clé, déposer l'audit, suivre GET /api/runs/{id}
```

---

## Ce qui a été validé juste avant

**La chaîne API → file → ouvrier fonctionne de bout en bout.** L'audit ASI_02
est allé jusqu'à `completed` à 100 %, exécuté par le conteneur `worker`, avec le
suivi lisible par l'API :

```
statut : completed | worker : worker-46b244c4b933 | lancé par : key-ace4a8b8746c
92 lignes de journal, 8 échanges captés en direct
```

Le cycle complet des clés a servi : l'admin a créé une clé `operator` expirant à
1 jour, et c'est **elle** qui a déposé l'audit — l'attribution apparaît dans le
suivi.

## État du projet

| | |
|---|---|
| Tests | **206**, verts en suite complète et isolés |
| Vérification de mutation | **11/11** (`python scripts/mutation_check.py`) |
| Images | API et dashboard, **0 vulnérabilité corrigeable** |
| Couverture | `store` 96 %, `worker` 71 %, `api/main` 60 % |

## Ce qui reste après le point 1

1. **Rangement du dépôt avant livraison** — retirer du suivi `presentation/`,
   `presentation.jsx`, `.outils/`, `.deepeval/`, et 44 des 48 résultats d'audit.
   Décidé, jamais exécuté : il manquait votre accord sur les audits à garder.
2. **Étude de validation DVAP** — outillage et cartographie prêts et testés,
   mais un seul laboratoire audité sur quinze.
3. **Push vers le dépôt d'entreprise** — bloqué sur deux décisions : l'URL du
   dépôt, et le sort des ~50 commits signés `Ton Nom <ton.email@exemple.com>`.

## Faiblesses connues, nommées plutôt que tues

- `api/main.py` : seul fichier neuf sous A en maintenabilité (B, 635 lignes) ;
- `run_agent.py` et `run_audit_global.py` à 0 % de couverture — manque ancien ;
- `judge/replay.py`, `garak_runner.py`, `pyrit_runner.py` à 0 % ;
- trois scénarios sans épreuve : ouvrier tué **au milieu** d'un audit d'une
  heure, deux répliques d'API réellement simultanées, volume **réseau** plutôt
  que local.
