# Point de reprise — mis à jour le 2026-09-02

Document de passation. Il dit **où on s'est arrêté**, **pourquoi**, et **par quoi
reprendre**. À supprimer une fois le point 1 traité.

---

## 🔴 Point 1 — deux axes d'audit manquent dans l'image Docker

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

### Ce qui est ÉTABLI

La résolution des dépendances **passe**, `garak` compris. Vérifié par
`pip-compile` sur l'hôte :

| Fait | Preuve |
|---|---|
| `pyrit` + `garak` résolvent sans conflit | **220 paquets**, 0 conflit |
| Le venv isolé de garak était un contournement **Windows** | Le conflit annoncé avec deepeval n'apparaît pas à la résolution |
| Les épinglages critiques tiennent | `click` 8.1.8, `mcp` 2.1.1, `msgpack` 1.2.2, `deepteam`, `deepeval`, `langfuse`, `opentelemetry` — **inchangés** |
| Impact limité sur l'existant | 5 paquets changent de version, tous mineurs : `langsmith`, `openai`, `pip-audit`, `tomli`, `cyclonedx-python-lib` |

`requirements.txt` déclare désormais les deux, avec le commentaire expliquant
la panne.

### Ce qui BLOQUE — le réseau, pas le code

> La machine est en **IPv6 seul**. L'hôte joint PyPI (via IPv6), mais les
> conteneurs Docker n'ont pas de route IPv6 : `pip` y échoue en
> « Temporary failure in name resolution ». Or le verrou officiel se régénère
> dans un conteneur Linux — impossible tant que cela dure.

**Deux façons de débloquer :**

1. **Une connexion avec IPv4** — partage de connexion mobile, ou désactiver un
   VPN. Vérification :
   `python -c "import socket; socket.getaddrinfo('pypi.org',443,socket.AF_INET)"`
2. **Activer IPv6 dans Docker** — dans `daemon.json` :
   `{"ipv6": true, "fixed-cidr-v6": "fd00::/80"}`, puis redémarrer Docker Desktop.

### Piste écartée, et pourquoi

`uv pip compile --python-platform linux` résout bien (301 paquets) et contourne
le problème de plateforme. Mais il fait **reculer semgrep de 1.170.1 à 1.79.0**.
Vérifié : ce n'est causé **ni par `pyrit` ni par `garak`** — c'est une stratégie
de résolution différente. Livrer un verrou produit par un autre outil, avec 90
versions de recul sur un scanner de sécurité, n'est pas acceptable sans examen.

### Reprendre ici

```bash
# 0. PREALABLE : le conteneur doit joindre PyPI.
docker run --rm python:3.11-slim pip download --no-deps -d /tmp packaging
#    Echec en « name resolution » => voir « Ce qui BLOQUE » ci-dessus.

# 1. Regenerer le verrou officiel, meme methode que d'habitude.
docker run --rm -v "$PWD":/w -w /w python:3.11-slim sh -c "pip install -q pip-tools && python -m piptools compile --strip-extras --output-file=/tmp/n.lock requirements.txt && cp /tmp/n.lock requirements.lock"

# 2. Reconstruire, puis verifier que les QUATRE axes sont bien dans l'image.
docker compose up -d --build
docker compose exec worker python -c "import pyrit, garak, deepteam, semgrep; print('4 axes OK')"

# 3. Controle final : relancer l'audit ASI_02 par l'API, et verifier que
#    `score_components` porte une VALEUR pour deepteam, pyrit, garak ET
#    microsoft — pas None, pas not_measured.
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

1. **Étude de validation DVAP** — outillage et cartographie prêts et testés,
   mais un seul laboratoire audité sur quinze.
2. **Push vers le dépôt d'entreprise** — bloqué sur deux décisions : l'URL du
   dépôt, et le sort des ~50 commits signés `Ton Nom <ton.email@exemple.com>`.

## Faiblesses connues, nommées plutôt que tues

- `api/main.py` : seul fichier neuf sous A en maintenabilité (B, 635 lignes) ;
- `run_agent.py` et `run_audit_global.py` à 0 % de couverture — manque ancien ;
- `judge/replay.py`, `garak_runner.py`, `pyrit_runner.py` à 0 % ;
- trois scénarios sans épreuve : ouvrier tué **au milieu** d'un audit d'une
  heure, deux répliques d'API réellement simultanées, volume **réseau** plutôt
  que local.
