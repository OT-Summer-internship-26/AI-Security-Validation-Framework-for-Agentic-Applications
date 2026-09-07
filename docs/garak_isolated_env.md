# garak — environnement isolé (Windows, sans Rust)

> **Chemin.** Ce document ecrivait `C:\Users\asser\garak-venv` en dur, et le
> code avait le meme defaut. Sur toute autre machine — et dans l'image, qui est
> Linux — l'axe garak etait donc introuvable, donc silencieusement absent de
> tous les audits. Le venv se place desormais dans le dossier personnel :
> `%USERPROFILE%\garak-venv` sous Windows, `~/garak-venv` ailleurs. C'est ce que
> `judge/garak_runner.py` cherche par defaut ; `GARAK_VENV_PYTHON` le surcharge.


## Pourquoi un venv séparé

`garak` ne peut **pas** cohabiter avec DeepTeam dans le même environnement Python :

- La version récente de garak dépend de `litellm` (source-only) qui exige la toolchain
  **Rust/Cargo** pour compiler — absente sur le poste Windows.
- La seule version installable sans Rust (`garak 0.9.0.11.post1`, via `--only-binary=:all:`)
  épingle **`openai==0.28.1`** (ancienne API 0.x). Or DeepTeam, DeepEval et LangChain-OpenAI
  exigent **`openai >= 2.x`**. Installer garak dans l'env principal **casse** ces trois outils
  (`ModuleNotFoundError: No module named 'openai.types'`).

DeepTeam étant le moteur d'attaque **principal** (doc. technique : pile technique / integration DeepTeam) et garak le **secondaire**
(« variantes automatiques »), garak est isolé dans son propre venv.

## Installation — RECETTE MINIMALE (recommandée)

```powershell
python -m venv %USERPROFILE%\garak-venv
%USERPROFILE%\garak-venv\Scripts\python.exe -m pip install --no-deps garak==0.9.0.11.post1
%USERPROFILE%\garak-venv\Scripts\python.exe -m pip install pyyaml xdg_base_dirs colorama requests httpx aiohttp numpy tqdm backoff markdown jinja2
```

**91 Mo au lieu de 1,4 Go, pour un verdict IDENTIQUE.**

garak *déclare* `torch`, `transformers`, `datasets`, `nltk`, `accelerate`,
`sentencepiece` — c'est pourquoi une installation normale produit un venv de
**1,4 Go** (mesuré sur le poste de développement). Mais ces paquets servent aux
générateurs HuggingFace **locaux**, que ce framework n'utilise pas : il attaque
une cible HTTP via `rest.RestGenerator`.

La liste ci-dessus n'est pas devinée. Elle a été établie en installant garak
`--no-deps`, puis en ajoutant une par une les dépendances que l'exécution
réclame vraiment, jusqu'à ce qu'un scan REST complet aboutisse.

Vérifié via `judge/garak_runner.py`, contre une cible bidon, même probe :

| venv | taille | `torch` | résultat |
|---|---|---|---|
| install normale | 1,4 Go | oui | score 5.0 — « ok (1/2 passés) », 1 constat |
| recette minimale | **91 Mo** | non | score 5.0 — « ok (1/2 passés) », 1 constat |

Mêmes compteurs bruts (`passed: 1, total: 2, returncode: 0`).

C'est cette recette que l'image Docker applique, dans un étage dédié (voir le
Dockerfile, étage `garak`). **L'image embarque donc garak désormais** : avant,
elle n'en avait aucun et l'axe sortait « unavailable » sur tous les audits de
production.

### Si un jour un détecteur ML devient nécessaire
Un axe garak qui exigerait un classifieur (toxicité, par ex.) échouerait sur un
`ModuleNotFoundError` **explicite** — pas en silence : `run_garak` rend alors
`excluded`, jamais un faux 10/10. Il suffirait alors d'ajouter le paquet
manquant à la liste, ou de repasser à l'installation complète.

## Installation complète (l'ancienne, si vraiment nécessaire)

```powershell
%USERPROFILE%\garak-venv\Scripts\python.exe -m pip install garak --only-binary=:all:
```

`--only-binary=:all:` force pip à ne prendre que des wheels : il évite `litellm`
source-only (Rust) et résout garak vers `0.9.0.11.post1`, sans jamais toucher à
l'environnement principal. Compter **1,4 Go** et une résolution très longue
(mesuré : plus de 45 min sous Linux, interrompue).

## Utilisation

```powershell
# Lancer garak depuis son venv (n'affecte pas l'env principal)
%USERPROFILE%\garak-venv\Scripts\python.exe -m garak --help
%USERPROFILE%\garak-venv\Scripts\python.exe -m garak --version
```

Vérification rapide :

```powershell
%USERPROFILE%\garak-venv\Scripts\python.exe -c "import garak; print('garak OK', garak.__version__)"
# -> garak OK 0.9.0.11.post1
```

## Alternatives pour une version récente de garak

Si une version récente de garak est requise (couverture d'attaques étendue), il faut `litellm`,
donc **Rust** :

1. Installer Rust : https://rustup.rs (`rustup-init.exe`), puis dans le venv garak :
   `...\garak-venv\Scripts\python.exe -m pip install -U garak`
2. **Ou** exécuter garak dans un conteneur Docker/Linux (recommandé en Phase 2, où litellm a des wheels).
