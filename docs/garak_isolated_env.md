# garak — environnement isolé (Windows, sans Rust)

## Pourquoi un venv séparé

`garak` ne peut **pas** cohabiter avec DeepTeam dans le même environnement Python :

- La version récente de garak dépend de `litellm` (source-only) qui exige la toolchain
  **Rust/Cargo** pour compiler — absente sur le poste Windows.
- La seule version installable sans Rust (`garak 0.9.0.11.post1`, via `--only-binary=:all:`)
  épingle **`openai==0.28.1`** (ancienne API 0.x). Or DeepTeam, DeepEval et LangChain-OpenAI
  exigent **`openai >= 2.x`**. Installer garak dans l'env principal **casse** ces trois outils
  (`ModuleNotFoundError: No module named 'openai.types'`).

DeepTeam étant le moteur d'attaque **principal** (NOTES.md §2/§5) et garak le **secondaire**
(« variantes automatiques »), garak est isolé dans son propre venv.

## Installation (déjà réalisée)

```powershell
python -m venv C:\Users\asser\garak-venv
C:\Users\asser\garak-venv\Scripts\python.exe -m pip install garak --only-binary=:all:
```

`--only-binary=:all:` force pip à ne prendre que des wheels : il évite `litellm` source-only
(Rust) et résout garak vers `0.9.0.11.post1`, sans jamais toucher à l'environnement principal.

## Utilisation

```powershell
# Lancer garak depuis son venv (n'affecte pas l'env principal)
C:\Users\asser\garak-venv\Scripts\python.exe -m garak --help
C:\Users\asser\garak-venv\Scripts\python.exe -m garak --version
```

Vérification rapide :

```powershell
C:\Users\asser\garak-venv\Scripts\python.exe -c "import garak; print('garak OK', garak.__version__)"
# -> garak OK 0.9.0.11.post1
```

## Alternatives pour une version récente de garak

Si une version récente de garak est requise (couverture d'attaques étendue), il faut `litellm`,
donc **Rust** :

1. Installer Rust : https://rustup.rs (`rustup-init.exe`), puis dans le venv garak :
   `...\garak-venv\Scripts\python.exe -m pip install -U garak`
2. **Ou** exécuter garak dans un conteneur Docker/Linux (recommandé en Phase 2, où litellm a des wheels).
