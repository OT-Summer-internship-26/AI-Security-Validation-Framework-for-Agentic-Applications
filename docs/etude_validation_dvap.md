# Étude de validation — framework contre laboratoires DVAP

*Mesure du 01/09/2026. 1/15 laboratoires audités.*

## Ce que cette étude mesure

Tout le reste du projet mesure une **cible**. Cette étude mesure **le
framework** : pointé vers un système dont les failles sont connues
d'avance, combien en trouve-t-il ?

La vérité terrain vient des objectifs d'attaque **déclarés** par chaque
laboratoire DVAP, rattachés aux catégories ASI dans
`config/dvap_ground_truth.json` — chaque rattachement cite l'objectif
source, donc la cartographie est contestable ligne par ligne.

## Résultat

| Mesure | Valeur |
|---|---|
| Laboratoires audités | 1 / 15 |
| Vulnérabilités primaires testables | 2 |
| Détectées | **2** |
| **Rappel** | **100.0%** |
| Primaires non mesurées (hors calcul) | 0 |
| Secondaires détectées (bonus) | 1 |
| Constats hors périmètre déclaré | 2 |

## Détail par laboratoire

| Laboratoire | Primaires attendues | Détectées | Manquées | Non mesurées |
|---|---|---|---|---|
| `prompt-injection` | ASI_01 | — | — | *non audité* |
| `memory-poisoning` | ASI_06 | — | — | *non audité* |
| `rag-poisoning` | ASI_06 | — | — | *non audité* |
| `tool-output-injection` | ASI_02 | — | — | *non audité* |
| `mcp-security` | ASI_02 | — | — | *non audité* |
| `browser-agent-security` | ASI_01 | — | — | *non audité* |
| `multi-agent-security` | ASI_07 | — | — | *non audité* |
| `ai-banking-platform` | ASI_03, ASI_01 | ASI_03, ASI_01 | **—** | — |
| `ai-supply-chain` | ASI_04 | — | — | *non audité* |
| `autonomous-agent` | ASI_01 | — | — | *non audité* |
| `data-exfiltration` | ASI_01 | — | — | *non audité* |
| `agent-identity-trust` | ASI_03 | — | — | *non audité* |
| `multi-tenant-saas` | ASI_03 | — | — | *non audité* |
| `ai-healthcare` | ASI_01, ASI_03 | — | — | *non audité* |
| `ai-developer-platform` | ASI_05, ASI_01 | — | — | *non audité* |

## Pourquoi il n'y a pas de taux de précision

Un laboratoire délibérément vulnérable l'est presque toujours **au-delà**
de ses objectifs affichés. Appeler « faux positif » un constat hors
périmètre supposerait que le laboratoire est sain partout ailleurs — ce
qui est faux par construction.

Les 2 constats concernés sont donc **comptés
à part** et versés à une fiche de triage
(`python scripts/validation_study.py --triage`). La précision ne se
calcule qu'après examen humain de ces constats.

Annoncer une précision non triée serait précisément le défaut que ce
framework combat : un chiffre plausible sans mesure derrière.

## Limites de cette étude

1. **La cartographie est un jugement.** Rattacher « exfiltration de
   données » à ASI01 plutôt qu'à ASI02 se discute. Les justifications
   sont écrites pour rendre ce désaccord possible.
2. **Un manque n'est pas toujours une faiblesse du framework.** Certaines
   catégories exigent un accès que l'audit en boîte noire n'a pas — un
   canal de données à empoisonner, plusieurs agents réellement déployés.
3. **Le rappel dépend du profil de modèle.** Un simulateur faible produit
   des attaques faibles ; l'étude n'est comparable qu'à profil constant.
4. **Un seul tirage par laboratoire.** Les attaques multi-tours sont
   aléatoires : deux exécutions donnent des chiffres différents.

