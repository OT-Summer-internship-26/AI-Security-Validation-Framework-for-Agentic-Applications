# Point de reprise — mis à jour le 2026-09-10

Document de passation. Il dit **où on s'est arrêté**, **pourquoi**, et **par quoi
reprendre**.

---

## ✅ Le point bloquant est fermé — les quatre axes sont dans l'image

La version précédente de ce document s'ouvrait sur un blocage rouge : `pyrit` et
`garak` absents de l'image, un audit qui rendait `not_measured` sur deux axes, et
un verrou impossible à régénérer parce que la machine était en IPv6 seul. **Plus
rien de tout cela n'est vrai.**

| Axe | Où il vit maintenant |
|---|---|
| `deepteam`, `semgrep` | pile principale, `requirements.lock` |
| `pyrit` | `requirements.lock` — `pyrit==1.0.1` |
| `garak` | étage Docker dédié : venv **isolé**, `garak==0.9.0.11.post1` posé `--no-deps` |

L'isolation de garak n'est pas un contournement resté en place faute de mieux,
c'est le choix mesuré : garak déclare `torch`, `transformers`, `datasets`,
`nltk`, `accelerate`, et épingle `openai<1.0.0` — incompatible avec le reste de
la pile. Le venv minimal (91 Mo, sans torch) et le venv de référence (1,4 Go)
rendent **le même verdict sur les mêmes compteurs bruts**. Quinze fois plus
petit, même résultat. Si un axe exigeait un jour un détecteur ML, l'échec serait
un `ModuleNotFoundError` explicite et `run_garak` rendrait `excluded` — jamais un
faux 10/10.

> **Report assumé, à connaître avant de toucher à garak.**
> `judge/garak_runner.py` construit une ligne `--model_type` / `--probes` que
> garak 0.16 a dépréciée (« Expected plugin name in format
> category.module_name.class_name »). La version est donc épinglée à celle que le
> runner sait piloter. Monter de version demande de réécrire le runner.

---

## État du projet — mesuré le 2026-09-08

| | |
|---|---|
| Tests | **293**, verts en suite complète |
| Couverture | **78 %** au total |
| Vérification de mutation | **23/23** (`python scripts/mutation_check.py`) |
| Images | API et dashboard, **0 vulnérabilité corrigeable** |

> **Les chiffres de la version précédente étaient tous faux, et dans les deux
> sens.** Elle annonçait 206 tests (il y en a 293), 11/11 en mutation (il y a 23
> mutations), et surtout « `run_agent.py`, `run_audit_global.py`, `replay.py`,
> `garak_runner.py`, `pyrit_runner.py` à **0 %** » — ils sont respectivement à
> 48 %, 55 %, 95 %, 86 % et 66 %. Une faiblesse écrite une fois et jamais
> remesurée oriente le travail vers un trou qui n'existe plus, pendant que les
> vrais restent invisibles. **Remesurer avant de mettre à jour cette section.**

---

## Ce qui reste

1. **Étude de validation DVAP** — outillage et cartographie prêts et testés, mais
   **un seul laboratoire audité sur quinze**. C'est le chantier qui reste le plus
   long, et le seul qui dise quelque chose sur la *précision* de l'outil.
2. **Les secrets GitHub de l'organisation** — voir la liste ci-dessous. C'est
   le seul obstacle restant entre le dépôt et une exécution réelle de la chaîne :
   sans eux elle reste **inerte**, et son silence se lit comme un succès.

---

## Le push vers l'entreprise est fait — 2026-09-10

Dépôt : `github.com/OT-Summer-internship-26/AI-Security-Validation-Framework-for-Agentic-Applications`
(**privé**). Il porte les 71 commits, les trois branches (`main`,
`durcissement-cicd`, `archive/travail-complet`) et le tag
`v1.0-travail-complet`. `main` a été avancé sur `durcissement-cicd` : c'est
désormais l'état complet qui s'affiche à qui ouvre le dépôt.

**Vérifié depuis un clone vierge de ce dépôt** : 245 fichiers, **288 tests
passent** (5 ignorés, Docker absent du poste), aucun secret versionné, aucun
audit simulé, et tous les actifs nécessaires présents (logo, `.env.example`,
`requirements.lock`, `Dockerfile`, `config/`, `cosign.pub`).

Le dépôt personnel `github.com/Asser-Belhassen/Ai-Security` est destiné à la
suppression et n'est plus le remote de ce dossier de travail : `origin` pointe
sur le dépôt d'entreprise, et les trois branches le suivent.

---

## Avant la mise en production — ce qui reste à trancher

1. **L'identité des commits — et elle continue de se poser.** Les **71 commits**
   sont signés `Ton Nom <ton.email@exemple.com>`. Aucun ne sera rattaché à un
   compte GitHub, et l'adresse de remplacement reste dans l'historique pour
   toujours.

   La cause est encore active : `git config user.email` vaut, **dans ce dépôt**,
   `ton.email@exemple.com`, et aucune identité globale n'est définie. Chaque
   commit futur repart donc avec la même signature. Le corriger coûte deux
   commandes et arrête l'hémorragie même si on ne touche pas à l'historique :

   ```bash
   git config user.name  "<votre nom>"
   git config user.email "<votre adresse GitHub>"   # ou l'adresse noreply de GitHub
   ```

   Reprendre les 71 commits existants est un autre geste, à faire **avant** que
   quiconque branche du travail dessus. `git filter-repo` **n'est pas installé**
   (`pip install git-filter-repo`), et la réécriture change tous les condensés :
   elle impose un `push --force` sur les **trois** branches en ligne et sur le
   tag. C'est la seule décision de cette liste qui devienne plus chère avec le
   temps — et elle l'est devenue : le dépôt d'entreprise porte désormais
   l'historique, et toute réécriture devra être annoncée à qui l'aura cloné.

2. **Aucun fichier `LICENSE`.** Sans licence, le dépôt est « tous droits
   réservés » : personne ne peut légalement le réutiliser, y compris à
   l'intérieur d'une entreprise qui voudrait s'en servir. À trancher selon la
   destination (interne, ou ouvert).

   *Le versant TIERS de cette question, lui, est reglé* : `THIRD_PARTY_NOTICES.md`
   porte l'attribution des quatre fichiers Microsoft embarqués et le texte MIT
   qu'ils exigent. Les deux sujets sont indépendants — ce point 2 ne concerne
   plus que la licence de VOTRE code.

3. **Les secrets attendus par les workflows n'existent pas encore.**
   `COSIGN_KEY`, `COSIGN_PASSWORD`, `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_PATH`,
   `DEPLOY_SSH_KEY`, `DEPLOY_HOST_KEY`, `DEPLOY_HEALTH_URL`. La chaîne est écrite
   pour rester **inerte** sans eux plutôt que d'échouer — donc leur absence ne se
   verra pas, elle se lira comme un succès. `cosign.pub` est versionné, comme il
   se doit ; `cosign.key` ne l'est pas et ne doit jamais l'être.

4. **Ces quatre workflows n'avaient JAMAIS tourné** (`ci_limites_connues.md`
   §D7) jusqu'au push du 2026-09-10, qui est donc leur toute première exécution.
   `images.yml` et `security_audit.yml` se déclenchent sur `push` ; `deploiement.yml`
   ne part qu'à la main et reste inerte sans les secrets du point 3 ;
   `retention_images.yml` attend le lundi 4 h UTC. **Le résultat n'a pas encore
   été regardé : onglet Actions du dépôt.** Prévoir que ça casse.

5. **`data/state.sqlite` est dans l'historique** (ajoutée par `73ae2a0`, retirée
   par `ffaeead`) et donc déjà en ligne. **Vérifié le 2026-09-08 : sans danger.**
   Le blob contient 3 exécutions de test contre `http://cible/chat`, `api_keys`
   et `run_exchanges` **vides**, et aucun motif de clé dans les octets bruts.
   Rien à purger.

6. **`presentation/`, `presentation.jsx` et `runs/` restent dans l'historique**
   des commits antérieurs, poussés avec le reste vers le dépôt d'entreprise. Ils
   sont retirés du suivi depuis — un clone ne les pose plus sur le disque — mais
   les retirer de l'historique demanderait une réécriture, à grouper avec le
   point 1 si on la fait.

---

## Faiblesses connues, nommées plutôt que tues

- **`api/main.py` : 1495 lignes, 680 instructions, 50 % de couverture.** C'est le
  point faible structurel du dépôt, et il s'est aggravé : la couverture a *baissé*
  de 60 % à 50 %. Ce n'est pas le travail récent qui l'explique — le code ajouté
  par le dernier commit est couvert à 94 % — mais les strates plus anciennes, que
  la croissance du fichier a diluées.
  *(L'ancien « B, 635 lignes » comptait les **instructions**, pas les lignes : à
  ne pas comparer au 1495 ci-dessus, qui est le fichier brut.)*
- Modules sous 50 % : `judge/llm_config.py` (40 %),
  `reporting/interpretation.py` (33 %), `scripts/setup_docker.py` (36 %),
  `scripts/validation_study.py` (41 %), `scripts/run_agent.py` (48 %),
  `scripts/mutation_check.py` (34 % — seul son calcul est éprouvé, pas sa boucle).
- **Trois scénarios sans épreuve** : ouvrier tué **au milieu** d'un audit d'une
  heure, deux répliques d'API réellement simultanées, volume **réseau** plutôt
  que local.
- Le multi-tours n'atteint jamais la cible avec son historique (§44.3 du
  journal) : `CrescendoJailbreaking` et `ContextPoisoning` sont dégradés en
  mono-tour du point de vue de la cible. La limite est désormais *affichée* dans
  le rapport et le dashboard, mais elle n'est pas *levée*.

---

## Deux leçons de méthode, payées deux fois chacune

Elles ne sont pas des anecdotes : elles décrivent le mode de panne dominant de ce
dépôt — un contrôle qui existe, qui est vert, et qui ne contrôle rien.

**Un auto-test que personne ne rejoue est pire qu'absent.** Quatre juges
portaient un `demo()` que rien ne lançait ; la correction fut une *liste*. Une
liste ne s'étend pas toute seule : `workflow/serialization.py` puis
`scripts/mutation_check.py` y sont retombés — le second n'étant jamais importé,
il était invisible **jusque dans le rapport de couverture**, qui ne montre pas ce
qu'il n'a pas vu. Remplacé par une **découverte** :
`test_aucun_autotest_demo_n_est_orphelin` rejoue tout module portant `def demo()`,
y compris ceux qui n'existent pas encore.

**Une ancre de mutation vieillit en silence.** La requête de purge a été extraite
dans une variable ; l'ancre, qui portait son indentation et sa virgule, n'a plus
correspondu à rien. Le contrôle rendait « ANCRE KO » et ce correctif n'était donc
plus éprouvé du tout. `mutation_check.py` compte désormais ces cas — et les
timeouts — **dans le dénominateur** : un ratio qui rétrécit en silence est un
mensonge par omission, et c'est exactement la maladie que ce script est censé
débusquer chez les autres.
