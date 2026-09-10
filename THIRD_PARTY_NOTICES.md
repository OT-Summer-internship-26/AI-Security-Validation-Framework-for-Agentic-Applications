# Avis relatifs aux composants tiers

Ce dépôt **contient des copies** de fichiers sources écrits par des tiers. La
licence de ces fichiers exige que leur avis de copyright et leur texte de
permission accompagnent toute copie : c'est l'objet de ce document.

Il ne dit rien de la licence du reste du dépôt — les deux sujets sont
indépendants, et le second reste à trancher (voir `docs/REPRISE.md`).

## Ce que ce document couvre, et ce qu'il ne couvre pas

**Couvert : le code COPIÉ dans le dépôt.** Quatre fichiers, listés ci-dessous.
Ils vivent dans l'arborescence, sont versionnés avec le reste, et se retrouvent
dans chaque clone et chaque image.

**Non couvert : les dépendances DÉCLARÉES.** `requirements.txt`,
`requirements.lock` et `dashboard/package.json` désignent des paquets que
`pip` et `npm` vont chercher à l'installation. Leur code n'est pas dans ce
dépôt et chacun porte sa propre licence, résolue par son gestionnaire de
paquets. `node_modules/` est d'ailleurs exclu par `.gitignore`.

---

## Microsoft Agent Governance Toolkit

**Source :** https://github.com/microsoft/agent-governance-toolkit
**Licence :** MIT
**Détenteur :** Microsoft Corporation

Chacun de ces fichiers porte déjà l'en-tête `Copyright (c) Microsoft
Corporation. / Licensed under the MIT License.` en tête de fichier. Ne pas le
retirer : c'est lui qui rattache le fichier à l'avis ci-dessous.

| Fichier | Rôle dans ce projet |
|---|---|
| `sandbox/security_skills.py` | 11 contrôles de scan statique, utilisés par la couche statique d'ASI05 en complément de Semgrep. **Importé à l'exécution.** |
| `sandbox/sandbox_provider.py` | Classes de base de l'isolation d'exécution (`SandboxConfig`, `SandboxResult`, `SandboxProvider`, `SubprocessSandboxProvider`), dont hérite `sandbox/docker_provider.py`. **Importé à l'exécution.** |
| `docs/references/microsoft_payloads_reference.py` | 28 charges adverses couvrant ASI01→ASI10. Lu **par analyse AST** — et non importé — par `agents/asi01_goal_hijacking.py`. |
| `docs/references/memory_guard_reference.py` | Implémentation de référence de la protection mémoire (ASI06). Document de référence : ni importé, ni exécuté. |

### Texte de la licence

Reproduit sans traduction : un texte de licence traduit n'est plus la licence.

```
MIT License

Copyright (c) Microsoft Corporation.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Tenir cette liste à jour

Elle a été établie en balayant **tous** les fichiers versionnés à la recherche
d'un avis de copyright, et non de mémoire. Quatre fichiers en portaient un, les
quatre ci-dessus. Pour la revérifier après avoir repris du code ailleurs :

```bash
git ls-files -z | xargs -0 grep -lI "Copyright (c)\|Copyright ©\|SPDX-License"
```

Tout fichier qui apparaît dans cette sortie sans figurer dans le tableau
ci-dessus est un composant tiers non déclaré.
