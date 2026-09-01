#!/usr/bin/env python
"""
mutation_check.py — Les tests protegent-ils VRAIMENT, ou decorent-ils ?

POURQUOI CE SCRIPT EXISTE
    Un test qui passe ne prouve rien tant qu'on ne l'a pas vu ECHOUER. La suite
    affichait « 189 tests verts » pendant que CINQ correctifs sur onze n'etaient
    adosses a aucun test capable de detecter leur disparition — mesure, pas
    suppose. Ils passaient pour de mauvaises raisons :

      · une comparaison de dates que l'ecart d'horloge rendait vraie de toute
        facon, quel que soit l'operateur ;
      · un test appelant la fonction corrigee DIRECTEMENT, si bien que retirer
        son appel du chemin reel ne changeait rien ;
      · un cas limite sortant par une autre condition avant d'atteindre celle
        qu'il pretendait eprouver ;
      · un test ecrivant sa PROPRE requete SQL — il eprouvait SQLite, pas le code.

    Ce script reintroduit chaque bug connu et EXIGE que le test devienne rouge.
    Les fichiers sont restaures dans tous les cas, y compris sur erreur.

USAGE
    python scripts/mutation_check.py    # code de sortie non nul si un test decore

    A relancer apres tout nouveau correctif : c'est le seul controle qui
    distingue un filet reel d'un filet decoratif.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent

# (libelle, fichier, texte_original, mutation, test_qui_doit_devenir_rouge)
MUTATIONS = [
    ("Reprise des travaux abandonnes (< au lieu de <=)",
     "api/store.py",
     "heartbeat <= ?", "heartbeat < ?",
     "tests/test_store.py::test_un_ouvrier_mort_ne_bloque_pas_un_audit_pour_toujours"),

    ("Prise de travail non atomique (sans la condition status)",
     "api/store.py",
     "WHERE id=? AND status='queued'", "WHERE id=?",
     "tests/test_store.py::test_la_condition_atomique_du_UPDATE_protege_vraiment"),

    ("Cle revoquee acceptee malgre tout",
     "api/store.py",
     "if r is None or r[\"revoked_at\"]:", "if r is None:",
     "tests/test_store.py::test_une_cle_revoquee_est_refusee"),

    ("Roles compares par egalite au lieu du niveau",
     "api/store.py",
     "return ROLES.index(role) >= ROLES.index(minimum)", "return role == minimum",
     "tests/test_store.py::test_les_roles_se_comparent_par_niveau_et_non_par_nom"),

    ("Resume des juges aveugle aux axes non-DeepTeam",
     "judge/summary.py",
     "judged = max(judged, juges_reels)", "judged = judged",
     "tests/test_judge.py::test_le_resume_des_juges_compte_TOUS_les_axes"),

    ("Le plan de remediation perd des constats",
     "judge/remediation_plan.py",
     "return _finaliser(_normaliser(groupes, constats), constats, \"llm\")",
     "return _finaliser(groupes, constats, \"llm\")",
     "tests/test_judge.py::test_le_plan_complete_les_constats_oublies_PAR_LE_MODELE"),

    ("La boucle agentique peut ADOUCIR l'audit",
     "agents/agentic_loop.py",
     "if vise > courant:", "if True:",
     "tests/test_agentic.py::test_un_modele_ne_peut_pas_reduire_le_nombre_d_attaques"),

    ("Le score retenu devient le MAXIMUM des passages",
     "agents/agentic_loop.py",
     "if second.score < premier.score:", "if second.score > premier.score:",
     "tests/test_agentic.py::test_un_second_passage_plus_clement_n_ameliore_pas_le_score"),

    ("Le chemin de resultats ignore la configuration",
     "workflow/paths.py",
     'return Path(valeur).expanduser().resolve() if valeur else defaut',
     'return defaut',
     "tests/test_workflow.py::test_autotest_paths"),

    ("Une categorie non mesuree revient dans le score",
     "workflow/confidence.py",
     'if agent is None or agent.get("measured") is False:',
     'if agent is None:',
     "tests/test_workflow.py::test_une_categorie_non_mesuree_EST_EXCLUE_MEME_AVEC_DES_STATISTIQUES"),

    ("Le gate CI accepte une derogation a date illisible",
     "scripts/ci_gate.py",
     "            expired.append(d)\n            continue",
     "            active.append(d)\n            continue",
     "tests/test_ci_gate.py::test_derogation_a_date_illisible_est_traitee_comme_expiree"),
]


def lancer(test: str) -> bool:
    """True si le test PASSE."""
    r = subprocess.run(
        [sys.executable, "-m", "pytest", test, "-q", "-p", "no:cacheprovider",
         "--no-header", "-x"],
        cwd=RACINE, capture_output=True, text=True, timeout=300)
    return r.returncode == 0


def main() -> int:
    resultats = []
    for libelle, fichier, avant, apres, test in MUTATIONS:
        if avant is None:                       # mutation non mecanisable
            resultats.append((libelle, "—", "non mutee"))
            continue

        chemin = RACINE / fichier
        original = chemin.read_text(encoding="utf-8")
        if avant not in original:
            resultats.append((libelle, "?", f"ancre absente dans {fichier}"))
            continue

        fd, nom = tempfile.mkstemp(suffix=".bak")
        os.close(fd)                    # sinon Windows refuse de le supprimer
        sauvegarde = Path(nom)
        sauvegarde.write_text(original, encoding="utf-8")
        try:
            chemin.write_text(original.replace(avant, apres, 1), encoding="utf-8")
            passe = lancer(test)
            # On EXIGE l'echec : un test qui passe encore ne teste rien.
            resultats.append((libelle, "OK" if not passe else "INUTILE",
                              "le test devient rouge" if not passe
                              else "LE TEST PASSE ENCORE — il ne protege rien"))
        finally:
            chemin.write_text(sauvegarde.read_text(encoding="utf-8"), encoding="utf-8")
            sauvegarde.unlink(missing_ok=True)

    print("\n" + "=" * 78)
    print("TEST DE MUTATION — un test qui passe ne prouve rien tant qu'on ne")
    print("l'a pas vu echouer. On casse le correctif, le test DOIT devenir rouge.")
    print("=" * 78 + "\n")
    for libelle, etat, detail in resultats:
        marque = {"OK": "[FILET REEL] ", "INUTILE": "[DECORATIF]  ",
                  "—": "[non mutee]  ", "?": "[ANCRE KO]   "}[etat]
        print(f"  {marque}{libelle}")
        print(f"                {detail}")
    reels = sum(1 for _, e, _ in resultats if e == "OK")
    total = sum(1 for _, e, _ in resultats if e in ("OK", "INUTILE"))
    print(f"\n  {reels}/{total} correctifs adosses a un test qui echoue quand on les casse.")
    return 0 if reels == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
