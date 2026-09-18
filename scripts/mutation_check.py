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

    # Panne de PRODUCTION, pas de logique : le checkpoint quittait le volume.
    # La mutation restaure un chemin code en dur, aveugle a AUDIT_DATA_DIR.
    ("Le point de reprise repart hors du volume de donnees",
     "workflow/audit_graph.py",
     "db = str(checkpoints_path())",
     'db = "data/checkpoints.sqlite"',
     "tests/test_workflow.py::test_le_checkpoint_atterrit_SUR_LE_VOLUME_des_resultats"),

    # Un axe exclu qui accuse la cible a tort envoie chercher la panne au mauvais
    # endroit. La mutation restaure le diagnostic devine d'origine.
    ("L'axe garak exclu accuse la cible sans avoir lu le journal",
     "judge/garak_runner.py",
     "        if saute or absent:",
     "        if False:",
     "tests/test_axes_runners.py::test_un_detecteur_indisponible_n_est_PAS_impute_a_la_cible"),

    # Le faux vert le plus cher du projet : un verdict de securite rendu sur un
    # audit que personne n'a designe. La mutation retablit le choix implicite.
    ("Le gate choisit lui-meme l'audit qu'il juge",
     "scripts/ci_gate.py",
     "    if not args.audit and not args.dernier:",
     "    if False:",
     "tests/test_ci_gate.py::test_le_gate_REFUSE_de_choisir_lui_meme_son_sujet"),

    # Le retour arriere sur etat durable : une image ancienne devant une base
    # recente doit refuser de demarrer. La mutation retire le garde-fou.
    ("Une image plus ancienne que la base demarre quand meme",
     "api/store.py",
     "    if actuelle > SCHEMA_VERSION:",
     "    if False:",
     "tests/test_store.py::test_une_base_PLUS_RECENTE_que_le_code_REFUSE_de_demarrer"),

    # SSRF authentifie : sans bornage, une cle operateur atteint n'importe quelle
    # adresse interne, et les reponses partent dans le transcript d'audit.
    ("Une cible hors liste autorisee est acceptee",
     "workflow/cibles.py",
     "    if not autorise:",
     "    if False:",
     "tests/test_api.py::test_une_cible_hors_liste_est_refusee"),

    # Compose lance l'API et l'ouvrier ensemble : sans verrou, la migration
    # s'applique deux fois, et l'un des deux services ne demarre pas.
    ("La migration se fait sans verrou d'ecriture",
     "api/store.py",
     'c.execute("BEGIN IMMEDIATE")',
     'c.execute("BEGIN DEFERRED")',
     "tests/test_store.py::test_deux_demarrages_SIMULTANES_ne_migrent_pas_deux_fois"),

    # Une cible authentifiee redevient inauditable si ce passage saute — et
    # l'echec est discret : axe exclu, audit « termine normalement ».
    ("Les en-tetes d'authentification se perdent avant la cible",
     "scripts/run_agent.py",
     "                                 headers=headers,",
     "                                 headers=None,",
     "tests/test_runners.py::test_les_en_tetes_atteignent_la_cible_depuis_la_CLI"),

    # Le transcript d'un audit redevient public si cette garde saute.
    ("Le transcript d'un audit se lit sans clef",
     "api/main.py",
     '    _identifier(x_api_key, minimum="viewer")\n    # Lues dans le MAGASIN',
     '    # Lues dans le MAGASIN',
     "tests/test_api.py::test_le_transcript_d_un_audit_n_est_PAS_lisible_sans_clef"),

    # Et les identifiants de la cible repartent en clair.
    ("Les identifiants de la cible sont stockes en clair",
     "api/main.py",
     "            propre[champ] = {nom: _MASQUE for nom in valeur}",
     "            propre[champ] = valeur",
     "tests/test_api.py::test_les_identifiants_de_la_CIBLE_ne_sont_jamais_rendus"),

    # Sans plafond, une cible bavarde dicte la memoire du processus.
    ("Une reponse de cible demesuree est acceptee",
     "agents/base_agent.py",
     "                    if recu > limite:",
     "                    if False:",
     "tests/test_base_agent.py::test_une_reponse_DEMESUREE_est_exclue_et_ne_remplit_pas_la_memoire"),

    # LE GARDE-FOU SSRF DU RUNNER GLOBAL. Il a deja ete faux ici, et de deux
    # facons a la fois : place dans `_run_via_graph`, il levait `NameError`
    # (`ap` est un local de `main()`) au lieu de refuser, et il ne couvrait pas
    # `--subprocess`, qui ne passe pas par le graphe. Aucun test ne parcourait
    # la branche : la suite est restee verte tout du long.
    ("L'allowlist ne borne plus le runner global",
     "scripts/run_audit_global.py",
     "        valider_cible(args.target)",
     "        pass",
     "tests/test_runners.py::test_une_cible_HORS_LISTE_est_refusee_par_LES_DEUX_runners"),

    # Une purge qui touche une execution EN COURS lui retire son suivi.
    #
    # ANCRE REPRISE LE 2026-09-08. La requete a ete extraite dans une variable
    # (`vieux = ...`) pour etre reutilisee par les trois DELETE : elle a perdu
    # l'indentation et la virgule que cette mutation attendait. Resultat, l'ancre
    # ne correspondait plus a rien et le controle rendait « ANCRE KO » — donc ce
    # correctif n'etait plus eprouve DU TOUT. On ancre desormais sur le litteral
    # seul, qui ne depend plus de la facon dont il est passe aux appels.
    ("La purge emporte aussi les executions en cours",
     "api/store.py",
     "\"SELECT id FROM runs WHERE finished_at IS NOT NULL AND finished_at < ?\"",
     "\"SELECT id FROM runs WHERE finished_at IS NULL OR finished_at < ?\"",
     "tests/test_store.py::test_la_purge_retire_le_VOLUME_et_garde_la_TRACE"),

    # Le code de la cible s'executait sur l'hote, avec ses cles, faute de Docker.
    ("Le code de la cible s'execute sans Docker",
     "agents/asi05_code_execution.py",
     "        if not docker_ok:",
     "        if False:",
     "tests/test_sandbox.py::test_sans_docker_le_code_de_la_cible_n_est_JAMAIS_execute"),
]


DELAI_TEST_S = 300


def lancer(test: str) -> bool | None:
    """True si le test PASSE, False s'il echoue, None s'il n'a pas abouti.

    LE TIMEOUT EST UN TROISIEME ETAT, ET C'EST TOUT L'ENJEU
        `TimeoutExpired` remontait jusqu'a `main()` et tuait la verification
        ENTIERE : aucun rapport imprime, et toutes les mutations suivantes
        jamais jouees — sans que rien ne le dise. Un seul test lent effacait
        donc le controle en silence. Mesure : l'execution est morte sur la
        mutation 12, les 5 suivantes n'ont jamais ete testees.

        Le compter comme « le test a echoue » serait PIRE que le plantage : la
        mutation passerait pour un FILET REEL alors que rien n'a ete mesure.
        C'est exactement le faux vert que ce script existe pour debusquer.

        `timeout=` ne borne d'ailleurs pas ce qu'on croit : sous Windows, avec
        `capture_output`, il ne couvre pas le drainage des tuyaux. Un delai de
        300 s s'est termine a 917 s (« timed out after -617 s »). Le traiter
        comme un cas possible plutot que comme une impossibilite theorique.
    """
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pytest", test, "-q", "-p", "no:cacheprovider",
             "--no-header", "-x"],
            cwd=RACINE, capture_output=True, text=True, timeout=DELAI_TEST_S)
    except subprocess.TimeoutExpired:
        return None
    return r.returncode == 0


def synthese(resultats):
    """(reels, total, perdues) — LE CALCUL QUI A MENTI, isole pour etre eprouve.

    « ANCRE » compte dans le TOTAL. Il en etait exclu, et le script affichait
    donc un ratio complet sur un perimetre retreci : « 16/16 », sortie 0, pendant
    qu'un correctif de securite (`valider_cible`) etait NEUTRALISE dans le
    fichier par une execution precedente non restauree.

    Un denominateur qui retrecit en silence est un mensonge par omission — et
    c'est exactement le defaut que ce script est cense debusquer ailleurs. D'ou
    cette fonction : le calcul est trop important pour n'exister que dans un
    `print`.
    """
    reels = sum(1 for _, e, _ in resultats if e == "OK")
    total = sum(1 for _, e, _ in resultats if e in ("OK", "INUTILE", "ANCRE", "TIMEOUT"))
    perdues = [(lib, det) for lib, e, det in resultats if e in ("ANCRE", "TIMEOUT")]
    return reels, total, perdues


def demo() -> None:
    """Auto-controle du calcul. Aucun fichier touche, aucun test lance."""
    # 1. Cas nominal.
    assert synthese([("a", "OK", ""), ("b", "OK", "")])[:2] == (2, 2)

    # 2. Un test decoratif fait baisser le ratio, sans sortir du perimetre.
    assert synthese([("a", "OK", ""), ("b", "INUTILE", "")])[:2] == (1, 2)

    # 3. LE CAS QUI A COUTE : une ancre absente ne doit PAS retrecir le total.
    reels, total, perdues = synthese([("a", "OK", ""), ("b", "ANCRE", "non restauree")])
    assert (reels, total) == (1, 2), (
        "une ancre absente sort du denominateur : le script afficherait un ratio "
        "complet alors qu'un correctif n'est plus eprouve du tout")
    assert perdues and perdues[0][0] == "b"

    # 4. Une mutation non mecanisable reste hors perimetre, elle, et c'est voulu :
    #    elle est declaree telle quelle, ce n'est pas un accident.
    assert synthese([("a", "OK", ""), ("b", "\u2014", "non mutee")])[:2] == (1, 1)

    # 5. UN TEST QUI N'ABOUTIT PAS ne prouve rien : il doit peser dans le
    #    denominateur comme une ancre absente, et etre SIGNALE. Le compter
    #    parmi les reels ferait passer une mutation jamais jouee pour un filet.
    reels, total, perdues = synthese([("a", "OK", ""), ("b", "TIMEOUT", "non abouti")])
    assert (reels, total) == (1, 2), (
        "un timeout hors du denominateur rendrait \u00ab 1/1 \u00bb et une sortie 0 "
        "alors qu'un correctif n'a pas ete eprouve du tout")
    assert perdues and perdues[0][0] == "b"

    print("scripts.mutation_check : 5/5 controles OK")


def main() -> int:
    resultats = []
    for libelle, fichier, avant, apres, test in MUTATIONS:
        if avant is None:                       # mutation non mecanisable
            resultats.append((libelle, "—", "non mutee"))
            continue

        chemin = RACINE / fichier
        original = chemin.read_text(encoding="utf-8")
        if avant not in original:
            # DEUX CAUSES, ET LES DEUX SONT GRAVES.
            #
            #   a) Le texte muté est TOUJOURS LÀ : une exécution précédente a été
            #      interrompue et n'a pas restauré. Le correctif est donc DÉSACTIVÉ
            #      dans l'arbre de travail — c'est arrivé, sur le garde-fou SSRF
            #      de `valider_cible`, et personne ne l'a vu : l'ancre manquante
            #      était rangée en « ? », EXCLUE du total, et le script sortait
            #      quand même en 0. « 16/16 » au lieu de « un correctif de
            #      sécurité est neutralisé ». Exactement la maladie que ce script
            #      est censé débusquer chez les autres.
            #
            #   b) Le correctif a été renommé ou supprimé, et la mutation ne
            #      correspond plus à rien : elle ne prouve donc plus rien.
            #
            # Dans les deux cas c'est un ÉCHEC, pas une omission.
            # DEUX CAUSES, ET ON NE PEUT PAS TOUJOURS TRANCHER.
            #     Si le texte MUTE est encore la, c'est probablement une
            #     execution interrompue qui n'a pas restaure — le correctif est
            #     alors DESACTIVE. Mais quand `apres` est une tournure banale
            #     (`pass`, `if False:`), elle peut aussi exister ailleurs dans le
            #     fichier : affirmer « non restauree » enverrait alors chercher
            #     une panne qui n'existe pas. Un diagnostic faux coute plus cher
            #     qu'un diagnostic prudent — dans les deux cas c'est un ECHEC.
            reste_mute = apres in original
            detail = (f"ancre absente dans {fichier}. "
                      f"Attendu : {avant.strip()[:70]}")
            if reste_mute:
                detail += (" — le texte MUTE est present : soit une execution "
                           "precedente n'a pas restaure (le correctif est alors "
                           "DESACTIVE), soit le correctif a change de forme et "
                           "cette ancre est a mettre a jour.")
            else:
                detail += (" — le correctif a change de forme : cette mutation "
                           "ne prouve plus rien tant qu'elle n'est pas ajustee.")
            resultats.append((libelle, "ANCRE", detail))
            continue

        fd, nom = tempfile.mkstemp(suffix=".bak")
        os.close(fd)                    # sinon Windows refuse de le supprimer
        sauvegarde = Path(nom)
        sauvegarde.write_text(original, encoding="utf-8")
        try:
            chemin.write_text(original.replace(avant, apres, 1), encoding="utf-8")
            passe = lancer(test)
            if passe is None:
                # Ni filet ni decor : rien n'a ete mesure. Compte dans le TOTAL,
                # jamais dans les reels — sinon le ratio parlerait d'un controle
                # qui n'a pas eu lieu.
                resultats.append((libelle, "TIMEOUT",
                                  f"le test n'a pas abouti en {DELAI_TEST_S}s — "
                                  "cette mutation ne prouve RIEN"))
            else:
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
                  "—": "[non mutee]  ", "ANCRE": "[ANCRE KO]   ",
                  "TIMEOUT": "[NON ABOUTI] "}[etat]
        print(f"  {marque}{libelle}")
        print(f"                {detail}")
    reels, total, perdues = synthese(resultats)
    print(f"\n  {reels}/{total} correctifs adosses a un test qui echoue quand on les casse.")
    if perdues:
        print(f"\n  {len(perdues)} mutation(s) n'ont PAS PU ETRE JOUEES :")
        for lib, det in perdues:
            print(f"    - {lib}\n      {det}")
        print("\n  Tant que ces ancres ne sont pas retablies, ce script ne dit")
        print("  RIEN sur les correctifs concernes.")
    return 0 if reels == total else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        demo()
        raise SystemExit(0)
    raise SystemExit(main())
