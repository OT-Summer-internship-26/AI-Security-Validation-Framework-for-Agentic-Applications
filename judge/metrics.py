"""
metrics.py — Ce qu'a réellement coûté un audit, mesuré sans dépendre de personne.

LE PROBLÈME QU'IL RÉSOUT
    L'observabilité du framework vivait entièrement dans LangFuse. Or LangFuse
    est OPTIONNEL : sans lui, un audit ne laissait aucune trace de son exécution
    — ni volume d'appels, ni jetons consommés, ni coût, ni durée par axe. Le
    rapport parlait uniquement des attaques, jamais du travail qui les avait
    produites.

    Conséquences concrètes :
    · impossible de répondre à « combien coûte un audit ? » sans relire un
      journal de sortie standard ;
    · impossible de savoir quel axe a pris les trois quarts du temps ;
    · impossible d'exposer quoi que ce soit à la supervision d'entreprise, qui
      attend des compteurs, pas un tableau de bord tiers.

CE QUE CE MODULE MESURE, ET OÙ IL SE BRANCHE
    Il s'accroche aux DEUX points de passage déjà uniques du framework :
    `tracing._wrap` (tout appel de modèle) et `tracing.observe_step` (les étapes
    non-LLM : cible HTTP, garak, pyrit, sandbox). Aucun appelant à modifier, et
    un axe ajouté demain est compté sans rien faire.

POURQUOI UN MODULE SÉPARÉ DE `tracing`
    `tracing` peut être entièrement inerte — c'est même son mode par défaut.
    Y loger les compteurs les rendrait inertes aussi. Ici, la mesure est
    TOUJOURS active : elle ne coûte qu'un verrou et quelques additions.

PORTÉE
    Les compteurs sont GLOBAUX au processus et protégés par un verrou : cinq
    agents tournent en parallèle dans autant de fils d'exécution. La ventilation
    par catégorie vient du contexte de traçage, qui est propre au fil.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any

_VERROU = threading.Lock()

# Un compteur par (portée, nom). La portée sépare les appels de modèle des
# étapes non-LLM : les mélanger donnerait une moyenne qui ne veut rien dire,
# une requête HTTP vers la cible n'ayant rien à voir avec un jugement.
_APPELS: dict[tuple[str, str], dict[str, float]] = defaultdict(
    lambda: {"n": 0, "erreurs": 0, "secondes": 0.0,
             "jetons_entree": 0, "jetons_sortie": 0, "cout": 0.0})

# Ventilation par catégorie ASI, pour répondre à « quel agent a coûté cher ».
_PAR_CATEGORIE: dict[str, dict[str, float]] = defaultdict(
    lambda: {"appels_llm": 0, "etapes": 0, "secondes": 0.0, "cout": 0.0,
             "jetons": 0})

_DEBUT = time.time()


def _categorie() -> str:
    """Catégorie ASI en cours sur CE fil d'exécution, ou « (global) »."""
    try:
        from judge.tracing import current_context

        return current_context().get("category") or "(global)"
    except Exception:
        return "(global)"


def record_llm(role: str, secondes: float, *, jetons_entree: int = 0,
               jetons_sortie: int = 0, cout: float = 0.0,
               erreur: bool = False) -> None:
    """Enregistre un appel de modèle. Ne lève jamais : une mesure ne casse rien."""
    try:
        cat = _categorie()
        with _VERROU:
            c = _APPELS[("llm", role)]
            c["n"] += 1
            c["secondes"] += secondes
            c["jetons_entree"] += jetons_entree
            c["jetons_sortie"] += jetons_sortie
            c["cout"] += cout
            if erreur:
                c["erreurs"] += 1
            p = _PAR_CATEGORIE[cat]
            p["appels_llm"] += 1
            p["secondes"] += secondes
            p["cout"] += cout
            p["jetons"] += jetons_entree + jetons_sortie
    except Exception:                      # jamais bloquant
        pass


def record_step(nom: str, secondes: float, *, erreur: bool = False) -> None:
    """Enregistre une étape non-LLM (cible HTTP, garak, pyrit, sandbox)."""
    try:
        cat = _categorie()
        with _VERROU:
            c = _APPELS[("etape", nom)]
            c["n"] += 1
            c["secondes"] += secondes
            if erreur:
                c["erreurs"] += 1
            p = _PAR_CATEGORIE[cat]
            p["etapes"] += 1
            p["secondes"] += secondes
    except Exception:
        pass


def reset() -> None:
    """Repart de zéro. Appelé au début d'un audit.

    Sans cela, deux audits lancés dans le même processus (l'API en lance
    plusieurs) additionneraient leurs compteurs, et le second afficherait le
    coût des deux.
    """
    global _DEBUT
    with _VERROU:
        _APPELS.clear()
        _PAR_CATEGORIE.clear()
        _DEBUT = time.time()


def snapshot() -> dict[str, Any]:
    """État courant des compteurs, prêt à écrire dans le JSON d'audit.

    Renvoie `{}` si rien n'a été mesuré — un bloc vide dans le rapport se lirait
    comme « l'audit n'a rien coûté », ce qui est faux : il n'a rien été observé.
    """
    with _VERROU:
        if not _APPELS:
            return {}
        llm = {nom: dict(v) for (portee, nom), v in _APPELS.items() if portee == "llm"}
        etapes = {nom: dict(v) for (portee, nom), v in _APPELS.items() if portee == "etape"}
        par_cat = {k: dict(v) for k, v in _PAR_CATEGORIE.items()}
        ecoule = time.time() - _DEBUT

    n_llm = sum(int(v["n"]) for v in llm.values())
    secondes_llm = sum(v["secondes"] for v in llm.values())
    cout = sum(v["cout"] for v in llm.values())
    jetons = sum(int(v["jetons_entree"] + v["jetons_sortie"]) for v in llm.values())
    secondes_etapes = sum(v["secondes"] for v in etapes.values())

    return {
        "appels_llm": n_llm,
        "erreurs_llm": sum(int(v["erreurs"]) for v in llm.values()),
        "jetons": jetons,
        "cout_usd": round(cout, 4),
        "secondes_llm": round(secondes_llm, 1),
        "secondes_etapes": round(secondes_etapes, 1),
        "secondes_total": round(ecoule, 1),
        # Attente CUMULÉE sur tous les fils d'exécution : modèles + cible + outils.
        "secondes_attente": round(secondes_llm + secondes_etapes, 1),
        # Rapport entre l'attente cumulée et le temps réellement écoulé.
        #
        # POURQUOI UN RAPPORT ET NON UN POURCENTAGE
        #     Cinq agents tournent en parallèle : l'attente cumulée DÉPASSE le
        #     temps écoulé, et un « pourcentage » dépassant 100 ne veut rien
        #     dire. Ce rapport, lui, se lit directement : 1,0 = tout s'est
        #     déroulé en série ; 4,5 = l'audit a effectivement attendu 4,5 choses
        #     à la fois. C'est la mesure du parallélisme RÉEL, celle qui dit si
        #     les vagues servent à quelque chose.
        #
        #     `None` quand le temps écoulé est trop court pour être mesuré — la
        #     résolution d'horloge de Windows peut rendre exactement 0.
        "parallelisme_effectif": (
            round((secondes_llm + secondes_etapes) / ecoule, 2)
            if ecoule > 0.01 else None),
        "par_role": {k: {**v, "n": int(v["n"]), "erreurs": int(v["erreurs"]),
                         "secondes": round(v["secondes"], 1),
                         "cout": round(v["cout"], 4)} for k, v in sorted(llm.items())},
        "par_etape": {k: {"n": int(v["n"]), "erreurs": int(v["erreurs"]),
                          "secondes": round(v["secondes"], 1)}
                      for k, v in sorted(etapes.items())},
        "par_categorie": {k: {"appels_llm": int(v["appels_llm"]),
                              "etapes": int(v["etapes"]),
                              "secondes": round(v["secondes"], 1),
                              "jetons": int(v["jetons"]),
                              "cout": round(v["cout"], 4)}
                          for k, v in sorted(par_cat.items())},
    }


def prometheus() -> str:
    """Compteurs au format d'exposition Prometheus.

    POURQUOI CE FORMAT ET PAS DU JSON
        La supervision d'entreprise collecte en tirant sur un `/metrics` au
        format texte de Prometheus. Servir du JSON obligerait chaque équipe à
        écrire un adaptateur — c'est-à-dire à ne pas superviser.

    Les compteurs sont CUMULATIFS depuis le démarrage du processus, comme le
    veut la convention : c'est le collecteur qui calcule les taux.
    """
    s = snapshot()
    lignes: list[str] = []

    def ajouter(nom: str, aide: str, typ: str, valeurs: list[tuple[str, Any]]) -> None:
        lignes.append(f"# HELP {nom} {aide}")
        lignes.append(f"# TYPE {nom} {typ}")
        lignes.extend(f"{nom}{etiq} {val}" for etiq, val in valeurs)

    if not s:
        ajouter("aisec_audit_llm_calls_total",
                "Appels de modele effectues depuis le demarrage.", "counter",
                [("", 0)])
        return "\n".join(lignes) + "\n"

    ajouter("aisec_llm_calls_total", "Appels de modele par role.", "counter",
            [(f'{{role="{r}"}}', v["n"]) for r, v in s["par_role"].items()])
    ajouter("aisec_llm_errors_total", "Appels de modele en erreur, par role.",
            "counter", [(f'{{role="{r}"}}', v["erreurs"]) for r, v in s["par_role"].items()])
    ajouter("aisec_llm_seconds_total", "Temps cumule d'attente des modeles, par role.",
            "counter", [(f'{{role="{r}"}}', v["secondes"]) for r, v in s["par_role"].items()])
    ajouter("aisec_llm_tokens_total", "Jetons consommes, par role et direction.",
            "counter",
            [(f'{{role="{r}",direction="{d}"}}', v[f"jetons_{c}"])
             for r, v in s["par_role"].items()
             for d, c in (("input", "entree"), ("output", "sortie"))])
    ajouter("aisec_llm_cost_usd_total", "Cout cumule estime, par role.", "counter",
            [(f'{{role="{r}"}}', v["cout"]) for r, v in s["par_role"].items()])
    ajouter("aisec_step_seconds_total",
            "Temps cumule des etapes non-LLM (cible HTTP, garak, pyrit, sandbox).",
            "counter",
            [(f'{{step="{n}"}}', v["secondes"]) for n, v in s["par_etape"].items()])
    ajouter("aisec_step_errors_total", "Etapes non-LLM en erreur.", "counter",
            [(f'{{step="{n}"}}', v["erreurs"]) for n, v in s["par_etape"].items()])
    ajouter("aisec_wait_seconds_total",
            "Attente cumulee (modeles + cible + outils), tous fils confondus.",
            "counter", [("", s["secondes_attente"])])
    ajouter("aisec_process_seconds_total",
            "Secondes ecoulees depuis la derniere remise a zero des compteurs.",
            "gauge", [("", s["secondes_total"])])
    return "\n".join(lignes) + "\n"


def demo() -> None:
    """Auto-test : cumul, ventilation, remise a zero, format Prometheus."""
    import time as _t

    reset()

    # 1. Rien de mesure -> {} et non des zeros. Un bloc de zeros dans le rapport
    #    se lirait « l'audit n'a rien coute », ce qui est faux.
    assert snapshot() == {}

    record_llm("severity", 1.5, jetons_entree=1000, jetons_sortie=200, cout=0.002)
    record_llm("severity", 0.5, jetons_entree=500, jetons_sortie=100, cout=0.001)
    record_llm("simulator", 3.0, jetons_entree=2000, jetons_sortie=800, cout=0.01,
               erreur=True)
    record_step("cible_http", 19.0)
    record_step("garak", 45.0, erreur=True)

    s = snapshot()
    # 2. Cumul par role, pas par appel.
    assert s["appels_llm"] == 3 and s["erreurs_llm"] == 1
    assert s["par_role"]["severity"]["n"] == 2
    assert s["par_role"]["severity"]["secondes"] == 2.0
    assert s["jetons"] == 1000 + 200 + 500 + 100 + 2000 + 800
    assert s["cout_usd"] == 0.013

    # 3. Les etapes non-LLM sont comptees A PART : melanger une requete HTTP de
    #    19 s et un jugement de 0,5 s donnerait une moyenne sans signification.
    assert s["par_etape"]["garak"]["erreurs"] == 1
    assert s["secondes_etapes"] == 64.0 and s["secondes_llm"] == 5.0

    # 4. L'attente cumulee est toujours mesuree ; le rapport de parallelisme,
    #    lui, exige un temps ecoule mesurable. Une horloge Windows peut rendre
    #    exactement 0 entre le reset et le releve — le module ne doit pas s'en
    #    trouver casse, seulement muet sur ce point precis.
    assert s["secondes_attente"] == 69.0
    assert s["parallelisme_effectif"] is None or s["parallelisme_effectif"] > 0


    # 5. Format Prometheus : chaque metrique porte son HELP et son TYPE, sinon
    #    un collecteur la refuse.
    p = prometheus()
    for m in ("aisec_llm_calls_total", "aisec_llm_tokens_total",
              "aisec_step_seconds_total", "aisec_llm_cost_usd_total"):
        assert f"# HELP {m} " in p and f"# TYPE {m} " in p, m
    assert 'aisec_llm_calls_total{role="severity"} 2' in p
    assert 'aisec_llm_tokens_total{role="severity",direction="input"} 1500' in p

    # 6. Remise a zero : deux audits dans le MEME processus (l'API en lance
    #    plusieurs) ne doivent pas additionner leurs couts.
    reset()
    assert snapshot() == {}
    assert "aisec_audit_llm_calls_total" in prometheus(), (
        "meme vide, /metrics doit repondre — un collecteur qui recoit une page "
        "blanche marque la cible en panne")

    # 7. L'attente cumulee PEUT depasser le temps ecoule : c'est le
    #    parallelisme. Un pourcentage dirait « 400 % », ce qui ne se lit pas ;
    #    un rapport de 4,0 se lit « quatre choses attendues a la fois ».
    reset()
    record_llm("x", 7200.0)
    record_step("y", 7200.0)
    _t.sleep(0.02)
    r = snapshot()["parallelisme_effectif"]
    assert r is not None and r > 100, "le rapport doit pouvoir depasser 1"

    print("judge.metrics : 7/7 controles OK")


if __name__ == "__main__":
    demo()
