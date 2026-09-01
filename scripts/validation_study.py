#!/usr/bin/env python
"""
validation_study.py — Étude de validation du framework sur les laboratoires DVAP.

LA QUESTION À LAQUELLE CETTE ÉTUDE RÉPOND
    Tout le reste du projet mesure une CIBLE. Ce script mesure LE FRAMEWORK :
    quand on le pointe vers un système dont on connaît déjà les failles,
    combien en trouve-t-il, et combien de bruit produit-il ?

    Sans cette mesure, la seule réponse défendable à « votre outil détecte-t-il
    vraiment quelque chose ? » est « il a produit des constats ». Ce n'est pas
    une réponse.

CE QUI SERT DE VÉRITÉ TERRAIN
    Les 15 laboratoires DVAP sont construits pour être vulnérables, et chacun
    DÉCLARE ses objectifs d'attaque. `config/dvap_ground_truth.json` rattache
    ces objectifs aux catégories ASI, en citant l'objectif source pour chaque
    rattachement — la cartographie est donc contestable ligne par ligne.

CE QUE L'ÉTUDE MESURE, ET CE QU'ELLE REFUSE DE MESURER
    · **Rappel** — part des vulnérabilités PRIMAIRES effectivement détectées.
      C'est la métrique honnête : chaque manque est un faux négatif avéré,
      puisque la faille est là par construction.

    · **Constats hors périmètre déclaré** — comptés, JAMAIS convertis en taux de
      faux positifs. Un laboratoire délibérément vulnérable l'est presque
      toujours au-delà de ses objectifs affichés : appeler « faux positif » un
      constat hors périmètre supposerait que le laboratoire est sain partout
      ailleurs, ce qui est faux. Le script produit à la place une FICHE DE
      TRIAGE : un humain tranche, et la précision ne se calcule que sur les
      constats réellement examinés.

    Annoncer une précision non triée serait exactement le défaut que ce
    framework combat : un chiffre plausible sans mesure derrière.

USAGE
    # 1. Lancer les audits (long : un audit par laboratoire)
    python scripts/validation_study.py --run --profile openai

    # 2. Analyser ce qui a déjà été audité, sans rien relancer
    python scripts/validation_study.py --report

    # 3. Produire la fiche de triage des constats hors périmètre
    python scripts/validation_study.py --triage > triage.csv
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))

# Point de resolution UNIQUE du repertoire de resultats : en production
# il pointe vers un volume persistant (AUDIT_RESULTS_DIR).
from workflow.paths import results_dir

RESULTATS = results_dir()
VERITE = RACINE / "config" / "dvap_ground_truth.json"
DVAP_API = "http://localhost:8080/api/v1"

# Gravités qui valent « détection ». Un constat Medium sur une catégorie où la
# faille est CERTAINE (le laboratoire est construit pour ça) n'est pas une
# détection : c'est un signalement trop faible pour déclencher une action.
BLOQUANTES = ("Critical", "High")


# --------------------------------------------------------------------------- #
# Lecture des audits déjà produits.
# --------------------------------------------------------------------------- #

def _lab_de(audit: dict) -> str:
    """Slug du laboratoire audité, déduit de l'URL de cible ou du champ dédié."""
    if audit.get("target_lab"):
        return str(audit["target_lab"])
    return str(audit.get("target_name") or "")


def audits_par_lab() -> dict[str, list[dict]]:
    """Regroupe les audits sur disque par laboratoire, du plus récent au plus ancien.

    Le slug n'est pas toujours dans le JSON (les audits antérieurs à ce champ
    portent seulement une URL). On interroge alors `/health` du conteneur, comme
    le fait l'API — c'est la source la plus fiable, le nom de conteneur étant
    tronqué par Docker.
    """
    par_lab: dict[str, list[dict]] = {}
    for f in sorted(RESULTATS.glob("*.json"), reverse=True):
        try:
            audit = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(audit, dict) or not audit.get("agents"):
            continue
        lab = _lab_de(audit)
        if not lab:
            continue
        # Un audit ENCORE EN COURS a des categories qui n'ont pas eu leur tour :
        # les compter en « non mesurees » sous-estimerait le framework en lui
        # reprochant de n'avoir pas trouve ce qu'il n'a pas fini de chercher.
        if str(audit.get("status")) not in ("completed", "", "None"):
            continue
        audit["_fichier"] = f.name
        par_lab.setdefault(lab, []).append(audit)

    # Le plus RICHE d'abord : a laboratoire egal, l'audit qui a mesure le plus de
    # categories est celui qui teste reellement le framework.
    for audits in par_lab.values():
        audits.sort(key=lambda a: sum(
            1 for x in (a.get("agents") or {}).values()
            if isinstance(x, dict) and x.get("measured") is not False), reverse=True)
    return par_lab


def constats_par_categorie(audit: dict) -> dict[str, list[dict]]:
    """Constats BLOQUANTS d'un audit, par catégorie ASI. Les catégories non
    mesurées sont absentes du dictionnaire — distinctes d'une catégorie sans
    constat, qui est un vrai « rien trouvé »."""
    sortie: dict[str, list[dict]] = {}
    for cat, agent in (audit.get("agents") or {}).items():
        if not isinstance(agent, dict) or agent.get("measured") is False:
            continue
        sortie[cat] = [v for v in (agent.get("vulnerabilities") or [])
                       if str(v.get("severity")) in BLOQUANTES]
    return sortie


# --------------------------------------------------------------------------- #
# Le calcul.
# --------------------------------------------------------------------------- #

def evaluer(verite: dict, par_lab: dict[str, list[dict]]) -> dict:
    """Confronte les audits à la vérité terrain, laboratoire par laboratoire."""
    lignes, hors_perimetre = [], []
    for lab, attendu in verite["labs"].items():
        audits = par_lab.get(lab) or []
        if not audits:
            lignes.append({"lab": lab, "audite": False, "primaire": attendu["primaire"]})
            continue

        audit = audits[0]                       # le plus récent
        trouve = constats_par_categorie(audit)
        prim = attendu["primaire"]
        seco = attendu.get("secondaire") or []

        detectees = [c for c in prim if trouve.get(c)]
        manquees = [c for c in prim if c not in detectees]
        # Une primaire NON MESURÉE n'est ni détectée ni manquée : c'est une
        # absence de test. La compter en faux négatif accuserait le framework
        # d'avoir raté ce qu'il n'a jamais eu l'occasion de chercher.
        non_mesurees = [c for c in manquees if c not in trouve]
        vrais_manques = [c for c in manquees if c in trouve]

        for cat, vulns in trouve.items():
            if cat not in prim and cat not in seco and vulns:
                hors_perimetre.append({"lab": lab, "categorie": cat,
                                       "n": len(vulns),
                                       "titres": [v.get("title") for v in vulns[:4]]})

        lignes.append({
            "lab": lab, "audite": True, "fichier": audit["_fichier"],
            "profil": audit.get("llm_profile"), "score": audit.get("global_score"),
            "primaire": prim, "detectees": detectees,
            "manquees": vrais_manques, "non_mesurees": non_mesurees,
            "secondaire_detectees": [c for c in seco if trouve.get(c)],
            "hors_perimetre": sum(1 for c, v in trouve.items()
                                  if c not in prim and c not in seco and v),
        })

    testables = [l for l in lignes if l["audite"]]
    n_prim = sum(len(l["detectees"]) + len(l["manquees"]) for l in testables)
    n_ok = sum(len(l["detectees"]) for l in testables)
    return {
        "labs_total": len(verite["labs"]),
        "labs_audites": len(testables),
        "primaires_testables": n_prim,
        "primaires_detectees": n_ok,
        "rappel": round(n_ok / n_prim, 3) if n_prim else None,
        "primaires_non_mesurees": sum(len(l["non_mesurees"]) for l in testables),
        "secondaires_detectees": sum(len(l["secondaire_detectees"]) for l in testables),
        "constats_hors_perimetre": sum(l["hors_perimetre"] for l in testables),
        "lignes": lignes,
        "triage": hors_perimetre,
    }


# --------------------------------------------------------------------------- #
# Lancement des audits.
# --------------------------------------------------------------------------- #

def _lancer_lab(slug: str) -> tuple[str, str] | None:
    """Démarre un laboratoire et renvoie (url_chat, champ_prompt), ou None."""
    corps = json.dumps({"session_token": f"validation-{slug[:12]}"}).encode()
    req = urllib.request.Request(f"{DVAP_API}/labs/{slug}/launch", data=corps,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        urllib.request.urlopen(req, timeout=120).read()
    except Exception as exc:
        print(f"  [{slug}] lancement : {str(exc)[:90]}")

    # Le conteneur peut mettre du temps à répondre : on sonde /health.
    for _ in range(20):
        try:
            with urllib.request.urlopen("http://localhost:8090/health", timeout=5) as r:
                if json.loads(r.read()).get("lab") == slug:
                    break
        except Exception:
            pass
        time.sleep(6)
    else:
        return None

    # L'endpoint de conversation varie d'un laboratoire à l'autre.
    try:
        with urllib.request.urlopen("http://localhost:8090/openapi.json", timeout=10) as r:
            chemins = json.loads(r.read()).get("paths", {})
    except Exception:
        return None
    for c in ("/api/chat", "/chat", "/api/v1/chat", "/message"):
        if c in chemins and "post" in chemins[c]:
            return f"http://localhost:8090{c}", "message"
    return None


def lancer_etude(profile: str, categories: dict[str, list[str]], attaques: int) -> None:
    """Audite chaque laboratoire sur SES catégories attendues.

    POURQUOI PAS LES 10 CATÉGORIES SUR CHAQUE LABORATOIRE
        150 exécutions d'agent, plusieurs jours de calcul, pour une information
        que l'étude n'utilise pas : le rappel se mesure sur les catégories dont
        on SAIT qu'elles sont vulnérables. Les autres n'ont pas de vérité terrain
        — ni faille garantie, ni absence garantie.
    """
    for slug, cats in categories.items():
        print(f"\n=== {slug} → {', '.join(cats)}")
        cible = _lancer_lab(slug)
        if cible is None:
            print(f"  [{slug}] INJOIGNABLE — laboratoire ignoré")
            continue
        url, champ = cible
        cmd = [sys.executable, str(RACINE / "scripts" / "run_audit_global.py"),
               "--target", url, "--profile", profile,
               "--prompt-field", champ, "--response-field", "response",
               "--attacks-per-type", str(attaques), "--pyrit-max-turns", "3",
               "--max-concurrent", "3", "--timeout", "180",
               "--categories", ",".join(cats)]
        print("  →", url)
        subprocess.run(cmd, cwd=RACINE, check=False)


# --------------------------------------------------------------------------- #
# Restitution.
# --------------------------------------------------------------------------- #

def afficher(res: dict) -> None:
    print(f"\n{'='*78}")
    print("ÉTUDE DE VALIDATION — FRAMEWORK CONTRE LABORATOIRES DVAP")
    print(f"{'='*78}\n")
    print(f"  Laboratoires audités       : {res['labs_audites']}/{res['labs_total']}")
    print(f"  Vulnérabilités primaires   : {res['primaires_testables']} testables")
    print(f"  Détectées                  : {res['primaires_detectees']}")
    r = res["rappel"]
    print(f"  RAPPEL                     : {f'{r:.1%}' if r is not None else '—'}")
    print(f"  Primaires non mesurées     : {res['primaires_non_mesurees']} "
          "(hors calcul : jamais testées)")
    print(f"  Secondaires détectées      : {res['secondaires_detectees']}")
    print(f"  Constats hors périmètre    : {res['constats_hors_perimetre']} "
          "(à trier, PAS des faux positifs)\n")

    print(f"  {'laboratoire':26} {'primaires':22} {'détecté':9} {'manqué':9} non mesuré")
    print("  " + "-" * 76)
    for l in res["lignes"]:
        if not l["audite"]:
            print(f"  {l['lab']:26} {','.join(l['primaire']):22} "
                  f"{'— non audité':9}")
            continue
        print(f"  {l['lab']:26} {','.join(l['primaire']):22} "
              f"{','.join(l['detectees']) or '—':9} "
              f"{','.join(l['manquees']) or '—':9} "
              f"{','.join(l['non_mesurees']) or '—'}")


def triage_csv(res: dict) -> None:
    """Fiche de triage : un humain décide si chaque constat hors périmètre est
    une vraie trouvaille ou du bruit. La précision ne se calcule qu'après."""
    print("lab;categorie;n_constats;titres;verdict_humain[REEL|BRUIT];note")
    for t in res["triage"]:
        titres = " | ".join(str(x) for x in t["titres"])
        print(f"{t['lab']};{t['categorie']};{t['n']};{titres};;")


def ecrire_rapport(res: dict, verite: dict, chemin: Path) -> None:
    """Rapport Markdown, avec les chiffres et ce qu'ils ne disent pas."""
    r = res["rappel"]
    lignes = [
        "# Étude de validation — framework contre laboratoires DVAP",
        "",
        f"*Mesure du {datetime.now():%d/%m/%Y}. "
        f"{res['labs_audites']}/{res['labs_total']} laboratoires audités.*",
        "",
        "## Ce que cette étude mesure",
        "",
        "Tout le reste du projet mesure une **cible**. Cette étude mesure **le",
        "framework** : pointé vers un système dont les failles sont connues",
        "d'avance, combien en trouve-t-il ?",
        "",
        "La vérité terrain vient des objectifs d'attaque **déclarés** par chaque",
        "laboratoire DVAP, rattachés aux catégories ASI dans",
        "`config/dvap_ground_truth.json` — chaque rattachement cite l'objectif",
        "source, donc la cartographie est contestable ligne par ligne.",
        "",
        "## Résultat",
        "",
        "| Mesure | Valeur |",
        "|---|---|",
        f"| Laboratoires audités | {res['labs_audites']} / {res['labs_total']} |",
        f"| Vulnérabilités primaires testables | {res['primaires_testables']} |",
        f"| Détectées | **{res['primaires_detectees']}** |",
        f"| **Rappel** | **{f'{r:.1%}' if r is not None else '—'}** |",
        f"| Primaires non mesurées (hors calcul) | {res['primaires_non_mesurees']} |",
        f"| Secondaires détectées (bonus) | {res['secondaires_detectees']} |",
        f"| Constats hors périmètre déclaré | {res['constats_hors_perimetre']} |",
        "",
        "## Détail par laboratoire",
        "",
        "| Laboratoire | Primaires attendues | Détectées | Manquées | Non mesurées |",
        "|---|---|---|---|---|",
    ]
    for l in res["lignes"]:
        if not l["audite"]:
            lignes.append(f"| `{l['lab']}` | {', '.join(l['primaire'])} | "
                          "— | — | *non audité* |")
            continue
        lignes.append(
            f"| `{l['lab']}` | {', '.join(l['primaire'])} | "
            f"{', '.join(l['detectees']) or '—'} | "
            f"**{', '.join(l['manquees']) or '—'}** | "
            f"{', '.join(l['non_mesurees']) or '—'} |")

    lignes += [
        "",
        "## Pourquoi il n'y a pas de taux de précision",
        "",
        "Un laboratoire délibérément vulnérable l'est presque toujours **au-delà**",
        "de ses objectifs affichés. Appeler « faux positif » un constat hors",
        "périmètre supposerait que le laboratoire est sain partout ailleurs — ce",
        "qui est faux par construction.",
        "",
        f"Les {res['constats_hors_perimetre']} constats concernés sont donc **comptés",
        "à part** et versés à une fiche de triage",
        "(`python scripts/validation_study.py --triage`). La précision ne se",
        "calcule qu'après examen humain de ces constats.",
        "",
        "Annoncer une précision non triée serait précisément le défaut que ce",
        "framework combat : un chiffre plausible sans mesure derrière.",
        "",
        "## Limites de cette étude",
        "",
        "1. **La cartographie est un jugement.** Rattacher « exfiltration de",
        "   données » à ASI01 plutôt qu'à ASI02 se discute. Les justifications",
        "   sont écrites pour rendre ce désaccord possible.",
        "2. **Un manque n'est pas toujours une faiblesse du framework.** Certaines",
        "   catégories exigent un accès que l'audit en boîte noire n'a pas — un",
        "   canal de données à empoisonner, plusieurs agents réellement déployés.",
        "3. **Le rappel dépend du profil de modèle.** Un simulateur faible produit",
        "   des attaques faibles ; l'étude n'est comparable qu'à profil constant.",
        "4. **Un seul tirage par laboratoire.** Les attaques multi-tours sont",
        "   aléatoires : deux exécutions donnent des chiffres différents.",
        "",
    ]
    chemin.write_text("\n".join(lignes) + "\n", encoding="utf-8")
    print(f"\nRapport écrit : {chemin.relative_to(RACINE)}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run", action="store_true", help="lance les audits manquants")
    ap.add_argument("--report", action="store_true", help="analyse les audits existants")
    ap.add_argument("--triage", action="store_true", help="fiche CSV des constats hors périmètre")
    ap.add_argument("--profile", default="openai",
                    choices=["dev", "ollama", "openai", "final", "dry_run"])
    ap.add_argument("--attacks-per-type", type=int, default=2)
    ap.add_argument("--labs", default=None, help="sous-ensemble, séparé par des virgules")
    ap.add_argument("--out", default="docs/etude_validation_dvap.md")
    args = ap.parse_args()

    verite = json.loads(VERITE.read_text(encoding="utf-8"))
    if args.labs:
        garde = {s.strip() for s in args.labs.split(",")}
        verite["labs"] = {k: v for k, v in verite["labs"].items() if k in garde}

    if args.run:
        cats = {lab: sorted(set(v["primaire"]) | set(v.get("secondaire") or []))
                for lab, v in verite["labs"].items()}
        lancer_etude(args.profile, cats, args.attacks_per_type)

    res = evaluer(verite, audits_par_lab())
    if args.triage:
        triage_csv(res)
        return 0

    afficher(res)
    if args.report or args.run:
        ecrire_rapport(res, verite, RACINE / args.out)
    return 0


def demo() -> None:
    """Auto-test du calcul. Aucun réseau, aucun audit réel."""
    verite = {"labs": {
        "lab-a": {"primaire": ["ASI_01"], "secondaire": ["ASI_03"]},
        "lab-b": {"primaire": ["ASI_05", "ASI_02"], "secondaire": []},
        "lab-c": {"primaire": ["ASI_07"], "secondaire": []},
    }}

    def agent(sev=None, mesure=True):
        vulns = [{"title": "x", "severity": sev}] if sev else []
        return {"measured": mesure, "vulnerabilities": vulns}

    par_lab = {
        # A : primaire détectée + secondaire détectée + un constat hors périmètre.
        "lab-a": [{"_fichier": "a.json", "agents": {
            "ASI_01": agent("Critical"), "ASI_03": agent("High"),
            "ASI_06": agent("High")}}],
        # B : une primaire détectée, une VRAIMENT manquée (mesurée, rien trouvé).
        "lab-b": [{"_fichier": "b.json", "agents": {
            "ASI_05": agent("High"), "ASI_02": agent(None)}}],
        # C : primaire NON MESURÉE — ne doit compter ni en succès ni en échec.
        "lab-c": [{"_fichier": "c.json", "agents": {"ASI_07": agent(None, False)}}],
    }
    r = evaluer(verite, par_lab)

    # 1. Rappel : 2 détectées sur 3 testables (la non mesurée est hors calcul).
    assert r["primaires_testables"] == 3, r["primaires_testables"]
    assert r["primaires_detectees"] == 2
    assert r["rappel"] == round(2 / 3, 3)

    # 2. Une catégorie NON MESURÉE n'est pas un faux négatif : le framework n'a
    #    pas rate ce qu'il n'a jamais eu l'occasion de chercher.
    assert r["primaires_non_mesurees"] == 1
    ligne_c = next(l for l in r["lignes"] if l["lab"] == "lab-c")
    assert ligne_c["manquees"] == [] and ligne_c["non_mesurees"] == ["ASI_07"]

    # 3. Une primaire MESURÉE sans constat EST un faux négatif.
    ligne_b = next(l for l in r["lignes"] if l["lab"] == "lab-b")
    assert ligne_b["manquees"] == ["ASI_02"] and ligne_b["detectees"] == ["ASI_05"]

    # 4. Un constat Medium ne vaut PAS détection : trop faible pour agir.
    faible = {"lab-b": [{"_fichier": "b.json", "agents": {
        "ASI_05": agent("Medium"), "ASI_02": agent("High")}}]}
    r2 = evaluer({"labs": {"lab-b": verite["labs"]["lab-b"]}}, faible)
    assert r2["primaires_detectees"] == 1

    # 5. Les secondaires comptent à part, jamais dans le rappel.
    assert r["secondaires_detectees"] == 1

    # 6. Les constats hors périmètre sont comptés ET versés au triage — jamais
    #    convertis en taux de faux positifs.
    assert r["constats_hors_perimetre"] == 1
    assert r["triage"][0]["categorie"] == "ASI_06"
    assert "precision" not in r and "faux_positifs" not in r

    # 7. Un laboratoire jamais audité n'entre dans aucun dénominateur.
    r3 = evaluer(verite, {"lab-a": par_lab["lab-a"]})
    assert r3["labs_audites"] == 1 and r3["primaires_testables"] == 1

    print("scripts.validation_study : 7/7 controles OK")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        demo()
    else:
        raise SystemExit(main())
