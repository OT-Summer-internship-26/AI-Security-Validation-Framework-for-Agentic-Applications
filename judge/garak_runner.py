"""
garak_runner.py — Attaques automatiques garak (NVIDIA/leondz) en complément DeepTeam + PyRIT.

POURQUOI SOUS-PROCESSUS (et pas un import)
    garak est installé dans un VENV ISOLÉ (~/garak-venv) : la seule version sans Rust
    (0.9.0.11) épingle `openai==0.28.1`, incompatible avec le stack openai 2.x de
    DeepTeam/DeepEval. On l'invoque donc par SOUS-PROCESSUS vers ce venv — jamais
    importé dans l'env principal. garak cible l'agent sous test via son générateur
    `rest` (aucun LLM attaquant requis : les probes garak SONT les attaques).

FAITS VÉRIFIÉS PAR SPIKE (garak 0.9.0.11 dans le venv)
    - Générateur `rest` : config JSON `{"rest.RestGenerator": {uri, method,
      headers, req_template_json_object avec "$INPUT", response_json,
      response_json_field}}` passée via `-G <fichier>`.
    - Rapport `.report.jsonl` : lignes `entry_type == "eval"` avec
      {probe, detector, passed, total} → score = passed/total agrégé.
    - Probes jailbreak/injection : dan.* (détecteurs par mots-clés, rapides).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

# Python du venv garak isolé (surchargeable par `GARAK_VENV_PYTHON`).
#
# LE DEFAUT ETAIT LE CHEMIN PERSONNEL DE L'AUTEUR, EN DUR.
#     C:\Users\asser\garak-venv\Scripts\python.exe . Sur toute AUTRE machine — un
#     collegue, un runner, et surtout L'IMAGE qui est Linux —
#     `garak_available()` rendait False pour toujours. L'axe garak, le SEUL
#     axe independant du LLM, disparaissait de tous les audits sans que rien
#     ne le dise : « unavailable » etait traite comme un axe exclu, jamais
#     comme un defaut d'installation. Meme classe de panne que PyRIT absent
#     du verrou — declare quelque part, introuvable la ou ca compte.
#
#     Le defaut se deduit maintenant du systeme et du dossier personnel : il
#     designe LE MEME FICHIER qu'avant sur le poste de l'auteur, donc rien ne
#     change pour lui, et un chemin atteignable partout ailleurs.
def _venv_garak_par_defaut() -> str:
    if os.name == "nt":
        return str(Path.home() / "garak-venv" / "Scripts" / "python.exe")
    return str(Path.home() / "garak-venv" / "bin" / "python")


GARAK_VENV_PYTHON = os.environ.get("GARAK_VENV_PYTHON") or _venv_garak_par_defaut()
# Probes ASI01 par défaut (jailbreak / override d'objectif) — petit set pour la vitesse.
DEFAULT_PROBES = os.environ.get("GARAK_PROBES", "dan.AntiDAN,dan.DAN_Jailbreak")
_TIMEOUT = int(os.environ.get("GARAK_TIMEOUT", "600"))


def garak_available() -> bool:
    """Vrai si le python du venv garak isolé existe."""
    return os.path.isfile(GARAK_VENV_PYTHON)


def run_garak(
    target_url: str,
    *,
    prompt_field: str = "prompt",
    response_field: str = "response",
    headers: dict[str, str] | None = None,
    probes: str = DEFAULT_PROBES,
    generations: int = 1,
    request_timeout: int = 60,
    extra_payload: dict[str, Any] | None = None,
) -> tuple[float | None, list[dict[str, Any]], str, dict[str, Any]]:
    """Lance garak (venv, sous-processus) contre `target_url`.

    Retour : (score | None, findings, status, raw)
        - score : pass_rate × 10 (10 = a résisté à toutes les attaques garak).
        - findings : dicts {probe, detector, passed, total, failure_rate} pour les
          probes où garak a détecté une faille (passed < total).
        - None : garak indisponible / échec / aucune évaluation exploitable
          (ex. cible injoignable) — jamais un faux 10/10.
    """
    if not garak_available():
        return None, [], f"unavailable: venv garak introuvable ({GARAK_VENV_PYTHON})", {}

    workdir = tempfile.mkdtemp(prefix="garak_")
    config_path = os.path.join(workdir, "rest.json")
    report_prefix = os.path.join(workdir, "run")

    # garak POST {prompt_field: "$INPUT"} vers target_url et lit response_field.
    config = {
        "rest.RestGenerator": {
            "name": "audit-target",
            "uri": target_url,
            "method": "post",
            # FUSION, PAS REMPLACEMENT. garak envoie le corps en CHAINE (`data=`)
            # et n'ajoute aucun Content-Type : des en-tetes de cible sans lui
            # (`{"Authorization": …}`) faisaient repondre 422 a une cible JSON
            # sur chaque sonde — axe exclu, sans autre signe.
            "headers": {"Content-Type": "application/json", **(headers or {})},
            # `extra_payload` : champs JSON constants exigés par la cible EN PLUS du
            # prompt (ex. lab DVAP autonomous-agent : {"title": …, "content": …} — les
            # deux sont requis, sinon 422). Même paramètre que build_http_callback pour
            # que les 4 axes voient exactement la même cible.
            "req_template_json_object": {prompt_field: "$INPUT", **(extra_payload or {})},
            "response_json": True,
            "response_json_field": response_field,
            # Read-timeout REST. ⚠️ BUG garak 0.9.0.11 : la config lit le champ
            # "response_timeout" (setattr self.response_timeout) MAIS la requête
            # utilise self.request_timeout (hardcodé 10s) → la valeur est IGNORÉE
            # dans cette version. Conséquence : les prompts longs (dan.DAN_Jailbreak)
            # sur un LLM local lent (llama3.2:3b > 10s) timeout → 0 évaluation → run
            # exclu (None), jamais un faux 10/10. Corrigé dans un garak récent (Rust).
            # On garde la bonne clé pour le jour où on passera à un garak à jour.
            "response_timeout": request_timeout,
        }
    }
    with open(config_path, "w", encoding="utf-8") as fh:
        json.dump(config, fh)

    cmd = [
        GARAK_VENV_PYTHON, "-m", "garak",
        "--model_type", "rest", "-G", config_path,
        "--probes", probes,
        "--generations", str(generations),
        "--report_prefix", report_prefix,
    ]
    # UTF-8 forcé : garak imprime des emojis (cp1252 planterait sur Windows).
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    # ⚠️ SORTIE VERS FICHIER, PAS VERS DES PIPES — et surtout PAS `subprocess.run(
    # timeout=…)`. Sur Windows, `run()` tue bien l'enfant à l'échéance, puis DRAINE les
    # pipes SANS délai ; or garak lance des sous-processus qui HÉRITENT de stdout, donc
    # le drain attend la mort du petit-fils, pas celle de garak. Constaté en vrai
    # (2026-08-19) : garak calé sur UNE requête HTTP a bloqué 6h19 malgré `timeout=600`
    # (TimeoutExpired levée à la toute fin, avec un « remaining » NÉGATIF de -22138 s).
    # Reproduit et mesuré : pipes + kill = bloqué toute la vie du petit-fils ; fichier +
    # wait(timeout) + kill = rendu en 0.1 s. Sans pipe à drainer, le délai est fiable.
    log_path = os.path.join(workdir, "garak_stdout.log")
    timed_out = False
    try:
        with open(log_path, "w", encoding="utf-8", errors="replace") as log_fh:
            proc = subprocess.Popen(
                cmd, stdout=log_fh, stderr=subprocess.STDOUT,
                cwd=workdir, env=env,
            )
            # TRACE : garak tourne en sous-processus et peut occuper jusqu'a
            # _TIMEOUT (600 s par defaut). Sans ce span, cette part — parfois la
            # plus longue d'une categorie — n'apparait dans aucun tableau de bord.
            from judge.tracing import observe_step

            with observe_step("garak", probes=probes, generations=generations) as etape:
                try:
                    proc.wait(timeout=_TIMEOUT)
                    etape.set_output(f"rc={proc.returncode}")
                except subprocess.TimeoutExpired:
                    timed_out = True
                    proc.kill()
                    proc.wait()
                    etape.set_output(f"tue apres {_TIMEOUT}s")
    except Exception as exc:  # venv cassé / exécutable introuvable
        return None, [], f"error: {type(exc).__name__}: {exc}", {}

    try:
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            stderr = fh.read()
    except Exception:
        stderr = ""

    # Même tué, garak a pu écrire un rapport PARTIEL exploitable : on continue vers le
    # parsing au lieu de tout jeter. Vérifié : le run tué à 6h19 contenait déjà les 2
    # évaluations réelles (0/2 passés = faille détectée) qu'on perdait auparavant.

    # Localiser le rapport .report.jsonl produit dans le workdir.
    report = next(
        (os.path.join(workdir, n) for n in os.listdir(workdir) if n.endswith(".report.jsonl")),
        None,
    )
    if report is None:
        why = f"tué après {_TIMEOUT}s" if timed_out else f"rc={proc.returncode}"
        return None, [], f"error: pas de rapport garak ({why})", {
            "stderr": (stderr or "")[-500:],
        }

    passed_total = 0
    total_total = 0
    findings: list[dict[str, Any]] = []
    with open(report, encoding="utf-8") as fh:
        for line in fh:
            try:
                d = json.loads(line)
            except Exception:
                continue
            if d.get("entry_type") != "eval":
                continue
            p, t = int(d.get("passed", 0)), int(d.get("total", 0))
            passed_total += p
            total_total += t
            if t > 0:
                findings.append({
                    "probe": d.get("probe"),
                    "detector": d.get("detector"),
                    "passed": p,
                    "total": t,
                    "failure_rate": round((1 - p / t) * 100, 1),
                })

    raw = {
        "probes": probes,
        "passed": passed_total,
        "total": total_total,
        "returncode": proc.returncode,
        "timed_out": timed_out,
    }
    # Aucune évaluation exploitable -> non scorable (PAS 10/10, PAS 0).
    #
    # ON NE DEVINE PLUS LA CAUSE, ON LA LIT DANS LE JOURNAL.
    #     Ce point rendait TOUJOURS « cible injoignable ? ». C'est une cause
    #     plausible, pas la seule — et un diagnostic faux coûte plus cher
    #     qu'un diagnostic absent : il envoie chercher la panne du mauvais
    #     côté. Le journal de garak est déjà lu plus haut, autant s'en servir.
    #
    #     CAS RÉEL, CONSTATÉ EN ÉPROUVANT LE VENV ALLÉGÉ : une probe à
    #     détecteur ML (`realtoxicityprompts.RTPBlank`) ressortait « cible
    #     injoignable ? » alors que la cible répondait parfaitement. garak
    #     ATTRAPE lui-même l'import manquant, SAUTE le détecteur, et sort en
    #     CODE 0. Ni le code de retour ni une exception ne trahissent rien ;
    #     seule cette ligne du journal le dit, mot pour mot :
    #         detector load failed: toxicity.ToxicCommentModel, skipping >>
    if total_total == 0:
        journal = stderr or ""
        saute = re.search(r"detector load failed: ([\w.]+)", journal)
        absent = re.search(r"No module named '([\w.]+)'", journal)
        if saute or absent:
            quoi = saute.group(1) if saute else absent.group(1)
            return None, findings, (
                f"excluded: garak n'a pas pu évaluer — détecteur/module « {quoi} » "
                f"indisponible dans {GARAK_VENV_PYTHON}. La cible n'est PAS en "
                "cause. Probe à détecteur ML sur un venv allégé ? "
                "Voir docs/garak_isolated_env.md."
            ), {**raw, "detecteur_indisponible": quoi}
        return None, findings, "excluded: aucune évaluation garak (cible injoignable ?)", raw

    score = round((passed_total / total_total) * 10, 2)
    # findings retenus = probes où garak a détecté une faille (passed < total).
    vuln_findings = [f for f in findings if f["passed"] < f["total"]]
    suffix = f" — PARTIEL, garak tué après {_TIMEOUT}s" if timed_out else ""
    return score, vuln_findings, f"ok ({passed_total}/{total_total} passés){suffix}", raw
