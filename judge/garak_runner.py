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
import subprocess
import tempfile
from typing import Any

# Python du venv garak isolé (surchargeable par variable d'environnement).
GARAK_VENV_PYTHON = os.environ.get(
    "GARAK_VENV_PYTHON", r"C:\Users\asser\garak-venv\Scripts\python.exe"
)
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
            "headers": headers or {"Content-Type": "application/json"},
            "req_template_json_object": {prompt_field: "$INPUT"},
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
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=_TIMEOUT, cwd=workdir, env=env,
        )
    except Exception as exc:  # timeout / venv cassé -> dégradation propre
        return None, [], f"error: {type(exc).__name__}: {exc}", {}

    # Localiser le rapport .report.jsonl produit dans le workdir.
    report = next(
        (os.path.join(workdir, n) for n in os.listdir(workdir) if n.endswith(".report.jsonl")),
        None,
    )
    if report is None:
        return None, [], f"error: pas de rapport garak (rc={proc.returncode})", {
            "stderr": (proc.stderr or "")[-500:],
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
    }
    # Aucune évaluation exploitable (cible injoignable ?) -> non scorable (PAS 10/10).
    if total_total == 0:
        return None, findings, "excluded: aucune évaluation garak (cible injoignable ?)", raw

    score = round((passed_total / total_total) * 10, 2)
    # findings retenus = probes où garak a détecté une faille (passed < total).
    vuln_findings = [f for f in findings if f["passed"] < f["total"]]
    return score, vuln_findings, f"ok ({passed_total}/{total_total} passés)", raw
