"""
main.py — API REST du framework d'audit. Sert le dashboard.

CE QUE ÇA FAIT
    Lance de VRAIS audits (les mêmes que `scripts/run_agent.py`) depuis une requête
    HTTP, suit leur progression en direct, et expose les résultats déjà produits.
    Le dashboard n'a donc plus besoin ni de VS Code ni du script de synchronisation.

ENDPOINTS
    GET  /health                     → santé de l'API + dépendances (Docker, Gemini…)
    GET  /agents                     → catalogue des agents ASI disponibles
    GET  /audits                     → tous les résultats d'audit enregistrés
    GET  /audits/{audit_id}          → un résultat complet
    POST /audits                     → LANCE un audit (retourne un run_id)
    GET  /runs                       → audits en cours / récents
    GET  /runs/{run_id}              → progression, journal, résultat final
    POST /runs/{run_id}/cancel       → annule un audit en cours

AUTHENTIFICATION
    Clé d'API optionnelle : si `FRAMEWORK_API_KEY` est défini, le header `X-API-Key`
    est exigé. Sinon (poste de développement) l'API est ouverte en local.
"""

from __future__ import annotations

import json
import os
import urllib.parse
import re
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "data" / "audit_results"
REPLAYS_DIR = ROOT / "data" / "replays"
RUNNER = ROOT / "scripts" / "run_agent.py"

# Charge .env AVANT tout : sans ça `GEMINI_API_KEY` est absent quand l'API est
# lancée par uvicorn, et le profil `final` échoue au moment du run.
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env", override=False)
except Exception:
    pass

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

app = FastAPI(
    title="AI Security Audit Framework",
    description="Audit automatisé OWASP Top 10 for Agentic Applications 2026",
    version="1.0.0",
)

# Le dashboard tourne sur un autre port (Vite :5173) → CORS indispensable.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ══════════════════════════════════════════════════════════════════════
#  Modèles
# ══════════════════════════════════════════════════════════════════════

class AuditRequest(BaseModel):
    """Paramètres de lancement d'un audit.

    MODES (exigence de l'encadrant)
        · `full`     — toutes les catégories implémentées, tous les axes. Plusieurs heures.
        · `targeted` — un sous-ensemble de catégories choisi par l'auditeur.
        · `quick`    — toutes les catégories, mais SEULEMENT les axes déterministes
                       (Garak, Semgrep, pip-audit, sandbox). Aucun appel LLM, donc
                       aucun plafond de débit : quelques minutes, résultat reproductible.
    """

    mode: str = Field(default="targeted", description="full | targeted | quick")
    category: str = Field(default="ASI_05", description="ex. ASI_01 … ASI_10")
    categories: list[str] | None = Field(
        default=None, description="plusieurs catégories ; prioritaire sur `category`"
    )
    # Axes désactivables — le mode `quick` les positionne automatiquement.
    disable_deepteam: bool = False
    disable_pyrit: bool = False
    disable_garak: bool = False
    disable_microsoft: bool = False
    target_url: str = Field(default="http://localhost:8090/api/coding/chat")
    # Format JSON de la cible — indispensable dès qu'on sort du lab par défaut.
    # Ex. lab DVAP `autonomous-agent` : prompt_field="content",
    # extra_payload={"title": "…"} (les deux champs sont requis, sinon 422).
    prompt_field: str = Field(default="message")
    response_field: str = Field(default="response")
    extra_payload: dict[str, Any] | None = None
    profile: str = Field(default="final", description="dev | final | ollama | dry_run")
    attacks_per_type: int = Field(default=3, ge=1, le=10)
    max_concurrent: int = Field(default=2, ge=1, le=10)
    pyrit_max_turns: int = Field(default=5, ge=1, le=15)
    timeout: float = Field(default=180.0, ge=10, le=600)
    source_path: str | None = None
    requirements_path: str | None = None
    explain_passes: bool = True
    garak_probes: str | None = None
    # ASI07 — identité d'agent pair usurpée. Enveloppe chaque prompt dans un
    # message inter-agents non signé : la cible vérifie-t-elle la provenance ?
    peer_agent_id: str | None = None


# ══════════════════════════════════════════════════════════════════════
#  Registre des exécutions en cours
# ══════════════════════════════════════════════════════════════════════

class Run:
    """Une exécution d'audit : sous-processus + journal + progression."""

    def __init__(self, run_id: str, req: AuditRequest) -> None:
        self.id = run_id
        self.request = req
        self.status = "queued"       # queued | running | completed | failed | cancelled
        self.progress = 0
        self.stage = "En file d'attente"
        self.logs: list[dict[str, str]] = []
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.finished_at: str | None = None
        self.result_file: str | None = None
        self.error: str | None = None
        self.proc: subprocess.Popen[str] | None = None
        # Échanges avec la cible, captés EN DIRECT pendant l'exécution.
        self.exchanges: list[dict[str, Any]] = []
        self.categories: list[str] | None = None
        self.result_files: list[str] | None = None
        self._lock = threading.Lock()

    def log(self, level: str, text: str) -> None:
        with self._lock:
            self.logs.append({
                "t": datetime.now(timezone.utc).isoformat(),
                "level": level, "text": text,
            })
            if len(self.logs) > 2000:      # borne mémoire
                self.logs = self.logs[-1500:]

    def add_exchange(self, entry: dict[str, Any]) -> None:
        with self._lock:
            self.exchanges.append(entry)
            if len(self.exchanges) > 600:
                self.exchanges = self.exchanges[-500:]

    def snapshot(self, since: int = 0, since_ex: int = 0) -> dict[str, Any]:
        with self._lock:
            return {
                "run_id": self.id,
                "status": self.status,
                "progress": self.progress,
                "stage": self.stage,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "result_file": self.result_file,
                "error": self.error,
                "request": self.request.model_dump(),
                "logs": self.logs[since:],
                "log_count": len(self.logs),
                "exchanges": self.exchanges[since_ex:],
                "exchange_count": len(self.exchanges),
                "categories": getattr(self, "categories", None),
                "result_files": getattr(self, "result_files", None),
            }


_RUNS: dict[str, Run] = {}
_RUNS_LOCK = threading.Lock()


# Étapes reconnues dans la sortie du runner → progression affichable.
# Chaque motif marque le DÉBUT de l'étape ; le pourcentage est indicatif.
_STAGES: list[tuple[str, int, str]] = [
    (r"AUDIT ASI", 3, "Initialisation"),
    (r"red_team\(\)|DeepTeam\s*:", 10, "DeepTeam — attaques comportementales"),
    (r"DeepTeam OK", 45, "DeepTeam terminé"),
    (r"PyRIT", 52, "PyRIT — attaque multi-tours"),
    (r"Garak", 66, "Garak — sondes automatiques"),
    (r"Microsoft|Arcanum", 78, "Payloads Microsoft"),
    (r"[Ss]tatique|[Ss]emgrep|pip-audit", 85, "Couche statique"),
    (r"[Dd]ynamique|[Ss]andbox", 92, "Couche dynamique — sandbox Docker"),
    (r"RÉSULTAT", 97, "Consolidation"),
    (r"Enregistré", 100, "Terminé"),
]


def _tail_exchanges(run: Run, path: Path, stop: threading.Event) -> None:
    """Suit le JSONL des échanges écrit par le runner et les pousse dans le run.

    POURQUOI UN FICHIER ET PAS STDOUT (bug MESURÉ le 2026-08-20)
        Les échanges transitaient par une balise `##EXCHANGE##` sur stdout. Mais
        DeepTeam écrit son spinner sur le MÊME flux depuis plusieurs threads : les
        écritures s'entrelacent, la ligne se fragmente, et le JSON devient
        illisible. Sur un run réel, 7 échanges captés sur ~30 — les 23 autres
        finissaient en texte brut dans les logs, et le dashboard affichait un
        panneau d'attaques quasi vide.

        Un fichier dédié n'a qu'un seul écrivain (le runner, sous verrou) : aucune
        fragmentation possible. On le relit ici ligne par ligne.

    Ne lève jamais : un défaut de journalisation ne doit pas casser un audit.
    """
    seen = 0
    # Boucle « sweep puis test » : quand `stop` est levé, on fait un DERNIER passage
    # avant de sortir. Sinon les échanges écrits entre l'avant-dernier réveil et la
    # mort du runner seraient perdus — exactement le genre de fuite silencieuse
    # qu'on vient de corriger.
    while True:
        try:
            if path.exists():
                with path.open(encoding="utf-8") as fh:
                    lines = fh.readlines()
                # Une dernière ligne sans "\n" est en cours d'écriture -> on attend.
                complete = lines if (lines and lines[-1].endswith("\n")) else lines[:-1]
                for line in complete[seen:]:
                    try:
                        entry = json.loads(line)
                    except Exception:
                        continue
                    run.add_exchange(entry)
                    run.log(
                        "warn" if entry.get("http_error") else "info",
                        f"Attaque #{entry.get('n')} envoyée — réponse en "
                        f"{entry.get('elapsed_s')}s"
                        + (" — CIBLE INJOIGNABLE, exclue" if entry.get("http_error") else ""),
                    )
                seen = len(complete)
        except Exception:
            pass
        if stop.is_set():
            return
        stop.wait(1.0)

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# Caractères de spinner Braille + barres de progression : DeepTeam en émet des
# MILLIERS par seconde. Les journaliser saturait le CPU du thread lecteur et
# affamait la boucle uvicorn — l'API devenait injoignable pendant tout l'audit.
_SPINNER = re.compile(r"[⠀-⣿─-▟]")
_NOISE = re.compile(
    r"^\s*(\d+%|\||━|─|╸|Testing|Evaluating|Generating|Simulating)\b.*$|"
    r"^\s*\d+\s*/\s*\d+\s*$"
)


def _drain(run: Run, stream: Any) -> None:
    """Lit la sortie du sous-processus, filtre le bruit et suit la progression.

    Le filtrage n'est pas cosmétique : sans lui, le spinner de DeepTeam produit
    un débit de lignes qui bloque l'API entière (constaté).
    """
    last_line = ""
    dropped = 0
    for raw_line in iter(stream.readline, ""):
        line = _ANSI.sub("", raw_line).rstrip()
        if not line:
            continue

        # Les échanges avec la cible ne passent PLUS par stdout : ils sont lus
        # depuis le JSONL du runner par `_tail_exchanges` (cf. son docstring).

        # La progression se lit AVANT le filtrage : une étape peut être annoncée
        # sur une ligne par ailleurs bruyante.
        for pattern, pct, label in _STAGES:
            if re.search(pattern, line):
                if pct >= run.progress:
                    run.progress, run.stage = pct, label
                break

        # Rejet du bruit : spinner, barres de progression, lignes répétées.
        if _SPINNER.search(line) or _NOISE.match(line) or line == last_line:
            dropped += 1
            continue
        last_line = line

        low = line.lower()
        if "traceback" in low:
            level = "critical"
        elif "error" in low or "[http_error]" in low or "warning" in low or "vulnérabilit" in low or "breach" in low:
            level = "warn"
        else:
            level = "info"
        run.log(level, line[:600])

    if dropped:
        run.log("debug", f"{dropped} ligne(s) de progression filtrées (spinner)")
    stream.close()


def _build_cmd(req: AuditRequest, category: str) -> list[str]:
    """Ligne de commande du runner pour UNE catégorie, selon le mode demandé."""
    cmd = [
        sys.executable, "-u", str(RUNNER), category,
        "--target", req.target_url,
        "--prompt-field", req.prompt_field,
        "--response-field", req.response_field,
        "--profile", req.profile,
        "--attacks-per-type", str(req.attacks_per_type),
        "--max-concurrent", str(req.max_concurrent),
        "--pyrit-max-turns", str(req.pyrit_max_turns),
        "--timeout", str(req.timeout),
    ]
    if req.extra_payload:
        cmd += ["--extra-payload", json.dumps(req.extra_payload)]
    if req.source_path:
        cmd += ["--source-path", req.source_path]
    if req.requirements_path:
        cmd += ["--requirements-path", req.requirements_path]
    if req.garak_probes:
        cmd += ["--garak-probes", req.garak_probes]
    if req.explain_passes:
        cmd += ["--explain-passes"]
    if req.peer_agent_id:
        cmd += ["--peer-agent-id", req.peer_agent_id]

    # Le mode `quick` coupe TOUS les axes qui consomment des appels LLM. Il ne
    # reste que Garak et les couches statique/dynamique — déterministes, sans
    # plafond de débit, donc les seuls qualifiés pour bloquer un déploiement.
    quick = req.mode == "quick"
    if quick or req.disable_deepteam:
        cmd.append("--no-deepteam")
    if quick or req.disable_pyrit:
        cmd.append("--no-pyrit")
    if req.disable_garak:
        cmd.append("--no-garak")
    if quick or req.disable_microsoft:
        cmd.append("--no-microsoft")
    return cmd


def _requested_categories(req: AuditRequest) -> list[str]:
    """Catégories à auditer, selon le mode."""
    try:
        from workflow.audit_graph import AGENT_REGISTRY
        available = sorted(AGENT_REGISTRY)
    except Exception:
        available = []
    if req.mode in ("full", "quick"):
        return available
    # Mode ciblé : l'auditeur choisit UNE OU PLUSIEURS catégories. `category`
    # (au singulier) reste accepté pour la compatibilité avec les anciens appels.
    if req.categories:
        chosen = [c for c in req.categories if c in available]
        if chosen:
            return chosen
        # Toutes les categories demandees sont inconnues : ne rien renvoyer, pour
        # que l'appelant soit refuse au lieu de retomber sur `req.category`.
        return []
    return [req.category] if req.category in available else []


def _execute(run: Run) -> None:
    """Lance le runner en sous-processus et suit son exécution.

    En mode `full` ou `targeted` multi-catégories, les agents sont enchaînés
    SÉQUENTIELLEMENT : ils partagent le même limiteur de débit LLM, donc les
    paralléliser n'apporterait rien (mesuré — le goulot est le quota, pas le CPU).
    """
    req = run.request
    cats = _requested_categories(req)
    run.categories = cats                      # type: ignore[attr-defined]

    if len(cats) > 1:
        _execute_many(run, cats)
        return

    cmd = _build_cmd(req, cats[0])

    # `TERM=dumb` + `NO_COLOR` désactivent le spinner et les couleurs de rich/tqdm
    # utilisés par DeepTeam — c'est la correction À LA SOURCE du flot de lignes
    # qui bloquait l'API. Le filtre côté lecteur reste en ceinture-bretelles.
    env = dict(
        os.environ,
        PYTHONUTF8="1", PYTHONIOENCODING="utf-8",
        TERM="dumb", NO_COLOR="1", FORCE_COLOR="0",
        TQDM_DISABLE="1", DEEPEVAL_DISABLE_PROGRESS_BAR="1",
    )
    before = {p.name for p in RESULTS_DIR.glob("*.json")} if RESULTS_DIR.exists() else set()

    run.status = "running"
    run.stage = "Démarrage du runner"
    run.log("info", f"$ {' '.join(cmd[2:])}")

    # Fichier des échanges : le runner y écrit, `_tail_exchanges` le relit.
    ex_path = RESULTS_DIR / f"{run.id}.exchanges.jsonl"
    ex_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = cmd + ["--exchange-log", str(ex_path)]
    ex_stop = threading.Event()
    ex_thread = threading.Thread(
        target=_tail_exchanges, args=(run, ex_path, ex_stop), daemon=True
    )
    ex_thread.start()

    try:
        run.proc = subprocess.Popen(
            cmd, cwd=str(ROOT), env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding="utf-8",
            errors="replace", bufsize=1,
        )
        _drain(run, run.proc.stdout)
        code = run.proc.wait()
        # Le runner est mort : `ex_stop` déclenche un DERNIER passage (cf. la boucle
        # de `_tail_exchanges`) qui capte les échanges écrits juste avant la sortie.
        ex_stop.set()
        ex_thread.join(timeout=5)

        if run.status == "cancelled":
            run.log("warn", "Audit annulé par l'utilisateur.")
        elif code == 0:
            after = {p.name for p in RESULTS_DIR.glob("*.json")}
            new = sorted(after - before)
            run.result_file = new[-1] if new else None
            run.status = "completed"
            run.progress = 100
            run.stage = "Terminé"
            run.log("info", f"Résultat enregistré : {run.result_file}")
        else:
            run.status = "failed"
            run.error = f"Le runner s'est arrêté avec le code {code}"
            run.log("critical", run.error)
    except Exception as exc:                              # jamais bloquant
        run.status = "failed"
        run.error = f"{type(exc).__name__}: {exc}"
        run.log("critical", run.error)
    finally:
        run.finished_at = datetime.now(timezone.utc).isoformat()


ENV_QUIET = dict(
    PYTHONUTF8="1", PYTHONIOENCODING="utf-8",
    TERM="dumb", NO_COLOR="1", FORCE_COLOR="0",
    TQDM_DISABLE="1", DEEPEVAL_DISABLE_PROGRESS_BAR="1",
)


def _execute_many(run: Run, cats: list[str]) -> None:
    """Enchaîne plusieurs agents dans une seule exécution (modes `full` et `targeted`).

    FAIL-SAFE : l'échec d'un agent n'interrompt pas les suivants — c'est la règle
    du workflow (doc. technique : orchestration LangGraph). Chaque agent produit son propre fichier de résultat.
    """
    env = dict(os.environ, **ENV_QUIET)
    run.status = "running"
    run.log("info", f"Mode {run.request.mode} — {len(cats)} agent(s) : {', '.join(cats)}")

    produced: list[str] = []
    failed: list[str] = []

    for i, cat in enumerate(cats, 1):
        if run.status == "cancelled":
            run.log("warn", "Annulé — agents restants non exécutés.")
            break

        run.stage = f"{cat} ({i}/{len(cats)})"
        run.log("info", f"── {cat} — agent {i} sur {len(cats)}")
        before = {p.name for p in RESULTS_DIR.glob("*.json")} if RESULTS_DIR.exists() else set()

        # Un JSONL d'échanges PAR CATÉGORIE (le compteur `n` du runner repart à 1
        # à chaque sous-processus ; un fichier partagé mélangerait les séries).
        ex_path = RESULTS_DIR / f"{run.id}.{cat}.exchanges.jsonl"
        ex_path.parent.mkdir(parents=True, exist_ok=True)
        ex_stop = threading.Event()
        ex_thread = threading.Thread(
            target=_tail_exchanges, args=(run, ex_path, ex_stop), daemon=True
        )
        ex_thread.start()

        try:
            run.proc = subprocess.Popen(
                _build_cmd(run.request, cat) + ["--exchange-log", str(ex_path)],
                cwd=str(ROOT), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                encoding="utf-8", errors="replace", bufsize=1,
            )
            _drain(run, run.proc.stdout)
            code = run.proc.wait()
            new = sorted({p.name for p in RESULTS_DIR.glob("*.json")} - before)
            if code == 0 and new:
                produced.append(new[-1])
                run.log("info", f"{cat} terminé — {new[-1]}")
            else:
                failed.append(cat)
                run.log("warn", f"{cat} en échec (code {code}) — on poursuit")
        except Exception as exc:
            failed.append(cat)
            run.log("critical", f"{cat} : {type(exc).__name__}: {exc}")
        finally:
            # `finally` : même si la catégorie plante, on arrête le suiveur et on
            # capte ses derniers échanges — sinon un thread par catégorie resterait
            # vivant jusqu'à la fin du processus.
            ex_stop.set()
            ex_thread.join(timeout=5)

        # Progression sur les agents, pas sur les étapes internes.
        run.progress = min(99, int(i / len(cats) * 100))

    run.result_files = produced                # type: ignore[attr-defined]
    run.result_file = produced[-1] if produced else None
    run.finished_at = datetime.now(timezone.utc).isoformat()

    if run.status == "cancelled":
        return
    if produced:
        run.status = "completed"
        run.progress = 100
        run.stage = "Terminé"
        run.log("info", f"{len(produced)} audit(s) produit(s)"
                        + (f", {len(failed)} en échec : {', '.join(failed)}" if failed else ""))
    else:
        run.status = "failed"
        run.error = f"Aucun agent n'a abouti ({len(failed)} échec(s))"
        run.log("critical", run.error)


# ══════════════════════════════════════════════════════════════════════
#  Utilitaires
# ══════════════════════════════════════════════════════════════════════

def _check_api_key(x_api_key: str | None) -> None:
    """Clé exigée UNIQUEMENT si `FRAMEWORK_API_KEY` est configurée."""
    expected = os.environ.get("FRAMEWORK_API_KEY", "").strip()
    if expected and x_api_key != expected:
        raise HTTPException(status_code=401, detail="X-API-Key invalide ou manquant")


def _read_results() -> list[dict[str, Any]]:
    """Charge tous les résultats d'audit, du plus récent au plus ancien."""
    if not RESULTS_DIR.exists():
        return []
    out: list[dict[str, Any]] = []
    for f in RESULTS_DIR.glob("*.json"):
        if f.name == "sample_audit.json":
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if "agents" not in data:
            continue
        data["_file"] = f.name
        out.append(data)
    out.sort(key=lambda d: str(d.get("timestamp", "")), reverse=True)
    return out


# ══════════════════════════════════════════════════════════════════════
#  Endpoints
# ══════════════════════════════════════════════════════════════════════

@app.get("/health")
def health() -> dict[str, Any]:
    """Santé de l'API et disponibilité des dépendances d'audit."""
    services: dict[str, Any] = {}
    try:
        from sandbox.docker_provider import DockerSandboxProvider
        services["docker_sandbox"] = DockerSandboxProvider().is_available()
    except Exception:
        services["docker_sandbox"] = False
    services["gemini_key"] = bool(os.environ.get("GEMINI_API_KEY", "").strip())
    services["results_dir"] = RESULTS_DIR.exists()
    services["runner"] = RUNNER.exists()
    with _RUNS_LOCK:
        services["active_runs"] = sum(1 for r in _RUNS.values() if r.status == "running")
    return {"status": "ok", "version": app.version, "services": services}


@app.get("/agents")
def list_agents() -> dict[str, Any]:
    """Catalogue des agents ASI enregistrés dans le workflow."""
    try:
        from workflow.audit_graph import AGENT_REGISTRY
        registry = AGENT_REGISTRY
    except Exception:
        registry = {}
    out = []
    for cat in [f"ASI_{i:02d}" for i in range(1, 11)]:
        cls = registry.get(cat)
        # Le nom lisible est porté par l'agent lui-même (attribut `name`).
        name = getattr(cls, "name", None) or NAMES_FALLBACK.get(cat, cat)
        out.append({"id": cat, "name": name, "available": cls is not None})
    return {"agents": out}


NAMES_FALLBACK = {
    "ASI_01": "Goal Hijacking", "ASI_02": "Tool Misuse",
    "ASI_03": "Identity & Privilege Abuse", "ASI_04": "Agentic Supply Chain",
    "ASI_05": "Unexpected Code Execution", "ASI_06": "Memory & Context Poisoning",
    "ASI_07": "Inter-Agent Communication", "ASI_08": "Cascading Failures",
    "ASI_09": "Trust Exploitation", "ASI_10": "Rogue Agents",
}


@app.get("/audits")
def list_audits() -> dict[str, Any]:
    """Tous les résultats d'audit enregistrés."""
    return {"audits": _read_results()}


@app.get("/audits/{audit_id}")
def get_audit(audit_id: str) -> dict[str, Any]:
    """Un résultat d'audit complet, par identifiant ou nom de fichier."""
    for d in _read_results():
        if d.get("audit_id") == audit_id or d.get("_file") == audit_id:
            return d
    raise HTTPException(status_code=404, detail="Audit introuvable")


@app.get("/audits/{audit_id}/report")
def get_audit_report(audit_id: str) -> Any:
    """Rapport de sécurité HTML complet d'un audit (livrable #8).

    Renvoie directement le HTML : le dashboard n'a qu'à ouvrir cette URL dans un
    onglet, et le rapport est imprimable en PDF depuis le navigateur (le template
    embarque sa feuille de style d'impression).

    Le rapport est régénéré à CHAQUE appel plutôt que mis en cache : les données
    d'audit sont figées sur disque, mais le générateur, lui, évolue — servir un
    HTML périmé masquerait toute correction apportée au rapport.
    """
    from fastapi.responses import HTMLResponse

    for d in _read_results():
        if d.get("audit_id") == audit_id or d.get("_file") == audit_id:
            try:
                from reporting.report_generator import render_html
                return HTMLResponse(render_html(d))
            except Exception as exc:
                raise HTTPException(
                    status_code=500,
                    detail=f"Génération du rapport impossible : {type(exc).__name__}: {exc}",
                ) from exc
    raise HTTPException(status_code=404, detail="Audit introuvable")


@app.post("/audits")
def create_audit(req: AuditRequest, x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    """LANCE un audit réel en tâche de fond et retourne son `run_id`."""
    _check_api_key(x_api_key)
    if not RUNNER.exists():
        raise HTTPException(status_code=500, detail="scripts/run_agent.py introuvable")

    # VALIDER AVANT DE LANCER.
    #     Sans ce controle, `category: "ASI_99"` renvoyait 200 : l'audit demarrait,
    #     occupait un thread et un sous-processus, puis echouait des MINUTES plus
    #     tard sur une faute de frappe. En profil `final`, c'est aussi du quota LLM
    #     depense pour rien. Un refus immediat coute une milliseconde.
    cats = _requested_categories(req)
    if not cats:
        from workflow.audit_graph import AGENT_REGISTRY

        raise HTTPException(
            status_code=400,
            detail=f"Aucune categorie valide. Connues : {sorted(AGENT_REGISTRY)}",
        )

    run_id = f"run-{datetime.now():%Y%m%d%H%M%S}-{uuid.uuid4().hex[:6]}"
    run = Run(run_id, req)
    with _RUNS_LOCK:
        _RUNS[run_id] = run
    threading.Thread(target=_execute, args=(run,), daemon=True).start()
    return {"run_id": run_id, "status": "queued"}


class ReplayRequest(BaseModel):
    """Rejeu des attaques d'un audit passé contre la même cible."""

    audit_id: str = Field(description="audit_id ou nom de fichier de l'audit source")
    target_url: str | None = Field(default=None, description="défaut : la cible de l'audit")
    profile: str = Field(default="final")
    timeout: float = Field(default=180.0, ge=10, le=600)
    only_compromised: bool = Field(
        default=True, description="ne rejouer que les attaques qui avaient percé"
    )
    repeat: int = Field(
        default=3, ge=1, le=10,
        description="envois par attaque — ≥3 requis pour conclure (cible non déterministe)"
    )


@app.post("/replay")
def create_replay(req: ReplayRequest, x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    """Rejoue un audit et retourne un `run_id` suivable comme un audit normal.

    POURQUOI CE MODE
        Deux audits successifs ne lancent pas les mêmes attaques (simulateur
        stochastique), donc leur comparaison mélange progrès réel et hasard. Le
        rejeu renvoie EXACTEMENT les mêmes prompts : tout changement de verdict
        est imputable à la cible. C'est la vérification de correctif.
    """
    _check_api_key(x_api_key)

    source = next(
        (d for d in _read_results()
         if d.get("audit_id") == req.audit_id or d.get("_file") == req.audit_id),
        None,
    )
    if source is None:
        raise HTTPException(status_code=404, detail="Audit source introuvable")

    target = req.target_url or source.get("target_url")
    if not target:
        raise HTTPException(status_code=400, detail="Aucune cible : précisez target_url")

    attacks = [
        a for ag in (source.get("agents") or {}).values()
        for a in (ag.get("attacks") or [])
    ]

    run_id = f"replay-{datetime.now():%Y%m%d%H%M%S}-{uuid.uuid4().hex[:6]}"
    run = Run(run_id, AuditRequest(
        category=next(iter(source.get("agents") or {"ASI_?": {}})),
        target_url=target, profile=req.profile, timeout=req.timeout,
    ))
    run.kind = "replay"                       # type: ignore[attr-defined]
    run.source_audit = source.get("_file")    # type: ignore[attr-defined]
    with _RUNS_LOCK:
        _RUNS[run_id] = run

    threading.Thread(
        target=_execute_replay,
        args=(run, attacks, target, req.profile, req.timeout,
              req.only_compromised, req.repeat),
        daemon=True,
    ).start()
    return {"run_id": run_id, "status": "queued", "attacks_available": len(attacks)}


def _execute_replay(
    run: Run, attacks: list[dict[str, Any]], target: str,
    profile: str, timeout: float, only_compromised: bool, repeat: int = 3,
) -> None:
    """Exécute un rejeu dans le processus de l'API (pas de sous-processus : le
    volume d'appels est faible et il n'y a rien à orchestrer)."""
    run.status = "running"
    run.stage = "Rejeu des attaques"
    run.log("info", f"Rejeu contre {target} — "
                    f"{'failles uniquement' if only_compromised else 'toutes les attaques'}")
    try:
        from agents.base_agent import build_http_callback
        from judge.llm_config import get_judge_models
        from judge.replay import replay_attacks

        cb = build_http_callback(target, prompt_field="message",
                                 response_field="response", timeout=timeout)
        _, evaluation_model = get_judge_models(profile)

        pool = [a for a in attacks if (a.get("prompt") or "").strip()]
        if only_compromised:
            pool = [a for a in pool if a.get("verdict") == "compromised"]
        total = max(1, len(pool))
        run.log("info", f"{len(pool)} attaque(s) à rejouer")

        LABEL = {
            "non_reproduite": "NON REPRODUITE", "regression": "RÉGRESSION",
            "toujours_vulnerable": "TOUJOURS VULNÉRABLE",
            "toujours_resistant": "toujours résistante", "instable": "INSTABLE — perce par intermittence",
            "non_juge": "non jugée",
        }

        def progress(item: dict[str, Any]) -> None:
            run.progress = min(99, int(item["n"] / total * 100))
            run.add_exchange({
                "n": item["n"], "elapsed_s": item["elapsed_s"],
                "prompt": item["prompt"], "response": item["response"],
                "http_error": item["verdict_after"] == "excluded",
            })
            lvl = "critical" if item["outcome"] in ("regression", "toujours_vulnerable") \
                else "info" if item["outcome"] == "non_reproduite" else "debug"
            run.log(lvl, f"#{item['n']} {item['axis']} — {item['verdict_before']} → "
                         f"{item['verdict_after']} · {LABEL.get(item['outcome'], '')}")

        result = replay_attacks(attacks, cb, evaluation_model,
                                only_compromised=only_compromised,
                                repeat=repeat, on_progress=progress)
        run.replay_result = result            # type: ignore[attr-defined]

        s = result["summary"]
        REPLAYS_DIR.mkdir(parents=True, exist_ok=True)
        out = REPLAYS_DIR / f"{datetime.now():%Y%m%d_%H%M%S}_{run.id}.json"
        out.write_text(json.dumps({
            "replay_id": run.id,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source_audit": getattr(run, "source_audit", None),
            "target_url": target, "profile": profile,
            "only_compromised": only_compromised, "repeat": repeat, **result,
        }, indent=2, ensure_ascii=False), encoding="utf-8")

        run.result_file = out.name
        run.status = "completed"
        run.progress = 100
        run.stage = "Rejeu terminé"
        run.log("info", f"Bilan — {s['corrigee']} corrigée(s), {s['regression']} régression(s), "
                        f"{s['toujours_vulnerable']} toujours vulnérable(s)")
    except Exception as exc:
        run.status = "failed"
        run.error = f"{type(exc).__name__}: {exc}"
        run.log("critical", run.error)
    finally:
        run.finished_at = datetime.now(timezone.utc).isoformat()


@app.get("/replays")
def list_replays() -> dict[str, Any]:
    """Tous les rejeux enregistrés, du plus récent au plus ancien."""
    if not REPLAYS_DIR.exists():
        return {"replays": []}
    out: list[dict[str, Any]] = []
    for f in REPLAYS_DIR.glob("*.json"):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        d["_file"] = f.name
        out.append(d)
    out.sort(key=lambda d: str(d.get("timestamp", "")), reverse=True)
    return {"replays": out}



# ══════════════════════════════════════════════════════════════════════
#  Labs DVAP — catalogue de cibles d'entraînement
# ══════════════════════════════════════════════════════════════════════

DVAP_API = os.environ.get("DVAP_API", "http://localhost:8080/api/v1")

def _open_http(cible, timeout: float):
    """Ouvre une URL en n'autorisant QUE http/https.

    POURQUOI UN HELPER ET PAS UNE VALIDATION PAR APPEL
        Quatre endroits ouvrent une URL ; `DVAP_API` vient de l'environnement,
        donc une valeur `file://` ou `gopher://` y ferait lire un fichier local
        au serveur. Valider dans chaque appelant, c'est garantir qu'un cinquième
        appel oubliera la vérification. Ici la seule façon d'ouvrir une URL est
        de passer par ce point.
    """
    import urllib.request

    url = cible.full_url if isinstance(cible, urllib.request.Request) else cible
    if urllib.parse.urlparse(url).scheme not in ("http", "https"):
        raise ValueError(f"schéma d'URL non autorisé : {url[:60]}")
    # Schéma validé juste au-dessus, et c'est le SEUL point du module qui ouvre
    # une URL : la validation ne peut donc pas être contournée.
    return urllib.request.urlopen(cible, timeout=timeout)  # noqa: S310  # nosec B310



#: Champs de requête/réponse acceptés par les labs, par ordre de préférence.
_PROMPT_FIELDS = ("message", "content", "prompt", "query", "input", "description")
_RESPONSE_FIELDS = ("response", "answer", "output", "result", "message")


def _instance_port(container: str) -> int | None:
    """Port hôte exposé par un conteneur d'instance DVAP."""
    try:
        out = subprocess.run(
            ["docker", "port", container, "8000"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        return int(out.rsplit(":", 1)[-1]) if out else None
    except Exception:
        return None


def _running_instances() -> list[dict[str, Any]]:
    """Conteneurs `dvap-instance-*` actifs, avec leur port et leur lab."""
    try:
        out = subprocess.run(
            ["docker", "ps", "--filter", "name=dvap-instance", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10,
        ).stdout.split()
    except Exception:
        return []

    found = []
    for name in out:
        port = _instance_port(name)
        if not port:
            continue
        info: dict[str, Any] = {"container": name, "port": port, "lab": None}
        # /health expose le slug du lab — plus fiable que de le déduire du nom
        # de conteneur, qui est tronqué par Docker.
        try:
            import urllib.request
            with _open_http(f"http://localhost:{port}/health", 5) as r:
                info["lab"] = json.loads(r.read()).get("lab")
        except Exception:
            pass
        info.update(_discover_endpoint(port))
        found.append(info)
    return found


def _discover_endpoint(port: int) -> dict[str, Any]:
    """Trouve l'endpoint de conversation via l'OpenAPI de l'instance.

    POURQUOI DÉCOUVRIR PLUTÔT QUE CODER EN DUR
        Les 15 labs n'exposent pas le même chemin : `/chat` pour prompt-injection,
        `/api/coding/chat` pour ai-developer-platform, `/api/agent/process-paper`
        pour autonomous-agent. Un mappage figé se périmerait à chaque nouveau lab.
        On lit donc le schéma OpenAPI et on retient le premier POST dont le corps
        ressemble à un message.
    """
    try:
        import urllib.request
        with _open_http(f"http://localhost:{port}/openapi.json", 8) as r:
            spec = json.loads(r.read())
    except Exception:
        return {"path": "/chat", "prompt_field": "message", "response_field": "response"}

    schemas = (spec.get("components") or {}).get("schemas") or {}
    best = None
    for path, ops in (spec.get("paths") or {}).items():
        post = ops.get("post")
        if not post:
            continue
        ref = ((post.get("requestBody") or {}).get("content") or {})             .get("application/json", {}).get("schema", {}).get("$ref", "")
        props = list((schemas.get(ref.rsplit("/", 1)[-1]) or {}).get("properties") or {})
        field = next((f for f in _PROMPT_FIELDS if f in props), None)
        if not field:
            continue
        # Un chemin contenant « chat » est le canal conversationnel évident.
        score = 0 if "chat" in path else 1
        cand = (score, path, field, props)
        if best is None or cand < best:
            best = cand

    if best is None:
        return {"path": "/chat", "prompt_field": "message", "response_field": "response"}

    _, path, field, props = best
    # Champs REQUIS en plus du prompt. Le lab `autonomous-agent` exige `title` :
    # sans lui, la cible répond 422 et TOUS les tests tombent en [HTTP_ERROR].
    extra = [p for p in props if p not in (field, "history")]
    return {"path": path, "prompt_field": field, "response_field": "response",
            "extra_fields": extra,
            "extra_payload": {k: f"audit-{k}" for k in extra} if extra else None}


@app.get("/dvap/labs")
def dvap_labs() -> dict[str, Any]:
    """Catalogue des labs DVAP + instances déjà lancées.

    Chaque lab en cours d'exécution porte son `target_url` prêt à l'emploi ;
    les autres doivent être lancés (POST /dvap/launch).
    """
    labs: list[dict[str, Any]] = []
    try:
        import urllib.request
        with _open_http(f"{DVAP_API}/labs", 8) as r:
            raw = json.loads(r.read())
        labs = [{"slug": l.get("slug"), "name": l.get("name"),
                 "difficulty": l.get("difficulty"), "category": l.get("category"),
                 "description": (l.get("description") or "")[:220]}
                for l in (raw if isinstance(raw, list) else raw.get("labs", []))]
    except Exception as exc:
        return {"labs": [], "running": [], "error": f"DVAP injoignable sur {DVAP_API} : {exc}"}

    running = _running_instances()
    by_lab = {i["lab"]: i for i in running if i.get("lab")}
    for l in labs:
        inst = by_lab.get(l["slug"])
        l["running"] = inst is not None
        if inst:
            l["port"] = inst["port"]
            l["target_url"] = f"http://localhost:{inst['port']}{inst['path']}"
            l["prompt_field"] = inst["prompt_field"]
            l["response_field"] = inst["response_field"]
            l["extra_payload"] = inst.get("extra_payload")
    return {"labs": labs, "running": running}


class LaunchLabRequest(BaseModel):
    """Démarre une instance de lab DVAP."""
    slug: str


@app.post("/dvap/launch")
def dvap_launch(req: LaunchLabRequest,
                x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    """Lance un lab et retourne son `target_url` découvert.

    L'API DVAP renvoie parfois une erreur 500 alors que le conteneur démarre
    correctement — on ne se fie donc pas à son code retour, on cherche le
    conteneur et son port.
    """
    _check_api_key(x_api_key)
    import urllib.error
    import urllib.request

    token = f"audit-{req.slug[:14]}-{uuid.uuid4().hex[:6]}"
    body = json.dumps({"session_token": token}).encode()
    request = urllib.request.Request(
        f"{DVAP_API}/labs/{req.slug}/launch", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        _open_http(request, 90).read()
    except urllib.error.HTTPError:
        pass                      # 500 fréquent alors que le conteneur démarre
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"DVAP injoignable : {exc}")

    # Le conteneur met quelques secondes à exposer son port.
    for _ in range(24):
        for inst in _running_instances():
            if inst.get("lab") == req.slug:
                return {"slug": req.slug, "port": inst["port"],
                        "target_url": f"http://localhost:{inst['port']}{inst['path']}",
                        "prompt_field": inst["prompt_field"],
                        "response_field": inst["response_field"],
                        "extra_payload": inst.get("extra_payload")}
        time.sleep(5)
    raise HTTPException(status_code=504,
                        detail=f"Lab {req.slug} lancé mais aucune instance joignable")


@app.get("/runs")
def list_runs() -> dict[str, Any]:
    """Toutes les exécutions, en cours ou terminées (sans les journaux)."""
    with _RUNS_LOCK:
        runs = list(_RUNS.values())
    return {
        "runs": [
            {k: v for k, v in r.snapshot().items() if k != "logs"}
            for r in sorted(runs, key=lambda r: r.started_at, reverse=True)
        ]
    }


@app.get("/runs/{run_id}")
def get_run(run_id: str, since: int = 0, since_ex: int = 0) -> dict[str, Any]:
    """Progression d'une exécution.

    `since` / `since_ex` : ne renvoient que les journaux et les échanges NOUVEAUX
    depuis le dernier appel — le dashboard interroge toutes les 1,5 s sans
    retransférer l'historique complet à chaque fois.
    """
    run = _RUNS.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Exécution introuvable")
    snap = run.snapshot(since=since, since_ex=since_ex)
    if getattr(run, "replay_result", None) is not None:
        snap["replay"] = run.replay_result           # type: ignore[attr-defined]
    if run.status == "completed" and run.result_file:
        path = (REPLAYS_DIR if getattr(run, "kind", "") == "replay" else RESULTS_DIR) / run.result_file
        if path.exists():
            try:
                snap["result"] = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                pass
    return snap


@app.post("/runs/{run_id}/cancel")
def cancel_run(run_id: str, x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    """Annule une exécution en cours."""
    _check_api_key(x_api_key)
    run = _RUNS.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Exécution introuvable")
    if run.status != "running":
        return {"run_id": run_id, "status": run.status, "detail": "déjà terminée"}
    run.status = "cancelled"
    if run.proc and run.proc.poll() is None:
        run.proc.terminate()
    return {"run_id": run_id, "status": "cancelled"}
