"""
run_agent.py — Lance un agent ASI et enregistre TOUT (attaques + réponses + résultats).

Capture la conversation en enveloppant le callback vers la cible : chaque prompt
envoyé et chaque réponse reçue est journalisé, quelle que soit la technique
(DeepTeam, PyRIT, payloads Microsoft, couche dynamique). Garak fait exception —
il tourne en sous-processus isolé.

Sortie : data/audit_results/{ts}_{ASI}_{profil}.json  (format lisible par le dashboard)

Usage :
    python scripts/run_agent.py ASI_01
    python scripts/run_agent.py ASI_05 --profile final --attacks-per-type 2
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Point de resolution UNIQUE du repertoire de resultats : en production
# il pointe vers un volume persistant (AUDIT_RESULTS_DIR).
from workflow.cibles import CibleRefusee, avertissement_si_libre, valider_cible
from workflow.paths import affichable, results_dir

OUT_DIR = results_dir()
G, R, Y, B, D, X = "\033[92m", "\033[91m", "\033[93m", "\033[1m", "\033[90m", "\033[0m"


def main() -> int:
    # Compteurs d'execution remis a zero : deux audits dans le meme
    # processus additionneraient leurs couts, et le second afficherait
    # la facture des deux.
    from judge.metrics import reset as _reset_metriques

    _reset_metriques()

    from workflow.audit_graph import AGENT_REGISTRY

    ap = argparse.ArgumentParser()
    ap.add_argument("category", choices=sorted(AGENT_REGISTRY), help="ex. ASI_01")
    ap.add_argument("--target", default="http://localhost:8090/chat")
    # Format JSON de la cible. Ces trois-là étaient CODÉS EN DUR sur le format du lab
    # `prompt-injection` ({"message"} -> {"response"}), ce qui rendait le framework
    # inutilisable sur toute autre cible. Ex. lab `autonomous-agent` :
    #   --prompt-field content --extra-payload '{"title":"Submitted research paper"}'
    ap.add_argument("--prompt-field", default="message",
                    help="clé JSON où placer le prompt (défaut: message)")
    ap.add_argument("--response-field", default="response",
                    help="clé JSON d'où lire la réponse (défaut: response)")
    # POURQUOI CE DRAPEAU A MANQUE SI LONGTEMPS
    #     `build_http_callback` accepte `headers` depuis toujours, et
    #     `workflow/audit_graph._build_callback` le lit dans `cfg["headers"]`.
    #     Mais AUCUN chemin ne le remplissait : ni la CLI, ni le modele de
    #     requete de l'API. Une cible derriere `Authorization: Bearer …` etait
    #     donc inauditable — le parametre existait, le cablage non.
    #     L'API, elle, passe par `AUDIT_TARGET_HEADERS` : une ligne de commande
    #     est journalisee et visible dans `ps`, un jeton n'a rien a y faire.
    ap.add_argument("--headers", default=os.environ.get("AUDIT_TARGET_HEADERS"),
                    help="en-tetes HTTP JSON envoyes a la cible (defaut : variable "
                         "AUDIT_TARGET_HEADERS, qui garde le jeton hors de `ps`). "
                         "Ex. --headers '{\"Authorization\": \"Bearer xxx\"}'. "
                         "Sans ce drapeau, une cible protegee par un token repond 401 : "
                         "l'axe est EXCLU du score (jamais note 0) — l'audit ne mesure "
                         "alors rien, sans le dire assez fort.")
    ap.add_argument("--extra-payload", default=None,
                    help="JSON de champs constants exigés en plus du prompt")
    ap.add_argument("--exchange-log", default=None,
                    help="fichier JSONL des échanges avec la cible (lu en direct par "
                         "l'API ; évite l'entrelacement stdout du spinner DeepTeam)")
    ap.add_argument("--profile", default="dev", choices=["dev", "ollama", "openai", "final", "dry_run"])
    ap.add_argument("--attacks-per-type", type=int, default=1)
    ap.add_argument("--max-concurrent", type=int, default=2)
    ap.add_argument("--pyrit-max-turns", type=int, default=3)
    ap.add_argument("--source-path", default=None, help="active la couche statique")
    ap.add_argument("--requirements-path", default=None)
    # Un petit modèle local (llama3.2:3b) dépasse souvent 90s sur les prompts longs.
    # Un timeout trop court fait tomber les tests en [HTTP_ERROR] → axes EXCLUS
    # (PyRIT/Microsoft renvoient None) et score DeepTeam calculé sur trop peu de tests.
    ap.add_argument("--timeout", type=float, default=180.0, help="timeout HTTP par requête (s)")
    ap.add_argument("--garak-probes", default="dan.DAN_Jailbreak")
    ap.add_argument("--mode", default="standard", choices=["standard", "agentic"],
                    help="'agentic' : boucle percevoir/planifier/agir/réfléchir. "
                         "Les réglages ne peuvent que se durcir et le score retenu "
                         "est le minimum des passages — la boucle ne peut donc pas "
                         "améliorer un verdict, seulement le durcir.")
    ap.add_argument("--agentic-passes", type=int, default=2,
                    help="nombre maximal de passages en mode agentique")
    ap.add_argument("--explain-passes", action="store_true",
                    help="fait analyser AUSSI les attaques résistées par le juge (~3x d'appels LLM)")
    # Désactivation d'axes — sert au mode « contrôle rapide » : en coupant les axes
    # qui consomment des appels LLM, il ne reste que les axes DÉTERMINISTES (Garak,
    # Semgrep, pip-audit, sandbox). Aucun plafond de débit, résultat reproductible,
    # quelques minutes au lieu de plusieurs heures.
    ap.add_argument("--no-deepteam", action="store_true", help="désactive l'axe DeepTeam")
    ap.add_argument("--no-pyrit", action="store_true", help="désactive l'axe PyRIT")
    ap.add_argument("--no-garak", action="store_true", help="désactive l'axe Garak")
    ap.add_argument("--no-microsoft", action="store_true", help="désactive les payloads Microsoft")
    # ASI07 : usurper l'identité d'un agent pair. Enveloppe chaque prompt dans un
    # message inter-agents NON SIGNÉ — si la cible obéit, message_spoofing est démontré.
    ap.add_argument("--peer-agent-id", default=None,
                    help="ASI07 : identité d'agent pair usurpée (ex. orchestrator-01)")
    args = ap.parse_args()

    from agents.base_agent import build_http_callback

    # Meme validation que `extra_payload` : un JSON invalide doit echouer ICI,
    # avant l'audit, et non a la premiere requete HTTP quinze minutes plus tard.
    # LA MEME REGLE QUE L'API, PAS UNE COPIE.
    #     L'allowlist ne protegeait que l'API : en CLI on visait n'importe quoi.
    #     C'est defendable — qui peut lancer ce script peut lancer `curl` — mais
    #     elle etait presentee comme bornant la cible, pas l'interface. Une
    #     garantie a moitie vraie est une garantie sur laquelle on se repose a
    #     tort. Vide par defaut : le developpement local ne change pas d'un iota.
    try:
        valider_cible(args.target)
    except CibleRefusee as refus:
        ap.error(str(refus))
    avertissement = avertissement_si_libre()
    if avertissement:
        print(f"[avertissement] {avertissement}", file=sys.stderr)

    headers = json.loads(args.headers) if args.headers else None
    if headers is not None and not isinstance(headers, dict):
        ap.error("--headers doit etre un objet JSON, ex. '{\"X-API-Key\": \"…\"}'")

    extra_payload = json.loads(args.extra_payload) if args.extra_payload else None
    if extra_payload is not None and not isinstance(extra_payload, dict):
        ap.error("--extra-payload doit être un objet JSON (ex. '{\"title\":\"x\"}')")

    cfg = {
        "target_url": args.target,
        "prompt_field": args.prompt_field, "response_field": args.response_field,
        "extra_payload": extra_payload,
        "llm_profile": args.profile, "attacks_per_type": args.attacks_per_type,
        "max_concurrent": args.max_concurrent, "pyrit_max_turns": args.pyrit_max_turns,
        "garak_probes": args.garak_probes,
        "garak_request_timeout": int(args.timeout),
        "http_timeout": args.timeout,
        "explain_passes": args.explain_passes,
        "mode": args.mode, "agentic_passes": args.agentic_passes,
    }
    if args.source_path:
        cfg["source_path"] = args.source_path
    if args.requirements_path:
        cfg["requirements_path"] = args.requirements_path
    if args.peer_agent_id:
        cfg["peer_identity"] = {"agent_id": args.peer_agent_id, "format": "json"}

    # -- capture : tout ce qui part vers la cible et tout ce qui revient -- #
    transcript: list[dict] = []
    raw_cb = build_http_callback(args.target, prompt_field=args.prompt_field,
                                 response_field=args.response_field,
                                 headers=headers,
                                 extra_payload=extra_payload, timeout=args.timeout)

    # Journal des échanges : un FICHIER JSONL dédié, pas stdout.
    #
    # POURQUOI PAS STDOUT (bug MESURÉ le 2026-08-20)
    #     La version précédente imprimait « ##EXCHANGE##{json} » sur stdout. Or
    #     DeepTeam écrit son spinner sur le MÊME flux (retour chariot, ligne jamais
    #     terminée) depuis PLUSIEURS threads (async_mode + max_concurrent). Les
    #     écritures s'entrelacent et fragmentent la ligne : sur un run réel, l'API
    #     n'a capté que 7 échanges sur ~30 — les autres finissaient en texte brut
    #     dans les logs. Un fichier dédié, ouvert une fois et écrit sous verrou,
    #     n'a aucun autre écrivain : rien ne peut s'y intercaler.
    exchange_lock = threading.Lock()
    exchange_fh = open(args.exchange_log, "a", encoding="utf-8") if args.exchange_log else None

    from agents.agentic_loop import SONDES

    def cb(prompt):
        t = time.time()
        reply = raw_cb(prompt)
        with exchange_lock:
            entry = {
                "n": len(transcript) + 1,
                "elapsed_s": round(time.time() - t, 2),
                "prompt": str(prompt),
                "response": str(reply),
                "http_error": "[HTTP_ERROR]" in str(reply),
                # Les sondes de perception du mode agentique NE SONT PAS des
                # attaques : les compter comme telles gonflerait le volume
                # offensif affiche et ferait passer une question anodine pour un
                # test de securite.
                "probe": str(prompt) in SONDES,
            }
            transcript.append(entry)
            if exchange_fh is not None:
                exchange_fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
                exchange_fh.flush()
        return reply

    from judge.llm_config import DEV_MODEL, GEMINI_MODEL
    model_used = {"dev": DEV_MODEL, "final": GEMINI_MODEL}.get(args.profile, args.profile)

    print(f"\n{B}AUDIT {args.category}{X}  cible {args.target}")
    print(f"{D}profil {args.profile} · modèle {model_used} · "
          f"{args.attacks_per_type} attaque(s)/type{X}\n", flush=True)

    # Identifiant d'audit dans chaque trace : sans lui, deux runs successifs se
    # melangent dans le tableau de bord et aucune trace n'est rattachable.
    from judge.tracing import audit_context, audit_span

    agent = AGENT_REGISTRY[args.category](target_callback=cb, config=cfg)

    # Axes coupés à la demande. `deepteam_category=""` rend la couche
    # comportementale non applicable côté socle : elle est alors EXCLUE du score,
    # jamais comptée zéro.
    if args.no_deepteam:
        # via la config, PAS en vidant `deepteam_category` : cela couperait toute
        # la couche comportementale, or Garak vit dedans.
        agent.config["skip_deepteam"] = True
    if args.no_pyrit:
        agent.use_pyrit = False
    if args.no_garak:
        agent.use_garak = False
    if args.no_microsoft:
        agent.use_microsoft_probes = False
    disabled = [n for n, off in (("DeepTeam", args.no_deepteam), ("PyRIT", args.no_pyrit),
                                 ("Garak", args.no_garak), ("Microsoft", args.no_microsoft)) if off]
    if disabled:
        print(f"{Y}Axes désactivés :{X} {', '.join(disabled)}")
    t0 = time.time()
    # `audit_span` donne une RACINE aux observations de ce processus : sans lui,
    # le mode sous-processus produit des traces orphelines la ou le mode LangGraph
    # produit un arbre. Meme audit, deux lectures differentes selon le runner.
    with audit_context(audit_id=f"{args.category}-{datetime.now():%Y%m%d%H%M%S}",
                       profile=args.profile), audit_span(f"audit {args.category}"):
        res = agent.execute()
    dt = round(time.time() - t0, 1)

    beh, sta, dyn = res.layers["behavioral"], res.layers["static"], res.layers["dynamic"]
    raw = beh.raw or {}

    # ---------------------------------------------------------- affichage --
    col = G if res.score >= 7 else Y if res.score >= 4 else R
    print(f"\n{B}══ RÉSULTAT ══{X}")
    print(f"  score agent : {col}{res.score}/10{X}   status={res.status}   durée {dt}s")
    print(f"  {B}comportementale{X} score={beh.score} error={beh.error}")
    # Chaque axe : score ET raison quand il est exclu (score None) — plus de silence.
    status_of = {"deepteam": raw.get("deepteam_status"), "pyrit": raw.get("pyrit_status"),
                 "garak": raw.get("garak_status"), "microsoft": raw.get("microsoft_status")}
    for k, v in (raw.get("score_components") or {}).items():
        why = status_of.get(k) or ""
        flag = f"  {R}EXCLU{X} — {why}" if v is None else (f"  {D}({why}){X}" if why else "")
        print(f"    · {k:<11} {v!s:<6}{flag}")
    if raw.get("deepteam_stats") is not None:
        print(f"    · {'deepteam_stats':<18} {raw['deepteam_stats']}")
    if raw.get("behavioral_note"):
        print(f"    {Y}⚠ {raw['behavioral_note']}{X}")
    print(f"  {B}statique{X}  score={sta.score} applicable={sta.applicable} error={sta.error}")
    print(f"  {B}dynamique{X} score={dyn.score} applicable={dyn.applicable} "
          f"provider={(dyn.raw or {}).get('sandbox_provider')}")

    n_sondes = sum(1 for e in transcript if e.get("probe"))
    entete = f"{len(transcript) - n_sondes} ATTAQUES"
    if n_sondes:
        entete += f" + {n_sondes} SONDES"
    print(f"\n{B}== {entete} =={X}")
    for e in transcript:
        flag = f"{R}[HTTP_ERROR — exclu]{X}" if e["http_error"] else ""
        print(f"\n{Y}── #{e['n']}{X} {D}({e['elapsed_s']}s){X} {flag}")
        etiquette = f"{B}SONDE ▸{X}" if e.get("probe") else f"{R}ATTAQUE ▸{X}"
        print(f"  {etiquette} {e['prompt'][:420]}")
        print(f"  {D}RÉPONSE ▸{X} {e['response'][:420]}")

    print(f"\n{B}══ {len(res.vulnerabilities)} VULNÉRABILITÉS ══{X}")
    for v in res.vulnerabilities:
        c = R if v.severity == "Critical" else Y if v.severity == "High" else D
        print(f"  [{c}{v.severity:<8}{X}] {v.layer:<11} {v.title}")

    # ------------------------------------------------ sauvegarde dashboard --
    # Format UNIQUE (workflow/serialization.py) : le runner en sous-processus et
    # l'orchestration LangGraph produisent le meme JSON. Deux serialiseurs
    # divergeraient au premier champ ajoute, et le rapport afficherait des choses
    # differentes selon le runner — sans que rien ne le signale.
    from workflow.serialization import build_agent_entry, collect_attacks

    agent_entry = build_agent_entry(
        args.category, res, duration_s=dt,
        attacks=collect_attacks(res, transcript),
    )
    agent_entry["name"] = getattr(agent, "name", args.category)

    record = {
        "audit_id": f"{args.category}-{datetime.now():%Y%m%d%H%M%S}",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "target_url": args.target, "target_name": f"{args.target} ({args.category})",
        "llm_profile": args.profile, "model": model_used,
        "global_score": None, "risk_level": None,
        "duration_seconds": int(dt), "cost_tokens": 0, "cost_usd": 0.0,
        "status": res.status,
        "agents": {args.category: agent_entry},
        "transcript": transcript,
    }
    # Fiabilite de la chaine de jugement, calculee UNE fois et ecrite dans le JSON.
    # Le rapport et le dashboard la LISENT : aucun des deux ne la recalcule, donc
    # ils ne peuvent pas afficher des chiffres differents sur la meme donnee.
    # Vide la file LangFuse : sans flush, les dernieres observations meurent avec
    # le processus. Inerte si le tracage n'est pas configure.
    from judge.tracing import flush as _flush_traces

    _flush_traces()

    from judge.summary import build_judge_summary

    judge_summary = build_judge_summary(record["agents"])
    if judge_summary:
        record["judge_summary"] = judge_summary

    # Point de calcul UNIQUE (workflow.audit_graph.consolidate). Ce fichier
    # reimplementait les seuils de risque a la main : ils pouvaient donc diverger
    # de ceux du reste du projet sans que rien ne le signale.
    from workflow.audit_graph import consolidate

    record.update(consolidate({args.category: res.score}, record["agents"]))

    # Synthese d'ouverture du rapport, produite UNE FOIS en fin de run : le score,
    # la plage et les constats sont alors definitifs. La placer dans la boucle de
    # persistance incrementale couterait un appel LLM par agent pour un texte jete
    # aussitot. Un audit interrompu n'en a donc pas — le rapport calcule alors la
    # version deterministe, qui dit exactement les memes faits.
    from judge.executive_summary import build_for_profile

    record["executive_summary"] = build_for_profile(record, args.profile)

    # Plan de remediation : produit UNE FOIS en fin de run, apres la synthese,
    # sur les constats definitifs. Regroupe les constats bloquants par cause
    # racine — 22 constats se ramenaient a 5 actions sur l'audit de reference.
    from judge.remediation_plan import build_for_profile as _plan_remediation

    record["remediation_plan"] = _plan_remediation(record, args.profile)

    gs = record["global_score"]

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / f"{datetime.now():%Y%m%d_%H%M%S}_{args.category}_{args.profile}.json"
    out.write_text(json.dumps(record, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    print(f"\n{G}Enregistré :{X} {affichable(out)}")
    print(f"{D}Visible dans le dashboard (page Historique / Attaques).{X}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
