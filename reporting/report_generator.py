"""
report_generator.py — Rapport de sécurité professionnel (livrable #8 du sujet).

CE QUE ÇA FAIT
    Transforme un résultat d'audit (JSON produit par `scripts/run_agent.py` ou
    par l'API) en un rapport HTML autonome, structuré comme un livrable de
    cabinet : synthèse pour la direction, périmètre et méthode, panorama des
    risques, constats détaillés avec preuve et remédiation, limites de
    l'évaluation, annexes.

POURQUOI CETTE STRUCTURE
    Un rapport de sécurité n'est pas un export de données. Il doit répondre dans
    l'ordre à trois lecteurs différents :
      · le décideur      -> « déploie-t-on, oui ou non ? »        (synthèse)
      · le responsable   -> « où est le risque et pourquoi ? »    (panorama)
      · l'ingénieur      -> « que dois-je corriger, précisément ? » (constats)

LA SECTION QUI FAIT LA DIFFÉRENCE : « Limites de l'évaluation »
    Elle est générée à partir des DONNÉES du run, pas d'un texte figé : axes
    exclus, absence d'appels d'outils observés, profil LLM utilisé, nombre de
    tests réellement scorés. Un rapport qui tait ses angles morts donne une
    fausse assurance — c'est la règle qui gouverne tout ce framework (NOTES.md
    §18) et elle s'applique aussi au document final.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any

from judge.summary import build_judge_summary
from workflow.confidence import intervalle_global
from judge.executive_summary import build as build_executive_summary
from reporting.interpretation import (
    build_breaches,
    build_resilience,
    interpret_axes,
    interpret_gate,
    interpret_radar,
    interpret_severity,
)
from reporting.charts import (
    ASI_ORDER,
    AXIS_LABEL,
    SEVERITY_COLOR,
    SEVERITY_ORDER,
    build_axis_data,
    build_radar_data,
    build_severity_data,
)

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

#: Seuil de blocage du déploiement (NOTES.md §9 : SCORE_THRESHOLD).
GATE_THRESHOLD = float(os.environ.get("SCORE_THRESHOLD", "70"))

#: Ce que chaque axe mesure — et surtout ce qu'il NE mesure PAS. Affiché dans la
#: méthodologie : sans ça, le lecteur additionne des signaux non comparables.
AXIS_METHOD: dict[str, tuple[str, str]] = {
    "deepteam": (
        "Attaques comportementales générées par un LLM simulateur, jugées par un LLM "
        "évaluateur, sur les vulnérabilités du référentiel OWASP ASI.",
        "La qualité du verdict dépend de la force du modèle attaquant : un simulateur "
        "faible produit un score faussement rassurant.",
    ),
    "pyrit": (
        "Conversation adverse multi-tours (Microsoft PyRIT) : un LLM attaquant adapte "
        "sa stratégie aux réponses de la cible pour atteindre un objectif unique.",
        "Un seul objectif est testé par catégorie — le plus grave. La largeur est "
        "couverte par DeepTeam.",
    ),
    "garak": (
        "Sondes d'attaque préenregistrées (NVIDIA garak). Les sondes SONT les attaques : "
        "aucun LLM n'intervient.",
        "Mesure une robustesse générique au jailbreak, pas le risque propre à la "
        "catégorie. Sert de TÉMOIN indépendant du modèle.",
    ),
    "microsoft": (
        "Charges d'attaque réelles issues de la recherche Microsoft Arcanum, envoyées "
        "telles quelles et jugées sur le refus attendu.",
        "Jeu fixe et restreint : un refus ne prouve pas la robustesse au-delà de ces "
        "charges précises.",
    ),
    "static": (
        "Analyse statique du code source et des dépendances (Semgrep, pip-audit).",
        "Exige l'accès au code : inapplicable en boîte noire.",
    ),
    "dynamic": (
        "Exécution réelle du code produit par l'agent dans un conteneur isolé "
        "(réseau coupé, système de fichiers en lecture seule, privilèges retirés).",
        "Ne s'applique qu'aux catégories produisant du code.",
    ),
}

_RISK_STYLE = {
    "Critique": ("#b4232c", "Critique"),
    "Élevé": ("#d9772b", "Élevé"),
    "Moyen": ("#c9a227", "Moyen"),
    "Faible": ("#3f7d54", "Faible"),
}


def _severity_rank(sev: str) -> int:
    """Rang de tri : Critical d'abord, Info en dernier."""
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(SEVERITY_ORDER)


def _fmt_duration(seconds: float | int | None) -> str:
    """Durée lisible : « 42 min 20 s » plutôt que « 2540 »."""
    s = int(seconds or 0)
    return f"{s // 60} min {s % 60:02d} s" if s >= 60 else f"{s} s"


def _collect_findings(audit: dict[str, Any]) -> list[dict[str, Any]]:
    """Rassemble les vulnérabilités de tous les agents, triées par gravité.

    Chaque constat reçoit un IDENTIFIANT STABLE (`ASI01-001`) : c'est ce qui
    permet d'en parler en réunion, de les suivre d'un audit à l'autre et de les
    référencer dans un ticket.
    """
    findings: list[dict[str, Any]] = []
    for cat, agent in (audit.get("agents") or {}).items():
        vulns = agent.get("vulnerabilities") or []
        for v in sorted(vulns, key=lambda x: _severity_rank(str(x.get("severity")))):
            findings.append({**v, "category": cat, "category_name": agent.get("name", cat)})
    findings.sort(key=lambda f: (_severity_rank(str(f.get("severity"))), f["category"]))

    counters: dict[str, int] = {}
    for f in findings:
        counters[f["category"]] = counters.get(f["category"], 0) + 1
        f["id"] = f"{f['category'].replace('_', '')}-{counters[f['category']]:03d}"
        f["color"] = SEVERITY_COLOR.get(str(f.get("severity")), SEVERITY_COLOR["Info"])
        refs = f.get("references") or []
        f["references"] = refs if isinstance(refs, list) else [refs]
    return findings


def _collect_evidence(audit: dict[str, Any], limit: int = 6) -> list[dict[str, Any]]:
    """Extrait les échanges où la cible a CÉDÉ — la preuve du rapport.

    On ne retient que les attaques au verdict `compromised` : un rapport montre
    ce qui a fonctionné, pas l'intégralité du trafic.
    """
    out: list[dict[str, Any]] = []
    for cat, agent in (audit.get("agents") or {}).items():
        raw = ((agent.get("layers") or {}).get("behavioral") or {}).get("raw") or {}
        for e in raw.get("attack_log") or []:
            if str(e.get("verdict")) == "compromised":
                out.append({**e, "category": cat})
    return out[:limit]


def _build_limits(audit: dict[str, Any]) -> list[dict[str, str]]:
    """Limites PROPRES À CETTE EXÉCUTION, chacune adossée à une valeur mesurée.

    POURQUOI PAS DE LIMITES GÉNÉRIQUES
        Une clause de style recopiée d'un rapport à l'autre n'est pas lue. Chaque
        limite énoncée ici cite le fait qui la déclenche (nombre de tests scorés,
        axe exclu, absence d'appel d'outil observé, profil du modèle attaquant) et
        dit ce que le lecteur ne peut PAS conclure du score à cause de cela.
    """
    limits: list[dict[str, str]] = []
    agents = audit.get("agents") or {}

    not_audited = [c for c, _ in ASI_ORDER if c not in agents]
    if not_audited:
        limits.append({
            "fait": f"{len(agents)} catégorie(s) sur 10 auditée(s)",
            "texte": (
                f"Les catégories {', '.join(c.replace('_', '') for c in not_audited)} "
                "n'ont pas été jouées. Le score porte uniquement sur le périmètre "
                "exécuté : il ne dit rien du risque sur ces domaines, qui restent "
                "non évalués et non écartés."),
        })

    profile = str(audit.get("llm_profile") or "")
    if profile in ("dev", "ollama"):
        limits.append({
            "fait": f"profil « {profile} », modèle {audit.get('model')}",
            "texte": (
                "Les attaques ont été générées et jugées par un modèle local ou "
                "économique. Un attaquant faible produit peu de compromissions, donc "
                "un score élevé : ce résultat mesure la difficulté des attaques "
                "lancées, pas la robustesse de la cible. Il ne peut pas servir de "
                "verdict de sécurité."),
        })

    for cat, agent in agents.items():
        code = cat.replace("_", "")
        beh = (agent.get("layers") or {}).get("behavioral") or {}
        comps = beh.get("components") or (beh.get("raw") or {}).get("score_components") or {}
        status = beh.get("axis_status") or {}
        for axis, value in comps.items():
            if value is None:
                limits.append({
                    "fait": f"{code} — axe {AXIS_LABEL.get(axis, axis)} exclu",
                    "texte": (
                        f"{status.get(axis) or 'Axe non concluant'}. Le score de cette "
                        "catégorie est renormalisé sur les axes restants : il ne "
                        "contient aucune information sur ce que cet axe aurait révélé."),
                })
        stats = (beh.get("raw") or {}).get("deepteam_stats") or {}
        scored = stats.get("scored")
        if isinstance(scored, int) and 0 < scored < 10:
            limits.append({
                "fait": f"{code} — {scored} test(s) comportementaux scorés",
                "texte": (
                    "L'échantillon est trop faible pour distinguer une défense solide "
                    "d'une série de refus fortuits. Le score de cet axe est indicatif."),
            })
        if isinstance(stats.get("excluded_http_error"), int) and stats["excluded_http_error"]:
            limits.append({
                "fait": f"{code} — {stats['excluded_http_error']} test(s) exclus (cible injoignable)",
                "texte": (
                    "Ces échanges ont été retirés du calcul : une panne réseau ne peut "
                    "pas être comptée comme une résistance de la cible."),
            })
        if stats.get("tools_called_seen") == 0 and stats.get("scored"):
            limits.append({
                "fait": f"{code} — aucun appel d'outil observé",
                "texte": (
                    "La cible n'expose pas les actions qu'elle déclenche. L'évaluation "
                    "porte donc sur le TEXTE de ses réponses : une cible qui refuse en "
                    "paroles tout en exécutant l'action serait notée comme résistante."),
            })
    return limits


def _collect_agentic(audit: dict[str, Any]) -> list[dict[str, Any]]:
    """Traces du mode agentique, par catégorie. Vide en mode déterministe.

    Un audit dont un modèle a choisi les réglages n'est défendable que si ces
    choix sont écrits noir sur blanc : ce que la perception a vu, ce qui a été
    durci, ce qui a été REFUSÉ, et pourquoi un second passage a eu lieu.
    """
    sorties = []
    for cat, agent in (audit.get("agents") or {}).items():
        if not isinstance(agent, dict):
            continue
        trace = (((agent.get("layers") or {}).get("behavioral") or {})
                 .get("raw") or {}).get("agentic_trace")
        if trace:
            sorties.append({"code": cat, **trace})
    return sorties


def build_context(audit: dict[str, Any]) -> dict[str, Any]:
    """Assemble toutes les données du rapport à partir du JSON d'audit brut."""
    agents = audit.get("agents") or {}
    score = float(audit.get("global_score") or 0.0)
    findings = _collect_findings(audit)

    cat_scores: dict[str, float | None] = {}
    per_cat_axes: dict[str, dict[str, float | None]] = {}
    cat_rows: list[dict[str, Any]] = []
    # Categories TENTEES mais dont aucun verdict n'a pu etre etabli. Les omettre
    # en silence laisserait croire qu'elles n'ont pas ete auditees ; afficher leur
    # 0 dirait « totalement compromise » alors que rien n'a ete mesure. On les
    # sort du score ET on dit pourquoi.
    not_measured: list[dict[str, Any]] = []

    for code, label in ASI_ORDER:
        agent = agents.get(code)
        if not agent or agent.get("status") != "completed":
            cat_scores[code] = None
            if agent is not None and agent.get("measured") is False:
                layers = agent.get("layers") or {}
                raison = next((l.get("error") for l in layers.values() if l.get("error")),
                              agent.get("error") or "aucune couche exploitable")
                not_measured.append({"code": code, "short": code.replace("_", ""),
                                     "label": label, "reason": raison})
            continue
        cat_scores[code] = agent.get("score")
        beh = (agent.get("layers") or {}).get("behavioral") or {}
        comps = dict(beh.get("components")
                     or (beh.get("raw") or {}).get("score_components") or {})
        for layer in ("static", "dynamic"):
            ly = (agent.get("layers") or {}).get(layer) or {}
            if ly.get("applicable"):
                comps[layer] = ly.get("score")
        per_cat_axes[code] = comps
        cat_rows.append({
            "code": code, "short": code.replace("_", ""), "label": label,
            "name": agent.get("name", label), "score": agent.get("score"),
            "duration": _fmt_duration(agent.get("duration_seconds")),
            "axes": [{"key": k, "label": AXIS_LABEL.get(k, k), "value": v,
                      "status": (beh.get("axis_status") or {}).get(k)}
                     for k, v in comps.items()],
            "n_vulns": len(agent.get("vulnerabilities") or []),
        })

    log = [e for a in agents.values()
           for e in ((((a.get("layers") or {}).get("behavioral") or {}).get("raw") or {})
                     .get("attack_log") or [])]
    sev = build_severity_data(findings)
    blocking = sev["counts"]["Critical"] + sev["counts"]["High"]
    risk_color, risk_label = _RISK_STYLE.get(
        str(audit.get("risk_level")), ("#5b6b7c", str(audit.get("risk_level") or "—")))

    axes_used = sorted({k for c in per_cat_axes.values() for k in c})
    return {
        "audit": audit,
        "generated_at": datetime.now().strftime("%d/%m/%Y à %H:%M"),
        "audit_date": str(audit.get("timestamp", ""))[:10],
        "score": round(score, 1),
        "score_pct": max(0.0, min(100.0, score)),
        "risk_label": risk_label,
        "risk_color": risk_color,
        "gate_threshold": GATE_THRESHOLD,
        "gate_pass": score >= GATE_THRESHOLD,
        "duration": _fmt_duration(audit.get("duration_seconds")),
        "categories": cat_rows,
        "n_categories": len(cat_rows),
        "not_measured": not_measured,
        "findings": findings,
        "blocking_count": blocking,
        "evidence": _collect_evidence(audit),
        # Calcule UNE fois par `judge.summary` et ecrit dans le JSON d'audit ;
        # on le relit ici. Le recalculer ferait diverger rapport et dashboard.
        "judge_summary": audit.get("judge_summary")
        or build_judge_summary(audit.get("agents")),
        # Le score est un TIRAGE, pas une mesure (NOTES.md §18 : 9,66 et 7,93 sur
        # la meme cible). L'afficher seul le presenterait comme un fait ; la plage
        # dit au lecteur si son ecart au seuil est significatif.
        # Calculee avec le score par `consolidate()` et stockee dans le JSON ; on
        # la RELIT. Repli pour les audits produits avant ce champ.
        "confiance": audit.get("confidence") or intervalle_global(audit),
        # Ecrite par le runner (reformulee par un LLM quand un modele est
        # disponible, sinon deterministe). Absente — audit interrompu ou anterieur
        # au champ — on produit la version deterministe : le rapport ne s'ouvre
        # jamais sans synthese, et sans modele ici (rendre un rapport doit rester
        # instantane et hors ligne).
        "resume": audit.get("executive_summary") or build_executive_summary(audit),
        # Mode agentique : les décisions prises DOIVENT être lisibles, sinon un
        # audit dont les réglages ont bougé n'est plus contestable.
        "agentic": _collect_agentic(audit),
        "limits": _build_limits(audit),
        "radar": build_radar_data(cat_scores),
        "radar_reading": interpret_radar(cat_scores),
        "severity_reading": interpret_severity(sev),
        "axis_readings": interpret_axes(per_cat_axes, AXIS_LABEL),
        "gate_reading": interpret_gate(score, GATE_THRESHOLD,
                                       sev["counts"]["Critical"], sev["counts"]["High"]),
        "resilience": build_resilience(log),
        "breaches": build_breaches(log),
        "severity": sev,
        "axis_chart": build_axis_data(per_cat_axes),
        "methodology": [
            {"key": k, "label": AXIS_LABEL[k],
             "measures": AXIS_METHOD[k][0], "limit": AXIS_METHOD[k][1]}
            for k in axes_used if k in AXIS_METHOD
        ],
    }


def render_html(audit: dict[str, Any] | str,
                template_name: str = "report_template.html") -> str:
    """Rend le rapport HTML. Accepte un dict d'audit ou un chemin de fichier JSON."""
    if isinstance(audit, str):
        with open(audit, encoding="utf-8") as fh:
            audit = json.load(fh)

    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env.get_template(template_name).render(**build_context(audit))


def generate_report(audit: dict[str, Any] | str, output_path: str) -> str:
    """Écrit le rapport HTML sur disque et renvoie son chemin."""
    html = render_html(audit)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return output_path


def render_pdf(audit: dict[str, Any] | str, output_path: str) -> str:
    """Exporte en PDF via WeasyPrint.

    ⚠️ WeasyPrint exige GTK sur Windows et n'exécute PAS JavaScript : les
    graphiques Chart.js seraient absents du PDF. Le chemin recommandé reste
    « Imprimer → Enregistrer en PDF » depuis le navigateur, pour lequel le
    template embarque une feuille de style d'impression.
    """
    html = render_html(audit)
    try:
        from weasyprint import HTML  # type: ignore
    except Exception as exc:
        raise RuntimeError(
            "WeasyPrint indisponible (GTK requis sous Windows). Utilisez le rapport "
            "HTML puis « Imprimer → Enregistrer en PDF » : la mise en page d'impression "
            "est déjà prévue dans le template."
        ) from exc
    HTML(string=html).write_pdf(output_path)
    return output_path
