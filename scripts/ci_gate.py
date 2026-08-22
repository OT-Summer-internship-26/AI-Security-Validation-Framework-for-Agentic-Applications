"""
ci_gate.py — Porte de qualité CI/CD : décide si le déploiement passe.

CE QUE ÇA FAIT
    Lit un résultat d'audit, applique `config/gate_policy.json`, écrit un
    rapport lisible et sort avec le bon code : 0 = passe, 1 = bloque.

POURQUOI UNE POLITIQUE ET PAS UN SEUIL
    Un seuil de score unique est faux dans les deux sens : un score élevé peut
    masquer une faille Critical, un score bas peut bloquer sur des catégories
    hors périmètre. La décision se compose donc de règles nommées et traçables.

USAGE
    python scripts/ci_gate.py                       # dernier audit
    python scripts/ci_gate.py <audit.json>
    python scripts/ci_gate.py --summary out.md      # rapport Markdown pour la PR
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "data" / "audit_results"
POLICY = ROOT / "config" / "gate_policy.json"

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Rang de gravité : plus petit = plus grave.
SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def load_policy() -> dict:
    """Politique versionnée. Les clés `_*` sont de la documentation, pas des règles."""
    if not POLICY.exists():
        return {"block_all_critical": True, "max_high_findings": 3,
                "min_score": 70, "enforce_min_score": False,
                "per_category": {}, "derogations": []}
    return {k: v for k, v in json.loads(POLICY.read_text(encoding="utf-8")).items()
            if not k.startswith("_")}


def latest_audit() -> Path | None:
    files = [p for p in RESULTS.glob("*.json") if p.name != "sample_audit.json"]
    return max(files, key=lambda p: p.stat().st_mtime) if files else None


def evaluate(audit: dict, policy: dict) -> tuple[str, list[dict], dict]:
    """Applique la politique → (verdict, règles déclenchées, compteurs).

    Verdicts, du plus permissif au plus strict :
    PASS · PASS_WARNING · REVIEW_REQUIRED · BLOCKED.
    """
    rank = {"PASS": 0, "PASS_WARNING": 1, "REVIEW_REQUIRED": 2, "BLOCKED": 3}
    verdict = "PASS"

    def escalate(v: str) -> None:
        nonlocal verdict
        if rank[v] > rank[verdict]:
            verdict = v

    rules: list[dict] = []
    # La catégorie vit dans la CLÉ du dict `agents` — les vulnérabilités
    # enregistrées ne portent pas toujours le champ. On l'injecte ici, sinon
    # tout tombe dans la catégorie par défaut et les règles par catégorie
    # deviennent inopérantes.
    vulns = [{**v, "asi_category": v.get("asi_category") or cat}
             for cat, ag in (audit.get("agents") or {}).items()
             for v in (ag.get("vulnerabilities") or [])]

    # ── Dérogations : seules celles NON expirées neutralisent un finding ──
    today = date.today()
    active, expired = [], []
    for d in policy.get("derogations", []):
        try:
            exp = datetime.fromisoformat(str(d.get("expires_at"))).date()
        except Exception:
            exp = today                      # date illisible → considérée expirée
        (active if exp >= today else expired).append(d)

    waived_titles = {str(d.get("finding_title", "")).strip().lower() for d in active}
    kept = [v for v in vulns
            if str(v.get("title", "")).strip().lower() not in waived_titles]
    waived = len(vulns) - len(kept)

    if waived:
        rules.append({"effect": "info", "label": f"{waived} finding(s) sous dérogation active"})
    if expired:
        escalate("REVIEW_REQUIRED")
        rules.append({"effect": "warn",
                      "label": f"{len(expired)} dérogation(s) expirée(s) — redevenue(s) bloquante(s)",
                      "detail": ", ".join(str(d.get("finding_title")) for d in expired)})

    # ── Catégories : « ignore » sort de la décision ──
    per_cat = policy.get("per_category", {})
    action = lambda c: (per_cat.get(c) or {}).get("action", "warn")  # noqa: E731
    considered = [v for v in kept if action(v.get("asi_category", "")) != "ignore"]
    ignored = len(kept) - len(considered)
    if ignored:
        cats = sorted({v.get("asi_category", "?") for v in kept
                       if action(v.get("asi_category", "")) == "ignore"})
        rules.append({"effect": "info",
                      "label": f"{ignored} finding(s) hors périmètre déclaré",
                      "detail": ", ".join(cats)})

    counts = {s: sum(1 for v in considered if v.get("severity") == s) for s in SEV_RANK}

    # ── Règle 1 : Critical bloque, INDÉPENDAMMENT du score ──
    if policy.get("block_all_critical", True):
        crit_block = [v for v in considered if v.get("severity") == "Critical"
                      and action(v.get("asi_category", "")) == "block"]
        crit_warn = [v for v in considered if v.get("severity") == "Critical"
                     and action(v.get("asi_category", "")) == "warn"]
        if crit_block:
            escalate("BLOCKED")
            rules.append({"effect": "block",
                          "label": f"{len(crit_block)} vulnérabilité(s) Critical en catégorie bloquante",
                          "detail": " · ".join(f"{v.get('asi_category')} — {v.get('title')}"
                                               for v in crit_block[:5])})
        if crit_warn:
            escalate("REVIEW_REQUIRED")
            rules.append({"effect": "warn",
                          "label": f"{len(crit_warn)} Critical en catégorie « avertissement »"})
        if not crit_block and not crit_warn:
            rules.append({"effect": "ok", "label": "Aucune vulnérabilité Critical retenue"})

    # ── Règle 2 : budget de findings High, réglable ──
    budget = int(policy.get("max_high_findings", 3))
    if counts["High"] > budget:
        escalate("BLOCKED")
        rules.append({"effect": "block",
                      "label": f"{counts['High']} findings High > budget de {budget}"})
    elif counts["High"]:
        escalate("PASS_WARNING")
        rules.append({"effect": "warn",
                      "label": f"{counts['High']} finding(s) High dans le budget ({budget})"})

    # ── Règle 3 : score, seulement si la politique l'exige ──
    # En mode `quick` le score est partiel : l'imposer bloquerait sur une mesure
    # qui n'a pas le même sens qu'un audit complet.
    score = audit.get("global_score")
    if policy.get("enforce_min_score", False) and score is not None:
        seuil = policy.get("min_score", 70)
        if score < seuil:
            escalate("BLOCKED")
            rules.append({"effect": "block", "label": f"Score {score}/100 sous le seuil de {seuil}"})
        else:
            rules.append({"effect": "ok", "label": f"Score {score}/100 ≥ seuil {seuil}"})
    elif score is not None:
        rules.append({"effect": "info",
                      "label": f"Score {score}/100 — non contraignant (audit partiel)"})

    return verdict, rules, counts


ICON = {"block": "🔴", "warn": "🟠", "ok": "🟢", "info": "⚪"}
LABEL = {"PASS": "PASS — déploiement autorisé",
         "PASS_WARNING": "PASS avec avertissement",
         "REVIEW_REQUIRED": "REVUE REQUISE — validation humaine",
         "BLOCKED": "BLOCAGE — déploiement refusé"}


def markdown(audit: dict, verdict: str, rules: list[dict], counts: dict, src: str) -> str:
    """Rapport pour le commentaire de pull request."""
    head = "❌" if verdict == "BLOCKED" else "⚠️" if verdict != "PASS" else "✅"
    out = [f"## {head} Quality Gate — {LABEL[verdict]}", "",
           f"`{src}` · cible `{audit.get('target_url', '?')}` · "
           f"mode `{audit.get('llm_profile', '?')}`", "",
           "| Critical | High | Medium | Low |", "|---:|---:|---:|---:|",
           f"| {counts['Critical']} | {counts['High']} | {counts['Medium']} | {counts['Low']} |",
           "", "### Règles appliquées", ""]
    for r in rules:
        line = f"- {ICON.get(r['effect'], '·')} **{r['label']}**"
        if r.get("detail"):
            line += f"\n  <sub>{r['detail']}</sub>"
        out.append(line)

    vulns = [v for ag in (audit.get("agents") or {}).values()
             for v in (ag.get("vulnerabilities") or [])]
    blocking = sorted((v for v in vulns if v.get("severity") in ("Critical", "High")),
                      key=lambda v: SEV_RANK.get(v.get("severity", "Info"), 9))
    if blocking:
        out += ["", "### Vulnérabilités à traiter", ""]
        for v in blocking[:10]:
            out.append(f"- **{v.get('severity')}** · `{v.get('asi_category')}` · "
                       f"{v.get('title')}")
            if v.get("recommendation"):
                out.append(f"  <sub>{str(v['recommendation'])[:200]}</sub>")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("audit", nargs="?", help="fichier d'audit (défaut : le plus récent)")
    ap.add_argument("--summary", help="écrit un rapport Markdown dans ce fichier")
    args = ap.parse_args()

    path = Path(args.audit) if args.audit else latest_audit()
    if path and not path.exists():
        path = RESULTS / str(args.audit)
    if not path or not path.exists():
        print("❌ Aucun résultat d'audit trouvé — le gate ne peut pas décider.")
        return 1

    audit = json.loads(path.read_text(encoding="utf-8"))
    policy = load_policy()
    verdict, rules, counts = evaluate(audit, policy)

    print(f"\n{'=' * 62}")
    print(f"  QUALITY GATE — {LABEL[verdict]}")
    print(f"{'=' * 62}")
    print(f"  audit    {path.name}")
    print(f"  cible    {audit.get('target_url', '?')}")
    print(f"  findings {counts['Critical']} Critical · {counts['High']} High · "
          f"{counts['Medium']} Medium · {counts['Low']} Low\n")
    for r in rules:
        print(f"  {ICON.get(r['effect'], '·')} {r['label']}")
        if r.get("detail"):
            print(f"       {r['detail'][:160]}")
    print()

    if args.summary:
        Path(args.summary).write_text(
            markdown(audit, verdict, rules, counts, path.name), encoding="utf-8")

    return 1 if verdict == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
