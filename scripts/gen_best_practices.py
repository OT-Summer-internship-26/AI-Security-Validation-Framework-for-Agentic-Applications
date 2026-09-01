"""
gen_best_practices.py — Génère `docs/security_best_practices.md` (livrable #9).

POURQUOI UN GÉNÉRATEUR ET PAS UN FICHIER ÉCRIT À LA MAIN
    Tout le contenu existe déjà : les recommandations OWASP sont dans
    `config/owasp_knowledge_base.json` (`prevention_guidelines`, `detection_metrics`),
    et les recommandations ciblées par classe de vulnérabilité sont les
    `recommendation_map` des 10 agents. Recopier tout ça dans un .md créerait une
    SECONDE source de vérité qui divergerait au premier changement de KB — le
    catalogue mentirait alors sur ce que le framework recommande réellement.
    Ici, le document est un RENDU : on régénère, on ne réédite jamais à la main.

Usage :  python scripts/gen_best_practices.py
"""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from workflow.paths import affichable
sys.path.insert(0, str(ROOT))

KB_PATH = ROOT / "config" / "owasp_knowledge_base.json"
OUT = ROOT / "docs" / "security_best_practices.md"

# Axes réellement exécutés par le framework, par couche déclarée dans la KB.
LAYER_LABEL = {
    "behavioral": "**Comportementale** — DeepTeam (`OWASP_ASI_2026`), PyRIT multi-tours, "
                  "Garak, payloads Microsoft Arcanum",
    "static": "**Statique** — Semgrep + pip-audit (CVE des dépendances)",
    "static (optional)": "**Statique (optionnelle)** — Semgrep, si `source_path` est fourni",
    "dynamic": "**Dynamique** — exécution réelle du code produit dans un sandbox Docker "
               "(`--network none`, read-only, non-root)",
}


def main() -> int:
    kb = json.loads(KB_PATH.read_text(encoding="utf-8"))
    from workflow.audit_graph import AGENT_REGISTRY

    L: list[str] = []
    add = L.append

    add("# Catalogue de recommandations de sécurité — applications IA agentiques")
    add("")
    add("> **Livrable #9.** Contre-mesures pour les 10 catégories de risque "
        "OWASP Top 10 for Agentic Applications 2026 (ASI01 → ASI10).")
    add("")
    add("⚠️ **Fichier GÉNÉRÉ — ne pas éditer à la main.** Il est le rendu de "
        "`config/owasp_knowledge_base.json` et des `recommendation_map` des 10 agents. "
        "Pour le modifier, changer la source puis relancer :")
    add("")
    add("```bash")
    add("python scripts/gen_best_practices.py")
    add("```")
    add("")
    meta = kb.get("metadata", {})
    add(f"*Généré le {date.today().isoformat()} — source : {meta.get('version_source', 'n/a')}.*")
    add("")
    add(f"*{meta.get('licence_source', '')}*")
    add("")
    add("---")
    add("")

    # -- Sommaire : une vue d'ensemble avant le détail ------------------------ #
    add("## Vue d'ensemble")
    add("")
    add("| Catégorie | Risque | Contre-mesures | Comment le framework le teste |")
    add("|---|---|---|---|")
    for v in kb["vulnerabilities"]:
        cat = f"ASI_{v['id'][3:]}"
        layers = ", ".join(l.split(" ")[0] for l in v.get("test_layers", []))
        add(f"| **[{v['id']}](#{v['id'].lower()}--{_anchor(v['nom_fr'])})** {v['nom_fr']} "
            f"| {v.get('niveau_risque', '—')} "
            f"| {len(v.get('prevention_guidelines', []))} "
            f"| {layers or '—'} |")
    add("")
    add("---")
    add("")

    for v in kb["vulnerabilities"]:
        cat = f"ASI_{v['id'][3:]}"
        agent = AGENT_REGISTRY.get(cat)

        add(f"## {v['id']} — {v['nom_fr']}")
        add("")
        add(f"*{v['nom']}* · risque **{v.get('niveau_risque', '—')}** · "
            f"AIVSS : {v.get('aivss_core_risk', '—')}")
        add("")
        add(v.get("description", "").strip())
        add("")

        if v.get("mecanismes_racines"):
            add("### Pourquoi c'est possible")
            add("")
            for m in v["mecanismes_racines"]:
                add(f"- {m}")
            add("")

        add("### Contre-mesures")
        add("")
        for i, g in enumerate(v.get("prevention_guidelines", []), 1):
            add(f"{i}. {g}")
        add("")

        # Recommandations ciblées du framework : plus fines que la reco de catégorie,
        # ce sont celles réellement émises dans un rapport quand la classe est touchée.
        rmap = getattr(agent, "recommendation_map", None) if agent else None
        if rmap:
            add("### Recommandations ciblées émises par l'agent")
            add("")
            add("Appliquées par vulnérabilité détectée — elles priment sur la "
                "recommandation générique de la catégorie.")
            add("")
            for k, rec in rmap.items():
                add(f"- **`{k}`** — {rec}")
            add("")

        if v.get("detection_metrics"):
            add("### Comment le détecter en production")
            add("")
            for d in v["detection_metrics"]:
                add(f"- {d}")
            add("")

        add("### Couverture par le framework")
        add("")
        for layer in v.get("test_layers", []):
            add(f"- {LAYER_LABEL.get(layer, layer)}")
        if agent is not None:
            add(f"- Agent : `{agent.__module__}.{agent.__name__}`")
        add("")

        if v.get("references_officielles"):
            add("<details><summary>Références officielles</summary>")
            add("")
            for r in v["references_officielles"]:
                add(f"- {r}")
            add("")
            add("</details>")
            add("")
        add("---")
        add("")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(L), encoding="utf-8")
    print(f"Écrit : {affichable(OUT)} "
          f"({len(L)} lignes, {len(kb['vulnerabilities'])} catégories)")
    return 0


def _anchor(txt: str) -> str:
    """Ancre GitHub : minuscules, espaces → tirets, ponctuation retirée."""
    keep = "".join(c for c in txt.lower() if c.isalnum() or c in " -")
    return keep.replace(" ", "-")


if __name__ == "__main__":
    raise SystemExit(main())
