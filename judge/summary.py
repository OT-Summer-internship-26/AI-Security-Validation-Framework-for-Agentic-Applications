"""
summary.py — Agrège ce que les juges disent DE LEUR PROPRE FIABILITÉ.

POURQUOI CE FICHIER EXISTE (et pourquoi il n'aurait jamais dû manquer)
    Cette agrégation a d'abord été écrite DEUX FOIS : 62 lignes en Python dans le
    générateur de rapport, 49 en TypeScript dans l'adaptateur du dashboard. Deux
    implémentations de la même règle, dans deux langages, sans rien pour détecter
    leur divergence : le premier ajout de compteur n'aurait été fait que d'un côté,
    et les deux surfaces auraient affiché des chiffres différents sur la même donnée.

    Le calcul vit donc ICI, à un seul endroit, et son résultat est ÉCRIT DANS LE
    JSON d'audit. Le rapport le lit. Le dashboard le lit. Personne ne recalcule.

POURQUOI DANS `judge/` ET PAS DANS `reporting/`
    Ce sont les compteurs des juges. Le générateur de rapport n'a pas à connaître
    les clés internes de `severity_judge` ou `cross_validation` : le jour où l'une
    change, seule la couche qui la possède doit bouger.

CE QUE LE RÉSUMÉ RÉPOND
    · Combien de gravités viennent réellement du juge, combien du barème statique ?
    · Combien de verdicts ont été rejugés, et cela a-t-il changé quelque chose ?
    · Le second avis apporte-t-il quoi que ce soit d'indépendant ?
    · Les refus observés sont-ils des refus de principe ou des accidents ?
    Sans ces chiffres, un verdict de modèle se lit comme un fait établi.
"""

from __future__ import annotations

from typing import Any

# Clés des compteurs, définies UNE fois. Tout consommateur passe par ce module ;
# renommer une clé ne peut donc plus casser un fichier lointain en silence.
CV_KEYS = ("triggered", "agreed", "changed", "unavailable")
RECO_KEYS = ("contextual_used", "generic_dropped", "deduplicated")
REFUSAL_KEYS = ("robust", "partial", "accidental")
MS_KEYS = ("complied", "refused", "unreadable")

# Au-delà de ce taux de repli, les gravités affichées ne viennent majoritairement
# plus du juge contextuel et le rapport doit le signaler visuellement.
FALLBACK_ALERT_PCT = 30


def _int(mapping: Any, key: str) -> int:
    """Lecture défensive : un JSON d'audit peut venir d'une version antérieure."""
    if not isinstance(mapping, dict):
        return 0
    value = mapping.get(key)
    return int(value) if isinstance(value, (int, float)) else 0


def build_judge_summary(agents: dict[str, Any] | None) -> dict[str, Any]:
    """Agrège les compteurs des juges sur toutes les catégories d'un audit.

    `agents` : le dict `audit["agents"]` (catégorie → résultat d'agent).

    Renvoie `{}` si aucun juge n'a tourné — le bloc disparaît alors de l'écran au
    lieu d'afficher des zéros, qui se liraient comme « aucun problème ».
    """
    judged = fallbacks = 0
    cv = dict.fromkeys(CV_KEYS, 0)
    reco = dict.fromkeys(RECO_KEYS, 0)
    refusal = dict.fromkeys(REFUSAL_KEYS, 0)
    ms = dict.fromkeys(MS_KEYS, 0)
    warnings: list[str] = []

    for category, agent in (agents or {}).items():
        layers = (agent or {}).get("layers") or {}
        raw = (layers.get("behavioral") or {}).get("raw") or {}
        stats = raw.get("deepteam_stats") or {}

        judge_stats = stats.get("judge") or {}
        judged += _int(judge_stats, "judged")
        fallbacks += sum(
            int(v) for k, v in judge_stats.items()
            if k.startswith("fallback_") and isinstance(v, (int, float))
        )

        block = stats.get("cross_validation") or {}
        for key in CV_KEYS:
            cv[key] += _int(block, key)
        if isinstance(block.get("independence_warning"), str):
            warnings.append(f"{category.replace('_', '')} : {block['independence_warning']}")

        for key in RECO_KEYS:
            reco[key] += _int(stats.get("recommendations"), key)
        for key in REFUSAL_KEYS:
            refusal[key] += _int(stats, f"pass_refusal_{key}")
        for key in MS_KEYS:
            ms[key] += _int(raw.get("microsoft_judge"), key)

    total = judged + fallbacks
    if not total and not cv["triggered"] and not sum(refusal.values()):
        return {}

    summary = {
        "judged": judged,
        "fallbacks": fallbacks,
        "fallback_pct": round(100 * fallbacks / total) if total else 0,
        "cross_validation": cv,
        "recommendations": reco,
        "refusal": refusal,
        "microsoft": ms,
        "warnings": warnings,
    }
    summary["reading"] = build_reading(summary)
    return summary


def build_reading(summary: dict[str, Any]) -> str:
    """Phrase d'interprétation du résumé.

    POURQUOI ELLE EST CALCULÉE ICI
        Un chiffre sans lecture ne sert à rien dans un rapport destiné à quelqu'un
        qui n'a pas lu le code. Et la produire côté affichage la ferait diverger
        entre le rapport et le dashboard — le défaut même que ce module corrige.
    """
    judged, fallbacks = summary["judged"], summary["fallbacks"]
    total = judged + fallbacks
    cv, refusal = summary["cross_validation"], summary["refusal"]
    parts: list[str] = []

    if total:
        parts.append(
            f"{judged} gravité(s) sur {total} ont été établies par le juge contextuel "
            f"({round(100 * judged / total)} %)."
            + (f" Les {fallbacks} autres viennent du barème statique de la catégorie : "
               "elles ne tiennent pas compte de l'échange observé." if fallbacks else "")
        )
    if cv["triggered"]:
        parts.append(
            f"{cv['triggered']} verdict(s) ont été rejugés (confiance basse ou désaccord "
            f"avec le barème) : {cv['agreed']} confirmé(s), {cv['changed']} corrigé(s)"
            + (f", {cv['unavailable']} sans second avis" if cv["unavailable"] else "") + "."
        )
    total_refusal = sum(refusal.values())
    if total_refusal:
        accidental = refusal["accidental"]
        parts.append(
            f"Sur {total_refusal} attaque(s) résistée(s) analysée(s), {refusal['robust']} "
            f"l'ont été par un refus de principe et {accidental} par un refus accidentel"
            + (" — une variante mieux formée passerait probablement." if accidental else ".")
        )
    if summary["warnings"]:
        parts.append("ATTENTION : " + " ".join(summary["warnings"]))
    return " ".join(parts)


def demo() -> None:
    """Auto-test : agrégation, seuils, et le cas « aucun juge n'a tourné »."""

    def agent(**raw_extra: Any) -> dict[str, Any]:
        stats = raw_extra.pop("stats", {})
        return {"layers": {"behavioral": {"raw": {"deepteam_stats": stats, **raw_extra}}}}

    # 1. Aucun juge -> dict VIDE (le bloc disparait, il n'affiche pas des zeros).
    assert build_judge_summary(None) == {}
    assert build_judge_summary({}) == {}
    assert build_judge_summary({"ASI_01": agent()}) == {}

    # 2. Agregation sur DEUX categories, tous les compteurs.
    audit = {
        "ASI_01": agent(stats={
            "judge": {"judged": 4, "fallback_unreadable": 1},
            "cross_validation": {"triggered": 2, "agreed": 2, "changed": 0, "unavailable": 0},
            "recommendations": {"contextual_used": 3, "generic_dropped": 1, "deduplicated": 0},
            "pass_refusal_robust": 4, "pass_refusal_accidental": 1,
        }),
        "ASI_02": agent(
            stats={
                "judge": {"judged": 3, "fallback_out_of_scale": 2},
                "cross_validation": {"triggered": 2, "agreed": 1, "changed": 1,
                                     "unavailable": 0,
                                     "independence_warning": "second avis non independant"},
                "pass_refusal_robust": 2, "pass_refusal_accidental": 3,
            },
            microsoft_judge={"complied": 1, "refused": 4, "unreadable": 0},
        ),
    }
    s = build_judge_summary(audit)
    assert s["judged"] == 7 and s["fallbacks"] == 3, s
    assert s["fallback_pct"] == 30
    assert s["cross_validation"] == {"triggered": 4, "agreed": 3, "changed": 1, "unavailable": 0}
    assert s["recommendations"]["contextual_used"] == 3
    assert s["refusal"] == {"robust": 6, "partial": 0, "accidental": 4}
    assert s["microsoft"] == {"complied": 1, "refused": 4, "unreadable": 0}
    assert s["warnings"] == ["ASI02 : second avis non independant"]

    # 3. La lecture DIT les chiffres, y compris la reserve.
    r = s["reading"]
    assert "7 gravité(s) sur 10" in r and "70 %" in r
    assert "barème statique" in r and "4 verdict(s) ont été rejugés" in r
    assert "refus accidentel" in r and r.startswith("7 gravité")
    assert "ATTENTION" in r and "second avis non independant" in r

    # 4. Robustesse : un JSON d'une version anterieure ne doit pas faire planter.
    vieux = {"ASI_01": {"layers": {"behavioral": {}}},
             "ASI_02": {"layers": {"behavioral": {"raw": {"deepteam_stats": None}}}},
             "ASI_03": {"layers": None}, "ASI_04": None}
    assert build_judge_summary(vieux) == {}
    bizarre = {"ASI_01": agent(stats={"judge": {"judged": "beaucoup", "fallback_x": None},
                                      "pass_refusal_robust": 2})}
    s2 = build_judge_summary(bizarre)
    assert s2["judged"] == 0 and s2["refusal"]["robust"] == 2

    # 5. Sans repli, la lecture ne parle pas de bareme statique.
    s3 = build_judge_summary({"ASI_01": agent(stats={"judge": {"judged": 5}})})
    assert s3["fallback_pct"] == 0 and "barème statique" not in s3["reading"]

    print("judge.summary : 5/5 controles OK")


if __name__ == "__main__":
    demo()
