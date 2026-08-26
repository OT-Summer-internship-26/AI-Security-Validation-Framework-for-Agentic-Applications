"""
serialization.py — Traduit un `AgentResult` en l'entrée JSON d'un fichier d'audit.

POURQUOI CE FICHIER
    Cette conversion vivait à l'intérieur de `scripts/run_agent.py`, sous forme de
    fonctions locales. Tant qu'un seul chemin d'exécution produisait des audits,
    ça suffisait. Dès qu'un second apparaît — l'orchestration LangGraph, qui
    travaille en mémoire au lieu de lancer des sous-processus — la recopier
    créerait DEUX formats qui divergeraient au premier champ ajouté : le rapport
    et le dashboard afficheraient alors des choses différentes selon le runner
    utilisé, sans que rien ne le signale.

    Un seul endroit produit le format. Les deux orchestrations l'appellent.

CE QUE LE FORMAT DOIT PRÉSERVER
    Tout le `raw` de chaque couche. Une version antérieure ne gardait que les
    scores : un axe exclu (PyRIT ou Microsoft → `None`) apparaissait alors sans
    aucune explication, et il devenait impossible de distinguer « non applicable »
    de « a échoué ». Or c'est exactement la distinction sur laquelle repose la
    règle anti-faux-10/10 du framework.
"""

from __future__ import annotations

from typing import Any


def serialize_layer(layer: Any) -> dict[str, Any]:
    """Sérialise une couche en CONSERVANT tout son `raw`.

    `garak_raw` est le seul champ écarté : c'est le rapport brut de Garak, qui
    pèse plusieurs mégaoctets et dont le contenu utile est déjà résumé.
    """
    raw = layer.raw or {}
    stats = raw.get("deepteam_stats") or {}
    return {
        "score": layer.score,
        "applicable": layer.applicable,
        "error": layer.error,
        "components": raw.get("score_components"),
        "stats": raw.get("deepteam_stats"),
        "axis_status": {
            "deepteam": raw.get("deepteam_status")
            or (f"{stats.get('scored', 0)} test(s) scorés" if stats else None),
            "pyrit": raw.get("pyrit_status"),
            "garak": raw.get("garak_status"),
            "microsoft": raw.get("microsoft_status"),
        },
        "note": raw.get("behavioral_note"),
        "raw": {k: v for k, v in raw.items() if k != "garak_raw"},
    }


def serialize_vulnerability(v: Any) -> dict[str, Any]:
    """Sérialise une vulnérabilité, analyse du juge comprise.

    `confidence` et `judge_detail` sont ce qui permet au rapport de dire d'où
    vient une gravité — du juge contextuel ou du barème statique. Les omettre
    ferait lire un verdict de modèle comme un fait établi.
    """
    return {
        "title": v.title,
        "severity": v.severity,
        "layer": v.layer,
        "evidence": getattr(v, "evidence", ""),
        "recommendation": getattr(v, "recommendation", ""),
        "confidence": getattr(v, "confidence", None),
        "judge_detail": getattr(v, "judge_detail", {}) or {},
        "aivss_core_risk": getattr(v, "aivss_core_risk", ""),
        "references": getattr(v, "references", []) or [],
    }


def collect_attacks(result: Any, transcript: list[dict[str, Any]] | None = None) -> list[dict]:
    """Rassemble le journal d'attaques des trois couches.

    POURQUOI LE TRANSCRIPT N'EST QU'UN REPLI
        Le journal des couches contient des attaques AVEC VERDICT. Le transcript
        brut est une trace réseau : y voir des « tests » affichait « 0 % d'attaques
        réussies » juste à côté de vulnérabilités Critical. On ne l'utilise donc
        que si le journal est vide, et chaque entrée est marquée `excluded`.
    """
    attacks: list[dict] = []
    for layer in (result.layers or {}).values():
        attacks += list((getattr(layer, "raw", None) or {}).get("attack_log") or [])
    if attacks or not transcript:
        return attacks
    return [{
        "technique": "Échange capturé", "layer": "behavioral", "axis": "DeepTeam",
        "vulnerability": "", "prompt": e["prompt"], "response": e["response"],
        "verdict": "excluded", "severity": None,
        "judge_reason": f"échange #{e['n']} · {e['elapsed_s']}s · non évalué"
        + (" · [HTTP_ERROR]" if e.get("http_error") else ""),
    } for e in transcript]


def build_agent_entry(category: str, result: Any, duration_s: float = 0.0,
                      attacks: list[dict] | None = None) -> dict[str, Any]:
    """Construit l'entrée `audit["agents"][category]` — le format unique.

    `attacks` : journal déjà collecté (le runner en sous-processus dispose aussi du
    transcript) ; sinon on le rassemble depuis les couches.
    """
    layers = result.layers or {}
    return {
        "name": getattr(result, "name", category),
        "status": result.status,
        "score": result.score,
        # `False` => le score 0 n'est pas un verdict : la categorie est exclue du
        # score global et le rapport doit le dire au lieu de l'afficher comme un echec.
        "measured": getattr(result, "measured", True),
        "duration_seconds": int(duration_s),
        "cost_tokens": 0,
        "layers": {
            name: serialize_layer(layers[name])
            for name in ("behavioral", "static", "dynamic") if name in layers
        },
        "attacks": attacks if attacks is not None else collect_attacks(result),
        "vulnerabilities": [serialize_vulnerability(v) for v in result.vulnerabilities],
    }


def demo() -> None:
    """Auto-test : format complet, `raw` préservé, repli sur le transcript."""
    from types import SimpleNamespace as NS

    layer = NS(score=8.0, applicable=True, error=None, raw={
        "score_components": {"deepteam": 8.0, "pyrit": None},
        "deepteam_stats": {"scored": 3},
        "pyrit_status": "exclu", "garak_raw": "x" * 10_000,
        "attack_log": [{"technique": "T", "verdict": "compromised"}],
    })
    vuln = NS(title="V", severity="High", layer="behavioral", evidence="e",
              recommendation="r", confidence=45, judge_detail={"impact": "i"},
              aivss_core_risk="a", references=["ref"])
    result = NS(name="Agent", status="completed", score=8.0,
                layers={"behavioral": layer}, vulnerabilities=[vuln])

    entry = build_agent_entry("ASI_01", result, duration_s=12.7)
    assert entry["score"] == 8.0 and entry["duration_seconds"] == 12
    beh = entry["layers"]["behavioral"]
    # Le `raw` est conserve, SAUF le rapport brut de Garak (plusieurs Mo).
    assert beh["raw"]["score_components"] == {"deepteam": 8.0, "pyrit": None}
    assert "garak_raw" not in beh["raw"]
    # Un axe exclu doit rester EXPLICABLE dans le fichier d'audit.
    assert beh["axis_status"]["pyrit"] == "exclu"
    assert beh["axis_status"]["deepteam"] == "3 test(s) scorés"
    # L'analyse du juge suit la vulnerabilite jusqu'au JSON.
    v = entry["vulnerabilities"][0]
    assert v["confidence"] == 45 and v["judge_detail"] == {"impact": "i"}
    # Le journal d'attaques vient des couches.
    assert entry["attacks"] == [{"technique": "T", "verdict": "compromised"}]

    # Sans journal, repli sur le transcript — et chaque entree est marquee EXCLUE,
    # pour ne pas faire passer une trace reseau pour un test note.
    vide = NS(name="A", status="completed", score=0.0,
              layers={"behavioral": NS(score=0, applicable=True, error=None, raw={})},
              vulnerabilities=[])
    attacks = collect_attacks(vide, [{"n": 1, "elapsed_s": 2.0, "prompt": "p",
                                      "response": "r", "http_error": True}])
    assert len(attacks) == 1 and attacks[0]["verdict"] == "excluded"
    assert "[HTTP_ERROR]" in attacks[0]["judge_reason"]

    print("workflow.serialization : 4/4 controles OK")


if __name__ == "__main__":
    demo()
