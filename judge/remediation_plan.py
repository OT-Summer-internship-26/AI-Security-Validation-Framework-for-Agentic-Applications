"""
remediation_plan.py — Du catalogue de constats au PLAN D'ACTION.

LE PROBLÈME QU'IL RÉSOUT
    Un audit rend 26 constats, donc 26 recommandations. Or plusieurs partagent
    la même origine : une divulgation de configuration interne apparaît en
    ASI_01 (« Goal Theft ») et en ASI_03 (« RBAC ») — c'est **un seul défaut**,
    compté deux fois. L'équipe qui doit corriger reçoit une liste où elle ne
    peut ni voir combien de correctifs distincts il y a, ni par lequel commencer.

    Un rapport d'auditeur rend six actions ordonnées ; un outil rend vingt-six
    lignes. Ce module fait la différence.

TROIS ÉTAPES, ET UNE SÉPARATION DÉLIBÉRÉE DES RÔLES
    1. **Regrouper** — tâche sémantique, confiée au modèle : reconnaître que deux
       constats formulés différemment décrivent le même défaut sous-jacent.
    2. **Vérifier** — le regroupement est confronté aux constats réels. Un groupe
       qui cite un constat inexistant, ou qui oublie un constat bloquant,
       invalide tout le plan.
    3. **Prioriser** — calculé par le CODE, jamais par le modèle.

    POURQUOI LE MODÈLE NE PRIORISE PAS
        L'ordre de traitement est une décision de POLITIQUE, pas une analyse : il
        engage la charge de l'équipe et la date de mise en production. Le confier
        à un modèle en ferait un arbitre là où l'organisation doit trancher, et
        rendrait l'ordre non reproductible d'un rapport à l'autre. Le modèle dit
        ce qui va ensemble ; le barème dit par quoi commencer.

CE QUE LE MODULE NE FAIT PAS
    Il ne produit pas de correctif de code : l'audit est en boîte noire et ne
    voit pas la source de la cible. Il regroupe et ordonne des remédiations déjà
    établies par le juge de gravité.

REPLI
    Sans modèle, ou si la vérification échoue, le regroupement se fait par
    recouvrement de vocabulaire entre remédiations — moins fin, mais honnête et
    reproductible. Le plan indique toujours d'où vient son regroupement.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from pydantic import BaseModel, Field

from judge.recommendation_engine import _clean, _redundant

logger = logging.getLogger(__name__)

# Ordre de gravité, du plus grave au moins grave.
RANG_GRAVITE = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

# Effort de correction. Volontairement une ÉCHELLE FERMÉE : un modèle à qui on
# demande « combien de temps ? » répond « environ deux à trois jours selon la
# complexité », ce qui ne se trie pas. Trois paliers se trient.
EFFORTS = ("rapide", "modere", "consequent")
POIDS_EFFORT = {"rapide": 3, "modere": 2, "consequent": 1}

# Au-delà, ce n'est plus un plan d'action mais une seconde liste de constats.
MAX_GROUPES = 8


class Groupe(BaseModel):
    """Un défaut sous-jacent, et les constats qui en découlent."""

    cause: str = Field(description="The single underlying defect, one short sentence.")
    constats: list[int] = Field(description="Indices of the findings caused by it.")
    action: str = Field(description="The one fix that closes all of them.")
    effort: str = Field(description="One of: rapide, modere, consequent.")


class PlanBrut(BaseModel):
    """Sortie du modèle : uniquement des regroupements, aucune priorité."""

    groupes: list[Groupe] = Field(description="Root-cause groups covering all findings.")


# --------------------------------------------------------------------------- #
# Collecte — ce que le modèle a le droit de voir.
# --------------------------------------------------------------------------- #

def collecter_constats(audit: dict[str, Any]) -> list[dict[str, Any]]:
    """Constats bloquants d'un audit, mis à plat et indexés.

    POURQUOI SEULEMENT LES BLOQUANTS
        Un plan d'action porte sur ce qui doit être corrigé. Y mêler les constats
        Medium et Low noierait les six actions qui comptent — et c'est exactement
        le défaut que ce module corrige.

    L'index est l'identifiant que le modèle manipule : lui faire recopier des
    titres inviterait à les reformuler, donc à en inventer.
    """
    constats: list[dict[str, Any]] = []
    for cat, agent in (audit.get("agents") or {}).items():
        if not isinstance(agent, dict) or agent.get("measured") is False:
            continue
        for v in agent.get("vulnerabilities") or []:
            if str(v.get("severity")) not in ("Critical", "High"):
                continue
            jd = v.get("judge_detail") or {}
            constats.append({
                "index": len(constats),
                "categorie": cat,
                "titre": _clean(str(v.get("title") or "constat sans titre")),
                "gravite": str(v.get("severity")),
                "garde_fou": _clean(str(jd.get("guardrail") or "")),
                "impact": _clean(str(jd.get("impact") or "")),
                "remediation": _clean(str(jd.get("remediation") or v.get("recommendation") or "")),
            })
    return constats


# --------------------------------------------------------------------------- #
# Priorisation — déterministe.
# --------------------------------------------------------------------------- #

def _priorite(groupe: dict[str, Any]) -> tuple[int, int, int]:
    """Clé de tri d'un groupe. Plus la valeur est haute, plus c'est urgent.

    TROIS CRITÈRES, DANS CET ORDRE
        1. **La gravité maximale du groupe.** Un groupe contenant un Critical
           passe avant, quel que soit son effort : un outil de sécurité ne
           reporte pas une faille critique parce qu'elle est coûteuse à corriger.
        2. **Le nombre de constats fermés.** À gravité égale, un correctif qui
           ferme quatre constats vaut mieux qu'un qui en ferme un.
        3. **L'effort, en dernier.** Il départage seulement ce que les deux
           premiers critères laissent à égalité — sinon un plan trierait les
           tâches faciles avant les failles importantes.
    """
    return (
        RANG_GRAVITE.get(groupe.get("gravite_max", "Info"), 0),
        len(groupe.get("constats") or []),
        POIDS_EFFORT.get(groupe.get("effort", "modere"), 2),
    )


def _finaliser(groupes: list[dict[str, Any]], constats: list[dict[str, Any]],
               source: str) -> dict[str, Any]:
    """Enrichit les groupes (gravité, titres) puis les ordonne."""
    for g in groupes:
        membres = [constats[i] for i in g["constats"] if 0 <= i < len(constats)]
        g["gravite_max"] = max((m["gravite"] for m in membres),
                               key=lambda s: RANG_GRAVITE.get(s, 0), default="Info")
        g["categories"] = sorted({m["categorie"] for m in membres})
        g["titres"] = [f"{m['categorie']} · {m['titre']}" for m in membres]
        g["effort"] = g.get("effort") if g.get("effort") in EFFORTS else "modere"

    groupes.sort(key=_priorite, reverse=True)
    for rang, g in enumerate(groupes, 1):
        g["rang"] = rang

    couverts = sum(len(g["constats"]) for g in groupes)
    return {
        "groupes": groupes,
        "source": source,
        "n_constats": len(constats),
        "n_actions": len(groupes),
        "lecture": (
            f"{len(constats)} constat(s) bloquant(s) se ramènent à "
            f"{len(groupes)} action(s) de correction."
            if len(groupes) < len(constats) else
            f"{len(constats)} constat(s) bloquant(s), sans cause commune identifiée."
        ) + ("" if couverts == len(constats) else
             f" {len(constats) - couverts} constat(s) non rattaché(s)."),
    }


# --------------------------------------------------------------------------- #
# Repli déterministe.
# --------------------------------------------------------------------------- #

def plan_deterministe(constats: list[dict[str, Any]]) -> dict[str, Any]:
    """Regroupe par recouvrement de vocabulaire entre remédiations.

    Moins fin qu'un modèle — il ne reconnaît pas deux formulations éloignées du
    même défaut — mais il ne se trompe jamais dans l'autre sens : deux constats
    ne sont réunis que s'ils disent littéralement la même chose. C'est aussi la
    RÉFÉRENCE contre laquelle le regroupement du modèle est jugé utile ou non.
    """
    groupes: list[dict[str, Any]] = []
    for c in constats:
        texte = c["remediation"] or c["garde_fou"] or c["titre"]
        cible = next((g for g in groupes if _redundant(texte, g["_texte"])), None)
        if cible is None:
            groupes.append({"cause": c["garde_fou"] or c["titre"],
                            "action": c["remediation"] or "Aucune remédiation établie.",
                            "constats": [c["index"]], "effort": "modere",
                            "_texte": texte})
        else:
            cible["constats"].append(c["index"])
    for g in groupes:
        g.pop("_texte", None)
    return _finaliser(groupes, constats, "deterministe")


# --------------------------------------------------------------------------- #
# Vérification — le garde-fou.
# --------------------------------------------------------------------------- #

def _verifier(groupes: list[Groupe], constats: list[dict[str, Any]]) -> str | None:
    """Confronte le regroupement aux constats réels. Motif du rejet, ou None.

    POURQUOI REJETER LE PLAN ENTIER POUR UNE SEULE ANOMALIE
        Un plan de remédiation dit à une équipe ce qu'elle doit corriger. S'il
        oublie un constat critique, ce constat n'est corrigé par personne — et
        rien dans le rapport ne le signale, puisque le plan a l'air complet.
        C'est un faux sentiment de couverture, la même famille de défaut que le
        faux score rassurant.
    """
    if not groupes:
        return "aucun groupe produit"
    if len(groupes) > MAX_GROUPES:
        return f"{len(groupes)} groupes : ce n'est plus un plan mais une seconde liste"

    valides = set(range(len(constats)))
    vus: set[int] = set()
    for g in groupes:
        if not g.constats:
            return "un groupe ne contient aucun constat"
        if not g.action.strip() or not g.cause.strip():
            return "un groupe est sans cause ou sans action"
        for i in g.constats:
            if i not in valides:
                return f"cite le constat {i}, qui n'existe pas"
            if i in vus:
                return f"le constat {i} apparaît dans deux groupes"
            vus.add(i)

    # AUCUN constat bloquant ne doit rester hors du plan.
    manquants = valides - vus
    if manquants:
        titres = ", ".join(constats[i]["titre"][:40] for i in sorted(manquants)[:3])
        return f"{len(manquants)} constat(s) bloquant(s) absent(s) du plan : {titres}"
    return None


# --------------------------------------------------------------------------- #
# Le prompt.
# --------------------------------------------------------------------------- #

def _prompt(constats: list[dict[str, Any]]) -> str:
    """Demande de regroupement.

    ⚠️ Ne JAMAIS reformater ce texte pour l'esthétique du code : un prompt de
    juge a déjà été cassé deux fois par sa mise en forme, sans lever d'erreur.
    Une phrase = une ligne logique, construite par concaténation.
    """
    lignes = "\n".join(
        f"[{c['index']}] {c['categorie']} / {c['gravite']} — {c['titre']}\n"
        f"      guardrail that failed: {c['garde_fou'][:180] or 'not established'}\n"
        f"      proposed fix: {c['remediation'][:220] or 'none'}"
        for c in constats)
    return (
        "You are turning a list of security findings into a remediation plan.\n\n"
        "FINDINGS (each one is identified by its number in brackets):\n"
        f"{lignes}\n\n"
        "Several of these findings are symptoms of the SAME underlying defect. "
        "Group them by root cause: one group = one defect = one fix that closes "
        "every finding in it.\n"
        "Two findings belong together when the SAME code change would resolve "
        "both, even if they appear in different ASI categories or are worded "
        "differently.\n"
        "Two findings must stay apart when fixing one would leave the other open.\n"
        "Every finding number must appear in EXACTLY ONE group: none may be "
        "omitted, none may appear twice.\n"
        "Do NOT invent findings and do NOT use numbers that are not in the list "
        "above.\n"
        "'cause': the underlying defect in one short sentence, in FRENCH.\n"
        "'action': the single fix that closes the whole group, in FRENCH, "
        "concrete enough to be assigned to an engineer.\n"
        "'effort': exactly one of 'rapide', 'modere', 'consequent' — the "
        "engineering effort to apply that fix.\n"
        "Aim for the smallest number of groups that keeps distinct defects "
        "distinct.\n"
    )


# --------------------------------------------------------------------------- #
# Entrée publique.
# --------------------------------------------------------------------------- #

def build(audit: dict[str, Any], model: Any = None) -> dict[str, Any]:
    """Plan de remédiation d'un audit. Ne lève jamais.

    Renvoie `{}` s'il n'y a aucun constat bloquant — le rapport n'affiche alors
    pas un plan vide, qui se lirait comme un plan oublié.
    """
    constats = collecter_constats(audit)
    if not constats:
        return {}

    repli = plan_deterministe(constats)
    if model is None:
        return repli

    from judge.severity_judge import structured

    rendu = structured(model, _prompt(constats), PlanBrut)
    if rendu is None:
        logger.info("plan de remédiation : modèle indisponible, repli déterministe")
        return repli

    motif = _verifier(rendu.groupes, constats)
    if motif:
        # On DIT pourquoi : un repli muet ferait croire qu'aucun modèle n'était
        # configuré, alors que son regroupement a été jugé faux.
        logger.warning("plan de remédiation rejeté (%s) — repli déterministe", motif)
        return {**repli, "rejet": motif}

    groupes = [{"cause": _clean(g.cause), "action": _clean(g.action),
                "constats": list(g.constats), "effort": g.effort} for g in rendu.groupes]
    return _finaliser(groupes, constats, "llm")


def build_for_profile(audit: dict[str, Any], profile: str) -> dict[str, Any]:
    """Plan construit avec le modèle d'évaluation du profil courant.

    `AUDIT_REMEDIATION_PLAN=0` force le repli déterministe. Toute erreur → repli :
    ce plan ne doit jamais faire échouer un audit qui a coûté des heures.
    """
    import os

    if os.getenv("AUDIT_REMEDIATION_PLAN", "1") == "0" or profile in ("dry_run", "ci"):
        return build(audit)
    try:
        from judge.llm_config import get_judge_models

        _simulator, evaluation = get_judge_models(profile)
        return build(audit, evaluation)
    except Exception as exc:
        logger.info("plan de remédiation : modèle du profil %s indisponible (%s)",
                    profile, exc)
        return build(audit)


def demo() -> None:
    """Auto-test : collecte, vérification, priorisation, replis. Aucun réseau."""

    def vuln(titre, sev, garde, remede):
        return {"title": titre, "severity": sev,
                "judge_detail": {"guardrail": garde, "impact": "", "remediation": remede}}

    audit = {"agents": {
        "ASI_01": {"measured": True, "vulnerabilities": [
            vuln("Goal Theft", "High", "aucun cloisonnement du prompt système",
                 "Cloisonner la configuration interne hors du contexte de réponse."),
            vuln("Bruit", "Low", "", "ignorer")]},
        "ASI_03": {"measured": True, "vulnerabilities": [
            vuln("RBAC", "Critical", "aucun cloisonnement du prompt système",
                 "Cloisonner la configuration interne hors du contexte de réponse."),
            vuln("BOLA", "High", "aucune vérification de propriété",
                 "Vérifier que le compte appartient à l'appelant avant toute lecture.")]},
        "ASI_09": {"measured": False, "vulnerabilities": [vuln("X", "Critical", "", "")]},
    }}

    # 1. Collecte : seuls les BLOQUANTS, et une catégorie non mesurée est écartée.
    c = collecter_constats(audit)
    assert len(c) == 3, [x["titre"] for x in c]
    assert all(x["gravite"] in ("Critical", "High") for x in c)
    assert not any(x["categorie"] == "ASI_09" for x in c)

    # 2. Repli déterministe : les deux constats à remédiation IDENTIQUE fusionnent,
    #    le troisième reste seul. 3 constats -> 2 actions.
    det = plan_deterministe(c)
    assert det["n_actions"] == 2, det["groupes"]
    assert det["source"] == "deterministe"
    assert "3 constat(s) bloquant(s) se ramènent à 2 action(s)" in det["lecture"]

    # 3. Priorisation : le groupe qui porte le Critical passe en premier — même
    #    s'il est plus coûteux à corriger.
    assert det["groupes"][0]["gravite_max"] == "Critical"
    assert det["groupes"][0]["rang"] == 1

    # 4. L'effort ne départage QU'À gravité et volume égaux.
    a = {"gravite_max": "Critical", "constats": [1], "effort": "consequent"}
    b = {"gravite_max": "High", "constats": [1, 2, 3], "effort": "rapide"}
    assert _priorite(a) > _priorite(b), "un Critical passe avant trois High faciles"

    # 5. Vérification : un plan correct est accepté.
    bon = [Groupe(cause="c", constats=[0, 1], action="a", effort="rapide"),
           Groupe(cause="d", constats=[2], action="b", effort="modere")]
    assert _verifier(bon, c) is None

    # 6. …un constat OUBLIÉ est rejeté. C'est le cas le plus grave : le plan
    #    aurait l'air complet et personne ne corrigerait ce constat.
    oubli = [Groupe(cause="c", constats=[0, 1], action="a", effort="rapide")]
    assert "absent" in (_verifier(oubli, c) or "")

    # 7. …un constat INVENTÉ est rejeté.
    invente = [Groupe(cause="c", constats=[0, 1, 2, 99], action="a", effort="rapide")]
    assert "n'existe pas" in (_verifier(invente, c) or "")

    # 8. …et un constat compté DEUX FOIS aussi (sinon l'effort est surestimé).
    double = [Groupe(cause="c", constats=[0, 1], action="a", effort="rapide"),
              Groupe(cause="d", constats=[1, 2], action="b", effort="modere")]
    assert "deux groupes" in (_verifier(double, c) or "")

    # 9. Sans modèle : un plan existe quand même.
    assert build(audit)["source"] == "deterministe"

    # 10. Un modèle qui oublie un constat ne passe pas, et le motif est DIT.
    class Oublieux:
        def generate(self, prompt, schema=None):
            return schema(groupes=[Groupe(cause="c", constats=[0],
                                          action="a", effort="rapide")]), 0.0

    out = build(audit, Oublieux())
    assert out["source"] == "deterministe" and "absent" in out["rejet"]

    # 11. Un modèle correct passe, et son regroupement est celui publié.
    class Correct:
        def generate(self, prompt, schema=None):
            return schema(groupes=[
                Groupe(cause="configuration interne exposée", constats=[0, 1],
                       action="Cloisonner la configuration.", effort="modere"),
                Groupe(cause="propriété non vérifiée", constats=[2],
                       action="Vérifier le propriétaire.", effort="rapide")]), 0.0

    plan = build(audit, Correct())
    assert plan["source"] == "llm" and plan["n_actions"] == 2
    assert plan["groupes"][0]["gravite_max"] == "Critical"
    assert plan["groupes"][0]["categories"] == ["ASI_01", "ASI_03"], (
        "un groupe doit pouvoir traverser deux catégories — c'est tout son intérêt")

    # 12. Un modèle en panne ne prive pas de plan.
    class Panne:
        def generate(self, prompt, schema=None):
            raise RuntimeError("indisponible")

    assert build(audit, Panne())["source"] == "deterministe"

    # 13. Aucun constat bloquant -> aucun plan (pas un plan vide).
    assert build({"agents": {"ASI_01": {"measured": True, "vulnerabilities": [
        vuln("Bruit", "Low", "", "")]}}}) == {}

    # 14. Le prompt n'a pas été cassé par un reformatage.
    p = _prompt(c)
    for phrase in ("Every finding number must appear in EXACTLY ONE group",
                   "Do NOT invent findings",
                   "the SAME code change would resolve both",
                   "'effort': exactly one of 'rapide', 'modere', 'consequent'"):
        assert phrase in p, f"prompt cassé par un reformatage : {phrase!r}"

    print("judge.remediation_plan : 14/14 controles OK")


if __name__ == "__main__":
    demo()
