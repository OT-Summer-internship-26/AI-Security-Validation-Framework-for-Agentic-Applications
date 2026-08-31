"""
recommendation_engine.py — Assemble la remédiation finale d'une vulnérabilité.

LE PROBLÈME QU'IL RÉSOUT
    Jusqu'ici, la remédiation d'un finding venait de deux sources STATIQUES :
    `recommendation_map` (une phrase par classe de vulnérabilité, écrite d'avance)
    puis les `prevention_guidelines` de la base OWASP (neuf puces par catégorie).
    Conséquence : deux findings de la MÊME classe recevaient le MÊME paragraphe —
    qu'un agent ait divulgué un mot de passe administrateur ou simplement changé
    de ton. Un lecteur ne pouvait pas savoir quoi corriger EN PREMIER, ni où.

    Ce module ajoute l'étage manquant : la remédiation CONTEXTUELLE, celle qui
    parle de l'échange réellement observé.

POURQUOI IL N'APPELLE AUCUN LLM LUI-MÊME
    Le plan d'origine (doc. technique : integration DeepTeam) prévoyait « générer des recommandations via un LLM » —
    donc un appel de plus par vulnérabilité. Inutile : le juge de gravité vient
    d'établir QUELLE garde a cédé et POURQUOI (`guardrail`), et quel serait
    l'impact. Il est au meilleur endroit pour dire quoi ajouter, et son appel est
    DÉJÀ payé. Le champ `remediation` a donc été ajouté à `SeverityVerdict` :
    coût marginal nul. Ce module n'invente rien, il ASSEMBLE — et c'est
    précisément pour ça qu'il est testable sans réseau.

LES TROIS ÉTAGES, DANS CET ORDRE
    1. **Correctif immédiat** — issu du verdict du juge. Ce qui aurait arrêté
       CETTE attaque. Peut manquer (juge indisponible, champ vide).
    2. **Contrôle à mettre en place** — `recommendation_map` de l'agent : la
       mesure curée pour cette classe de vulnérabilité.
    3. **Référence OWASP** — `prevention_guidelines` de la base de connaissances.

    Un étage absent est simplement sauté. Si les trois manquent, on renvoie la
    consigne générique — c'est-à-dire EXACTEMENT le comportement d'avant. Ce
    module ne peut donc jamais dégrader une remédiation existante.

CE QU'IL REFUSE DE FAIRE
    · Répéter deux fois la même chose : un correctif contextuel qui redit le
      contrôle curé fait doublon, on garde le plus précis (voir `_redundant`).
    · Laisser passer un conseil creux : « valider les entrées », « appliquer le
      moindre privilège » sont déjà dans le catalogue de référence. Émis comme
      correctif IMMÉDIAT, ils donnent l'illusion d'une analyse contextuelle. Ils
      sont donc filtrés (`_GENERIC_MARKERS`) plutôt qu'affichés en tête.
"""

from __future__ import annotations

import re
from typing import Any

# Consigne de repli, identique à celle qui existait dans `base_agent` : ce module
# ne doit jamais rendre une remédiation PLUS PAUVRE que celle d'avant.
DEFAULT_RECOMMENDATION = (
    "Appliquer le principe de moindre privilège, valider et assainir toute entrée "
    "non fiable, journaliser et surveiller le comportement de l'agent, et exiger "
    "une validation humaine pour les actions à fort impact."
)

# Formules creuses : vraies mais sans valeur en tête de remédiation, puisqu'elles
# figurent déjà dans le catalogue de référence affiché juste en dessous.
_GENERIC_MARKERS = (
    "validate input", "validate all input", "sanitize input", "sanitise input",
    "least privilege", "moindre privilège", "moindre privilege",
    "valider les entrées", "valider les entrees", "input validation",
    "follow best practices", "bonnes pratiques", "defense in depth",
)

_LABELS = {
    "contextual": "Correctif immédiat",
    "curated": "Contrôle à mettre en place",
    "guidelines": "Référence OWASP",
}


def _clean(text: str) -> str:
    """Normalise un fragment de recommandation (espaces, ponctuation finale)."""
    t = re.sub(r"\s+", " ", (text or "").strip())
    return t


# Longueur du radical retenu pour comparer deux formulations. 4 caractères font
# coïncider « signature »/« signer » et « validation »/« valider » — les variantes
# morphologiques du MÊME contrôle, que le juge et le catalogue écrivent rarement
# de la même façon. Au-delà, elles cessent de se rejoindre ; en deçà, des mots
# sans rapport commencent à se confondre.
_STEM = 4


def _words(text: str) -> set[str]:
    """Radicaux significatifs d'un texte, pour mesurer un recouvrement de sens."""
    return {w[:_STEM] for w in re.findall(r"[a-zà-ÿ]{4,}", (text or "").lower())}


def _is_generic(text: str) -> bool:
    """Le texte n'est-il qu'un conseil passe-partout ?

    Un correctif « immédiat » qui dit « valider les entrées » n'apprend rien : il
    occupe la place de l'information utile et laisse croire à une analyse
    contextuelle. Mieux vaut ne rien afficher à cet étage.
    """
    low = (text or "").lower()
    if len(low) < 25:
        return True
    return any(m in low for m in _GENERIC_MARKERS)


def _redundant(a: str, b: str, threshold: float = 0.6) -> bool:
    """`a` redit-il `b` ? (recouvrement de vocabulaire, insensible à la forme)

    POURQUOI PAS UNE ÉGALITÉ DE CHAÎNES
        Le juge reformule : « exiger une signature sur les messages inter-agents »
        et « signer les messages de pair » sont le même contrôle écrit deux fois.
        Une comparaison stricte ne les rapprocherait pas et le rapport afficherait
        un doublon. On compare les vocabulaires.
    """
    wa, wb = _words(a), _words(b)
    if not wa or not wb:
        return False
    return len(wa & wb) / min(len(wa), len(wb)) >= threshold


class RecommendationEngine:
    """Assemble une remédiation à partir des étages disponibles.

    Sans état et sans réseau : la même entrée produit toujours la même sortie,
    ce qui rend un rapport d'audit reproductible et contestable.
    """

    def __init__(self, max_guidelines: int | None = None) -> None:
        """max_guidelines : nombre de puces de référence conservées (None = toutes).

        Le défaut garde TOUT : tronquer par défaut ferait perdre silencieusement
        des mesures que la base de connaissances fournit.
        """
        self.max_guidelines = max_guidelines
        self.stats = {"contextual_used": 0, "generic_dropped": 0, "deduplicated": 0}

    def build(
        self,
        *,
        contextual: str = "",
        curated: str = "",
        guidelines: Any = "",
    ) -> str:
        """Retourne la remédiation finale, du plus précis au plus général.

        contextual : `remediation` du verdict du juge (ce qui aurait arrêté CETTE attaque).
        curated    : mesure écrite d'avance pour cette classe (`recommendation_map`).
        guidelines : `prevention_guidelines` de la KB — chaîne ou liste de puces.

        Ne lève jamais. Aucun étage disponible → `DEFAULT_RECOMMENDATION`.
        """
        contextual, curated = _clean(contextual), _clean(curated)

        if contextual and _is_generic(contextual):
            self.stats["generic_dropped"] += 1
            contextual = ""

        # Le curé ne doit pas répéter le contextuel : on garde le plus précis, donc
        # le contextuel (il cite l'échange observé).
        if contextual and curated and _redundant(curated, contextual):
            self.stats["deduplicated"] += 1
            curated = ""

        if contextual:
            self.stats["contextual_used"] += 1

        blocks: list[str] = []
        if contextual:
            blocks.append(f"{_LABELS['contextual']} — {contextual}")
        if curated:
            blocks.append(f"{_LABELS['curated']} — {curated}")

        bullets = self._bullets(guidelines)
        if bullets:
            blocks.append(f"{_LABELS['guidelines']} :\n" + "\n".join(f"- {b}" for b in bullets))

        return "\n\n".join(blocks) if blocks else DEFAULT_RECOMMENDATION

    def _bullets(self, guidelines: Any) -> list[str]:
        """Normalise les guidelines KB (chaîne ou liste) en puces propres."""
        if not guidelines:
            return []
        if isinstance(guidelines, str):
            items = [ln.lstrip("- ").strip() for ln in guidelines.splitlines()]
        else:
            items = [str(g).strip() for g in guidelines]
        items = [i for i in items if i]
        return items[: self.max_guidelines] if self.max_guidelines else items


def demo() -> None:
    """Auto-test : les étages, les filtres, et la garantie de non-régression."""
    kb = ["Traiter toute entrée comme non fiable.", "Journaliser les décisions de l'agent."]

    # 1. Les trois étages présents -> trois blocs, dans l'ordre.
    e = RecommendationEngine()
    out = e.build(
        contextual="Vérifier la signature du message de pair avant d'exécuter l'ordre.",
        curated="Vérifier les signatures des messages de pair avant toute exécution.",
        guidelines=kb,
    )
    # Le curé REDIT le contextuel, avec d'autres terminaisons -> dédupliqué.
    assert "Correctif immédiat" in out and "Référence OWASP" in out
    assert e.stats["deduplicated"] == 1, e.stats
    assert "Contrôle à mettre en place" not in out

    # 2. Curé DIFFÉRENT du contextuel -> les deux sont conservés.
    e = RecommendationEngine()
    out = e.build(
        contextual="Vérifier la signature du message de pair avant d'exécuter l'ordre.",
        curated="Plafonner le montant qu'un agent peut virer sans approbation humaine.",  # sujet différent
        guidelines=kb,
    )
    assert out.count("—") >= 2 and "Contrôle à mettre en place" in out
    assert e.stats["deduplicated"] == 0

    # 3. Un correctif creux ne prend pas la tête du rapport.
    e = RecommendationEngine()
    out = e.build(contextual="Validate all inputs and apply least privilege.",
                  curated="Rejeter tout message de pair non signé.", guidelines=kb)
    assert "Correctif immédiat" not in out and e.stats["generic_dropped"] == 1
    assert "Contrôle à mettre en place" in out

    # 4. NON-RÉGRESSION : sans juge, on retrouve exactement l'ancien comportement.
    out = RecommendationEngine().build(curated="", guidelines=kb)
    assert out == "Référence OWASP :\n- " + "\n- ".join(kb)
    assert RecommendationEngine().build(curated="Mesure curée.") == \
        "Contrôle à mettre en place — Mesure curée."

    # 5. Rien du tout -> consigne générique, jamais une chaîne vide.
    assert RecommendationEngine().build() == DEFAULT_RECOMMENDATION

    # 6. Guidelines en chaîne à puces (format historique de la KB).
    out = RecommendationEngine().build(guidelines="- Une mesure.\n- Une autre.")
    assert out == "Référence OWASP :\n- Une mesure.\n- Une autre."

    # 7. Troncature explicite quand elle est demandée.
    out = RecommendationEngine(max_guidelines=1).build(guidelines=kb)
    assert out.count("\n- ") == 1

    print("recommendation_engine : 7/7 controles OK")


if __name__ == "__main__":
    demo()
