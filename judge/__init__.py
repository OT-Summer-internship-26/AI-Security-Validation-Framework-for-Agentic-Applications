"""
Package `judge` — les quatre juges LLM du framework, et leurs runners d'attaque.

DeepTeam évalue déjà pass/fail via son `evaluation_model`. Ce package ajoute ce
qu'il ne fait pas : dire À QUEL POINT c'est grave, vérifier ce jugement, dire QUOI
CORRIGER, et trancher si une cible a cédé.

LES QUATRE JUGES
    severity_judge.py       gravité contextuelle + explication en 7 champs
    cross_validation.py     réconciliation à 3 voix des verdicts douteux
    recommendation_engine.py  assemblage de la remédiation (contextuel > curé > KB)
    compliance_judge.py     l'agent a-t-il cédé, oui ou non (axe Microsoft)

    Ils partagent `structured()` (repli quand le modèle répond en texte libre) et
    `excerpt()` (extrait tête + queue) de `severity_judge`. Cette mise en commun
    n'est pas cosmétique : le seul juge qui vivait à l'écart, dans `base_agent`,
    est celui où un prompt en français a produit un faux 10/10 pendant des
    semaines (doc. technique : fiabilite des juges LLM).

RUNNERS (pilotent des outils, ne jugent pas)
    llm_config.py    profils de modèles (dev / ollama / final / dry_run)
    pyrit_runner.py  attaques multi-tours PyRIT
    garak_runner.py  sondes Garak en sous-processus isolé
    replay.py        rejeu à l'identique des attaques d'un audit passé

AUTO-TESTS — aucun réseau, une commande chacun :
    python -m judge.cross_validation
    python -m judge.recommendation_engine
    python -m judge.compliance_judge
"""
