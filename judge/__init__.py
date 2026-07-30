"""
Package `judge` — couches LLM-as-Judge personnalisées AU-DESSUS de DeepTeam.

DeepTeam évalue déjà pass/fail via son `evaluation_model`. Ce package ajoute :
    - severity_judge.py        : gravité contextuelle (pas juste pass/fail)
    - cross_validation.py      : double jugement si confidence < 80 %
    - recommendation_engine.py : recommandations intelligentes via LLM
"""
