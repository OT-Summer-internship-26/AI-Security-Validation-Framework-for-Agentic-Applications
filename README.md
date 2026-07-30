# AI Security Audit Framework

> Framework automatisé d'audit de sécurité pour applications IA agentiques,
> basé sur **OWASP Top 10 for Agentic Applications 2026 (ASI01 → ASI10)**.

Stage — Ooredoo Tunisie, Département Intelligence Artificielle.

---

## Objectif

Prendre n'importe quel agent IA en entrée, l'auditer contre les 10 catégories
de risques agentiques, générer un rapport de sécurité automatisé, et s'intégrer
en CI/CD pour bloquer les déploiements non sécurisés (score < 70).

```
Agent IA (URL) → API FastAPI → Workflow LangGraph (10 agents)
    → Architecture à 3 couches (comportementale / statique / dynamique)
    → Scoring pondéré /100 → Rapport HTML/PDF → Gate CI/CD
```

## Architecture à 3 couches

| Couche | Outil | Ce qu'elle teste |
|---|---|---|
| Comportementale | DeepTeam (OWASP_ASI_2026) | L'agent se laisse-t-il manipuler ? |
| Statique | Semgrep + pip-audit | Patterns dangereux / CVE dans le code |
| Dynamique | Sandbox Docker | Que fait réellement le code généré ? |

## Statut

🚧 **Phase 1 — bootstrap du projet.** Structure et squelettes en place ;
la logique des agents, du workflow et du reporting sera implémentée en Phase 2.

Voir [NOTES.md](NOTES.md) pour le contexte complet du projet.

## Quick start (Phase 2 — à venir)

```bash
pip install -r requirements.txt
cp .env.example .env   # renseigner les clés
uvicorn api.main:app --reload
```
