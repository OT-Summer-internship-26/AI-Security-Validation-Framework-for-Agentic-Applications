/**
 * repository.ts — Point d'accès UNIQUE aux données d'audit pour les pages.
 *
 * Les audits proviennent de l'API (`api/main.py`), chargés par `store.ts`.
 * Aucune page n'appelle `fetch` ni ne connaît le format brut : tout passe ici.
 */
import { DEFAULT_POLICY as RAW_POLICY } from './audits'
import { currentAudits, currentPolicy, currentSource } from './store'
import type { Audit, QualityGatePolicy, ScoreHistoryPoint, Vulnerability } from '@/types'

export { useAudits, reloadAudits } from './store'
export type { DataSource } from './store'

/** Tous les audits, du plus récent au plus ancien. */
export function getAudits(): Audit[] {
  return currentAudits()
}

/** `true` si les données affichées viennent d'audits réels (et non de la démo). */
export function hasRealData(): boolean {
  return currentSource() === 'api'
}

/** Un audit par identifiant, ou `undefined`. */
export function getAudit(id: string | null | undefined): Audit | undefined {
  if (!id) return undefined
  return getAudits().find(a => a.id === id)
}

/** L'audit le plus récent (par date, pas par position dans le tableau). */
export function getLatestAudit(): Audit | undefined {
  return getAudits()[0]
}

/** Résout un identifiant éventuellement absent vers un audit, si disponible. */
export function resolveAudit(id: string | null | undefined): Audit | undefined {
  return getAudit(id) ?? getLatestAudit()
}

/** Historique de score pour une cible donnée (ou toutes), ordre chronologique. */
export function getScoreHistory(targetName?: string): ScoreHistoryPoint[] {
  return getAudits()
    .filter(a => !targetName || a.target_name === targetName)
    .map(a => ({
      date: a.started_at.slice(0, 10),
      score: a.global_score,
      target: a.target_name,
      audit_id: a.id,
    }))
    .reverse()
}

/** Toutes les vulnérabilités d'un audit, à plat. */
export function getVulnerabilities(audit: Audit): Vulnerability[] {
  return audit.agents.flatMap(a => a.vulnerabilities)
}

/** L'audit précédent de la MÊME cible — la baseline naturelle du Quality Gate. */
export function getBaselineFor(audit: Audit): Audit | undefined {
  return getAudits().find(
    a => a.target_name === audit.target_name &&
         new Date(a.started_at).getTime() < new Date(audit.started_at).getTime()
  )
}

/**
 * Politique de Quality Gate EN VIGUEUR : celle que l'API sert (`GET /gate/policy`),
 * c'est-à-dire celle que `scripts/ci_gate.py` applique. Repli local sinon.
 *
 * `mode` et `baseline_audit_id` n'existent que dans le simulateur du dashboard :
 * la CI juge toujours en mode absolu, sans baseline.
 */
export function getDefaultPolicy(): QualityGatePolicy {
  const servie = currentPolicy()
  if (!servie) return RAW_POLICY
  return {
    ...RAW_POLICY,
    ...servie,
    mode: 'absolute',
    baseline_audit_id: null,
    per_category: servie.per_category ?? {},
    derogations: (servie.derogations ?? []).map((d, i) => ({ id: `der-${i + 1}`, ...d })),
  }
}
