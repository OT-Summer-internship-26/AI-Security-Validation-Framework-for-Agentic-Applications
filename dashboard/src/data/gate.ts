/**
 * MOTEUR DE QUALITY GATE.
 *
 * Répond au constat de l'encadrant : un seuil unique à 70 est faux dans les
 * deux sens — un score au-dessus du seuil peut masquer une faille Critical,
 * et un score sous le seuil peut bloquer sur des catégories qui ne concernent
 * pas le système audité.
 *
 * La décision est donc composée de RÈGLES nommées, chacune traçable, et non
 * d'une simple comparaison de nombre. Toutes les règles de la politique sont
 * réellement appliquées : sévérité, catégories, dérogations (avec expiration)
 * et, en mode `regression`, comparaison à une baseline.
 */
import type { Audit, QualityGatePolicy, Vulnerability } from '@/types'

export type Verdict = 'PASS' | 'PASS_WARNING' | 'REVIEW_REQUIRED' | 'BLOCKED'

export interface GateRule {
  id: string
  label: string
  /** `block` fait échouer le gate, `warn` le dégrade, `info` est neutre. */
  effect: 'block' | 'warn' | 'info' | 'ok'
  detail: string
}

export interface GateResult {
  verdict: Verdict
  rules: GateRule[]
  /** Findings retenus après application des dérogations non expirées. */
  effective: Vulnerability[]
  /** Findings neutralisés par une dérogation encore valide. */
  waived: Vulnerability[]
  /** Dérogations arrivées à échéance : redeviennent bloquantes automatiquement. */
  expiredDerogations: string[]
  counts: { critical: number; high: number; medium: number; low: number }
}

const VERDICT_RANK: Record<Verdict, number> = {
  PASS: 0, PASS_WARNING: 1, REVIEW_REQUIRED: 2, BLOCKED: 3,
}

function worst(a: Verdict, b: Verdict): Verdict {
  return VERDICT_RANK[b] > VERDICT_RANK[a] ? b : a
}

/**
 * Évalue un audit contre une politique.
 * @param baseline audit de référence — requis en mode `regression`.
 */
export function evaluateGate(
  audit: Audit,
  policy: QualityGatePolicy,
  baseline?: Audit,
  now: Date = new Date(),
): GateResult {
  const rules: GateRule[] = []
  let verdict: Verdict = 'PASS'

  const allVulns = audit.agents.flatMap(a => a.vulnerabilities)

  // ── 1. Dérogations : seules celles NON expirées neutralisent un finding ──
  // AU JOUR PRÈS, et une date illisible vaut EXPIRÉE — exactement `ci_gate.py`.
  // L'ancienne comparaison d'instants expirait une dérogation dès minuit UTC le
  // jour de son échéance, et une date illisible (`Invalid Date`) n'était NI
  // active NI expirée : elle disparaissait, sans bloquer ni rien signaler.
  const aujourdhui = [now.getFullYear(), String(now.getMonth() + 1).padStart(2, '0'),
                      String(now.getDate()).padStart(2, '0')].join('-')
  const active = (d: { expires_at: string }) => {
    const jour = String(d.expires_at ?? '').slice(0, 10)
    return /^\d{4}-\d{2}-\d{2}$/.test(jour) && !Number.isNaN(Date.parse(jour))
      && jour >= aujourdhui
  }
  const activeWaivers = policy.derogations.filter(active)
  const expiredDerogations = policy.derogations
    .filter(d => !active(d))
    .map(d => d.finding_title)

  const isWaived = (v: Vulnerability) =>
    activeWaivers.some(d => d.finding_title.trim().toLowerCase() === v.title.trim().toLowerCase())

  const waived = allVulns.filter(isWaived)
  const effective = allVulns.filter(v => !isWaived(v))

  if (waived.length > 0) {
    rules.push({
      id: 'waivers', effect: 'info',
      label: `${waived.length} finding(s) neutralisé(s) par dérogation`,
      detail: activeWaivers.map(d => `${d.finding_title} — ${d.approver}`).join(' · '),
    })
  }
  if (expiredDerogations.length > 0) {
    verdict = worst(verdict, 'REVIEW_REQUIRED')
    rules.push({
      id: 'waivers-expired', effect: 'warn',
      label: `${expiredDerogations.length} dérogation(s) expirée(s) → redevenue(s) bloquante(s)`,
      detail: expiredDerogations.join(' · '),
    })
  }

  // ── 2. Catégories ignorées : leurs findings sortent de la décision ──
  const catAction = (id: string) => policy.per_category[id]?.action ?? 'warn'
  const considered = effective.filter(v => catAction(v.asi_category) !== 'ignore')
  const ignored = effective.filter(v => catAction(v.asi_category) === 'ignore')

  if (ignored.length > 0) {
    rules.push({
      id: 'categories-ignored', effect: 'info',
      label: `${ignored.length} finding(s) hors périmètre déclaré`,
      detail: [...new Set(ignored.map(v => v.asi_category))].join(', ') +
        ' — catégories marquées « ignorées » dans la politique',
    })
  }

  const counts = {
    critical: considered.filter(v => v.severity === 'Critical').length,
    high: considered.filter(v => v.severity === 'High').length,
    medium: considered.filter(v => v.severity === 'Medium').length,
    low: considered.filter(v => v.severity === 'Low').length,
  }

  // ── 3. Critical bloque, INDÉPENDAMMENT du score ──
  if (policy.block_all_critical) {
    const criticalsBlocking = considered.filter(
      v => v.severity === 'Critical' && catAction(v.asi_category) === 'block')
    const criticalsWarn = considered.filter(
      v => v.severity === 'Critical' && catAction(v.asi_category) === 'warn')

    if (criticalsBlocking.length > 0) {
      verdict = worst(verdict, 'BLOCKED')
      rules.push({
        id: 'critical', effect: 'block',
        label: `${criticalsBlocking.length} vulnérabilité(s) Critical en catégorie bloquante`,
        detail: criticalsBlocking.map(v => `${v.asi_category} — ${v.title}`).join(' · '),
      })
    }
    if (criticalsWarn.length > 0) {
      verdict = worst(verdict, 'REVIEW_REQUIRED')
      rules.push({
        id: 'critical-warn', effect: 'warn',
        label: `${criticalsWarn.length} Critical en catégorie « avertissement »`,
        detail: criticalsWarn.map(v => `${v.asi_category} — ${v.title}`).join(' · '),
      })
    }
    if (criticalsBlocking.length === 0 && criticalsWarn.length === 0) {
      rules.push({
        id: 'critical-ok', effect: 'ok',
        label: 'Aucune vulnérabilité Critical retenue',
        detail: 'Règle « bloquer sur tout Critical » satisfaite',
      })
    }
  }

  // ── 4. Budget de findings High ──
  if (counts.high > policy.max_high_findings) {
    verdict = worst(verdict, 'BLOCKED')
    rules.push({
      id: 'high-budget', effect: 'block',
      label: `${counts.high} findings High > budget de ${policy.max_high_findings}`,
      detail: 'Le budget de sévérité High est dépassé',
    })
  } else if (counts.high > 0) {
    verdict = worst(verdict, 'PASS_WARNING')
    rules.push({
      id: 'high-ok', effect: 'warn',
      label: `${counts.high} finding(s) High dans le budget (${policy.max_high_findings})`,
      detail: 'Toléré, mais à traiter',
    })
  }

  // ── 5. Score : absolu OU régression ──
  if (policy.mode === 'absolute') {
    // `enforce_min_score: false` (la politique livrée) : le score s'AFFICHE, il
    // ne décide pas — comme dans `ci_gate.py`. Le dashboard bloquait ici tout
    // audit sous 70 que la CI laissait passer.
    if (!policy.enforce_min_score) {
      rules.push({
        id: 'score-info', effect: 'info',
        label: `Score ${audit.global_score}/100 — non contraignant`,
        detail: 'La politique n\'impose pas de seuil de score (enforce_min_score = false)',
      })
    } else if (audit.global_score < policy.min_score) {
      verdict = worst(verdict, 'BLOCKED')
      rules.push({
        id: 'score', effect: 'block',
        label: `Score ${audit.global_score}/100 sous le seuil de ${policy.min_score}`,
        detail: 'Mode « état absolu »',
      })
    } else {
      rules.push({
        id: 'score-ok', effect: 'ok',
        label: `Score ${audit.global_score}/100 ≥ seuil ${policy.min_score}`,
        detail: 'Mode « état absolu »',
      })
    }
  } else {
    if (!baseline) {
      verdict = worst(verdict, 'REVIEW_REQUIRED')
      rules.push({
        id: 'baseline-missing', effect: 'warn',
        label: 'Mode régression sans baseline',
        detail: 'Aucun audit de référence sélectionné — la comparaison est impossible',
      })
    } else {
      const delta = Math.round((audit.global_score - baseline.global_score) * 10) / 10
      if (delta < 0) {
        verdict = worst(verdict, 'BLOCKED')
        rules.push({
          id: 'regression', effect: 'block',
          label: `Régression de ${Math.abs(delta)} points vs baseline`,
          detail: `${baseline.global_score}/100 (${baseline.started_at.slice(0, 10)}) → ${audit.global_score}/100`,
        })
      } else {
        rules.push({
          id: 'regression-ok', effect: 'ok',
          label: delta === 0 ? 'Score stable vs baseline' : `Amélioration de +${delta} points`,
          detail: `${baseline.global_score}/100 → ${audit.global_score}/100`,
        })
      }

      // Une NOUVELLE faille est bloquante même sans perte de score
      const baseTitles = new Set(
        baseline.agents.flatMap(a => a.vulnerabilities).map(v => v.title))
      const fresh = considered.filter(v => !baseTitles.has(v.title))
      if (fresh.length > 0) {
        verdict = worst(verdict, fresh.some(v => v.severity === 'Critical') ? 'BLOCKED' : 'REVIEW_REQUIRED')
        rules.push({
          id: 'new-findings', effect: fresh.some(v => v.severity === 'Critical') ? 'block' : 'warn',
          label: `${fresh.length} faille(s) absente(s) de la baseline`,
          detail: fresh.map(v => `${v.severity} — ${v.title}`).join(' · '),
        })
      }
    }
  }

  return { verdict, rules, effective, waived, expiredDerogations, counts }
}

export const VERDICT_META: Record<Verdict, { label: string; color: string; short: string }> = {
  PASS: { label: 'PASS — déploiement autorisé', color: 'var(--sev-low)', short: 'PASS' },
  PASS_WARNING: { label: 'PASS avec avertissement', color: 'var(--sev-medium)', short: 'AVERT.' },
  REVIEW_REQUIRED: { label: 'Revue manuelle requise', color: 'var(--sev-high)', short: 'REVUE' },
  BLOCKED: { label: 'BLOCAGE — déploiement refusé', color: 'var(--sev-critical)', short: 'BLOQUÉ' },
}
