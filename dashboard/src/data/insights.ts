/**
 * insights.ts — Lecture des audits pour la vue d'ensemble.
 *
 * PROBLÈME RÉSOLU ICI
 *     Tous les audits ne sont PAS comparables. Un « contrôle rapide » n'exécute
 *     que Garak et les couches statique/dynamique ; un audit complet exécute les
 *     quatre axes comportementaux. Les moyenner produit un chiffre qui ne mesure
 *     rien, et les tracer sur une même courbe donne des dents de scie qui
 *     ressemblent à des régressions alors que ce sont des configurations
 *     différentes.
 *
 *     On regroupe donc par SIGNATURE : cible + ensemble d'axes réellement exécutés.
 */
import type { Audit, AgentResult, Vulnerability } from '@/types'

export const AXES = ['deepteam', 'pyrit', 'garak', 'microsoft'] as const

/**
 * Scores par axe d'UN agent (deepteam / pyrit / garak / microsoft).
 *
 * L'adaptateur expose ces scores sous `components` ; le `raw` brut du socle les
 * nomme `score_components`, et un niveau d'imbrication supplémentaire existe selon
 * la provenance. On accepte les trois — sans ce repli, la signature était toujours
 * identique et le bandeau d'incomparabilité ne se déclenchait jamais.
 */
export function axisScores(agent: AgentResult): Record<string, number | null> {
  const layerRaw = (agent.layers.behavioral.raw || {}) as Record<string, unknown>
  return ((layerRaw.components
    ?? layerRaw.score_components
    ?? (layerRaw.raw as Record<string, unknown> | undefined)?.score_components
  ) ?? {}) as Record<string, number | null>
}

/** Axes comportementaux réellement notés dans cet audit. */
export function axesUsed(audit: Audit): string[] {
  const out = new Set<string>()
  audit.agents.forEach(a => {
    const comps = axisScores(a)
    AXES.forEach(k => { if (comps?.[k] != null) out.add(k) })
    if (a.layers.static.applicable && a.layers.static.score != null) out.add('static')
    if (a.layers.dynamic.applicable && a.layers.dynamic.score != null) out.add('dynamic')
  })
  return [...out].sort()
}

/** Mode déduit des axes : un audit sans axe LLM est un contrôle rapide. */
export function inferMode(audit: Audit): 'quick' | 'partial' | 'complete' {
  const ax = axesUsed(audit)
  const llm = ax.some(a => ['deepteam', 'pyrit', 'microsoft'].includes(a))
  if (!llm) return 'quick'
  return ax.includes('deepteam') && ax.includes('pyrit') ? 'complete' : 'partial'
}

export const MODE_LABEL = {
  quick: 'Contrôle rapide', partial: 'Partiel', complete: 'Complet',
} as const

/** Nom de cible sans le suffixe de catégorie ajouté par le runner. */
export function targetOf(audit: Audit): string {
  return audit.target_name.replace(/\s*\(ASI_\d+\)\s*$/, '').trim() || audit.target_url
}

/** Signature de comparabilité : deux audits ne se comparent que si elle coïncide. */
export function signature(audit: Audit): string {
  return `${targetOf(audit)}::${inferMode(audit)}::${axesUsed(audit).join('+')}`
}

/**
 * Audits comparables au plus récent — c'est la seule série qu'on peut tracer
 * comme une évolution sans induire en erreur.
 */
export function comparableSeries(audits: Audit[], reference: Audit): Audit[] {
  const sig = signature(reference)
  return audits.filter(a => signature(a) === sig)
}

export interface VulnGroup {
  key: string
  title: string
  severity: Vulnerability['severity']
  category: string
  layer: string
  /** Nombre d'audits distincts où la faille est apparue. */
  occurrences: number
  /** `true` si présente dans l'audit le plus récent de sa cible. */
  stillOpen: boolean
  remediation: string
  sample: Vulnerability
}

const SEV_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 } as const

/**
 * Regroupe les vulnérabilités identiques.
 *
 * POURQUOI : la même faille détectée dans cinq audits successifs s'affichait
 * cinq fois, saturant la liste des « plus critiques » avec une seule réalité.
 * Le compteur d'occurrences est en outre une information utile — une faille
 * reproduite est certaine, une faille vue une fois peut être un artefact.
 */
export function groupVulnerabilities(audits: Audit[]): VulnGroup[] {
  const latestPerTarget = new Map<string, string>()
  audits.forEach(a => {
    const t = targetOf(a)
    if (!latestPerTarget.has(t)) latestPerTarget.set(t, a.id)   // audits déjà triés
  })

  const map = new Map<string, VulnGroup>()
  audits.forEach(audit => {
    const isLatest = latestPerTarget.get(targetOf(audit)) === audit.id
    audit.agents.forEach((ag: AgentResult) => {
      ag.vulnerabilities.forEach(v => {
        const key = `${v.asi_category}::${v.layer}::${v.title}`
        const g = map.get(key)
        if (g) {
          g.occurrences += 1
          g.stillOpen = g.stillOpen || isLatest
        } else {
          map.set(key, {
            key, title: v.title, severity: v.severity, category: v.asi_category,
            layer: v.layer, occurrences: 1, stillOpen: isLatest,
            remediation: v.remediation || v.description || '',
            sample: v,
          })
        }
      })
    })
  })

  return [...map.values()].sort((a, b) =>
    SEV_RANK[a.severity] - SEV_RANK[b.severity]
    || Number(b.stillOpen) - Number(a.stillOpen)
    || b.occurrences - a.occurrences)
}

export interface Coverage {
  measured: number
  total: number
  /** Catégories jamais auditées, toutes cibles confondues. */
  neverAudited: string[]
}

/** Couverture réelle du référentiel — plus parlant qu'une moyenne de scores. */
export function coverage(audits: Audit[], allCategories: readonly { id: string }[]): Coverage {
  const seen = new Set<string>()
  audits.forEach(a => a.agents
    .filter(ag => ag.status === 'completed')
    .forEach(ag => seen.add(ag.asi_category)))
  return {
    measured: seen.size,
    total: allCategories.length,
    neverAudited: allCategories.filter(c => !seen.has(c.id)).map(c => c.id),
  }
}
