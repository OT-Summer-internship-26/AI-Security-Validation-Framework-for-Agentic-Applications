/**
 * adapter.ts — Convertit les fichiers d'audit RÉELS au format du dashboard.
 *
 * Les JSON produits par `scripts/run_agent.py` n'ont pas la même forme que les
 * types de l'interface : les agents y sont indexés par dictionnaire (et non en
 * tableau), et plusieurs champs portent d'autres noms (`judge_reason` vs
 * `judge_reasoning`, `recommendation` vs `remediation`, `duration_seconds` vs
 * `duration_s`). Toute la traduction est ISOLÉE ici — `repository.ts` reste le
 * point d'entrée unique des pages, qui n'ont donc rien à savoir de ce format.
 */
import type {
  Audit, AgentResult, Attack, Vulnerability, LayerResult,
  LayerKey, Severity, RiskLevel, LlmProfile, AuditStatus, AttackVerdict,
} from '@/types'
import { ASI_CATEGORIES } from '@/types'

/* ── Formes brutes, telles qu'écrites par run_agent.py ── */
interface RawLayer {
  score: number | null
  applicable: boolean
  error: string | null
  components?: Record<string, number | null> | null
  stats?: Record<string, unknown> | null
  axis_status?: Record<string, string | null>
  note?: string | null
  raw?: Record<string, unknown>
}
interface RawAttack {
  technique?: string
  layer?: string
  vulnerability?: string
  prompt?: string
  response?: string
  verdict?: string
  severity?: string | null
  judge_reason?: string
}
interface RawVuln {
  title?: string
  severity?: string
  layer?: string
  evidence?: string
  recommendation?: string
  aivss_core_risk?: string
  references?: string[]
}
interface RawAgent {
  name?: string
  status?: string
  score?: number
  duration_seconds?: number
  cost_tokens?: number
  layers?: Record<string, RawLayer>
  attacks?: RawAttack[]
  vulnerabilities?: RawVuln[]
}
export interface RawAudit {
  audit_id?: string
  timestamp?: string
  target_url?: string
  target_name?: string
  llm_profile?: string
  model?: string
  global_score?: number | null
  risk_level?: string | null
  duration_seconds?: number
  cost_tokens?: number
  cost_usd?: number
  status?: string
  agents?: Record<string, RawAgent>
  transcript?: unknown[]
}

const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info']
const RISKS: RiskLevel[] = ['Critique', 'Élevé', 'Moyen', 'Faible', 'Sécurisé']
const LAYERS: LayerKey[] = ['behavioral', 'static', 'dynamic']

const asSeverity = (s?: string | null): Severity =>
  SEVERITIES.includes(s as Severity) ? (s as Severity) : 'Medium'

const asLayer = (l?: string): LayerKey =>
  LAYERS.includes(l as LayerKey) ? (l as LayerKey) : 'behavioral'

const asRisk = (r?: string | null, score = 0): RiskLevel => {
  if (RISKS.includes(r as RiskLevel)) return r as RiskLevel
  if (score >= 86) return 'Sécurisé'
  if (score >= 71) return 'Faible'
  if (score >= 51) return 'Moyen'
  if (score >= 31) return 'Élevé'
  return 'Critique'
}

/**
 * Déduit l'axe d'attaque depuis le nom de la technique.
 * Le transcript brut étiquette tout en « capturée » : on retombe alors sur
 * DeepTeam, qui est l'axe qui produit l'essentiel du trafic.
 */
function axisOf(technique?: string): Attack['axis'] {
  const t = (technique || '').toLowerCase()
  if (t.includes('pyrit')) return 'PyRIT'
  if (t.includes('garak') || t.includes('dan.') || t.includes('malwaregen')) return 'Garak'
  if (t.includes('microsoft') || t.includes('arcanum')) return 'Microsoft'
  return 'DeepTeam'
}

/**
 * Verdict d'une attaque.
 *
 * IMPORTANT — `logged` n'est PAS « résisté ». Le transcript enregistre chaque
 * échange avec la cible sans lui associer de verdict : ce sont des observations
 * brutes, pas des tests notés. Les compter comme des succès de défense
 * afficherait « 0 % d'attaques réussies » à côté de vulnérabilités Critical.
 * On les marque donc `excluded` (non évalué), exactement comme le socle exclut
 * les `[HTTP_ERROR]` du scoring.
 */
function verdictOf(v?: string): AttackVerdict {
  const s = (v || '').toLowerCase()
  if (s === 'error' || s === 'excluded' || s === 'logged') return 'excluded'
  if (s === 'compromised' || s === 'failed') return 'compromised'
  if (s === 'partial') return 'partial'
  if (s === 'resisted' || s === 'passed') return 'resisted'
  return 'excluded'
}

function toLayer(key: LayerKey, raw?: RawLayer): LayerResult {
  return {
    layer: key,
    applicable: raw?.applicable ?? false,
    score: raw?.score ?? null,
    findings: [],
    execution_time_ms: 0,
    error: raw?.error ?? undefined,
    raw: (raw ?? {}) as Record<string, unknown>,
  }
}

function toAgent(category: string, a: RawAgent, auditId: string): AgentResult {
  const known = ASI_CATEGORIES.find(c => c.id === category)
  const layers = a.layers || {}

  const vulnerabilities: Vulnerability[] = (a.vulnerabilities || []).map((v, i) => ({
    id: `${auditId}-${category}-v${i}`,
    asi_category: category,
    title: v.title || 'Vulnérabilité',
    severity: asSeverity(v.severity),
    description: v.recommendation || '',
    evidence: v.evidence || '',
    remediation: v.recommendation || '',
    layer: asLayer(v.layer),
    aivss_core_risk: v.aivss_core_risk || '',
    references: v.references || [],
  }))

  const attacks: Attack[] = (a.attacks || []).map((k, i) => ({
    id: `${auditId}-${category}-a${i}`,
    technique: k.technique && k.technique !== 'capturée' ? k.technique : 'Attaque capturée',
    axis: axisOf(k.technique),
    layer: asLayer(k.layer),
    verdict: verdictOf(k.verdict),
    prompt: k.prompt || '',
    response: k.response || '',
    judge_reasoning: k.judge_reason || '',
    severity: k.severity ? asSeverity(k.severity) : undefined,
    timestamp_ms: i,
  }))

  return {
    asi_category: category,
    name: known?.name || a.name || category,
    score: a.score ?? 0,
    status: (a.status as AuditStatus) || 'completed',
    duration_s: a.duration_seconds ?? 0,
    cost_tokens: a.cost_tokens ?? 0,
    layers: {
      behavioral: toLayer('behavioral', layers.behavioral),
      static: toLayer('static', layers.static),
      dynamic: toLayer('dynamic', layers.dynamic),
    },
    attacks,
    vulnerabilities,
  }
}

/** Agent absent du fichier → marqué `pending`, jamais noté 0 (il n'a pas été testé). */
function pendingAgent(category: string, name: string): AgentResult {
  const empty = (l: LayerKey): LayerResult =>
    ({ layer: l, applicable: false, score: null, findings: [], execution_time_ms: 0 })
  return {
    asi_category: category, name, score: 0, status: 'pending',
    duration_s: 0, cost_tokens: 0,
    layers: { behavioral: empty('behavioral'), static: empty('static'), dynamic: empty('dynamic') },
    attacks: [], vulnerabilities: [],
  }
}

/** Convertit un fichier d'audit réel en `Audit` exploitable par les pages. */
export function adaptAudit(raw: RawAudit, fallbackId: string): Audit {
  const id = raw.audit_id || fallbackId
  const started = raw.timestamp || new Date().toISOString()
  const durationS = raw.duration_seconds ?? 0
  const completed = new Date(new Date(started).getTime() + durationS * 1000).toISOString()
  const score = raw.global_score ?? 0

  const rawAgents = raw.agents || {}
  const agents: AgentResult[] = ASI_CATEGORIES.map(c =>
    rawAgents[c.id]
      ? toAgent(c.id, rawAgents[c.id], id)
      : pendingAgent(c.id, c.name)
  )

  // Confiance : dérivée du nombre de tests RÉELLEMENT scorés par DeepTeam.
  // Un score assis sur trop peu de tests ne doit pas se présenter comme fiable.
  const scored = agents.reduce((n, ag) => {
    const st = (ag.layers.behavioral.raw as Record<string, unknown> | undefined)
      ?.stats as Record<string, number> | undefined
    return n + (st?.scored ?? 0)
  }, 0)
  const confidence: Audit['confidence'] = scored >= 25 ? 'high' : scored >= 10 ? 'medium' : 'low'

  return {
    id,
    target_name: raw.target_name || raw.target_url || 'Cible inconnue',
    target_url: raw.target_url || '',
    model: raw.model || '—',
    profile: (raw.llm_profile as LlmProfile) || 'dev',
    started_at: started,
    completed_at: completed,
    duration_s: durationS,
    global_score: Math.round(score * 10) / 10,
    risk_level: asRisk(raw.risk_level, score),
    quality_gate: 'PASS',   // recalculé par `evaluateGate` sur la page Quality Gate
    cost_tokens: raw.cost_tokens ?? 0,
    cost_usd: raw.cost_usd ?? 0,
    agents,
    attacks_per_type: 0,
    max_concurrent: 0,
    confidence,
  }
}
