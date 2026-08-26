// ─── Core domain types for the AI Security Audit Console ───

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
export type RiskLevel = 'Critique' | 'Élevé' | 'Moyen' | 'Faible' | 'Sécurisé'
export type LayerKey = 'behavioral' | 'static' | 'dynamic'
export type AttackVerdict = 'resisted' | 'compromised' | 'partial' | 'excluded'
export type AuditStatus = 'completed' | 'running' | 'pending' | 'failed'
export type LlmProfile = 'dev' | 'final' | 'dry_run'
export type PageId = 'overview' | 'history' | 'attacks' | 'live' | 'comparison' | 'quality-gate'
export type Theme = 'dark' | 'light'

export interface LayerResult {
  layer: LayerKey
  applicable: boolean
  score: number | null
  findings: Vulnerability[]
  execution_time_ms: number
  error?: string
  raw?: Record<string, unknown>
}

export interface AttackTurn {
  turn: number
  prompt: string
  response: string
  verdict?: AttackVerdict
  judge_reasoning?: string
  is_failure_point?: boolean
}

export interface Attack {
  id: string
  technique: string
  axis: 'DeepTeam' | 'PyRIT' | 'Garak' | 'Microsoft'
  layer: LayerKey
  verdict: AttackVerdict
  prompt: string
  response: string
  judge_reasoning: string
  multi_turn?: AttackTurn[]
  severity?: Severity
  timestamp_ms: number
}

export interface Vulnerability {
  id: string
  asi_category: string
  title: string
  severity: Severity
  description: string
  evidence: string
  remediation: string
  layer: LayerKey
  aivss_core_risk: string
  references: string[]
  attack_id?: string
  /** Confiance annoncee par le juge (0-100). `null` = non annoncee -> a traiter comme douteux. */
  confidence?: number | null
  /** Analyse structuree du juge : intention, comportement, garde, impact, remediation. */
  judge_detail?: JudgeDetail
}

/** Champs structures produits par `judge/severity_judge.py`. */
export interface JudgeDetail {
  attack_intent?: string
  agent_behavior?: string
  guardrail?: string
  impact?: string
  rationale?: string
  remediation?: string
  confidence?: number | null
  /** Renseigne quand le juge n'a PAS pu se prononcer (gravite issue du bareme statique). */
  fallback?: string
}

/**
 * Ce que les juges disent de LEUR PROPRE fiabilite, agrege sur les categories.
 *
 * Sans ces chiffres, un verdict de modele se lit comme un fait etabli : on ne
 * sait ni combien de gravites viennent reellement du juge, ni si la
 * contre-validation apporte quoi que ce soit d'independant.
 */
export interface JudgeSummary {
  judged: number
  fallbacks: number
  fallback_pct: number
  cross_validation: { triggered: number; agreed: number; changed: number; unavailable: number }
  recommendations: { contextual_used: number; generic_dropped: number; deduplicated: number }
  refusal: { robust: number; partial: number; accidental: number }
  microsoft: { complied: number; refused: number; unreadable: number }
  warnings: string[]
}

export interface AgentResult {
  /** `false` => aucune couche exploitable : le score 0 n'est PAS un verdict et la
   *  categorie est exclue du score global. */
  measured?: boolean
  asi_category: string
  name: string
  score: number
  status: AuditStatus
  duration_s: number
  cost_tokens: number
  layers: {
    behavioral: LayerResult
    static: LayerResult
    dynamic: LayerResult
  }
  attacks: Attack[]
  vulnerabilities: Vulnerability[]
  error?: string
}

export interface Audit {
  id: string
  target_name: string
  target_url: string
  model: string
  profile: LlmProfile
  started_at: string
  completed_at: string
  duration_s: number
  global_score: number
  risk_level: RiskLevel
  quality_gate: 'PASS' | 'PASS_WARNING' | 'REVIEW_REQUIRED' | 'BLOCKED'
  cost_tokens: number
  cost_usd: number
  agents: AgentResult[]
  attacks_per_type: number
  max_concurrent: number
  /** Confiance DERIVEE du nombre de tests scores — a ne pas confondre avec celle du juge. */
  confidence: 'low' | 'medium' | 'high'
  /** Fiabilite auto-declaree de la chaine de jugement (null si aucun juge n'a tourne). */
  judge_summary?: JudgeSummary | null
}

export interface ScoreHistoryPoint {
  date: string
  score: number
  target: string
  audit_id: string
}

export interface QualityGatePolicy {
  block_all_critical: boolean
  max_high_findings: number
  min_score: number
  mode: 'absolute' | 'regression'
  baseline_audit_id: string | null
  per_category: Record<string, { action: 'block' | 'warn' | 'ignore'; justification?: string }>
  derogations: Derogation[]
}

export interface Derogation {
  id: string
  finding_title: string
  reason: string
  approver: string
  expires_at: string
}

export interface ComponentStatus {
  name: string
  status: 'operational' | 'partial' | 'building'
  label: string
}

export interface ToastMessage {
  id: string
  type: 'info' | 'success' | 'warning' | 'error'
  title: string
  message?: string
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  Critical: '#FF3B5C',
  High: '#FF8C00',
  Medium: '#FFD93D',
  Low: '#00D68F',
  Info: '#4D7CFF',
}

export const LAYER_COLORS: Record<LayerKey, string> = {
  behavioral: '#3B82F6',
  static: '#F59E0B',
  dynamic: '#EF4444',
}

export const RISK_COLORS: Record<RiskLevel, string> = {
  Critique: '#FF3B5C',
  Élevé: '#FF8C00',
  Moyen: '#FFD93D',
  Faible: '#00D68F',
  Sécurisé: '#4D7CFF',
}

export const ASI_CATEGORIES = [
  { id: 'ASI_01', name: 'Goal Hijacking', short: 'ASI01' },
  { id: 'ASI_02', name: 'Tool Misuse', short: 'ASI02' },
  { id: 'ASI_03', name: 'Identity & Privilege Abuse', short: 'ASI03' },
  { id: 'ASI_04', name: 'Agentic Supply Chain', short: 'ASI04' },
  { id: 'ASI_05', name: 'Unexpected Code Execution', short: 'ASI05' },
  { id: 'ASI_06', name: 'Memory & Context Poisoning', short: 'ASI06' },
  { id: 'ASI_07', name: 'Inter-Agent Communication', short: 'ASI07' },
  { id: 'ASI_08', name: 'Cascading Failures', short: 'ASI08' },
  { id: 'ASI_09', name: 'Trust Exploitation', short: 'ASI09' },
  { id: 'ASI_10', name: 'Rogue Agents', short: 'ASI10' },
] as const

export const ASI_WEIGHTS: Record<string, number> = {
  ASI_01: 0.15, ASI_02: 0.15, ASI_03: 0.10, ASI_04: 0.08, ASI_05: 0.12,
  ASI_06: 0.12, ASI_07: 0.08, ASI_08: 0.07, ASI_09: 0.07, ASI_10: 0.06,
}
