import type { Severity, RiskLevel, LayerKey, AttackVerdict } from '@/types'
import { SEVERITY_COLORS, LAYER_COLORS, RISK_COLORS } from '@/types'

export function SeverityBadge({ severity }: { severity: Severity }) {
  const color = SEVERITY_COLORS[severity]
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-semibold"
      style={{ backgroundColor: `${color}15`, color, border: `1px solid ${color}30` }}
    >
      {severity}
    </span>
  )
}

export function RiskBadge({ level }: { level: RiskLevel }) {
  const color = RISK_COLORS[level]
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold"
      style={{ backgroundColor: `${color}15`, color, border: `1px solid ${color}30` }}
    >
      {level}
    </span>
  )
}

export function LayerBadge({ layer }: { layer: LayerKey }) {
  const color = LAYER_COLORS[layer]
  const labels: Record<LayerKey, string> = {
    behavioral: 'Behavioral',
    static: 'Static',
    dynamic: 'Dynamic',
  }
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium"
      style={{ backgroundColor: `${color}15`, color, border: `1px solid ${color}30` }}
    >
      {labels[layer]}
    </span>
  )
}

export function VerdictBadge({ verdict }: { verdict: AttackVerdict }) {
  const config: Record<AttackVerdict, { label: string; color: string; icon: string }> = {
    resisted: { label: 'Résisté', color: '#00D68F', icon: '✅' },
    compromised: { label: 'Compromis', color: '#FF3B5C', icon: '❌' },
    partial: { label: 'Partiel', color: '#FFD93D', icon: '⚠️' },
    excluded: { label: 'Exclu', color: '#8B96AE', icon: '—' },
  }
  const { label, color, icon } = config[verdict]
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-semibold"
      style={{ backgroundColor: `${color}15`, color, border: `1px solid ${color}30` }}
    >
      <span>{icon}</span>
      {label}
    </span>
  )
}

export function ConfidenceBadge({ confidence }: { confidence: 'low' | 'medium' | 'high' }) {
  const config = {
    low: { color: '#FF8C00', label: 'Confiance faible' },
    medium: { color: '#FFD93D', label: 'Confiance moyenne' },
    high: { color: '#00D68F', label: 'Confiance élevée' },
  }
  const { color, label } = config[confidence]
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-medium"
      style={{ backgroundColor: `${color}10`, color, border: `1px solid ${color}25` }}
    >
      {label}
    </span>
  )
}
