import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts'
import type { Attack } from '@/types'

/**
 * Répartition des verdicts d'attaque.
 *
 * Les attaques non évaluées apparaissent SÉPARÉMENT plutôt que comptées comme
 * des défenses réussies — sans quoi le taux de résistance serait surévalué.
 */
const META: Record<string, { label: string; color: string }> = {
  resisted:    { label: 'Résisté',     color: 'var(--sev-low)' },
  compromised: { label: 'Compromis',   color: 'var(--sev-critical)' },
  partial:     { label: 'Partiel',     color: 'var(--sev-medium)' },
  excluded:    { label: 'Non évalué',  color: 'var(--border-bright)' },
}

export function VerdictDonut({ attacks, height = 240 }: {
  attacks: Attack[]; height?: number
}) {
  const counts: Record<string, number> = {}
  attacks.forEach(a => { counts[a.verdict] = (counts[a.verdict] || 0) + 1 })

  const data = Object.entries(counts)
    .filter(([, n]) => n > 0)
    .map(([k, n]) => ({ key: k, name: META[k]?.label ?? k, value: n, color: META[k]?.color ?? 'var(--text-muted)' }))

  if (data.length === 0) {
    return <p className="text-sm text-text-muted py-8 text-center">Aucune attaque enregistrée.</p>
  }

  const scored = attacks.filter(a => a.verdict !== 'excluded').length
  const breached = counts.compromised || 0
  const rate = scored ? Math.round((breached / scored) * 1000) / 10 : null

  return (
    <div className="relative">
      <ResponsiveContainer width="100%" height={height}>
        <PieChart>
          <Pie
            data={data} dataKey="value" nameKey="name"
            innerRadius="58%" outerRadius="82%" paddingAngle={2}
            stroke="var(--bg-surface)" strokeWidth={2} animationDuration={600}
          >
            {data.map((d, i) => <Cell key={i} fill={d.color} />)}
          </Pie>
          <Legend
            verticalAlign="bottom" height={28}
            formatter={(v: string) => <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{v}</span>}
          />
          <Tooltip
            content={({ active, payload }) => {
              if (!active || !payload?.length) return null
              const d = payload[0].payload as { name: string; value: number }
              return (
                <div className="glass rounded-xl p-2.5 text-xs shadow-lifted">
                  <div className="font-semibold text-text-primary">{d.name}</div>
                  <div className="text-text-secondary mt-0.5 tabular">
                    {d.value} attaque{d.value > 1 ? 's' : ''}
                  </div>
                </div>
              )
            }}
          />
        </PieChart>
      </ResponsiveContainer>

      {/* Centre du donut : le chiffre qui compte */}
      <div className="absolute inset-x-0 top-[38%] -translate-y-1/2 pointer-events-none text-center">
        <div
          className="text-3xl font-bold font-mono tabular leading-none"
          style={{ color: rate === null ? 'var(--text-muted)' : rate > 20 ? 'var(--sev-critical)' : 'var(--sev-low)' }}
        >
          {rate === null ? '—' : `${rate}%`}
        </div>
        <div className="text-[10px] text-text-muted mt-1">réussite adverse</div>
      </div>
    </div>
  )
}
