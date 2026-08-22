import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  Cell, ReferenceLine, LabelList,
} from 'recharts'
import type { AgentResult } from '@/types'

/**
 * Décomposition du score par AXE et par COUCHE.
 *
 * POURQUOI CE GRAPHIQUE
 *     Un score global de 7,05 ne dit pas d'où il vient. Ici on voit
 *     immédiatement que DeepTeam donne 10 pendant que PyRIT et Garak donnent 0 —
 *     c'est la démonstration visuelle que le multi-axes rattrape ce qu'un axe
 *     unique manquerait. Les axes indisponibles sont montrés comme tels, jamais
 *     tracés à zéro (un zéro se lirait « catastrophique » au lieu de « non mesuré »).
 */
interface Row {
  name: string
  score: number | null
  weight: number
  group: 'axe comportemental' | 'couche'
  status?: string
}

const AXIS_LABEL: Record<string, string> = {
  deepteam: 'DeepTeam', pyrit: 'PyRIT', garak: 'Garak', microsoft: 'Payloads MS',
}
const AXIS_WEIGHT: Record<string, number> = {
  deepteam: 0.5, pyrit: 0.2, garak: 0.2, microsoft: 0.1,
}

function colorOf(score: number | null): string {
  if (score === null) return 'var(--border-bright)'
  if (score >= 8) return 'var(--sev-low)'
  if (score >= 5) return 'var(--sev-medium)'
  if (score > 0) return 'var(--sev-high)'
  return 'var(--sev-critical)'
}

export function AxisBreakdownChart({ agent, height = 300 }: {
  agent: AgentResult; height?: number
}) {
  const beh = agent.layers.behavioral
  const raw = (beh.raw || {}) as Record<string, unknown>
  const comps = (raw.score_components || {}) as Record<string, number | null>
  const status = (raw.axis_status || {}) as Record<string, string | null>

  const rows: Row[] = []

  Object.entries(AXIS_LABEL).forEach(([key, label]) => {
    if (!(key in comps)) return
    rows.push({
      name: label,
      score: comps[key] ?? null,
      weight: AXIS_WEIGHT[key],
      group: 'axe comportemental',
      status: status[key] || undefined,
    })
  })

  ;([
    ['Statique', agent.layers.static, 0.3],
    ['Dynamique', agent.layers.dynamic, 0.2],
  ] as const).forEach(([label, layer, w]) => {
    if (!layer.applicable) return
    rows.push({ name: label, score: layer.score, weight: w, group: 'couche', status: layer.error || undefined })
  })

  if (rows.length === 0) {
    return <p className="text-sm text-text-muted py-8 text-center">Aucun axe mesuré.</p>
  }

  const data = rows.map(r => ({ ...r, plotted: r.score ?? 0 }))

  return (
    <div>
      <ResponsiveContainer width="100%" height={height}>
        <BarChart data={data} margin={{ top: 18, right: 16, left: -22, bottom: 4 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border-base)" vertical={false} />
          <XAxis
            dataKey="name"
            tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
            stroke="var(--border-base)"
            interval={0}
          />
          <YAxis
            domain={[0, 10]} ticks={[0, 2.5, 5, 7.5, 10]}
            tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
            stroke="var(--border-base)"
          />
          <ReferenceLine
            y={7} stroke="var(--sev-low)" strokeDasharray="5 5" strokeOpacity={0.5}
            label={{ value: 'seuil 7', position: 'right', fill: 'var(--sev-low)', fontSize: 10 }}
          />
          <Bar dataKey="plotted" radius={[6, 6, 0, 0]} maxBarSize={64} animationDuration={600}>
            {data.map((d, i) => (
              <Cell
                key={i}
                fill={colorOf(d.score)}
                fillOpacity={d.score === null ? 0.28 : 0.9}
              />
            ))}
            <LabelList
              dataKey="score"
              position="top"
              formatter={(v: number | null) => (v === null ? 'n/d' : v.toFixed(1))}
              style={{ fill: 'var(--text-primary)', fontSize: 11, fontWeight: 700 }}
            />
          </Bar>
          <Tooltip
            cursor={{ fill: 'var(--bg-elevated)', opacity: 0.5 }}
            content={({ active, payload }) => {
              if (!active || !payload?.length) return null
              const d = payload[0].payload as Row
              return (
                <div className="glass rounded-xl p-3 text-xs shadow-lifted max-w-xs">
                  <div className="font-semibold text-text-primary">{d.name}</div>
                  <div className="text-text-muted mt-0.5">{d.group} · poids ×{d.weight}</div>
                  <div
                    className="font-mono font-bold mt-1.5 tabular"
                    style={{ color: colorOf(d.score) }}
                  >
                    {d.score === null ? 'non mesuré — exclu du calcul' : `${d.score.toFixed(2)}/10`}
                  </div>
                  {d.status && (
                    <div className="text-text-secondary mt-1 leading-snug">{d.status}</div>
                  )}
                </div>
              )
            }}
          />
        </BarChart>
      </ResponsiveContainer>
      <p className="text-[11px] text-text-muted text-center -mt-1">
        Barres pâles = axe non mesuré, exclu du calcul (jamais compté zéro)
      </p>
    </div>
  )
}
