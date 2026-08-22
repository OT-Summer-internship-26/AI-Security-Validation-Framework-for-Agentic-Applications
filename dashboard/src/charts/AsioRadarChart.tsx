import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  ResponsiveContainer, Tooltip,
} from 'recharts'
import { ASI_CATEGORIES } from '@/types'
import type { Audit } from '@/types'

interface RadarDataPoint {
  category: string
  short: string
  score: number | null
  tested: boolean
  fullMark: number
}

/**
 * Radar des 10 catégories ASI.
 *
 * Les catégories NON testées ne sont jamais tracées à 0 : un zéro se lirait
 * « catastrophique » alors qu'il signifie « pas encore mesuré ». Elles sont
 * simplement absentes de la série et signalées dans l'infobulle.
 *
 * Accepte soit un `audit` complet, soit une liste `data` (utilisé par le
 * Live Audit, qui met à jour le radar catégorie par catégorie).
 */
export function AsioRadarChart({
  audit,
  data: liveData,
  size = 280,
}: {
  audit?: Audit
  data?: { category: string; score: number }[]
  size?: number
}) {
  const points: RadarDataPoint[] = ASI_CATEGORIES.map(cat => {
    let score: number | null = null

    if (liveData) {
      const hit = liveData.find(d => d.category === cat.id)
      score = hit ? hit.score : null
    } else if (audit) {
      const agent = audit.agents.find(a => a.asi_category === cat.id)
      score = !agent || agent.status === 'pending' ? null : agent.score
    }

    return {
      category: cat.name,
      short: cat.short,
      score,
      tested: score !== null,
      fullMark: 10,
    }
  })

  const testedCount = points.filter(p => p.tested).length

  return (
    <div className="relative">
      <ResponsiveContainer width="100%" height={size}>
        <RadarChart data={points} outerRadius="74%">
          <PolarGrid stroke="var(--border-base)" />
          <PolarAngleAxis
            dataKey="short"
            tick={({ payload, x, y, textAnchor }) => {
              const p = points.find(pt => pt.short === payload.value)
              return (
                <text
                  x={x} y={y} textAnchor={textAnchor}
                  fill={p?.tested ? 'var(--text-secondary)' : 'var(--text-muted)'}
                  fontSize={10}
                  fontWeight={p?.tested ? 600 : 400}
                  opacity={p?.tested ? 1 : 0.55}
                >
                  {payload.value}
                </text>
              )
            }}
          />
          <PolarRadiusAxis
            domain={[0, 10]}
            tick={{ fill: 'var(--text-muted)', fontSize: 9 }}
            tickCount={5}
            stroke="var(--border-base)"
          />
          <Radar
            name="Score"
            dataKey="score"
            stroke="var(--layer-behavioral)"
            fill="var(--layer-behavioral)"
            fillOpacity={0.18}
            strokeWidth={2}
            isAnimationActive
            animationDuration={450}
            connectNulls={false}
            dot={{ r: 3, fill: 'var(--layer-behavioral)', strokeWidth: 0 }}
          />
          <Tooltip
            content={({ active, payload }) => {
              if (!active || !payload?.length) return null
              const p = payload[0].payload as RadarDataPoint
              return (
                <div className="glass rounded-xl p-2.5 text-xs shadow-lifted">
                  <div className="font-semibold text-text-primary">{p.category}</div>
                  <div className="text-text-secondary mt-1">
                    {p.score === null
                      ? 'Non testé — exclu du calcul'
                      : `Score ${p.score.toFixed(2)}/10`}
                  </div>
                </div>
              )
            }}
          />
        </RadarChart>
      </ResponsiveContainer>

      <div className="text-[10px] text-text-muted text-center -mt-1">
        {testedCount}/10 catégories mesurées · les non testées ne sont pas tracées
      </div>
    </div>
  )
}
