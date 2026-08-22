import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell,
} from 'recharts'
import { ASI_CATEGORIES } from '@/types'
import type { Audit } from '@/types'

export function CategoryBarChart({ audit, height = 200 }: { audit: Audit; height?: number }) {
  const data = ASI_CATEGORIES.map(cat => {
    const agent = audit.agents.find(a => a.asi_category === cat.id)
    return {
      short: cat.short,
      score: agent && agent.status === 'completed' ? agent.score : null,
    }
  }).filter(d => d.score !== null)

  const getColor = (score: number) =>
    score >= 8 ? '#00D68F' : score >= 5 ? '#FFD93D' : score >= 2.5 ? '#FF8C00' : '#FF3B5C'

  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#252D42" vertical={false} />
        <XAxis dataKey="short" tick={{ fill: '#8B96AE', fontSize: 10 }} stroke="#252D42" />
        <YAxis domain={[0, 10]} tick={{ fill: '#8B96AE', fontSize: 11 }} stroke="#252D42" />
        <Tooltip
          content={({ active, payload }) => {
            if (!active || !payload?.length) return null
            return (
              <div className="glass rounded-lg p-2 text-xs">
                <div className="font-semibold text-text-primary">{payload[0].payload.short}</div>
                <div className="text-text-secondary mt-1">
                  Score: {(payload[0].value as number).toFixed(1)}/10
                </div>
              </div>
            )
          }}
        />
        <Bar dataKey="score" radius={[4, 4, 0, 0]}>
          {data.map((d, i) => (
            <Cell key={i} fill={getColor(d.score!)} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
