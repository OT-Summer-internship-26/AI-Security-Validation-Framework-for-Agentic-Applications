import {
  XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceArea, ReferenceLine, Area, ComposedChart, Line,
} from 'recharts'
import { getScoreHistory } from '@/data/repository'

/**
 * Évolution du score global. La bande sous 70 matérialise la zone où le
 * Quality Gate bloque en mode « état absolu ». La série est tracée en bleu :
 * le rouge Ooredoo reste réservé au chrome de l'application.
 */
export function ScoreTimelineChart({ height = 230 }: { height?: number }) {
  const data = getScoreHistory().map(h => ({
    date: h.date,
    score: h.score,
    target: h.target,
    auditId: h.audit_id,
  }))

  return (
    <ResponsiveContainer width="100%" height={height}>
      <ComposedChart data={data} margin={{ top: 10, right: 12, left: -18, bottom: 0 }}>
        <defs>
          <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--layer-behavioral)" stopOpacity={0.28} />
            <stop offset="100%" stopColor="var(--layer-behavioral)" stopOpacity={0} />
          </linearGradient>
        </defs>

        <CartesianGrid strokeDasharray="3 3" stroke="var(--border-base)" vertical={false} />
        <XAxis
          dataKey="date"
          tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
          stroke="var(--border-base)"
          tickFormatter={(v: string) => v.slice(5)}
        />
        <YAxis
          domain={[0, 100]}
          tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
          stroke="var(--border-base)"
        />

        <ReferenceArea y1={0} y2={70} fill="var(--sev-critical)" fillOpacity={0.055} />
        <ReferenceLine
          y={70}
          stroke="var(--sev-critical)"
          strokeDasharray="5 5"
          strokeOpacity={0.55}
          label={{
            value: 'seuil 70',
            position: 'insideTopRight',
            fill: 'var(--sev-critical)',
            fontSize: 10,
          }}
        />

        <Area type="monotone" dataKey="score" stroke="none" fill="url(#scoreGradient)" fillOpacity={1} />
        <Line
          type="monotone"
          dataKey="score"
          stroke="var(--layer-behavioral)"
          strokeWidth={2.5}
          dot={{ fill: 'var(--layer-behavioral)', r: 4, strokeWidth: 0 }}
          activeDot={{ r: 6, fill: 'var(--layer-behavioral)', stroke: 'var(--bg-surface)', strokeWidth: 2 }}
          animationDuration={600}
        />

        <Tooltip
          cursor={{ stroke: 'var(--border-bright)', strokeDasharray: '3 3' }}
          content={({ active, payload }) => {
            if (!active || !payload?.length) return null
            const p = payload[0].payload
            const blocked = p.score < 70
            return (
              <div className="glass rounded-xl p-3 text-xs shadow-lifted">
                <div className="font-semibold text-text-primary">{p.target}</div>
                <div className="text-text-secondary mt-1">{p.date}</div>
                <div
                  className="font-mono font-bold mt-1 tabular"
                  style={{ color: blocked ? 'var(--sev-critical)' : 'var(--sev-low)' }}
                >
                  {p.score.toFixed(1)}/100 · {blocked ? 'sous le seuil' : 'au-dessus du seuil'}
                </div>
              </div>
            )
          }}
        />
      </ComposedChart>
    </ResponsiveContainer>
  )
}
