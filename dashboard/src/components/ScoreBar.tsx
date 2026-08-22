export function ScoreBar({ score, max = 100, color }: { score: number; max?: number; color?: string }) {
  const pct = Math.min((score / max) * 100, 100)
  const barColor = color || (
    pct >= 71 ? '#00D68F' : pct >= 51 ? '#FFD93D' : pct >= 31 ? '#FF8C00' : '#FF3B5C'
  )
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 rounded-full bg-bg-elevated overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700 ease-out"
          style={{ width: `${pct}%`, backgroundColor: barColor }}
        />
      </div>
      <span className="font-mono text-sm tabular-nums w-12 text-right" style={{ color: barColor }}>
        {score.toFixed(1)}
      </span>
    </div>
  )
}

export function MiniScoreBar({ score, max = 10 }: { score: number; max?: number }) {
  const pct = Math.min((score / max) * 100, 100)
  const barColor = pct >= 80 ? '#00D68F' : pct >= 50 ? '#FFD93D' : pct >= 25 ? '#FF8C00' : '#FF3B5C'
  return (
    <div className="flex items-center gap-1.5">
      <div className="flex-1 h-1.5 rounded-full bg-bg-elevated overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${pct}%`, backgroundColor: barColor }}
        />
      </div>
      <span className="font-mono text-xs tabular-nums text-text-secondary w-8">
        {score.toFixed(1)}
      </span>
    </div>
  )
}
