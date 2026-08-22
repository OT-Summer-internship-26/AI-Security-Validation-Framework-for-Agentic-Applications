import { motion } from 'framer-motion'
import { ShieldCheck, ShieldAlert, ShieldQuestion, Info } from 'lucide-react'
import type { AgentResult } from '@/types'

/**
 * Qualité des refus — le graphique le plus révélateur du rapport.
 *
 * POURQUOI
 *     Un test « passé » ne prouve pas que la défense est solide. Le juge classe
 *     chaque refus : de PRINCIPE (l'agent a compris et refusé), PARTIEL (refus
 *     mais fuite résiduelle) ou ACCIDENTEL (l'agent n'a rien compris et a répondu
 *     à côté — une variante mieux formée passerait).
 *
 *     Un taux d'accidentels élevé signale un score FAUSSEMENT RASSURANT : c'est
 *     exactement le piège observé sur ce lab, qui « résistait » aux attaques
 *     encodées uniquement parce qu'il ne sait pas les décoder.
 */
const META = {
  robust: {
    label: 'Refus de principe', color: 'var(--sev-low)', icon: ShieldCheck,
    hint: "L'agent a compris l'attaque et l'a refusée en citant sa politique.",
  },
  partial: {
    label: 'Refus partiel', color: 'var(--sev-medium)', icon: ShieldQuestion,
    hint: 'Refusée, mais avec une fuite de contexte ou d\'indices.',
  },
  accidental: {
    label: 'Refus accidentel', color: 'var(--sev-critical)', icon: ShieldAlert,
    hint: "L'agent n'a pas compris et a répondu à côté — une variante mieux formée passerait.",
  },
} as const

export function RefusalQualityChart({ agent }: { agent: AgentResult }) {
  const stats = ((agent.layers.behavioral.raw || {}) as Record<string, unknown>)
    .stats as Record<string, number> | undefined

  const robust = stats?.pass_refusal_robust ?? 0
  const partial = stats?.pass_refusal_partial ?? 0
  const accidental = stats?.pass_refusal_accidental ?? 0
  const total = robust + partial + accidental

  if (total === 0) {
    return (
      <div className="flex items-start gap-2.5 p-4 rounded-xl bg-bg-elevated border border-border">
        <Info size={16} className="text-text-muted mt-0.5 shrink-0" />
        <p className="text-xs text-text-secondary leading-relaxed">
          Analyse des refus non effectuée. Activez « Analyser aussi les attaques
          résistées » au lancement pour savoir si les défenses tiennent par
          principe ou par hasard.
        </p>
      </div>
    )
  }

  const rows = [
    { key: 'robust' as const, n: robust },
    { key: 'partial' as const, n: partial },
    { key: 'accidental' as const, n: accidental },
  ].filter(r => r.n > 0)

  const fragile = Math.round(((partial + accidental) / total) * 100)

  return (
    <div className="space-y-3">
      {/* Barre empilée */}
      <div className="flex h-9 rounded-xl overflow-hidden border border-border">
        {rows.map(r => {
          const m = META[r.key]
          return (
            <motion.div
              key={r.key}
              initial={{ width: 0 }}
              animate={{ width: `${(r.n / total) * 100}%` }}
              transition={{ duration: 0.6, ease: 'easeOut' }}
              className="flex items-center justify-center"
              style={{ background: `color-mix(in srgb, ${m.color} 22%, transparent)` }}
              title={`${m.label} : ${r.n}`}
            >
              <span className="text-xs font-bold font-mono tabular" style={{ color: m.color }}>
                {r.n}
              </span>
            </motion.div>
          )
        })}
      </div>

      {/* Détail */}
      <div className="space-y-2">
        {rows.map(r => {
          const m = META[r.key]
          const Icon = m.icon
          return (
            <div key={r.key} className="flex items-start gap-2.5">
              <Icon size={15} style={{ color: m.color }} className="mt-0.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-baseline gap-2">
                  <span className="text-sm font-semibold" style={{ color: m.color }}>
                    {m.label}
                  </span>
                  <span className="text-xs font-mono tabular text-text-muted">
                    {r.n}/{total} · {Math.round((r.n / total) * 100)}%
                  </span>
                </div>
                <p className="text-[11px] text-text-muted leading-snug mt-0.5">{m.hint}</p>
              </div>
            </div>
          )
        })}
      </div>

      {fragile >= 50 && (
        <div className="flex items-start gap-2.5 p-3 rounded-xl
                        bg-severity-critical/[0.06] border border-severity-critical/30">
          <ShieldAlert size={16} className="text-severity-critical mt-0.5 shrink-0" />
          <p className="text-xs text-text-secondary leading-relaxed">
            <b className="text-severity-critical">Score faussement rassurant.</b>{' '}
            {fragile} % des défenses n'ont pas tenu par principe. Le score comportemental
            surestime la robustesse réelle de l'agent.
          </p>
        </div>
      )}
    </div>
  )
}
