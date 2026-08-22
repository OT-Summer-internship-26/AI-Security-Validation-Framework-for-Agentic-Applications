import { useMemo } from 'react'
import { motion } from 'framer-motion'
import {
  ArrowRight, ShieldAlert, Ban, Radar as RadarIcon, Layers, Repeat,
  TriangleAlert as AlertTriangle, CircleCheck as CheckCircle, Info, Wrench,
} from 'lucide-react'
import { RiskBadge, ConfidenceBadge, SeverityBadge } from '@/components/Badges'
import { AsioRadarChart } from '@/charts/AsioRadarChart'
import {
  getAudits, getLatestAudit, getDefaultPolicy, useAudits,
} from '@/data/repository'
import {
  comparableSeries, groupVulnerabilities, coverage, inferMode, targetOf,
  MODE_LABEL, axesUsed,
} from '@/data/insights'
import { evaluateGate, VERDICT_META } from '@/data/gate'
import { useApp } from '@/App'
import { ASI_CATEGORIES } from '@/types'

export function OverviewPage() {
  const { setCurrentPage, setSelectedAuditId } = useApp()
  useAudits()
  const audits = getAudits()
  const latest = getLatestAudit()!

  // Seuls les audits de MÊME cible et MÊME configuration sont comparables.
  const series = useMemo(() => comparableSeries(audits, latest), [audits, latest])
  const groups = useMemo(() => groupVulnerabilities(audits), [audits])
  const cov = useMemo(() => coverage(audits, ASI_CATEGORIES), [audits])

  const open = groups.filter(g => g.stillOpen)
  const openCritical = open.filter(g => g.severity === 'Critical')
  const openHigh = open.filter(g => g.severity === 'High')
  const reproduced = open.filter(g => g.occurrences > 1)

  const gate = evaluateGate(latest, getDefaultPolicy())
  const gateMeta = VERDICT_META[gate.verdict]
  const mode = inferMode(latest)
  const axes = axesUsed(latest)

  const prev = series[1]
  const delta = prev ? Math.round((latest.global_score - prev.global_score) * 10) / 10 : null

  const scoreColor = latest.global_score >= 86 ? 'var(--sev-info)'
    : latest.global_score >= 71 ? 'var(--sev-low)'
    : latest.global_score >= 51 ? 'var(--sev-medium)'
    : latest.global_score >= 31 ? 'var(--sev-high)' : 'var(--sev-critical)'

  const goto = (id: string, page: 'attacks' | 'history') => {
    setSelectedAuditId(id); setCurrentPage(page)
  }

  return (
    <div className="p-6 space-y-6 max-w-[1500px] mx-auto pb-16">

      {/* ─── Posture — le score AVEC son contexte de mesure ─── */}
      <motion.div
        initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}
        className="card p-7 grid gap-8 lg:grid-cols-[minmax(300px,400px)_1fr] items-start"
      >
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert size={15} className="text-brand" />
            <span className="text-[11px] font-semibold uppercase tracking-[0.15em] text-text-muted">
              Dernier audit
            </span>
          </div>

          <div className="flex items-baseline gap-2 mt-2">
            <motion.span
              initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.08, type: 'spring', stiffness: 180, damping: 20 }}
              className="text-[86px] leading-[0.85] font-bold font-mono tabular"
              style={{ color: scoreColor }}
            >
              {latest.global_score}
            </motion.span>
            <span className="text-xl text-text-muted font-medium">/100</span>
            {delta !== null && delta !== 0 && (
              <span
                className="text-sm font-mono font-bold ml-1"
                style={{ color: delta > 0 ? 'var(--sev-low)' : 'var(--sev-critical)' }}
                title="vs l'audit précédent de même configuration"
              >
                {delta > 0 ? '+' : ''}{delta}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2 mt-4 flex-wrap">
            <RiskBadge level={latest.risk_level} />
            <ConfidenceBadge confidence={latest.confidence} />
            <span
              className="px-2.5 py-1 rounded-lg text-[11px] font-bold uppercase tracking-wide
                         flex items-center gap-1.5"
              style={{ color: gateMeta.color,
                       background: `color-mix(in srgb, ${gateMeta.color} 11%, transparent)` }}
            >
              {gate.verdict === 'BLOCKED' && <Ban size={12} />}{gateMeta.short}
            </span>
          </div>

          {/* Contexte de mesure : sans lui, le score n'est pas interprétable. */}
          <div className="mt-5 pt-4 border-t border-border space-y-1.5 text-xs">
            <Line k="Cible" v={targetOf(latest)} mono />
            <Line k="Mode" v={MODE_LABEL[mode]} />
            <Line k="Axes exécutés" v={axes.join(' · ') || 'aucun'} mono />
            <Line k="Profil LLM" v={`${latest.profile} · ${latest.model}`} mono />
          </div>

          {mode !== 'complete' && (
            <p className="text-[11px] text-severity-high mt-3 flex items-start gap-1.5">
              <AlertTriangle size={12} className="mt-0.5 shrink-0" />
              Configuration partielle — ce score ne se compare qu'à d'autres audits
              lancés dans le même mode.
            </p>
          )}
        </div>

        <div>
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-text-primary">Couverture OWASP ASI</h3>
            <button
              onClick={() => goto(latest.id, 'attacks')}
              className="text-xs text-brand hover:underline flex items-center gap-1"
            >
              Voir les attaques <ArrowRight size={12} />
            </button>
          </div>
          <AsioRadarChart audit={latest} size={280} />
        </div>
      </motion.div>

      {/* ─── Indicateurs actionnables ─── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Kpi
          icon={Ban} label="Critical ouvertes" value={openCritical.length}
          color="var(--sev-critical)"
          note={openCritical.length ? 'bloquent le déploiement' : 'aucune faille bloquante'}
          onClick={() => goto(latest.id, 'attacks')}
        />
        <Kpi
          icon={AlertTriangle} label="High ouvertes" value={openHigh.length}
          color="var(--sev-high)"
          note={`budget de ${getDefaultPolicy().max_high_findings} toléré`}
        />
        <Kpi
          icon={Repeat} label="Failles reproduites" value={reproduced.length}
          color="var(--sev-info)"
          note="vues sur plusieurs audits — certaines"
        />
        <Kpi
          icon={RadarIcon} label="Couverture" value={`${cov.measured}/${cov.total}`}
          color={cov.measured >= 8 ? 'var(--sev-low)' : 'var(--sev-medium)'}
          note={cov.neverAudited.length
            ? `jamais audité : ${cov.neverAudited.slice(0, 4).join(', ')}${cov.neverAudited.length > 4 ? '…' : ''}`
            : 'référentiel couvert'}
        />
      </div>

      {/* ─── Dette de sécurité ─── */}
      <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} className="card p-5">
        <div className="flex items-center justify-between mb-1 flex-wrap gap-2">
          <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <Wrench size={15} className="text-brand" /> À corriger en priorité
          </h3>
          <span className="text-[11px] text-text-muted">
            {open.length} faille(s) distincte(s) encore présente(s)
          </span>
        </div>
        <p className="text-[11px] text-text-muted mb-4">
          Failles dédupliquées et présentes dans le dernier audit de leur cible.
          Le compteur indique dans combien d'audits la faille a été reproduite.
        </p>

        <div className="space-y-2">
          {open.slice(0, 6).map((g, i) => {
            const cat = ASI_CATEGORIES.find(c => c.id === g.category)
            return (
              <motion.button
                key={g.key}
                initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
                onClick={() => goto(latest.id, 'attacks')}
                className="w-full flex items-center gap-3 p-3.5 rounded-xl border border-border
                           hover:border-border-bright hover:bg-bg-elevated transition-all text-left group"
              >
                <SeverityBadge severity={g.severity} />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-text-primary truncate">{g.title}</div>
                  <div className="text-xs text-text-muted mt-0.5">
                    {cat?.short} · couche {g.layer}
                    {g.remediation && ` · ${g.remediation.slice(0, 70)}`}
                  </div>
                </div>
                {g.occurrences > 1 && (
                  <span
                    className="px-2 py-0.5 rounded-lg text-[10px] font-bold font-mono shrink-0"
                    style={{ color: 'var(--sev-critical)',
                             background: 'color-mix(in srgb, var(--sev-critical) 10%, transparent)' }}
                    title={`Reproduite dans ${g.occurrences} audits — certaine`}
                  >
                    ×{g.occurrences}
                  </span>
                )}
                <ArrowRight size={15} className="text-text-muted group-hover:text-brand
                                                 group-hover:translate-x-0.5 transition-all shrink-0" />
              </motion.button>
            )
          })}
          {open.length === 0 && (
            <div className="flex items-center gap-2.5 p-4 text-sm text-text-secondary">
              <CheckCircle size={16} className="text-severity-low" />
              Aucune faille ouverte dans les derniers audits.
            </div>
          )}
        </div>
      </motion.div>

      {/* ─── Évolution — série comparable UNIQUEMENT ─── */}
      <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} className="card p-5">
        <div className="flex items-center justify-between mb-1 flex-wrap gap-2">
          <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <Layers size={15} className="text-brand" /> Évolution — {targetOf(latest)}
          </h3>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded-lg bg-bg-elevated text-text-secondary">
            mode {MODE_LABEL[mode].toLowerCase()}
          </span>
        </div>
        <p className="text-[11px] text-text-muted mb-4">
          Seuls les audits de même cible et même configuration sont tracés — comparer
          un contrôle rapide à un audit complet n'aurait aucun sens.
        </p>

        {series.length < 2 ? (
          <div className="flex items-start gap-2.5 p-4 rounded-xl bg-bg-elevated border border-border">
            <Info size={16} className="text-text-muted mt-0.5 shrink-0" />
            <p className="text-sm text-text-secondary">
              Un seul audit dans cette configuration. Relancez le même mode sur la
              même cible pour obtenir une évolution interprétable.
            </p>
          </div>
        ) : (
          <div className="space-y-2.5">
            {series.slice(0, 8).map(a => {
              const col = a.global_score >= 71 ? 'var(--sev-low)'
                : a.global_score >= 51 ? 'var(--sev-medium)'
                : a.global_score >= 31 ? 'var(--sev-high)' : 'var(--sev-critical)'
              return (
                <button
                  key={a.id} onClick={() => goto(a.id, 'history')}
                  className="w-full flex items-center gap-3 hover:opacity-80 transition-opacity"
                >
                  <span className="text-xs text-text-muted font-mono w-[92px] text-left tabular">
                    {a.started_at.slice(0, 10)}
                  </span>
                  <div className="flex-1 h-2 rounded-full bg-bg-elevated overflow-hidden">
                    <motion.div
                      className="h-full rounded-full"
                      style={{ background: col }}
                      initial={{ width: 0 }}
                      animate={{ width: `${a.global_score}%` }}
                      transition={{ duration: 0.5 }}
                    />
                  </div>
                  <span className="font-mono text-sm font-bold tabular w-14 text-right"
                        style={{ color: col }}>
                    {a.global_score}
                  </span>
                  <RiskBadge level={a.risk_level} />
                </button>
              )
            })}
          </div>
        )}
      </motion.div>
    </div>
  )
}

/* ─────────────────────── sous-composants ─────────────────────── */

function Line({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <span className="text-text-muted shrink-0">{k}</span>
      <span className={`text-right text-text-secondary truncate ${mono ? 'font-mono text-[11px]' : ''}`}
            title={v}>
        {v}
      </span>
    </div>
  )
}

function Kpi({ icon: Icon, label, value, color, note, onClick }: {
  icon: typeof Ban; label: string; value: string | number
  color: string; note: string; onClick?: () => void
}) {
  const Tag = onClick ? 'button' : 'div'
  return (
    <Tag
      onClick={onClick}
      className={`card p-5 text-left w-full ${onClick ? 'card-hover cursor-pointer' : ''}`}
    >
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">
          {label}
        </span>
        <Icon size={17} style={{ color }} />
      </div>
      <div className="font-mono text-[34px] font-bold tabular leading-none mt-2" style={{ color }}>
        {value}
      </div>
      <div className="text-[11px] text-text-muted mt-2 leading-snug">{note}</div>
    </Tag>
  )
}
