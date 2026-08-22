import { useState, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Search, ChevronDown, RotateCcw, ShieldCheck, ShieldOff,
  ArrowRight, ArrowLeft, Scale, Radar,
} from 'lucide-react'
import { resolveAudit, getAudits , useAudits} from '@/data/repository'
import { SeverityBadge, LayerBadge, VerdictBadge } from '@/components/Badges'
import { AxisBreakdownChart } from '@/charts/AxisBreakdownChart'
import { VerdictDonut } from '@/charts/VerdictDonut'
import { RefusalQualityChart } from '@/charts/RefusalQualityChart'
import { useApp } from '@/App'
import { startReplay } from '@/data/api'
import { ASI_CATEGORIES } from '@/types'
import type { Attack, AttackVerdict, LayerKey, Severity } from '@/types'

type AttackWithCategory = Attack & { category: string }

export function AttacksPage() {
  const { selectedAuditId, setSelectedAuditId, addToast, setCurrentPage } = useApp()
  useAudits()   // abonnement : rafraîchit la page après un audit
  const audits = getAudits()
  const audit = resolveAudit(selectedAuditId)!

  const [search, setSearch] = useState('')
  const [filterCategory, setFilterCategory] = useState<string>('all')
  const [filterSeverity, setFilterSeverity] = useState<Severity | 'all'>('all')
  const [filterVerdict, setFilterVerdict] = useState<AttackVerdict | 'all'>('all')
  const [filterLayer, setFilterLayer] = useState<LayerKey | 'all'>('all')
  const [expanded, setExpanded] = useState<Set<string>>(new Set([audit.agents[0]?.asi_category]))

  const allAttacks: AttackWithCategory[] = useMemo(() =>
    audit.agents
      .filter(a => a.status === 'completed')
      .flatMap(a => a.attacks.map(atk => ({ ...atk, category: a.asi_category })))
  , [audit])

  const filtered = useMemo(() => allAttacks.filter(a => {
    if (filterCategory !== 'all' && a.category !== filterCategory) return false
    if (filterSeverity !== 'all' && a.severity !== filterSeverity) return false
    if (filterVerdict !== 'all' && a.verdict !== filterVerdict) return false
    if (filterLayer !== 'all' && a.layer !== filterLayer) return false
    if (search) {
      const q = search.toLowerCase()
      if (!a.prompt.toLowerCase().includes(q) && !a.response.toLowerCase().includes(q)) return false
    }
    return true
  }), [allAttacks, filterCategory, filterSeverity, filterVerdict, filterLayer, search])

  const byCategory = useMemo(() => {
    const groups: Record<string, AttackWithCategory[]> = {}
    filtered.forEach(a => { (groups[a.category] ??= []).push(a) })
    return groups
  }, [filtered])

  const stats = useMemo(() => ({
    total: filtered.length,
    breached: filtered.filter(a => a.verdict === 'compromised').length,
    resisted: filtered.filter(a => a.verdict === 'resisted').length,
  }), [filtered])

  // Agent principal de l'audit — porte les couches et les statistiques du juge.
  const mainAgent = useMemo(
    () => audit.agents.find(a => a.status === 'completed'),
  [audit])

  const toggle = (cat: string) => setExpanded(prev => {
    const next = new Set(prev)
    next.has(cat) ? next.delete(cat) : next.add(cat)
    return next
  })

  /**
   * Rejoue les attaques qui avaient percé, sur la même cible.
   * Le rejeu porte sur TOUTES les failles de l'audit, pas sur une seule : une
   * faille isolée ne dit rien, et le coût par attaque est identique.
   */
  const replayFailures = async () => {
    try {
      const r = await startReplay({
        audit_id: audit.id, only_compromised: true, repeat: 3, profile: audit.profile,
      })
      addToast({
        type: 'info', title: 'Rejeu lancé',
        message: `${r.attacks_available} attaque(s) disponibles — suivi dans Live Audit`,
      })
      setCurrentPage('live')
    } catch (e) {
      addToast({ type: 'error', title: 'Rejeu impossible', message: (e as Error).message })
    }
  }

  const selectClass = 'px-3 py-2 rounded-xl bg-bg-surface border border-border text-sm ' +
    'text-text-primary outline-none hover:border-border-bright transition-colors'

  return (
    <div className="p-6 space-y-5 max-w-[1500px] mx-auto">
      {/* ─── En-tête : le bilan d'abord, les filtres ensuite ─── */}
      <div className="flex items-end justify-between gap-6 flex-wrap">
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.14em] text-text-muted">
            Banc d'attaques
          </div>
          <h1 className="text-2xl font-bold text-text-primary mt-1">
            Attaques envoyées et réponses de la cible
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            {audit.target_name} · profil {audit.profile} · {audit.model}
          </p>
        </div>
        <div className="flex items-stretch gap-3">
          <StatTile label="Attaques" value={stats.total} tone="neutral" icon={Radar} />
          <StatTile label="Résisté" value={stats.resisted} tone="low" icon={ShieldCheck} />
          <StatTile label="Compromis" value={stats.breached} tone="critical" icon={ShieldOff} />
        </div>
      </div>

      {/* ─── Graphiques d'analyse ─── */}
      {mainAgent && (
        <div className="grid gap-5 lg:grid-cols-[1.4fr_1fr_1.2fr]">
          <div className="card p-5">
            <h3 className="text-sm font-semibold text-text-primary mb-1">
              D'où vient le score
            </h3>
            <p className="text-[11px] text-text-muted mb-2">
              Décomposition par axe et par couche — chacun avec son poids
            </p>
            <AxisBreakdownChart agent={mainAgent} />
          </div>
          <div className="card p-5">
            <h3 className="text-sm font-semibold text-text-primary mb-1">
              Verdicts des attaques
            </h3>
            <p className="text-[11px] text-text-muted mb-2">
              Les non évaluées sont comptées à part
            </p>
            <VerdictDonut attacks={allAttacks} />
          </div>
          <div className="card p-5">
            <h3 className="text-sm font-semibold text-text-primary mb-1">
              Les défenses tiennent-elles par principe ?
            </h3>
            <p className="text-[11px] text-text-muted mb-3">
              Un refus accidentel ne protège pas d'une variante mieux formée
            </p>
            <RefusalQualityChart agent={mainAgent} />
          </div>
        </div>
      )}

      <div className="flex items-center gap-3 flex-wrap">
        <select
          value={audit.id}
          onChange={e => setSelectedAuditId(e.target.value)}
          className={selectClass}
        >
          {audits.map(a => (
            <option key={a.id} value={a.id}>
              {a.target_name} — {a.global_score}/100 — {a.started_at.slice(0, 10)}
            </option>
          ))}
        </select>

        <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-bg-surface border border-border flex-1 min-w-[220px]">
          <Search size={16} className="text-text-muted" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Rechercher dans les prompts et les réponses…"
            className="flex-1 bg-transparent text-sm text-text-primary placeholder:text-text-muted outline-none"
          />
        </div>

        <select value={filterCategory} onChange={e => setFilterCategory(e.target.value)} className={selectClass}>
          <option value="all">Toutes catégories</option>
          {ASI_CATEGORIES.map(c => <option key={c.id} value={c.id}>{c.short}</option>)}
        </select>
        <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value as Severity | 'all')} className={selectClass}>
          <option value="all">Toutes sévérités</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select value={filterVerdict} onChange={e => setFilterVerdict(e.target.value as AttackVerdict | 'all')} className={selectClass}>
          <option value="all">Tous verdicts</option>
          <option value="resisted">Résisté</option>
          <option value="compromised">Compromis</option>
          <option value="partial">Partiel</option>
        </select>
        <select value={filterLayer} onChange={e => setFilterLayer(e.target.value as LayerKey | 'all')} className={selectClass}>
          <option value="all">Toutes couches</option>
          <option value="behavioral">Behavioral</option>
          <option value="static">Static</option>
          <option value="dynamic">Dynamic</option>
        </select>
      </div>

      {/* ─── Catégories ─── */}
      <div className="space-y-2.5">
        {ASI_CATEGORIES.map(cat => {
          const attacks = byCategory[cat.id] || []
          const agent = audit.agents.find(a => a.asi_category === cat.id)
          const isPending = !agent || agent.status === 'pending'
          const isExpanded = expanded.has(cat.id)
          const breached = attacks.filter(a => a.verdict === 'compromised').length

          return (
            <div key={cat.id} className="card overflow-hidden">
              <button
                onClick={() => !isPending && toggle(cat.id)}
                disabled={isPending}
                className={`w-full flex items-center gap-3 p-4 text-left transition-colors
                  ${isPending ? 'opacity-55 cursor-not-allowed' : 'hover:bg-bg-elevated'}`}
              >
                <ChevronDown
                  size={18}
                  className={`text-text-muted transition-transform duration-300 ${isExpanded ? 'rotate-180' : ''}`}
                />
                <span className="font-mono text-xs font-semibold text-text-muted w-14">{cat.short}</span>
                <span className="text-sm font-semibold text-text-primary flex-1">{cat.name}</span>

                {isPending ? (
                  <span className="text-xs text-text-muted italic">Non implémenté — Phase 2</span>
                ) : (
                  <>
                    {breached > 0 && (
                      <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold
                                       bg-severity-critical/10 text-severity-critical border border-severity-critical/25">
                        {breached} compromis
                      </span>
                    )}
                    <span className="text-xs text-text-secondary tabular">{attacks.length} attaque(s)</span>
                    <ScorePill score={agent.score} />
                  </>
                )}
              </button>

              <AnimatePresence initial={false}>
                {isExpanded && !isPending && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.28, ease: 'easeOut' }}
                    className="border-t border-border overflow-hidden"
                  >
                    {attacks.length > 0 ? (
                      attacks.map((atk, i) => (
                        <AttackRow key={atk.id} attack={atk} index={i}
                                   onReplay={() => replayFailures()} />
                      ))
                    ) : (
                      <div className="p-5 text-sm text-text-muted text-center">
                        Aucune attaque ne correspond aux filtres.
                      </div>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          )
        })}
      </div>
    </div>
  )
}

/* ─────────────────────────── sous-composants ─────────────────────────── */

function StatTile({ label, value, tone, icon: Icon }: {
  label: string; value: number
  tone: 'neutral' | 'low' | 'critical'
  icon: typeof Radar
}) {
  const color = tone === 'critical' ? 'var(--sev-critical)'
    : tone === 'low' ? 'var(--sev-low)' : 'var(--text-secondary)'
  return (
    <div className="card px-4 py-3 min-w-[118px]">
      <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-text-muted">
        <Icon size={12} style={{ color }} /> {label}
      </div>
      <div className="text-2xl font-bold mt-1 tabular font-mono" style={{ color }}>{value}</div>
    </div>
  )
}

function ScorePill({ score }: { score: number }) {
  const color = score >= 8 ? 'var(--sev-low)' : score >= 5 ? 'var(--sev-medium)' : 'var(--sev-critical)'
  return (
    <span
      className="font-mono text-sm font-bold px-2.5 py-1 rounded-lg tabular"
      style={{ color, background: `color-mix(in srgb, ${color} 10%, transparent)` }}
    >
      {score.toFixed(1)}
    </span>
  )
}

function AttackRow({ attack, index, onReplay }: {
  attack: Attack; index: number; onReplay: () => void
}) {
  const breached = attack.verdict === 'compromised'

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(index * 0.04, 0.3), duration: 0.25 }}
      className={`px-5 py-5 border-b-2 last:border-b-0 relative
        ${breached
          ? 'bg-severity-critical/[0.045] border-b-severity-critical/15'
          : 'border-b-border'}`}
    >
      {breached && (
        <span className="absolute left-0 top-0 bottom-0 w-1 bg-severity-critical" />
      )}

      {/* Bandeau d'identité de l'attaque — numéro, technique, verdict */}
      <div className="flex items-center gap-2.5 flex-wrap mb-4">
        <span
          className="w-7 h-7 rounded-lg flex items-center justify-center text-[11px]
                     font-mono font-bold shrink-0"
          style={{
            color: breached ? 'var(--sev-critical)' : 'var(--text-secondary)',
            background: breached
              ? 'color-mix(in srgb, var(--sev-critical) 12%, transparent)'
              : 'var(--bg-elevated)',
          }}
        >
          {String(index + 1).padStart(2, '0')}
        </span>
        <span className="px-2.5 py-1 rounded-lg bg-bg-elevated text-[13px] font-mono font-semibold
                         text-text-primary border border-border">
          {attack.technique}
        </span>
        <span className="text-xs font-semibold text-text-secondary px-2 py-1 rounded-lg bg-bg-elevated">
          {attack.axis}
        </span>
        <LayerBadge layer={attack.layer} />
        <VerdictBadge verdict={attack.verdict} />
        {attack.severity && <SeverityBadge severity={attack.severity} />}
        <button
          onClick={onReplay}
          disabled={!breached}
          className="ml-auto text-xs font-medium text-text-secondary hover:text-brand
                     flex items-center gap-1.5 transition-colors px-2.5 py-1.5 rounded-lg
                     border border-border hover:border-brand/30 hover:bg-brand/[0.05]
                     disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:text-text-secondary"
          title={breached
            ? "Renvoyer cette attaque à la cible pour vérifier si la faille persiste"
            : "Le rejeu ne concerne que les attaques qui ont percé"}
        >
          <RotateCcw size={12} /> Rejouer
        </button>
      </div>

      <div className="grid gap-3 lg:grid-cols-2">
        <CodePanel
          label="Prompt envoyé"
          text={attack.prompt}
          accent="var(--brand)"
          icon={ArrowRight}
          scanning={breached}
        />
        <CodePanel
          label="Réponse de la cible"
          text={attack.response}
          accent={breached ? 'var(--sev-critical)' : 'var(--layer-behavioral)'}
          icon={ArrowLeft}
        />
      </div>

      <div className="mt-3">
        <FieldLabel icon={Scale}>Verdict du juge LLM</FieldLabel>
        <div
          className="rounded-xl border-l-[3px] border border-border p-3.5"
          style={{
            borderLeftColor: breached ? 'var(--sev-critical)' : 'var(--sev-low)',
            background: 'var(--bg-elevated)',
          }}
        >
          <p className="text-[13px] text-text-primary leading-relaxed">{attack.judge_reasoning}</p>
        </div>
      </div>

      {attack.multi_turn && attack.multi_turn.length > 0 && (
        <div className="mt-4">
          <FieldLabel>Conversation multi-tours — PyRIT</FieldLabel>
          <div className="relative pl-4 space-y-2">
            <span className="absolute left-[5px] top-2 bottom-2 w-px bg-border" />
            {attack.multi_turn.map(turn => (
              <div key={turn.turn} className="relative">
                <span
                  className="absolute -left-4 top-3.5 w-2.5 h-2.5 rounded-full border-2 border-bg-surface"
                  style={{
                    background: turn.is_failure_point
                      ? 'var(--sev-critical)' : 'var(--border-bright)',
                  }}
                />
                <div
                  className={`rounded-xl border p-3 transition-colors
                    ${turn.is_failure_point
                      ? 'border-severity-critical/40 bg-severity-critical/[0.06]'
                      : 'border-border bg-bg-elevated'}`}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-xs font-mono font-bold text-text-muted">T{turn.turn}</span>
                    {turn.verdict && <VerdictBadge verdict={turn.verdict} />}
                    {turn.is_failure_point && (
                      <span className="px-2 py-0.5 rounded-md bg-severity-critical text-white
                                       text-[10px] font-bold tracking-wide">
                        ÉCHEC ICI
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-text-secondary mb-1.5 flex gap-2">
                    <span className="font-mono text-brand shrink-0">▸</span>
                    <span>{turn.prompt}</span>
                  </div>
                  <div className="text-xs text-text-primary flex gap-2">
                    <span className="font-mono text-layer-behavioral shrink-0">◂</span>
                    <span>{turn.response}</span>
                  </div>
                  {turn.judge_reasoning && (
                    <div className="text-xs text-text-muted mt-2 italic border-t border-border pt-2">
                      {turn.judge_reasoning}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </motion.div>
  )
}

function FieldLabel({ children, icon: Icon, color }: {
  children: React.ReactNode; icon?: typeof Scale; color?: string
}) {
  return (
    <div
      className="text-[11px] font-bold uppercase tracking-[0.12em] mb-2 flex items-center gap-1.5"
      style={{ color: color ?? 'var(--text-secondary)' }}
    >
      {Icon && <Icon size={12} />}
      {children}
    </div>
  )
}

/**
 * Bloc de payload. Toujours sur fond sombre, même en thème clair : une charge
 * adverse doit se lire comme du terminal. Le contenu passe par {} — React
 * échappe, aucun traitement manuel (voir la note en bas de fichier d'origine).
 */
function CodePanel({ label, text, accent, icon: Icon, scanning = false }: {
  label: string; text: string; accent: string
  icon: typeof ArrowRight; scanning?: boolean
}) {
  return (
    <div>
      <FieldLabel icon={Icon} color={accent}>{label}</FieldLabel>
      <div
        className={`code-block p-3.5 border-l-4 max-h-56 overflow-auto terminal-scroll
                    ${scanning ? 'scan-frame' : ''}`}
        style={{ borderLeftColor: accent }}
      >
        <pre className="text-[13px] font-mono whitespace-pre-wrap break-words leading-[1.65]">
          {text}
        </pre>
      </div>
    </div>
  )
}
