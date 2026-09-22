import { useState, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Search, Download, ChevronRight, X, Clock, Coins, ShieldCheck, FileText,
} from 'lucide-react'
import { getAudits, getAudit, getDefaultPolicy, useAudits } from '@/data/repository'
import { openReport } from '@/data/api'
import { inferMode, targetOf, MODE_LABEL, axesUsed } from '@/data/insights'
import { evaluateGate, VERDICT_META } from '@/data/gate'
import { ScoreBar } from '@/components/ScoreBar'
import { JudgeReliability } from '@/components/JudgeReliability'
import { RiskBadge, SeverityBadge, ConfidenceBadge } from '@/components/Badges'
import { AsioRadarChart } from '@/charts/AsioRadarChart'
import { CategoryBarChart } from '@/charts/CategoryBarChart'
import { useApp } from '@/App'
import type { Audit, RiskLevel } from '@/types'

type SortKey = 'date' | 'score' | 'duration' | 'cost'
type SortDir = 'asc' | 'desc'

export function HistoryPage() {
  const { selectedAuditId, setSelectedAuditId, addToast } = useApp()
  useAudits()   // abonnement : rafraîchit après un audit
  const [search, setSearch] = useState('')
  const [riskFilter, setRiskFilter] = useState<RiskLevel | 'all'>('all')
  const [modeFilter, setModeFilter] = useState<'all' | 'quick' | 'partial' | 'complete'>('all')
  const [sortKey, setSortKey] = useState<SortKey>('date')
  const [sortDir, setSortDir] = useState<SortDir>('desc')

  const filtered = useMemo(() => {
    let result = getAudits().filter(a =>
      a.target_name.toLowerCase().includes(search.toLowerCase())
    )
    if (riskFilter !== 'all') {
      result = result.filter(a => a.risk_level === riskFilter)
    }
    // Filtrer par mode est indispensable : comparer un contrôle rapide à un
    // audit complet n'a pas de sens, et les mélanger fausse la lecture du tableau.
    if (modeFilter !== 'all') {
      result = result.filter(a => inferMode(a) === modeFilter)
    }
    result.sort((a, b) => {
      let cmp = 0
      if (sortKey === 'date') cmp = new Date(a.started_at).getTime() - new Date(b.started_at).getTime()
      else if (sortKey === 'score') cmp = a.global_score - b.global_score
      else if (sortKey === 'duration') cmp = a.duration_s - b.duration_s
      else if (sortKey === 'cost') cmp = a.cost_tokens - b.cost_tokens
      return sortDir === 'desc' ? -cmp : cmp
    })
    return result
  }, [search, riskFilter, modeFilter, sortKey, sortDir])

  const selectedAudit = getAudit(selectedAuditId) || null

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setSortDir('desc') }
  }

  const exportData = (format: 'csv' | 'json') => {
    const data = format === 'json'
      ? JSON.stringify(filtered, null, 2)
      : ['id,target,score,risk,date,duration_s,cost_tokens']
        .concat(filtered.map(a =>
          `${a.id},${a.target_name},${a.global_score},${a.risk_level},${a.started_at},${a.duration_s},${a.cost_tokens}`
        )).join('\n')
    const blob = new Blob([data], { type: format === 'json' ? 'application/json' : 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `audits-export.${format}`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-bg-surface border border-border flex-1 min-w-[200px]">
          <Search size={16} className="text-text-muted" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Rechercher une cible..."
            className="flex-1 bg-transparent text-sm text-text-primary placeholder:text-text-muted outline-none"
          />
        </div>
        <select
          value={riskFilter}
          onChange={e => setRiskFilter(e.target.value as RiskLevel | 'all')}
          className="px-3 py-2 rounded-lg bg-bg-surface border border-border text-sm text-text-primary outline-none"
        >
          <option value="all">Tous les risques</option>
          <option value="Critique">Critique</option>
          <option value="Élevé">Élevé</option>
          <option value="Moyen">Moyen</option>
          <option value="Faible">Faible</option>
          <option value="Sécurisé">Sécurisé</option>
        </select>
        <select
          value={modeFilter}
          onChange={e => setModeFilter(e.target.value as typeof modeFilter)}
          className="px-3 py-2 rounded-lg bg-bg-surface border border-border text-sm text-text-primary outline-none"
        >
          <option value="all">Tous les modes</option>
          <option value="complete">Audit complet</option>
          <option value="partial">Partiel</option>
          <option value="quick">Contrôle rapide</option>
        </select>
        <button
          onClick={() => exportData('csv')}
          className="px-3 py-2 rounded-lg bg-bg-surface border border-border text-sm text-text-secondary hover:text-text-primary transition-colors flex items-center gap-2"
        >
          <Download size={14} /> CSV
        </button>
        <button
          onClick={() => exportData('json')}
          className="px-3 py-2 rounded-lg bg-bg-surface border border-border text-sm text-text-secondary hover:text-text-primary transition-colors flex items-center gap-2"
        >
          <Download size={14} /> JSON
        </button>
      </div>

      <div className="card overflow-x-auto">
        <table className="w-full text-sm min-w-[940px]">
          <thead>
            <tr className="border-b border-border bg-bg-elevated">
              <Th onClick={() => toggleSort('date')} active={sortKey === 'date'} dir={sortDir}>
                Date
              </Th>
              <Th>Périmètre</Th>
              <Th onClick={() => toggleSort('score')} active={sortKey === 'score'} dir={sortDir}>
                Score
              </Th>
              <Th>Risque</Th>
              <Th align="right">Failles</Th>
              <Th align="right">Attaques</Th>
              <Th onClick={() => toggleSort('duration')} active={sortKey === 'duration'}
                  dir={sortDir} align="right">
                Durée
              </Th>
              <Th>Rapport</Th>
              <th className="px-4 py-3 w-10"></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(a => {
              const vulns = a.agents.flatMap(ag => ag.vulnerabilities)
              const crit = vulns.filter(v => v.severity === 'Critical').length
              const high = vulns.filter(v => v.severity === 'High').length
              const attacks = a.agents.reduce((n, ag) => n + ag.attacks.length, 0)
              const cats = a.agents.filter(ag => ag.status === 'completed')
              const mode = inferMode(a)

              return (
                <tr
                  key={a.id}
                  onClick={() => setSelectedAuditId(a.id)}
                  className="border-b border-border-subtle hover:bg-bg-elevated
                             cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3 whitespace-nowrap">
                    <div className="font-mono text-xs text-text-primary tabular">
                      {a.started_at.slice(0, 10)}
                    </div>
                    <div className="font-mono text-[11px] text-text-muted tabular">
                      {new Date(a.started_at).toLocaleTimeString('fr-FR',
                        { hour: '2-digit', minute: '2-digit' })}
                    </div>
                  </td>

                  {/* Périmètre : ce qui DIFFÉRENCIE réellement deux audits de la
                      même cible — catégories couvertes et mode d'exécution. */}
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      {cats.slice(0, 3).map(ag => (
                        <span key={ag.asi_category}
                              className="px-1.5 py-0.5 rounded-md bg-bg-overlay text-[11px]
                                         font-mono font-semibold text-text-primary">
                          {ag.asi_category.replace('_', '')}
                        </span>
                      ))}
                      {cats.length > 3 && (
                        <span className="text-[11px] text-text-muted">+{cats.length - 3}</span>
                      )}
                      <ModeChip mode={mode} />
                    </div>
                    <div className="text-[11px] text-text-muted mt-1 truncate max-w-[280px]"
                         title={a.target_name}>
                      {targetOf(a)} · {a.profile}
                    </div>
                  </td>

                  <td className="px-4 py-3 w-40"><ScoreBar score={a.global_score} max={100} /></td>
                  <td className="px-4 py-3"><RiskBadge level={a.risk_level} /></td>

                  <td className="px-4 py-3 text-right whitespace-nowrap">
                    {crit + high === 0 ? (
                      <span className="text-xs text-text-muted">aucune</span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 font-mono text-xs tabular">
                        {crit > 0 && (
                          <span className="px-1.5 py-0.5 rounded-md font-bold"
                                style={{ color: 'var(--sev-critical)',
                                         background: 'color-mix(in srgb, var(--sev-critical) 11%, transparent)' }}
                                title={`${crit} Critical`}>
                            {crit}C
                          </span>
                        )}
                        {high > 0 && (
                          <span className="px-1.5 py-0.5 rounded-md font-bold"
                                style={{ color: 'var(--sev-high)',
                                         background: 'color-mix(in srgb, var(--sev-high) 11%, transparent)' }}
                                title={`${high} High`}>
                            {high}H
                          </span>
                        )}
                      </span>
                    )}
                  </td>

                  <td className="px-4 py-3 text-right font-mono text-xs tabular text-text-secondary">
                    {attacks || '—'}
                  </td>
                  <td className="px-4 py-3 text-right font-mono text-xs tabular text-text-secondary">
                    {humanDuration(a.duration_s)}
                  </td>
                  {/* Rapport : l'API le génère à la volée et renvoie le HTML.
                      Un BOUTON et non un lien : un lien ne porte pas la clé
                      d'API, et l'API protégée répondait 401 (voir openReport).
                      `stopPropagation` est indispensable — sans lui, le clic
                      ouvrirait AUSSI le tiroir de détail de la ligne. */}
                  <td className="px-4 py-3 whitespace-nowrap">
                    <button
                      type="button"
                      onClick={e => {
                        e.stopPropagation()
                        openReport(a.id).catch((err: Error) => addToast({
                          type: 'error', title: 'Rapport indisponible', message: err.message,
                        }))
                      }}
                      title="Ouvrir le rapport de sécurité (imprimable en PDF)"
                      className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg
                                 border border-border text-xs font-medium text-text-secondary
                                 hover:border-brand hover:text-brand transition-colors"
                    >
                      <FileText size={13} /> Rapport
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <ChevronRight size={16} className="text-text-muted" />
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="py-12 text-center text-text-muted text-sm">
            Aucun audit ne correspond à ces critères.
          </div>
        )}
      </div>

      <AnimatePresence>
        {selectedAudit && (
          <AuditDrawer audit={selectedAudit} onClose={() => setSelectedAuditId(null)} />
        )}
      </AnimatePresence>
    </div>
  )
}

function AuditDrawer({ audit, onClose }: { audit: Audit; onClose: () => void }) {
  const vulns = audit.agents.flatMap(a => a.vulnerabilities)
  const attacks = audit.agents.flatMap(a => a.attacks)
  const mode = inferMode(audit)
  const axes = axesUsed(audit)

  // Le verdict est RECALCULÉ avec la politique en vigueur, pas lu depuis le
  // fichier. Le champ stocké valait « PASS » par défaut et affichait donc
  // « déploiement autorisé » sur un audit portant deux vulnérabilités Critical.
  const gate = evaluateGate(audit, getDefaultPolicy())
  const meta = VERDICT_META[gate.verdict]

  const agent = audit.agents.find(a => a.status === 'completed')
  const behRaw = (agent?.layers.behavioral.raw || {}) as Record<string, unknown>
  const comps = behRaw.components as Record<string, number | null> | undefined
  const stats = behRaw.stats as Record<string, number> | undefined

  const scored = attacks.filter(a => a.verdict !== 'excluded')
  const breached = scored.filter(a => a.verdict === 'compromised')

  const LAYERS = agent ? ([
    ['Comportementale', agent.layers.behavioral, 0.5],
    ['Statique', agent.layers.static, 0.3],
    ['Dynamique', agent.layers.dynamic, 0.2],
  ] as const) : []

  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="fixed inset-0 z-40 flex justify-end" onClick={onClose}
    >
      <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" />
      <motion.div
        initial={{ x: "100%" }} animate={{ x: 0 }} exit={{ x: "100%" }}
        transition={{ type: "spring", stiffness: 300, damping: 30 }}
        onClick={e => e.stopPropagation()}
        className="relative w-full max-w-3xl h-full bg-bg-surface border-l border-border overflow-y-auto"
      >
        {/* En-tête */}
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 p-5
                        border-b border-border bg-bg-surface/95 backdrop-blur">
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              {audit.agents.filter(a => a.status === "completed").map(a => (
                <span key={a.asi_category}
                      className="px-1.5 py-0.5 rounded-md bg-bg-overlay text-[11px]
                                 font-mono font-semibold text-text-primary">
                  {a.asi_category.replace("_", "")}
                </span>
              ))}
              <span className="text-xs text-text-muted">{MODE_LABEL[mode]}</span>
            </div>
            <h2 className="text-base font-semibold text-text-primary mt-1.5 truncate">
              {targetOf(audit)}
            </h2>
            <div className="text-xs text-text-muted mt-0.5 font-mono">
              {audit.started_at.slice(0, 16).replace("T", " ")} · {audit.model} · {audit.profile}
            </div>
          </div>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary shrink-0">
            <X size={20} />
          </button>
        </div>

        <div className="p-5 space-y-5">
          {/* Verdict — recalculé, avec les règles qui l'ont produit */}
          <div className="rounded-xl border-2 p-4"
               style={{ borderColor: `color-mix(in srgb, ${meta.color} 42%, transparent)`,
                        background: `color-mix(in srgb, ${meta.color} 5%, transparent)` }}>
            <div className="flex items-center gap-3 flex-wrap">
              <ShieldCheck size={20} style={{ color: meta.color }} />
              <span className="text-base font-bold" style={{ color: meta.color }}>{meta.label}</span>
              <code className="ml-auto font-mono text-sm font-bold" style={{ color: meta.color }}>
                exit {gate.verdict === "BLOCKED" ? "1" : "0"}
              </code>
            </div>
            <div className="mt-2.5 space-y-1">
              {gate.rules.filter(r => r.effect !== "info").slice(0, 4).map(r => (
                <div key={r.id} className="text-xs flex items-start gap-2">
                  <span className="font-mono text-[10px] uppercase shrink-0 w-16"
                        style={{ color: r.effect === "block" ? "var(--sev-critical)"
                          : r.effect === "warn" ? "var(--sev-high)" : "var(--sev-low)" }}>
                    {r.effect === "block" ? "bloque" : r.effect === "warn" ? "avertit" : "conforme"}
                  </span>
                  <span className="text-text-secondary">{r.label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Mesures clés */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <Stat label="Score global" value={String(audit.global_score)} suffix="/100"
                  color={audit.global_score >= 71 ? "var(--sev-low)"
                    : audit.global_score >= 51 ? "var(--sev-medium)" : "var(--sev-critical)"} />
            <Stat label="Attaques évaluées" value={String(scored.length)}
                  suffix={attacks.length !== scored.length ? `/${attacks.length}` : ""} />
            <Stat label="Percées" value={String(breached.length)}
                  color={breached.length ? "var(--sev-critical)" : "var(--sev-low)"} />
            <Stat label="Durée" value={humanDuration(audit.duration_s)} />
          </div>

          {/* Scores par couche — remplace un radar à un seul point */}
          {agent && (
            <Section title="Score par couche"
                     hint="pondération renormalisée sur les couches applicables">
              <div className="space-y-2.5">
                {LAYERS.map(([name, layer, w]) => (
                  <div key={name} className="flex items-center gap-3">
                    <span className="text-xs text-text-secondary w-32 shrink-0">{name}</span>
                    <span className="font-mono text-[10px] text-text-muted w-8">×{w}</span>
                    <div className="flex-1 h-2 rounded-full bg-bg-elevated overflow-hidden">
                      {layer.applicable && layer.score != null && (
                        <div className="h-full rounded-full"
                             style={{ width: `${layer.score * 10}%`,
                                      background: layer.score >= 7 ? "var(--sev-low)"
                                        : layer.score >= 4 ? "var(--sev-medium)"
                                        : "var(--sev-critical)" }} />
                      )}
                    </div>
                    <span className="font-mono text-xs tabular w-28 text-right"
                          style={{ color: layer.applicable ? "var(--text-primary)" : "var(--text-muted)" }}>
                      {layer.applicable && layer.score != null
                        ? layer.score.toFixed(2) : "non applicable"}
                    </span>
                  </div>
                ))}
              </div>
            </Section>
          )}

          {/* Axes comportementaux — montre CE QUI a tourné, et ce qui a été exclu */}
          {comps && (
            <Section title="Axes comportementaux" hint="un axe exclu n'est jamais compté zéro">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                {(["deepteam", "pyrit", "garak", "microsoft"] as const).map(k => {
                  const v = comps[k]
                  const label = { deepteam: "DeepTeam", pyrit: "PyRIT",
                                  garak: "Garak", microsoft: "Payloads MS" }[k]
                  const col = v == null ? "var(--text-muted)"
                    : v >= 7 ? "var(--sev-low)" : v > 0 ? "var(--sev-medium)" : "var(--sev-critical)"
                  return (
                    <div key={k} className="rounded-xl border border-border bg-bg-elevated p-3">
                      <div className="text-[10px] uppercase tracking-wider text-text-muted">{label}</div>
                      <div className="font-mono text-xl font-bold tabular mt-1" style={{ color: col }}>
                        {v == null ? "—" : v.toFixed(1)}
                      </div>
                      {v == null && <div className="text-[10px] text-text-muted">exclu du calcul</div>}
                    </div>
                  )
                })}
              </div>
            </Section>
          )}

          {/* Qualité des refus — révèle un score faussement rassurant */}
          {stats && ((stats.pass_refusal_robust ?? 0) + (stats.pass_refusal_accidental ?? 0)) > 0 && (
            <Section title="Qualité des refus"
                     hint="un refus accidentel ne protège pas d'une variante mieux formée">
              <div className="grid grid-cols-3 gap-2.5">
                <Stat label="De principe" value={String(stats.pass_refusal_robust ?? 0)}
                      color="var(--sev-low)" />
                <Stat label="Partiels" value={String(stats.pass_refusal_partial ?? 0)}
                      color="var(--sev-medium)" />
                <Stat label="Accidentels" value={String(stats.pass_refusal_accidental ?? 0)}
                      color="var(--sev-critical)" />
              </div>
            </Section>
          )}

          {/* Fiabilité de la chaîne de jugement : d'où viennent ces gravités,
              et ce qu'elles valent. Mêmes chiffres que le rapport HTML. */}
          <JudgeReliability summary={audit.judge_summary} />

          {/* Vulnérabilités avec preuve et remédiation */}
          <Section title={`Vulnérabilités (${vulns.length})`}>
            <div className="space-y-2.5">
              {vulns.map((v, i) => (
                <div key={i} className="rounded-xl border border-border bg-bg-elevated p-3.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <SeverityBadge severity={v.severity} />
                    <span className="text-sm font-medium text-text-primary">{v.title}</span>
                    <span className="text-[11px] text-text-muted ml-auto font-mono">
                      {v.asi_category} · {v.layer}
                    </span>
                  </div>
                  {/* Analyse structurée du juge : la gravité seule ne dit pas CE QUI
                      s'est passé, ni si le verdict est sûr. */}
                  {v.judge_detail && (v.judge_detail.agent_behavior || v.judge_detail.fallback) && (
                    <div className="mt-2.5 rounded-lg border border-border bg-bg-base p-2.5">
                      <div className="flex items-center gap-2 mb-1.5">
                        <span className="text-[10px] uppercase tracking-wide text-text-muted">
                          Analyse du juge
                        </span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-semibold ${
                          v.confidence == null || v.confidence < 80
                            ? 'bg-red-500/15 text-red-500'
                            : 'bg-slate-500/15 text-text-muted'}`}>
                          {v.confidence == null ? 'confiance non annoncée' : `confiance ${v.confidence}%`}
                        </span>
                      </div>
                      {v.judge_detail.fallback ? (
                        <p className="text-[11px] text-text-muted">
                          Juge indisponible ({v.judge_detail.fallback}) — gravité issue du
                          barème statique de la catégorie, non contextualisée.
                        </p>
                      ) : (
                        <dl className="text-[11px] space-y-1">
                          {([
                            ["Ce que l'attaque visait", v.judge_detail.attack_intent],
                            ["Ce que l'agent a fait", v.judge_detail.agent_behavior],
                            ['Défense en cause', v.judge_detail.guardrail],
                            ['Impact en production', v.judge_detail.impact],
                          ] as [string, string | undefined][])
                            .filter(([, val]) => val)
                            .map(([k, val]) => (
                              <div key={k} className="flex gap-2">
                                <dt className="shrink-0 text-text-muted w-40">{k}</dt>
                                <dd className="text-text-primary">{val}</dd>
                              </div>
                            ))}
                        </dl>
                      )}
                    </div>
                  )}
                  {v.evidence && (
                    <pre className="code-block p-2.5 mt-2.5 text-[11px] font-mono
                                    whitespace-pre-wrap break-words max-h-28 overflow-auto">
                      {v.evidence}
                    </pre>
                  )}
                  {v.remediation && (
                    <p className="text-xs text-text-secondary mt-2 leading-relaxed">
                      <b className="text-text-primary">Remédiation — </b>{v.remediation}
                    </p>
                  )}
                </div>
              ))}
              {vulns.length === 0 && (
                <p className="text-sm text-text-muted py-3">Aucune vulnérabilité détectée.</p>
              )}
            </div>
          </Section>

          <div className="text-[11px] text-text-muted font-mono pt-2 border-t border-border">
            axes exécutés : {axes.join(" · ") || "aucun"}
          </div>
        </div>
      </motion.div>
    </motion.div>
  )
}

function Section({ title, hint, children }: {
  title: string; hint?: string; children: React.ReactNode
}) {
  return (
    <div>
      <h3 className="text-sm font-semibold text-text-primary">{title}</h3>
      <p className="text-[11px] text-text-muted mb-2.5">{hint || ""}</p>
      {children}
    </div>
  )
}

function Stat({ label, value, suffix, color }: {
  label: string; value: string; suffix?: string; color?: string
}) {
  return (
    <div className="rounded-xl border border-border bg-bg-elevated p-3">
      <div className="text-[10px] uppercase tracking-wider text-text-muted">{label}</div>
      <div className="font-mono text-xl font-bold tabular mt-1"
           style={{ color: color || "var(--text-primary)" }}>
        {value}<span className="text-xs text-text-muted font-normal">{suffix}</span>
      </div>
    </div>
  )
}

/** Durée lisible : « 15 min » plutôt que « 916s ». */
function humanDuration(seconds: number): string {
  if (!seconds) return '—'
  if (seconds < 90) return `${Math.round(seconds)} s`
  const m = Math.round(seconds / 60)
  if (m < 60) return `${m} min`
  return `${Math.floor(m / 60)} h ${String(m % 60).padStart(2, '0')}`
}

function Th({ children, onClick, active, dir, align = 'left' }: {
  children?: React.ReactNode; onClick?: () => void
  active?: boolean; dir?: 'asc' | 'desc'; align?: 'left' | 'right'
}) {
  const base = `px-4 py-3 text-[10px] font-mono font-semibold uppercase tracking-wider
                text-text-muted text-${align}`
  if (!onClick) return <th className={base}>{children}</th>
  return (
    <th className={base}>
      <button
        onClick={onClick}
        className={`flex items-center gap-1 hover:text-text-primary
                    ${align === 'right' ? 'ml-auto' : ''} ${active ? 'text-text-primary' : ''}`}
      >
        {children} {active && (dir === 'desc' ? '↓' : '↑')}
      </button>
    </th>
  )
}

/** Le mode est LA donnée qui rend deux scores comparables — ou pas. */
function ModeChip({ mode }: { mode: 'quick' | 'partial' | 'complete' }) {
  const color = mode === 'complete' ? 'var(--sev-low)'
    : mode === 'partial' ? 'var(--sev-medium)' : 'var(--sev-info)'
  return (
    <span
      className="px-1.5 py-0.5 rounded-md text-[10px] font-semibold border"
      style={{ color, borderColor: `color-mix(in srgb, ${color} 30%, transparent)`,
               background: `color-mix(in srgb, ${color} 8%, transparent)` }}
      title={`Mode : ${MODE_LABEL[mode]}`}
    >
      {MODE_LABEL[mode]}
    </span>
  )
}
