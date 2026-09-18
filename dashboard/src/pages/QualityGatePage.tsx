import { useState, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ShieldCheck, ToggleLeft, ToggleRight, Calendar, TriangleAlert as AlertTriangle,
  MailWarning as FileWarning, CircleCheck as CheckCircle, Circle as XCircle,
  Eye, Info, Ban, ArrowRight,
} from 'lucide-react'
import { getAudits, getDefaultPolicy, getBaselineFor, resolveAudit , useAudits} from '@/data/repository'
import { evaluateGate, VERDICT_META, type GateRule } from '@/data/gate'
import { ASI_CATEGORIES } from '@/types'
import type { QualityGatePolicy } from '@/types'
import { useApp } from '@/App'

export function QualityGatePage() {
  const { selectedAuditId, setSelectedAuditId } = useApp()
  useAudits()   // abonnement : rafraîchit la page après un audit
  const audits = getAudits()
  const audit = resolveAudit(selectedAuditId)!

  const [policy, setPolicy] = useState<QualityGatePolicy>(() => {
    const base = getDefaultPolicy()
    const auto = getBaselineFor(audit)
    return { ...base, baseline_audit_id: base.baseline_audit_id ?? auto?.id ?? null }
  })

  const patch = (p: Partial<QualityGatePolicy>) => setPolicy(prev => ({ ...prev, ...p }))

  const baseline = useMemo(
    () => audits.find(a => a.id === policy.baseline_audit_id),
    [audits, policy.baseline_audit_id])

  // Toutes les règles sont réellement appliquées ici — voir data/gate.ts
  const result = useMemo(
    () => evaluateGate(audit, policy, baseline),
    [audit, policy, baseline])

  const meta = VERDICT_META[result.verdict]
  const today = new Date()

  const selectClass = 'px-3 py-2 rounded-xl bg-bg-elevated border border-border text-sm ' +
    'text-text-primary outline-none hover:border-border-bright transition-colors'

  return (
    <div className="p-6 space-y-5 max-w-[1500px] mx-auto pb-16">
      <div className="flex items-end justify-between gap-6 flex-wrap">
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.14em] text-text-muted">
            Politique de déploiement
          </div>
          <h1 className="text-2xl font-bold text-text-primary mt-1">Quality Gate</h1>
          <p className="text-sm text-text-secondary mt-1 max-w-2xl text-balance">
            Un seuil de score unique est faux dans les deux sens : un score élevé peut masquer
            une faille Critical, un score bas peut bloquer sur des catégories hors périmètre.
            La décision se compose donc de règles nommées et traçables.
          </p>
        </div>
        <select value={audit.id} onChange={e => setSelectedAuditId(e.target.value)} className={selectClass}>
          {audits.map(a => (
            <option key={a.id} value={a.id}>
              {a.target_name} — {a.global_score}/100 — {a.started_at.slice(0, 10)}
            </option>
          ))}
        </select>
      </div>

      {/* ─── Verdict ─── */}
      <AnimatePresence mode="wait">
        <motion.div
          key={result.verdict}
          initial={{ opacity: 0, y: 10, scale: 0.99 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          className="card p-6 border-2 relative overflow-hidden"
          style={{
            borderColor: `color-mix(in srgb, ${meta.color} 45%, transparent)`,
            background: `color-mix(in srgb, ${meta.color} 5%, var(--bg-surface))`,
          }}
        >
          <div className="flex items-center gap-5 flex-wrap">
            <div
              className="w-16 h-16 rounded-2xl flex items-center justify-center shrink-0"
              style={{ background: `color-mix(in srgb, ${meta.color} 12%, transparent)` }}
            >
              {result.verdict === 'BLOCKED' ? <Ban size={32} style={{ color: meta.color }} />
                : result.verdict === 'PASS' ? <CheckCircle size={32} style={{ color: meta.color }} />
                : result.verdict === 'REVIEW_REQUIRED' ? <Eye size={32} style={{ color: meta.color }} />
                : <AlertTriangle size={32} style={{ color: meta.color }} />}
            </div>
            <div className="flex-1 min-w-[260px]">
              <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-text-muted">
                Simulateur — {audit.target_name} · {audit.started_at.slice(0, 10)}
              </div>
              <div className="text-2xl font-bold mt-1" style={{ color: meta.color }}>{meta.label}</div>
              <div className="text-xs text-text-secondary mt-1.5 flex items-center gap-3 flex-wrap">
                <span>Score <b className="font-mono tabular">{audit.global_score}</b>/100</span>
                <span>·</span>
                <span style={{ color: 'var(--sev-critical)' }}>{result.counts.critical} Critical</span>
                <span style={{ color: 'var(--sev-high)' }}>{result.counts.high} High</span>
                {result.waived.length > 0 && (
                  <span className="text-text-muted">· {result.waived.length} sous dérogation</span>
                )}
              </div>
            </div>
            <div className="text-right">
              <div className="text-[10px] uppercase tracking-wider text-text-muted">Sortie CI/CD</div>
              <code className="text-lg font-mono font-bold" style={{ color: meta.color }}>
                exit {result.verdict === 'BLOCKED' ? '1' : '0'}
              </code>
            </div>
          </div>

          {result.verdict === 'BLOCKED' && audit.global_score >= policy.min_score && (
            <div className="mt-4 pt-4 border-t border-border flex items-start gap-2">
              <Info size={15} className="text-severity-critical mt-0.5 shrink-0" />
              <p className="text-xs text-text-secondary text-balance">
                Le score dépasse le seuil de {policy.min_score}, et pourtant le déploiement est bloqué.
                C'est précisément ce qu'un seuil unique laissait passer.
              </p>
            </div>
          )}
        </motion.div>
      </AnimatePresence>

      {/* ─── Règles appliquées ─── */}
      <div className="card p-5">
        <h3 className="text-sm font-semibold text-text-primary mb-4 flex items-center gap-2">
          <ShieldCheck size={16} className="text-brand" />
          Règles appliquées — décision décomposée
        </h3>
        <div className="space-y-2">
          {result.rules.map((r, i) => <RuleRow key={r.id} rule={r} index={i} />)}
          {result.rules.length === 0 && (
            <p className="text-sm text-text-muted py-3">Aucune règle déclenchée.</p>
          )}
        </div>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        {/* ─── Règles globales ─── */}
        <div className="card p-5 space-y-1">
          <h3 className="text-sm font-semibold text-text-primary mb-3">Règles globales</h3>

          <div className="flex items-center justify-between py-2.5">
            <div>
              <div className="text-sm text-text-primary">Bloquer sur toute vulnérabilité Critical</div>
              <div className="text-xs text-text-muted mt-0.5">Indépendamment du score</div>
            </div>
            <button
              onClick={() => patch({ block_all_critical: !policy.block_all_critical })}
              className={policy.block_all_critical ? 'text-brand' : 'text-text-muted'}
              aria-label="Basculer le blocage sur Critical"
            >
              {policy.block_all_critical ? <ToggleRight size={34} /> : <ToggleLeft size={34} />}
            </button>
          </div>

          <div className="py-2.5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-text-primary">Findings High tolérés</span>
              <span className="font-mono font-bold tabular text-text-primary">{policy.max_high_findings}</span>
            </div>
            <input
              type="range" min={0} max={20} value={policy.max_high_findings}
              onChange={e => patch({ max_high_findings: Number(e.target.value) })}
              className="w-full accent-brand"
            />
          </div>

          <div className="flex items-center justify-between py-2.5">
            <div>
              <div className="text-sm text-text-primary">Imposer le seuil de score</div>
              <div className="text-xs text-text-muted mt-0.5">
                Désactivé, le score s'affiche sans décider — un audit partiel n'est pas comparable
              </div>
            </div>
            <button
              onClick={() => patch({ enforce_min_score: !policy.enforce_min_score })}
              className={policy.enforce_min_score ? 'text-brand' : 'text-text-muted'}
              aria-label="Basculer le seuil de score"
            >
              {policy.enforce_min_score ? <ToggleRight size={34} /> : <ToggleLeft size={34} />}
            </button>
          </div>

          <div className="py-2.5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-text-primary">Seuil de score minimum</span>
              <span className="font-mono font-bold tabular text-text-primary">{policy.min_score}/100</span>
            </div>
            <input
              type="range" min={0} max={100} value={policy.min_score}
              onChange={e => patch({ min_score: Number(e.target.value) })}
              className={`w-full accent-brand ${
                policy.mode === 'regression' || !policy.enforce_min_score ? 'opacity-40' : ''}`}
              disabled={policy.mode === 'regression' || !policy.enforce_min_score}
            />
            {policy.mode === 'regression' && (
              <p className="text-[11px] text-text-muted mt-1">
                Inactif en mode régression — c'est la dégradation qui décide.
              </p>
            )}
          </div>

          <div className="py-2.5">
            <div className="text-sm text-text-primary mb-2">Mode d'évaluation</div>
            <div className="flex gap-2 flex-wrap">
              {(['absolute', 'regression'] as const).map(m => (
                <button
                  key={m}
                  onClick={() => patch({ mode: m })}
                  className={`px-3.5 py-2 rounded-xl text-xs font-medium border transition-all
                    ${policy.mode === m
                      ? 'bg-brand/[0.08] text-brand border-brand/30'
                      : 'bg-bg-elevated text-text-secondary border-border hover:text-text-primary'}`}
                >
                  {m === 'absolute' ? 'État absolu' : 'Régression vs baseline'}
                  {m === 'regression' && (
                    <span className="ml-1.5 text-[9px] uppercase tracking-wide opacity-70">recommandé</span>
                  )}
                </button>
              ))}
            </div>
            {policy.mode === 'regression' && (
              <select
                value={policy.baseline_audit_id || ''}
                onChange={e => patch({ baseline_audit_id: e.target.value || null })}
                className={`${selectClass} w-full mt-2.5`}
              >
                <option value="">Sélectionner une baseline…</option>
                {audits.filter(a => a.id !== audit.id).map(a => (
                  <option key={a.id} value={a.id}>
                    {a.target_name} — {a.global_score}/100 ({a.started_at.slice(0, 10)})
                  </option>
                ))}
              </select>
            )}
          </div>
        </div>

        {/* ─── Par catégorie ─── */}
        <div className="card p-5">
          <h3 className="text-sm font-semibold text-text-primary mb-1">Périmètre par catégorie ASI</h3>
          <p className="text-xs text-text-muted mb-4">
            Une catégorie « ignorée » sort de la décision — utile quand elle ne s'applique
            pas au système audité (ex. ASI07 sur une cible mono-agent).
          </p>
          <div className="space-y-1">
            {ASI_CATEGORIES.map(cat => {
              const cfg = policy.per_category[cat.id] || { action: 'warn' as const }
              const nb = result.effective.filter(v => v.asi_category === cat.id).length
              return (
                <div key={cat.id} className="flex items-center gap-3 py-1.5">
                  <span className="font-mono text-xs font-semibold text-text-muted w-12">{cat.short}</span>
                  <span className="text-sm text-text-secondary flex-1 truncate">{cat.name}</span>
                  {nb > 0 && (
                    <span className="text-[10px] font-mono tabular px-1.5 py-0.5 rounded
                                     bg-bg-elevated text-text-muted">{nb}</span>
                  )}
                  <div className="flex gap-1">
                    {(['block', 'warn', 'ignore'] as const).map(act => (
                      <button
                        key={act}
                        onClick={() => patch({
                          per_category: { ...policy.per_category, [cat.id]: { action: act } },
                        })}
                        className={`px-2.5 py-1 rounded-lg text-[10px] font-semibold uppercase transition-colors
                          ${cfg.action === act
                            ? act === 'block' ? 'bg-severity-critical/15 text-severity-critical'
                              : act === 'warn' ? 'bg-severity-high/15 text-severity-high'
                              : 'bg-bg-overlay text-text-secondary'
                            : 'bg-bg-elevated text-text-muted hover:text-text-secondary'}`}
                      >
                        {act === 'block' ? 'Bloquant' : act === 'warn' ? 'Avert.' : 'Ignoré'}
                      </button>
                    ))}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* ─── Dérogations ─── */}
      <div className="card p-5">
        <h3 className="text-sm font-semibold text-text-primary mb-1 flex items-center gap-2">
          <FileWarning size={16} className="text-severity-high" /> Dérogations
        </h3>
        <p className="text-xs text-text-muted mb-4">
          Une dérogation neutralise un finding jusqu'à sa date d'expiration. Passé ce
          délai, le finding redevient bloquant automatiquement — aucune dette permanente.
        </p>
        <div className="grid gap-3 md:grid-cols-2">
          {policy.derogations.length === 0 && (
            <p className="text-sm text-text-muted py-3">Aucune dérogation active.</p>
          )}
          {policy.derogations.map(d => {
            const expired = new Date(d.expires_at) < today
            const daysLeft = Math.ceil((new Date(d.expires_at).getTime() - today.getTime()) / 86400000)
            return (
              <div
                key={d.id}
                className={`rounded-xl border p-3.5 ${expired
                  ? 'border-severity-critical/40 bg-severity-critical/[0.05]'
                  : 'border-border bg-bg-elevated'}`}
              >
                <div className="flex items-start gap-2.5">
                  <Calendar size={15} className={expired ? 'text-severity-critical' : 'text-text-muted'} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-text-primary">{d.finding_title}</div>
                    <div className="text-xs text-text-secondary mt-1">{d.reason}</div>
                    <div className="flex items-center gap-3 mt-2 text-xs flex-wrap">
                      <span className="text-text-muted">Approbateur : {d.approver}</span>
                      <span className={expired ? 'text-severity-critical font-semibold'
                        : daysLeft <= 7 ? 'text-severity-high font-medium' : 'text-text-muted'}>
                        {expired ? `expirée depuis ${Math.abs(daysLeft)} j — redevenue bloquante`
                          : `expire dans ${daysLeft} j`}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* ─── Légende des verdicts ─── */}
      <div className="card p-5">
        <h3 className="text-sm font-semibold text-text-primary mb-3">
          Quatre verdicts possibles, pas deux
        </h3>
        <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
          {([
            { v: 'PASS' as const, desc: 'Déploiement autorisé', icon: CheckCircle },
            { v: 'PASS_WARNING' as const, desc: 'Autorisé, findings High à traiter', icon: AlertTriangle },
            { v: 'REVIEW_REQUIRED' as const, desc: 'Revue humaine avant déploiement', icon: Eye },
            { v: 'BLOCKED' as const, desc: 'Déploiement refusé, exit 1', icon: XCircle },
          ]).map(({ v, desc, icon: Icon }) => {
            const m = VERDICT_META[v]
            const active = result.verdict === v
            return (
              <div
                key={v}
                className={`flex items-start gap-3 p-3 rounded-xl border transition-all
                  ${active ? 'shadow-card' : 'border-transparent bg-bg-elevated'}`}
                style={active ? {
                  borderColor: `color-mix(in srgb, ${m.color} 40%, transparent)`,
                  background: `color-mix(in srgb, ${m.color} 7%, transparent)`,
                } : undefined}
              >
                <Icon size={18} style={{ color: m.color }} className="mt-0.5 shrink-0" />
                <div>
                  <div className="text-sm font-semibold" style={{ color: m.color }}>{m.short}</div>
                  <div className="text-xs text-text-muted mt-0.5">{desc}</div>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function RuleRow({ rule, index }: { rule: GateRule; index: number }) {
  const cfg = {
    block: { color: 'var(--sev-critical)', Icon: XCircle },
    warn: { color: 'var(--sev-high)', Icon: AlertTriangle },
    info: { color: 'var(--sev-info)', Icon: Info },
    ok: { color: 'var(--sev-low)', Icon: CheckCircle },
  }[rule.effect]

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.05 }}
      className="flex items-start gap-3 p-3 rounded-xl border border-border bg-bg-elevated"
    >
      <cfg.Icon size={17} style={{ color: cfg.color }} className="mt-0.5 shrink-0" />
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium text-text-primary">{rule.label}</div>
        <div className="text-xs text-text-secondary mt-0.5 break-words">{rule.detail}</div>
      </div>
      <span
        className="text-[10px] font-bold uppercase tracking-wide px-2 py-1 rounded-lg shrink-0
                   flex items-center gap-1"
        style={{ color: cfg.color, background: `color-mix(in srgb, ${cfg.color} 10%, transparent)` }}
      >
        {rule.effect === 'block' ? <><ArrowRight size={10} /> bloque</>
          : rule.effect === 'warn' ? 'avertit'
          : rule.effect === 'ok' ? 'conforme' : 'contexte'}
      </span>
    </motion.div>
  )
}
