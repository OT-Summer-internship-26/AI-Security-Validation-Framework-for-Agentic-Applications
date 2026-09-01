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
  const iv = latest.score_interval
  const resume = latest.executive_summary
  const plan = latest.remediation_plan
  const exec = latest.execution
  // Un écart plus petit que le bruit irréductible du simulateur n'est pas une
  // évolution : deux exécutions identiques varient déjà d'autant (doc. technique : fiabilite du score). Le seuil
  // vient du JSON — le recopier ici le ferait diverger du rapport.
  const bruit = delta !== null && iv ? Math.abs(delta) < iv.plancher : false

  const scoreColor = latest.global_score >= 86 ? 'var(--sev-info)'
    : latest.global_score >= 71 ? 'var(--sev-low)'
    : latest.global_score >= 51 ? 'var(--sev-medium)'
    : latest.global_score >= 31 ? 'var(--sev-high)' : 'var(--sev-critical)'

  const goto = (id: string, page: 'attacks' | 'history') => {
    setSelectedAuditId(id); setCurrentPage(page)
  }

  return (
    <div className="p-6 space-y-6 max-w-[1500px] mx-auto pb-16">

      {/* ─── Synthèse d'ouverture : ce que l'audit a trouvé, en une lecture.
              Sans elle, le lecteur reconstitue le verdict depuis des compteurs. ─── */}
      {resume && (
        <motion.div
          initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}
          className="card p-6 border-l-[3px]"
          style={{ borderLeftColor: 'var(--brand)' }}
        >
          <div className="text-[11px] font-bold uppercase tracking-wide text-text-muted mb-3">
            Synthèse
          </div>
          <p className="text-[13.5px] leading-relaxed">{resume.constat}</p>
          <p className="text-[13.5px] leading-relaxed mt-2">{resume.consequence}</p>
          <p className="text-[13.5px] leading-relaxed mt-3 pt-3 border-t border-border">
            <b>Action prioritaire.</b> {resume.priorite}
          </p>
          <div className="text-[10.5px] italic text-text-muted mt-3">
            {resume.source === 'llm'
              ? 'Reformulée par modèle de langage à partir des seuls constats de '
                + "l'audit, et vérifiée contre eux."
              : 'Générée mécaniquement depuis les résultats'
                + (resume.rejet ? ` — reformulation rejetée (${resume.rejet}).` : '.')}
          </div>
        </motion.div>
      )}

      {/* ─── Plan d'action : combien de correctifs distincts, et dans quel ordre.
              Une liste de 22 constats ne répond à aucune des deux questions. ─── */}
      {plan && plan.groupes.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}
          className="card p-6"
        >
          <div className="flex items-baseline justify-between gap-3 flex-wrap mb-1">
            <div className="text-[11px] font-bold uppercase tracking-wide text-text-muted">
              Plan de remédiation
            </div>
            <div className="text-[11px] text-text-muted">
              {plan.source === 'llm'
                ? 'Regroupement par modèle, vérifié contre les constats'
                : 'Regroupement mécanique'
                  + (plan.rejet ? ` — modèle rejeté (${plan.rejet})` : '')}
            </div>
          </div>
          <p className="text-[13px] mb-4">{plan.lecture}</p>
          <div className="space-y-2">
            {plan.groupes.map(g => (
              <div key={g.rang} className="flex gap-3 items-start p-3 rounded-lg border border-border">
                <div className="font-mono font-bold text-[15px] tabular w-6 shrink-0
                                text-text-muted">{g.rang}</div>
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-semibold">{g.cause}</div>
                  <div className="text-[12.5px] text-text-muted mt-0.5">{g.action}</div>
                  <div className="text-[10.5px] text-text-muted mt-1.5 flex gap-2 flex-wrap">
                    <span className="font-mono">{g.categories.join(' · ')}</span>
                    <span>·</span><span>effort {g.effort}</span>
                    <span>·</span><span>ferme {g.constats.length} constat(s)</span>
                  </div>
                </div>
                <SeverityBadge severity={g.gravite_max} />
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* ─── Conduite de l'audit : ce qu'il a coûté. Sans ce bloc, l'interface
              montre les attaques et jamais le travail qui les a produites. ─── */}
      {exec && (
        <motion.div
          initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}
          className="card p-6"
        >
          <div className="text-[11px] font-bold uppercase tracking-wide text-text-muted mb-3">
            Conduite de l'audit
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              ['Appels de modèle', exec.appels_llm.toLocaleString('fr-FR'),
               exec.erreurs_llm ? `${exec.erreurs_llm} en erreur` : null],
              ['Jetons', exec.jetons.toLocaleString('fr-FR'), null],
              ['Coût estimé', exec.cout_usd ? `${exec.cout_usd} $` : '—', null],
              ['Durée', `${Math.round(exec.secondes_total / 60)} min`,
               exec.parallelisme_effectif
                 ? `parallélisme ${exec.parallelisme_effectif}` : null],
            ].map(([label, valeur, note]) => (
              <div key={label as string}>
                <div className="text-[10.5px] uppercase tracking-wide text-text-muted">
                  {label}
                </div>
                <div className="text-[20px] font-bold font-mono tabular mt-0.5">
                  {valeur}
                </div>
                {note && <div className="text-[10.5px] text-text-muted">{note}</div>}
              </div>
            ))}
          </div>
          <div className="text-[11px] text-text-muted mt-4 leading-snug">
            {Math.round(exec.secondes_attente / 60)} min cumulées passées à
            attendre la cible, les modèles et les sous-processus.
            {' '}Détail : {Object.entries(exec.par_role)
              .map(([r, v]) => `${r} ${v.n}`).join(' · ')}
            {Object.keys(exec.par_etape).length > 0 && ' · '}
            {Object.entries(exec.par_etape).map(([s, v]) => `${s} ${v.n}`).join(' · ')}
          </div>
        </motion.div>
      )}

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
                style={{ color: bruit ? 'var(--text-muted)'
                  : delta > 0 ? 'var(--sev-low)' : 'var(--sev-critical)' }}
                title={bruit
                  ? `Écart de ${delta} pt(s) INFÉRIEUR au bruit du simulateur `
                    + `(±${iv!.plancher}) : deux exécutions identiques varient déjà `
                    + `d'autant. Ce n'est pas une évolution mesurée.`
                  : "vs l'audit précédent de même configuration"}
              >
                {delta > 0 ? '+' : ''}{delta}{bruit && ' ≈'}
              </span>
            )}
          </div>

          {/* Plage de confiance : le score est un TIRAGE (doc. technique : fiabilite du score : 9,66 et 7,93 sur la
              même cible). L'afficher nu le présenterait comme une mesure. */}
          {iv && (
            <div className="mt-2 text-[11px] text-text-muted leading-snug">
              <span className="font-mono tabular">
                {iv.bas} – {iv.haut}
              </span>
              <span className="opacity-70"> (±{iv.marge} pts, {iv.categories} catégorie
                {iv.categories > 1 ? 's' : ''})</span>
              {iv.bas < 70 && iv.haut >= 70 && (
                <span className="ml-1.5 px-1.5 py-0.5 rounded font-bold"
                      style={{ color: 'var(--sev-medium)',
                               background: 'color-mix(in srgb, var(--sev-medium) 14%, transparent)' }}
                      title={iv.lecture}>
                  chevauche le seuil
                </span>
              )}
            </div>
          )}

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
