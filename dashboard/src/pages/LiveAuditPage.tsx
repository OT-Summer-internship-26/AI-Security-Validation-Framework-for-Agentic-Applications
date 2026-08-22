import { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Play, Square, Download, Terminal, ChevronDown, ChevronUp, Clock,
  CircleCheck as CheckCircle, Loader as Loader2, TriangleAlert as AlertTriangle,
  Radio, Ban, ServerCrash, RefreshCw, ShieldAlert, FolderCode, ArrowRight, ArrowLeft,
  Zap, Target, Layers, Users,
} from 'lucide-react'
import { useApp } from '@/App'
import { reloadAudits } from '@/data/repository'
import {
  API_BASE, getAgents, getHealth, startAudit, getRun, cancelRun, fetchRuns,
  type AgentInfo, type HealthInfo, type RunState, type RunLog, type LiveExchange,
  type AuditMode, getDvapLabs, launchDvapLab, type DvapLab,
} from '@/data/api'
import { adaptAudit } from '@/data/adapter'
import { ArchitectureFlow, type ArchStage } from '@/components/ArchitectureFlow'
import { AsioRadarChart } from '@/charts/AsioRadarChart'
import type { LlmProfile, Audit } from '@/types'

/* Étape signalée par l'API → nœud du schéma d'architecture. */
function stageToArch(stage: string, progress: number): { active: ArchStage; done: ArchStage[] } {
  const chain: ArchStage[] = [
    'target', 'api', 'graph', 'agent',
    'deepteam', 'pyrit', 'garak', 'microsoft',
    'static', 'dynamic', 'judge', 'scoring', 'report', 'gate',
  ]
  const s = stage.toLowerCase()
  let active: ArchStage = 'api'
  if (s.includes('initialis') || s.includes('démarrage')) active = 'target'
  else if (s.includes('deepteam') && !s.includes('terminé')) active = 'deepteam'
  else if (s.includes('deepteam')) active = 'pyrit'
  else if (s.includes('pyrit')) active = 'pyrit'
  else if (s.includes('garak')) active = 'garak'
  else if (s.includes('microsoft')) active = 'microsoft'
  else if (s.includes('statique')) active = 'static'
  else if (s.includes('dynamique') || s.includes('sandbox')) active = 'dynamic'
  else if (s.includes('consolidation')) active = 'scoring'
  else if (s.includes('terminé')) active = 'report'
  else if (progress > 0) active = 'graph'
  const idx = chain.indexOf(active)
  return { active, done: chain.slice(0, Math.max(0, idx)) }
}

const MODES: {
  id: AuditMode; name: string; hint: string; cost: string
  icon: typeof Zap; color: string
}[] = [
  {
    id: 'quick', name: 'Contrôle rapide', icon: Zap, color: 'var(--sev-low)',
    hint: 'Garak, Semgrep, pip-audit, sandbox. Aucun appel LLM.',
    cost: 'quelques minutes · déterministe',
  },
  {
    id: 'targeted', name: 'Audit ciblé', icon: Target, color: 'var(--sev-info)',
    hint: 'Les catégories de votre choix, tous les axes.',
    cost: '~15 min par agent',
  },
  {
    id: 'full', name: 'Audit complet', icon: Layers, color: 'var(--sev-high)',
    hint: 'Tous les agents implémentés, tous les axes. À lancer la nuit.',
    cost: 'plusieurs heures · tous les agents',
  },
]

const LOG_COLOR: Record<string, string> = {
  info: '#4ADE80', warn: '#FBBF24', critical: '#FF3D9A', debug: '#64748B',
}

// Formats JSON des cibles connues. Chaque agent cible a SA forme de requête : le lab
// `autonomous-agent` exige {title, content} (422 sinon), `prompt-injection` veut {message}.
// Un préréglage évite de retaper les trois champs — « Personnalisé » les réouvre.
const TARGET_PRESETS = {
  'dvap-autonomous': {
    label: 'DVAP · autonomous-agent (ASI01)',
    url: 'http://localhost:8090/api/agent/process-paper',
    promptField: 'content',
    responseField: 'response',
    extra: '{"title": "Submitted research paper"}',
  },
  'dvap-prompt-injection': {
    label: 'DVAP · prompt-injection',
    url: 'http://localhost:8090/chat',
    promptField: 'message',
    responseField: 'response',
    extra: '',
  },
  custom: {
    label: 'Personnalisé',
    url: '',
    promptField: 'message',
    responseField: 'response',
    extra: '',
  },
} as const

type PresetKey = keyof typeof TARGET_PRESETS

export function LiveAuditPage() {
  const { addToast, setCurrentPage, setSelectedAuditId } = useApp()

  const [health, setHealth] = useState<HealthInfo | null>(null)
  const [agents, setAgents] = useState<AgentInfo[]>([])
  const [apiError, setApiError] = useState<string | null>(null)

  const [mode, setMode] = useState<AuditMode>('targeted')
  const [categories, setCategories] = useState<string[]>(['ASI_05'])
  const [preset, setPreset] = useState<PresetKey>('dvap-autonomous')
  // `as const` fige les valeurs des préréglages en types littéraux -> on annote en
  // string, sinon setTargetUrl n'accepterait plus que l'URL du préréglage initial.
  const [targetUrl, setTargetUrl] = useState<string>(TARGET_PRESETS['dvap-autonomous'].url)
  const [promptField, setPromptField] = useState<string>(TARGET_PRESETS['dvap-autonomous'].promptField)
  const [responseField, setResponseField] = useState<string>(TARGET_PRESETS['dvap-autonomous'].responseField)
  const [extraPayload, setExtraPayload] = useState<string>(TARGET_PRESETS['dvap-autonomous'].extra)
  const [profile, setProfile] = useState<LlmProfile>('final')
  const [attacksPerType, setAttacksPerType] = useState(3)
  const [pyritTurns, setPyritTurns] = useState(5)
  const [timeout_, setTimeout_] = useState(180)
  const [sourcePath, setSourcePath] = useState('')
  const [explainPasses, setExplainPasses] = useState(true)
  const [peerAgentId, setPeerAgentId] = useState('orchestrator-01')
  const [labs, setLabs] = useState<DvapLab[]>([])
  const [labsError, setLabsError] = useState<string | null>(null)
  const [labBusy, setLabBusy] = useState<string | null>(null)

  const [run, setRun] = useState<RunState | null>(null)
  const [logs, setLogs] = useState<RunLog[]>([])
  const [exchanges, setExchanges] = useState<LiveExchange[]>([])
  const [showLogs, setShowLogs] = useState(true)
  const [busy, setBusy] = useState(false)

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const sinceRef = useRef(0)
  const sinceExRef = useRef(0)
  const logBoxRef = useRef<HTMLDivElement>(null)
  const atkBoxRef = useRef<HTMLDivElement>(null)

  /* ── Santé de l'API ── */
  const refreshHealth = useCallback(() => {
    Promise.all([getHealth(), getAgents()])
      .then(([h, a]) => { setHealth(h); setAgents(a.agents); setApiError(null) })
      .catch((e: Error) => { setApiError(e.message); setHealth(null) })
  }, [])

  const loadLabs = useCallback(() => {
    getDvapLabs()
      .then(d => { setLabs(d.labs); setLabsError(d.error || null) })
      .catch((e: Error) => setLabsError(e.message))
  }, [])

  useEffect(() => { refreshHealth(); loadLabs() }, [refreshHealth, loadLabs])

  /* ── Reprise d'un audit en cours ──────────────────────────────────────
     Le suivi vit dans l'état de ce composant : changer de page ou rafraîchir
     le démontait et « perdait » un audit qui continuait pourtant côté serveur.
     Au montage, on demande à l'API s'il en existe un et on se raccroche. */
  useEffect(() => {
    if (run) return
    let cancelled = false
    fetchRuns()
      .then(({ runs }) => {
        const live = runs.find(r => r.status === 'running' || r.status === 'queued')
        if (cancelled || !live) return
        setBusy(true)
        poll(live.run_id)
        addToast({
          type: 'info', title: 'Audit en cours retrouvé',
          message: `${(live.categories || [live.request?.category]).join(', ')} — suivi repris`,
        })
      })
      .catch(() => {})       // API muette : le formulaire reste utilisable
    return () => { cancelled = true }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  /** Sélectionne un lab — le démarre d'abord s'il ne tourne pas encore. */
  const selectLab = async (lab: DvapLab) => {
    // Un lab découvert devient un préréglage « personnalisé » : son endpoint et
    // ses champs viennent du schéma OpenAPI, pas d'une table figée.
    const apply = (url: string, pf: string, rf: string,
                   extra?: Record<string, unknown> | null) => {
      setPreset('custom')
      setTargetUrl(url); setPromptField(pf); setResponseField(rf)
      // Champs constants exigés par la cible en plus du prompt (ex. `title`) :
      // sans eux la cible répond 422 et tous les tests sont exclus.
      setExtraPayload(extra ? JSON.stringify(extra) : '')
    }
    if (lab.running && lab.target_url) {
      apply(lab.target_url, lab.prompt_field || 'message',
            lab.response_field || 'response', lab.extra_payload)
      return
    }
    setLabBusy(lab.slug)
    try {
      const r = await launchDvapLab(lab.slug)
      apply(r.target_url, r.prompt_field, r.response_field, r.extra_payload)
      addToast({ type: 'success', title: `Lab ${lab.slug} lancé`, message: r.target_url })
      loadLabs()
    } catch (e) {
      addToast({ type: 'error', title: 'Lancement du lab impossible',
                 message: (e as Error).message })
    } finally {
      setLabBusy(null)
    }
  }

  useEffect(() => {
    if (logBoxRef.current) logBoxRef.current.scrollTop = logBoxRef.current.scrollHeight
  }, [logs])

  useEffect(() => {
    if (atkBoxRef.current) atkBoxRef.current.scrollTop = atkBoxRef.current.scrollHeight
  }, [exchanges])

  const stopPolling = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
  }, [])

  useEffect(() => () => stopPolling(), [stopPolling])

  /* ── Suivi d'une exécution ── */
  const poll = useCallback((runId: string) => {
    stopPolling()
    sinceRef.current = 0
    sinceExRef.current = 0
    setLogs([])
    setExchanges([])
    pollRef.current = setInterval(async () => {
      try {
        const s = await getRun(runId, sinceRef.current, sinceExRef.current)
        sinceRef.current = s.log_count
        sinceExRef.current = s.exchange_count
        if (s.logs.length) setLogs(prev => [...prev, ...s.logs].slice(-800))
        if (s.exchanges?.length) {
          setExchanges(prev => [...prev, ...s.exchanges].slice(-300))
        }
        setRun(s)
        if (s.status === 'completed' || s.status === 'failed' || s.status === 'cancelled') {
          stopPolling()
          setBusy(false)
          if (s.status === 'completed') {
            addToast({
              type: 'success', title: 'Audit terminé',
              message: `Résultat : ${s.result_file}`,
            })
            void reloadAudits()   // l'historique et les attaques se mettent à jour
          } else if (s.status === 'failed') {
            addToast({ type: 'error', title: 'Audit en échec', message: s.error || '' })
          }
        }
      } catch (e) {
        stopPolling()
        setBusy(false)
        setApiError((e as Error).message)
      }
    }, 1500)
  }, [addToast, stopPolling])

  const launch = async () => {
    // JSON invalide -> on refuse AVANT de lancer : sinon la cible répond 422 sur chaque
    // requête et l'audit rend un score vide au bout de plusieurs minutes.
    let extra: Record<string, unknown> | null = null
    if (extraPayload.trim()) {
      try {
        extra = JSON.parse(extraPayload)
      } catch {
        addToast({
          type: 'error', title: 'Payload additionnel invalide',
          message: 'Ce champ doit être un objet JSON, ex. {"title": "x"}',
        })
        return
      }
    }
    setBusy(true)
    try {
      const { run_id } = await startAudit({
        mode, category: categories[0] || 'ASI_05', categories,
        target_url: targetUrl, profile,
        prompt_field: promptField, response_field: responseField, extra_payload: extra,
        attacks_per_type: attacksPerType, pyrit_max_turns: pyritTurns,
        timeout: timeout_, source_path: sourcePath || null,
        explain_passes: explainPasses, max_concurrent: 2,
        peer_agent_id: categories.includes('ASI_07') ? (peerAgentId || null) : null,
      })
      addToast({ type: 'info', title: 'Audit lancé', message: run_id })
      poll(run_id)
    } catch (e) {
      setBusy(false)
      addToast({ type: 'error', title: 'Lancement impossible', message: (e as Error).message })
    }
  }

  const stop = async () => {
    if (!run) return
    try { await cancelRun(run.run_id); addToast({ type: 'warning', title: 'Annulation demandée' }) }
    catch (e) { addToast({ type: 'error', title: 'Annulation impossible', message: (e as Error).message }) }
  }

  const available = agents.filter(a => a.available)
  const running = run?.status === 'running' || run?.status === 'queued'
  const arch = stageToArch(run?.stage || '', run?.progress || 0)

  // Résultat final converti au format de l'interface pour le radar et le score.
  const finalAudit: Audit | null = run?.result
    ? adaptAudit(run.result, run.result_file || run.run_id)
    : null
  const score = finalAudit?.global_score ?? null
  const scoreColor = score === null ? 'var(--text-muted)'
    : score >= 86 ? 'var(--sev-info)' : score >= 71 ? 'var(--sev-low)'
    : score >= 51 ? 'var(--sev-medium)' : score >= 31 ? 'var(--sev-high)' : 'var(--sev-critical)'
  const criticals = finalAudit
    ? finalAudit.agents.flatMap(a => a.vulnerabilities).filter(v => v.severity === 'Critical').length
    : 0

  return (
    <div className="p-6 space-y-5 max-w-[1500px] mx-auto pb-16">
      {/* ─── API injoignable ─── */}
      {apiError && (
        <div className="card p-5 border-2 border-severity-critical/40 bg-severity-critical/[0.05]">
          <div className="flex items-start gap-3">
            <ServerCrash size={22} className="text-severity-critical mt-0.5 shrink-0" />
            <div className="flex-1">
              <div className="text-sm font-semibold text-severity-critical">API d'audit injoignable</div>
              <p className="text-xs text-text-secondary mt-1">{apiError}</p>
              <code className="block mt-2 code-block p-2.5 text-[11px] font-mono">
                cd ai_security_framework{'\n'}
                python -m uvicorn api.main:app --port 8000
              </code>
            </div>
            <button
              onClick={refreshHealth}
              className="px-3 py-1.5 rounded-xl border border-border text-xs font-medium
                         text-text-secondary hover:text-text-primary flex items-center gap-1.5"
            >
              <RefreshCw size={13} /> Réessayer
            </button>
          </div>
        </div>
      )}

      {/* ─── Formulaire ─── */}
      {!running && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="card p-6 space-y-5">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-[0.14em] text-text-muted">
                Console d'audit
              </div>
              <h2 className="text-2xl font-bold text-text-primary mt-1">Lancer un audit</h2>
              <p className="text-sm text-text-secondary mt-1">
                Exécution réelle côté serveur — attaques envoyées à la cible, sandbox Docker inclus.
              </p>
            </div>
            {health && (
              <div className="flex flex-wrap gap-2">
                <Chip ok={health.services.runner} label="Runner" />
                <Chip ok={health.services.docker_sandbox} label="Sandbox Docker" />
                <Chip ok={health.services.gemini_key} label="Clé Gemini" />
              </div>
            )}
          </div>

          {/* ─── Mode d'exécution ─── */}
          <div>
            <Label>Mode d'exécution</Label>
            <div className="grid gap-3 md:grid-cols-3">
              {MODES.map(m => {
                const on = mode === m.id
                const Icon = m.icon
                return (
                  <button
                    key={m.id}
                    onClick={() => setMode(m.id)}
                    className={`text-left p-3.5 rounded-xl border transition-all
                      ${on ? 'shadow-card' : 'bg-bg-elevated border-border hover:border-border-bright'}`}
                    style={on ? {
                      borderColor: `color-mix(in srgb, ${m.color} 45%, transparent)`,
                      background: `color-mix(in srgb, ${m.color} 7%, transparent)`,
                    } : undefined}
                  >
                    <div className="flex items-center gap-2 mb-1.5">
                      <Icon size={16} style={{ color: on ? m.color : 'var(--text-muted)' }} />
                      <span className="text-sm font-semibold"
                            style={{ color: on ? m.color : 'var(--text-primary)' }}>
                        {m.name}
                      </span>
                    </div>
                    <p className="text-[11px] text-text-muted leading-snug">{m.hint}</p>
                    <p className="text-[11px] font-mono mt-1.5"
                       style={{ color: on ? m.color : 'var(--text-muted)' }}>
                      {m.cost}
                    </p>
                  </button>
                )
              })}
            </div>
            {mode === 'quick' && (
              <p className="text-[11px] text-text-secondary mt-2 flex items-start gap-1.5">
                <ShieldAlert size={12} className="mt-0.5 shrink-0 text-severity-low" />
                DeepTeam, PyRIT et les payloads Microsoft sont désactivés. Il ne reste que
                les axes déterministes — reproductibles, donc les seuls qui puissent
                bloquer un déploiement automatiquement.
              </p>
            )}
          </div>

          {/* Catégories — sélection MULTIPLE en mode ciblé : un audit peut porter
              sur un, deux ou dix agents. Les autres modes fixent le périmètre. */}
          <div>
            <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
              <Label>
                {mode === 'targeted'
                  ? `Catégories à auditer — ${categories.length} sélectionnée(s)`
                  : `Périmètre imposé par le mode — ${available.length} agents`}
              </Label>
              {mode === 'targeted' && (
                <div className="flex gap-2 items-center">
                  <button
                    onClick={() => setCategories(available.map(a => a.id))}
                    className="text-[11px] text-brand hover:underline"
                  >
                    Tout sélectionner
                  </button>
                  <span className="text-text-muted text-[11px]">·</span>
                  <button
                    onClick={() => setCategories([])}
                    className="text-[11px] text-text-muted hover:text-text-primary"
                  >
                    Aucune
                  </button>
                </div>
              )}
            </div>
            <div className="flex flex-wrap gap-2">
              {agents.map(a => {
                const forced = mode !== 'targeted'
                const on = forced ? a.available : categories.includes(a.id)
                return (
                  <button
                    key={a.id}
                    disabled={!a.available || forced}
                    onClick={() => setCategories(prev =>
                      prev.includes(a.id) ? prev.filter(x => x !== a.id) : [...prev, a.id])}
                    title={a.available ? a.name : 'Agent non implémenté — Phase 2'}
                    className={`px-3 py-1.5 rounded-xl text-xs font-medium border transition-all
                      ${!a.available
                        ? 'opacity-40 cursor-not-allowed bg-bg-elevated text-text-muted border-border'
                        : on ? 'bg-brand/[0.08] text-brand border-brand/30'
                        : 'bg-bg-elevated text-text-muted border-border hover:text-text-secondary'}
                      ${forced ? 'cursor-default' : ''}`}
                  >
                    {a.id.replace('_', '')} — {a.name}
                  </button>
                )
              })}
            </div>
            {mode === 'targeted' && categories.length === 0 && (
              <p className="text-[11px] text-severity-high mt-2">
                Sélectionnez au moins une catégorie.
              </p>
            )}
            {mode === 'targeted' && categories.length > 1 && (
              <p className="text-[11px] text-text-muted mt-2">
                Les {categories.length} agents s'exécutent séquentiellement — ils partagent
                le même limiteur de débit LLM, les paralléliser n'apporterait rien.
              </p>
            )}
          </div>

          <div className="grid gap-5 md:grid-cols-2">
            <div>
              <Label>Cible</Label>
              <select
                value={preset}
                onChange={e => {
                  const k = e.target.value as PresetKey
                  const p = TARGET_PRESETS[k]
                  setPreset(k)
                  setPromptField(p.promptField)
                  setResponseField(p.responseField)
                  setExtraPayload(p.extra)
                  if (p.url) setTargetUrl(p.url)
                }}
                className="w-full px-3 py-2.5 rounded-xl bg-bg-elevated border border-border
                           text-sm text-text-primary outline-none focus:border-brand"
              >
                {(Object.keys(TARGET_PRESETS) as PresetKey[]).map(k => (
                  <option key={k} value={k}>{TARGET_PRESETS[k].label}</option>
                ))}
              </select>
            </div>
            <div>
              <Label>URL de la cible</Label>
              <input
                value={targetUrl} onChange={e => setTargetUrl(e.target.value)}
                className="w-full px-3 py-2.5 rounded-xl bg-bg-elevated border border-border
                           text-sm font-mono text-text-primary outline-none focus:border-brand"
              />
            </div>
          </div>

          {/* Labs DVAP — cibles d'entraînement.
              L'endpoint de chaque lab est DÉCOUVERT via son schéma OpenAPI : les
              15 labs n'exposent pas le même chemin ni les mêmes champs JSON, et un
              mappage codé en dur se périmerait à chaque nouveau lab. */}
          <div>
            <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
              <Label>Lab DVAP — cible d'entraînement</Label>
              <button
                onClick={loadLabs}
                className="text-[11px] text-text-muted hover:text-text-primary flex items-center gap-1.5"
              >
                <RefreshCw size={11} /> Rafraîchir
              </button>
            </div>

            {labsError ? (
              <p className="text-[11px] text-severity-high">{labsError}</p>
            ) : labs.length === 0 ? (
              <p className="text-[11px] text-text-muted">Chargement du catalogue…</p>
            ) : (
              <>
                <div className="flex flex-wrap gap-2">
                  {labs.map(l => {
                    const on = targetUrl === l.target_url
                    return (
                      <button
                        key={l.slug}
                        onClick={() => selectLab(l)}
                        disabled={labBusy === l.slug}
                        title={`${l.name} — ${l.description}`}
                        className={`px-2.5 py-1.5 rounded-xl text-xs font-medium border
                          transition-all flex items-center gap-1.5
                          ${on ? 'bg-brand/[0.08] text-brand border-brand/30'
                               : l.running
                                 ? 'bg-bg-elevated text-text-secondary border-border hover:text-text-primary'
                                 : 'bg-bg-elevated text-text-muted border-border hover:text-text-secondary'}`}
                      >
                        {labBusy === l.slug
                          ? <Loader2 size={11} className="animate-spin" />
                          : <span className="w-1.5 h-1.5 rounded-full shrink-0"
                                  style={{ background: l.running
                                    ? 'var(--sev-low)' : 'var(--text-muted)' }} />}
                        {l.slug}
                        <span className="opacity-60 text-[10px]">{l.difficulty}</span>
                      </button>
                    )
                  })}
                </div>
                <p className="text-[11px] text-text-muted mt-2">
                  Pastille verte : lab déjà lancé, cliquer le sélectionne. Pastille grise :
                  le lab démarre au clic (jusqu'à deux minutes), puis son endpoint et son
                  format JSON sont détectés automatiquement.
                </p>
              </>
            )}
          </div>

          {preset === 'custom' && (
            <div className="grid gap-5 md:grid-cols-3">
              <div>
                <Label>Champ du prompt</Label>
                <input
                  value={promptField} onChange={e => setPromptField(e.target.value)}
                  className="w-full px-3 py-2.5 rounded-xl bg-bg-elevated border border-border
                             text-sm font-mono text-text-primary outline-none focus:border-brand"
                />
              </div>
              <div>
                <Label>Champ de la réponse</Label>
                <input
                  value={responseField} onChange={e => setResponseField(e.target.value)}
                  className="w-full px-3 py-2.5 rounded-xl bg-bg-elevated border border-border
                             text-sm font-mono text-text-primary outline-none focus:border-brand"
                />
              </div>
              <div>
                <Label>Champs constants (JSON)</Label>
                <input
                  value={extraPayload} onChange={e => setExtraPayload(e.target.value)}
                  placeholder='{"title": "..."}'
                  className="w-full px-3 py-2.5 rounded-xl bg-bg-elevated border border-border
                             text-sm font-mono text-text-primary outline-none focus:border-brand"
                />
              </div>
            </div>
          )}

          <div>
            <Label>Profil LLM</Label>
            <div className="flex gap-2 flex-wrap">
              {(['final', 'dev', 'dry_run'] as LlmProfile[]).map(p => (
                <button
                  key={p} onClick={() => setProfile(p)}
                  className={`px-4 py-2.5 rounded-xl text-sm font-medium border transition-all
                    ${profile === p
                      ? 'bg-brand/[0.08] text-brand border-brand/30 shadow-card'
                      : 'bg-bg-elevated text-text-secondary border-border hover:text-text-primary'}`}
                >
                  {p}
                  {p === 'final' && <span className="ml-1.5 text-[9px] uppercase opacity-70">audit officiel</span>}
                </button>
              ))}
            </div>
          </div>

          <div className="grid gap-5 md:grid-cols-3">
            <Slider label="Attaques par type" value={attacksPerType} min={1} max={10} onChange={setAttacksPerType} />
            <Slider label="Tours PyRIT" value={pyritTurns} min={1} max={10} onChange={setPyritTurns} />
            <Slider label="Timeout HTTP (s)" value={timeout_} min={30} max={300} step={30} onChange={setTimeout_} />
          </div>

          {/* ASI07 : l'usurpation d'identité de pair ne concerne que cette catégorie.
              Le champ n'apparaît donc que si elle est sélectionnée. */}
          {categories.includes('ASI_07') && (
            <div>
              <Label>ASI07 — identité d'agent pair usurpée</Label>
              <div className="flex items-center gap-2 px-3 py-2.5 rounded-xl bg-bg-elevated border border-border">
                <Users size={15} className="text-text-muted shrink-0" />
                <input
                  value={peerAgentId} onChange={e => setPeerAgentId(e.target.value)}
                  placeholder="orchestrator-01 — laisser vide pour ne pas usurper"
                  className="flex-1 bg-transparent text-sm font-mono text-text-primary
                             placeholder:text-text-muted outline-none"
                />
              </div>
              <p className="text-[11px] text-text-muted mt-2">
                Chaque prompt est enveloppé dans un message inter-agents <b>non signé</b>{' '}
                prétendant venir de cet agent. Si la cible obéit sans vérifier la provenance,
                <code className="mx-1 font-mono">message_spoofing</code> est démontré.
              </p>
            </div>
          )}

          <div>
            <Label>Code source de la cible — active la couche statique</Label>
            <div className="flex items-center gap-2 px-3 py-2.5 rounded-xl bg-bg-elevated border border-border">
              <FolderCode size={15} className="text-text-muted shrink-0" />
              <input
                value={sourcePath} onChange={e => setSourcePath(e.target.value)}
                placeholder="Chemin local — laisser vide pour un audit boîte-noire"
                className="flex-1 bg-transparent text-sm font-mono text-text-primary
                           placeholder:text-text-muted outline-none"
              />
            </div>
          </div>

          <label className="flex items-start gap-2.5 cursor-pointer">
            <input
              type="checkbox" checked={explainPasses}
              onChange={e => setExplainPasses(e.target.checked)}
              className="mt-0.5 accent-brand w-4 h-4"
            />
            <span>
              <span className="text-sm text-text-primary">Analyser aussi les attaques résistées</span>
              <span className="block text-xs text-text-muted mt-0.5">
                Le juge classe chaque refus en robuste, partiel ou accidentel — révèle les
                scores faussement rassurants. Environ trois fois plus d'appels LLM.
              </span>
            </span>
          </label>

          {attacksPerType === 1 && (
            <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-severity-high/10 border border-severity-high/25">
              <AlertTriangle size={14} className="text-severity-high" />
              <span className="text-xs font-medium text-severity-high">
                Confiance faible — un score mono-run est bruité
              </span>
            </div>
          )}

          <button
            onClick={launch}
            disabled={busy || !!apiError || (mode === 'targeted' && categories.length === 0)}
            className="px-6 py-3 rounded-xl bg-brand text-white text-sm font-semibold
                       flex items-center gap-2 hover:bg-brand-dark transition-all shadow-glow
                       disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {busy ? <Loader2 size={18} className="animate-spin" /> : <Play size={18} />}
            {busy ? 'Lancement…' : "Lancer l'audit"}
          </button>
        </motion.div>
      )}

      {/* ─── Exécution ─── */}
      {run && (
        <>
          <div className="card p-4 flex items-center gap-3 flex-wrap">
            <span className="font-mono text-xs text-text-muted">{run.run_id}</span>
            <span className={`px-2.5 py-1 rounded-lg font-semibold text-[11px] uppercase tracking-wide
              ${run.status === 'running' ? 'bg-severity-low/10 text-severity-low'
                : run.status === 'completed' ? 'bg-sev-info/10 text-severity-info'
                : run.status === 'failed' ? 'bg-severity-critical/10 text-severity-critical'
                : 'bg-bg-elevated text-text-secondary'}`}>
              {run.status}
            </span>
            <span className="text-sm text-text-primary font-medium">{run.stage}</span>

            {running && (
              <button
                onClick={stop}
                className="ml-auto px-3.5 py-2 rounded-xl border border-border text-sm
                           text-severity-critical hover:bg-severity-critical/[0.07] flex items-center gap-2"
              >
                <Square size={15} /> Annuler
              </button>
            )}
            {run.status === 'completed' && (
              <button
                onClick={() => { setRun(null); setLogs([]) }}
                className="ml-auto px-3.5 py-2 rounded-xl border border-border text-sm
                           text-text-secondary hover:text-text-primary flex items-center gap-2"
              >
                <Play size={15} /> Nouvel audit
              </button>
            )}

            <div className="w-full h-1.5 rounded-full bg-bg-elevated overflow-hidden mt-1">
              <motion.div
                className="h-full rounded-full bg-brand"
                animate={{ width: `${run.progress}%` }}
                transition={{ duration: 0.4 }}
              />
            </div>
          </div>

          <ArchitectureFlow
            active={running ? arch.active : 'gate'}
            done={running ? arch.done : []}
            category={`${run.request.category} · ${run.request.profile}`}
          />

          {/* Score final */}
          {finalAudit && (
            <div className="grid gap-5 lg:grid-cols-[1fr_minmax(300px,420px)]">
              <div className="card p-6 flex flex-col justify-center items-center">
                <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-text-muted">
                  Score global
                </div>
                <div className="text-[76px] leading-none font-bold font-mono tabular mt-2" style={{ color: scoreColor }}>
                  {score?.toFixed(1)}
                </div>
                <div className="text-sm text-text-muted mt-1">sur 100 · {finalAudit.risk_level}</div>
                {criticals > 0 && (
                  <motion.div
                    initial={{ scale: 2, opacity: 0, rotate: -12 }}
                    animate={{ scale: 1, opacity: 1, rotate: -5 }}
                    transition={{ type: 'spring', stiffness: 220, damping: 16 }}
                    className="mt-5 px-5 py-2.5 rounded-xl border-[3px] border-severity-critical
                               bg-severity-critical/[0.07] flex items-center gap-2"
                  >
                    <Ban size={20} className="text-severity-critical" />
                    <span className="text-severity-critical font-bold tracking-wide">
                      {criticals} CRITICAL — DÉPLOIEMENT BLOQUÉ
                    </span>
                  </motion.div>
                )}
                {criticals > 0 && score !== null && score >= 70 && (
                  <p className="text-xs text-text-secondary mt-3 text-center max-w-md text-balance">
                    Le score dépasse le seuil de 70, et pourtant des détournements Critical
                    sont confirmés. Un seuil unique aurait laissé passer ce déploiement.
                  </p>
                )}
              </div>
              <div className="card p-5">
                <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-text-muted mb-2">
                  Couverture ASI
                </div>
                <AsioRadarChart audit={finalAudit} />
              </div>
            </div>
          )}

          {/* ─── Attaques en direct ─── */}
          <div className="card overflow-hidden">
            <div className="flex items-center gap-2 p-4 border-b border-border">
              <ShieldAlert size={14} className="text-brand" />
              <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-text-muted">
                Attaques envoyées à la cible — en direct
              </span>
              <span className="text-[11px] font-mono tabular font-semibold text-text-secondary
                               px-2 py-0.5 rounded-lg bg-bg-elevated ml-1">
                {exchanges.length}
              </span>
              {running && (
                <span className="flex items-center gap-1.5 text-[11px] text-severity-low ml-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-severity-low animate-pulse" />
                  en cours
                </span>
              )}
            </div>

            <div ref={atkBoxRef} className="max-h-[520px] overflow-y-auto terminal-scroll p-4 space-y-3">
              {exchanges.length === 0 && (
                <p className="text-sm text-text-muted py-10 text-center">
                  {running
                    ? "Les échanges avec la cible s'afficheront ici dès le premier envoi."
                    : 'Aucun échange capturé.'}
                </p>
              )}

              <AnimatePresence initial={false}>
                {exchanges.map(ex => (
                  <motion.div
                    key={ex.n}
                    initial={{ opacity: 0, x: -14 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.25 }}
                    className={`rounded-xl border p-3.5 ${ex.http_error
                      ? 'border-severity-high/40 bg-severity-high/[0.05]'
                      : 'border-border bg-bg-elevated'}`}
                  >
                    <div className="flex items-center gap-2 mb-2.5 flex-wrap">
                      <span className="w-7 h-7 rounded-lg bg-bg-surface border border-border
                                       flex items-center justify-center text-[11px] font-mono font-bold
                                       text-text-secondary shrink-0">
                        {String(ex.n).padStart(2, '0')}
                      </span>
                      <span className="text-[11px] font-mono text-text-muted tabular">
                        {ex.elapsed_s}s
                      </span>
                      {ex.http_error && (
                        <span className="px-2 py-0.5 rounded-md bg-severity-high/15
                                         text-severity-high text-[10px] font-bold">
                          CIBLE INJOIGNABLE — EXCLU
                        </span>
                      )}
                    </div>

                    <div className="grid gap-2.5 lg:grid-cols-2">
                      <div>
                        <div className="text-[10px] font-bold uppercase tracking-[0.12em] mb-1.5
                                        flex items-center gap-1.5" style={{ color: 'var(--brand)' }}>
                          <ArrowRight size={11} /> Attaque envoyée
                        </div>
                        <div className="code-block p-2.5 border-l-4 max-h-40 overflow-auto terminal-scroll"
                             style={{ borderLeftColor: 'var(--brand)' }}>
                          <pre className="text-[11px] font-mono whitespace-pre-wrap break-words leading-relaxed">
                            {ex.prompt}
                          </pre>
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] font-bold uppercase tracking-[0.12em] mb-1.5
                                        flex items-center gap-1.5"
                             style={{ color: ex.http_error ? 'var(--sev-high)' : 'var(--layer-behavioral)' }}>
                          <ArrowLeft size={11} /> Réponse de la cible
                        </div>
                        <div className="code-block p-2.5 border-l-4 max-h-40 overflow-auto terminal-scroll"
                             style={{ borderLeftColor: ex.http_error ? 'var(--sev-high)' : 'var(--layer-behavioral)' }}>
                          <pre className="text-[11px] font-mono whitespace-pre-wrap break-words leading-relaxed">
                            {ex.response}
                          </pre>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>

            {run.status === 'completed' && (
              <div className="p-3 border-t border-border bg-bg-elevated flex items-center gap-2 flex-wrap">
                <span className="text-xs text-text-secondary">
                  Verdicts détaillés et analyses du juge disponibles sur la page Attaques.
                </span>
                <button
                  onClick={() => { setSelectedAuditId(null); setCurrentPage('attacks') }}
                  className="ml-auto text-xs text-brand hover:underline flex items-center gap-1"
                >
                  Voir les verdicts <ArrowRight size={12} />
                </button>
              </div>
            )}
          </div>

          {/* Terminal */}
          <div className="card overflow-hidden">
            <button
              onClick={() => setShowLogs(v => !v)}
              className="w-full flex items-center gap-2 p-4 hover:bg-bg-elevated transition-colors"
            >
              <Terminal size={14} className="text-text-muted" />
              <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-text-muted">
                Journal d'exécution — sortie réelle du runner
              </span>
              <span className="text-[11px] text-text-muted tabular ml-1">{logs.length}</span>
              {showLogs ? <ChevronUp size={14} className="ml-auto text-text-muted" />
                : <ChevronDown size={14} className="ml-auto text-text-muted" />}
            </button>
            {showLogs && (
              <div ref={logBoxRef} className="code-block rounded-none max-h-[460px] overflow-y-auto terminal-scroll p-3 space-y-0.5">
                {logs.length === 0 && (
                  <div className="text-[11px] font-mono text-text-muted">En attente de sortie…</div>
                )}
                {logs.map((l, i) => (
                  <div key={i} className="text-[11px] font-mono leading-relaxed flex gap-2">
                    <span className="shrink-0 font-semibold" style={{ color: LOG_COLOR[l.level] || '#64748B' }}>
                      {l.level.slice(0, 4).toUpperCase().padEnd(4)}
                    </span>
                    <span style={{ color: l.level === 'debug' ? '#8B96AE' : '#E6EDF9' }}>{l.text}</span>
                  </div>
                ))}
                {running && <div className="text-[11px] font-mono text-severity-low animate-pulse">▊</div>}
              </div>
            )}
          </div>
        </>
      )}

      {!run && !apiError && (
        <p className="text-xs text-text-muted text-center">
          API : <code className="font-mono">{API_BASE}</code>
        </p>
      )}
    </div>
  )
}

/* ─────────────────────────── sous-composants ─────────────────────────── */

function Label({ children }: { children: React.ReactNode }) {
  return (
    <label className="text-[10px] font-semibold uppercase tracking-[0.12em] text-text-secondary mb-2 block">
      {children}
    </label>
  )
}

function Chip({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-semibold border"
      style={{
        color: ok ? 'var(--sev-low)' : 'var(--sev-high)',
        borderColor: `color-mix(in srgb, ${ok ? 'var(--sev-low)' : 'var(--sev-high)'} 30%, transparent)`,
        background: `color-mix(in srgb, ${ok ? 'var(--sev-low)' : 'var(--sev-high)'} 8%, transparent)`,
      }}
    >
      {ok ? <CheckCircle size={12} /> : <AlertTriangle size={12} />} {label}
    </span>
  )
}

function Slider({ label, value, min, max, step = 1, onChange }: {
  label: string; value: number; min: number; max: number
  step?: number; onChange: (v: number) => void
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-text-secondary">
          {label}
        </span>
        <span className="font-mono font-bold tabular text-text-primary text-sm">{value}</span>
      </div>
      <input
        type="range" min={min} max={max} step={step} value={value}
        onChange={e => onChange(Number(e.target.value))}
        className="w-full accent-brand"
      />
    </div>
  )
}
