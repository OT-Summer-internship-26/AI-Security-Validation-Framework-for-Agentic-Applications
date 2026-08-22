import { motion } from 'framer-motion'
import {
  Globe, Network, Bot, Layers, Sword, FileSearch, Boxes,
  Scale, Calculator, FileText, ShieldCheck,
} from 'lucide-react'

/**
 * Schéma de l'architecture RÉELLE du framework, avec mise en évidence du
 * composant en cours d'exécution.
 *
 * Sert de repère pendant un audit long : on voit non seulement « quelle étape »
 * mais « quel composant du projet » travaille à cet instant.
 */

export type ArchStage =
  | 'idle' | 'target' | 'api' | 'graph' | 'agent'
  | 'deepteam' | 'pyrit' | 'garak' | 'microsoft'
  | 'static' | 'dynamic' | 'judge' | 'scoring' | 'report' | 'gate'

interface Node {
  id: ArchStage
  label: string
  sub: string
  icon: typeof Globe
  color: string
}

/** Ligne 1 — chaîne principale du pipeline. */
const MAIN: Node[] = [
  { id: 'target', label: 'Cible', sub: 'HTTP /chat', icon: Globe, color: 'var(--text-secondary)' },
  { id: 'api', label: 'API FastAPI', sub: 'POST /audit', icon: Network, color: 'var(--sev-info)' },
  { id: 'graph', label: 'LangGraph', sub: 'StateGraph', icon: Boxes, color: 'var(--sev-info)' },
  { id: 'agent', label: 'Agents ASI', sub: 'BaseSecurityAgent', icon: Bot, color: 'var(--brand)' },
]

/** Ligne 2 — les 4 axes comportementaux + les 2 autres couches. */
const LAYERS: Node[] = [
  { id: 'deepteam', label: 'DeepTeam', sub: 'axe ×0.5', icon: Sword, color: 'var(--layer-behavioral)' },
  { id: 'pyrit', label: 'PyRIT', sub: 'axe ×0.2', icon: Sword, color: 'var(--layer-behavioral)' },
  { id: 'garak', label: 'Garak', sub: 'axe ×0.2', icon: Sword, color: 'var(--layer-behavioral)' },
  { id: 'microsoft', label: 'Payloads MS', sub: 'axe ×0.1', icon: Sword, color: 'var(--layer-behavioral)' },
  { id: 'static', label: 'Statique', sub: 'Semgrep · pip-audit', icon: FileSearch, color: 'var(--layer-static)' },
  { id: 'dynamic', label: 'Dynamique', sub: 'sandbox Docker', icon: Layers, color: 'var(--layer-dynamic)' },
]

/** Ligne 3 — consolidation. */
const OUT: Node[] = [
  { id: 'judge', label: 'SeverityJudge', sub: 'gravité LLM', icon: Scale, color: 'var(--sev-info)' },
  { id: 'scoring', label: 'Scoring', sub: 'pondéré /100', icon: Calculator, color: 'var(--sev-info)' },
  { id: 'report', label: 'Rapport', sub: 'HTML · PDF', icon: FileText, color: 'var(--sev-info)' },
  { id: 'gate', label: 'Quality Gate', sub: 'CI/CD', icon: ShieldCheck, color: 'var(--brand)' },
]

export function ArchitectureFlow({
  active,
  done = [],
  category,
}: {
  active: ArchStage
  done?: ArchStage[]
  category?: string
}) {
  return (
    <div className="card p-5">
      <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
        <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-text-muted">
          Architecture du framework — composant en cours
        </div>
        {category && (
          <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded-lg
                           bg-brand/[0.08] text-brand border border-brand/20">
            {category}
          </span>
        )}
      </div>

      <div className="space-y-3 overflow-x-auto pb-1">
        <Row nodes={MAIN} active={active} done={done} arrowAfterLast />
        <Branch />
        <Row nodes={LAYERS} active={active} done={done} dense />
        <Branch up />
        <Row nodes={OUT} active={active} done={done} />
      </div>
    </div>
  )
}

function Row({ nodes, active, done, dense, arrowAfterLast }: {
  nodes: Node[]; active: ArchStage; done: ArchStage[]
  dense?: boolean; arrowAfterLast?: boolean
}) {
  return (
    <div className="flex items-stretch gap-1.5 min-w-max">
      {nodes.map((n, i) => (
        <div key={n.id} className="flex items-center gap-1.5">
          <NodeBox node={n} active={active === n.id} done={done.includes(n.id)} dense={dense} />
          {(i < nodes.length - 1 || arrowAfterLast) && (
            <Arrow lit={done.includes(n.id) || active === n.id} />
          )}
        </div>
      ))}
    </div>
  )
}

function NodeBox({ node, active, done, dense }: {
  node: Node; active: boolean; done: boolean; dense?: boolean
}) {
  const Icon = node.icon
  const state = active ? 'active' : done ? 'done' : 'idle'

  return (
    <motion.div
      animate={active ? { scale: 1.04 } : { scale: 1 }}
      transition={{ type: 'spring', stiffness: 300, damping: 22 }}
      className={`relative rounded-xl border flex items-center gap-2 transition-colors duration-300
        ${dense ? 'px-2.5 py-2' : 'px-3 py-2.5'}
        ${state === 'active' ? 'shadow-lifted' : state === 'done' ? '' : 'opacity-55'}`}
      style={{
        borderColor: state === 'idle' ? 'var(--border-base)'
          : `color-mix(in srgb, ${node.color} 45%, transparent)`,
        background: state === 'active'
          ? `color-mix(in srgb, ${node.color} 11%, var(--bg-surface))`
          : state === 'done'
            ? `color-mix(in srgb, ${node.color} 5%, var(--bg-surface))`
            : 'var(--bg-elevated)',
      }}
    >
      {active && (
        <span
          className="absolute inset-0 rounded-xl animate-pulse-ring pointer-events-none"
          style={{ ['--ring-color' as string]: `color-mix(in srgb, ${node.color} 40%, transparent)` }}
        />
      )}
      <Icon
        size={dense ? 15 : 17}
        style={{ color: state === 'idle' ? 'var(--text-muted)' : node.color }}
        className="shrink-0"
      />
      <div className="min-w-0">
        <div
          className={`${dense ? 'text-[11px]' : 'text-xs'} font-semibold leading-tight whitespace-nowrap`}
          style={{ color: state === 'idle' ? 'var(--text-muted)' : 'var(--text-primary)' }}
        >
          {node.label}
        </div>
        <div className="text-[9px] text-text-muted leading-tight whitespace-nowrap">
          {node.sub}
        </div>
      </div>
    </motion.div>
  )
}

function Arrow({ lit }: { lit: boolean }) {
  return (
    <svg width="22" height="10" className="shrink-0" aria-hidden>
      <line
        x1="0" y1="5" x2="15" y2="5"
        stroke={lit ? 'var(--sev-low)' : 'var(--border-base)'}
        strokeWidth="2" strokeLinecap="round"
        strokeDasharray={lit ? undefined : '4 4'}
        className={lit ? 'animate-flow-dash' : ''}
      />
      <path
        d="M15 1.5 L21 5 L15 8.5 Z"
        fill={lit ? 'var(--sev-low)' : 'var(--border-base)'}
      />
    </svg>
  )
}

function Branch({ up = false }: { up?: boolean }) {
  return (
    <div className="flex items-center gap-2 pl-6">
      <svg width="14" height="16" aria-hidden>
        <path
          d={up ? 'M7 15 L7 1 M3 5 L7 1 L11 5' : 'M7 1 L7 15 M3 11 L7 15 L11 11'}
          stroke="var(--border-bright)" strokeWidth="1.6" fill="none"
          strokeLinecap="round" strokeLinejoin="round"
        />
      </svg>
      <span className="text-[9px] uppercase tracking-[0.14em] text-text-muted">
        {up ? 'consolidation' : '3 couches — behavioral ×0.5 · static ×0.3 · dynamic ×0.2'}
      </span>
    </div>
  )
}
