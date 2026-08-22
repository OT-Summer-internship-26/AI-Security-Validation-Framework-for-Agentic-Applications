import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  LayoutDashboard, Factory as History, Swords, Radio, GitCompareArrows,
  ShieldCheck, ChevronLeft, ChevronRight, ChevronDown, Wrench,
} from 'lucide-react'
import type { PageId, ComponentStatus } from '@/types'
import { useApp } from '@/App'
import { Logo } from '@/components/Logo'
import { COMPONENTS } from '@/data/audits'

const NAV_ITEMS: {
  id: PageId; label: string; hint: string; icon: typeof LayoutDashboard
}[] = [
  { id: 'overview', label: 'Vue d\'ensemble', hint: 'Posture globale', icon: LayoutDashboard },
  { id: 'history', label: 'Historique', hint: 'Audits passés', icon: History },
  { id: 'attacks', label: 'Attaques', hint: 'Prompts et réponses', icon: Swords },
  { id: 'live', label: 'Live Audit', hint: 'Exécution en direct', icon: Radio },
  { id: 'comparison', label: 'Comparatif', hint: 'Régressions', icon: GitCompareArrows },
  { id: 'quality-gate', label: 'Quality Gate', hint: 'Politique CI/CD', icon: ShieldCheck },
]

const STATUS_STYLE: Record<ComponentStatus['status'], { dot: string; label: string }> = {
  operational: { dot: 'var(--sev-low)', label: 'opérationnel' },
  partial: { dot: 'var(--sev-medium)', label: 'partiel' },
  building: { dot: 'var(--text-muted)', label: 'Phase 2' },
}

export function Sidebar() {
  const { currentPage, setCurrentPage } = useApp()
  const [collapsed, setCollapsed] = useState(false)
  const [showComponents, setShowComponents] = useState(false)

  const ready = COMPONENTS.filter(c => c.status === 'operational').length

  return (
    <motion.aside
      animate={{ width: collapsed ? 76 : 264 }}
      transition={{ type: 'spring', stiffness: 320, damping: 32 }}
      className="sticky top-0 z-20 h-screen flex flex-col border-r border-border
                 bg-bg-surface/90 backdrop-blur-xl"
    >
      {/* ─── Marque ─── */}
      <div className={`flex items-center border-b border-border py-4
                       ${collapsed ? 'justify-center px-2' : 'px-4'}`}>
        <AnimatePresence mode="wait">
          <motion.div
            key={collapsed ? 'mini' : 'full'}
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
          >
            <Logo collapsed={collapsed} />
          </motion.div>
        </AnimatePresence>
      </div>

      {!collapsed && (
        <div className="px-4 pt-4 pb-1">
          <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-text-muted">
            Security Audit Console
          </div>
          <div className="text-[11px] text-text-muted mt-0.5">OWASP ASI 2026</div>
        </div>
      )}

      {/* ─── Navigation ─── */}
      <nav className="flex-1 py-3 px-2.5 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map(item => {
          const active = currentPage === item.id
          const Icon = item.icon
          return (
            <button
              key={item.id}
              onClick={() => setCurrentPage(item.id)}
              className={`w-full flex items-center gap-3 rounded-xl transition-all duration-200
                relative border text-left
                ${collapsed ? 'justify-center px-2 py-3' : 'px-3 py-2.5'}
                ${active
                  ? 'bg-brand/[0.07] border-brand/25'
                  : 'border-transparent hover:bg-bg-elevated'}`}
              title={collapsed ? item.label : undefined}
            >
              {active && (
                <motion.span
                  layoutId="nav-active"
                  className="absolute left-0 top-2 bottom-2 w-[3px] rounded-r-full bg-brand"
                  transition={{ type: 'spring', stiffness: 400, damping: 32 }}
                />
              )}
              <Icon
                size={19}
                className={`flex-shrink-0 ${active ? 'text-brand' : 'text-text-muted'}`}
              />
              {!collapsed && (
                <span className="min-w-0">
                  <span className={`block text-sm font-medium leading-tight
                    ${active ? 'text-brand' : 'text-text-primary'}`}>
                    {item.label}
                  </span>
                  <span className="block text-[11px] text-text-muted leading-tight mt-0.5">
                    {item.hint}
                  </span>
                </span>
              )}
            </button>
          )
        })}
      </nav>

      {/* ─── Composants : replié par défaut, ne mange plus la moitié de la barre ─── */}
      <div className="border-t border-border">
        {collapsed ? (
          <div className="py-3 flex flex-col items-center gap-1" title={`${ready}/${COMPONENTS.length} composants opérationnels`}>
            <Wrench size={16} className="text-text-muted" />
            <span className="text-[10px] font-mono font-semibold text-text-secondary">
              {ready}/{COMPONENTS.length}
            </span>
          </div>
        ) : (
          <>
            <button
              onClick={() => setShowComponents(v => !v)}
              className="w-full flex items-center gap-2 px-4 py-3 hover:bg-bg-elevated transition-colors"
            >
              <Wrench size={13} className="text-text-muted" />
              <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-text-muted">
                Composants
              </span>
              <span className="text-[10px] font-mono font-semibold text-text-secondary
                               px-1.5 py-0.5 rounded bg-bg-elevated">
                {ready}/{COMPONENTS.length}
              </span>
              <ChevronDown
                size={14}
                className={`ml-auto text-text-muted transition-transform duration-200
                            ${showComponents ? 'rotate-180' : ''}`}
              />
            </button>

            <AnimatePresence initial={false}>
              {showComponents && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.22 }}
                  className="overflow-hidden"
                >
                  <div className="px-4 pb-3 space-y-1.5 max-h-[280px] overflow-y-auto">
                    {COMPONENTS.map(c => {
                      const s = STATUS_STYLE[c.status]
                      return (
                        <div key={c.name} className="flex items-center gap-2" title={c.label}>
                          <span
                            className="w-1.5 h-1.5 rounded-full shrink-0"
                            style={{ background: s.dot }}
                          />
                          <span className={`text-[11px] truncate flex-1
                            ${c.status === 'building' ? 'text-text-muted' : 'text-text-secondary'}`}>
                            {c.name}
                          </span>
                          {c.status !== 'operational' && (
                            <span className="text-[9px] uppercase tracking-wide text-text-muted shrink-0">
                              {s.label}
                            </span>
                          )}
                        </div>
                      )
                    })}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </>
        )}
      </div>

      <button
        onClick={() => setCollapsed(v => !v)}
        className="absolute -right-3 top-24 w-6 h-6 rounded-full bg-bg-surface border border-border
                   flex items-center justify-center text-text-secondary hover:text-text-primary
                   hover:border-border-bright transition-colors z-30 shadow-card"
        aria-label={collapsed ? 'Déplier le menu' : 'Replier le menu'}
      >
        {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
      </button>
    </motion.aside>
  )
}
