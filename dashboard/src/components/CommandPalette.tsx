import { useState, useEffect, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Search, Radio, ArrowRight, LayoutDashboard, Factory as History, Swords, GitCompareArrows, ShieldCheck } from 'lucide-react'
import { useApp } from '@/App'
import { getAudits } from '@/data/repository'

interface CommandItem {
  id: string
  label: string
  category: string
  icon: typeof Search
  action: () => void
}

export function CommandPalette() {
  const { commandPaletteOpen, setCommandPaletteOpen, setCurrentPage, setSelectedAuditId, addToast } = useApp()
  const [query, setQuery] = useState('')

  useEffect(() => {
    if (!commandPaletteOpen) setQuery('')
  }, [commandPaletteOpen])

  const items: CommandItem[] = useMemo(() => {
    const nav: CommandItem[] = [
      { id: 'nav-overview', label: 'Vue d\'ensemble', category: 'Navigation', icon: LayoutDashboard, action: () => setCurrentPage('overview') },
      { id: 'nav-history', label: 'Historique des audits', category: 'Navigation', icon: History, action: () => setCurrentPage('history') },
      { id: 'nav-attacks', label: 'Attaques & vulnérabilités', category: 'Navigation', icon: Swords, action: () => setCurrentPage('attacks') },
      { id: 'nav-live', label: 'Live Audit', category: 'Navigation', icon: Radio, action: () => setCurrentPage('live') },
      { id: 'nav-comparison', label: 'Comparatif & régressions', category: 'Navigation', icon: GitCompareArrows, action: () => setCurrentPage('comparison') },
      { id: 'nav-qg', label: 'Quality Gate', category: 'Navigation', icon: ShieldCheck, action: () => setCurrentPage('quality-gate') },
    ]
    const audits: CommandItem[] = getAudits().map(a => ({
      id: `audit-${a.id}`,
      label: `${a.target_name} — Score ${a.global_score}`,
      category: 'Audits',
      icon: Search,
      action: () => {
        setSelectedAuditId(a.id)
        setCurrentPage('history')
        addToast({ type: 'info', title: 'Audit sélectionné', message: a.target_name })
      },
    }))
    const actions: CommandItem[] = [
      { id: 'action-launch', label: 'Lancer un nouvel audit', category: 'Actions', icon: Radio, action: () => { setCurrentPage('live'); addToast({ type: 'info', title: 'Live Audit', message: 'Formulaire d\'audit prêt' }) } },
    ]
    return [...nav, ...audits, ...actions]
  }, [setCurrentPage, setSelectedAuditId, addToast])

  const filtered = useMemo(() => {
    if (!query) return items
    return items.filter(i => i.label.toLowerCase().includes(query.toLowerCase()))
  }, [items, query])

  return (
    <AnimatePresence>
      {commandPaletteOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-start justify-center pt-24 bg-black/50 backdrop-blur-sm"
          onClick={() => setCommandPaletteOpen(false)}
        >
          <motion.div
            initial={{ opacity: 0, y: -20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -20, scale: 0.95 }}
            transition={{ type: 'spring', stiffness: 300, damping: 25 }}
            onClick={e => e.stopPropagation()}
            className="w-full max-w-xl mx-4 rounded-xl glass shadow-card overflow-hidden"
          >
            <div className="flex items-center gap-3 px-4 py-3 border-b border-border">
              <Search size={18} className="text-text-muted" />
              <input
                autoFocus
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Rechercher une page, un audit, une action..."
                className="flex-1 bg-transparent text-text-primary placeholder:text-text-muted outline-none text-sm"
                onKeyDown={e => {
                  if (e.key === 'Escape') setCommandPaletteOpen(false)
                  if (e.key === 'Enter' && filtered[0]) {
                    filtered[0].action()
                    setCommandPaletteOpen(false)
                  }
                }}
              />
              <kbd className="text-[10px] font-mono text-text-muted px-1.5 py-0.5 rounded bg-bg-deep border border-border">ESC</kbd>
            </div>
            <div className="max-h-80 overflow-y-auto p-2">
              {filtered.length === 0 && (
                <div className="text-center text-text-muted text-sm py-8">Aucun résultat</div>
              )}
              {filtered.map(item => {
                const Icon = item.icon
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      item.action()
                      setCommandPaletteOpen(false)
                    }}
                    className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-text-secondary hover:text-text-primary hover:bg-bg-elevated transition-colors text-left"
                  >
                    <Icon size={16} className="flex-shrink-0" />
                    <span className="flex-1">{item.label}</span>
                    <span className="text-[10px] text-text-muted uppercase tracking-wider">{item.category}</span>
                    <ArrowRight size={14} className="text-text-muted" />
                  </button>
                )
              })}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
