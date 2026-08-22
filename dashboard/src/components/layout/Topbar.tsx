import { Search, Sun, Moon, Command, Database, FlaskConical } from 'lucide-react'
import { useApp } from '@/App'
import { hasRealData, useAudits } from '@/data/repository'
import type { PageId } from '@/types'

const PAGE_TITLES: Record<PageId, string> = {
  overview: 'Vue d\'ensemble',
  history: 'Historique des audits',
  attacks: 'Attaques & vulnérabilités',
  live: 'Audit en direct',
  comparison: 'Comparatif & régressions',
  'quality-gate': 'Quality Gate',
}

export function Topbar() {
  const { theme, toggleTheme, currentPage, setCommandPaletteOpen } = useApp()
  useAudits()   // le badge de provenance suit l'état réel du chargement

  return (
    <header className="relative z-10 h-16 flex items-center justify-between px-6 border-b border-border bg-bg-surface/60 backdrop-blur-xl">
      <div className="flex items-center gap-2 text-sm">
        <span className="text-text-muted">Console de sécurité</span>
        <span className="text-text-muted">/</span>
        <span className="text-text-primary font-medium">{PAGE_TITLES[currentPage]}</span>
      </div>

      <div className="flex items-center gap-3">
        {/* Provenance des données : un auditeur doit savoir en un coup d'œil s'il
            regarde de vrais résultats ou le jeu de démonstration. */}
        {hasRealData() ? (
          <span
            className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px]
                       font-semibold bg-severity-low/10 text-severity-low border border-severity-low/25"
            title="Résultats produits par scripts/run_agent.py"
          >
            <Database size={12} /> Données réelles
          </span>
        ) : (
          <span
            className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px]
                       font-semibold bg-severity-medium/12 text-severity-medium border border-severity-medium/25"
            title="Lancez : python scripts/sync_dashboard.py"
          >
            <FlaskConical size={12} /> Démonstration
          </span>
        )}

        <button
          onClick={() => setCommandPaletteOpen(true)}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-bg-elevated border border-border text-text-secondary text-sm hover:border-border-bright transition-colors"
        >
          <Search size={15} />
          <span className="hidden md:inline">Rechercher...</span>
          <kbd className="flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-bg-deep text-[10px] font-mono text-text-muted border border-border">
            <Command size={10} />K
          </kbd>
        </button>

        <button
          onClick={toggleTheme}
          className="w-9 h-9 rounded-lg bg-bg-elevated border border-border flex items-center justify-center text-text-secondary hover:text-text-primary transition-colors"
          aria-label="Basculer le thème"
        >
          {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
        </button>

        <div className="w-9 h-9 rounded-full bg-gradient-to-br from-brand to-brand-dark flex items-center justify-center text-white text-sm font-bold">
          AB
        </div>
      </div>
    </header>
  )
}
