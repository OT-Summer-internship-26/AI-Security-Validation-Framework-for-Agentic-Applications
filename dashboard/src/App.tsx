import { useState, useCallback, useEffect, createContext, useContext } from 'react'
import type { PageId, ToastMessage, Theme } from '@/types'
import { Layout } from '@/components/layout/Layout'
import { CommandPalette } from '@/components/CommandPalette'
import { ToastContainer } from '@/components/ToastContainer'

interface AppContextValue {
  theme: Theme
  toggleTheme: () => void
  currentPage: PageId
  setCurrentPage: (p: PageId) => void
  toasts: ToastMessage[]
  addToast: (t: Omit<ToastMessage, 'id'>) => void
  dismissToast: (id: string) => void
  commandPaletteOpen: boolean
  setCommandPaletteOpen: (v: boolean) => void
  selectedAuditId: string | null
  setSelectedAuditId: (id: string | null) => void
}

const AppContext = createContext<AppContextValue | null>(null)
export const useApp = () => {
  const ctx = useContext(AppContext)
  if (!ctx) throw new Error('useApp must be used within AppProvider')
  return ctx
}

const PAGES: PageId[] = ['overview', 'history', 'attacks', 'live', 'comparison', 'quality-gate']

/**
 * Routage par hash (`#/attacks?audit=xxx`).
 * Choisi plutôt qu'un routeur d'historique : le dashboard peut être servi en
 * fichier statique ou derrière n'importe quel chemin sans règle de réécriture
 * serveur. Permet rafraîchissement, retour arrière et partage de lien — ce que
 * la version Streamlit faisait avec `query_params`.
 */
function readHash(): { page: PageId; audit: string | null } {
  const raw = window.location.hash.replace(/^#\/?/, '')
  const [path, query] = raw.split('?')
  const page = (PAGES as string[]).includes(path) ? (path as PageId) : 'overview'
  const audit = new URLSearchParams(query || '').get('audit')
  return { page, audit }
}

function writeHash(page: PageId, audit: string | null): void {
  const q = audit ? `?audit=${encodeURIComponent(audit)}` : ''
  const next = `#/${page}${q}`
  if (window.location.hash !== next) window.history.pushState(null, '', next)
}

function App() {
  const initial = readHash()

  const [theme, setTheme] = useState<Theme>(() => {
    const stored = localStorage.getItem('audit-theme')
    return stored === 'dark' || stored === 'light' ? stored : 'light'
  })
  const [currentPage, setCurrentPageState] = useState<PageId>(initial.page)
  const [selectedAuditId, setSelectedAuditIdState] = useState<string | null>(initial.audit)
  const [toasts, setToasts] = useState<ToastMessage[]>([])
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false)

  const setCurrentPage = useCallback((p: PageId) => {
    setCurrentPageState(p)
    setSelectedAuditIdState(prev => {
      writeHash(p, prev)
      return prev
    })
  }, [])

  const setSelectedAuditId = useCallback((id: string | null) => {
    setSelectedAuditIdState(id)
    setCurrentPageState(prev => {
      writeHash(prev, id)
      return prev
    })
  }, [])

  // Retour arrière / avant du navigateur
  useEffect(() => {
    const onNav = () => {
      const { page, audit } = readHash()
      setCurrentPageState(page)
      setSelectedAuditIdState(audit)
    }
    window.addEventListener('popstate', onNav)
    window.addEventListener('hashchange', onNav)
    return () => {
      window.removeEventListener('popstate', onNav)
      window.removeEventListener('hashchange', onNav)
    }
  }, [])

  // Normalise l'URL au premier rendu (arrivée sur "/" sans hash)
  useEffect(() => {
    if (!window.location.hash) {
      window.history.replaceState(null, '', `#/${initial.page}`)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const toggleTheme = useCallback(() => {
    setTheme(t => {
      const next = t === 'dark' ? 'light' : 'dark'
      localStorage.setItem('audit-theme', next)
      return next
    })
  }, [])

  const addToast = useCallback((t: Omit<ToastMessage, 'id'>): void => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
    setToasts(prev => [...prev, { ...t, id }])
    setTimeout(() => {
      setToasts(prev => prev.filter(x => x.id !== id))
    }, 5000)
  }, [])

  const dismissToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(x => x.id !== id))
  }, [])

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setCommandPaletteOpen(v => !v)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  useEffect(() => {
    document.documentElement.classList.toggle('light', theme === 'light')
    document.documentElement.classList.toggle('dark', theme === 'dark')
  }, [theme])

  return (
    <AppContext.Provider value={{
      theme, toggleTheme, currentPage, setCurrentPage,
      toasts, addToast, dismissToast,
      commandPaletteOpen, setCommandPaletteOpen,
      selectedAuditId, setSelectedAuditId,
    }}>
      <div className="relative min-h-screen">
        <div className="aurora-bg" />
        <Layout />
        <CommandPalette />
        <ToastContainer />
      </div>
    </AppContext.Provider>
  )
}

export default App
