import { AnimatePresence, motion } from 'framer-motion'
import { useApp } from '@/App'
import { Sidebar } from './Sidebar'
import { Topbar } from './Topbar'
import { OverviewPage } from '@/pages/OverviewPage'
import { HistoryPage } from '@/pages/HistoryPage'
import { AttacksPage } from '@/pages/AttacksPage'
import { LiveAuditPage } from '@/pages/LiveAuditPage'
import { ComparisonPage } from '@/pages/ComparisonPage'
import { QualityGatePage } from '@/pages/QualityGatePage'
import { DataGate } from '@/components/DataGate'
import type { PageId } from '@/types'

const PAGES: Record<PageId, React.ComponentType> = {
  overview: OverviewPage,
  history: HistoryPage,
  attacks: AttacksPage,
  live: LiveAuditPage,
  comparison: ComparisonPage,
  'quality-gate': QualityGatePage,
}

// « live » reste accessible même sans aucun audit : c'est la page qui permet
// justement d'en lancer un. Les autres exigent au moins un résultat.
const NEEDS_DATA: Record<PageId, boolean> = {
  overview: true, history: true, attacks: true,
  live: false, comparison: true, 'quality-gate': true,
}

export function Layout() {
  const { currentPage } = useApp()
  const PageComponent = PAGES[currentPage]
  const gated = NEEDS_DATA[currentPage]

  return (
    <div className="relative z-10 flex w-full min-h-screen">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0">
        <Topbar />
        {/* Scroll porté par <main> : le bas des pages denses reste atteignable
            même en 1366x768 (l'ancien overflow:hidden le rendait inaccessible). */}
        <main className="flex-1 min-h-0 overflow-y-auto">
          <AnimatePresence mode="wait">
            <motion.div
              key={currentPage}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.22, ease: 'easeOut' }}
            >
              {gated
                ? <DataGate>{() => <PageComponent />}</DataGate>
                : <PageComponent />}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  )
}
