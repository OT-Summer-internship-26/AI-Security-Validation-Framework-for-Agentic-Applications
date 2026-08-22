import { AnimatePresence, motion } from 'framer-motion'
import { CircleCheck as CheckCircle, TriangleAlert as AlertTriangle, Circle as XCircle, Info, X } from 'lucide-react'
import { useApp } from '@/App'
import type { ToastMessage } from '@/types'

const ICONS = {
  success: CheckCircle,
  warning: AlertTriangle,
  error: XCircle,
  info: Info,
}

const COLORS = {
  success: '#00D68F',
  warning: '#FF8C00',
  error: '#FF3B5C',
  info: '#4D7CFF',
}

export function ToastContainer() {
  const { toasts, dismissToast } = useApp()

  return (
    <div className="fixed bottom-6 right-6 z-50 space-y-2 pointer-events-none">
      <AnimatePresence>
        {toasts.map((toast: ToastMessage) => {
          const Icon = ICONS[toast.type]
          const color = COLORS[toast.type]
          return (
            <motion.div
              key={toast.id}
              initial={{ opacity: 0, x: 100, scale: 0.9 }}
              animate={{ opacity: 1, x: 0, scale: 1 }}
              exit={{ opacity: 0, x: 100, scale: 0.9 }}
              transition={{ type: 'spring', stiffness: 300, damping: 25 }}
              className="pointer-events-auto flex items-start gap-3 p-4 rounded-xl glass shadow-card max-w-sm"
            >
              <Icon size={20} style={{ color }} className="flex-shrink-0 mt-0.5" />
              <div className="flex-1 min-w-0">
                <div className="text-sm font-semibold text-text-primary">{toast.title}</div>
                {toast.message && (
                  <div className="text-xs text-text-secondary mt-0.5">{toast.message}</div>
                )}
              </div>
              <button
                onClick={() => dismissToast(toast.id)}
                className="text-text-muted hover:text-text-primary transition-colors"
              >
                <X size={16} />
              </button>
            </motion.div>
          )
        })}
      </AnimatePresence>
    </div>
  )
}
