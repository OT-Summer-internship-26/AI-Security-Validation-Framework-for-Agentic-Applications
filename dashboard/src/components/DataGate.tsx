import { Loader as Loader2, ServerCrash, Inbox, RefreshCw } from 'lucide-react'
import { useAudits, reloadAudits } from '@/data/repository'
import { API_BASE } from '@/data/api'
import type { Audit } from '@/types'

/**
 * Garde de chargement des données.
 *
 * POURQUOI
 *     Depuis le passage à l'API, `getAudits()` peut être vide le temps du chargement,
 *     ou le rester si l'API est éteinte. Sans ce composant, chaque page devrait
 *     tester `audit === undefined` à chaque accès. Ici la page ne s'affiche QUE
 *     lorsqu'il y a au moins un audit — son code redevient direct et sûr.
 */
export function DataGate({ children }: { children: (audits: Audit[]) => React.ReactNode }) {
  const { audits, source, error } = useAudits()

  if (source === 'loading') {
    return (
      <div className="p-6 max-w-[1500px] mx-auto">
        <div className="card p-12 flex flex-col items-center gap-3">
          <Loader2 size={28} className="animate-spin text-brand" />
          <p className="text-sm text-text-secondary">Chargement des audits…</p>
          <code className="text-[11px] font-mono text-text-muted">{API_BASE}</code>
        </div>
      </div>
    )
  }

  if (audits.length === 0) {
    const offline = !!error
    return (
      <div className="p-6 max-w-[1500px] mx-auto">
        <div className="card p-10 flex flex-col items-center gap-4 text-center">
          {offline
            ? <ServerCrash size={30} className="text-severity-critical" />
            : <Inbox size={30} className="text-text-muted" />}
          <div>
            <h3 className="text-lg font-semibold text-text-primary">
              {offline ? "API d'audit injoignable" : 'Aucun audit enregistré'}
            </h3>
            <p className="text-sm text-text-secondary mt-1.5 max-w-md">
              {offline
                ? error
                : "Lancez votre premier audit depuis la page Live Audit — le résultat apparaîtra ici automatiquement."}
            </p>
          </div>
          {offline && (
            <code className="code-block p-3 text-[11px] font-mono text-left">
              cd ai_security_framework{'\n'}
              python -m uvicorn api.main:app --port 8000
            </code>
          )}
          <button
            onClick={() => void reloadAudits()}
            className="px-4 py-2 rounded-xl border border-border text-sm font-medium
                       text-text-secondary hover:text-text-primary flex items-center gap-2"
          >
            <RefreshCw size={14} /> Recharger
          </button>
        </div>
      </div>
    )
  }

  return <>{children(audits)}</>
}
