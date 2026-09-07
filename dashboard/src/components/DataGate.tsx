import { Loader as Loader2, ServerCrash, Inbox, RefreshCw, TriangleAlert } from 'lucide-react'
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
 *
 * ⚠ L'ÉCRAN « API INJOIGNABLE » ÉTAIT INATTEIGNABLE PAR CONSTRUCTION.
 *     Il ne s'affichait que si `audits.length === 0`. Or le store ne laisse
 *     JAMAIS la liste vide en cas d'échec : il la remplit avec les quatre audits
 *     de démonstration (datés de juillet). La condition n'était donc jamais
 *     vraie, et aucun composant ne lisait `source === 'demo'` — malgré ce que
 *     prétendait la docstring du store.
 *
 *     Résultat constaté : l'API éteinte, le dashboard affichait quatre audits de
 *     juillet 2026 dans l'historique, sans un mot. L'utilisateur les a pris pour
 *     ses propres audits — et il avait raison de le croire, rien ne disait le
 *     contraire. Un mode dégradé qui ne s'annonce pas est pire qu'une panne :
 *     une panne, au moins, on la voit.
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

  // Données de démonstration : la page reste utilisable — c'est le but d'une
  // démo — mais elle ne doit JAMAIS pouvoir passer pour un historique réel.
  // Le bandeau est persistant et en tête de page, au-dessus de tout contenu :
  // un badge discret dans un coin, c'est exactement ce qu'on ne regarde pas.
  if (source === 'demo') {
    return (
      <>
        <div className="px-6 pt-6 max-w-[1500px] mx-auto">
          <div className="card p-4 border-severity-high/40 bg-severity-high/5
                          flex flex-col sm:flex-row sm:items-center gap-3">
            <TriangleAlert size={22} className="text-severity-high shrink-0" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-text-primary">
                Données de DÉMONSTRATION — ce n'est pas votre historique
              </p>
              <p className="text-[13px] text-text-secondary mt-0.5">
                {error ?? `API injoignable sur ${API_BASE}.`} Les audits affichés
                sont un jeu d'exemple figé, daté de juillet 2026. Vos vrais audits
                n'apparaîtront qu'une fois l'API démarrée.
              </p>
              <code className="code-block inline-block mt-2 px-2 py-1 text-[11px] font-mono">
                start-dashboard.bat
              </code>
              <span className="text-[12px] text-text-muted ml-2">
                démarre l'API <em>et</em> le dashboard (run-dashboard.bat ne lance que le dashboard).
              </span>
            </div>
            <button
              onClick={() => void reloadAudits()}
              className="px-3 py-2 rounded-xl border border-border text-sm font-medium
                         text-text-secondary hover:text-text-primary flex items-center
                         gap-2 shrink-0"
            >
              <RefreshCw size={14} /> Réessayer
            </button>
          </div>
        </div>
        {children(audits)}
      </>
    )
  }

  return <>{children(audits)}</>
}
