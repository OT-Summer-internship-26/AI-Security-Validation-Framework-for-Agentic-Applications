/**
 * store.ts — État partagé des audits, alimenté par l'API.
 *
 * POURQUOI UN STORE
     * Les pages étaient synchrones (`getAudits()` renvoyait un tableau figé). Passer
 * à l'API impose un chargement asynchrone. Plutôt que de disséminer des `useEffect`
 * dans chaque page, un store minimal centralise le chargement, le cache et la
 * notification — les pages consomment `useAudits()` et n'ont rien d'autre à savoir.
 *
 * Repli : si l'API est injoignable, on sert le jeu de démonstration et
 * `source` vaut `'demo'`, ce que la barre supérieure affiche explicitement.
 */
import { useSyncExternalStore } from 'react'
import { fetchAudits } from './api'
import { adaptAudit } from './adapter'
import { AUDITS as DEMO_AUDITS } from './audits'
import type { Audit } from '@/types'

export type DataSource = 'api' | 'demo' | 'loading'

interface State {
  audits: Audit[]
  source: DataSource
  error: string | null
  loadedAt: number
}

let state: State = { audits: [], source: 'loading', error: null, loadedAt: 0 }
const listeners = new Set<() => void>()

function emit(next: Partial<State>): void {
  state = { ...state, ...next }
  listeners.forEach(l => l())
}

function byDateDesc(a: Audit, b: Audit): number {
  return new Date(b.started_at).getTime() - new Date(a.started_at).getTime()
}

let inFlight: Promise<void> | null = null

/** Recharge les audits depuis l'API. Concurrent-safe : un seul appel à la fois. */
export function reloadAudits(): Promise<void> {
  if (inFlight) return inFlight
  inFlight = fetchAudits()
    .then(({ audits }) => {
      const adapted = audits
        .map((raw, i) => adaptAudit(raw, (raw as { _file?: string })._file || `audit-${i}`))
        .sort(byDateDesc)
      emit({
        audits: adapted.length ? adapted : [...DEMO_AUDITS].sort(byDateDesc),
        source: adapted.length ? 'api' : 'demo',
        error: adapted.length ? null : 'Aucun audit enregistré — jeu de démonstration affiché.',
        loadedAt: Date.now(),
      })
    })
    .catch((err: Error) => {
      emit({
        audits: [...DEMO_AUDITS].sort(byDateDesc),
        source: 'demo',
        error: err.message,
        loadedAt: Date.now(),
      })
    })
    .finally(() => { inFlight = null })
  return inFlight
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb)
  if (state.source === 'loading' && !inFlight) void reloadAudits()
  return () => { listeners.delete(cb) }
}

const getSnapshot = (): State => state

/** Hook de lecture : audits, provenance des données et erreur éventuelle. */
export function useAudits(): State {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot)
}

/** Accès direct hors composant (rarement utile — préférer `useAudits`). */
export const currentAudits = (): Audit[] => state.audits
export const currentSource = (): DataSource => state.source
