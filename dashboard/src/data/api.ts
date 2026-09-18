/**
 * api.ts — Client de l'API d'audit (FastAPI, `api/main.py`).
 *
 * Le dashboard lit et LANCE les audits par HTTP. Plus de copie de fichiers,
 * plus de script de synchronisation : les résultats affichés sont ceux que
 * l'API sert depuis `data/audit_results/`, et le bouton « Lancer » exécute
 * réellement `scripts/run_agent.py` côté serveur.
 */
import type { RawAudit } from './adapter'

export const API_BASE =
  (import.meta.env.VITE_API_BASE as string | undefined) ?? 'http://127.0.0.1:8000'

/**
 * Clé d'API de la PERSONNE qui utilise le dashboard, si le serveur en exige une.
 * Saisie dans le bandeau « Clé d'API requise » (DataGate), gardée en
 * `sessionStorage` : elle disparaît avec l'onglet.
 *
 * PLUS DE CLÉ COMPILÉE DANS LE PAQUET.
 *     `VITE_API_KEY` était inscrite dans le JavaScript servi à tout visiteur —
 *     une clé lisible par quiconque charge la page. Et l'image Docker ne la
 *     posait pas : le dashboard conteneurisé recevait 401 partout dès que l'API
 *     exigeait une clé. Chacun saisit désormais SA clé, ce qui garde aussi
 *     l'attribution (« qui a lancé cet audit ») pour laquelle les clés existent.
 *
 *     `VITE_API_KEY` reste un confort du serveur de DÉVELOPPEMENT : au build,
 *     `import.meta.env.DEV` vaut `false` et la branche sort du paquet.
 */
const CLE_STOCKEE = 'aisec_api_key'
let cleMemoire = ''          // repli si le stockage est bloqué (navigation privée…)

export function getApiKey(): string {
  if (cleMemoire) return cleMemoire
  try {
    const cle = sessionStorage.getItem(CLE_STOCKEE)
    if (cle) return cle
  } catch { /* stockage indisponible */ }
  return import.meta.env.DEV ? ((import.meta.env.VITE_API_KEY as string | undefined) ?? '') : ''
}

export function setApiKey(cle: string): void {
  cleMemoire = cle
  try {
    if (cle) sessionStorage.setItem(CLE_STOCKEE, cle)
    else sessionStorage.removeItem(CLE_STOCKEE)
  } catch { /* stockage indisponible : la clé vit en mémoire */ }
}

function enTetesAuth(): Record<string, string> {
  const cle = getApiKey()
  return cle ? { 'X-API-Key': cle } : {}
}

export interface HealthInfo {
  status: string
  version: string
  services: {
    docker_sandbox: boolean
    gemini_key: boolean
    results_dir: boolean
    runner: boolean
    active_runs: number
  }
}

export interface AgentInfo {
  id: string
  name: string
  available: boolean
}

export interface RunLog {
  t: string
  level: 'info' | 'warn' | 'critical' | 'debug'
  text: string
}

export type AuditMode = 'quick' | 'targeted' | 'full'

export interface RunRequest {
  mode: AuditMode
  categories?: string[] | null
  disable_deepteam?: boolean
  disable_pyrit?: boolean
  disable_garak?: boolean
  disable_microsoft?: boolean
  category: string
  target_url: string
  /** Format JSON de la cible : où mettre le prompt, où lire la réponse, et les
   *  champs constants qu'elle exige en plus (ex. {"title": "..."}). */
  prompt_field?: string
  response_field?: string
  extra_payload?: Record<string, unknown> | null
  profile: string
  attacks_per_type: number
  max_concurrent: number
  pyrit_max_turns: number
  timeout: number
  source_path?: string | null
  requirements_path?: string | null
  explain_passes: boolean
  garak_probes?: string | null
  peer_agent_id?: string | null
}

/** Un échange avec la cible, capté en direct pendant l'exécution. */
export interface LiveExchange {
  n: number
  elapsed_s: number
  prompt: string
  response: string
  http_error: boolean
}

export interface RunState {
  run_id: string
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  progress: number
  stage: string
  started_at: string
  finished_at: string | null
  result_file: string | null
  error: string | null
  request: RunRequest
  logs: RunLog[]
  log_count: number
  categories?: string[] | null
  result_files?: string[] | null
  exchanges: LiveExchange[]
  exchange_count: number
  result?: RawAudit
}

export class ApiError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message)
    this.name = 'ApiError'
  }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: {
        'Content-Type': 'application/json',
        ...enTetesAuth(),
        ...(init?.headers || {}),
      },
    })
  } catch {
    throw new ApiError(
      `API injoignable sur ${API_BASE}. Démarrez-la : python -m uvicorn api.main:app --port 8000`
    )
  }
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new ApiError(body || `HTTP ${res.status}`, res.status)
  }
  return res.json() as Promise<T>
}

export interface DvapLab {
  slug: string
  name: string
  difficulty: string
  category: string
  description: string
  running: boolean
  port?: number
  target_url?: string
  prompt_field?: string
  response_field?: string
  extra_payload?: Record<string, unknown> | null
}

export const getDvapLabs = () =>
  req<{ labs: DvapLab[]; running: unknown[]; error?: string }>('/dvap/labs')

export const launchDvapLab = (slug: string) =>
  req<{ slug: string; port: number; target_url: string
        prompt_field: string; response_field: string
        extra_payload?: Record<string, unknown> | null }>('/dvap/launch', {
    method: 'POST', body: JSON.stringify({ slug }),
  })

export const getHealth = () => req<HealthInfo>('/health')
export const getAgents = () => req<{ agents: AgentInfo[] }>('/agents')
export const fetchAudits = () => req<{ audits: RawAudit[] }>('/audits')
export const fetchRuns = () => req<{ runs: Omit<RunState, 'logs'>[] }>('/runs')

export const startAudit = (body: Partial<RunRequest>) =>
  req<{ run_id: string; status: string }>('/audits', {
    method: 'POST',
    body: JSON.stringify(body),
  })

export interface ReplayRequest {
  audit_id: string
  only_compromised?: boolean
  repeat?: number
  profile?: string
}

export const startReplay = (body: ReplayRequest) =>
  req<{ run_id: string; status: string; attacks_available: number }>('/replay', {
    method: 'POST',
    body: JSON.stringify(body),
  })

export const getRun = (runId: string, since = 0, sinceEx = 0) =>
  req<RunState>(`/runs/${runId}?since=${since}&since_ex=${sinceEx}`)

/**
 * Ouvre le rapport HTML d'un audit dans un nouvel onglet.
 *
 * Un lien ne porte pas d'en-tête : `<a href=".../report">` rendait 401 dès que
 * l'API exigeait une clé. On télécharge donc le rapport AVEC la clé, puis on
 * l'affiche depuis un `blob:`. L'onglet est ouvert avant l'appel réseau, pendant
 * le clic : ouvert après un `await`, le bloqueur de fenêtres le refuserait.
 */
export async function openReport(auditId: string): Promise<void> {
  const onglet = window.open('', '_blank')
  try {
    const res = await fetch(`${API_BASE}/audits/${encodeURIComponent(auditId)}/report`,
                            { headers: enTetesAuth() })
    if (!res.ok) {
      const corps = await res.text().catch(() => '')
      throw new ApiError(corps || `HTTP ${res.status}`, res.status)
    }
    const url = URL.createObjectURL(new Blob([await res.text()], { type: 'text/html' }))
    if (onglet) {
      onglet.opener = null
      onglet.location.href = url
    } else {
      window.open(url, '_blank', 'noopener')
    }
  } catch (err) {
    onglet?.close()
    throw err
  }
}

export const cancelRun = (runId: string) =>
  req<{ run_id: string; status: string }>(`/runs/${runId}/cancel`, { method: 'POST' })
