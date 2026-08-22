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
 * Clé d'API, si le serveur en exige une (`FRAMEWORK_API_KEY` côté API).
 * Fournie par `dashboard/.env.local` → `VITE_API_KEY=…`. Jamais codée en dur :
 * ce fichier est versionné, pas le `.env.local`.
 */
const API_KEY = (import.meta.env.VITE_API_KEY as string | undefined) ?? ''

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

class ApiError extends Error {
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
        ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
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

export const cancelRun = (runId: string) =>
  req<{ run_id: string; status: string }>(`/runs/${runId}/cancel`, { method: 'POST' })
