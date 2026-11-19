import { ScanEvent } from './types'

// Empty on Render (same origin). Set VITE_API_BASE when the UI is hosted
// separately from the API, e.g. https://network-map.onrender.com
const API_BASE = (import.meta.env.VITE_API_BASE || '').replace(/\/+$/, '')

export interface ScanRequest {
  target: string
  ports: string
  traceroute: boolean
  geo: boolean
  udp: boolean
}

export interface RateLimitInfo {
  limit: number
  remaining: number
  resetAt: number | null
}

function readRateLimit(response: Response): RateLimitInfo | null {
  const limit = Number(response.headers.get('ratelimit-limit'))
  const remaining = Number(response.headers.get('ratelimit-remaining'))
  if (!Number.isFinite(limit) || !Number.isFinite(remaining)) return null
  const reset = Number(response.headers.get('ratelimit-reset'))
  return {
    limit,
    remaining,
    resetAt: Number.isFinite(reset) ? Date.now() + reset * 1000 : null,
  }
}

async function readNdjson(
  response: Response,
  onEvent: (event: ScanEvent) => void,
  signal: AbortSignal,
) {
  if (!response.body) throw new Error('Поток данных недоступен')

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  try {
    while (true) {
      if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })

      let newline = buffer.indexOf('\n')
      while (newline !== -1) {
        const line = buffer.slice(0, newline).trim()
        buffer = buffer.slice(newline + 1)
        if (line) {
          try {
            onEvent(JSON.parse(line) as ScanEvent)
          } catch {
            // ignore malformed line, keep stream alive
          }
        }
        newline = buffer.indexOf('\n')
      }
    }

    const tail = buffer.trim()
    if (tail) {
      try {
        onEvent(JSON.parse(tail) as ScanEvent)
      } catch {}
    }
  } finally {
    try {
      reader.releaseLock()
    } catch {}
  }
}

async function assertOk(response: Response) {
  if (response.ok) return
  let message = `Ошибка сервера (${response.status})`
  try {
    const data = await response.json()
    if (data?.error) message = data.error
  } catch {}
  throw new Error(message)
}

export async function streamScan(
  request: ScanRequest,
  onEvent: (event: ScanEvent) => void,
  signal: AbortSignal,
  onRateLimit?: (info: RateLimitInfo) => void,
) {
  const response = await fetch(`${API_BASE}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
    signal,
  })
  const rate = readRateLimit(response)
  if (rate) onRateLimit?.(rate)
  await assertOk(response)
  await readNdjson(response, onEvent, signal)
}

export async function streamDemo(onEvent: (event: ScanEvent) => void, signal: AbortSignal) {
  const response = await fetch(`${API_BASE}/api/demo`, { signal })
  await assertOk(response)
  await readNdjson(response, onEvent, signal)
}

export interface SubdomainResponse {
  host: string
  total: number
  subdomains: string[]
  truncated?: boolean
  cached?: boolean
}

export type GarbageKind = 'auto' | 'site' | 'dns' | 'ip'

export interface GarbagePick {
  ok: boolean
  kind?: GarbageKind
  target?: string
  pickedAt?: number
  error?: string
  verify?: {
    http?: number
    title?: string | null
    bytes?: number
    finalHost?: string
    server?: string | null
    ms?: number
    ip?: string
    port?: number
    domain?: string
    ns?: string
    tcp53?: boolean
    reason?: string
  }
  meta?: Record<string, unknown>
}

export async function fetchGarbage(kind: GarbageKind, signal?: AbortSignal): Promise<GarbagePick> {
  const response = await fetch(`${API_BASE}/api/garbage?kind=${encodeURIComponent(kind)}`, {
    signal,
    headers: { Accept: 'application/json' },
  })
  await assertOk(response)
  const data = (await response.json()) as GarbagePick
  return {
    ok: Boolean(data.ok),
    kind: data.kind,
    target: typeof data.target === 'string' ? data.target : undefined,
    pickedAt: Number(data.pickedAt) || undefined,
    error: typeof data.error === 'string' ? data.error : undefined,
    verify: data.verify,
    meta: data.meta,
  }
}

export interface MonitorTargetStatus {
  target: string
  source?: 'env' | 'bot'
  lastRun: number | null
  nextRun: number | null
  open: number
  added: string[]
  removed: string[]
  nodes?: number
  hops?: number
  nodeAdded?: number
  nodeRemoved?: number
  hopAdded?: number
  hopRemoved?: number
  error: string | null
}

export interface MonitorChange {
  at: number
  target: string
  added: string[]
  removed: string[]
  nodesAdded?: string[]
  nodesRemoved?: string[]
  hopsAdded?: string[]
  hopsRemoved?: string[]
  source?: string
}

export interface MonitorStatus {
  enabled: boolean
  intervalMin: number
  ports: number
  alerts: { webhook: boolean; telegram: boolean }
  scanAlerts?: boolean
  notifyFirst?: boolean
  trace?: boolean
  telegramChannel?: boolean
  botTargets?: number
  admin?: boolean
  bot?: { enabled: boolean; polling: boolean; chats: number; targets: number; maxPerChat: number }
  env?: { targets: number; telegramToken: boolean; telegramChat: boolean; webhook: boolean }
  issues?: string[]
  targets: MonitorTargetStatus[]
  history: MonitorChange[]
  scans?: StoreScan[]
  hint?: string | null
}

export interface StoreScan {
  at: number
  target: string
  source?: string
  nodes?: string[]
  ports?: string[]
  hops?: string[]
  labels?: Record<string, string>
}

export async function fetchMonitor(signal?: AbortSignal, token?: string): Promise<MonitorStatus> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (token) headers['X-Monitor-Token'] = token
  const response = await fetch(`${API_BASE}/api/monitor`, { signal, headers })
  await assertOk(response)
  const data = (await response.json()) as MonitorStatus
  return {
    enabled: Boolean(data.enabled),
    intervalMin: Number(data.intervalMin) || 0,
    ports: Number(data.ports) || 0,
    alerts: {
      webhook: Boolean(data.alerts?.webhook),
      telegram: Boolean(data.alerts?.telegram),
    },
    scanAlerts: Boolean(data.scanAlerts),
    notifyFirst: Boolean(data.notifyFirst),
    trace: Boolean(data.trace),
    telegramChannel: Boolean(data.telegramChannel),
    botTargets: Number(data.botTargets) || 0,
    admin: Boolean(data.admin),
    bot: data.bot
      ? {
          enabled: Boolean(data.bot.enabled),
          polling: Boolean(data.bot.polling),
          chats: Number(data.bot.chats) || 0,
          targets: Number(data.bot.targets) || 0,
          maxPerChat: Number(data.bot.maxPerChat) || 0,
        }
      : undefined,
    env: data.env
      ? {
          targets: Number(data.env.targets) || 0,
          telegramToken: Boolean(data.env.telegramToken),
          telegramChat: Boolean(data.env.telegramChat),
          webhook: Boolean(data.env.webhook),
        }
      : undefined,
    issues: Array.isArray(data.issues) ? data.issues.map(String) : [],
    targets: Array.isArray(data.targets) ? data.targets : [],
    history: Array.isArray(data.history) ? data.history : [],
    scans: Array.isArray(data.scans) ? data.scans : undefined,
    hint: data.hint ?? null,
  }
}

export async function testMonitorAlert(token?: string): Promise<void> {
  const response = await fetch(`${API_BASE}/api/monitor/test`, {
    method: 'POST',
    headers: token ? { 'X-Monitor-Token': token } : {},
  })
  await assertOk(response)
}

/* ------------------------------------------------------------------ */
/*  preview & reputation                                               */
/* ------------------------------------------------------------------ */

export interface PreviewResponse {
  ok: boolean
  status?: number
  image?: string
  url?: string
  title?: string | null
  ms?: number
  cached?: boolean
  error?: string
  hint?: string
  available?: boolean
  enabled?: boolean
  engine?: string | null
  ports?: number[]
}

export async function fetchPreview(host: string, port: number, signal?: AbortSignal): Promise<PreviewResponse> {
  const response = await fetch(
    `${API_BASE}/api/preview?host=${encodeURIComponent(host)}&port=${encodeURIComponent(String(port))}`,
    { signal, headers: { Accept: 'application/json' } },
  )
  let data: Partial<PreviewResponse> = {}
  try {
    data = (await response.json()) as PreviewResponse
  } catch {}
  return {
    ...data,
    ok: Boolean(data.ok) && response.ok,
    status: response.status,
  }
}

export interface ReputationResponse {
  ok: boolean
  enabled: boolean
  ip?: string
  reputation?: import('./types').ReputationInfo
  error?: string
  reason?: string
}

export async function fetchReputation(ip: string, signal?: AbortSignal): Promise<ReputationResponse> {
  const response = await fetch(`${API_BASE}/api/reputation?ip=${encodeURIComponent(ip)}`, {
    signal,
    headers: { Accept: 'application/json' },
  })
  let data: Partial<ReputationResponse> = {}
  try {
    data = (await response.json()) as ReputationResponse
  } catch {}
  return {
    ok: Boolean(data.ok) && response.ok,
    enabled: Boolean(data.enabled),
    ip: data.ip,
    reputation: data.reputation,
    error: data.error,
    reason: data.reason,
  }
}

export async function fetchSubdomains(host: string, signal?: AbortSignal): Promise<SubdomainResponse> {
  const response = await fetch(`${API_BASE}/api/subdomains?host=${encodeURIComponent(host)}`, {
    signal,
    headers: { Accept: 'application/json' },
  })
  await assertOk(response)
  const data = (await response.json()) as SubdomainResponse
  return {
    host: data.host || host,
    total: Number(data.total) || data.subdomains?.length || 0,
    subdomains: Array.isArray(data.subdomains) ? data.subdomains.map(String) : [],
    truncated: Boolean(data.truncated),
    cached: Boolean(data.cached),
  }
}