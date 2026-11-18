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
  bot?: { enabled: boolean; polling: boolean; chats: number; targets: number; maxPerChat: number }
  env?: { targets: number; telegramToken: boolean; telegramChat: boolean; webhook: boolean }
  issues?: string[]
  targets: MonitorTargetStatus[]
  history: MonitorChange[]
  hint?: string | null
}

export async function fetchMonitor(signal?: AbortSignal): Promise<MonitorStatus> {
  const response = await fetch(`${API_BASE}/api/monitor`, {
    signal,
    headers: { Accept: 'application/json' },
  })
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
    hint: data.hint ?? null,
  }
}

export async function testMonitorAlert(): Promise<void> {
  const response = await fetch(`${API_BASE}/api/monitor/test`, { method: 'POST' })
  await assertOk(response)
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