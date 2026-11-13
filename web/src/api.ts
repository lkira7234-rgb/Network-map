import { ScanEvent } from './types'

// Empty on Render (same origin). Set VITE_API_BASE when the UI is hosted
// separately from the API, e.g. https://network-map.onrender.com
const API_BASE = (import.meta.env.VITE_API_BASE || '').replace(/\/+$/, '')

export interface ScanRequest {
  target: string
  ports: string
  traceroute: boolean
  geo: boolean
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