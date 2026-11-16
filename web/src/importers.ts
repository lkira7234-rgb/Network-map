import { BasicFinding, FindingSeverity, PortState, ScanEvent } from './types'
import { parseNmapXml } from './nmap'

/* ------------------------------------------------------------------ */
/*  httpx / nuclei import                                              */
/* ------------------------------------------------------------------ */

export interface ImportSummary {
  target: string
  events: ScanEvent[]
  kind: 'nmap' | 'httpx' | 'nuclei'
  hosts: number
  ports: number
  findings: number
}

const isIp = (value: string) => /^[0-9.]+$/.test(value) || value.includes(':')

function hostnameOf(value: string): string {
  const raw = String(value || '').trim()
  if (!raw) return ''
  try {
    return new URL(raw.includes('://') ? raw : `https://${raw}`).hostname || raw
  } catch {
    return raw.replace(/^[a-z]+:\/\//i, '').replace(/[/?#].*$/, '')
  }
}

function portOf(value: unknown, fallback: number): number {
  const port = Number(value)
  return Number.isFinite(port) && port > 0 && port <= 65535 ? Math.trunc(port) : fallback
}

function statusOf(value: unknown): PortState {
  const state = String(value || '').toLowerCase()
  if (state === 'closed' || state === 'reset') return 'closed'
  if (state === 'filtered' || state === 'timeout') return 'filtered'
  return 'open'
}

export function parseHttpxJsonl(text: string): ImportSummary {
  const events: ScanEvent[] = []
  const seenIps = new Set<string>()
  const seenPorts = new Set<string>()
  const lines = text.split(/\r?\n/).filter((line) => line.trim())
  const rows: any[] = []
  for (const line of lines) {
    try {
      const parsed = JSON.parse(line)
      if (parsed && typeof parsed === 'object') rows.push(parsed)
    } catch {
      // httpx sometimes prints a banner before the JSON; skip non-JSON lines.
    }
  }
  if (!rows.length) {
    throw new Error('В файле нет JSON-строк httpx. Нужен вывод `httpx -json`.')
  }

  const target = hostnameOf(rows[0].input || rows[0].host || rows[0].url || 'httpx-import') || 'httpx-import'
  const portSet = new Set<number>()

  for (const row of rows) {
    const hostname = hostnameOf(row.input || row.host || row.url || target)
    const ip = String(row.ip || row.host || hostname)
    if (!ip) continue
    const secure = String(row.scheme || '').toLowerCase() === 'https' || String(row.url || '').startsWith('https://')
    const port = portOf(row.port, secure ? 443 : 80)
    const service = String(row.webserver || row.tech?.[0] || (secure ? 'https' : 'http')).slice(0, 60)
    portSet.add(port)

    if (!seenIps.has(ip)) {
      seenIps.add(ip)
      events.push({ type: 'ip', ip, family: ip.includes(':') ? 6 : 4, primary: seenIps.size === 1 })
    }
    const portKey = `${ip}:${port}`
    if (!seenPorts.has(portKey)) {
      seenPorts.add(portKey)
      events.push({
        type: 'port',
        ip,
        port,
        protocol: 'tcp',
        state: 'open',
        service: secure ? 'https' : 'http',
      })
    }
    events.push({
      type: 'http',
      ip,
      port,
      status: Number(row.status_code || row.status || 0) || undefined,
      server: row.webserver ? String(row.webserver) : undefined,
      poweredBy: row['x-powered-by'] ? String(row['x-powered-by']) : undefined,
      contentType: row.content_type ? String(row.content_type) : undefined,
      title: row.title ? String(row.title).slice(0, 200) : undefined,
      headers: row.header && typeof row.header === 'object' ? row.header : undefined,
      tech: Array.isArray(row.tech) ? row.tech.map(String).slice(0, 20) : undefined,
    })
    if (hostname && hostname !== ip) {
      events.push({ type: 'ptr', ip, ptr: hostname })
    }
  }

  events.unshift({
    type: 'meta',
    host: target,
    isIp: isIp(target),
    ports: [...portSet].sort((a, b) => a - b),
    traceroute: false,
    geo: false,
    startedAt: Date.now(),
  })
  events.push({
    type: 'log',
    level: 'ok',
    message: `httpx: ${seenIps.size} хостов · ${seenPorts.size} HTTP-ответов импортировано`,
  })
  events.push({
    type: 'done',
    stats: {
      open: seenPorts.size,
      closed: 0,
      filtered: 0,
      scanned: seenPorts.size,
      ips: seenIps.size,
      hops: 0,
      durationMs: 0,
      portCount: portSet.size,
    },
  })

  return {
    target,
    events,
    kind: 'httpx',
    hosts: seenIps.size,
    ports: seenPorts.size,
    findings: 0,
  }
}

const NUCLEI_SEVERITY: Record<string, FindingSeverity> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
  unknown: 'info',
}

export function parseNucleiJsonl(text: string): ImportSummary {
  const events: ScanEvent[] = []
  const seenIps = new Set<string>()
  const seenPorts = new Set<string>()
  const lines = text.split(/\r?\n/).filter((line) => line.trim())
  const rows: any[] = []
  for (const line of lines) {
    try {
      const parsed = JSON.parse(line)
      if (parsed && typeof parsed === 'object') rows.push(parsed)
    } catch {
      // ignore banners / progress lines
    }
  }
  if (!rows.length) {
    throw new Error('В файле нет JSON-строк nuclei. Нужен вывод `nuclei -jsonl`.')
  }

  const first = rows[0]
  const target =
    hostnameOf(first.host || first['matched-at'] || first.url || 'nuclei-import') || 'nuclei-import'
  const portSet = new Set<number>()
  let findings = 0

  for (const row of rows) {
    const info = row.info || {}
    const hostname = hostnameOf(row.host || row['matched-at'] || target)
    const ip = String(row.ip || hostname)
    if (!ip) continue
    const port = portOf(row.port, String(row['matched-at'] || row.host || '').startsWith('https') ? 443 : 80)
    portSet.add(port)

    if (!seenIps.has(ip)) {
      seenIps.add(ip)
      events.push({ type: 'ip', ip, family: ip.includes(':') ? 6 : 4, primary: seenIps.size === 1 })
    }
    const portKey = `${ip}:${port}`
    if (!seenPorts.has(portKey)) {
      seenPorts.add(portKey)
      events.push({
        type: 'port',
        ip,
        port,
        protocol: 'tcp',
        state: statusOf(row.type === 'http' ? 'open' : row.type),
        service: row.type ? String(row.type).slice(0, 40) : 'nuclei',
      })
    }

    const templateId = String(row['template-id'] || row.templateID || row.template || 'unknown')
    const cveId = /^cve-\d{4}-\d+$/i.test(templateId) ? templateId.toUpperCase() : null
    const severity = NUCLEI_SEVERITY[String(info.severity || '').toLowerCase()] || 'info'
    const finding: BasicFinding = {
      id: cveId || `nuclei:${templateId}`,
      title: String(info.name || templateId).slice(0, 160),
      severity,
      category: 'exposure',
      summary:
        String(info.description || '').slice(0, 400) ||
        `Сработал шаблон nuclei «${templateId}». Это результат проверки, а не подтверждённая эксплуатация.`,
      recommendation:
        'Проверить находку вручную и закрыть по рекомендации шаблона nuclei или обновить компонент.',
      evidence: String(row['matched-at'] || row.url || `${ip}:${port}`).slice(0, 400),
      ip,
      port,
      protocol: 'tcp',
    }
    events.push({ type: 'finding', finding })
    findings++
  }

  events.unshift({
    type: 'meta',
    host: target,
    isIp: isIp(target),
    ports: [...portSet].sort((a, b) => a - b),
    traceroute: false,
    geo: false,
    startedAt: Date.now(),
  })
  events.push({ type: 'log', level: 'ok', message: `nuclei: ${rows.length} результатов · ${findings} находок импортировано` })
  events.push({
    type: 'done',
    stats: {
      open: seenPorts.size,
      closed: 0,
      filtered: 0,
      scanned: rows.length,
      ips: seenIps.size,
      hops: 0,
      durationMs: 0,
      portCount: portSet.size,
    },
  })

  return {
    target,
    events,
    kind: 'nuclei',
    hosts: seenIps.size,
    ports: seenPorts.size,
    findings,
  }
}

export function parseImport(text: string): ImportSummary {
  const trimmed = text.trim()
  if (!trimmed) throw new Error('Файл пустой.')
  if (trimmed.startsWith('<')) {
    const result = parseNmapXml(text)
    const findings = result.events.filter((event) => event.type === 'finding').length
    return {
      target: result.target,
      events: result.events,
      kind: 'nmap',
      hosts: result.hosts,
      ports: result.ports,
      findings,
    }
  }

  let first: any = null
  for (const line of trimmed.split(/\r?\n/)) {
    if (!line.trim()) continue
    try {
      first = JSON.parse(line)
      break
    } catch {
      continue
    }
  }
  if (!first) {
    throw new Error('Не удалось распознать файл. Поддерживаются Nmap/Masscan XML, httpx JSON и nuclei JSONL.')
  }

  const keys = Object.keys(first)
  const isNuclei =
    keys.some((key) => ['template-id', 'templateID', 'template'].includes(key)) ||
    (first.info && typeof first.info === 'object' && 'severity' in first.info)
  if (isNuclei) return parseNucleiJsonl(text)

  const isHttpx =
    keys.some((key) => ['url', 'status_code', 'webserver', 'scheme', 'content_type', 'tech'].includes(key)) ||
    (typeof first.host === 'string' && ('status_code' in first || 'input' in first))
  if (isHttpx) return parseHttpxJsonl(text)

  throw new Error('Неизвестный JSON-формат. Поддерживаются httpx (-json) и nuclei (-jsonl).')
}
