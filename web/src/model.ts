import {
  DnsRecords,
  GeoInfo,
  HopInfo,
  IpEntry,
  LogEntry,
  ScanEvent,
  ScanState,
  Selection,
  SelectionDetails,
  emptyDns,
  initialState,
} from './types'

let logId = 0

function log(state: ScanState, level: LogEntry['level'], message: string): ScanState {
  const entry: LogEntry = { id: ++logId, t: Date.now(), level, message }
  const logs = [...state.logs, entry]
  return { ...state, logs: logs.slice(-260) }
}

function patchIp(state: ScanState, ip: string, patch: Partial<IpEntry>): IpEntry[] {
  let found = false
  const ips = state.ips.map((entry) => {
    if (entry.ip !== ip) return entry
    found = true
    return { ...entry, ...patch, ports: patch.ports ?? entry.ports }
  })
  if (!found) {
    ips.push({
      ip,
      family: 4,
      primary: state.ips.length === 0,
      ports: {},
      ...patch,
    })
  }
  return ips
}

export type ScanAction =
  | { type: 'begin'; target: string; demo?: boolean }
  | { type: 'event'; event: ScanEvent }
  | { type: 'events'; events: ScanEvent[] }
  | { type: 'fail'; message: string }
  | { type: 'cancel' }
  | { type: 'reset' }

export function scanReducer(state: ScanState, action: ScanAction): ScanState {
  if (action.type === 'reset') return initialState

  if (action.type === 'events') {
    return action.events.reduce<ScanState>(
      (acc, event) => scanReducer(acc, { type: 'event', event }),
      state,
    )
  }

  if (action.type === 'begin') {
    return {
      ...initialState,
      phase: 'scanning',
      target: action.target,
      host: action.target,
      demo: action.demo ?? false,
      startedAt: Date.now(),
      logs: [{ id: ++logId, t: Date.now(), level: 'info', message: `Запрос: ${action.target}` }],
    }
  }

  if (action.type === 'fail') {
    return {
      ...state,
      phase: 'error',
      error: action.message,
      logs: [...state.logs, { id: ++logId, t: Date.now(), level: 'error' as const, message: action.message }].slice(-260),
    }
  }

  if (action.type === 'cancel') {
    return {
      ...state,
      phase: state.ips.length ? 'done' : 'idle',
      logs: [...state.logs, { id: ++logId, t: Date.now(), level: 'info' as const, message: 'Сканирование остановлено оператором' }].slice(-260),
    }
  }

  const event = action.event

  switch (event.type) {
    case 'meta':
      return {
        ...state,
        phase: 'scanning',
        host: event.host,
        demo: Boolean(event.demo) || state.demo,
        startedAt: event.startedAt ?? state.startedAt,
        portOrder: event.ports,
        error: null,
      }

    case 'dns': {
      const records: DnsRecords = { ...emptyDns(), ...state.dns, ...event.records }
      return log({ ...state, dns: records }, 'ok', 'DNS записи получены')
    }

    case 'ip': {
      const exists = state.ips.some((ip) => ip.ip === event.ip)
      const ips = patchIp(state, event.ip, {
        family: event.family,
        primary: event.primary,
        ttl: event.ttl ?? null,
      })
      return exists ? { ...state, ips } : log({ ...state, ips }, 'info', `Узел ${event.ip}`)
    }

    case 'ptr':
      return { ...state, ips: patchIp(state, event.ip, { ptr: event.ptr }) }

    case 'geo': {
      const ips = state.ips.some((ip) => ip.ip === event.ip)
        ? state.ips.map((ip) => (ip.ip === event.ip ? { ...ip, geo: event.geo } : ip))
        : state.ips
      const hops = state.hops.map((hop) => (hop.ip === event.ip ? { ...hop, geo: event.geo } : hop))
      return { ...state, ips, hops }
    }

    case 'port': {
      const existing = state.ips.find((ip) => ip.ip === event.ip)
      const prev = existing?.ports[event.port]
      const portInfo = {
        port: event.port,
        state: event.state,
        rtt: event.rtt,
        service: event.service ?? null,
        banner: event.banner,
        error: event.error,
      }
      const ports = { ...(existing?.ports || {}), [event.port]: { ...prev, ...portInfo } }
      const ips = patchIp(state, event.ip, { ports })
      const next = { ...state, ips }
      return event.state === 'open' && !prev ? log(next, 'open', `${event.ip}:${event.port} OPEN`) : next
    }

    case 'tls': {
      const ips = patchIp(state, event.ip, {
        tls: {
          port: event.port,
          subject: event.subject,
          issuer: event.issuer,
          validFrom: event.validFrom,
          validTo: event.validTo,
          altNames: event.altNames,
          serial: event.serial,
          fingerprint: event.fingerprint,
          protocol: event.protocol,
          cipher: event.cipher,
          alpn: event.alpn,
        },
      })
      return log({ ...state, ips }, 'ok', `TLS ${event.ip}:${event.port}`)
    }

    case 'http': {
      const ips = patchIp(state, event.ip, {
        http: {
          port: event.port,
          status: event.status,
          server: event.server,
          poweredBy: event.poweredBy,
          contentType: event.contentType,
          title: event.title,
          headers: event.headers,
        },
      })
      return { ...state, ips }
    }

    case 'hop': {
      const hop: HopInfo = {
        index: event.index,
        ip: event.ip,
        rtt: event.rtt,
        timeout: event.timeout,
      }
      const hops = [...state.hops.filter((h) => h.index !== event.index), hop].sort((a, b) => a.index - b.index)
      return { ...state, hops }
    }

    case 'rdap':
      return log({ ...state, rdap: event.rdap }, 'info', 'RDAP: данные регистратора получены')

    case 'log':
      return log(state, event.level, event.message)

    case 'fatal':
      return {
        ...state,
        phase: 'error',
        error: event.message,
        logs: [...state.logs, { id: ++logId, t: Date.now(), level: 'error' as const, message: event.message }].slice(-260),
      }

    case 'done':
      return {
        ...state,
        phase: state.phase === 'error' ? 'error' : 'done',
        stats: event.stats,
        logs: [
          ...state.logs,
          {
            id: ++logId,
            t: Date.now(),
            level: 'ok' as const,
            message: `Скан завершён · ${event.stats.open} open · ${event.stats.hops} hops · ${(event.stats.durationMs ?? 0) / 1000}s`,
          },
        ].slice(-260),
      }

    default:
      return state
  }
}

/* ------------------------------------------------------------------ */
/*  selectors                                                          */
/* ------------------------------------------------------------------ */

export const primaryIp = (state: ScanState): IpEntry | undefined =>
  state.ips.find((ip) => ip.primary) || state.ips[0]

export const openPorts = (ip: IpEntry) =>
  Object.values(ip.ports)
    .filter((p) => p.state === 'open')
    .sort((a, b) => a.port - b.port)

export const allPorts = (ip: IpEntry) => Object.values(ip.ports).sort((a, b) => a.port - b.port)

export const portCounts = (state: ScanState) => {
  let open = 0
  let closed = 0
  let filtered = 0
  for (const ip of state.ips) {
    for (const port of Object.values(ip.ports)) {
      if (port.state === 'open') open++
      else if (port.state === 'closed') closed++
      else filtered++
    }
  }
  return { open, closed, filtered }
}

const fmtGeo = (geo?: GeoInfo | null): string => {
  if (!geo) return '—'
  return [geo.city, geo.country].filter(Boolean).join(', ') || '—'
}

export function getSelectionDetails(state: ScanState, selection: Selection): SelectionDetails | null {
  if (!selection) return null
  const primary = primaryIp(state)

  if (selection.kind === 'core') {
    const rows: { label: string; value: string }[] = [
      { label: 'HOST', value: state.host || '—' },
      { label: 'PRIMARY IP', value: primary?.ip || '—' },
      { label: 'A / AAAA', value: `${state.dns.a.length} / ${state.dns.aaaa.length}` },
      { label: 'NAMESERVERS', value: String(state.dns.ns.length) },
      { label: 'MX', value: String(state.dns.mx.length) },
      { label: 'ПОРТОВ ПРОСКАНИРОВАНО', value: String(primary ? Object.keys(primary.ports).length : 0) },
    ]
    const block = state.rdap
      ? {
          title: 'RDAP / REGISTRY',
          rows: [
            { label: 'NAME', value: state.rdap.name || '—' },
            { label: 'REGISTRAR', value: state.rdap.registrar || '—' },
            { label: 'ORG', value: state.rdap.org || '—' },
            { label: 'CREATED', value: state.rdap.registered ? state.rdap.registered.slice(0, 10) : '—' },
            { label: 'EXPIRES', value: state.rdap.expires ? state.rdap.expires.slice(0, 10) : '—' },
            { label: 'NS', value: (state.rdap.nameservers || []).join(' · ') || '—' },
          ],
        }
      : undefined

    return {
      eyebrow: 'TARGET CORE',
      title: state.host || 'AWAITING TARGET',
      subtitle: state.dns.cname[0] || primary?.ptr || (primary ? `${primary.ip} · ${fmtGeo(primary.geo)}` : 'Введи адрес и запусти скан'),
      color: '#ff2fd6',
      rows,
      block,
    }
  }

  if (selection.kind === 'ip') {
    const ip = state.ips.find((entry) => entry.ip === selection.ip)
    if (!ip) return null
    const counts = portCounts({ ...state, ips: [ip] })
    const rows: { label: string; value: string }[] = [
      { label: 'IP', value: ip.ip },
      { label: 'FAMILY', value: `IPv${ip.family}` },
      { label: 'PTR', value: ip.ptr || '—' },
      { label: 'GEO', value: fmtGeo(ip.geo) },
      { label: 'ISP', value: ip.geo?.isp || '—' },
      { label: 'ASN', value: ip.geo?.asn || '—' },
      { label: 'TTL', value: ip.ttl != null ? `${ip.ttl}s` : '—' },
      { label: 'ПОРТЫ', value: `${counts.open} open · ${counts.closed} closed · ${counts.filtered} filtered` },
    ]
    const block = ip.tls
      ? {
          title: `TLS ${ip.tls.port} CERTIFICATE`,
          rows: [
            { label: 'SUBJECT', value: ip.tls.subject || '—' },
            { label: 'ISSUER', value: ip.tls.issuer || '—' },
            { label: 'PROTOCOL', value: ip.tls.protocol || '—' },
            { label: 'CIPHER', value: ip.tls.cipher || '—' },
            { label: 'VALID TO', value: ip.tls.validTo || '—' },
            { label: 'SAN', value: (ip.tls.altNames || []).slice(0, 4).join(', ') || '—' },
          ],
        }
      : ip.http
        ? {
            title: `HTTP ${ip.http.port}`,
            rows: [
              { label: 'STATUS', value: String(ip.http.status ?? '—') },
              { label: 'SERVER', value: ip.http.server || '—' },
              { label: 'TITLE', value: ip.http.title || '—' },
            ],
          }
        : undefined

    return {
      eyebrow: ip.primary ? 'PRIMARY NODE' : 'RESOLVED NODE',
      title: ip.ip,
      subtitle: ip.ptr || fmtGeo(ip.geo),
      color: '#38f6ff',
      rows,
      block,
    }
  }

  if (selection.kind === 'port') {
    const ip = state.ips.find((entry) => entry.ip === selection.ip)
    const port = ip?.ports[selection.port]
    if (!ip || !port) return null
    const rows = [
      { label: 'ENDPOINT', value: `${ip.ip}:${port.port}` },
      { label: 'STATE', value: port.state.toUpperCase() },
      { label: 'SERVICE', value: port.service || 'unknown' },
      { label: 'RTT', value: port.rtt != null ? `${port.rtt} ms` : '—' },
      { label: 'BANNER', value: port.banner || '—' },
      { label: 'ERROR', value: port.error || '—' },
    ]
    const tlsBlock = ip.tls?.port === port.port
      ? {
          title: 'TLS HANDSHAKE',
          rows: [
            { label: 'SUBJECT', value: ip.tls.subject || '—' },
            { label: 'ISSUER', value: ip.tls.issuer || '—' },
            { label: 'VALID TO', value: ip.tls.validTo || '—' },
            { label: 'CIPHER', value: ip.tls.cipher || '—' },
          ],
        }
      : ip.http?.port === port.port
        ? {
            title: 'HTTP RESPONSE',
            rows: [
              { label: 'STATUS', value: String(ip.http.status ?? '—') },
              { label: 'SERVER', value: ip.http.server || '—' },
              { label: 'TITLE', value: ip.http.title || '—' },
            ],
          }
        : undefined

    return {
      eyebrow: 'SERVICE PORT',
      title: `:${port.port}`,
      subtitle: `${port.service || 'unknown service'} · ${port.state}`,
      color: port.state === 'open' ? '#49ff9e' : port.state === 'filtered' ? '#8b94a8' : '#ff4d6d',
      rows,
      block: tlsBlock,
    }
  }

  if (selection.kind === 'ns') {
    const name = state.dns.ns[selection.index]
    if (!name) return null
    return {
      eyebrow: 'AUTHORITATIVE DNS',
      title: name,
      subtitle: 'NAMESERVER',
      color: '#ffb020',
      rows: [
        { label: 'ROLE', value: 'Authoritative nameserver' },
        { label: 'INDEX', value: `NS-${selection.index + 1}` },
        { label: 'ZONE', value: state.host || '—' },
        { label: 'COUNT', value: String(state.dns.ns.length) },
      ],
    }
  }

  if (selection.kind === 'mx') {
    const mx = state.dns.mx[selection.index]
    if (!mx) return null
    return {
      eyebrow: 'MAIL EXCHANGE',
      title: mx.exchange,
      subtitle: `PRIORITY ${mx.priority}`,
      color: '#c07bff',
      rows: [
        { label: 'EXCHANGE', value: mx.exchange },
        { label: 'PRIORITY', value: String(mx.priority) },
        { label: 'ZONE', value: state.host || '—' },
      ],
    }
  }

  if (selection.kind === 'hop') {
    const hop = state.hops.find((h) => h.index === selection.index)
    if (!hop) return null
    return {
      eyebrow: `ROUTE HOP ${String(hop.index).padStart(2, '0')}`,
      title: hop.ip || '***',
      subtitle: hop.ip ? fmtGeo(hop.geo) : 'нет ответа / ICMP filtered',
      color: '#ff6bd6',
      rows: [
        { label: 'IP', value: hop.ip || '—' },
        { label: 'RTT', value: hop.rtt != null ? `${hop.rtt} ms` : '—' },
        { label: 'CITY', value: hop.geo?.city || '—' },
        { label: 'COUNTRY', value: hop.geo?.country || '—' },
        { label: 'ISP', value: hop.geo?.isp || '—' },
        { label: 'ASN', value: hop.geo?.asn || '—' },
      ],
    }
  }

  if (selection.kind === 'you') {
    return {
      eyebrow: 'LOCAL ORIGIN',
      title: 'THIS WORKSTATION',
      subtitle: 'точка старта трассировки',
      color: '#ffffff',
      rows: [
        { label: 'ROLE', value: 'Scanner / observer' },
        { label: 'TARGET', value: state.host || '—' },
        { label: 'HOPS', value: String(state.hops.length) },
        { label: 'MODE', value: state.demo ? 'DEMO' : 'LIVE' },
      ],
    }
  }

  return null
}