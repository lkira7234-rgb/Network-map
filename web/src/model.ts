import {
  DnsRecords,
  GeoInfo,
  HopInfo,
  HttpInfo,
  IpEntry,
  LogEntry,
  ObjectSummary,
  PortInfo,
  ScanEvent,
  ScanState,
  Selection,
  SelectionDetails,
  SummaryCert,
  SummaryFlag,
  emptyDns,
  initialState,
  portKey,
} from './types'
import { matchCvesForPort } from './cve'
import { findingsForIp, findingsForPort } from './checks'
import { techForHttp, techForIp } from './tech'

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
  | { type: 'import'; target: string; events: ScanEvent[] }
  | { type: 'fail'; message: string }
  | { type: 'cancel' }
  | { type: 'reset' }

export function scanReducer(state: ScanState, action: ScanAction): ScanState {
  if (action.type === 'reset') return initialState

  if (action.type === 'import') {
    const seeded: ScanState = { ...initialState, target: action.target, host: action.target }
    return action.events.reduce<ScanState>(
      (acc, event) => scanReducer(acc, { type: 'event', event }),
      seeded,
    )
  }

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
      const protocol = event.protocol ?? 'tcp'
      const key = portKey(event.port, protocol)
      const existing = state.ips.find((ip) => ip.ip === event.ip)
      const prev = existing?.ports[key]
      const portInfo = {
        port: event.port,
        protocol,
        state: event.state,
        rtt: event.rtt,
        service: event.service ?? null,
        banner: event.banner,
        error: event.error,
      }
      const ports = { ...(existing?.ports || {}), [key]: { ...prev, ...portInfo } }
      const ips = patchIp(state, event.ip, { ports })
      const next = { ...state, ips }
      const label = `${event.ip}:${event.port}${protocol === 'udp' ? '/udp' : ''}`
      return event.state === 'open' && !prev ? log(next, 'open', `${label} OPEN`) : next
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
      const entry = {
        port: event.port,
        status: event.status,
        server: event.server,
        poweredBy: event.poweredBy,
        contentType: event.contentType,
        title: event.title,
        headers: event.headers,
        cookies: event.cookies,
        generator: event.generator,
        bodySample: event.bodySample,
        tech: event.tech,
      }
      const previous = state.ips.find((ip) => ip.ip === event.ip)
      const httpAll = [...(previous?.httpAll || []).filter((item) => item.port !== event.port), entry].sort(
        (a, b) => a.port - b.port,
      )
      const ips = patchIp(state, event.ip, { http: entry, httpAll })
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

    case 'finding': {
      const key = `${event.finding.id}|${event.finding.ip}|${event.finding.port ?? ''}|${event.finding.protocol ?? ''}`
      const exists = state.extraFindings.some(
        (item) => `${item.id}|${item.ip}|${item.port ?? ''}|${item.protocol ?? ''}` === key,
      )
      if (exists) return state
      return {
        ...state,
        extraFindings: [...state.extraFindings, event.finding],
      }
    }

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
    .sort((a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol))

export const allPorts = (ip: IpEntry) =>
  Object.values(ip.ports).sort((a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol))

export const portCounts = (state: ScanState) => {
  let open = 0
  let closed = 0
  let filtered = 0
  let udp = 0
  let udpOpen = 0
  for (const ip of state.ips) {
    for (const port of Object.values(ip.ports)) {
      if (port.state === 'open') open++
      else if (port.state === 'closed') closed++
      else filtered++
      if (port.protocol === 'udp') {
        udp++
        if (port.state === 'open') udpOpen++
      }
    }
  }
  return { open, closed, filtered, udp, udpOpen }
}

const fmtGeo = (geo?: GeoInfo | null): string => {
  if (!geo) return '—'
  return [geo.city, geo.country].filter(Boolean).join(', ') || '—'
}

/* ------------------------------------------------------------------ */
/*  packet inspector                                                   */
/* ------------------------------------------------------------------ */

const REASONS: Record<number, string> = {
  200: 'OK',
  201: 'Created',
  204: 'No Content',
  301: 'Moved Permanently',
  302: 'Found',
  303: 'See Other',
  304: 'Not Modified',
  307: 'Temporary Redirect',
  308: 'Permanent Redirect',
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not Found',
  405: 'Method Not Allowed',
  429: 'Too Many Requests',
  500: 'Internal Server Error',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
  504: 'Gateway Timeout',
}

const HTTP_PORT_NUMBERS = new Set([80, 81, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443])

function httpEntries(ip: IpEntry) {
  return ip.httpAll?.length ? ip.httpAll : ip.http ? [ip.http] : []
}

function requestText(host: string): string {
  return [
    'GET / HTTP/1.1',
    `Host: ${host || '—'}`,
    'User-Agent: NetworkMap/1.0 (topology visualizer)',
    'Accept: text/html,application/xhtml+xml,*/*;q=0.8',
    'Connection: close',
  ].join('\r\n')
}

function responseText(http: HttpInfo): string {
  const status = http.status ?? 0
  const lines = [`HTTP/1.1 ${status} ${REASONS[status] || 'Unknown'}`]
  for (const [key, value] of Object.entries(http.headers || {})) {
    lines.push(`${key}: ${value}`)
  }
  if (http.title) lines.push('', `<!-- <title>${http.title}</title> -->`)
  return lines.join('\r\n')
}

function packetFor(ip: IpEntry, host: string, port?: PortInfo): SelectionDetails['packet'] {
  const entries = httpEntries(ip)
  const http =
    port != null
      ? entries.find((entry) => entry.port === port.port)
      : entries.find((entry) => entry.port === 443) ||
        entries.slice().sort((a, b) => a.port - b.port)[0]

  if (http) {
    return {
      label: `HTTP · :${http.port}`,
      request: requestText(host),
      response: responseText(http),
      note:
        port != null
          ? 'Обмен захвачен скан-запросом GET / по этому порту. Тело ответа не сохраняется.'
          : 'Это реальный обмен, который выполнил сканер при проверке HTTP на узле.',
    }
  }

  const tls = port ? (ip.tls?.port === port.port ? ip.tls : null) : ip.tls
  if (tls) {
    return {
      label: `TLS · :${tls.port}`,
      request: 'TLS ClientHello (SNI, ALPN h2, http/1.1)',
      response: [
        `Protocol: ${tls.protocol || '—'}`,
        `Cipher: ${tls.cipher || '—'}`,
        `Subject: ${tls.subject || '—'}`,
        `Issuer: ${tls.issuer || '—'}`,
        `Valid to: ${tls.validTo || '—'}`,
        `ALPN: ${tls.alpn || '—'}`,
      ].join('\r\n'),
      note: 'Показан результат TLS-рукопожатия. Приватный ключ и сессия не сохраняются.',
    }
  }

  if (port?.banner) {
    return {
      label: `BANNER · :${port.port}`,
      response: port.banner,
      note:
        port.protocol === 'udp'
          ? 'UDP-сервис ответил на минимальную пробу. Полный диалог не ведётся.'
          : 'Сканер подключился и прочитал приветствие сервиса, не отправляя команд.',
    }
  }

  if (port && HTTP_PORT_NUMBERS.has(port.port)) {
    return {
      label: `HTTP · :${port.port}`,
      request: requestText(host),
      response: '— ответ не получен (таймаут или порт не HTTP) —',
      note: 'Соединение установлено, но корректного HTTP-ответа не было.',
    }
  }

  return undefined
}


/* ------------------------------------------------------------------ */
/*  object summary                                                     */
/* ------------------------------------------------------------------ */

type ProviderTable = [RegExp, string][]

const DNS_PROVIDERS: ProviderTable = [
  [/cloudflare/, 'Cloudflare'],
  [/awsdns/, 'AWS Route 53'],
  [/domaincontrol|godaddy/, 'GoDaddy'],
  [/googledomains|ns-cloud|google/, 'Google Cloud DNS'],
  [/azure-dns/, 'Azure DNS'],
  [/digitalocean/, 'DigitalOcean'],
  [/nsone/, 'NS1'],
  [/yandex/, 'Yandex DNS'],
  [/reg\.ru|regru/, 'REG.RU'],
  [/timeweb/, 'Timeweb'],
  [/beget/, 'Beget'],
  [/hetzner/, 'Hetzner'],
  [/dnsimple/, 'DNSimple'],
  [/registrar-servers|namecheap/, 'Namecheap'],
  [/cloudns/, 'ClouDNS'],
  [/dnspod/, 'DNSPod'],
  [/hurricane|he\.net/, 'Hurricane Electric'],
]

const MAIL_PROVIDERS: ProviderTable = [
  [/google|googlemail/, 'Google Workspace'],
  [/protection\.outlook|outlook|microsoft/, 'Microsoft 365'],
  [/yandex/, 'Yandex Mail'],
  [/mail\.ru|mailru/, 'Mail.ru'],
  [/zoho/, 'Zoho Mail'],
  [/icloud|apple/, 'iCloud Mail'],
  [/proton/, 'Proton Mail'],
  [/mimecast/, 'Mimecast'],
  [/proofpoint|pphosted/, 'Proofpoint'],
  [/barracuda/, 'Barracuda'],
  [/mailgun/, 'Mailgun'],
  [/sendgrid/, 'SendGrid'],
  [/amazonses|amazonaws/, 'Amazon SES'],
]

const EDGE_PROVIDERS: ProviderTable = [
  [/cf-ray|cloudflare/, 'Cloudflare'],
  [/x-amz-cf-id|cloudfront/, 'AWS CloudFront'],
  [/akamai/, 'Akamai'],
  [/x-fastly|x-served-by/, 'Fastly'],
  [/x-vercel|server=vercel/, 'Vercel'],
  [/x-nf-request-id|netlify/, 'Netlify'],
  [/x-github-request-id/, 'GitHub Pages'],
  [/sucuri/, 'Sucuri'],
  [/x-proxy-cache|varnish/, 'Varnish'],
  [/bunnycdn|b-cdn/, 'Bunny CDN'],
  [/ddos-guard/, 'DDoS-Guard'],
  [/qrator/, 'Qrator'],
]

function matchProvider(haystack: string, table: ProviderTable): string | null {
  for (const [pattern, name] of table) {
    if (pattern.test(haystack)) return name
  }
  return null
}

/**
 * Turns raw DNS/HTTP/TLS events into a compact "what is this host" summary:
 * DNS and mail providers, edge/CDN, network owner, certificate health and
 * a handful of HTTP security headers.
 */
export function objectSummary(state: ScanState): ObjectSummary | null {
  const hasData =
    state.dns.ns.length > 0 ||
    state.dns.mx.length > 0 ||
    state.ips.some((entry) => entry.http || entry.tls)
  if (!hasData) return null

  const ns = state.dns.ns.join(' ').toLowerCase()
  const dnsName = ns ? matchProvider(ns, DNS_PROVIDERS) || state.dns.ns[0] || '—' : '—'

  const mx = state.dns.mx.map((entry) => entry.exchange).join(' ').toLowerCase()
  const mailName = mx
    ? matchProvider(mx, MAIL_PROVIDERS) || state.dns.mx[0]?.exchange || '—'
    : '—'

  const httpEntries = state.ips.flatMap((entry) =>
    entry.httpAll?.length ? entry.httpAll : entry.http ? [entry.http] : [],
  )
  const preferred =
    httpEntries.find((entry) => entry.port === 443) ||
    httpEntries.slice().sort((a, b) => a.port - b.port)[0]
  const headers = preferred?.headers || {}
  const server = preferred?.server || httpEntries.find((entry) => entry?.server)?.server || ''
  const haystack = [
    ...httpEntries.flatMap((entry) => Object.entries(entry?.headers || {}).map(([k, v]) => `${k}=${v}`)),
    ...httpEntries.map((entry) => entry?.server || ''),
    ...httpEntries.map((entry) => entry?.poweredBy || ''),
  ]
    .join(' ')
    .toLowerCase()
  const edge = haystack ? matchProvider(haystack, EDGE_PROVIDERS) : null
  // A bare "Server: github.com" is not a CDN — only surface generic proxies.
  const genericServer = /^(nginx|openresty|envoy|caddy|apache|httpd|microsoft-iis|iis|litespeed|varnish|traefik)\b/i.test(
    server,
  )
  const edgeName = edge || (genericServer ? server : '—')

  const primary = primaryIp(state)
  const geo = primary?.geo
  const asnName = [geo?.asn, geo?.isp || geo?.org].filter(Boolean).join(' · ') || '—'

  const tlsInfo = state.ips.find((entry) => entry.tls)?.tls
  let cert: SummaryCert | null = null
  if (tlsInfo) {
    const parsed = tlsInfo.validTo ? Date.parse(tlsInfo.validTo) : NaN
    const days = Number.isFinite(parsed) ? Math.ceil((parsed - Date.now()) / 86_400_000) : null
    cert = {
      issuer: tlsInfo.issuer || '—',
      subject: tlsInfo.subject || '—',
      protocol: tlsInfo.protocol || '—',
      days,
      validTo: tlsInfo.validTo || null,
      expired: days != null && days <= 0,
      expiringSoon: days != null && days > 0 && days <= 14,
      altNames: tlsInfo.altNames?.length || 0,
    }
  }

  const csp = String(headers['content-security-policy'] || '')
  const hygiene: SummaryFlag[] = [
    { key: 'hsts', label: 'HSTS', hint: 'strict-transport-security', ok: Boolean(headers['strict-transport-security']) },
    { key: 'csp', label: 'CSP', hint: 'content-security-policy', ok: Boolean(csp) },
    {
      key: 'xfo',
      label: 'XFO',
      hint: 'x-frame-options или CSP frame-ancestors',
      ok: Boolean(headers['x-frame-options']) || /frame-ancestors/i.test(csp),
    },
    { key: 'xcto', label: 'XCTO', hint: 'x-content-type-options', ok: Boolean(headers['x-content-type-options']) },
    { key: 'ref', label: 'REF', hint: 'referrer-policy', ok: Boolean(headers['referrer-policy']) },
  ]

  return {
    providers: [
      { label: 'DNS', value: dnsName },
      { label: 'ПОЧТА', value: mailName },
      { label: 'CDN / WAF', value: edgeName },
      { label: 'ASN', value: asnName },
    ],
    cert,
    hygiene,
    hygieneOk: hygiene.filter((flag) => flag.ok).length,
  }
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
      findings: findingsForIp(ip, state.host || state.target || ''),
      tech: techForIp(ip),
      packet: packetFor(ip, state.host || state.target || ''),
    }
  }

  if (selection.kind === 'link') {
    const ip = state.ips.find((entry) => entry.ip === selection.ip)
    if (!ip) return null
    const counts = portCounts({ ...state, ips: [ip] })
    const open = Object.values(ip.ports).filter((port) => port.state === 'open')
    return {
      eyebrow: 'LINK INSPECTOR',
      title: `${state.host || state.target || 'target'} → ${ip.ip}`,
      subtitle: `${counts.open} open · ${ip.ptr || fmtGeo(ip.geo)}`,
      color: '#38f6ff',
      rows: [
        { label: 'FROM', value: state.host || state.target || '—' },
        { label: 'TO', value: ip.ip },
        { label: 'ASN', value: ip.geo?.asn || '—' },
        { label: 'OPEN PORTS', value: open.map((port) => `${port.port}${port.protocol === 'udp' ? '/u' : ''}`).join(', ') || '—' },
        { label: 'TLS', value: ip.tls ? `${ip.tls.protocol || 'TLS'} · ${ip.tls.issuer || '—'}` : '—' },
      ],
      packet: packetFor(ip, state.host || state.target || ''),
    }
  }

  if (selection.kind === 'port') {
    const ip = state.ips.find((entry) => entry.ip === selection.ip)
    const port = ip?.ports[portKey(selection.port, selection.protocol ?? 'tcp')]
    if (!ip || !port) return null
    const rows = [
      { label: 'ENDPOINT', value: `${ip.ip}:${port.port}` },
      { label: 'PROTOCOL', value: port.protocol.toUpperCase() },
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
      eyebrow: port.protocol === 'udp' ? 'UDP SERVICE' : 'SERVICE PORT',
      title: `:${port.port}`,
      subtitle: `${port.service || 'unknown service'} · ${port.state} · ${port.protocol}`,
      color:
        port.state !== 'open'
          ? port.state === 'filtered'
            ? '#8b94a8'
            : '#ff4d6d'
          : port.protocol === 'udp'
            ? '#ffb020'
            : '#49ff9e',
      rows,
      block: tlsBlock,
      findings: findingsForPort(ip, port, state.host || state.target || ''),
      cves: matchCvesForPort(ip, port),
      tech: httpEntries(ip).find((entry) => entry.port === port.port)
        ? techForHttp(httpEntries(ip).find((entry) => entry.port === port.port)!)
        : undefined,
      packet: packetFor(ip, state.host || state.target || '', port),
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