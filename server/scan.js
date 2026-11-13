import dns from 'node:dns/promises'
import net from 'node:net'
import tls from 'node:tls'
import http from 'node:http'
import https from 'node:https'
import { spawn } from 'node:child_process'
import readline from 'node:readline'

/* ------------------------------------------------------------------ */
/*  constants                                                          */
/* ------------------------------------------------------------------ */

export const MAX_PORTS = 1024

const DEFAULT_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 1521,
  3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 27017,
]

const SERVICES = {
  20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
  67: 'dhcp', 69: 'tftp', 80: 'http', 110: 'pop3', 111: 'rpcbind', 123: 'ntp',
  135: 'msrpc', 137: 'netbios-ns', 138: 'netbios-dgm', 139: 'netbios-ssn',
  143: 'imap', 161: 'snmp', 389: 'ldap', 443: 'https', 445: 'smb',
  465: 'smtps', 500: 'isakmp', 514: 'syslog', 587: 'submission', 631: 'ipp',
  636: 'ldaps', 873: 'rsync', 993: 'imaps', 995: 'pop3s', 1080: 'socks',
  1433: 'mssql', 1521: 'oracle', 1723: 'pptp', 1883: 'mqtt', 2049: 'nfs',
  2375: 'docker', 2376: 'docker-tls', 3000: 'dev-http', 3306: 'mysql',
  3389: 'rdp', 4444: 'metasploit', 5000: 'dev-http', 5060: 'sip',
  5432: 'postgres', 5555: 'adb', 5672: 'amqp', 5900: 'vnc', 5984: 'couchdb',
  6379: 'redis', 6443: 'k8s-api', 7001: 'weblogic', 8000: 'http-alt',
  8080: 'http-proxy', 8081: 'http-alt', 8443: 'https-alt', 8888: 'http-alt',
  9000: 'http-alt', 9090: 'http-alt', 9200: 'elasticsearch', 9300: 'es-transport',
  9443: 'https-alt', 10000: 'webmin', 11211: 'memcached', 27017: 'mongodb',
  32400: 'plex', 50000: 'sap',
}

const TLS_PORTS = new Set([443, 465, 636, 993, 995, 8443, 9443, 2376, 6443])
const HTTP_PORTS = new Set([80, 3000, 5000, 8000, 8080, 8081, 8888, 9000, 9090, 9200, 10000])
const BANNER_PORTS = new Set([21, 22, 23, 25, 110, 143, 587])

const DNS_TIMEOUT = 7000
const GEO_TIMEOUT = 5000
const RDAP_TIMEOUT = 9000
const TRACEROUTE_MAX_HOPS = 12
const TRACEROUTE_BUDGET = 26000
const GLOBALPING_BUDGET = 22000
const GLOBALPING_POLL_MS = 1200
const MAX_RESOLVED_IPS = 4
const PORT_CONCURRENCY = 64

/* ------------------------------------------------------------------ */
/*  helpers                                                            */
/* ------------------------------------------------------------------ */

const now = () => Date.now()

function safe(promise, ms = DNS_TIMEOUT) {
  return Promise.race([
    Promise.resolve(promise).catch(() => null),
    new Promise((resolve) => setTimeout(() => resolve(null), ms).unref?.()),
  ])
}

function uniq(arr) {
  return [...new Set(arr)]
}

export function serviceName(port) {
  return SERVICES[port] || null
}

export function normalizeTarget(raw) {
  if (typeof raw !== 'string') throw new Error('Цель не указана')
  let value = raw.trim()
  if (!value) throw new Error('Цель не указана')
  if (value.length > 512) throw new Error('Слишком длинная цель')

  // Accept pasted URLs: https://user@host:port/path -> host
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    try {
      const url = new URL(value)
      value = url.hostname
    } catch {
      throw new Error('Не удалось разобрать URL')
    }
  }

  value = value.replace(/^\[|\]$/g, '')
  value = value.replace(/\.$/, '')

  if (net.isIP(value)) return { host: value, isIp: true, family: net.isIP(value) }

  if (!/^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$/i.test(value)) {
    throw new Error('Некорректный адрес или домен')
  }

  return { host: value.toLowerCase(), isIp: false, family: 0 }
}

export function parsePorts(input) {
  if (input === undefined || input === null || String(input).trim() === '') {
    return [...DEFAULT_PORTS]
  }

  const parts = String(input)
    .split(/[\s,;]+/)
    .filter(Boolean)

  const ports = new Set()

  for (const part of parts) {
    const m = /^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$/.exec(part)
    if (!m) throw new Error(`Некорректный порт: ${part}`)
    let from = Number(m[1])
    let to = m[2] ? Number(m[2]) : from
    if (from > to) [from, to] = [to, from]
    if (from < 1 || to > 65535) throw new Error('Порты должны быть в диапазоне 1–65535')
    for (let p = from; p <= to; p++) {
      ports.add(p)
      if (ports.size > MAX_PORTS) throw new Error(`Максимум ${MAX_PORTS} портов за один скан`)
    }
  }

  return [...ports].sort((a, b) => a - b)
}

function isAborted(signal) {
  return signal?.aborted === true
}

/* ------------------------------------------------------------------ */
/*  DNS                                                                */
/* ------------------------------------------------------------------ */

async function resolveRecords(host) {
  const [a, aaaa, cname, ns, mx, txt, soa] = await Promise.all([
    safe(dns.resolve4(host, { ttl: true })),
    safe(dns.resolve6(host, { ttl: true })),
    safe(dns.resolveCname(host)),
    safe(dns.resolveNs(host)),
    safe(dns.resolveMx(host)),
    safe(dns.resolveTxt(host)),
    safe(dns.resolveSoa(host)),
  ])

  let aRecords = (a || []).map((r) => ({ address: r.address, ttl: r.ttl ?? null }))
  let aaaaRecords = (aaaa || []).map((r) => ({ address: r.address, ttl: r.ttl ?? null }))

  // resolve4 does not follow CNAME chains on all platforms
  if (!aRecords.length && cname?.length) {
    const followed = await safe(dns.resolve4(cname[0], { ttl: true }))
    if (followed?.length) aRecords = followed.map((r) => ({ address: r.address, ttl: r.ttl ?? null }))
  }

  // Some resolvers / networks stall c-ares queries. Fall back to the OS
  // resolver so an IPv4-only host never silently becomes unreachable.
  if (!aRecords.length) {
    const rows = await safe(dns.lookup(host, { all: true }), 5000)
    if (rows?.length) {
      for (const row of rows) {
        if (row.family === 4 && !aRecords.some((r) => r.address === row.address)) {
          aRecords.push({ address: row.address, ttl: null })
        }
        if (row.family === 6 && !aaaaRecords.some((r) => r.address === row.address)) {
          aaaaRecords.push({ address: row.address, ttl: null })
        }
      }
    }
  }

  return {
    a: aRecords.slice(0, MAX_RESOLVED_IPS),
    aaaa: aaaaRecords.slice(0, 2),
    cname: cname || [],
    ns: ns || [],
    mx: (mx || []).filter((entry) => Boolean(entry.exchange)).sort((x, y) => x.priority - y.priority),
    txt: (txt || []).map((chunks) => chunks.join('')).slice(0, 12),
    soa: soa || null,
  }
}

/* ------------------------------------------------------------------ */
/*  port probing                                                       */
/* ------------------------------------------------------------------ */

function probePort(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const started = now()
    const socket = new net.Socket()
    let done = false
    let bannerTimer = null

    const finish = (state, extra = {}) => {
      if (done) return
      done = true
      if (bannerTimer) clearTimeout(bannerTimer)
      socket.removeAllListeners()
      socket.destroy()
      resolve({
        port,
        state,
        rtt: Math.max(0, now() - started),
        service: serviceName(port),
        ...extra,
      })
    }

    socket.setTimeout(timeoutMs)

    socket.once('connect', () => {
      if (BANNER_PORTS.has(port)) {
        let banner = ''
        socket.once('data', (chunk) => {
          banner = chunk.toString('utf8').replace(/[\u0000-\u001f]+/g, ' ').trim().slice(0, 140)
          finish('open', banner ? { banner } : {})
        })
        bannerTimer = setTimeout(() => finish('open'), 220)
      } else {
        finish('open')
      }
    })

    socket.once('timeout', () => finish('filtered', { error: 'TIMEOUT' }))
    socket.once('error', (err) => {
      const state = err.code === 'ECONNREFUSED' ? 'closed' : 'filtered'
      finish(state, { error: err.code || 'ERROR' })
    })

    try {
      socket.connect({ host: ip, port })
    } catch {
      finish('filtered', { error: 'CONNECT_FAILED' })
    }
  })
}

/* ------------------------------------------------------------------ */
/*  TLS / HTTP fingerprints                                            */
/* ------------------------------------------------------------------ */

function probeTls(ip, port, servername, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false
    const finish = (value) => {
      if (settled) return
      settled = true
      try {
        socket.destroy()
      } catch {}
      resolve(value)
    }

    const socket = tls.connect({
      host: ip,
      port,
      servername: servername || undefined,
      rejectUnauthorized: false,
      ALPNProtocols: ['h2', 'http/1.1'],
      timeout: timeoutMs,
    })

    socket.once('secureConnect', () => {
      try {
        const cert = socket.getPeerCertificate(true) || {}
        const subject = cert.subject || {}
        const issuer = cert.issuer || {}
        finish({
          subject: subject.CN || subject.O || null,
          issuer: issuer.O || issuer.CN || null,
          validFrom: cert.valid_from || null,
          validTo: cert.valid_to || null,
          altNames: cert.subjectaltname
            ? cert.subjectaltname.replace(/DNS:/g, '').split(', ').slice(0, 12)
            : [],
          serial: cert.serialNumber || null,
          fingerprint: cert.fingerprint256 || null,
          protocol: socket.getProtocol() || null,
          cipher: socket.getCipher()?.name || null,
          alpn: socket.alpnProtocol || null,
        })
      } catch {
        finish(null)
      }
    })

    socket.once('timeout', () => finish(null))
    socket.once('error', () => finish(null))
  })
}

function probeHttp({ ip, port, hostname, secure, timeoutMs }) {
  return new Promise((resolve) => {
    let settled = false
    const finish = (value) => {
      if (settled) return
      settled = true
      try {
        req.destroy()
      } catch {}
      resolve(value)
    }

    const lib = secure ? https : http
    const req = lib.request(
      {
        host: ip,
        port,
        servername: secure ? hostname : undefined,
        method: 'GET',
        path: '/',
        timeout: timeoutMs,
        rejectUnauthorized: false,
        headers: {
          Host: hostname,
          'User-Agent': 'NetworkMap/1.0 (topology visualizer)',
          Accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
          Connection: 'close',
        },
      },
      (res) => {
        let body = ''
        res.setEncoding('utf8')
        res.on('data', (chunk) => {
          body += chunk
          if (body.length > 24000) {
            const title = extractTitle(body)
            finish({
              status: res.statusCode || 0,
              server: res.headers.server || null,
              poweredBy: res.headers['x-powered-by'] || null,
              contentType: res.headers['content-type'] || null,
              title,
              headers: pickHeaders(res.headers),
            })
          }
        })
        res.on('end', () => {
          finish({
            status: res.statusCode || 0,
            server: res.headers.server || null,
            poweredBy: res.headers['x-powered-by'] || null,
            contentType: res.headers['content-type'] || null,
            title: extractTitle(body),
            headers: pickHeaders(res.headers),
          })
        })
        res.on('error', () => finish(null))
      },
    )

    req.on('timeout', () => finish(null))
    req.on('error', () => finish(null))
    req.end()
  })
}

function pickHeaders(headers) {
  const keep = [
    'server', 'content-type', 'x-powered-by', 'strict-transport-security',
    'content-security-policy', 'via', 'x-cache', 'cf-ray', 'x-frame-options',
  ]
  const out = {}
  for (const key of keep) {
    if (headers[key]) out[key] = String(headers[key]).slice(0, 180)
  }
  return out
}

function extractTitle(html) {
  const m = /<title[^>]*>([\s\S]{0,200}?)<\/title>/i.exec(html)
  if (!m) return null
  return m[1]
    .replace(/\s+/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .trim()
    .slice(0, 140) || null
}

/* ------------------------------------------------------------------ */
/*  GEO / RDAP                                                         */
/* ------------------------------------------------------------------ */

const geoCache = new Map()

async function lookupGeo(ip) {
  if (geoCache.has(ip)) return geoCache.get(ip)

  let result = null
  try {
    const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      signal: AbortSignal.timeout(GEO_TIMEOUT),
      headers: { 'User-Agent': 'NetworkMap/1.0' },
    })
    if (res.ok) {
      const d = await res.json()
      if (d && d.success !== false) {
        result = {
          country: d.country || null,
          countryCode: d.country_code || null,
          region: d.region || null,
          city: d.city || null,
          isp: d.connection?.isp || null,
          org: d.connection?.org || null,
          asn: d.connection?.asn ? `AS${d.connection.asn}` : null,
          lat: typeof d.latitude === 'number' ? d.latitude : null,
          lon: typeof d.longitude === 'number' ? d.longitude : null,
          timezone: d.timezone?.id || null,
        }
      }
    }
  } catch {}

  if (!result) {
    try {
      const res = await fetch(
        `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,regionName,city,isp,org,as,lat,lon,timezone`,
        { signal: AbortSignal.timeout(GEO_TIMEOUT) },
      )
      if (res.ok) {
        const d = await res.json()
        if (d && d.status === 'success') {
          result = {
            country: d.country || null,
            countryCode: d.countryCode || null,
            region: d.regionName || null,
            city: d.city || null,
            isp: d.isp || null,
            org: d.org || null,
            asn: d.as || null,
            lat: typeof d.lat === 'number' ? d.lat : null,
            lon: typeof d.lon === 'number' ? d.lon : null,
            timezone: d.timezone || null,
          }
        }
      }
    } catch {}
  }

  if (result) {
    if (geoCache.size > 600) geoCache.clear()
    geoCache.set(ip, result)
  }
  return result
}

function vcardName(entity) {
  const vcard = entity?.vcardArray?.[1]
  if (!Array.isArray(vcard)) return null
  const fn = vcard.find((entry) => entry[0] === 'fn')
  return typeof fn?.[3] === 'string' ? fn[3] : null
}

function rdapSummary(raw) {
  if (!raw || typeof raw !== 'object') return null
  const events = Array.isArray(raw.events) ? raw.events : []
  const event = (action) => events.find((e) => e.eventAction === action)?.eventDate || null
  const entities = Array.isArray(raw.entities) ? raw.entities : []
  const registrar = entities.find((e) => (e.roles || []).includes('registrar'))
  const orgEntity = entities.find((e) => (e.roles || []).includes('registrant')) || entities[0]

  return {
    name: raw.name || raw.ldhName || null,
    handle: raw.handle || null,
    type: raw.objectClassName || null,
    country: raw.country || null,
    registrar: vcardName(registrar) || null,
    org: vcardName(orgEntity) || null,
    status: Array.isArray(raw.status) ? raw.status.slice(0, 4) : [],
    registered: event('registration'),
    changed: event('last changed'),
    expires: event('expiration'),
    nameservers: (raw.nameservers || []).map((n) => n.ldhName).filter(Boolean).slice(0, 8),
  }
}

async function lookupRdap(host, isIp) {
  const url = isIp
    ? `https://rdap.org/ip/${encodeURIComponent(host)}`
    : `https://rdap.org/domain/${encodeURIComponent(host)}`
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(RDAP_TIMEOUT),
      headers: { Accept: 'application/rdap+json, application/json', 'User-Agent': 'NetworkMap/1.0' },
    })
    if (!res.ok) return null
    return rdapSummary(await res.json())
  } catch {
    return null
  }
}

/* ------------------------------------------------------------------ */
/*  traceroute                                                         */
/* ------------------------------------------------------------------ */

function traceroute(ip, emit, signal) {
  return new Promise((resolve) => {
    const isWin = process.platform === 'win32'
    const args = isWin
      ? ['-d', '-h', String(TRACEROUTE_MAX_HOPS), '-w', '600', ip]
      : ['-n', '-m', String(TRACEROUTE_MAX_HOPS), '-w', '1', '-q', '1', ip]

    let child
    let spawnFailed = false
    try {
      child = spawn(isWin ? 'tracert' : 'traceroute', args, {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      })
    } catch {
      resolve({ hops: [], ok: false })
      return
    }

    const hops = []
    let finished = false
    const finish = () => {
      if (finished) return
      finished = true
      clearTimeout(killTimer)
      try {
        child.kill()
      } catch {}
      resolve({ hops, ok: !spawnFailed })
    }

    const killTimer = setTimeout(finish, TRACEROUTE_BUDGET)

    const rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity })
    rl.on('line', (line) => {
      if (isAborted(signal)) return finish()
      const parsed = parseHopLine(line)
      if (!parsed) return
      if (hops.some((h) => h.index === parsed.index)) return
      hops.push(parsed)
      emit({ type: 'hop', ...parsed })
    })

    child.once('error', (err) => {
      // Render / minimal containers often lack tracert/traceroute entirely.
      if (['ENOENT', 'EACCES', 'EPERM'].includes(err?.code)) spawnFailed = true
      finish()
    })
    child.once('close', finish)
    signal?.addEventListener('abort', finish, { once: true })
  })
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number)
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    )
  }
  if (net.isIPv6(ip)) {
    const value = ip.toLowerCase()
    return value === '::1' || value.startsWith('fc') || value.startsWith('fd') || value.startsWith('fe80')
  }
  return false
}

/* Fallback for hosts without a traceroute binary (e.g. Render): ask the free
   Globalping API to run the measurement from a German probe and stream hops. */
async function globalpingTraceroute(ip, onHop, signal) {
  try {
    const create = await fetch('https://api.globalping.io/v1/measurements', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'NetworkMap/1.0' },
      body: JSON.stringify({
        type: 'traceroute',
        target: ip,
        limit: 1,
        locations: [{ country: 'DE' }],
      }),
      signal: AbortSignal.timeout(8000),
    })
    if (!create.ok) return []
    const { id } = await create.json()
    if (!id) return []

    const deadline = Date.now() + GLOBALPING_BUDGET
    while (Date.now() < deadline) {
      if (isAborted(signal)) return []
      await sleep(GLOBALPING_POLL_MS)
      if (isAborted(signal)) return []

      const res = await fetch(`https://api.globalping.io/v1/measurements/${id}`, {
        headers: { 'User-Agent': 'NetworkMap/1.0' },
        signal: AbortSignal.timeout(8000),
      })
      if (!res.ok) continue
      const data = await res.json()
      if (data.status !== 'finished') continue

      const hops = data.results?.[0]?.result?.hops || []
      const parsedHops = []
      hops.slice(0, TRACEROUTE_MAX_HOPS).forEach((hop, offset) => {
        const rtts = (hop.timings || [])
          .map((timing) => timing.rtt)
          .filter((rtt) => Number.isFinite(rtt))
        const parsed = {
          index: offset + 1,
          ip: hop.resolvedAddress || null,
          rtt: rtts.length ? Math.round(Math.min(...rtts)) : null,
          timeout: !hop.resolvedAddress,
        }
        parsedHops.push(parsed)
        if (!isAborted(signal)) onHop({ type: 'hop', ...parsed })
      })
      return parsedHops
    }
  } catch {}
  return []
}

function parseHopLine(line) {
  const head = /^\s*(\d{1,2})\s+(.*)$/.exec(line)
  if (!head) return null
  const index = Number(head[1])
  if (index < 1) return null
  const rest = head[2]

  const ipMatch = /(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})/i.exec(rest)

  if (!ipMatch) {
    // Any numbered line without an address is a timed-out probe. This also
    // covers localized tracert output (e.g. Russian "мс" instead of "ms").
    return { index, ip: null, rtt: null, timeout: true }
  }

  // Decoding OEM console output on Windows can mangle the "ms" unit, so we
  // strip the address and read the remaining numbers as RTT candidates.
  const withoutIp = rest.replace(ipMatch[1], ' ')
  const rtts = []
  for (const m of withoutIp.matchAll(/<\s*(\d+(?:[.,]\d+)?)/g)) {
    rtts.push(0)
  }
  for (const m of withoutIp.matchAll(/(\d+(?:[.,]\d+)?)/g)) {
    rtts.push(Math.round(Number(m[1].replace(',', '.'))))
  }

  return {
    index,
    ip: ipMatch[1],
    rtt: rtts.length ? Math.min(...rtts) : null,
    timeout: false,
  }
}

/* ------------------------------------------------------------------ */
/*  main scan                                                          */
/* ------------------------------------------------------------------ */

export async function runScan(input, emit, signal) {
  const started = now()
  const target = normalizeTarget(input.target)
  const ports = parsePorts(input.ports)
  const useTraceroute = input.traceroute !== false
  const useGeo = input.geo !== false

  const portTimeout = Math.min(10000, Math.max(200, Number(input.timeout) || 1400))

  emit({
    type: 'meta',
    host: target.host,
    isIp: target.isIp,
    ports,
    portTimeout,
    traceroute: useTraceroute,
    geo: useGeo,
    startedAt: started,
  })

  emit({
    type: 'log',
    level: 'info',
    message: `Инициализация сканирования ${target.host} · ${ports.length} порт(ов)`,
  })

  /* ---------- DNS ---------- */
  let records = null
  let ips = []

  if (target.isIp) {
    ips = [{ ip: target.host, family: target.family }]
    emit({ type: 'log', level: 'ok', message: `IP-цель: ${target.host}` })
  } else {
    records = await resolveRecords(target.host)
    ips = [
      ...records.a.map((r) => ({ ip: r.address, family: 4, ttl: r.ttl })),
      ...records.aaaa.map((r) => ({ ip: r.address, family: 6, ttl: r.ttl })),
    ]
    records = { ...records, a: records.a, aaaa: records.aaaa }
    emit({ type: 'dns', records })

    if (!ips.length) {
      emit({ type: 'fatal', message: `Не удалось разрешить ${target.host}: записей A/AAAA нет` })
      emit({ type: 'done', stats: emptyStats(started, ports.length) })
      return
    }

    // de-dupe and cap
    const seen = new Set()
    ips = ips.filter((entry) => {
      if (seen.has(entry.ip)) return false
      seen.add(entry.ip)
      return true
    }).slice(0, MAX_RESOLVED_IPS + 2)

    emit({
      type: 'log',
      level: 'ok',
      message: `DNS: ${records.a.length} A · ${records.aaaa.length} AAAA · ${records.ns.length} NS · ${records.mx.length} MX`,
    })
  }

  /* ---------- IP nodes ---------- */
  ips.forEach((entry, index) => {
    emit({
      type: 'ip',
      ip: entry.ip,
      family: entry.family,
      primary: index === 0,
      ttl: entry.ttl ?? null,
    })
  })

  const primary = ips[0]

  /* ---------- async enrichment: ptr + geo + rdap ---------- */
  const enrich = []

  // reverse lookups (streamed while port scanning starts)
  for (const entry of ips) {
    enrich.push(
      safe(dns.reverse(entry.ip), 4000).then((names) => {
        if (names?.[0] && !isAborted(signal)) {
          emit({ type: 'ptr', ip: entry.ip, ptr: names[0] })
        }
      }),
    )
  }

  if (useGeo) {
    const geoIps = uniq(ips.map((e) => e.ip)).slice(0, 6)
    enrich.push(
      (async () => {
        for (const ip of geoIps) {
          const geo = await lookupGeo(ip)
          if (geo && !isAborted(signal)) emit({ type: 'geo', ip, geo })
        }
      })(),
    )
  }

  enrich.push(
    (async () => {
      const rdap = await lookupRdap(target.host, target.isIp)
      if (rdap && !isAborted(signal)) emit({ type: 'rdap', rdap })
    })(),
  )

  /* ---------- traceroute ---------- */
  let hopCount = 0
  const hopGeo = []
  const onHop = (event) => {
    hopCount++
    emit(event)
    if (useGeo && event.ip) {
      hopGeo.push(
        lookupGeo(event.ip).then((geo) => {
          if (geo && !isAborted(signal)) emit({ type: 'geo', ip: event.ip, geo })
        }),
      )
    }
  }

  const tracerouteTask = useTraceroute
    ? traceroute(primary.ip, onHop, signal)
    : Promise.resolve({ hops: [], ok: false })

  /* ---------- stats ---------- */
  const stats = {
    open: 0,
    closed: 0,
    filtered: 0,
    scanned: 0,
    ips: ips.length,
    hops: 0,
  }

  const probeCache = new Set()
  const probeTasks = new Set()

  async function probeOpenPort(ip, port) {
    const key = `${ip}:${port}`
    if (probeCache.has(key)) return
    probeCache.add(key)

    if (TLS_PORTS.has(port)) {
      const info = await probeTls(ip, port, target.isIp ? undefined : target.host, Math.max(portTimeout, 2500))
      if (info && !isAborted(signal)) {
        emit({ type: 'tls', ip, port, ...info })
        emit({ type: 'log', level: 'ok', message: `TLS ${ip}:${port} · ${info.subject || 'certificate'} (${info.protocol || 'tls'})` })
      }
      const httpInfo = await probeHttp({
        ip, port, hostname: target.host, secure: true, timeoutMs: Math.max(portTimeout, 3000),
      })
      if (httpInfo && !isAborted(signal)) {
        emit({ type: 'http', ip, port, ...httpInfo })
        emit({ type: 'log', level: 'info', message: `HTTP ${ip}:${port} → ${httpInfo.status} ${httpInfo.server || ''}`.trim() })
      }
    } else if (HTTP_PORTS.has(port)) {
      const httpInfo = await probeHttp({
        ip, port, hostname: target.host, secure: false, timeoutMs: Math.max(portTimeout, 3000),
      })
      if (httpInfo && !isAborted(signal)) {
        emit({ type: 'http', ip, port, ...httpInfo })
        emit({ type: 'log', level: 'info', message: `HTTP ${ip}:${port} → ${httpInfo.status} ${httpInfo.server || ''}`.trim() })
      }
    }
  }

  async function scanIp(entry) {
    const queue = ports.slice()
    const workers = Array.from(
      { length: Math.min(PORT_CONCURRENCY, queue.length) },
      async () => {
        while (queue.length && !isAborted(signal)) {
          const port = queue.shift()
          const result = await probePort(entry.ip, port, portTimeout)
          if (isAborted(signal)) return
          stats.scanned++
          if (result.state === 'open') stats.open++
          else if (result.state === 'closed') stats.closed++
          else stats.filtered++

          emit({ type: 'port', ip: entry.ip, ...result })

          if (result.state === 'open') {
            emit({
              type: 'log',
              level: 'open',
              message: `${entry.ip}:${port} OPEN${result.service ? ` · ${result.service}` : ''} (${result.rtt} ms)`,
            })
            const probe = probeOpenPort(entry.ip, port).finally(() => {
              probeTasks.delete(probe)
            })
            probeTasks.add(probe)
          }
        }
      },
    )
    await Promise.all(workers)
  }

  for (const entry of ips) {
    if (isAborted(signal)) break
    await scanIp(entry)
  }

  const traceResult = useTraceroute
    ? await tracerouteTask
    : { hops: [], ok: false }

  let hops = traceResult.hops
  if (useTraceroute && (!traceResult.ok || !hops.length) && !isAborted(signal) && !isPrivateIp(primary.ip)) {
    emit({
      type: 'log',
      level: 'info',
      message: 'Локальный traceroute недоступен — строю маршрут через Globalping (DE)',
    })
    hops = await globalpingTraceroute(primary.ip, onHop, signal)
  }
  stats.hops = hops.length

  await Promise.allSettled([...enrich, ...hopGeo, ...probeTasks])

  if (!isAborted(signal)) {
    emit({
      type: 'done',
      stats: { ...stats, durationMs: now() - started },
    })
  }
}

function emptyStats(startedAt, portCount) {
  return {
    open: 0, closed: 0, filtered: 0, scanned: 0, ips: 0, hops: 0,
    durationMs: now() - startedAt, portCount,
  }
}