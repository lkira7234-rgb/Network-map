import { collectCves, severityColor, severityLabel } from './cve'
import { collectFindings, findingColor, findingLabel } from './checks'
import { techForIp } from './tech'
import { ScanState, Selection } from './types'

/* ------------------------------------------------------------------ */
/*  spotlight search                                                   */
/* ------------------------------------------------------------------ */

export interface SearchResult {
  id: string
  /** Primary line, e.g. `104.16.0.1:443`. */
  label: string
  /** Secondary line: service, CVE title, geo, … */
  hint: string
  color: string
  selection: Selection
  /** Node IPs to keep bright while the rest of the graph dims. */
  ips: string[]
}

export interface SearchOutcome {
  query: string
  results: SearchResult[]
  ips: string[]
}

const empty: SearchOutcome = { query: '', results: [], ips: [] }

function score(haystack: string, tokens: string[]): number {
  if (!tokens.length) return 0
  let total = 0
  for (const token of tokens) {
    const at = haystack.indexOf(token)
    if (at < 0) return -1
    total += at === 0 ? 3 : at > 0 && /[\s:.\-/]/.test(haystack[at - 1]) ? 2 : 1
  }
  return total
}

export function searchModel(state: ScanState, query: string): SearchOutcome {
  const trimmed = query.trim().toLowerCase()
  if (trimmed.length < 1) return empty
  const tokens = trimmed.split(/\s+/).filter(Boolean)

  const cves = collectCves(state)
  const findings = collectFindings(state)
  const results: (SearchResult & { rank: number })[] = []

  for (const ip of state.ips) {
    const tech = techForIp(ip)
    const ports = Object.values(ip.ports)
    const ipCves = cves.filter((match) => match.ip === ip.ip)
    const ipFindings = findings.filter((finding) => finding.ip === ip.ip)
    const haystack = [
      ip.ip,
      ip.ptr || '',
      ip.geo?.city || '',
      ip.geo?.country || '',
      ip.geo?.isp || '',
      ip.geo?.asn || '',
      ...ports.map((port) => `${port.port} ${port.protocol} ${port.service || ''}`),
      ...ports.map((port) => port.banner || ''),
      ...ipCves.map((match) => `${match.id} ${match.summary} ${match.product}`),
      ...ipFindings.map((finding) => `${finding.title} ${finding.summary}`),
      ...tech.map((hit) => hit.name),
    ]
      .join(' ')
      .toLowerCase()

    const rank = score(haystack, tokens)
    if (rank < 0) continue

    results.push({
      id: `ip:${ip.ip}`,
      label: ip.ip,
      hint: [ip.ptr, ip.geo?.asn, `${ports.filter((port) => port.state === 'open').length} open`]
        .filter(Boolean)
        .join(' · '),
      color: '#38f6ff',
      selection: { kind: 'ip', ip: ip.ip },
      ips: [ip.ip],
      rank: rank + 2,
    })

    for (const port of ports) {
      const portText = `${port.port} ${port.protocol} ${port.service || ''}`.toLowerCase()
      const portRank = score(portText, tokens)
      if (portRank < 0) continue
      results.push({
        id: `port:${ip.ip}:${port.protocol}:${port.port}`,
        label: `${ip.ip}:${port.port}${port.protocol === 'udp' ? '/udp' : ''}`,
        hint: `${port.state} · ${port.service || 'unknown'}${port.banner ? ` · ${port.banner.slice(0, 48)}` : ''}`,
        color: port.state === 'open' ? (port.protocol === 'udp' ? '#ffb020' : '#49ff9e') : '#ff4d6d',
        selection: {
          kind: 'port',
          ip: ip.ip,
          port: port.port,
          protocol: port.protocol,
        },
        ips: [ip.ip],
        rank: portRank + 4,
      })
    }

    for (const match of ipCves) {
      results.push({
        id: `cve:${match.id}:${match.ip}:${match.port}`,
        label: match.id,
        hint: `${severityLabel[match.severity]} · ${match.ip}:${match.port} · ${match.product} ${match.version}`,
        color: severityColor[match.severity],
        selection: {
          kind: 'port',
          ip: match.ip,
          port: match.port,
          protocol: match.protocol,
        },
        ips: [match.ip],
        rank: score(`${match.id} ${match.summary} ${match.product}`.toLowerCase(), tokens) + 3,
      })
    }

    for (const finding of ipFindings) {
      const findingRank = score(
        `${finding.title} ${finding.summary} ${finding.id}`.toLowerCase(),
        tokens,
      )
      if (findingRank < 0) continue
      results.push({
        id: `finding:${finding.id}:${finding.ip}:${finding.port ?? ''}`,
        label: finding.title,
        hint: `${findingLabel[finding.severity]} · ${finding.ip}${finding.port ? `:${finding.port}` : ''}`,
        color: findingColor[finding.severity],
        selection: finding.port
          ? { kind: 'port', ip: finding.ip, port: finding.port, protocol: finding.protocol }
          : { kind: 'ip', ip: finding.ip },
        ips: [finding.ip],
        rank: findingRank + 1,
      })
    }
  }

  for (const hop of state.hops) {
    if (!hop.ip) continue
    const hopRank = score(`${hop.ip} hop ${hop.index} ${hop.geo?.city || ''}`.toLowerCase(), tokens)
    if (hopRank < 0) continue
    results.push({
      id: `hop:${hop.index}`,
      label: `HOP ${String(hop.index).padStart(2, '0')}`,
      hint: `${hop.ip}${hop.geo?.city ? ` · ${hop.geo.city}` : ''}`,
      color: '#ff6bd6',
      selection: { kind: 'hop', index: hop.index },
      ips: [],
      rank: hopRank,
    })
  }

  const ns = state.dns.ns
  ns.forEach((name, index) => {
    const value = score(name.toLowerCase(), tokens)
    if (value < 0) return
    results.push({
      id: `ns:${name}`,
      label: name,
      hint: 'NAMESERVER',
      color: '#ffb020',
      selection: { kind: 'ns', index },
      ips: [],
      rank: value,
    })
  })

  const mx = state.dns.mx
  mx.forEach((entry, index) => {
    const value = score(entry.exchange.toLowerCase(), tokens)
    if (value < 0) return
    results.push({
      id: `mx:${entry.exchange}`,
      label: entry.exchange,
      hint: `MX ${entry.priority}`,
      color: '#c07bff',
      selection: { kind: 'mx', index },
      ips: [],
      rank: value,
    })
  })

  results.sort((a, b) => b.rank - a.rank || a.label.localeCompare(b.label))
  const top = results.slice(0, 40).map(({ rank, ...rest }) => rest)
  const ips = [...new Set(top.flatMap((result) => result.ips))]
  return { query: trimmed, results: top, ips }
}
