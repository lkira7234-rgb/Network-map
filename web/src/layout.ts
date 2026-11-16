import * as THREE from 'three'
import { HopInfo, IpEntry, PortInfo, ScanState } from './types'

export const CORE_Y = 10

export type ClusterMode = 'none' | 'subnet' | 'asn'

export interface PortNode {
  info: PortInfo
  pos: THREE.Vector3
}

export interface IpLayout {
  entry: IpEntry
  pos: THREE.Vector3
  ports: PortNode[]
  open: PortNode[]
  closed: PortNode[]
}

export interface DnsNodeLayout {
  name: string
  sub?: string
  pos: THREE.Vector3
}

export interface SubdomainLayout {
  name: string
  pos: THREE.Vector3
}

export interface HopLayout {
  hop: HopInfo
  pos: THREE.Vector3
}

export interface ClusterLayout {
  key: string
  label: string
  pos: THREE.Vector3
  radius: number
  count: number
}

export interface Layout {
  core: THREE.Vector3
  you: THREE.Vector3
  ips: IpLayout[]
  ns: DnsNodeLayout[]
  mx: DnsNodeLayout[]
  hops: HopLayout[]
  hopLine: THREE.Vector3[]
  clusters: ClusterLayout[]
}

const v = (x: number, y: number, z: number) => new THREE.Vector3(x, y, z)

/** /24 for IPv4 and /64 for IPv6 — stable, readable groups. */
export function subnetKey(ip: string): string {
  if (ip.includes(':')) {
    const head = ip.split(':').filter(Boolean).slice(0, 4).join(':')
    return `${head}::/64`
  }
  const parts = ip.split('.')
  return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : ip
}

function asnKey(entry: IpEntry): string {
  if (entry.geo?.asn) return entry.geo.asn
  if (entry.geo?.org) return `AS? · ${entry.geo.org}`
  if (entry.geo?.isp) return `AS? · ${entry.geo.isp}`
  return 'AS? · unknown'
}

function groupEntries(entries: IpEntry[], mode: ClusterMode) {
  const groups = new Map<string, IpEntry[]>()
  for (const entry of entries) {
    const key = mode === 'asn' ? asnKey(entry) : subnetKey(entry.ip)
    const list = groups.get(key)
    if (list) list.push(entry)
    else groups.set(key, [entry])
  }
  return [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))
}

function portNodes(entry: IpEntry, base: THREE.Vector3): PortNode[] {
  return Object.values(entry.ports).map((info) => {
    // UDP orbits slightly outside TCP so :53 and udp/:53 never overlap.
    const udp = info.protocol === 'udp'
    const a = ((info.port * 2.399963) + (udp ? 1.75 : 0)) % (Math.PI * 2)
    const open = info.state === 'open'
    const filtered = info.state === 'filtered'
    const rr = (open ? 3.3 : filtered ? 4.4 : 4.0) + (udp ? 0.9 : 0)
    return {
      info,
      pos: v(
        base.x + Math.cos(a) * rr,
        base.y + Math.sin(a) * rr * 0.66,
        base.z + Math.sin(a) * rr * 0.52,
      ),
    }
  })
}

function makeIpLayout(entry: IpEntry, pos: THREE.Vector3): IpLayout {
  const ports = portNodes(entry, pos)
  return {
    entry,
    pos,
    ports,
    open: ports.filter((p) => p.info.state === 'open'),
    closed: ports.filter((p) => p.info.state !== 'open'),
  }
}

export function buildLayout(state: ScanState, cluster: ClusterMode = 'none'): Layout {
  const core = v(0, CORE_Y, 0)
  const you = v(-10.5, CORE_Y + 1.6, 31)

  const count = Math.max(1, state.ips.length)
  const clusters: ClusterLayout[] = []
  let ips: IpLayout[] = []

  const groups = cluster === 'none' ? null : groupEntries(state.ips, cluster)
  if (groups && groups.length > 1 && state.ips.length >= 3) {
    const ring = Math.max(16, Math.min(40, 10 + groups.length * 2.3))
    groups.forEach(([key, entries], index) => {
      const angle = (index / groups.length) * Math.PI * 2 + Math.PI * 0.15
      const center = v(
        Math.cos(angle) * ring,
        CORE_Y + Math.sin(index * 1.7) * 3.2,
        Math.sin(angle) * ring + 1.5,
      )
      const memberRadius = 3.4 + Math.min(5.5, Math.sqrt(entries.length) * 1.6)
      entries.forEach((entry, member) => {
        const memberAngle = (member / Math.max(1, entries.length)) * Math.PI * 2
        const pos = v(
          center.x + Math.cos(memberAngle) * memberRadius,
          center.y + Math.sin(member * 1.9) * 1.7,
          center.z + Math.sin(memberAngle) * memberRadius,
        )
        ips.push(makeIpLayout(entry, pos))
      })
      clusters.push({
        key,
        label: key,
        pos: center,
        radius: memberRadius + 2.4,
        count: entries.length,
      })
    })
  } else {
    const ring = count === 1 ? 10 : 12 + Math.sqrt(count) * 2.6
    ips = state.ips.map((entry, index) => {
      const angle = (index / count) * Math.PI * 2 + Math.PI * 0.22
      const pos = v(
        Math.cos(angle) * ring,
        CORE_Y + (index % 2 === 0 ? 2.4 : -1.7) + (index > 1 ? 1.9 : 0),
        Math.sin(angle) * ring + 1.5,
      )
      return makeIpLayout(entry, pos)
    })
  }

  const nsCount = Math.max(1, state.dns.ns.length)
  const ns: DnsNodeLayout[] = state.dns.ns.map((name, index) => {
    const angle = (index / nsCount) * Math.PI * 2 + Math.PI * 0.1
    return {
      name,
      sub: 'NS',
      pos: v(
        Math.cos(angle) * 18.5,
        CORE_Y + 8.8 + Math.sin(angle * 1.5) * 2.2,
        Math.sin(angle) * 18.5,
      ),
    }
  })

  const mxCount = Math.max(1, state.dns.mx.length)
  const mx: DnsNodeLayout[] = state.dns.mx.map((entry, index) => {
    const angle = (index / mxCount) * Math.PI * 2 + Math.PI * 0.55
    return {
      name: entry.exchange,
      sub: `MX ${entry.priority}`,
      pos: v(
        Math.cos(angle) * 24.5,
        CORE_Y + 2.5 + Math.sin(angle * 1.35) * 6,
        Math.sin(angle) * 24.5,
      ),
    }
  })

  const hops: HopLayout[] = state.hops.map((hop) => {
    const t = Math.min(1, hop.index / 12)
    return {
      hop,
      pos: v(
        THREE.MathUtils.lerp(you.x, 0, Math.min(1, t * 1.15)) +
          Math.sin(hop.index * 1.9) * 3.2 * (1 - t * 0.55),
        CORE_Y + 1.6 + Math.sin(t * Math.PI) * 4.5 + Math.cos(hop.index * 2.1) * 1.1,
        THREE.MathUtils.lerp(you.z, 3.2, t),
      ),
    }
  })

  const hopLine: THREE.Vector3[] = [you, ...hops.map((h) => h.pos), core]

  return { core, you, ips, ns, mx, hops, hopLine, clusters }
}

/** Certificate-transparency names orbit above the core on their own shell. */
export function buildSubdomainLayout(names: string[]): SubdomainLayout[] {
  const count = Math.max(1, names.length)
  const ring = Math.max(19, Math.min(31, 17 + count * 0.28))
  return names.map((name, index) => {
    const angle = (index / count) * Math.PI * 2
    return {
      name,
      pos: v(
        Math.cos(angle) * ring,
        CORE_Y + 15 + Math.sin(index * 1.7) * 2.6,
        Math.sin(angle) * ring,
      ),
    }
  })
}

export function ipLinkPoints(from: THREE.Vector3, to: THREE.Vector3): THREE.Vector3[] {
  const mid = from.clone().lerp(to, 0.5)
  mid.y += 1.7
  return [from, mid, to]
}

export function shortName(value: string, max = 26): string {
  if (value.length <= max) return value
  return value.slice(0, max - 1) + '…'
}
