import * as THREE from 'three'
import { HopInfo, IpEntry, PortInfo, ScanState } from './types'

export const CORE_Y = 10

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

export interface HopLayout {
  hop: HopInfo
  pos: THREE.Vector3
}

export interface Layout {
  core: THREE.Vector3
  you: THREE.Vector3
  ips: IpLayout[]
  ns: DnsNodeLayout[]
  mx: DnsNodeLayout[]
  hops: HopLayout[]
  hopLine: THREE.Vector3[]
}

const v = (x: number, y: number, z: number) => new THREE.Vector3(x, y, z)

export function buildLayout(state: ScanState): Layout {
  const core = v(0, CORE_Y, 0)
  const you = v(-10.5, CORE_Y + 1.6, 31)

  const count = Math.max(1, state.ips.length)
  const ips: IpLayout[] = state.ips.map((entry, index) => {
    const angle = (index / count) * Math.PI * 2 + Math.PI * 0.22
    const radius = count === 1 ? 10 : 11.8
    const pos = v(
      Math.cos(angle) * radius,
      CORE_Y + (index % 2 === 0 ? 2.4 : -1.7) + (index > 1 ? 1.9 : 0),
      Math.sin(angle) * radius + 1.5,
    )

    const ports: PortNode[] = Object.values(entry.ports).map((info) => {
      const a = (info.port * 2.399963) % (Math.PI * 2)
      const open = info.state === 'open'
      const filtered = info.state === 'filtered'
      const rr = open ? 3.3 : filtered ? 4.4 : 4.0
      return {
        info,
        pos: v(
          pos.x + Math.cos(a) * rr,
          pos.y + Math.sin(a) * rr * 0.66,
          pos.z + Math.sin(a) * rr * 0.52,
        ),
      }
    })

    return {
      entry,
      pos,
      ports,
      open: ports.filter((p) => p.info.state === 'open'),
      closed: ports.filter((p) => p.info.state !== 'open'),
    }
  })

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

  return { core, you, ips, ns, mx, hops, hopLine }
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