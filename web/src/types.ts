export type PortState = 'open' | 'closed' | 'filtered'

export interface DnsEntry {
  address: string
  ttl?: number | null
}

export interface MxEntry {
  exchange: string
  priority: number
}

export interface DnsRecords {
  a: DnsEntry[]
  aaaa: DnsEntry[]
  cname: string[]
  ns: string[]
  mx: MxEntry[]
  txt: string[]
  soa: Record<string, unknown> | null
}

export interface GeoInfo {
  country?: string | null
  countryCode?: string | null
  region?: string | null
  city?: string | null
  isp?: string | null
  org?: string | null
  asn?: string | null
  lat?: number | null
  lon?: number | null
  timezone?: string | null
}

export interface PortInfo {
  port: number
  state: PortState
  rtt?: number
  service?: string | null
  banner?: string
  error?: string
}

export interface TlsInfo {
  subject?: string | null
  issuer?: string | null
  validFrom?: string | null
  validTo?: string | null
  altNames?: string[]
  serial?: string | null
  fingerprint?: string | null
  protocol?: string | null
  cipher?: string | null
  alpn?: string | null
}

export interface HttpInfo {
  status?: number
  server?: string | null
  poweredBy?: string | null
  contentType?: string | null
  title?: string | null
  headers?: Record<string, string>
}

export interface IpEntry {
  ip: string
  family: number
  primary: boolean
  ttl?: number | null
  ptr?: string | null
  geo?: GeoInfo | null
  ports: Record<number, PortInfo>
  tls?: (TlsInfo & { port: number }) | null
  http?: (HttpInfo & { port: number }) | null
}

export interface HopInfo {
  index: number
  ip: string | null
  rtt: number | null
  timeout?: boolean
  geo?: GeoInfo | null
}

export interface RdapInfo {
  name?: string | null
  handle?: string | null
  type?: string | null
  country?: string | null
  registrar?: string | null
  org?: string | null
  status?: string[]
  registered?: string | null
  changed?: string | null
  expires?: string | null
  nameservers?: string[]
}

export interface ScanStats {
  open: number
  closed: number
  filtered: number
  scanned: number
  ips: number
  hops: number
  durationMs?: number
  portCount?: number
}

export type Phase = 'idle' | 'scanning' | 'done' | 'error'

export interface LogEntry {
  id: number
  t: number
  level: 'info' | 'ok' | 'open' | 'error'
  message: string
}

export interface ScanState {
  phase: Phase
  target: string
  host: string
  demo: boolean
  dns: DnsRecords
  ips: IpEntry[]
  hops: HopInfo[]
  rdap: RdapInfo | null
  logs: LogEntry[]
  error: string | null
  startedAt: number | null
  stats: ScanStats | null
  portOrder: number[]
}

export const emptyDns = (): DnsRecords => ({
  a: [],
  aaaa: [],
  cname: [],
  ns: [],
  mx: [],
  txt: [],
  soa: null,
})

export const initialState: ScanState = {
  phase: 'idle',
  target: '',
  host: '',
  demo: false,
  dns: emptyDns(),
  ips: [],
  hops: [],
  rdap: null,
  logs: [],
  error: null,
  startedAt: null,
  stats: null,
  portOrder: [],
}

/* ------------------------------------------------------------------ */
/*  selection                                                          */
/* ------------------------------------------------------------------ */

export type Selection =
  | { kind: 'core' }
  | { kind: 'ip'; ip: string }
  | { kind: 'port'; ip: string; port: number }
  | { kind: 'ns'; index: number }
  | { kind: 'mx'; index: number }
  | { kind: 'hop'; index: number }
  | { kind: 'you' }
  | null

export interface SelectionDetails {
  eyebrow: string
  title: string
  subtitle?: string
  color: string
  rows: { label: string; value: string }[]
  notes?: { label: string; value: string }[]
  block?: { title: string; rows: { label: string; value: string }[] }
}

/* ------------------------------------------------------------------ */
/*  raw event protocol                                                 */
/* ------------------------------------------------------------------ */

export type ScanEvent =
  | {
      type: 'meta'
      host: string
      isIp: boolean
      ports: number[]
      traceroute: boolean
      geo: boolean
      startedAt: number
      demo?: boolean
    }
  | { type: 'dns'; records: Partial<DnsRecords> }
  | { type: 'ip'; ip: string; family: number; primary: boolean; ttl?: number | null }
  | { type: 'ptr'; ip: string; ptr: string }
  | { type: 'geo'; ip: string; geo: GeoInfo }
  | { type: 'port'; ip: string; port: number; state: PortState; rtt?: number; service?: string | null; banner?: string; error?: string }
  | { type: 'tls'; ip: string; port: number } & TlsInfo
  | { type: 'http'; ip: string; port: number } & HttpInfo
  | { type: 'hop'; index: number; ip: string | null; rtt: number | null; timeout?: boolean }
  | { type: 'rdap'; rdap: RdapInfo }
  | { type: 'log'; level: LogEntry['level']; message: string }
  | { type: 'fatal'; message: string }
  | { type: 'done'; stats: ScanStats }