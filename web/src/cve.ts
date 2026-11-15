import { HttpInfo, IpEntry, PortInfo, Protocol, ScanState } from './types'

/* ------------------------------------------------------------------ */
/*  local CVE heuristics                                               */
/* ------------------------------------------------------------------ */

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface CveHit {
  id: string
  product: string
  version: string
  severity: Severity
  summary: string
  fixed?: string
  caveat?: string
  evidence: string
}

export interface CveMatch extends CveHit {
  ip: string
  port: number
  protocol: Protocol
}

interface Rule {
  id: string
  product: string
  pattern: RegExp
  min?: string
  max?: string
  test?: (version: string) => boolean
  severity: Severity
  summary: string
  fixed?: string
  caveat?: string
}

/**
 * Deliberately small and conservative. Every rule is a publicly known CVE with
 * a version range that can be read from a banner; anything ambiguous is left
 * out. This is a hint, not an authoritative vulnerability assessment.
 */
const RULES: Rule[] = [
  {
    id: 'CVE-2024-6387',
    product: 'OpenSSH',
    pattern: /openssh[_/ -]?v?(\d+(?:\.\d+)*p?\d*)/i,
    min: '8.5',
    max: '9.8',
    severity: 'critical',
    summary: 'regreSSHion: удалённое выполнение кода в sshd через гонку в обработчике SIGALRM (glibc).',
    fixed: '9.8p1',
    caveat: 'Проявляется не на всех сборках: нужен glibc и подходящий тайминг.',
  },
  {
    id: 'CVE-2018-15473',
    product: 'OpenSSH',
    pattern: /openssh[_/ -]?v?(\d+(?:\.\d+)*p?\d*)/i,
    max: '7.7',
    severity: 'medium',
    summary: 'Перечисление пользователей через разницу во времени ответа при аутентификации.',
    fixed: '7.7',
  },
  {
    id: 'CVE-2021-23017',
    product: 'nginx',
    pattern: /nginx[/ -]?v?(\d+(?:\.\d+)*)/i,
    min: '0.6.18',
    max: '1.20.1',
    severity: 'high',
    summary: 'Переполнение в resolver: 1-байтовая запись за границу буфера при разборе DNS-ответа.',
    fixed: '1.20.1 / 1.21.0',
    caveat: 'Нужна директива resolver и обработка ответа от DNS-сервера.',
  },
  {
    id: 'CVE-2022-41741',
    product: 'nginx',
    pattern: /nginx[/ -]?v?(\d+(?:\.\d+)*)/i,
    min: '1.0.7',
    max: '1.23.2',
    severity: 'medium',
    summary: 'Повреждение памяти в ngx_http_mp4_module при обработке специально собранного mp4.',
    fixed: '1.23.2 / 1.22.1',
    caveat: 'Только если включён модуль mp4.',
  },
  {
    id: 'CVE-2021-41773',
    product: 'Apache httpd',
    pattern: /apache(?: httpd)?[/ ]v?(\d+(?:\.\d+)*)/i,
    min: '2.4.49',
    max: '2.4.51',
    severity: 'critical',
    summary: 'Path traversal и RCE: обход нормализации пути в mod_alias через encoded dot-dot.',
    fixed: '2.4.51',
    caveat: 'Эксплуатируется при включённом mod_cgi; в 2.4.50 закрыт частично.',
  },
  {
    id: 'CVE-2011-2523',
    product: 'vsftpd',
    pattern: /vsftpd[ /]v?(\d+(?:\.\d+)*)/i,
    min: '2.3.4',
    max: '2.3.5',
    severity: 'critical',
    summary: 'Бэкдор в vsftpd 2.3.4: строка «:)» в логине открывает shell на порту 6200.',
    fixed: '2.3.5',
  },
  {
    id: 'CVE-2015-3306',
    product: 'ProFTPD',
    pattern: /proftpd[ /]v?(\d+(?:\.\d+)*)/i,
    min: '1.3.5',
    max: '1.3.6',
    severity: 'critical',
    summary: 'mod_copy позволяет копировать файлы без аутентификации и выполнить код.',
    fixed: '1.3.6',
    caveat: 'Нужен загруженный модуль mod_copy.',
  },
  {
    id: 'CVE-2019-10149',
    product: 'Exim',
    pattern: /exim[ /]v?(\d+(?:\.\d+)*)/i,
    min: '4.87',
    max: '4.92',
    severity: 'critical',
    summary: '«Return of the WIZard»: RCE через специальный адрес получателя в Exim.',
    fixed: '4.92',
  },
  {
    id: 'CVE-2007-2447',
    product: 'Samba',
    pattern: /samba[ /]v?(\d+(?:\.\d+)*)/i,
    min: '3.0.0',
    max: '3.0.21',
    severity: 'critical',
    summary: 'Передача метасимволов shell в username map script — удалённое выполнение команд.',
    fixed: '3.0.21',
  },
  {
    id: 'CVE-2021-43798',
    product: 'Grafana',
    pattern: /grafana[ /]v?(\d+(?:\.\d+)*)/i,
    min: '8.0.0',
    max: '8.3.1',
    severity: 'high',
    summary: 'Path traversal в плагинах: чтение произвольных файлов без аутентификации.',
    fixed: '8.3.1 / 8.2.7 / 8.1.8 / 8.0.7',
  },
  {
    id: 'CVE-2015-1427',
    product: 'Elasticsearch',
    pattern: /elasticsearch[ /]v?(\d+(?:\.\d+)*)/i,
    min: '1.4.0',
    max: '1.4.5',
    severity: 'critical',
    summary: 'Groovy sandbox escape: удалённое выполнение команд через search API.',
    fixed: '1.4.5',
  },
  {
    id: 'CVE-2019-11043',
    product: 'PHP-FPM',
    pattern: /php[/ ]v?(\d+\.\d+\.\d+)/i,
    test: (version) => {
      const [major, minor, patch] = versionNumbers(version)
      if (major !== 7 || patch === undefined) return false
      if (minor === 1) return patch < 33
      if (minor === 2) return patch < 24
      if (minor === 3) return patch < 11
      return false
    },
    severity: 'critical',
    summary: 'Переполнение в FPM при определённой конфигурации nginx — RCE через PATH_INFO.',
    fixed: '7.3.11',
    caveat: 'Требует связки nginx + php-fpm с небезопасным fastcgi_split_path_info.',
  },
  {
    id: 'CVE-2014-0160',
    product: 'OpenSSL',
    pattern: /openssl[ /]v?(1\.0\.1[a-f]?)/i,
    test: (version) => {
      const suffix = version.replace('1.0.1', '') || ''
      return suffix === '' || suffix <= 'f'
    },
    severity: 'high',
    summary: 'Heartbleed: чтение памяти процесса через расширение heartbeat в TLS.',
    fixed: '1.0.1g',
  },
]

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 }

export const severityLabel: Record<Severity, string> = {
  critical: 'КРИТИЧНО',
  high: 'ВЫСОКИЙ',
  medium: 'СРЕДНИЙ',
  low: 'НИЗКИЙ',
}

export const severityColor: Record<Severity, string> = {
  critical: '#ff3b5c',
  high: '#ff7a3d',
  medium: '#ffb020',
  low: '#8b94a8',
}

function versionNumbers(value: string): number[] {
  return (value.match(/\d+/g) || []).map((part) => Number(part))
}

/** Compare dotted versions with an optional OpenSSH-style "pN" patch level. */
export function compareVersions(left: string, right: string): number {
  const a = versionNumbers(left)
  const b = versionNumbers(right)
  const length = Math.max(a.length, b.length)
  for (let i = 0; i < length; i++) {
    const delta = (a[i] ?? 0) - (b[i] ?? 0)
    if (delta !== 0) return delta > 0 ? 1 : -1
  }
  return 0
}

function inRange(version: string, min?: string, max?: string): boolean {
  if (min && compareVersions(version, min) < 0) return false
  if (max && compareVersions(version, max) >= 0) return false
  return true
}

function portHttp(ip: IpEntry, port: PortInfo): HttpInfo[] {
  if (ip.httpAll?.length) return ip.httpAll.filter((entry) => entry.port === port.port)
  return ip.http?.port === port.port ? [ip.http] : []
}

/** All heuristic hits for one open port. */
export function matchCvesForPort(ip: IpEntry, port: PortInfo): CveHit[] {
  if (port.state !== 'open') return []
  const http = portHttp(ip, port)
  const text = [
    port.service,
    port.banner,
    ...http.flatMap((entry) => [
      entry.server,
      entry.poweredBy,
      entry.contentType,
      ...Object.entries(entry.headers || {}).flat(),
    ]),
  ]
    .filter(Boolean)
    .join(' \n ')
  if (!text) return []

  const hits: CveHit[] = []
  const seen = new Set<string>()
  for (const rule of RULES) {
    const match = rule.pattern.exec(text)
    if (!match) continue
    const version = match[1]
    if (rule.test) {
      if (!rule.test(version)) continue
    } else if (!inRange(version, rule.min, rule.max)) {
      continue
    }
    if (seen.has(rule.id)) continue
    seen.add(rule.id)
    hits.push({
      id: rule.id,
      product: rule.product,
      version,
      severity: rule.severity,
      summary: rule.summary,
      fixed: rule.fixed,
      caveat: rule.caveat,
      evidence: match[0].trim().slice(0, 90),
    })
  }
  return hits.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
}

/** Flat list of CVE hints across all nodes, used by the map, HUD and reports. */
export function collectCves(state: ScanState): CveMatch[] {
  const matches: CveMatch[] = []
  for (const ip of state.ips) {
    for (const port of Object.values(ip.ports)) {
      for (const hit of matchCvesForPort(ip, port)) {
        matches.push({
          ...hit,
          ip: ip.ip,
          port: port.port,
          protocol: port.protocol,
        })
      }
    }
  }
  return matches.sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.port - b.port,
  )
}

export function cveKey(ip: string, port: number, protocol: Protocol): string {
  return `${ip}|${protocol}|${port}`
}

export function cvePortSet(matches: CveMatch[]): Set<string> {
  return new Set(matches.map((match) => cveKey(match.ip, match.port, match.protocol)))
}
