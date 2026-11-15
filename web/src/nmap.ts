import { Protocol, ScanEvent, PortState } from './types'

/* Nmap / Masscan XML → the same event stream the live scanner produces. */

const MAX_HOSTS = 512
const MAX_PORTS = 20_000

export interface NmapImport {
  target: string
  events: ScanEvent[]
  hosts: number
  ports: number
  udpPorts: number
  scanner: string
}

const attr = (element: Element | null | undefined, name: string): string =>
  element?.getAttribute(name)?.trim() || ''

const child = (element: Element, tag: string): Element | null =>
  Array.from(element.children).find((item) => item.tagName === tag) || null

const children = (element: Element, tag: string): Element[] =>
  Array.from(element.children).filter((item) => item.tagName === tag)

const clean = (value: string, limit = 160): string =>
  value.replace(/\s+/g, ' ').trim().slice(0, limit)

/** Russian plural: 1 хост / 2 хоста / 5 хостов. */
export function plural(count: number, forms: [string, string, string]): string {
  const abs = Math.abs(count) % 100
  const tail = abs % 10
  if (abs > 10 && abs < 20) return `${count} ${forms[2]}`
  if (tail === 1) return `${count} ${forms[0]}`
  if (tail >= 2 && tail <= 4) return `${count} ${forms[1]}`
  return `${count} ${forms[2]}`
}

const mapState = (value: string): PortState => {
  if (value === 'open') return 'open'
  if (value === 'closed' || value === 'reset') return 'closed'
  return 'filtered'
}

function scriptOutputs(scope: Element): Map<string, Element> {
  const found = new Map<string, Element>()
  for (const script of Array.from(scope.getElementsByTagName('script'))) {
    const id = attr(script, 'id')
    if (id && !found.has(id)) found.set(id, script)
  }
  return found
}

function parseHttpHeaders(output: string): { status?: number; headers: Record<string, string> } {
  const headers: Record<string, string> = {}
  let status: number | undefined
  for (const line of output.split(/\r?\n/)) {
    const statusMatch = line.match(/^HTTP\/[\d.]+\s+(\d{3})/)
    if (statusMatch) {
      status = Number(statusMatch[1])
      continue
    }
    const header = line.match(/^([A-Za-z0-9-]+):\s*(.+)$/)
    if (header) headers[header[1].toLowerCase()] = header[2].trim()
  }
  return { status, headers }
}

function tableText(script: Element, key: string): string {
  const table = Array.from(script.getElementsByTagName('table')).find(
    (item) => attr(item, 'key') === key,
  )
  if (!table) return ''
  return Array.from(table.getElementsByTagName('elem'))
    .map((item) => item.textContent?.trim() || '')
    .filter(Boolean)
    .join(', ')
}

function certInfo(script: Element) {
  const elems = Array.from(script.getElementsByTagName('elem'))
  const get = (key: string) =>
    elems.find((item) => attr(item, 'key') === key)?.textContent?.trim() || undefined

  const altNames = elems
    .map((item) => item.textContent?.trim() || '')
    .filter((value) => value.startsWith('DNS:'))
    .flatMap((value) => value.replace(/^DNS:/, '').split(','))
    .map((value) => value.trim())
    .filter(Boolean)

  return {
    subject: tableText(script, 'subject') || get('subject'),
    issuer: tableText(script, 'issuer') || get('issuer'),
    validFrom: get('notBefore') || get('validFrom'),
    validTo: get('notAfter') || get('validTo'),
    altNames: altNames.length ? altNames.slice(0, 40) : undefined,
  }
}

export function parseNmapXml(xml: string): NmapImport {
  const doc = new DOMParser().parseFromString(xml, 'application/xml')
  if (doc.querySelector('parsererror')) {
    throw new Error('Не удалось разобрать XML. Проверь, что это отчёт Nmap или Masscan.')
  }

  const root = doc.documentElement
  if (!root || root.tagName !== 'nmaprun') {
    throw new Error(`Это не отчёт Nmap/Masscan: корневой тег <${root?.tagName || '?'}>.`)
  }

  const hostElements = children(root, 'host')
  if (!hostElements.length) {
    throw new Error('В файле нет ни одного <host>. Похоже, скан не нашёл целей.')
  }
  if (hostElements.length > MAX_HOSTS) {
    throw new Error(
      `Слишком много хостов: ${hostElements.length}. Максимум ${MAX_HOSTS} — отфильтруй отчёт.`,
    )
  }

  const events: ScanEvent[] = []
  const startedAt = Date.now()
  const portSet = new Set<number>()
  let hostCount = 0
  let portCount = 0
  let udpPorts = 0
  let firstTarget = ''

  events.push({
    type: 'log',
    level: 'info',
    message: `ИМПОРТ ${attr(root, 'scanner') || 'NMAP'}: ${plural(
      hostElements.length,
      ['хост', 'хоста', 'хостов'],
    )} в файле`,
  })

  const pushPort = (event: Extract<ScanEvent, { type: 'port' }>) => {
    portCount += 1
    if (portCount > MAX_PORTS) {
      throw new Error(
        `Слишком много портов: больше ${MAX_PORTS}. Отфильтруй отчёт, иначе карта зависнет.`,
      )
    }
    portSet.add(event.port)
    events.push(event)
  }

  for (const host of hostElements) {
    const status = child(host, 'status')
    if (attr(status, 'state') === 'down') continue

    const addresses = children(host, 'address').filter((item) => {
      const type = attr(item, 'addrtype')
      return type === 'ipv4' || type === 'ipv6'
    })
    if (!addresses.length) continue

    const hostnameElement = host
      .getElementsByTagName('hostname')
      .item(0) as Element | null
    const hostname = attr(hostnameElement, 'name')

    hostCount += 1
    const primary = hostCount === 1
    const primaryIp = attr(addresses[0], 'addr')
    if (!firstTarget) firstTarget = hostname || primaryIp

    addresses.forEach((address, index) => {
      const ip = attr(address, 'addr')
      if (!ip) return
      events.push({
        type: 'ip',
        ip,
        family: attr(address, 'addrtype') === 'ipv6' ? 6 : 4,
        primary: primary && index === 0,
      })
      if (hostname) events.push({ type: 'ptr', ip, ptr: hostname })
    })

    const portsElement = child(host, 'ports')
    if (portsElement) {
      for (const extra of children(portsElement, 'extraports')) {
        const count = Number(attr(extra, 'count')) || 0
        if (count > 0) {
          events.push({
            type: 'log',
            level: 'info',
            message: `${primaryIp}: ${plural(count, ['порт', 'порта', 'портов'])} в состоянии «${attr(extra, 'state')}» (сгруппировано Nmap)`,          })
        }
      }

      for (const portElement of children(portsElement, 'port')) {
        const protocol: Protocol = attr(portElement, 'protocol') === 'udp' ? 'udp' : 'tcp'
        const port = Number(attr(portElement, 'portid'))
        if (!Number.isFinite(port) || port <= 0 || port > 65535) continue
        if (protocol === 'udp') udpPorts += 1

        const stateElement = child(portElement, 'state')
        const state = mapState(attr(stateElement, 'state'))
        const serviceElement = child(portElement, 'service')
        const serviceName = attr(serviceElement, 'name')
        const product = attr(serviceElement, 'product')
        const version = attr(serviceElement, 'version')
        const extraInfo = attr(serviceElement, 'extrainfo')
        const cpe = Array.from(serviceElement?.getElementsByTagName('cpe') || [])
          .map((item) => item.textContent?.trim() || '')
          .filter(Boolean)
          .join(' ')

        const service = clean(
          [serviceName, product, version].filter(Boolean).join(' · ') ||
            (state === 'open' ? 'unknown' : ''),
          120,
        )
        const banner = clean([product, version, extraInfo, cpe].filter(Boolean).join(' '), 220)

        pushPort({
          type: 'port',
          ip: primaryIp,
          port,
          protocol,
          state,
          service: service || null,
          banner: banner || undefined,
        })

        if (protocol === 'tcp') {
          const scripts = scriptOutputs(portElement)
          const title = scripts.get('http-title')
          const headersScript = scripts.get('http-headers')
          const headers = headersScript ? parseHttpHeaders(attr(headersScript, 'output')) : null

          if (title || headers) {
            events.push({
              type: 'http',
              ip: primaryIp,
              port,
              status: headers?.status,
              server: headers?.headers.server || product || undefined,
              poweredBy: headers?.headers['x-powered-by'] || undefined,
              contentType: headers?.headers['content-type'] || undefined,
              title: title ? clean(attr(title, 'output'), 200) : undefined,
              headers: headers?.headers,
            })
          }

          const cert = scripts.get('ssl-cert')
          if (cert) {
            const info = certInfo(cert)
            const cipherScript = scripts.get('ssl-enum-ciphers')
            const protocolTable = cipherScript
              ? Array.from(cipherScript.getElementsByTagName('table')).find((item) =>
                  /^TLSv/.test(attr(item, 'key')),
                )
              : null
            if (info.subject || info.issuer || info.validTo) {
              events.push({
                type: 'tls',
                ip: primaryIp,
                port,
                subject: info.subject,
                issuer: info.issuer,
                validFrom: info.validFrom,
                validTo: info.validTo,
                altNames: info.altNames,
                protocol: protocolTable ? attr(protocolTable, 'key') : undefined,
              })
            }
          }
        }
      }
    }
  }

  if (!hostCount) throw new Error('В файле нет хостов в состоянии up.')

  const target = firstTarget || 'nmap-import'
  events.unshift({
    type: 'meta',
    host: target,
    isIp: /^[0-9.]+$/.test(target) || target.includes(':'),
    ports: [...portSet].sort((a, b) => a - b),
    traceroute: false,
    geo: false,
    startedAt,
  })

  if (udpPorts) {
    events.push({
      type: 'log',
      level: 'info',
      message: `Импортировано ${plural(udpPorts, ['UDP-порт', 'UDP-порта', 'UDP-портов'])} — на карте они отмечены янтарным.`,
    })
  }
  const open = events.filter((event) => event.type === 'port' && event.state === 'open').length
  const closed = events.filter((event) => event.type === 'port' && event.state === 'closed').length
  const filtered = events.filter(
    (event) => event.type === 'port' && event.state === 'filtered',
  ).length

  events.push({
    type: 'log',
    level: 'ok',
    message: `ИМПОРТ ЗАВЕРШЁН: ${plural(hostCount, ['хост', 'хоста', 'хостов'])} · ${plural(
      portCount,
      ['порт', 'порта', 'портов'],
    )} · ${open} открыто`,
  })
  events.push({
    type: 'done',
    stats: {
      open,
      closed,
      filtered,
      scanned: portCount,
      ips: hostCount,
      hops: 0,
      udp: udpPorts,
      durationMs: 0,
      portCount: portSet.size,
    },
  })

  return {
    target,
    events,
    hosts: hostCount,
    ports: portCount,
    udpPorts,
    scanner: attr(root, 'scanner') || 'nmap',
  }
}
