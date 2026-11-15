import {
  BasicFinding,
  FindingSeverity,
  HttpInfo,
  IpEntry,
  PortInfo,
  ScanState,
} from './types'

/* ------------------------------------------------------------------ */
/*  passive configuration checks                                       */
/* ------------------------------------------------------------------ */

/**
 * These checks only look at data the scanner already collected: open ports,
 * service banners, HTTP headers and certificate fields. Nothing is exploited
 * and no extra request is sent. Every finding is a reason to look closer.
 */

export const findingLabel: Record<FindingSeverity, string> = {
  critical: 'КРИТИЧНО',
  high: 'ВЫСОКИЙ',
  medium: 'СРЕДНИЙ',
  low: 'НИЗКИЙ',
  info: 'ИНФО',
}

export const findingColor: Record<FindingSeverity, string> = {
  critical: '#ff3b5c',
  high: '#ff7a3d',
  medium: '#ffb020',
  low: '#8b94a8',
  info: '#38f6ff',
}

const ORDER: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

interface PortRule {
  id: string
  title: string
  severity: FindingSeverity
  category: 'exposure'
  summary: string
  recommendation: string
  ports: number[]
}

const PORT_RULES: PortRule[] = [
  {
    id: 'telnet',
    title: 'Telnet открыт в интернет',
    severity: 'high',
    category: 'exposure',
    summary: 'Логин, команды и пароль Telnet передаются открытым текстом — их можно перехватить.',
    recommendation: 'Отключить Telnet и использовать SSH или доступ через VPN.',
    ports: [23],
  },
  {
    id: 'ftp',
    title: 'FTP без шифрования',
    severity: 'medium',
    category: 'exposure',
    summary: 'FTP передаёт логин и пароль открытым текстом. Анонимный доступ тоже возможен.',
    recommendation: 'Перейти на SFTP/FTPS или закрыть порт 21 для интернета.',
    ports: [21],
  },
  {
    id: 'rdp',
    title: 'RDP доступен из интернета',
    severity: 'high',
    category: 'exposure',
    summary: 'Открытый RDP — популярная цель подбора паролей и программ-вымогателей.',
    recommendation: 'Убрать 3389 за VPN, ограничить allowlist и включить MFA.',
    ports: [3389],
  },
  {
    id: 'vnc',
    title: 'VNC доступен из интернета',
    severity: 'high',
    category: 'exposure',
    summary: 'VNC часто работает без пароля или со слабым паролем и даёт полный доступ к экрану.',
    recommendation: 'Закрыть VNC за VPN или туннелем, включить пароль и ограничить адреса.',
    ports: [5900],
  },
  {
    id: 'smb',
    title: 'SMB / NetBIOS открыты',
    severity: 'high',
    category: 'exposure',
    summary: 'Службы Windows-сети не должны быть доступны из интернета: это риск утечки данных и эксплойтов.',
    recommendation: 'Заблокировать 139/445 на периметре, оставить SMB только внутри сети.',
    ports: [139, 445],
  },
  {
    id: 'redis',
    title: 'Redis доступен из интернета',
    severity: 'critical',
    category: 'exposure',
    summary: 'Redis по умолчанию не требует пароля. Открытый порт часто означает чтение и запись данных.',
    recommendation: 'Закрыть 6379, включить requirepass/ACL и bind на localhost или приватную сеть.',
    ports: [6379],
  },
  {
    id: 'mongodb',
    title: 'MongoDB доступна из интернета',
    severity: 'critical',
    category: 'exposure',
    summary: 'MongoDB без аутентификации позволяет читать и менять базы. Проверь, включён ли auth.',
    recommendation: 'Закрыть 27017, включить авторизацию и bind только на приватный интерфейс.',
    ports: [27017],
  },
  {
    id: 'memcached',
    title: 'Memcached доступен из интернета',
    severity: 'critical',
    category: 'exposure',
    summary: 'Memcached не имеет аутентификации, а открытый UDP/TCP-порт используют для amplification-атак.',
    recommendation: 'Закрыть 11211 на периметре и слушать только localhost/приватную сеть.',
    ports: [11211],
  },
  {
    id: 'elasticsearch',
    title: 'Elasticsearch доступен из интернета',
    severity: 'high',
    category: 'exposure',
    summary: 'Кластер может отдавать индексы и API без аутентификации — это утечка данных.',
    recommendation: 'Закрыть 9200/9300, включить security и доступ только из доверенной сети.',
    ports: [9200, 9300],
  },
  {
    id: 'couchdb',
    title: 'CouchDB доступен из интернета',
    severity: 'high',
    category: 'exposure',
    summary: 'CouchDB в режиме admin party не требует пароля и позволяет менять базы.',
    recommendation: 'Закрыть 5984 и настроить администратора и правила доступа.',
    ports: [5984],
  },
  {
    id: 'docker',
    title: 'Docker API открыт',
    severity: 'critical',
    category: 'exposure',
    summary: 'Docker API без TLS/аутентификации фактически даёт root на хосте через запуск контейнера.',
    recommendation: 'Закрыть 2375/2376 на периметре, использовать TLS-сертификаты и VPN.',
    ports: [2375, 2376],
  },
  {
    id: 'kubernetes',
    title: 'Kubernetes API доступен',
    severity: 'high',
    category: 'exposure',
    summary: 'API-сервер Kubernetes на периметре требует строгой аутентификации и авторизации.',
    recommendation: 'Ограничить 6443 по IP, включить RBAC и аудит, не публиковать API без необходимости.',
    ports: [6443],
  },
  {
    id: 'ldap',
    title: 'LDAP открыт в интернет',
    severity: 'medium',
    category: 'exposure',
    summary: 'LDAP может раскрывать структуру каталога и использоваться для перечисления пользователей.',
    recommendation: 'Закрыть 389 на периметре, использовать LDAPS внутри сети.',
    ports: [389],
  },
  {
    id: 'nfs',
    title: 'NFS открыт в интернет',
    severity: 'high',
    category: 'exposure',
    summary: 'NFS часто экспортирует каталоги без сильной аутентификации и раскрывает файловую систему.',
    recommendation: 'Закрыть 2049 на периметре и ограничить экспорт доверенными хостами.',
    ports: [2049],
  },
  {
    id: 'rsync',
    title: 'Rsync открыт в интернет',
    severity: 'high',
    category: 'exposure',
    summary: 'Rsync-модули могут быть доступны без пароля и отдавать файлы.',
    recommendation: 'Закрыть 873, использовать SSH-туннель и ограничить модули.',
    ports: [873],
  },
  {
    id: 'socks',
    title: 'SOCKS-прокси открыт',
    severity: 'high',
    category: 'exposure',
    summary: 'Открытый SOCKS-прокси позволяет использовать сервер как точку выхода для чужого трафика.',
    recommendation: 'Закрыть 1080 или включить аутентификацию и allowlist.',
    ports: [1080],
  },
  {
    id: 'adb',
    title: 'ADB доступен из интернета',
    severity: 'critical',
    category: 'exposure',
    summary: 'Android Debug Bridge без авторизации даёт установку приложений и доступ к устройству.',
    recommendation: 'Отключить отладку по сети, закрыть 5555 и использовать USB/ADB over VPN.',
    ports: [5555],
  },
  {
    id: 'webmin',
    title: 'Webmin открыт в интернет',
    severity: 'medium',
    category: 'exposure',
    summary: 'Панель администрирования Webmin — чувствительная цель для подбора пароля.',
    recommendation: 'Ограничить 10000 по IP или убрать за VPN, включить MFA.',
    ports: [10000],
  },
  {
    id: 'mqtt',
    title: 'MQTT-брокер доступен',
    severity: 'medium',
    category: 'exposure',
    summary: 'MQTT часто принимает подключения без аутентификации и раскрывает телеметрию устройств.',
    recommendation: 'Закрыть 1883 на периметре, включить TLS и логин/пароль.',
    ports: [1883],
  },
  {
    id: 'amqp',
    title: 'AMQP-брокер доступен',
    severity: 'medium',
    category: 'exposure',
    summary: 'RabbitMQ/AMQP на периметре может отдавать очереди и управление без ограничений.',
    recommendation: 'Закрыть 5672, использовать TLS и отдельные учётные записи.',
    ports: [5672],
  },
  {
    id: 'database',
    title: 'База данных доступна из интернета',
    severity: 'medium',
    category: 'exposure',
    summary: 'Порт СУБД открыт на периметре: возможны подбор паролей и эксплуатация уязвимостей.',
    recommendation: 'Закрыть порт для интернета, оставить доступ из приватной сети или через VPN.',
    ports: [1433, 1521, 3306, 5432],
  },
  {
    id: 'metasploit',
    title: 'Необычный порт 4444 открыт',
    severity: 'medium',
    category: 'exposure',
    summary: 'Порт 4444 часто используют reverse-shell и Metasploit. Открытый порт стоит проверить.',
    recommendation: 'Выяснить процесс на порту и закрыть его, если это не согласованный сервис.',
    ports: [4444],
  },
]

const TLS_PORT_NUMBERS = new Set([443, 465, 636, 993, 995, 8443, 9443, 2376, 6443])
const WEAK_CIPHER = /(rc4|3des|des(?!-ede)|export|null|anon|md5)/i

function parseCertDate(value?: string | null): number {
  if (!value) return NaN
  const raw = value.trim()
  const normalised = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?$/.test(raw)
    ? `${raw.replace(' ', 'T')}Z`
    : raw
  return Date.parse(normalised)
}

function isIpAddress(value: string): boolean {
  return /^[0-9.]+$/.test(value) || value.includes(':')
}

function certMatchesHost(host: string, altNames: string[]): boolean {
  const target = host.toLowerCase().replace(/\.$/, '')
  return altNames.some((raw) => {
    const name = raw.toLowerCase().replace(/\.$/, '')
    if (!name) return false
    if (name === target) return true
    if (name.startsWith('*.')) {
      const suffix = name.slice(2)
      const dot = target.indexOf('.')
      return dot > 0 && target.slice(dot + 1) === suffix
    }
    return false
  })
}

function httpEntries(ip: IpEntry): (HttpInfo & { port: number })[] {
  if (ip.httpAll?.length) return ip.httpAll
  return ip.http ? [ip.http] : []
}

function serviceFindings(ip: IpEntry): BasicFinding[] {
  const found: BasicFinding[] = []
  for (const port of Object.values(ip.ports)) {
    if (port.state !== 'open') continue
    for (const rule of PORT_RULES) {
      if (!rule.ports.includes(port.port)) continue
      found.push({
        id: rule.id,
        title: rule.title,
        severity: rule.severity,
        category: rule.category,
        summary: rule.summary,
        recommendation: rule.recommendation,
        evidence: `${port.port}/${port.protocol}${port.service ? ` · ${port.service}` : ''}`,
        ip: ip.ip,
        port: port.port,
        protocol: port.protocol,
      })
    }
  }
  return found
}

function tlsFindings(ip: IpEntry, host: string): BasicFinding[] {
  const tls = ip.tls
  if (!tls) return []
  const found: BasicFinding[] = []
  const expiry = parseCertDate(tls.validTo)
  if (Number.isFinite(expiry)) {
    const days = Math.ceil((expiry - Date.now()) / 86_400_000)
    if (days <= 0) {
      found.push({
        id: 'tls-expired',
        title: 'TLS-сертификат истёк',
        severity: 'high',
        category: 'tls',
        summary: `Срок действия сертификата закончился ${days === 0 ? 'сегодня' : `${Math.abs(days)} дн. назад`}. Браузеры показывают предупреждение.`,
        recommendation: 'Выпустить новый сертификат и настроить автоматическое продление.',
        evidence: `validTo ${tls.validTo}`,
        ip: ip.ip,
        port: tls.port,
        protocol: 'tcp',
      })
    } else if (days <= 14) {
      found.push({
        id: 'tls-expiring',
        title: 'TLS-сертификат скоро истекает',
        severity: 'medium',
        category: 'tls',
        summary: `До окончания срока действия осталось ${days} дн. Продление может быть пропущено.`,
        recommendation: 'Проверить автообновление сертификата до истечения срока.',
        evidence: `validTo ${tls.validTo}`,
        ip: ip.ip,
        port: tls.port,
        protocol: 'tcp',
      })
    }
  }

  if (/^TLSv1(\.0|\.1)?$/i.test(String(tls.protocol || ''))) {
    found.push({
      id: 'tls-weak-protocol',
      title: 'Устаревшая версия TLS',
      severity: 'medium',
      category: 'tls',
      summary: `Сервер согласовал ${tls.protocol}. TLS 1.0/1.1 не соответствуют современным требованиям.`,
      recommendation: 'Отключить TLS 1.0/1.1 и оставить TLS 1.2+.',
      evidence: `${tls.protocol}${tls.cipher ? ` · ${tls.cipher}` : ''}`,
      ip: ip.ip,
      port: tls.port,
      protocol: 'tcp',
    })
  }

  if (tls.cipher && WEAK_CIPHER.test(tls.cipher)) {
    found.push({
      id: 'tls-weak-cipher',
      title: 'Слабый TLS-шифр',
      severity: 'high',
      category: 'tls',
      summary: `Сервер выбрал ${tls.cipher}. Такие шифры считаются устаревшими или небезопасными.`,
      recommendation: 'Настроить современный cipher suite и отключить RC4/3DES/NULL/EXPORT.',
      evidence: tls.cipher,
      ip: ip.ip,
      port: tls.port,
      protocol: 'tcp',
    })
  }

  if (tls.issuer && tls.subject && tls.issuer === tls.subject) {
    found.push({
      id: 'tls-self-signed',
      title: 'Похоже на самоподписанный сертификат',
      severity: 'low',
      category: 'tls',
      summary: 'Издатель и субъект сертификата совпадают. Клиенты не могут проверить цепочку доверия.',
      recommendation: 'Использовать сертификат публичного или внутреннего доверенного УЦ.',
      evidence: tls.issuer,
      ip: ip.ip,
      port: tls.port,
      protocol: 'tcp',
    })
  }

  if (!isIpAddress(host) && tls.altNames?.length && !certMatchesHost(host, tls.altNames)) {
    found.push({
      id: 'tls-hostname',
      title: 'Сертификат не совпадает с именем хоста',
      severity: 'medium',
      category: 'tls',
      summary: `В SAN сертификата нет ${host}. Браузер может считать соединение недоверенным.`,
      recommendation: 'Выпустить сертификат на используемые имена или обновить SAN.',
      evidence: tls.altNames.slice(0, 4).join(', '),
      ip: ip.ip,
      port: tls.port,
      protocol: 'tcp',
    })
  }

  return found
}

function headerFindings(ip: IpEntry): BasicFinding[] {
  const entries = httpEntries(ip)
  if (!entries.length) return []
  const preferred =
    entries.find((entry) => entry.port === 443) ||
    entries.find((entry) => entry.port === ip.tls?.port) ||
    entries.slice().sort((a, b) => a.port - b.port)[0]
  const headers = preferred.headers || {}
  const https = preferred.port === 443 || TLS_PORT_NUMBERS.has(preferred.port)
  const csp = String(headers['content-security-policy'] || '')
  const missing: string[] = []
  if (https && !headers['strict-transport-security']) missing.push('HSTS')
  if (!csp) missing.push('CSP')
  if (!headers['x-frame-options'] && !/frame-ancestors/i.test(csp)) missing.push('X-Frame-Options')
  if (!headers['x-content-type-options']) missing.push('X-Content-Type-Options')
  if (!headers['referrer-policy']) missing.push('Referrer-Policy')
  if (!missing.length) return []

  const checks = https ? 5 : 4
  const severity: FindingSeverity = missing.length >= 4 ? 'medium' : 'low'
  return [
    {
      id: 'http-headers',
      title: `Не настроены заголовки безопасности (${missing.length}/${checks})`,
      severity,
      category: 'http',
      summary: `На порту ${preferred.port} отсутствуют: ${missing.join(', ')}. Это упрощает clickjacking, MIME-sniffing и утечку referrer.`,
      recommendation: https
        ? 'Добавить HSTS, CSP, X-Frame-Options, X-Content-Type-Options и Referrer-Policy на веб-сервере или прокси.'
        : 'Добавить CSP, X-Frame-Options, X-Content-Type-Options и Referrer-Policy; HSTS — после перехода на HTTPS.',
      evidence: `:${preferred.port} · ${missing.join(', ')}`,
      ip: ip.ip,
      port: preferred.port,
      protocol: 'tcp',
    },
  ]
}

function plaintextHttpFinding(ip: IpEntry): BasicFinding[] {
  const open = Object.values(ip.ports).filter((port) => port.state === 'open')
  const http = open.find((port) => port.port === 80 && port.protocol === 'tcp')
  if (!http) return []
  const tlsPort = open.some(
    (port) => port.protocol === 'tcp' && (TLS_PORT_NUMBERS.has(port.port) || port.port === ip.tls?.port),
  )
  if (tlsPort) return []
  return [
    {
      id: 'http-plaintext',
      title: 'HTTP без HTTPS',
      severity: 'medium',
      category: 'http',
      summary: 'Веб-сервер отвечает по HTTP, а TLS-порт не найден. Логины, cookie и данные могут идти открытым текстом.',
      recommendation: 'Включить HTTPS, перенаправлять HTTP на HTTPS и использовать HSTS.',
      evidence: '80/tcp',
      ip: ip.ip,
      port: 80,
      protocol: 'tcp',
    },
  ]
}

function udpFindings(ip: IpEntry): BasicFinding[] {
  const found: BasicFinding[] = []
  for (const port of Object.values(ip.ports)) {
    if (port.state !== 'open' || port.protocol !== 'udp') continue
    if (port.port === 53) {
      found.push({
        id: 'udp-dns',
        title: 'DNS отвечает из интернета',
        severity: 'low',
        category: 'udp',
        summary: 'Сервер ответил на DNS-запрос. Если это не авторитативный сервер, возможен open resolver и DNS-amplification.',
        recommendation: 'Ограничить рекурсию и rate-limit либо закрыть 53/udp на периметре.',
        evidence: port.banner || '53/udp',
        ip: ip.ip,
        port: 53,
        protocol: 'udp',
      })
    } else if (port.port === 161) {
      found.push({
        id: 'udp-snmp-public',
        title: 'SNMP отвечает на community public',
        severity: 'high',
        category: 'udp',
        summary: 'SNMPv1/v2c с community public раскрывает системную информацию, интерфейсы и конфигурацию.',
        recommendation: 'Отключить SNMPv1/v2c, использовать SNMPv3 с аутентификацией или закрыть 161/udp.',
        evidence: port.banner || '161/udp',
        ip: ip.ip,
        port: 161,
        protocol: 'udp',
      })
    } else if (port.port === 5353) {
      found.push({
        id: 'udp-mdns',
        title: 'mDNS доступен из интернета',
        severity: 'low',
        category: 'udp',
        summary: 'mDNS-ответ раскрывает имена и сервисы локальной сети; на периметре он обычно не нужен.',
        recommendation: 'Заблокировать 5353/udp на внешнем интерфейсе.',
        evidence: port.banner || '5353/udp',
        ip: ip.ip,
        port: 5353,
        protocol: 'udp',
      })
    } else if (port.port === 1900) {
      found.push({
        id: 'udp-ssdp',
        title: 'SSDP отвечает из интернета',
        severity: 'low',
        category: 'udp',
        summary: 'SSDP-ответ раскрывает UPnP-устройства и может использоваться для amplification.',
        recommendation: 'Заблокировать 1900/udp на периметре и отключить UPnP на внешнем интерфейсе.',
        evidence: port.banner || '1900/udp',
        ip: ip.ip,
        port: 1900,
        protocol: 'udp',
      })
    } else if (port.port === 123) {
      found.push({
        id: 'udp-ntp',
        title: 'NTP доступен из интернета',
        severity: 'low',
        category: 'udp',
        summary: 'Открытый NTP может участвовать в amplification-атаках и раскрывать состояние сервера.',
        recommendation: 'Ограничить 123/udp доверенными сетями или включить rate-limit.',
        evidence: port.banner || '123/udp',
        ip: ip.ip,
        port: 123,
        protocol: 'udp',
      })
    }
  }
  return found
}

function sortFindings(items: BasicFinding[]): BasicFinding[] {
  return items
    .slice()
    .sort(
      (a, b) =>
        ORDER[a.severity] - ORDER[b.severity] ||
        (a.port ?? 0) - (b.port ?? 0) ||
        a.id.localeCompare(b.id),
    )
}

export function findingsForIp(ip: IpEntry, host = ''): BasicFinding[] {
  return sortFindings([
    ...serviceFindings(ip),
    ...tlsFindings(ip, host),
    ...headerFindings(ip),
    ...plaintextHttpFinding(ip),
    ...udpFindings(ip),
  ])
}

export function findingsForPort(ip: IpEntry, port: PortInfo, host = ''): BasicFinding[] {
  return findingsForIp(ip, host).filter(
    (finding) =>
      finding.port === undefined ||
      (finding.port === port.port &&
        (!finding.protocol || finding.protocol === port.protocol)),
  )
}

export function collectFindings(state: ScanState): BasicFinding[] {
  return sortFindings(
    state.ips.flatMap((ip) => findingsForIp(ip, state.host || state.target || '')),
  )
}

export function findingsForNode(findings: BasicFinding[], ip: string): BasicFinding[] {
  return findings.filter((finding) => finding.ip === ip)
}
