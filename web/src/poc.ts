import { BasicFinding, SelectionCve } from './types'

/**
 * Safe PoC builder.
 *
 * Commands only retrieve banners, headers and version information. No exploit
 * payloads are generated: the goal is to let an operator confirm what the scan
 * already suspected without attacking the target.
 */

export interface PocCommand {
  id: string
  label: string
  language: 'bash' | 'python' | 'nmap'
  code: string
  note?: string
}

export interface PocInput {
  host?: string | null
  ip?: string | null
  port?: number
  service?: string | null
  secure?: boolean
  cves?: SelectionCve[]
  findings?: BasicFinding[]
}

export interface PocDoc {
  title: string
  target: string
  commands: PocCommand[]
  caveat: string
}

const WEB_PORTS = new Set([80, 443, 8000, 8080, 8443, 8888])

const shellQuote = (value: string) => `'${value.replace(/'/g, `'\\''`)}'`

function endpoint(input: PocInput): { host: string; port: number | null; url: string; authority: string; secure: boolean } {
  const host = String(input.ip || input.host || 'target').replace(/^\[|\]$/g, '')
  const port = input.port && Number.isFinite(input.port) ? Number(input.port) : null
  const secure = input.secure ?? (port === 443 || port === 8443)
  const scheme = secure ? 'https' : 'http'
  const authority = port ? `${host}:${port}` : host
  return {
    host,
    port,
    authority,
    secure,
    url: `${scheme}://${authority}/`,
  }
}

function curlProbe(url: string): PocCommand {
  return {
    id: 'curl-head',
    label: 'HTTP HEAD · версия и заголовки',
    language: 'bash',
    code: `curl -sS -k -I --connect-timeout 4 --max-time 8 ${shellQuote(url)}`,
    note: 'Только запрос заголовков. Ничего не изменяет на сервере.',
  }
}

function pythonBanner(host: string, port: number | null, secure: boolean): PocCommand {
  const targetPort = port || (secure ? 443 : 80)
  const request = 'HEAD / HTTP/1.1'
  return {
    id: 'python-banner',
    label: 'PYTHON · безопасный баннер',
    language: 'python',
    code: `import socket
import ssl

host, port = ${JSON.stringify(host)}, ${targetPort}
sock = socket.create_connection((host, port), timeout=5)
if ${secure ? 'True' : 'False'}:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock = context.wrap_socket(sock, server_hostname=host)
sock.sendall(${JSON.stringify(`${request}\r\nHost: ${host}\r\nUser-Agent: NetworkMap-PoC/1.0\r\nConnection: close\r\n\r\n`)}.encode())
print(sock.recv(4096).decode("utf-8", "replace"))
sock.close()`,
    note: 'Читает первый ответ и закрывает соединение. Без полезной нагрузки.',
  }
}

function tlsProbe(authority: string): PocCommand {
  return {
    id: 'openssl',
    label: 'TLS · сертификат и протокол',
    language: 'bash',
    code: `openssl s_client -connect ${shellQuote(authority)} -servername ${shellQuote(authority.split(':')[0])} -brief < /dev/null`,
    note: 'Проверяет цепочку и версию TLS, не отправляя HTTP-запросов.',
  }
}

function findingCommand(input: PocInput): PocCommand | null {
  const finding = input.findings?.[0]
  if (!finding) return null
  
  const host = String(input.ip || input.host || 'target')
  const port = input.port || finding.port
  const authority = port ? `${host}:${port}` : host
  const id = finding.id.toLowerCase()
  const title = finding.title

  if (id.includes('redis')) {
    return {
      id: 'redis-ping',
      label: 'REDIS · PING без авторизации',
      language: 'bash',
      code: `redis-cli -h ${shellQuote(String(input.ip || host))}${port ? ` -p ${port}` : ''} --no-auth-warning PING`,
      note: `${title}: ожидается PONG только если порт действительно открыт.`,
    }
  }
  if (id.includes('mongo')) {
    return {
      id: 'mongo-ping',
      label: 'MONGODB · ping',
      language: 'bash',
      code: `mongosh ${shellQuote(`mongodb://${authority}/?directConnection=true&serverSelectionTimeoutMS=4000`)} --quiet --eval 'db.runCommand({ ping: 1 })'`,
      note: `${title}: только служебная команда ping.`,
    }
  }
  if (id.includes('ftp')) {
    return {
      id: 'ftp-list',
      label: 'FTP · анонимный листинг',
      language: 'bash',
      code: `curl -sS --connect-timeout 4 --max-time 8 ${shellQuote(`ftp://${authority}/`)}`,
      note: `${title}: пробует анонимный вход и ничего не загружает.`,
    }
  }
  if (id.includes('smb')) {
    return {
      id: 'smb-list',
      label: 'SMB · список ресурсов',
      language: 'nmap',
      code: `nmap -Pn -p ${port || 445} --script smb-os-discovery,smb2-security-mode ${shellQuote(host)}`,
      note: `${title}: только discovery-скрипты Nmap.`,
    }
  }
  if (id.includes('rdp')) {
    return {
      id: 'rdp-info',
      label: 'RDP · NTLM info',
      language: 'nmap',
      code: `nmap -Pn -p ${port || 3389} --script rdp-ntlm-info ${shellQuote(host)}`,
      note: `${title}: пассивная идентификация службы.`,
    }
  }
  if (id.includes('telnet')) {
    return {
      id: 'telnet-banner',
      label: 'TELNET · баннер',
      language: 'bash',
      code: `timeout 6 bash -c 'exec 3<>/dev/tcp/${host}/${port || 23}; head -c 1024 <&3'`,
      note: `${title}: читает приглашение и закрывает соединение.`,
    }
  }
  return null
}

function cveCommand(input: PocInput, cves: SelectionCve[]): PocCommand | null {
  const cve = cves[0]
  if (!cve) return null
  const { authority, url, secure } = endpoint(input)
  return {
    id: `cve-${cve.id}`,
    label: `${cve.id} · проверка версии`,
    language: 'bash',
    code: `curl -sS -k -D - --connect-timeout 4 --max-time 8 ${shellQuote(secure ? url : `http://${authority}/`)} -o /dev/null`,
    note: `${cve.product} ${cve.version}. Проверь баннер/версию вручную; PoC не содержит эксплойта.`,
  }
}

export function buildPoc(input: PocInput): PocDoc {
  const { host, port, url, secure, authority } = endpoint(input)
  const commands: PocCommand[] = []

  const webPort = port != null && WEB_PORTS.has(port)
  if (webPort || !port) {
    commands.push(curlProbe(url))
  }
  if (port && (secure || [443, 8443, 465, 993, 995].includes(port))) {
    commands.push(tlsProbe(authority))
  }
  if (port && (webPort || port === 22 || port === 21)) {
    commands.push(pythonBanner(host, port, secure))
  }

  const finding = findingCommand(input)
  if (finding) commands.push(finding)
  const cve = cveCommand(input, input.cves || [])
  if (cve) commands.push(cve)

  if (!commands.length) {
    commands.push(pythonBanner(host, port, secure))
  }

  return {
    title: `PoC · ${input.service || input.findings?.[0]?.title || input.cves?.[0]?.id || 'безопасная проверка'}`,
    target: authority,
    commands: commands.slice(0, 4),
    caveat:
      'Команды только читают баннеры и заголовки. Запускай их лишь на системах, которые тебе разрешено проверять.',
  }
}

export function pocText(doc: PocDoc): string {
  return [
    `# ${doc.title}`,
    `# target: ${doc.target}`,
    '',
    ...doc.commands.flatMap((command) => [
      `## ${command.label}`,
      command.code,
      command.note ? `# ${command.note}` : '',
      '',
    ]),
    `# ${doc.caveat}`,
  ]
    .filter((line) => line !== '')
    .join('\n')
}
