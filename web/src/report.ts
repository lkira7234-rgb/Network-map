import {
  DnsRecords,
  GeoInfo,
  HopInfo,
  IpEntry,
  LogEntry,
  ObjectSummary,
  RdapInfo,
  ScanState,
  ScanStats,
  TlsInfo,
  HttpInfo,
  PortInfo,
} from './types'
import { objectSummary } from './model'

/* ------------------------------------------------------------------ */
/*  report model                                                       */
/* ------------------------------------------------------------------ */

export interface ReportPort {
  port: number
  state: string
  service: string
  rtt: number | null
  banner: string
}

export interface ReportIp {
  ip: string
  family: number
  primary: boolean
  ptr: string | null
  geo: GeoInfo | null
  ports: ReportPort[]
  tls: (TlsInfo & { port: number }) | null
  http: (HttpInfo & { port: number })[]
}

export interface ReportDoc {
  tool: string
  generatedAt: string
  target: string
  host: string
  demo: boolean
  stats: ScanStats | null
  summary: ObjectSummary | null
  dns: DnsRecords
  rdap: RdapInfo | null
  ips: ReportIp[]
  hops: HopInfo[]
  logs: LogEntry[]
}

const portLabel = (port: PortInfo) => port.service || '—'

function reportIp(entry: IpEntry): ReportIp {
  return {
    ip: entry.ip,
    family: entry.family,
    primary: entry.primary,
    ptr: entry.ptr ?? null,
    geo: entry.geo ?? null,
    ports: Object.values(entry.ports)
      .sort((a, b) => a.port - b.port)
      .map((port) => ({
        port: port.port,
        state: port.state,
        service: portLabel(port),
        rtt: port.rtt ?? null,
        banner: port.banner || '',
      })),
    tls: entry.tls ?? null,
    http: entry.httpAll?.length ? entry.httpAll : entry.http ? [entry.http] : [],
  }
}

export function buildReport(model: ScanState): ReportDoc {
  return {
    tool: 'NETWORK//MAP',
    generatedAt: new Date().toISOString(),
    target: model.target,
    host: model.host,
    demo: model.demo,
    stats: model.stats,
    summary: objectSummary(model),
    dns: model.dns,
    rdap: model.rdap,
    ips: model.ips.map(reportIp),
    hops: model.hops,
    logs: model.logs.slice(-60),
  }
}

export function reportFileName(model: ScanState, extension: string): string {
  const host = (model.host || model.target || 'scan').replace(/[^a-zA-Z0-9._-]+/g, '_')
  const date = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')
  return `network-map_${host}_${date}.${extension}`
}

/* ------------------------------------------------------------------ */
/*  helpers                                                            */
/* ------------------------------------------------------------------ */

export function downloadText(name: string, mime: string, content: string) {
  const blob = new Blob([content], { type: `${mime};charset=utf-8` })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = name
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 4000)
}

const esc = (value: unknown): string =>
  String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')

const dash = (value: unknown) => {
  const text = String(value ?? '').trim()
  return text ? esc(text) : '—'
}

const fmtGeo = (geo?: GeoInfo | null) => {
  if (!geo) return '—'
  return [geo.city, geo.country, geo.isp || geo.org].filter(Boolean).join(' · ') || '—'
}

const fmtDate = (value?: string | null) => {
  if (!value) return '—'
  const raw = value.trim()
  // Nmap prints certificate dates as naive UTC ("2025-01-01T00:00:00").
  const normalised = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?$/.test(raw)
    ? `${raw.replace(' ', 'T')}Z`
    : raw
  const parsed = Date.parse(normalised)
  if (!Number.isFinite(parsed)) return value
  return new Date(parsed).toISOString().replace('T', ' ').slice(0, 16) + ' UTC'
}

const stateLabel: Record<string, string> = {
  open: 'открыт',
  closed: 'закрыт',
  filtered: 'фильтр',
}

/* ------------------------------------------------------------------ */
/*  HTML report                                                        */
/* ------------------------------------------------------------------ */

function rows(pairs: [string, string][]): string {
  return pairs
    .filter(([, value]) => value && value !== '—')
    .map(([label, value]) => `<div class="kv"><span>${esc(label)}</span><b>${value}</b></div>`)
    .join('')
}

function dnsTable(title: string, values: string[], mono = true): string {
  if (!values.length) return ''
  return `<div class="dns-block"><h4>${esc(title)}</h4><ul class="${mono ? 'mono' : ''}">${values
    .map((value) => `<li>${esc(value)}</li>`)
    .join('')}</ul></div>`
}

function ipSection(ip: ReportIp): string {
  const openPorts = ip.ports.filter((port) => port.state === 'open').length
  const portRows = ip.ports
    .map(
      (port) => `<tr class="state-${esc(port.state)}">
        <td class="mono">${port.port}</td>
        <td>${dash(stateLabel[port.state] || port.state)}</td>
        <td class="mono">${dash(port.service)}</td>
        <td class="mono">${port.rtt != null ? `${port.rtt} мс` : '—'}</td>
        <td class="banner">${dash(port.banner)}</td>
      </tr>`,
    )
    .join('')

  const tls = ip.tls
    ? `<div class="sub"><h4>TLS · порт ${ip.tls.port}</h4>${rows([
        ['Издатель', dash(ip.tls.issuer)],
        ['Субъект', dash(ip.tls.subject)],
        ['Протокол', dash(ip.tls.protocol)],
        ['Шифр', dash(ip.tls.cipher)],
        ['ALPN', dash(ip.tls.alpn)],
        ['Действителен с', fmtDate(ip.tls.validFrom)],
        ['Действителен до', fmtDate(ip.tls.validTo)],
        ['SAN', esc(ip.tls.altNames?.slice(0, 18).join(', ') || '—')],
        ['Отпечаток', dash(ip.tls.fingerprint)],
      ])}</div>`
    : ''

  const http = ip.http
    .map((entry, index) => {
      const headers = Object.entries(entry.headers || {})
      return `<div class="sub"><h4>HTTP · порт ${entry.port}${index === 0 ? '' : ` #${index + 1}`}</h4>${rows([
        ['Статус', dash(entry.status)],
        ['Server', dash(entry.server)],
        ['X-Powered-By', dash(entry.poweredBy)],
        ['Content-Type', dash(entry.contentType)],
        ['Title', dash(entry.title)],
      ])}${
        headers.length
          ? `<table class="headers"><thead><tr><th>Заголовок</th><th>Значение</th></tr></thead><tbody>${headers
              .map(([key, value]) => `<tr><td class="mono">${esc(key)}</td><td>${esc(value)}</td></tr>`)
              .join('')}</tbody></table>`
          : ''
      }</div>`
    })
    .join('')

  return `<section class="ip">
    <div class="ip-head">
      <h3>${esc(ip.ip)}</h3>
      <div class="badges">
        <span class="badge">IPv${ip.family}</span>
        ${ip.primary ? '<span class="badge primary">основной</span>' : ''}
        <span class="badge ${openPorts ? 'good' : ''}">${openPorts} открыто</span>
      </div>
    </div>
    ${rows([
      ['PTR', dash(ip.ptr)],
      ['GEO', esc(fmtGeo(ip.geo))],
      ['ASN', dash(ip.geo?.asn)],
    ])}
    ${
      ip.ports.length
        ? `<table class="ports"><thead><tr><th>Порт</th><th>Состояние</th><th>Сервис</th><th>RTT</th><th>Баннер</th></tr></thead><tbody>${portRows}</tbody></table>`
        : ''
    }
    ${tls}
    ${http}
  </section>`
}

export function buildHtmlReport(model: ScanState, summary = objectSummary(model)): string {
  const doc = buildReport(model)
  const stats = model.stats || {
    open: 0,
    closed: 0,
    filtered: 0,
    scanned: 0,
    ips: model.ips.length,
    hops: model.hops.length,
  }

  const providers = summary
    ? `<div class="providers">${summary.providers
        .map(
          (item) =>
            `<div class="provider"><span>${esc(item.label)}</span><b>${dash(item.value)}</b></div>`,
        )
        .join('')}</div>`
    : ''

  const cert = summary?.cert
    ? `<div class="cert ${summary.cert.expired ? 'bad' : summary.cert.expiringSoon ? 'warn' : 'ok'}">
        <span>TLS</span>
        <b>${dash(summary.cert.issuer)}</b>
        <em>${
          summary.cert.days == null
            ? dash(summary.cert.protocol)
            : summary.cert.expired
              ? 'срок истёк'
              : `${summary.cert.days} дн. до истечения`
        }</em>
      </div>`
    : ''

  const hygiene = summary
    ? `<div class="hygiene"><span class="score">${summary.hygieneOk}/${summary.hygiene.length}</span>${summary.hygiene
        .map(
          (flag) =>
            `<span class="${flag.ok ? 'ok' : 'bad'}" title="${esc(flag.hint)}">${
              flag.ok ? '✓' : '✕'
            } ${esc(flag.label)}</span>`,
        )
        .join('')}</div>`
    : ''

  const dns = model.dns
  const dnsBlocks = [
    dnsTable('A', dns.a.map((entry) => `${entry.address}${entry.ttl ? ` · TTL ${entry.ttl}` : ''}`)),
    dnsTable('AAAA', dns.aaaa.map((entry) => `${entry.address}${entry.ttl ? ` · TTL ${entry.ttl}` : ''}`)),
    dnsTable('CNAME', dns.cname),
    dnsTable('NS', dns.ns),
    dnsTable('MX', dns.mx.map((entry) => `${entry.priority} · ${entry.exchange}`)),
    dnsTable('TXT', dns.txt),
    dns.soa ? dnsTable('SOA', [JSON.stringify(dns.soa)]) : '',
  ]
    .filter(Boolean)
    .join('')

  const hops = model.hops.length
    ? `<section class="block"><h2>Маршрут</h2><table class="hops"><thead><tr><th>#</th><th>IP</th><th>RTT</th><th>GEO</th></tr></thead><tbody>${model.hops
        .map(
          (hop) => `<tr>
            <td class="mono">${hop.index}</td>
            <td class="mono">${hop.timeout ? '*' : dash(hop.ip)}</td>
            <td class="mono">${hop.rtt != null ? `${hop.rtt} мс` : '—'}</td>
            <td>${esc(fmtGeo(hop.geo))}</td>
          </tr>`,
        )
        .join('')}</tbody></table></section>`
    : ''

  const rdap = model.rdap
    ? `<section class="block"><h2>Регистрация (RDAP)</h2>${rows([
        ['Имя', dash(model.rdap.name)],
        ['Организация', dash(model.rdap.org)],
        ['Регистратор', dash(model.rdap.registrar)],
        ['Страна', dash(model.rdap.country)],
        ['Зарегистрирован', dash(model.rdap.registered)],
        ['Изменён', dash(model.rdap.changed)],
        ['Истекает', dash(model.rdap.expires)],
        ['Статус', esc(model.rdap.status?.join(', ') || '—')],
        ['NS', esc(model.rdap.nameservers?.join(', ') || '—')],
      ])}</section>`
    : ''

  const log = model.logs.length
    ? `<section class="block"><h2>Журнал</h2><div class="log">${model.logs
        .slice(-80)
        .map(
          (entry) =>
            `<div class="log-line ${esc(entry.level)}"><span>${esc(
              new Date(entry.t).toISOString().slice(11, 19),
            )}</span>${esc(entry.message)}</div>`,
        )
        .join('')}</div></section>`
    : ''

  const generated = new Date(doc.generatedAt)
  const generatedText = `${generated.toLocaleDateString('ru-RU')} ${generated
    .toLocaleTimeString('ru-RU')
    .slice(0, 5)}`

  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NETWORK//MAP — ${esc(model.host || model.target)}</title>
<style>
  :root { --ink: #12181f; --muted: #5d6b78; --line: #d8e0e7; --accent: #0d7f96; --good: #0b7a4b; --bad: #b4233a; --warn: #a76700; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 32px; background: #eef2f5; color: var(--ink); font: 13px/1.45 -apple-system, "Segoe UI", Roboto, Arial, sans-serif; }
  .sheet { max-width: 980px; margin: 0 auto; background: #fff; padding: 34px 38px 42px; box-shadow: 0 12px 40px rgba(16, 32, 48, 0.12); }
  header { display: flex; justify-content: space-between; gap: 24px; align-items: flex-start; padding-bottom: 18px; border-bottom: 3px solid var(--ink); }
  .brand { font-size: 22px; font-weight: 800; letter-spacing: 0.08em; }
  .brand span { color: var(--accent); }
  .brand small { display: block; margin-top: 4px; font-size: 10px; font-weight: 600; letter-spacing: 0.22em; color: var(--muted); }
  .meta { text-align: right; font-size: 11px; color: var(--muted); }
  .meta b { display: block; font-size: 16px; color: var(--ink); margin-bottom: 2px; }
  .demo { display: inline-block; margin-top: 6px; padding: 2px 7px; border: 1px solid var(--warn); color: var(--warn); font-size: 9px; letter-spacing: 0.12em; }
  h2 { margin: 26px 0 10px; font-size: 11px; letter-spacing: 0.16em; text-transform: uppercase; color: var(--muted); border-bottom: 1px solid var(--line); padding-bottom: 6px; }
  h3 { margin: 0; font-size: 17px; }
  h4 { margin: 0 0 6px; font-size: 10px; letter-spacing: 0.12em; text-transform: uppercase; color: var(--muted); }
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-top: 14px; }
  .stat { padding: 10px 12px; border: 1px solid var(--line); border-left: 3px solid var(--accent); }
  .stat b { display: block; font-size: 21px; line-height: 1.1; }
  .stat span { font-size: 9px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted); }
  .providers { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
  .provider { padding: 8px 10px; background: #f5f8fa; border: 1px solid var(--line); }
  .provider span { display: block; font-size: 9px; letter-spacing: 0.12em; color: var(--muted); }
  .provider b { font-size: 12px; }
  .cert { display: flex; align-items: center; gap: 10px; margin-top: 8px; padding: 8px 10px; border-left: 3px solid var(--good); background: #f5faf7; }
  .cert.warn { border-color: var(--warn); background: #fff9ec; }
  .cert.bad { border-color: var(--bad); background: #fff5f6; }
  .cert span { font-size: 9px; letter-spacing: 0.12em; border: 1px solid currentColor; padding: 1px 5px; }
  .cert b { flex: 1; font-size: 12px; }
  .cert em { font-style: normal; font-size: 11px; color: var(--muted); }
  .hygiene { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin-top: 8px; }
  .hygiene span { font-size: 10px; padding: 2px 7px; border: 1px solid var(--line); color: var(--muted); }
  .hygiene .score { font-weight: 700; color: var(--ink); }
  .hygiene .ok { color: var(--good); border-color: #b7dfca; background: #f3faf6; }
  .hygiene .bad { color: var(--bad); border-color: #f0c2c9; background: #fff6f7; }
  .kv { display: flex; justify-content: space-between; gap: 18px; padding: 4px 0; border-bottom: 1px dotted var(--line); }
  .kv:last-child { border-bottom: 0; }
  .kv span { flex: 0 0 145px; color: var(--muted); }
  .kv b { flex: 1; text-align: right; font-weight: 600; overflow-wrap: anywhere; }
  .ip { margin-top: 18px; padding: 16px 16px 14px; border: 1px solid var(--line); border-top: 3px solid var(--accent); break-inside: avoid; }
  .ip-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 8px; }
  .badges { display: flex; gap: 5px; flex-wrap: wrap; }
  .badge { font-size: 9px; letter-spacing: 0.08em; padding: 2px 6px; border: 1px solid var(--line); color: var(--muted); }
  .badge.primary { border-color: var(--accent); color: var(--accent); }
  .badge.good { border-color: var(--good); color: var(--good); }
  .sub { margin-top: 12px; padding-top: 10px; border-top: 1px dashed var(--line); }
  table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 11px; }
  th { text-align: left; padding: 5px 7px; background: #eef3f6; font-size: 9px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); }
  td { padding: 5px 7px; border-bottom: 1px solid var(--line); vertical-align: top; }
  tr { break-inside: avoid; }
  .mono { font-family: "Cascadia Mono", Consolas, monospace; }
  td.banner { max-width: 360px; overflow-wrap: anywhere; }
  .state-open td:first-child { color: var(--good); font-weight: 700; }
  .state-closed td:first-child { color: var(--bad); }
  .state-filtered td:first-child { color: var(--warn); }
  .dns-block { margin-top: 10px; }
  .dns-block ul { margin: 0; padding-left: 18px; }
  .dns-block li { margin: 1px 0; overflow-wrap: anywhere; }
  .dns-block .mono { font-family: "Cascadia Mono", Consolas, monospace; font-size: 11px; }
  .block { break-inside: avoid; }
  .log { max-height: 300px; overflow: hidden; padding: 8px 10px; background: #f5f8fa; border: 1px solid var(--line); font-family: "Cascadia Mono", Consolas, monospace; font-size: 10px; }
  .log-line { display: flex; gap: 9px; padding: 1px 0; }
  .log-line span { color: var(--muted); }
  .log-line.open { color: var(--accent); }
  .log-line.error { color: var(--bad); }
  .log-line.ok { color: var(--good); }
  footer { margin-top: 30px; padding-top: 12px; border-top: 1px solid var(--line); display: flex; justify-content: space-between; gap: 16px; font-size: 10px; color: var(--muted); }
  @media (max-width: 720px) {
    body { padding: 10px; }
    .sheet { padding: 18px 14px 24px; }
    header { flex-direction: column; }
    .meta { text-align: left; }
    .stats, .providers { grid-template-columns: 1fr 1fr; }
    .kv span { flex-basis: 110px; }
  }
  @media print {
    @page { size: A4; margin: 12mm; }
    body { padding: 0; background: #fff; font-size: 10.5px; }
    .sheet { max-width: none; padding: 0; box-shadow: none; }
    h2 { margin-top: 18px; }
    .ip { padding: 10px 12px; }
    .log { max-height: none; }
    footer { margin-top: 18px; }
  }
</style>
</head>
<body>
<div class="sheet">
  <header>
    <div class="brand">NETWORK<span>//</span>MAP<small>CYBERSPACE TOPOLOGY REPORT</small></div>
    <div class="meta">
      <b>${esc(model.host || model.target)}</b>
      <div>${esc(model.target)}${model.host && model.host !== model.target ? ` → ${esc(model.host)}` : ''}</div>
      <div>Отчёт от ${esc(generatedText)}</div>
      ${model.demo ? '<span class="demo">DEMO / СИНТЕТИЧЕСКИЕ ДАННЫЕ</span>' : ''}
    </div>
  </header>

  <div class="stats">
    <div class="stat"><b>${stats.ips}</b><span>IP-узлов</span></div>
    <div class="stat"><b>${stats.open}</b><span>открытых портов</span></div>
    <div class="stat"><b>${stats.closed + stats.filtered}</b><span>закрыто / фильтр</span></div>
    <div class="stat"><b>${stats.hops}</b><span>хопов</span></div>
  </div>

  <h2>Сводка по объекту</h2>
  ${providers || '<p>Нет данных.</p>'}
  ${cert}
  ${hygiene}

  <h2>DNS</h2>
  ${dnsBlocks || '<p>Нет данных.</p>'}

  <h2>Узлы и порты</h2>
  ${doc.ips.length ? doc.ips.map(ipSection).join('') : '<p>Нет данных.</p>'}

  ${hops}
  ${rdap}
  ${log}

  <footer>
    <span>NETWORK//MAP · ${esc(model.demo ? 'demo' : 'live scan')} · ${esc(model.target)}</span>
    <span>Сгенерировано автоматически. Проверяй только те системы, на которые у тебя есть разрешение.</span>
  </footer>
</div>
</body>
</html>`
}

/** Opens the browser print dialog for the HTML report (Save as PDF). */
export function printHtmlReport(html: string) {
  const frame = document.createElement('iframe')
  frame.setAttribute('aria-hidden', 'true')
  frame.style.cssText = 'position:fixed;right:0;bottom:0;width:1px;height:1px;border:0;opacity:0;'
  document.body.appendChild(frame)
  frame.onload = () => {
    const view = frame.contentWindow
    if (!view) {
      frame.remove()
      return
    }
    view.focus()
    view.print()
    window.setTimeout(() => frame.remove(), 1500)
  }
  frame.srcdoc = html
}
