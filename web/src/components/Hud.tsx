import { FormEvent, useEffect, useMemo, useRef, useState } from 'react'
import { ScanEvent, ScanState, Selection, SelectionAction, SubdomainInfo, SubdomainState } from '../types'
import { Probe } from './Probe'
import { MonitorPanel } from './MonitorPanel'
import { getSelectionDetails, objectSummary, portCounts } from '../model'
import { RateLimitInfo } from '../api'
import { DEFAULT_FORM, PORT_PRESETS, ScanFormValues, formToUrl } from '../form'
import { buildHtmlReport, buildReport, downloadText, printHtmlReport, reportFileName } from '../report'
import { plural } from '../nmap'
import { parseImport } from '../importers'
import { Severity, collectCves, severityColor, severityLabel } from '../cve'
import { collectFindings, findingColor, findingLabel } from '../checks'
import { techCategoryLabel, techColor } from '../tech'
import { ClusterMode } from '../layout'
import { HistoryResult, formatSnapshotTime, hasDiff } from '../history'

interface HudProps {
  model: ScanState
  initial: ScanFormValues
  rateLimit: RateLimitInfo | null
  selection: Selection
  hover: string | null
  mode: 'orbit' | 'fly'
  scanning: boolean
  cluster: ClusterMode
  subdomains: SubdomainInfo[]
  subState: SubdomainState
  focusIps: string[]
  history: HistoryResult | null
  onCluster: (mode: ClusterMode) => void
  onFindSubdomains: () => void
  onScanSubdomain: (name: string) => void
  onClearFocus: () => void
  onOpenSpotlight: () => void
  onClearHistory: () => void
  onSelect: (selection: Selection) => void
  onScan: (values: ScanFormValues) => void
  onImport: (events: ScanEvent[], target: string) => void
  onDemo: () => void
  onStop: () => void
  onToggleMode: () => void
  onResetCamera: () => void
}

const PRESETS = ['github.com', 'cloudflare.com', '1.1.1.1', 'example.com']

const pad = (value: number) => String(value).padStart(2, '0')

const clock = (value: number) => {
  const date = new Date(value)
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

const formatDuration = (ms: number) => {
  if (!ms || ms < 0) return '0.0s'
  return `${(ms / 1000).toFixed(1)}s`
}

const STATUS: Record<ScanState['phase'], string> = {
  idle: 'ОЖИДАНИЕ',
  scanning: 'СКАНИРОВАНИЕ',
  done: 'ГОТОВО',
  error: 'ОШИБКА',
}

export function Hud({
  model,
  initial,
  rateLimit,
  selection,
  hover,
  mode,
  scanning,
  cluster,
  subdomains,
  subState,
  focusIps,
  history,
  onCluster,
  onFindSubdomains,
  onScanSubdomain,
  onClearFocus,
  onOpenSpotlight,
  onClearHistory,
  onSelect,
  onScan,
  onImport,
  onDemo,
  onStop,
  onToggleMode,
  onResetCamera,
}: HudProps) {
  const [target, setTarget] = useState(initial.target || DEFAULT_FORM.target)
  const [ports, setPorts] = useState(initial.ports)
  const [traceroute, setTraceroute] = useState(initial.traceroute)
  const [geo, setGeo] = useState(initial.geo)
  const [udp, setUdp] = useState(initial.udp)
  const [, tick] = useState(0)
  const [mobileTab, setMobileTab] = useState<'scan' | 'telemetry' | 'inspect'>('scan')
  const [sheetOpen, setSheetOpen] = useState(true)
  const [shareState, setShareState] = useState<'idle' | 'copied' | 'error'>('idle')
  const [actionNote, setActionNote] = useState<{ id: string; message: string } | null>(null)
  const [reportOpen, setReportOpen] = useState(false)
  const [importState, setImportState] = useState<{
    status: 'idle' | 'busy' | 'ok' | 'error'
    message: string
  }>({ status: 'idle', message: '' })

  const logRef = useRef<HTMLDivElement>(null)
  const errorRef = useRef<HTMLDivElement>(null)
  const reportRef = useRef<HTMLDivElement>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const actionTimer = useRef<number | null>(null)
  const details = getSelectionDetails(model, selection)
  const summary = objectSummary(model)
  const counts = portCounts(model)
  const cves = useMemo(() => collectCves(model), [model.ips])
  const findings = useMemo(
    () => collectFindings(model),
    [model.ips, model.extraFindings, model.host, model.target],
  )
  const diff = history?.diff ?? null
  const primary = model.ips.find((ip) => ip.primary) || model.ips[0]
  const hasReport =
    model.phase !== 'idle' &&
    (model.ips.length > 0 || model.hops.length > 0 || model.dns.a.length > 0 || Boolean(model.rdap))

  const resetIn = rateLimit?.resetAt
    ? Math.max(0, Math.ceil((rateLimit.resetAt - Date.now()) / 1000))
    : 0
  const exhausted = Boolean(rateLimit && rateLimit.remaining <= 0)

  useEffect(() => {
    const scanningNow = model.phase === 'scanning'
    if (!scanningNow && !exhausted) return
    const id = window.setInterval(() => {
      if (!scanningNow && rateLimit?.resetAt && Date.now() > rateLimit.resetAt + 1000) {
        window.clearInterval(id)
      }
      tick((value) => value + 1)
    }, 500)
    return () => window.clearInterval(id)
  }, [model.phase, exhausted, rateLimit])

  useEffect(() => {
    const el = logRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [model.logs.length])

  // Subdomain scans and shared links change the target from the outside.
  useEffect(() => {
    if (model.target) setTarget(model.target)
  }, [model.target])

  // Mobile: reveal the inspector as soon as a node is tapped.
  useEffect(() => {
    if (selection) {
      setMobileTab('inspect')
      setSheetOpen(true)
    } else {
      setMobileTab((tab) => (tab === 'inspect' ? 'scan' : tab))
    }
  }, [selection])

  // Mobile: surface validation / scan errors instead of leaving the sheet closed.
  useEffect(() => {
    if (model.error) {
      setMobileTab('scan')
      setSheetOpen(true)
      const id = window.setTimeout(() => {
        errorRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
      }, 80)
      return () => window.clearTimeout(id)
    }
  }, [model.error])

  useEffect(() => {
    if (shareState === 'idle') return
    const id = window.setTimeout(() => setShareState('idle'), 2200)
    return () => window.clearTimeout(id)
  }, [shareState])

  // Close the download menu on outside click or Escape.
  useEffect(() => {
    if (!reportOpen) return
    const onDown = (event: MouseEvent) => {
      if (!reportRef.current?.contains(event.target as Node)) setReportOpen(false)
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setReportOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [reportOpen])

  const pickTab = (tab: 'scan' | 'telemetry' | 'inspect') => {
    if (mobileTab === tab && sheetOpen) {
      setSheetOpen(false)
      return
    }
    setMobileTab(tab)
    setSheetOpen(true)
  }

  const startDemo = () => {
    onDemo()
    setSheetOpen(false)
  }

  const share = async () => {
    const value = target.trim()
    if (!value) return
    const url = formToUrl({ target: value, ports, traceroute, geo, udp })
    try {
      if (navigator.share && window.matchMedia('(max-width: 720px)').matches) {
        await navigator.share({ title: 'NETWORK//MAP', url })
        return
      }
      await navigator.clipboard.writeText(url)
      setShareState('copied')
    } catch (error) {
      if ((error as Error)?.name === 'AbortError') return
      setShareState('error')
    }
  }

  const flashAction = (id: string, message: string) => {
    setActionNote({ id, message })
    if (actionTimer.current != null) window.clearTimeout(actionTimer.current)
    actionTimer.current = window.setTimeout(() => setActionNote(null), 3600)
  }

  const copyValue = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value)
      return true
    } catch {
      // Clipboard API needs a secure context; fall back for plain http hosts.
    }
    try {
      const area = document.createElement('textarea')
      area.value = value
      area.setAttribute('readonly', '')
      area.style.position = 'fixed'
      area.style.opacity = '0'
      document.body.appendChild(area)
      area.select()
      const ok = document.execCommand('copy')
      document.body.removeChild(area)
      return ok
    } catch {
      return false
    }
  }

  const runAction = async (action: SelectionAction) => {
    if (action.kind === 'open') {
      window.open(action.value, '_blank', 'noopener,noreferrer')
      flashAction(action.id, `Открываю ${action.value}`)
      return
    }
    if (action.kind === 'download') {
      downloadText(action.filename || 'connection.rdp', 'application/x-rdp', action.value)
      flashAction(action.id, `Скачиваю ${action.filename || 'connection.rdp'}`)
      return
    }
    const ok = await copyValue(action.value)
    flashAction(
      action.id,
      ok
        ? action.id === 'burp'
          ? 'URL скопирован — вставь в Burp Repeater (Ctrl+R)'
          : `Скопировано: ${action.value}`
        : 'Браузер не дал доступ к буферу обмена',
    )
  }

  const submit = (event: FormEvent) => {
    event.preventDefault()
    const value = target.trim()
    if (!value) return
    setImportState({ status: 'idle', message: '' })
    onScan({ target: value, ports, traceroute, geo, udp })
    setSheetOpen(false)
  }

  const importFile = async (file: File | undefined) => {
    if (!file) return
    if (file.size > 32 * 1024 * 1024) {
      setImportState({ status: 'error', message: 'Файл больше 32 МБ — отфильтруй отчёт.' })
      return
    }
    setImportState({ status: 'busy', message: 'Читаю файл…' })
    try {
      const result = parseImport(await file.text())
      onImport(result.events, result.target)
      setTarget(result.target)
      const parts = [result.kind.toUpperCase()]
      if (result.hosts) parts.push(plural(result.hosts, ['хост', 'хоста', 'хостов']))
      if (result.ports) parts.push(plural(result.ports, ['порт', 'порта', 'портов']))
      if (result.findings) parts.push(plural(result.findings, ['находка', 'находки', 'находок']))
      setImportState({ status: 'ok', message: parts.join(' · ') })
      setSheetOpen(false)
    } catch (error) {
      setImportState({
        status: 'error',
        message: (error as Error)?.message || 'Не удалось прочитать файл.',
      })
    }
  }

  const saveReport = (kind: 'html' | 'json') => {
    if (!hasReport) return
    if (kind === 'json') {
      downloadText(reportFileName(model, 'json'), 'application/json', JSON.stringify(buildReport(model), null, 2))
    } else {
      downloadText(reportFileName(model, 'html'), 'text/html', buildHtmlReport(model, summary))
    }
    setReportOpen(false)
  }

  const savePdf = () => {
    if (!hasReport) return
    printHtmlReport(buildHtmlReport(model, summary))
    setReportOpen(false)
  }

  const elapsed = model.stats?.durationMs ?? (model.startedAt ? Date.now() - model.startedAt : 0)
  const phaseLabel = model.demo && model.phase !== 'idle' ? 'DEMO' : STATUS[model.phase]

  return (
    <div className={`hud mobile-tab-${mobileTab} ${sheetOpen ? 'sheet-open' : 'sheet-closed'}`}>
      <div className="scanlines" />
      <div className="cs-vignette" />

      <header className="mobile-head">
        <div className="mobile-head-row">
          <div className="mobile-brand">
            NETWORK<span>//</span>MAP
          </div>
          <div className="mobile-target">
            <b>{model.host || 'NO TARGET'}</b>
            <i>{primary?.ip || '—'}</i>
          </div>
          <span className={`mobile-phase ${model.phase}`}>
            <i /> {phaseLabel}
          </span>
        </div>
        <div className="mobile-stats">
          <span><b>{model.ips.length}</b> IP</span>
          <span className="open"><b>{counts.open}</b> ОТКР</span>
          <span className="hops"><b>{model.hops.length}</b> ХОПЫ</span>
          <span><b>{formatDuration(elapsed)}</b> ВРЕМЯ</span>
        </div>
      </header>

      <aside className="left-col">
        <div className="brand">
          <div className="brand-mark">
            <span />
          </div>
          <div className="brand-text">
            <h1>
              NETWORK<span>//</span>MAP
            </h1>
            <p>CYBERSPACE TOPOLOGY SCANNER</p>
          </div>
        </div>

        <form className="panel scanner" onSubmit={submit}>
          <div className="panel-head">
            <span>01 / TARGET ACQUISITION</span>
            <div className="panel-head-actions">
              <div className="report-menu" ref={reportRef}>
                <button
                  type="button"
                  className="link-btn report-btn"
                  onClick={() => setReportOpen((value) => !value)}
                  disabled={!hasReport}
                  aria-haspopup="menu"
                  aria-expanded={reportOpen}
                  title="Скачать отчёт: HTML, PDF или JSON"
                >
                  ⭳ ОТЧЁТ
                </button>
                {reportOpen && (
                  <div className="report-list" role="menu" aria-label="Формат отчёта">
                    <button type="button" role="menuitem" onClick={() => saveReport('html')}>
                      <b>HTML</b>
                      <em>готовая страница с картой данных</em>
                    </button>
                    <button type="button" role="menuitem" onClick={savePdf}>
                      <b>PDF</b>
                      <em>через диалог печати → «Сохранить как PDF»</em>
                    </button>
                    <button type="button" role="menuitem" onClick={() => saveReport('json')}>
                      <b>JSON</b>
                      <em>все события и сырые заголовки</em>
                    </button>
                  </div>
                )}
              </div>
              <button
                type="button"
                className={`link-btn ${shareState}`}
                onClick={share}
                disabled={!target.trim()}
                title="Скопировать ссылку на этот скан"
              >
                {shareState === 'copied' ? '✓ СКОПИРОВАНО' : shareState === 'error' ? '✕ НЕТ ДОСТУПА' : '⧉ ССЫЛКА'}
              </button>
              <span className={`status-dot ${model.phase}`} />
            </div>
          </div>

          <label className="field-label" htmlFor="target">
            ХОСТ ИЛИ IP
          </label>
          <input
            id="target"
            className="text-input"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="github.com или 8.8.8.8"
            spellCheck={false}
            autoComplete="off"
          />

          <label className="field-label" htmlFor="ports">
            ПОРТЫ <span className="label-hint">диапазоны: 1-1024</span>
          </label>
          <input
            id="ports"
            className="text-input"
            value={ports}
            onChange={(event) => setPorts(event.target.value)}
            placeholder="22,80,443,8000-8100"
            spellCheck={false}
            autoComplete="off"
          />

          <div className="preset-row">
            <span className="quick-label">НАБОР:</span>
            {PORT_PRESETS.map((preset) => (
              <button
                key={preset.id}
                type="button"
                className={`chip ${ports === preset.value ? 'active' : ''}`}
                onClick={() => setPorts(preset.value)}
                title={preset.hint}
              >
                {preset.label}
              </button>
            ))}
          </div>

          <div className="import-row">
            <span className="quick-label">ИМПОРТ:</span>
            <button
              type="button"
              className="chip import-chip"
              onClick={() => fileRef.current?.click()}
              title="Nmap/Masscan XML, httpx -json, nuclei -jsonl"
            >
              ↥ XML · HTTPX · NUCLEI
            </button>
            <input
              ref={fileRef}
              type="file"
              className="import-file"
              accept=".xml,.json,.jsonl,text/xml,application/xml,application/json,application/x-ndjson"
              onChange={(event) => {
                const file = event.target.files?.[0]
                // Reset so picking the same file twice still fires onChange.
                event.target.value = ''
                void importFile(file)
              }}
            />
          </div>

          <div className="search-row">
            <button
              type="button"
              className="chip search-chip"
              onClick={onOpenSpotlight}
              disabled={model.ips.length === 0 && model.hops.length === 0 && model.dns.ns.length === 0}
              title="Поиск по IP, портам, сервисам, CVE и находкам"
            >
              ⌕ SPOTLIGHT <kbd>CTRL K</kbd>
            </button>
            <span className="search-hint">фильтр графа</span>
          </div>

          {importState.status !== 'idle' && (
            <p className={`import-note ${importState.status}`}>
              {importState.status === 'busy' ? <span className="spinner" /> : null}
              {importState.message}
            </p>
          )}

          <div className="options-row">
            <label className="toggle">
              <input type="checkbox" checked={traceroute} onChange={(event) => setTraceroute(event.target.checked)} />
              <span className="toggle-box" />
              TRACEROUTE
            </label>
            <label className="toggle">
              <input type="checkbox" checked={geo} onChange={(event) => setGeo(event.target.checked)} />
              <span className="toggle-box" />
              GEO / ASN
            </label>
            <label className="toggle" title="UDP-пробы: DNS 53, NTP 123, SNMP 161, mDNS 5353, SSDP 1900">
              <input type="checkbox" checked={udp} onChange={(event) => setUdp(event.target.checked)} />
              <span className="toggle-box" />
              UDP
            </label>
          </div>

          <div className="actions-row">
            <button type="submit" className="btn primary" disabled={scanning}>
              {scanning ? (
                <>
                  <span className="spinner" /> СКАНИРУЮ…
                </>
              ) : (
                <>▶ ЗАПУСТИТЬ СКАН</>
              )}
            </button>
            {scanning ? (
              <button type="button" className="btn danger" onClick={() => { onStop(); setSheetOpen(false) }}>
                СТОП
              </button>
            ) : (
              <button type="button" className="btn ghost" onClick={startDemo}>
                ДЕМО
              </button>
            )}
          </div>

          {scanning && (
            <div className="progress">
              <span />
            </div>
          )}

          {rateLimit && (
            <p className={`limit-line ${exhausted ? 'empty' : ''}`}>
              <span>ЛИМИТ</span>
              <b>
                {rateLimit.remaining}/{rateLimit.limit}
              </b>
              {exhausted ? (
                <em>{resetIn > 0 ? `сброс через ${resetIn} с` : 'лимит свободен'}</em>
              ) : (
                <em>сканов в минуту</em>
              )}
            </p>
          )}

          <div className="quick-row">
            <span className="quick-label">QUICK:</span>
            {PRESETS.map((preset) => (
              <button key={preset} type="button" className="chip" onClick={() => setTarget(preset)}>
                {preset}
              </button>
            ))}
          </div>

          <p className="scanner-note">
            Пустой список портов = топ-27. Сканируй только те системы, которые тебе разрешено проверять.
          </p>
        </form>

        <Probe model={model} />

        <section className="panel subdomains">
          <div className="panel-head">
            <span>06 / SUBDOMAINS</span>
            <span className="subdomain-count">
              {subdomains.length > 0 ? subdomains.length : 'CT'}
            </span>
          </div>

          <div className="subdomain-actions">
            <button
              type="button"
              className="btn ghost small"
              onClick={onFindSubdomains}
              disabled={subState.status === 'loading' || !model.host}
              title="Certificate Transparency через crt.sh"
            >
              {subState.status === 'loading' ? (
                <>
                  <span className="spinner" /> ИЩУ…
                </>
              ) : subdomains.length ? (
                <>⟳ ОБНОВИТЬ CT</>
              ) : (
                <>⌕ НАЙТИ ПОДДОМЕНЫ</>
              )}
            </button>
            <span className="subdomain-source">crt.sh · TLS SAN</span>
          </div>

          {subState.status !== 'idle' && (
            <p
              className={`import-note ${
                subState.status === 'ok' ? 'ok' : subState.status === 'error' ? 'error' : 'busy'
              }`}
            >
              {subState.status === 'loading' ? <span className="spinner" /> : null}
              {subState.message}
            </p>
          )}

          {subdomains.length > 0 && (
            <div className="subdomain-list">
              {subdomains.slice(0, 60).map((item) => (
                <button
                  type="button"
                  className={`subdomain-chip ${item.fromCertificate ? 'cert' : ''}`}
                  key={item.name}
                  onClick={() => onScanSubdomain(item.name)}
                  title={`Сканировать ${item.name} с текущими портами`}
                >
                  <span>{item.name}</span>
                  {item.fromCertificate ? <i>CT</i> : null}
                </button>
              ))}
            </div>
          )}

          {subdomains.length > 60 && (
            <p className="subdomain-more">
              +{subdomains.length - 60} ещё в файле CT — уточни домен или выбери имя в сцене.
            </p>
          )}

          <p className="subdomain-note">
            Имена из Certificate Transparency. Клик по имени — быстрый скан с текущими портами.
            Для IP доступен только TLS SAN в инспекторе.
          </p>
        </section>

        {model.error && (
          <div className="panel error-panel" ref={errorRef}>
            <div className="panel-head">
              <span>SCAN ERROR</span>
              <span className="status-dot error" />
            </div>
            <p>{model.error}</p>
          </div>
        )}

        {details && (
          <section className="panel inspector">
            <div className="panel-head">
              <span>03 / INSPECTOR</span>
              <button type="button" className="icon-btn" onClick={() => onSelect(null)} aria-label="Закрыть">
                ✕
              </button>
            </div>
            <div className="inspector-eyebrow" style={{ color: details.color }}>
              {details.eyebrow}
            </div>
            <h2 className="inspector-title" style={{ textShadow: `0 0 18px ${details.color}55` }}>
              {details.title}
            </h2>
            {details.subtitle && <p className="inspector-subtitle">{details.subtitle}</p>}

            <div className="kv-list">
              {details.rows.map((row) => (
                <div className="kv" key={row.label}>
                  <span className="k">{row.label}</span>
                  <span className="v">{row.value}</span>
                </div>
              ))}
            </div>

            {details.actions && details.actions.length > 0 && (
              <div className="inspector-block quick-actions">
                <h4 style={{ color: '#49ff9e' }}>DIRECT CONNECT</h4>
                <div className="quick-action-row">
                  {details.actions.map((action) => (
                    <button
                      key={action.id}
                      type="button"
                      className={`quick-action ${action.id}`}
                      onClick={() => void runAction(action)}
                      title={action.hint || action.value}
                    >
                      <i>
                        {action.kind === 'open' ? '↗' : action.kind === 'copy' ? '⧉' : '⭳'}
                      </i>
                      {action.label}
                    </button>
                  ))}
                </div>
                {actionNote && (
                  <p className="quick-note" aria-live="polite">
                    {actionNote.message}
                  </p>
                )}
                <p className="quick-disclaimer">
                  Ссылки строятся локально из данных скана. Burp получает URL через буфер обмена —
                  вставь его в Repeater. Для SSH замени <code>user</code>, для <code>nc</code> нужен
                  netcat из nmap/ncat.
                </p>
              </div>
            )}

            {details.tech && details.tech.length > 0 && (
              <div className="inspector-block tech-block">
                <h4 style={{ color: '#38f6ff' }}>СТЕК ТЕХНОЛОГИЙ</h4>
                <div className="tech-badges">
                  {details.tech.map((hit) => (
                    <span
                      className="tech-badge"
                      key={`${hit.name}-${hit.category}`}
                      style={{
                        color: techColor[hit.category],
                        borderColor: `${techColor[hit.category]}55`,
                        background: `${techColor[hit.category]}12`,
                      }}
                      title={`${techCategoryLabel[hit.category]} · источник: ${hit.evidence || '—'}`}
                    >
                      {hit.name}
                      {hit.version ? <> <b>{hit.version}</b></> : null}
                    </span>
                  ))}
                </div>
                <p className="tech-note">
                  Определено локально по заголовкам, именам cookie, meta generator и HTML. Без
                  активных запросов.
                </p>
              </div>
            )}

            {details.block && (
              <div className="inspector-block">
                <h4 style={{ color: details.color }}>{details.block.title}</h4>
                {details.block.rows.map((row) => (
                  <div className="kv" key={row.label}>
                    <span className="k">{row.label}</span>
                    <span className="v">{row.value}</span>
                  </div>
                ))}
              </div>
            )}

            {details.cves && details.cves.length > 0 && (
              <div className="inspector-block cve-detail">
                <h4 style={{ color: '#ff3b5c' }}>ПОТЕНЦИАЛЬНЫЕ УЯЗВИМОСТИ</h4>
                {details.cves.map((cve) => (
                  <div className="cve-detail-item" key={cve.id}>
                    <div className="cve-detail-top">
                      <span className={`cve-sev ${cve.severity}`}>
                        {severityLabel[cve.severity as Severity] || cve.severity}
                      </span>
                      <b>{cve.id}</b>
                      <em>
                        {cve.product} {cve.version}
                      </em>
                    </div>
                    <p>{cve.summary}</p>
                    {cve.caveat && <p className="cve-caveat">{cve.caveat}</p>}
                    {cve.fixed && <span className="cve-fixed">исправлено в {cve.fixed}</span>}
                  </div>
                ))}
                <p className="cve-note">
                  Версия взята из баннера и может быть неточной. Это эвристика, а не результат
                  аудита.
                </p>
              </div>
            )}

            {details.findings && details.findings.length > 0 && (
              <div className="inspector-block finding-detail">
                <h4 style={{ color: '#ffb020' }}>БАЗОВЫЕ УЯЗВИМОСТИ И МИСКОНФИГУРАЦИИ</h4>
                {details.findings.map((finding) => (
                  <div
                    className="finding-detail-item"
                    key={`${finding.id}-${finding.ip}-${finding.protocol}-${finding.port}`}
                  >
                    <div className="finding-detail-top">
                      <span className={`finding-sev ${finding.severity}`}>
                        {findingLabel[finding.severity]}
                      </span>
                      <b>{finding.title}</b>
                      {finding.port && (
                        <em>
                          :{finding.port}
                          {finding.protocol === 'udp' ? '/udp' : ''}
                        </em>
                      )}
                    </div>
                    <p>{finding.summary}</p>
                    {finding.evidence && <p className="finding-evidence">{finding.evidence}</p>}
                    <p className="finding-fix">→ {finding.recommendation}</p>
                  </div>
                ))}
                <p className="cve-note">
                  Проверка по открытым портам, баннерам и заголовкам. Она не эксплуатирует
                  уязвимости и не заменяет аудит.
                </p>
              </div>
            )}

            {details.packet && (
              <div className="inspector-block packet-block">
                <h4 style={{ color: '#38f6ff' }}>PACKET · {details.packet.label}</h4>
                {details.packet.request && (
                  <>
                    <span className="packet-label">ЗАПРОС</span>
                    <pre className="packet-pre">{details.packet.request}</pre>
                  </>
                )}
                {details.packet.response && (
                  <>
                    <span className="packet-label">ОТВЕТ</span>
                    <pre className="packet-pre response">{details.packet.response}</pre>
                  </>
                )}
                {details.packet.note && <p className="packet-note">{details.packet.note}</p>}
              </div>
            )}
          </section>
        )}
      </aside>

      <aside className="right-col">
        {(summary || findings.length > 0) && model.phase !== 'idle' && (
          <section className="panel summary">
            <div className="panel-head">
              <span>{summary ? '04 / OBJECT SUMMARY' : '04 / FINDINGS'}</span>
              {summary && (
                <span
                  className={`hygiene-score ${
                    summary.hygieneOk === summary.hygiene.length
                      ? 'ok'
                      : summary.hygieneOk >= 3
                        ? 'warn'
                        : 'bad'
                  }`}
                  title="Присутствие заголовков безопасности HTTP"
                >
                  {summary.hygieneOk}/{summary.hygiene.length}
                </span>
              )}
            </div>

            {summary && (
              <>
            <div className="summary-grid">
              {summary.providers.map((item) => (
                <div className="summary-item" key={item.label}>
                  <span className="k">{item.label}</span>
                  <span className="v" title={item.value}>{item.value}</span>
                </div>
              ))}
            </div>

            {summary.cert && (
              <div
                className={`cert-row ${
                  summary.cert.expired ? 'bad' : summary.cert.expiringSoon ? 'warn' : 'ok'
                }`}
                title={summary.cert.validTo ? `Действителен до ${summary.cert.validTo}` : undefined}
              >
                <span className="cert-tag">TLS</span>
                <span className="cert-main">{summary.cert.issuer}</span>
                <span className="cert-days">
                  {summary.cert.days == null
                    ? summary.cert.protocol
                    : summary.cert.expired
                      ? 'истёк'
                      : `${summary.cert.days} дн.`}
                </span>
              </div>
            )}

            <div className="hygiene-row">
              {summary.hygiene.map((flag) => (
                <span
                  key={flag.key}
                  className={`hygiene ${flag.ok ? 'ok' : 'bad'}`}
                  title={`${flag.hint}: ${flag.ok ? 'есть' : 'нет'}`}
                >
                  <i /> {flag.label}
                </span>
              ))}
            </div>
              </>
            )}

            {cves.length > 0 && (
              <div className="cve-block">
                <div className="cve-head">
                  <span>ПОТЕНЦИАЛЬНЫЕ CVE</span>
                  <b>{cves.length}</b>
                </div>
                {cves.slice(0, 3).map((match) => (
                  <div className="cve-item" key={`${match.id}-${match.ip}-${match.protocol}-${match.port}`}>
                    <i style={{ background: severityColor[match.severity] }} />
                    <span className="cve-id">{match.id}</span>
                    <span className="cve-what">
                      {match.product} {match.version} · :{match.port}
                      {match.protocol === 'udp' ? '/u' : ''}
                    </span>
                  </div>
                ))}
                {cves.length > 3 && <span className="cve-more">+{cves.length - 3} ещё в инспекторе</span>}
                <p className="cve-note">Эвристика по баннерам, не заключение аудита.</p>
              </div>
            )}

            {findings.length > 0 && (
              <div className="findings-block">
                <div className="findings-head">
                  <span>БАЗОВЫЕ ПРОВЕРКИ</span>
                  <b>{findings.length}</b>
                </div>
                {findings.slice(0, 3).map((finding) => (
                  <div
                    className="finding-item"
                    key={`${finding.id}-${finding.ip}-${finding.protocol}-${finding.port}`}
                  >
                    <i style={{ background: findingColor[finding.severity] }} />
                    <span className="finding-title">{finding.title}</span>
                    <span className="finding-what">
                      {finding.ip}
                      {finding.port ? `:${finding.port}` : ''}
                      {finding.protocol === 'udp' ? '/u' : ''}
                    </span>
                  </div>
                ))}
                {findings.length > 3 && (
                  <span className="finding-more">+{findings.length - 3} ещё в инспекторе</span>
                )}
                <p className="finding-note">Пассивная проверка конфигурации, без эксплуатации.</p>
              </div>
            )}
          </section>
        )}

        <section className="panel history">
          <div className="panel-head">
            <span>08 / HISTORY · DIFF</span>
            {history && (
              <button type="button" className="link-btn" onClick={onClearHistory} title="Удалить историю сканов из браузера">
                ОЧИСТИТЬ
              </button>
            )}
          </div>

          {!history && (
            <p className="history-empty">
              История хранится локально в IndexedDB (последние 20 сканов). Сделай повторный скан
              того же домена — покажу новые и закрывшиеся порты.
            </p>
          )}

          {history && (
            <>
              <div className="history-meta">
                <span>{formatSnapshotTime(history.snapshot.at)}</span>
                <b>
                  {history.snapshot.counts.ips} IP · {history.snapshot.counts.open} откр.
                </b>
                <em>скан #{history.total}</em>
              </div>

              {!diff && (
                <p className="history-empty">
                  Это первый скан {history.snapshot.host} в этом браузере — сравнивать пока не с
                  чем.
                </p>
              )}

              {diff && !hasDiff(diff) && (
                <p className="diff-clean">
                  ✓ Изменений нет · {diff.unchanged} открытых портов без изменений
                </p>
              )}

              {diff && hasDiff(diff) && (
                <div className="diff-grid">
                  {diff.newPorts.length > 0 && (
                    <div className="diff-group new">
                      <h5>НОВЫЕ ПОРТЫ · {diff.newPorts.length}</h5>
                      {diff.newPorts.slice(0, 10).map((port) => (
                        <span className="diff-item" key={`new-${port.ip}-${port.protocol}-${port.port}`}>
                          {port.ip}:{port.port}
                          {port.protocol === 'udp' ? '/u' : ''} · {port.service}
                        </span>
                      ))}
                      {diff.newPorts.length > 10 && (
                        <span className="diff-more">+{diff.newPorts.length - 10} ещё</span>
                      )}
                    </div>
                  )}

                  {diff.closedPorts.length > 0 && (
                    <div className="diff-group closed">
                      <h5>ЗАКРЫЛИСЬ · {diff.closedPorts.length}</h5>
                      {diff.closedPorts.slice(0, 10).map((port) => (
                        <span className="diff-item" key={`old-${port.ip}-${port.protocol}-${port.port}`}>
                          {port.ip}:{port.port}
                          {port.protocol === 'udp' ? '/u' : ''} · {port.service}
                        </span>
                      ))}
                      {diff.closedPorts.length > 10 && (
                        <span className="diff-more">+{diff.closedPorts.length - 10} ещё</span>
                      )}
                    </div>
                  )}

                  {diff.newCves.length > 0 && (
                    <div className="diff-group cve">
                      <h5>НОВЫЕ CVE · {diff.newCves.length}</h5>
                      {diff.newCves.slice(0, 8).map((cve) => (
                        <span className="diff-item" key={`cve-${cve.id}-${cve.ip}-${cve.port}`}>
                          {cve.id} · {cve.ip}:{cve.port}
                        </span>
                      ))}
                      {diff.newCves.length > 8 && (
                        <span className="diff-more">+{diff.newCves.length - 8} ещё</span>
                      )}
                    </div>
                  )}

                  {diff.newFindings.length > 0 && (
                    <div className="diff-group finding">
                      <h5>НОВЫЕ НАХОДКИ · {diff.newFindings.length}</h5>
                      {diff.newFindings.slice(0, 6).map((finding) => (
                        <span className="diff-item" key={`finding-${finding.id}-${finding.ip}-${finding.port ?? ''}`}>
                          {finding.title} · {finding.ip}
                          {finding.port ? `:${finding.port}` : ''}
                        </span>
                      ))}
                      {diff.newFindings.length > 6 && (
                        <span className="diff-more">+{diff.newFindings.length - 6} ещё</span>
                      )}
                    </div>
                  )}

                  {(diff.goneCves.length > 0 || diff.goneFindings.length > 0) && (
                    <div className="diff-group gone">
                      <h5>УШЛИ · {diff.goneCves.length + diff.goneFindings.length}</h5>
                      {diff.goneCves.slice(0, 4).map((cve) => (
                        <span className="diff-item" key={`gone-cve-${cve.id}-${cve.ip}-${cve.port}`}>
                          {cve.id} · {cve.ip}:{cve.port}
                        </span>
                      ))}
                      {diff.goneFindings.slice(0, 4).map((finding) => (
                        <span className="diff-item" key={`gone-finding-${finding.id}-${finding.ip}-${finding.port ?? ''}`}>
                          {finding.title} · {finding.ip}
                        </span>
                      ))}
                    </div>
                  )}

                  <span className="diff-unchanged">{diff.unchanged} портов без изменений</span>
                </div>
              )}
            </>
          )}
        </section>

        <MonitorPanel />

        <section className={`panel telemetry phase-${model.phase}`}>
          <div className="panel-head">
            <span>02 / TELEMETRY</span>
            <span className={`status-pill ${model.phase}`}>
              <i /> {phaseLabel}
            </span>
          </div>

          <div className="target-line">
            <span className="target-host">{model.host || 'NO TARGET'}</span>
            <span className="target-ip">{primary?.ip || '—'}</span>
          </div>

          <div className="stats-grid">
            <div className="stat">
              <span className="stat-value">{model.ips.length}</span>
              <span className="stat-label">IP-УЗЛЫ</span>
            </div>
            <div className="stat open" title={counts.udp ? `TCP ${counts.open - counts.udpOpen} · UDP ${counts.udpOpen}` : undefined}>
              <span className="stat-value">{counts.open}</span>
              <span className="stat-label">ОТКРЫТО</span>
            </div>
            <div className="stat closed">
              <span className="stat-value">{counts.closed + counts.filtered}</span>
              <span className="stat-label">ЗАКРЫТО</span>
            </div>
            <div className="stat hops">
              <span className="stat-value">{model.hops.length}</span>
              <span className="stat-label">ХОПЫ</span>
            </div>
          </div>

          <div className="dns-strip">
            <span className="dns-chip">A <b>{model.dns.a.length}</b></span>
            <span className="dns-chip">AAAA <b>{model.dns.aaaa.length}</b></span>
            <span className="dns-chip ns">NS <b>{model.dns.ns.length}</b></span>
            <span className="dns-chip mx">MX <b>{model.dns.mx.length}</b></span>
            <span className="dns-chip">TXT <b>{model.dns.txt.length}</b></span>
          </div>

          <div className="cluster-row">
            <span className="quick-label">КЛАСТЕРЫ:</span>
            {(
              [
                ['none', 'ВЫКЛ', 'Без группировки'],
                ['subnet', '/24', 'Группировать по подсети /24 (IPv6 — /64)'],
                ['asn', 'ASN', 'Группировать по автономной системе из GEO/ASN'],
              ] as [ClusterMode, string, string][]
            ).map(([value, label, hint]) => (
              <button
                key={value}
                type="button"
                className={`chip ${cluster === value ? 'active' : ''}`}
                onClick={() => onCluster(value)}
                title={hint}
              >
                {label}
              </button>
            ))}
            {model.ips.length > 0 && model.ips.length < 3 && (
              <span className="cluster-hint">нужно 3+ узла</span>
            )}
          </div>

          {model.dns.cname.length > 0 && (
            <div className="cname-line">
              <span>CNAME</span>
              <b>{model.dns.cname.join(' → ')}</b>
            </div>
          )}

          <div className="section-label">
            <span>EVENT STREAM</span>
            <span>{formatDuration(elapsed)}</span>
          </div>
          <div className="log" ref={logRef}>
            {model.logs.length === 0 && <div className="log-empty">// поток пуст · ожидание цели</div>}
            {model.logs.map((entry) => (
              <div className={`log-line ${entry.level}`} key={entry.id}>
                <span className="t">{clock(entry.t)}</span>
                <span className="m">{entry.message}</span>
              </div>
            ))}
          </div>
        </section>
      </aside>

      {model.phase === 'idle' && !selection && (
        <div className="hero">
          <p className="hero-kicker">SYSTEM READY · AWAITING COORDINATES</p>
          <p className="hero-title">
            ВОЙДИ В СЕТЬ<span className="caret">_</span>
          </p>
          <p className="hero-sub">
            Введи домен или IP слева, выбери порты и запусти скан — топология соберётся в 3D прямо на глазах.
          </p>
          <button type="button" className="hero-demo" onClick={startDemo}>
            ▶ ОТКРЫТЬ ДЕМО-КАРТУ
          </button>
        </div>
      )}

      {mode === 'fly' && (
        <div className="flight-banner">
          <span className="flight-led" /> FLIGHT MODE
          <em>WASD · МЫШЬ · SPACE/C</em>
          <b>ESC — ВЫЙТИ</b>
        </div>
      )}

      {focusIps.length > 0 && (
        <div className="focus-banner">
          <span>⌕ ФОКУС: {focusIps.length} узл. · остальные притушены</span>
          <button type="button" onClick={onClearFocus}>
            ✕ СБРОС
          </button>
        </div>
      )}

      <div className="bottom-bar">
        <div className="mode-group">
          <button type="button" className={`mode-btn ${mode === 'fly' ? 'active' : ''}`} onClick={onToggleMode}>
            {mode === 'fly' ? '✈ ПОЛЁТ АКТИВЕН' : '✈ СВОБОДНЫЙ ПОЛЁТ'}
          </button>
          <button type="button" className="mode-btn" onClick={onOpenSpotlight}>
            ⌕ ПОИСК
          </button>
          <button type="button" className="mode-btn" onClick={onResetCamera}>
            ⟲ СБРОС
          </button>
        </div>
        <div className="hints">
          {mode === 'fly'
            ? 'WASD · мышь · SPACE/C · SHIFT · ESC выход'
            : 'ЛКМ вращение · колесо зум · ПКМ панорама'}
        </div>
        <div className="hover-readout" title={hover || ''}>
          <span>▸</span> {hover || 'наведи на узел'}
        </div>
      </div>

      <nav className="mobile-dock" aria-label="Мобильные панели">
        <button
          type="button"
          className={`dock-btn ${sheetOpen && mobileTab === 'scan' ? 'active' : ''}`}
          onClick={() => pickTab('scan')}
          aria-expanded={sheetOpen && mobileTab === 'scan'}
        >
          <span className="dock-index">01</span>
          <span className="dock-label">СКАН</span>
        </button>
        <button
          type="button"
          className={`dock-btn ${sheetOpen && mobileTab === 'telemetry' ? 'active' : ''}`}
          onClick={() => pickTab('telemetry')}
          aria-expanded={sheetOpen && mobileTab === 'telemetry'}
        >
          <span className="dock-index">02</span>
          <span className="dock-label">ДАННЫЕ</span>
        </button>
        <button
          type="button"
          className={`dock-btn ${sheetOpen && mobileTab === 'inspect' ? 'active' : ''}`}
          onClick={() => pickTab('inspect')}
          disabled={!details}
          aria-expanded={sheetOpen && mobileTab === 'inspect'}
        >
          <span className="dock-index">03</span>
          <span className="dock-label">ИНСПЕКТ</span>
        </button>
        <button type="button" className="dock-btn reset" onClick={onResetCamera}>
          <span className="dock-icon">⟲</span>
          <span className="dock-label">СБРОС</span>
        </button>
      </nav>

      <div className="legend">
        <span><i className="dot target" />TARGET</span>
        <span><i className="dot ip" />IP</span>
        <span><i className="dot open" />OPEN</span>
        {counts.udp > 0 && <span><i className="dot udp" />UDP</span>}
        {cves.length > 0 && <span><i className="dot cve" />CVE</span>}
        <span><i className="dot closed" />CLOSED</span>
        <span><i className="dot ns" />DNS</span>
        <span><i className="dot hop" />HOP</span>
        {subdomains.length > 0 && <span><i className="dot sub" />CT</span>}
      </div>

      <div className="reticle">
        <span />
        <span />
        <span />
        <span />
      </div>

      <div className="corner top-left" />
      <div className="corner top-right" />
      <div className="corner bottom-left" />
      <div className="corner bottom-right" />
    </div>
  )
}