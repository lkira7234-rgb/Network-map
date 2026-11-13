import { FormEvent, useEffect, useRef, useState } from 'react'
import { ScanState, Selection } from '../types'
import { getSelectionDetails, portCounts } from '../model'

export interface ScanFormValues {
  target: string
  ports: string
  traceroute: boolean
  geo: boolean
}

interface HudProps {
  model: ScanState
  selection: Selection
  hover: string | null
  mode: 'orbit' | 'fly'
  scanning: boolean
  onSelect: (selection: Selection) => void
  onScan: (values: ScanFormValues) => void
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
  selection,
  hover,
  mode,
  scanning,
  onSelect,
  onScan,
  onDemo,
  onStop,
  onToggleMode,
  onResetCamera,
}: HudProps) {
  const [target, setTarget] = useState('github.com')
  const [ports, setPorts] = useState('22,80,443,8080,8443')
  const [traceroute, setTraceroute] = useState(true)
  const [geo, setGeo] = useState(true)
  const [, tick] = useState(0)
  const [mobileTab, setMobileTab] = useState<'scan' | 'telemetry' | 'inspect'>('scan')
  const [sheetOpen, setSheetOpen] = useState(true)

  const logRef = useRef<HTMLDivElement>(null)
  const errorRef = useRef<HTMLDivElement>(null)
  const details = getSelectionDetails(model, selection)
  const counts = portCounts(model)
  const primary = model.ips.find((ip) => ip.primary) || model.ips[0]

  useEffect(() => {
    if (model.phase !== 'scanning') return
    const id = window.setInterval(() => tick((value) => value + 1), 300)
    return () => window.clearInterval(id)
  }, [model.phase])

  useEffect(() => {
    const el = logRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [model.logs.length])

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

  const submit = (event: FormEvent) => {
    event.preventDefault()
    const value = target.trim()
    if (!value) return
    onScan({ target: value, ports, traceroute, geo })
    setSheetOpen(false)
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
            <span className={`status-dot ${model.phase}`} />
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
          </section>
        )}
      </aside>

      <aside className="right-col">
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
            <div className="stat open">
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

      <div className="bottom-bar">
        <div className="mode-group">
          <button type="button" className={`mode-btn ${mode === 'fly' ? 'active' : ''}`} onClick={onToggleMode}>
            {mode === 'fly' ? '✈ ПОЛЁТ АКТИВЕН' : '✈ СВОБОДНЫЙ ПОЛЁТ'}
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
        <span><i className="dot closed" />CLOSED</span>
        <span><i className="dot ns" />DNS</span>
        <span><i className="dot hop" />HOP</span>
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