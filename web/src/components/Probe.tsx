import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ScanState } from '../types'

const INTERVALS = [
  { value: 2000, label: '2 с' },
  { value: 5000, label: '5 с' },
  { value: 10000, label: '10 с' },
]

const MAX_REQUESTS = 20
const MAX_FAILURES = 3
const TIMEOUT_MS = 8000

const TLS_PORTS = new Set([443, 8443, 9443, 6443])

const schemeFor = (port: number): 'http' | 'https' => (TLS_PORTS.has(port) ? 'https' : 'http')

interface ProbeResult {
  id: number
  ms: number
  ok: boolean
  note: string
  port: number
  scheme: 'http' | 'https'
}

const avg = (values: number[]) =>
  values.length ? Math.round(values.reduce((sum, value) => sum + value, 0) / values.length) : 0

export function Probe({ model }: { model: ScanState }) {
  const host = model.host
  const openPorts = useMemo(() => {
    const found = new Set<number>()
    for (const ip of model.ips) {
      for (const port of Object.values(ip.ports)) {
        if (port.state === 'open' && port.protocol !== 'udp') found.add(port.port)
      }
    }
    return [...found].sort((a, b) => a - b)
  }, [model.ips])

  const [port, setPort] = useState(443)
  const [path, setPath] = useState('/')
  const [interval, setInterval] = useState(5000)
  const [running, setRunning] = useState(false)
  const [sending, setSending] = useState(false)
  const [results, setResults] = useState<ProbeResult[]>([])
  const [nextAt, setNextAt] = useState(Number.MAX_SAFE_INTEGER)
  const [now, setNow] = useState(() => Date.now())
  const [error, setError] = useState<string | null>(null)

  const abortRef = useRef<AbortController | null>(null)
  const inFlight = useRef(false)
  const failures = useRef(0)
  const sent = useRef(0)

  // Track open ports as the scan streams in.
  useEffect(() => {
    if (!openPorts.length || openPorts.includes(port)) return
    setPort(openPorts.includes(443) ? 443 : openPorts[0])
  }, [openPorts, port])

  // A new target resets the probe session.
  useEffect(() => {
    setRunning(false)
    setSending(false)
    setNextAt(Number.MAX_SAFE_INTEGER)
    setResults([])
    setError(null)
    failures.current = 0
    sent.current = 0
    abortRef.current?.abort()
  }, [host])

  useEffect(() => {
    if (!running) return
    const id = window.setInterval(() => setNow(Date.now()), 150)
    return () => window.clearInterval(id)
  }, [running])

  useEffect(() => () => abortRef.current?.abort(), [])

  const scheme = schemeFor(port)
  const mixedContent = window.location.protocol === 'https:' && scheme === 'http'
  const blocked = mixedContent || !host || Boolean(model.demo)

  const fire = useCallback(async () => {
    if (inFlight.current) return
    inFlight.current = true
    setSending(true)
    setNextAt(Number.MAX_SAFE_INTEGER)

    const controller = new AbortController()
    abortRef.current = controller
    let timedOut = false
    const timer = window.setTimeout(() => {
      timedOut = true
      controller.abort()
    }, TIMEOUT_MS)
    const cleanPath = path.trim() || '/'
    const targetScheme = schemeFor(port)
    const url = `${targetScheme}://${host}:${port}${cleanPath.startsWith('/') ? cleanPath : `/${cleanPath}`}${
      cleanPath.includes('?') ? '&' : '?'
    }nm=${Date.now()}`

    const started = performance.now()
    let ok = false
    let note = 'нет ответа'
    let cancelled = false
    try {
      // no-cors keeps the request coming from this browser (the user's IP)
      // and lets it reach hosts that never send CORS headers.
      await fetch(url, {
        mode: 'no-cors',
        cache: 'no-store',
        credentials: 'omit',
        redirect: 'follow',
        referrerPolicy: 'no-referrer',
        signal: controller.signal,
      })
      ok = true
      note = `${targetScheme.toUpperCase()} · ответ получен`
    } catch (err) {
      const aborted = (err as Error)?.name === 'AbortError'
      cancelled = aborted && !timedOut
      note = aborted ? 'таймаут' : 'нет ответа'
    } finally {
      window.clearTimeout(timer)
      inFlight.current = false
      setSending(false)
    }

    // A manual stop aborts the request; do not log it as a failed packet.
    if (cancelled) return

    const ms = Math.max(1, Math.round(performance.now() - started))
    sent.current += 1
    setResults((prev) =>
      [{ id: sent.current, ms, ok, note, port, scheme: targetScheme }, ...prev].slice(0, 8),
    )
    failures.current = ok ? 0 : failures.current + 1

    if (failures.current >= MAX_FAILURES) {
      setRunning(false)
      setError(`${MAX_FAILURES} неудачи подряд — остановил, чтобы не долбить хост.`)
      return
    }
    if (sent.current >= MAX_REQUESTS) {
      setRunning(false)
      setError(`Пауза: ${MAX_REQUESTS} запросов за сессию. Запусти заново, когда решишь продолжить.`)
      return
    }

    setNow(Date.now())
    setNextAt(Date.now() + interval)
  }, [host, port, path, interval])

  useEffect(() => {
    if (!running || blocked || inFlight.current) return
    if (now < nextAt) return
    void fire()
  }, [running, blocked, now, nextAt, fire])

  const start = () => {
    if (blocked) return
    setError(null)
    setResults([])
    failures.current = 0
    sent.current = 0
    setRunning(true)
    setNextAt(Date.now())
    setNow(Date.now())
  }

  const stop = () => {
    setRunning(false)
    setSending(false)
    setNextAt(Number.MAX_SAFE_INTEGER)
    abortRef.current?.abort()
  }

  const fingerprint = useMemo(() => {
    for (const ip of model.ips) {
      const http = ip.httpAll?.find((entry) => entry.port === port) || (ip.http?.port === port ? ip.http : null)
      if (http) return { kind: 'http' as const, http, tls: ip.tls?.port === port ? ip.tls : null }
      if (ip.tls?.port === port) return { kind: 'http' as const, http: null, tls: ip.tls }
    }
    return null
  }, [model.ips, port])

  const times = results.map((result) => result.ms)
  const remaining = running && !sending ? Math.max(0, (nextAt - now) / 1000) : 0
  const progress = running ? (sending ? 1 : Math.min(1, Math.max(0, 1 - remaining / (interval / 1000)))) : 0

  if (!host || model.phase === 'idle') return null

  return (
    <section className="panel probe">
      <div className="panel-head">
        <span>05 / DIRECT PROBE</span>
        <span className="probe-tag">МОЙ IP</span>
      </div>

      <p className="probe-note">
        Запрос уходит из твоего браузера напрямую на хост — с твоего IP, а не с сервера.
      </p>

      <div className="probe-target">
        <span className="probe-host" title={host}>
          {host}
        </span>
        <span className="probe-ip">:{port}</span>
      </div>

      <div className="probe-row">
        <label className="probe-field">
          <span>ПОРТ</span>
          <select
            className="probe-input"
            value={port}
            onChange={(event) => {
              // Stats and the log are tied to one port; start a clean session.
              setPort(Number(event.target.value))
              setResults([])
              setError(null)
              failures.current = 0
              sent.current = 0
            }}
            disabled={running}
          >
            {openPorts.length === 0 && <option value={port}>{port}</option>}
            {openPorts.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        <label className="probe-field grow">
          <span>ПУТЬ</span>
          <input
            className="probe-input"
            value={path}
            onChange={(event) => setPath(event.target.value)}
            spellCheck={false}
            autoComplete="off"
            placeholder="/"
            disabled={running}
          />
        </label>
        <span className={`probe-scheme ${scheme}`}>{scheme.toUpperCase()}</span>
      </div>

      <div className="probe-row">
        <button type="button" className="btn primary probe-start" onClick={start} disabled={running || blocked}>
          {running ? 'ИДЁТ…' : 'ПУСК'}
        </button>
        <button type="button" className="btn danger probe-stop" onClick={stop} disabled={!running}>
          СТОП
        </button>
        <div className="probe-intervals">
          {INTERVALS.map((option) => (
            <button
              key={option.value}
              type="button"
              className={`chip ${interval === option.value ? 'active' : ''}`}
              onClick={() => setInterval(option.value)}
              disabled={running}
              title="Пауза между запросами, чтобы не получить бан по IP"
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      <div className={`probe-timer ${running ? 'live' : ''}`}>
        <span style={{ width: `${progress * 100}%` }} />
        <em>
          {running
            ? sending
              ? 'отправка…'
              : remaining > 0
                ? `следующий через ${remaining.toFixed(1)} с`
                : 'отправка…'
            : `пауза ${interval / 1000} с между запросами`}
        </em>
      </div>

      {mixedContent && (
        <p className="probe-warn">
          Страница открыта по HTTPS, поэтому браузер заблокирует HTTP-запрос на порт {port}. Выбери
          TLS-порт (443, 8443) или запусти сайт локально.
        </p>
      )}
      {model.demo && <p className="probe-warn">В демо-режиме цель не существует — проба отключена.</p>}
      {error && <p className="probe-warn">{error}</p>}

      <div className="probe-stats">
        <div>
          <b>{results[0] ? results[0].ms : '—'}</b>
          <span>ПОСЛ, МС</span>
        </div>
        <div>
          <b>{times.length ? avg(times) : '—'}</b>
          <span>СРЕД</span>
        </div>
        <div>
          <b>{times.length ? Math.min(...times) : '—'}</b>
          <span>МИН</span>
        </div>
        <div>
          <b>{times.length ? Math.max(...times) : '—'}</b>
          <span>МАКС</span>
        </div>
        <div>
          <b>{sent.current}</b>
          <span>ПАКЕТОВ</span>
        </div>
      </div>

      {results.length > 0 ? (
        <div className="probe-log">
          {results.map((result) => (
            <div className={`probe-result ${result.ok ? 'ok' : 'bad'}`} key={result.id}>
              <span className="n">#{String(result.id).padStart(2, '0')}</span>
              <span className="ms">{result.ms} мс</span>
              <span className="port">:{result.port}</span>
              <span className="note">{result.note}</span>
            </div>
          ))}
        </div>
      ) : (
        <div className="probe-empty">
          {running ? '// ожидание первого ответа' : '// нажми ПУСК — запросы пойдут с твоего IP'}
        </div>
      )}

      {fingerprint && (
        <div className="probe-fingerprint">
          <span className="k">ИЗ СКАНА · :{port}</span>
          {fingerprint.http ? (
            <>
              <span className="v">
                HTTP {fingerprint.http.status ?? '—'}
                {fingerprint.http.server ? ` · ${fingerprint.http.server}` : ''}
              </span>
              {fingerprint.http.title && <span className="t">{fingerprint.http.title}</span>}
            </>
          ) : fingerprint.tls ? (
            <span className="v">
              TLS {fingerprint.tls.protocol || ''} · {fingerprint.tls.issuer || 'certificate'}
            </span>
          ) : null}
        </div>
      )}

      <p className="probe-legal">
        Браузер не показывает тело ответа чужого сайта — статус и заголовки берутся из скана выше.
      </p>
    </section>
  )
}