import { useCallback, useEffect, useReducer, useRef, useState } from 'react'
import { Scene } from './components/Scene'
import { Hud } from './components/Hud'
import { Spotlight } from './components/Spotlight'
import { initialState } from './types'
import { scanReducer } from './model'
import { RateLimitInfo, GarbageKind, GarbagePick, fetchGarbage, fetchSubdomains, streamDemo, streamScan } from './api'
import { DEFAULT_FORM, ScanFormValues, formFromUrl, formToUrl } from './form'
import { ScanEvent, ScanState, Selection, SubdomainInfo, SubdomainState } from './types'
import { ClusterMode } from './layout'
import { HistoryResult, clearHistory, recordScan } from './history'
import { SearchResult } from './search'
import { audio } from './audio'

const errorMessage = (error: unknown) => {
  if (error instanceof Error) return error.message
  return 'Неизвестная ошибка'
}

export interface GarbageState {
  status: 'idle' | 'picking' | 'ok' | 'error'
  message: string
  target?: string
}

const formatBytes = (value?: number) => {
  if (!value || !Number.isFinite(value)) return null
  return value >= 1024 ? `${(value / 1024).toFixed(1)} КБ` : `${Math.round(value)} Б`
}

function describeGarbage(pick: GarbagePick) {
  const verify = pick.verify || {}
  if (pick.kind === 'dns') {
    const domain = verify.domain ? ` · домен ${verify.domain}` : ''
    return `живой DNS ${pick.target}${domain}${verify.tcp53 ? ' · 53/tcp открыт' : ''}`
  }
  if (pick.kind === 'ip') {
    const source = verify.domain ? ` · ${verify.domain}` : ''
    const port = verify.port ? ` · открыт ${verify.port}/tcp` : ''
    return `живой IP ${pick.target}${source}${port}`
  }
  const size = formatBytes(verify.bytes)
  const title = verify.title ? ` · «${verify.title}»` : ''
  return `живой сайт ${pick.target}${verify.http ? ` · HTTP ${verify.http}` : ''}${
    size ? ` · ${size}` : ''
  }${title}`
}

const cleanHost = (value: string) =>
  value
    .trim()
    .toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
    .replace(/[/?#].*$/, '')
    .replace(/:\d+$/, '')
    .replace(/\.$/, '')

const isIp = (value: string) => /^[0-9.]+$/.test(value) || value.includes(':')

/**
 * Names that are already confirmed by the certificate the scanner fetched.
 * crt.sh is often slow or down, so these are shown even without the lookup.
 */
function certificateNames(model: ScanState, host: string): SubdomainInfo[] {
  const found = new Map<string, SubdomainInfo>()
  for (const ip of model.ips) {
    for (const raw of ip.tls?.altNames || []) {
      const name = String(raw)
        .trim()
        .toLowerCase()
        .replace(/^\*\./, '')
        .replace(/\.$/, '')
      if (!name || name === host || !name.endsWith(`.${host}`)) continue
      if (!/^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9])?)+$/.test(name)) continue
      found.set(name, { name, fromCertificate: true })
    }
  }
  return [...found.values()]
}

function mergeSubdomains(primary: SubdomainInfo[], extra: SubdomainInfo[]): SubdomainInfo[] {
  const merged = new Map<string, SubdomainInfo>()
  for (const item of primary) merged.set(item.name, item)
  for (const item of extra) {
    const current = merged.get(item.name)
    merged.set(item.name, current ? { ...current, fromCertificate: item.fromCertificate } : item)
  }
  return [...merged.values()].sort(
    (a, b) =>
      a.name.split('.').length - b.name.split('.').length || a.name.localeCompare(b.name),
  )
}

export function App() {
  const [model, dispatch] = useReducer(scanReducer, initialState)
  const [selection, setSelection] = useState<Selection>(null)
  const [hover, setHover] = useState<string | null>(null)
  const [mode, setMode] = useState<'orbit' | 'fly'>('orbit')
  const [resetSignal, setResetSignal] = useState(0)
  const [rateLimit, setRateLimit] = useState<RateLimitInfo | null>(null)
  const [cluster, setCluster] = useState<ClusterMode>('none')
  const [subdomains, setSubdomains] = useState<SubdomainInfo[]>([])
  const [subState, setSubState] = useState<SubdomainState>({ status: 'idle', message: '' })
  const [focusIps, setFocusIps] = useState<string[]>([])
  const [focusSignal, setFocusSignal] = useState(0)
  const [spotlightOpen, setSpotlightOpen] = useState(false)
  const [history, setHistory] = useState<HistoryResult | null>(null)
  const [garbage, setGarbage] = useState<GarbageState>({ status: 'idle', message: '' })
  const [soundOn, setSoundOn] = useState(() => audio.readPreference())
  const [trashMode, setTrashMode] = useState(false)
  const [warpSignal, setWarpSignal] = useState(0)
  const [initial] = useState<ScanFormValues>(
    () => formFromUrl(window.location.search) || DEFAULT_FORM,
  )

  const bufferRef = useRef<ScanEvent[]>([])
  const timerRef = useRef<number | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const garbageAbortRef = useRef<AbortController | null>(null)
  const subAbortRef = useRef<AbortController | null>(null)
  const warpTimerRef = useRef<number | null>(null)
  const openPortsRef = useRef(0)
  const portSoundAtRef = useRef(0)
  const alarmRef = useRef(false)
  const runIdRef = useRef(0)
  const bootedRef = useRef(false)
  const lastFormRef = useRef<ScanFormValues>(initial)
  const hostRef = useRef('')
  const recordedRef = useRef('')
  const modelRef = useRef(model)
  modelRef.current = model

  const flush = useCallback(() => {
    timerRef.current = null
    if (!bufferRef.current.length) return
    const events = bufferRef.current
    bufferRef.current = []
    dispatch({ type: 'events', events })
  }, [])

  const enqueue = useCallback(
    (event: ScanEvent) => {
      bufferRef.current.push(event)
      if (timerRef.current == null) {
        timerRef.current = window.setTimeout(flush, 55)
      }
    },
    [flush],
  )

  const flushNow = useCallback(() => {
    if (timerRef.current != null) {
      window.clearTimeout(timerRef.current)
      timerRef.current = null
    }
    flush()
  }, [flush])

  useEffect(() => {
    return () => {
      abortRef.current?.abort()
      garbageAbortRef.current?.abort()
      subAbortRef.current?.abort()
      if (timerRef.current != null) window.clearTimeout(timerRef.current)
      if (warpTimerRef.current != null) window.clearTimeout(warpTimerRef.current)
    }
  }, [])

  // Sound preference is persisted by the engine and applied on mount.
  useEffect(() => {
    audio.setEnabled(soundOn)
  }, [soundOn])

  // UI feedback: node clicks, newly opened ports and high-severity findings.
  useEffect(() => {
    if (selection) audio.play('click')
  }, [selection])

  useEffect(() => {
    if (model.phase === 'scanning' || model.phase === 'done') {
      const open = model.ips.reduce(
        (total, ip) => total + Object.values(ip.ports).filter((port) => port.state === 'open').length,
        0,
      )
      if (open > openPortsRef.current) {
        // Streamed ports arrive in bursts; throttle the blip instead of playing
        // one tone per port on a 1000-port scan.
        const now = Date.now()
        if (now - portSoundAtRef.current > 320) {
          audio.play('port')
          portSoundAtRef.current = now
        }
      }
      openPortsRef.current = open
    } else if (model.phase === 'idle') {
      openPortsRef.current = 0
      portSoundAtRef.current = 0
      alarmRef.current = false
    }
  }, [model.phase, model.ips])

  const begin = useCallback((target: string, demo: boolean, keepSubdomains = false) => {
    abortRef.current?.abort()
    const id = ++runIdRef.current
    const controller = new AbortController()
    abortRef.current = controller
    bufferRef.current = []
    if (timerRef.current != null) {
      window.clearTimeout(timerRef.current)
      timerRef.current = null
    }
    const host = cleanHost(target)
    if (!keepSubdomains) {
      subAbortRef.current?.abort()
      setSubdomains([])
      setSubState({ status: 'idle', message: '' })
    }
    hostRef.current = host
    openPortsRef.current = 0
    portSoundAtRef.current = 0
    setSelection(null)
    setHover(null)
    setFocusIps([])
    setHistory(null)
    recordedRef.current = ''
    dispatch({ type: 'begin', target, demo })
    return { id, controller }
  }, [])

  const runScan = useCallback(
    async (values: ScanFormValues, options?: { keepSubdomains?: boolean }) => {
      lastFormRef.current = values
      // Keep the address bar in sync so the result can be shared as a link.
      try {
        window.history.replaceState(null, '', formToUrl(values))
      } catch {}
      const { id, controller } = begin(values.target, false, options?.keepSubdomains)
      try {
        await streamScan(
          values,
          (event) => {
            if (runIdRef.current === id) enqueue(event)
          },
          controller.signal,
          setRateLimit,
        )
      } catch (error) {
        if ((error as Error)?.name !== 'AbortError' && runIdRef.current === id) {
          dispatch({ type: 'fail', message: errorMessage(error) })
        }
      } finally {
        if (runIdRef.current === id) flushNow()
      }
    },
    [begin, enqueue, flushNow],
  )

  const runDemo = useCallback(async () => {
    const form = { ...DEFAULT_FORM, target: 'core.neotokyo.net' }
    lastFormRef.current = form
    const { id, controller } = begin(form.target, true)
    try {
      await streamDemo((event) => {
        if (runIdRef.current === id) enqueue(event)
      }, controller.signal)
    } catch (error) {
      if ((error as Error)?.name !== 'AbortError' && runIdRef.current === id) {
        dispatch({ type: 'fail', message: errorMessage(error) })
      }
    } finally {
      if (runIdRef.current === id) flushNow()
    }
  }, [begin, enqueue, flushNow])

  const runGarbage = useCallback(
    async (kind: GarbageKind) => {
      garbageAbortRef.current?.abort()
      const controller = new AbortController()
      garbageAbortRef.current = controller
      if (warpTimerRef.current != null) {
        window.clearTimeout(warpTimerRef.current)
        warpTimerRef.current = null
      }
      setTrashMode(true)
      setGarbage({
        status: 'picking',
        message:
          kind === 'auto'
            ? 'Ищу случайную живую цель — сайт, DNS или IP…'
            : `Ищу живую цель: ${
                kind === 'site' ? 'сайт без заглушки' : kind === 'dns' ? 'DNS-сервер' : 'публичный IP'
              }…`,
      })
      try {
        const pick = await fetchGarbage(kind, controller.signal)
        if (garbageAbortRef.current !== controller) return
        if (!pick.ok || !pick.target) {
          setTrashMode(false)
          setGarbage({
            status: 'error',
            message: pick.error || 'Не нашёл живую цель. Попробуй ещё раз.',
          })
          return
        }
        setGarbage({ status: 'ok', message: describeGarbage(pick), target: pick.target })
        // Cinematic warp runs while the new scan starts streaming.
        audio.play('warp')
        setWarpSignal((value) => value + 1)
        warpTimerRef.current = window.setTimeout(() => {
          warpTimerRef.current = null
          setTrashMode(false)
        }, 2900)
        const values = { ...lastFormRef.current, target: pick.target }
        lastFormRef.current = values
        await runScan(values)
      } catch (error) {
        if ((error as Error)?.name === 'AbortError') return
        if (garbageAbortRef.current !== controller) return
        setTrashMode(false)
        setGarbage({ status: 'error', message: errorMessage(error) })
      } finally {
        if (garbageAbortRef.current === controller) garbageAbortRef.current = null
      }
    },
    [runScan],
  )

  const importScan = useCallback(
    (events: ScanEvent[], target: string) => {
      runIdRef.current++
      abortRef.current?.abort()
      abortRef.current = null
      bufferRef.current = []
      if (timerRef.current != null) {
        window.clearTimeout(timerRef.current)
        timerRef.current = null
      }
      lastFormRef.current = { ...lastFormRef.current, target }
      hostRef.current = cleanHost(target)
      subAbortRef.current?.abort()
      setSubdomains([])
      setSubState({ status: 'idle', message: '' })
      setSelection(null)
      setHover(null)
      setFocusIps([])
      setHistory(null)
      recordedRef.current = ''
      dispatch({ type: 'import', target, events })
    },
    [],
  )

  // A shared link (?target=...) starts scanning on its own.
  useEffect(() => {
    if (bootedRef.current) return
    bootedRef.current = true
    if (!formFromUrl(window.location.search)) return
    runScan(initial)
  }, [initial, runScan])

  // Certificate names can be extracted from the scan itself, without crt.sh.
  useEffect(() => {
    if (model.phase !== 'done' || !model.host || model.ips.length === 0) return
    const host = cleanHost(model.host)
    if (!host || isIp(host)) return
    const cert = certificateNames(model, host)
    if (cert.length) {
      setSubdomains((current) => mergeSubdomains(current, cert))
    }
  }, [model.phase, model.host, model.ips])

  // Local history / diff: saved once per completed scan.
  useEffect(() => {
    if (model.phase !== 'done' || model.ips.length === 0) return
    const key = `${model.host}|${model.startedAt}|${model.demo}`
    if (recordedRef.current === key) return
    recordedRef.current = key
    void recordScan(modelRef.current).then((result) => {
      if (result) setHistory(result)
    })
  }, [model.phase, model.host, model.startedAt, model.demo, model.ips.length])

  const findSubdomains = useCallback(async () => {
    const host = cleanHost(modelRef.current.host || modelRef.current.target || '')
    if (!host) {
      setSubState({ status: 'error', message: 'Сначала запусти скан домена.' })
      return
    }
    if (isIp(host)) {
      setSubState({
        status: 'error',
        message: 'Для IP поддоменов нет. TLS SAN из сертификата показан в инспекторе.',
      })
      return
    }
    subAbortRef.current?.abort()
    const controller = new AbortController()
    subAbortRef.current = controller
    hostRef.current = host
    setSubState({ status: 'loading', message: 'Запрашиваю Certificate Transparency (crt.sh)…' })
    try {
      const data = await fetchSubdomains(host, controller.signal)
      if (hostRef.current !== host) return
      const cert = certificateNames(modelRef.current, host)
      const list = mergeSubdomains(
        data.subdomains.map((name) => ({ name, fromCertificate: cert.some((item) => item.name === name) })),
        cert,
      )
      setSubdomains(list)
      setSubState({
        status: 'ok',
        message: list.length
          ? `${list.length} имён из CT${data.truncated ? ' · показаны первые 200' : ''}${
              data.cached ? ' · из кэша' : ''
            }`
          : 'crt.sh не нашёл имён. Проверь TLS SAN в инспекторе.',
      })
    } catch (error) {
      if ((error as Error)?.name === 'AbortError') return
      if (hostRef.current !== host) return
      setSubState({ status: 'error', message: errorMessage(error) })
    }
  }, [])

  const scanSubdomain = useCallback(
    (name: string) => {
      const values: ScanFormValues = { ...lastFormRef.current, target: name }
      void runScan(values, { keepSubdomains: true })
    },
    [runScan],
  )

  const clearFocus = useCallback(() => setFocusIps([]), [])

  const openSpotlight = useCallback(() => {
    if (mode === 'fly') {
      document.exitPointerLock?.()
      setMode('orbit')
    }
    setSpotlightOpen(true)
  }, [mode])

  const pickSearch = useCallback((result: SearchResult) => {
    setSelection(result.selection)
    setFocusIps(result.ips)
    if (result.ips.length) setFocusSignal((value) => value + 1)
  }, [])

  const resetHistory = useCallback(() => {
    void clearHistory().then(() => setHistory(null))
  }, [])

  const stop = useCallback(() => {
    runIdRef.current++
    abortRef.current?.abort()
    abortRef.current = null
    garbageAbortRef.current?.abort()
    garbageAbortRef.current = null
    if (warpTimerRef.current != null) {
      window.clearTimeout(warpTimerRef.current)
      warpTimerRef.current = null
    }
    setTrashMode(false)
    flushNow()
    dispatch({ type: 'cancel' })
  }, [flushNow])

  const toggleMode = useCallback(() => {
    setMode((current) => {
      if (current === 'fly') {
        document.exitPointerLock?.()
        return 'orbit'
      }
      const canvas = document.querySelector<HTMLCanvasElement>('#scene canvas')
      canvas?.requestPointerLock?.()
      return 'fly'
    })
  }, [])

  const exitFly = useCallback(() => setMode('orbit'), [])
  const resetCamera = useCallback(() => setResetSignal((value) => value + 1), [])

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        openSpotlight()
        return
      }
      const target = event.target as HTMLElement | null
      if (target && ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)) return
      if (event.code === 'Escape' && mode === 'fly') {
        document.exitPointerLock?.()
        setMode('orbit')
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [mode, openSpotlight])

  return (
    <div className="app">
      <Scene
        model={model}
        selection={selection}
        onSelect={setSelection}
        onHover={setHover}
        mode={mode}
        onExitFly={exitFly}
        resetSignal={resetSignal}
        cluster={cluster}
        subdomains={subdomains}
        focusIps={focusIps}
        focusSignal={focusSignal}
        onScanSubdomain={scanSubdomain}
        trashMode={trashMode}
        warpSignal={warpSignal}
      />
      <Hud
        model={model}
        initial={initial}
        rateLimit={rateLimit}
        selection={selection}
        hover={hover}
        mode={mode}
        scanning={model.phase === 'scanning'}
        cluster={cluster}
        onCluster={setCluster}
        subdomains={subdomains}
        subState={subState}
        onFindSubdomains={findSubdomains}
        onScanSubdomain={scanSubdomain}
        focusIps={focusIps}
        onClearFocus={clearFocus}
        onOpenSpotlight={openSpotlight}
        history={history}
        onClearHistory={resetHistory}
        onSelect={setSelection}
        onScan={runScan}
        onImport={importScan}
        onDemo={runDemo}
        onStop={stop}
        onToggleMode={toggleMode}
        onResetCamera={resetCamera}
        garbage={garbage}
        onGarbage={runGarbage}
        soundOn={soundOn}
        onToggleSound={() => setSoundOn((value) => !value)}
      />
      <Spotlight
        open={spotlightOpen}
        model={model}
        onClose={() => setSpotlightOpen(false)}
        onPick={pickSearch}
      />
    </div>
  )
}
