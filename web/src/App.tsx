import { useCallback, useEffect, useReducer, useRef, useState } from 'react'
import { Scene } from './components/Scene'
import { Hud } from './components/Hud'
import { initialState } from './types'
import { scanReducer } from './model'
import { RateLimitInfo, streamDemo, streamScan } from './api'
import { DEFAULT_FORM, ScanFormValues, formFromUrl, formToUrl } from './form'
import { ScanEvent, Selection } from './types'

const errorMessage = (error: unknown) => {
  if (error instanceof Error) return error.message
  return 'Неизвестная ошибка'
}

export function App() {
  const [model, dispatch] = useReducer(scanReducer, initialState)
  const [selection, setSelection] = useState<Selection>(null)
  const [hover, setHover] = useState<string | null>(null)
  const [mode, setMode] = useState<'orbit' | 'fly'>('orbit')
  const [resetSignal, setResetSignal] = useState(0)
  const [rateLimit, setRateLimit] = useState<RateLimitInfo | null>(null)
  const [initial] = useState<ScanFormValues>(
    () => formFromUrl(window.location.search) || DEFAULT_FORM,
  )

  const bufferRef = useRef<ScanEvent[]>([])
  const timerRef = useRef<number | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const runIdRef = useRef(0)
  const bootedRef = useRef(false)

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
      if (timerRef.current != null) window.clearTimeout(timerRef.current)
    }
  }, [])

  const begin = useCallback((target: string, demo: boolean) => {
    abortRef.current?.abort()
    const id = ++runIdRef.current
    const controller = new AbortController()
    abortRef.current = controller
    bufferRef.current = []
    if (timerRef.current != null) {
      window.clearTimeout(timerRef.current)
      timerRef.current = null
    }
    setSelection(null)
    setHover(null)
    dispatch({ type: 'begin', target, demo })
    return { id, controller }
  }, [])

  const runScan = useCallback(
    async (values: ScanFormValues) => {
      // Keep the address bar in sync so the result can be shared as a link.
      try {
        window.history.replaceState(null, '', formToUrl(values))
      } catch {}
      const { id, controller } = begin(values.target, false)
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
    const { id, controller } = begin('core.neotokyo.net', true)
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
      setSelection(null)
      setHover(null)
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

  const stop = useCallback(() => {
    runIdRef.current++
    abortRef.current?.abort()
    abortRef.current = null
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
      const target = event.target as HTMLElement | null
      if (target && ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)) return
      if (event.code === 'Escape' && mode === 'fly') {
        document.exitPointerLock?.()
        setMode('orbit')
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [mode])

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
      />
      <Hud
        model={model}
        initial={initial}
        rateLimit={rateLimit}
        selection={selection}
        hover={hover}
        mode={mode}
        scanning={model.phase === 'scanning'}
        onSelect={setSelection}
        onScan={runScan}
        onImport={importScan}
        onDemo={runDemo}
        onStop={stop}
        onToggleMode={toggleMode}
        onResetCamera={resetCamera}
      />
    </div>
  )
}