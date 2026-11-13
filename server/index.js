import express from 'express'
import path from 'node:path'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'
import { runScan } from './scan.js'
import { runDemo } from './demo.js'
import { createRateLimiter } from './rate-limit.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const distDir = path.resolve(__dirname, '..', 'dist')
const PORT = Number(process.env.PORT) || 8787
const HOST = process.env.HOST || '127.0.0.1'

const MAX_ACTIVE_SCANS = Math.max(1, Number(process.env.MAX_ACTIVE_SCANS) || 4)
const SCAN_LIMIT = Math.max(1, Number(process.env.SCAN_LIMIT) || 3)
const SCAN_WINDOW_MS = Math.max(1_000, Number(process.env.SCAN_WINDOW_MS) || 60_000)
const DEMO_LIMIT = Math.max(1, Number(process.env.DEMO_LIMIT) || 10)

const scanLimiter = createRateLimiter({ limit: SCAN_LIMIT, windowMs: SCAN_WINDOW_MS })
const demoLimiter = createRateLimiter({ limit: DEMO_LIMIT, windowMs: SCAN_WINDOW_MS })

const app = express()
app.disable('x-powered-by')
// Render terminates TLS in front of the app; trust its proxy header so req.ip
// is the real client. Direct connections cannot spoof X-Forwarded-For locally.
const TRUST_PROXY = process.env.TRUST_PROXY
  ? (/^\d+$/.test(process.env.TRUST_PROXY) ? Number(process.env.TRUST_PROXY) : process.env.TRUST_PROXY)
  : process.env.RENDER
    ? 1
    : 'loopback'
app.set('trust proxy', TRUST_PROXY)
app.use(express.json({ limit: '32kb' }))

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  next()
})

// Optional cross-origin access when the UI is hosted separately from the API.
// Comma-separated list, e.g. CORS_ORIGIN=https://user.github.io
const CORS_ORIGIN = process.env.CORS_ORIGIN || ''
if (CORS_ORIGIN) {
  const allowed = new Set(CORS_ORIGIN.split(',').map((value) => value.trim()).filter(Boolean))
  app.use((req, res, next) => {
    const origin = req.headers.origin
    if (origin && (allowed.has('*') || allowed.has(origin))) {
      res.setHeader('Access-Control-Allow-Origin', allowed.has('*') ? '*' : origin)
      res.setHeader('Vary', 'Origin')
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
      res.setHeader('Access-Control-Max-Age', '86400')
    }
    if (req.method === 'OPTIONS') {
      res.sendStatus(204)
      return
    }
    next()
  })
}

/* ------------------------------------------------------------------ */
/*  streaming helpers                                                  */
/* ------------------------------------------------------------------ */

async function streamNdjson(res, run) {
  res.status(200)
  res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8')
  res.setHeader('Cache-Control', 'no-cache, no-transform')
  res.setHeader('X-Accel-Buffering', 'no')
  res.setHeader('Connection', 'keep-alive')
  res.flushHeaders?.()

  const controller = new AbortController()
  let closed = false

  const emit = (event) => {
    if (closed) return
    try {
      res.write(JSON.stringify(event) + '\n')
    } catch {
      closed = true
      controller.abort()
    }
  }

  const onClose = () => {
    if (!res.writableEnded) {
      closed = true
      controller.abort()
    }
  }
  res.on('close', onClose)

  try {
    await run(emit, controller.signal)
  } catch (err) {
    if (!closed) {
      emit({
        type: 'fatal',
        message: err?.message ? String(err.message) : 'Неизвестная ошибка сканирования',
      })
    }
  } finally {
    res.off('close', onClose)
    if (!closed) {
      try {
        res.end()
      } catch {}
    }
  }
}

/* ------------------------------------------------------------------ */
/*  API                                                                */
/* ------------------------------------------------------------------ */

let activeScans = 0

function sendRateLimited(res, retryAfter) {
  res.setHeader('Retry-After', String(retryAfter))
  res.status(429).json({
    error: `Слишком много сканирований. Попробуй через ${retryAfter} с.`,
  })
}

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    service: 'network-map',
    time: new Date().toISOString(),
    platform: process.platform,
    activeScans,
  })
})

app.post('/api/scan', async (req, res) => {
  const target = typeof req.body?.target === 'string' ? req.body.target.trim() : ''
  if (!target) {
    res.status(400).json({ error: 'Укажи домен или IP-адрес' })
    return
  }

  const limit = scanLimiter.take(req.ip)
  if (!limit.ok) {
    sendRateLimited(res, limit.retryAfter)
    return
  }

  if (activeScans >= MAX_ACTIVE_SCANS) {
    res.status(429).json({ error: 'Слишком много одновременных сканирований. Попробуй чуть позже.' })
    return
  }

  activeScans++
  try {
    await streamNdjson(res, (emit, signal) =>
      runScan(
        {
          target,
          ports: req.body?.ports,
          traceroute: req.body?.traceroute !== false,
          geo: req.body?.geo !== false,
          timeout: req.body?.timeout,
        },
        emit,
        signal,
      ),
    )
  } finally {
    activeScans--
  }
})

app.get('/api/demo', async (req, res) => {
  const limit = demoLimiter.take(req.ip)
  if (!limit.ok) {
    sendRateLimited(res, limit.retryAfter)
    return
  }
  await streamNdjson(res, (emit, signal) => runDemo(emit, signal))
})

/* ------------------------------------------------------------------ */
/*  static frontend                                                    */
/* ------------------------------------------------------------------ */

if (fs.existsSync(distDir)) {
  app.use(express.static(distDir, { maxAge: '1h', index: false }))

  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api/')) return next()
    const indexFile = path.join(distDir, 'index.html')
    if (!fs.existsSync(indexFile)) return next()
    res.sendFile(indexFile)
  })
}

app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    res.status(404).json({ error: 'API endpoint not found' })
  } else {
    res
      .status(404)
      .type('text/plain')
      .send('Network Map interface is not built yet. Run: npm run build')
  }
})

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err)
  res.status(err?.status || 500).json({ error: err?.message || 'Internal error' })
})

app.listen(PORT, HOST, () => {
  console.log(`\n  NETWORK//MAP server  →  http://${HOST}:${PORT}`)
  console.log(`  API                 →  POST /api/scan · GET /api/demo`)
  console.log(`  Limits              →  ${SCAN_LIMIT} scans/${Math.round(SCAN_WINDOW_MS / 1000)}s per IP · ${MAX_ACTIVE_SCANS} concurrent\n`)
})