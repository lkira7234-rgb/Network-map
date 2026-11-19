import express from 'express'
import path from 'node:path'
import fs from 'node:fs'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { runScan, normalizeTarget } from './scan.js'
import { runDemo } from './demo.js'
import { createMonitor } from './monitor.js'
import { createTelegramBot } from './bot.js'
import { createGarbage } from './garbage.js'
import { createRateLimiter } from './rate-limit.js'
import { createStore } from './store.js'
import { createReputation } from './reputation.js'
import { createPreview } from './preview.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const distDir = path.resolve(__dirname, '..', 'dist')
const PORT = Number(process.env.PORT) || 8787
// Render sets RENDER=true and routes traffic to the container, so it must bind
// to all interfaces even if HOST is not explicitly configured.
const HOST = process.env.HOST || (process.env.RENDER ? '0.0.0.0' : '127.0.0.1')

const MAX_ACTIVE_SCANS = Math.max(1, Number(process.env.MAX_ACTIVE_SCANS) || 4)
const SCAN_LIMIT = Math.max(1, Number(process.env.SCAN_LIMIT) || 3)
const SCAN_WINDOW_MS = Math.max(1_000, Number(process.env.SCAN_WINDOW_MS) || 60_000)
const DEMO_LIMIT = Math.max(1, Number(process.env.DEMO_LIMIT) || 10)

const scanLimiter = createRateLimiter({ limit: SCAN_LIMIT, windowMs: SCAN_WINDOW_MS })
const demoLimiter = createRateLimiter({ limit: DEMO_LIMIT, windowMs: SCAN_WINDOW_MS })
const subLimiter = createRateLimiter({ limit: 20, windowMs: SCAN_WINDOW_MS })
const garbageLimiter = createRateLimiter({
  limit: Math.max(1, Number(process.env.GARBAGE_LIMIT) || 12),
  windowMs: SCAN_WINDOW_MS,
})
const previewLimiter = createRateLimiter({ limit: 8, windowMs: SCAN_WINDOW_MS })
const reputationLimiter = createRateLimiter({ limit: 30, windowMs: SCAN_WINDOW_MS })
const MAX_ACTIVE_PICKS = Math.max(1, Number(process.env.MAX_ACTIVE_PICKS) || 3)

const store = createStore()
const reputation = createReputation(process.env, store)
const preview = createPreview(process.env, store)
const MONITOR_TOKEN = String(process.env.MONITOR_TOKEN || '').trim()

// crt.sh is slow and rate-sensitive, so a short server-side cache keeps repeat
// lookups instant and polite.
const subCache = new Map()
const SUB_CACHE_MS = 10 * 60_000
const SUB_MAX = 200

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
      res.setHeader('Access-Control-Expose-Headers', 'RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset, Retry-After')
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

// Standard RateLimit-* headers so the UI can show the remaining quota instead
// of failing with an opaque 429.
function setRateLimitHeaders(res, limit) {
  res.setHeader('RateLimit-Limit', String(limit.limit))
  res.setHeader('RateLimit-Remaining', String(limit.remaining))
  res.setHeader('RateLimit-Reset', String(limit.resetAfter))
}

function sendRateLimited(res, limit) {
  setRateLimitHeaders(res, limit)
  res.setHeader('Retry-After', String(limit.retryAfter))
  res.status(429).json({
    error: `Слишком много сканирований. Попробуй через ${limit.retryAfter} с.`,
    retryAfter: limit.retryAfter,
  })
}

/* ------------------------------------------------------------------ */
/*  monitor auth                                                       */
/* ------------------------------------------------------------------ */

/**
 * Constant-time comparison for the operator token. An empty MONITOR_TOKEN
 * disables the management endpoints entirely (they answer 404, like any
 * unknown route) so a misconfigured deploy never exposes them publicly.
 */
function monitorAuthorized(req) {
  if (!MONITOR_TOKEN) return false
  const provided = Buffer.from(String(req.get('x-monitor-token') || ''))
  const expected = Buffer.from(MONITOR_TOKEN)
  if (provided.length !== expected.length) return false
  return crypto.timingSafeEqual(provided, expected)
}

function requireMonitorToken(req, res) {
  if (monitorAuthorized(req)) return true
  res.status(404).json({ error: 'API endpoint not found' })
  return false
}

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    service: 'network-map',
    time: new Date().toISOString(),
    platform: process.platform,
    activeScans,
    storage: store.kind,
    preview: preview.publicStatus().available,
  })
})

app.post('/api/scan', async (req, res) => {
  const target = typeof req.body?.target === 'string' ? req.body.target.trim() : ''
  if (!target) {
    res.status(400).json({ error: 'Укажи домен или IP-адрес' })
    return
  }

  // Reject malformed targets before spending the client's rate-limit slot.
  try {
    normalizeTarget(target)
  } catch (err) {
    res.status(400).json({ error: err?.message || 'Некорректная цель' })
    return
  }

  const limit = scanLimiter.take(req.ip)
  setRateLimitHeaders(res, limit)
  if (!limit.ok) {
    sendRateLimited(res, limit)
    return
  }

  if (activeScans >= MAX_ACTIVE_SCANS) {
    res.setHeader('Retry-After', '5')
    res.status(429).json({ error: 'Слишком много одновременных сканирований. Попробуй чуть позже.' })
    return
  }

  activeScans++
  const observed = { nodes: new Set(), ports: new Set(), hops: new Set(), labels: {}, done: false }
  try {
    await streamNdjson(res, async (emit, signal) => {
      const reputationJobs = []
      const reputationAsked = new Set()
      await runScan(
        {
          target,
          ports: req.body?.ports,
          traceroute: req.body?.traceroute !== false,
          geo: req.body?.geo !== false,
          udp: req.body?.udp === true,
          timeout: req.body?.timeout,
        },
        (event) => {
          if (event.type === 'ip' && event.ip) observed.nodes.add(String(event.ip))
          else if (event.type === 'hop' && event.ip) {
            observed.hops.add(`${event.index} · ${event.ip}`)
          } else if (event.type === 'port' && event.state === 'open') {
            const key = `${event.ip}:${event.port}/${event.protocol || 'tcp'}`
            observed.ports.add(key)
            observed.labels[key] = event.service || 'unknown'
          } else if (event.type === 'done') observed.done = true
          emit(event)

          // Reputation is optional and slow: look it up in parallel while the
          // stream is open, then emit one extra event per resolved node.
          if (event.type === 'ip' && event.ip && reputation.enabled && !reputationAsked.has(event.ip)) {
            reputationAsked.add(event.ip)
            reputationJobs.push(
              reputation
                .lookup(event.ip)
                .then((data) => {
                  if (data) emit({ type: 'reputation', ip: event.ip, reputation: data })
                })
                .catch(() => {}),
            )
          }
        },
        signal,
      )
      // Keep the NDJSON response open until the reputation events are flushed.
      if (reputationJobs.length) await Promise.allSettled(reputationJobs)
    })
  } finally {
    activeScans--
  }

  // Local scan history and alerts are best-effort: a storage or Telegram
  // outage must never break the stream that already finished successfully.
  if (observed.done) {
    try {
      store.addScan({
        target,
        source: 'ui',
        at: Date.now(),
        nodes: [...observed.nodes],
        ports: [...observed.ports],
        hops: [...observed.hops],
        labels: observed.labels,
      })
    } catch (error) {
      console.warn(`[scan-history] ${error?.message || error}`)
    }
    monitor
      .observeScan({
        target,
        nodes: [...observed.nodes],
        ports: [...observed.ports],
        hops: [...observed.hops],
        labels: observed.labels,
      })
      .catch((error) => console.warn(`[scan-alert] ${error?.message || error}`))
  }
})

app.get('/api/demo', async (req, res) => {
  const limit = demoLimiter.take(req.ip)
  setRateLimitHeaders(res, limit)
  if (!limit.ok) {
    sendRateLimited(res, limit)
    return
  }
  await streamNdjson(res, (emit, signal) => runDemo(emit, signal))
})

/* ------------------------------------------------------------------ */
/*  garbage mode: a random target that is actually alive               */
/* ------------------------------------------------------------------ */

const garbage = createGarbage()
let activePicks = 0

app.get('/api/garbage', async (req, res) => {
  const requested = String(req.query.kind || 'auto').toLowerCase()
  const kind = ['auto', 'site', 'dns', 'ip'].includes(requested) ? requested : 'auto'

  const limit = garbageLimiter.take(req.ip)
  setRateLimitHeaders(res, limit)
  if (!limit.ok) {
    sendRateLimited(res, limit)
    return
  }

  if (activePicks >= MAX_ACTIVE_PICKS) {
    res.setHeader('Retry-After', '5')
    res.status(429).json({ ok: false, error: 'Слишком много поисков цели. Попробуй через пару секунд.' })
    return
  }

  res.setHeader('Cache-Control', 'no-store')
  activePicks++
  try {
    const result = await garbage.pick(kind)
    res.json(result)
  } catch (error) {
    res.status(502).json({ ok: false, error: error?.message || 'Не удалось найти случайную цель' })
  } finally {
    activePicks--
  }
})

app.get('/api/garbage/info', (req, res) => {
  res.setHeader('Cache-Control', 'no-store')
  res.json(garbage.publicStatus())
})

/* ------------------------------------------------------------------ */
/*  perimeter monitor                                                  */
/* ------------------------------------------------------------------ */

const monitor = createMonitor(process.env, console, store)
const bot = createTelegramBot({
  token: String(process.env.ALERT_TELEGRAM_TOKEN || '').trim(),
  monitor,
})
let lastMonitorTest = 0
const MONITOR_TEST_COOLDOWN_MS = 10 * 60_000

app.get('/api/monitor', (req, res) => {
  res.setHeader('Cache-Control', 'no-store')
  const admin = monitorAuthorized(req)
  // Anonymous visitors only get the compressed status: no targets, no history
  // and no environment diagnostics.
  const base = admin ? monitor.publicStatus() : monitor.publicSummary()
  const hint = monitor.enabled
    ? null
    : bot.publicStatus().enabled
      ? 'Целей пока нет: пришли сайт боту в личные сообщения или задай MONITOR_TARGETS в окружении.'
      : 'Мониторинг выключен. Задай MONITOR_TARGETS и (по желанию) ALERT_WEBHOOK_URL или ALERT_TELEGRAM_TOKEN + ALERT_TELEGRAM_CHAT в окружении сервера.'
  res.json({
    ...base,
    admin,
    bot: bot.publicStatus(),
    targets: admin ? base.targets || [] : [],
    history: admin ? base.history || [] : [],
    scans: admin ? store.scans(12) : undefined,
    hint,
  })
})

app.post('/api/monitor/test', async (req, res) => {
  if (!requireMonitorToken(req, res)) return
  if (!monitor.enabled && !monitor.notifyScans) {
    res.status(400).json({ error: 'Мониторинг не настроен на сервере.' })
    return
  }
  const now = Date.now()
  if (now - lastMonitorTest < MONITOR_TEST_COOLDOWN_MS) {
    const retryAfter = Math.ceil((MONITOR_TEST_COOLDOWN_MS - (now - lastMonitorTest)) / 1000)
    res.setHeader('Retry-After', String(retryAfter))
    res.status(429).json({ error: `Тест уже отправлялся. Повтори через ${retryAfter} с.`, retryAfter })
    return
  }
  const result = await monitor.sendTest()
  if (!result.sent) {
    const reason =
      result.results
        .filter((item) => !item.ok)
        .map((item) => `${item.channel}: ${item.error}`)
        .join('; ') ||
      result.error ||
      'каналы не настроены'
    res.status(502).json({ error: `Не удалось отправить уведомление — ${reason}` })
    return
  }
  lastMonitorTest = now
  res.json({ ok: true, channels: result.results.filter((item) => item.ok).map((item) => item.channel) })
})

// External cron hook (e.g. GitHub Actions) for hosts that sleep when idle.
// Protected by MONITOR_TOKEN: without a matching X-Monitor-Token the route is
// indistinguishable from a missing endpoint.
app.post('/api/monitor/run', async (req, res) => {
  if (!requireMonitorToken(req, res)) return
  const result = await monitor.runNow()
  res.json({ ok: true, ...result })
})

/* ------------------------------------------------------------------ */
/*  headless web preview                                               */
/* ------------------------------------------------------------------ */

app.get('/api/preview', async (req, res) => {
  const limit = previewLimiter.take(req.ip)
  setRateLimitHeaders(res, limit)
  if (!limit.ok) {
    sendRateLimited(res, limit)
    return
  }

  res.setHeader('Cache-Control', 'no-store')
  const result = await preview.capture(req.query.host, req.query.port)
  res.status(result.ok ? 200 : result.status || 502).json(result)
})

/* ------------------------------------------------------------------ */
/*  IP reputation (AbuseIPDB, optional)                                */
/* ------------------------------------------------------------------ */

app.get('/api/reputation', async (req, res) => {
  const ip = String(req.query.ip || '').trim()
  if (!ip) {
    res.status(400).json({ ok: false, enabled: reputation.enabled, error: 'Укажи IP' })
    return
  }

  const limit = reputationLimiter.take(req.ip)
  setRateLimitHeaders(res, limit)
  if (!limit.ok) {
    sendRateLimited(res, limit)
    return
  }

  res.setHeader('Cache-Control', 'no-store')
  if (!reputation.enabled) {
    res.json({ ok: false, enabled: false, reason: 'ABUSEIPDB_API_KEY не задан на сервере' })
    return
  }

  try {
    const data = await reputation.lookup(ip)
    if (!data) {
      res.status(502).json({ ok: false, enabled: true, error: 'Репутация недоступна' })
      return
    }
    res.json({ ok: true, enabled: true, ip, reputation: data })
  } catch (error) {
    res.status(502).json({ ok: false, enabled: true, error: error?.message || 'Ошибка AbuseIPDB' })
  }
})

/* ------------------------------------------------------------------ */
/*  certificate transparency                                           */
/* ------------------------------------------------------------------ */

function normalizeDomain(raw) {
  let value = String(raw || '').trim().toLowerCase()
  if (!value) throw new Error('Укажи домен')
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/[/?#].*$/, '').replace(/\.$/, '')
  if (value.includes('@')) value = value.split('@').pop()
  if (!value) throw new Error('Укажи домен')
  if (/^[0-9.]+$/.test(value) || value.includes(':')) {
    throw new Error('Это IP-адрес: поддомены ищутся только для домена')
  }
  if (!/^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value)) {
    throw new Error('Некорректный домен')
  }
  return value
}

app.get('/api/subdomains', async (req, res) => {
  let host
  try {
    host = normalizeDomain(req.query.host)
  } catch (err) {
    res.status(400).json({ error: err?.message || 'Некорректный домен' })
    return
  }

  const limit = subLimiter.take(req.ip)
  setRateLimitHeaders(res, limit)
  if (!limit.ok) {
    sendRateLimited(res, limit)
    return
  }

  const cached = subCache.get(host)
  if (cached && Date.now() - cached.at < SUB_CACHE_MS) {
    res.setHeader('Cache-Control', 'no-store')
    res.json({ ...cached.payload, cached: true })
    return
  }

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 15_000)
  try {
    const response = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(`%.${host}`)}&output=json`,
      {
        headers: {
          Accept: 'application/json',
          'User-Agent': 'NetworkMap/1.0 (subdomain discovery)',
        },
        signal: controller.signal,
      },
    )
    if (!response.ok) throw new Error(`crt.sh ответил ${response.status}`)
    const text = await response.text()
    if (text.length > 8_000_000) throw new Error('слишком большой ответ')
    let rows = []
    try {
      rows = JSON.parse(text)
    } catch {
      throw new Error('crt.sh вернул не JSON')
    }
    if (!Array.isArray(rows)) throw new Error('crt.sh вернул неожиданный формат')

    const names = new Set()
    for (const row of rows) {
      const candidates = [row?.common_name, ...String(row?.name_value || '').split('\n')]
      for (const candidate of candidates) {
        const name = String(candidate || '')
          .trim()
          .toLowerCase()
          .replace(/^\*\./, '')
          .replace(/\.$/, '')
        if (!name || name === host) continue
        if (!name.endsWith(`.${host}`)) continue
        if (!/^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(name)) continue
        names.add(name)
      }
    }

    const all = [...names].sort(
      (a, b) => a.split('.').length - b.split('.').length || a.localeCompare(b),
    )
    const payload = {
      host,
      total: all.length,
      subdomains: all.slice(0, SUB_MAX),
      truncated: all.length > SUB_MAX,
    }
    subCache.set(host, { at: Date.now(), payload })
    res.setHeader('Cache-Control', 'no-store')
    res.json(payload)
  } catch (err) {
    const message =
      err?.name === 'AbortError'
        ? 'crt.sh не ответил за 15 с'
        : err?.message || 'неизвестная ошибка'
    res.status(502).json({
      error: `Не удалось получить поддомены: ${message}. TLS SAN из скана всё равно показан в инспекторе.`,
    })
  } finally {
    clearTimeout(timer)
  }
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

const server = app.listen(PORT, HOST, () => {
  console.log(`\n  NETWORK//MAP server  →  http://${HOST}:${PORT}`)
  console.log(`  API                 →  POST /api/scan · GET /api/demo`)
  console.log(`  Limits              →  ${SCAN_LIMIT} scans/${Math.round(SCAN_WINDOW_MS / 1000)}s per IP · ${MAX_ACTIVE_SCANS} concurrent`)
  console.log(
    `  Storage             →  ${store.kind} · preview ${preview.publicStatus().available ? 'on' : 'off'}` +
      ` · reputation ${reputation.enabled ? 'on' : 'off'} · monitor token ${MONITOR_TOKEN ? 'on' : 'off'}\n`,
  )
  // The bot can receive new sites at any time, so it starts even when the
  // hourly monitor is idle; monitor.start() is a no-op in that case.
  monitor
    .start()
    .then(() => bot.start())
    .catch((error) => console.warn(`[monitor] start failed: ${error?.message || error}`))
})

let shuttingDown = false
function shutdown(signal) {
  if (shuttingDown) return
  shuttingDown = true
  console.log(`[server] ${signal} · shutting down`)
  try {
    monitor.stop()
  } catch {}
  try {
    preview.close()
  } catch {}
  server.close(() => {
    try {
      store.close()
    } catch {}
    process.exit(0)
  })
  // Render sends SIGTERM and waits; never hang the deploy on a stuck socket.
  setTimeout(() => {
    try {
      store.close()
    } catch {}
    process.exit(0)
  }, 5000).unref?.()
}

process.once('SIGTERM', () => shutdown('SIGTERM'))
process.once('SIGINT', () => shutdown('SIGINT'))