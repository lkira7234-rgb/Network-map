import fs from 'node:fs/promises'
import path from 'node:path'
import { normalizeTarget, parsePorts, runScan } from './scan.js'

/**
 * Perimeter monitor.
 *
 * Runs scheduled scans on the server and posts a short diff to a webhook when
 * an open port appears or disappears. Endpoints and bot tokens are read from
 * the operator's environment only: they are never accepted from the browser
 * and never returned by the API, so no visitor can read or replace them.
 */

const DEFAULT_PORTS = '22,80,443,3389,3306,5432,6379,8080,9200,27017'
const MAX_TARGETS = 5
const MAX_PORTS = 200
const MAX_HISTORY = 30
const MIN_INTERVAL_MIN = 5

const csv = (value) =>
  String(value || '')
    .split(/[\s,;]+/)
    .map((item) => item.trim())
    .filter(Boolean)

function readTargets(raw) {
  const targets = []
  for (const value of csv(raw)) {
    try {
      targets.push(normalizeTarget(value.replace(/^["'`]+|["'`]+$/g, '')).host)
    } catch {
      // Ignore malformed entries so one typo does not disable the monitor.
    }
    if (targets.length >= MAX_TARGETS) break
  }
  return [...new Set(targets)]
}

/**
 * Tolerant port parsing: operators paste values with quotes, spaces or a stray
 * placeholder. Skip what cannot be parsed instead of disabling monitoring.
 */
function readPorts(raw) {
  const source = String(raw ?? '').trim()
  const tokens = (source || DEFAULT_PORTS)
    .split(/[\s,;]+/)
    .map((item) => item.replace(/^["'`]+|["'`]+$/g, '').trim())
    .filter(Boolean)
  const ports = new Set()
  const invalid = []
  for (const token of tokens) {
    try {
      for (const port of parsePorts(token)) {
        ports.add(port)
        if (ports.size >= MAX_PORTS) break
      }
    } catch {
      invalid.push(token)
    }
    if (ports.size >= MAX_PORTS) break
  }
  return { ports: [...ports].sort((a, b) => a - b).slice(0, MAX_PORTS), invalid }
}

function shortPort(key, labels) {
  const label = labels[key]
  return label && label !== 'unknown' ? `${key} (${label})` : key
}

function formatAlert(target, added, removed, labels, at) {
  const lines = [`\u26a0\ufe0f NETWORK//MAP \u00b7 ${target}`]
  if (added.length) lines.push(`+ ${added.map((key) => shortPort(key, labels)).join(', ')}`)
  if (removed.length) lines.push(`\u2212 ${removed.map((key) => shortPort(key, labels)).join(', ')}`)
  lines.push(new Date(at).toISOString().slice(0, 16).replace('T', ' ') + ' UTC')
  return lines.join('\n').slice(0, 1800)
}

async function postJson(url, body, timeoutMs = 8000) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  })
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`.trim())
  }
}

export function createMonitor(env = process.env, logger = console) {
  const targets = readTargets(env.MONITOR_TARGETS)
  const { ports, invalid: invalidPorts } = readPorts(env.MONITOR_PORTS)
  const intervalMin = Math.max(
    MIN_INTERVAL_MIN,
    Number(env.MONITOR_INTERVAL_MIN) || 60,
  )
  const webhookUrl = String(env.ALERT_WEBHOOK_URL || '').trim()
  const telegramToken = String(env.ALERT_TELEGRAM_TOKEN || '').trim()
  const telegramChat = String(env.ALERT_TELEGRAM_CHAT || '').trim()
  const stateFile = env.MONITOR_STATE_FILE
    ? path.resolve(env.MONITOR_STATE_FILE)
    : path.resolve(process.cwd(), '.monitor-state.json')

  const enabled = targets.length > 0 && ports.length > 0
  const telegram = Boolean(telegramToken && telegramChat)

  const issues = []
  if (!targets.length) issues.push('MONITOR_TARGETS не задан или не распознан')
  if (!ports.length) issues.push('MONITOR_PORTS пуст или некорректен — пример: 22,80,443,6379')
  else if (invalidPorts.length) {
    issues.push(`MONITOR_PORTS: пропущено некорректных значений — ${invalidPorts.length}`)
  }

  /** @type {Map<string, { at: number, open: string[], labels: Record<string, string> }>} */
  const snapshots = new Map()
  /** @type {Array<{ at: number, target: string, added: string[], removed: string[] }>} */
  const history = []
  const status = new Map(
    targets.map((target) => [
      target,
      { target, lastRun: null, nextRun: null, open: 0, added: [], removed: [], error: null },
    ]),
  )

  let timer = null
  let running = false
  let started = false

  async function loadState() {
    try {
      const raw = await fs.readFile(stateFile, 'utf8')
      const parsed = JSON.parse(raw)
      for (const [target, value] of Object.entries(parsed?.targets || {})) {
        if (!Array.isArray(value?.open)) continue
        snapshots.set(target, {
          at: Number(value.at) || 0,
          open: value.open.map(String),
          labels: value.labels && typeof value.labels === 'object' ? value.labels : {},
        })
      }
    } catch {
      // First start or unwritable disk (Render): the in-memory state still works.
    }
  }

  async function saveState() {
    try {
      const payload = { savedAt: Date.now(), targets: {} }
      for (const [target, value] of snapshots) payload.targets[target] = value
      await fs.writeFile(stateFile, JSON.stringify(payload), 'utf8')
    } catch {
      // Ephemeral filesystem or read-only disk: ignore.
    }
  }

  async function deliver(text) {
    const jobs = []
    if (webhookUrl) {
      // `content` is read by Discord, `text` by Slack and most generic hooks.
      jobs.push(
        postJson(webhookUrl, { content: text, text, message: text }).catch((error) => {
          logger.warn(`[monitor] webhook failed: ${error.message}`)
        }),
      )
    }
    if (telegram) {
      jobs.push(
        postJson(`https://api.telegram.org/bot${telegramToken}/sendMessage`, {
          chat_id: telegramChat,
          text,
          disable_web_page_preview: true,
        }).catch((error) => {
          logger.warn(`[monitor] telegram failed: ${error.message}`)
        }),
      )
    }
    await Promise.all(jobs)
  }

  async function scanTarget(target) {
    const open = new Set()
    const labels = {}
    let error = null
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 90_000)

    try {
      await runScan(
        { target, ports: ports.join(','), traceroute: false, geo: false, udp: false, timeout: 1200 },
        (event) => {
          if (event.type === 'port' && event.state === 'open') {
            const key = `${event.ip}:${event.port}/${event.protocol || 'tcp'}`
            open.add(key)
            labels[key] = event.service || 'unknown'
          }
          if (event.type === 'fatal') error = String(event.message || 'scan failed')
        },
        controller.signal,
      )
    } catch (err) {
      error = err?.name === 'AbortError' ? 'таймаут скана' : err?.message || 'ошибка скана'
    } finally {
      clearTimeout(timeout)
    }

    return { open: [...open].sort(), labels, error }
  }

  async function scanOne(target) {
    const entry = status.get(target)
    const previous = snapshots.get(target)
    const { open, labels, error } = await scanTarget(target)
    const added = error ? [] : open.filter((key) => previous && !previous.open.includes(key))
    const removed = error ? [] : (previous?.open || []).filter((key) => !open.includes(key))
    const at = Date.now()

    if (!error) {
      snapshots.set(target, { at, open, labels })
      await saveState()
    }

    if (entry) {
      entry.lastRun = at
      entry.error = error
      entry.open = open.length
      entry.added = added
      entry.removed = removed
      entry.nextRun = started ? at + intervalMin * 60_000 : null
    }

    if (added.length || removed.length) {
      history.unshift({ at, target, added, removed })
      if (history.length > MAX_HISTORY) history.pop()
      const text = formatAlert(target, added, removed, { ...previous?.labels, ...labels }, at)
      logger.log(`[monitor] ${target}: +${added.length} / -${removed.length}`)
      await deliver(text)
    }

    return { target, open: open.length, added, removed, error }
  }

  async function runNow() {
    if (!enabled || running) return { skipped: true, results: [] }
    running = true
    const results = []
    try {
      for (const target of targets) {
        results.push(await scanOne(target))
      }
    } finally {
      running = false
    }
    return { skipped: false, results }
  }

  function schedule() {
    if (timer) clearTimeout(timer)
    timer = setTimeout(async () => {
      timer = null
      try {
        await runNow()
      } catch (error) {
        logger.warn(`[monitor] tick failed: ${error.message}`)
      }
      if (started) schedule()
    }, intervalMin * 60_000)
    // Never keep the process alive just for the timer.
    timer.unref?.()
  }

  async function start() {
    if (!enabled || started) return
    started = true
    await loadState()
    logger.log(
      `[monitor] ${targets.length} target(s), ${ports.length} port(s), every ${intervalMin} min` +
        `${webhookUrl ? ', webhook' : ''}${telegram ? ', telegram' : ''}`,
    )
    schedule()
    // First pass runs in the background so startup and health checks stay fast.
    setTimeout(() => {
      runNow().catch((error) => logger.warn(`[monitor] first run failed: ${error.message}`))
    }, 4000).unref?.()
  }

  function stop() {
    started = false
    if (timer) clearTimeout(timer)
    timer = null
  }

  function publicStatus() {
    return {
      enabled,
      intervalMin,
      ports: ports.length,
      alerts: { webhook: Boolean(webhookUrl), telegram },
      // Presence of configuration only: no values, URLs or tokens. Lets an
      // operator see which variable the running process is missing.
      env: {
        targets: targets.length,
        telegramToken: Boolean(telegramToken),
        telegramChat: Boolean(telegramChat),
        webhook: Boolean(webhookUrl),
      },
      issues,
      targets: [...status.values()].map((entry) => ({
        ...entry,
        added: entry.added.slice(0, 40),
        removed: entry.removed.slice(0, 40),
      })),
      history: history.slice(0, 12),
    }
  }

  async function sendTest() {
    if (!webhookUrl && !telegram) return false
    await deliver(
      `\u2705 NETWORK//MAP \u00b7 тестовое уведомление\nЦель: ${targets[0] || '—'} · портов: ${ports.length} · интервал: ${intervalMin} мин`,
    )
    return true
  }

  return {
    enabled,
    intervalMin,
    start,
    stop,
    runNow,
    sendTest,
    publicStatus,
    targets,
    ports,
  }
}
