import fs from 'node:fs/promises'
import path from 'node:path'
import { normalizeTarget, parsePorts, runScan } from './scan.js'

/**
 * Perimeter monitor and scan alerts.
 *
 * Runs scheduled scans on the server and, optionally, follows every scan made
 * from the UI. Whenever the set of resolved nodes, open ports or traceroute
 * hops changes, a short diff is posted to a webhook and/or a Telegram chat or
 * channel. Endpoints and bot tokens are read from the operator's environment
 * only: they are never accepted from the browser and never returned by the API.
 */

const DEFAULT_PORTS = '22,80,443,3389,3306,5432,6379,8080,9200,27017'
const MAX_TARGETS = 5
const MAX_PORTS = 200
const MAX_HISTORY = 30
const MAX_SNAPSHOTS = 200
const MIN_INTERVAL_MIN = 5
const MAX_ALERT_ITEMS = 6

const csv = (value) =>
  String(value || '')
    .split(/[\s,;]+/)
    .map((item) => item.trim())
    .filter(Boolean)

const flag = (value) => /^(1|true|yes|on)$/i.test(String(value || '').trim())

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

function describePort(key, labels) {
  const label = labels[key]
  return label && label !== 'unknown' ? `${key} (${label})` : key
}

function listLines(prefix, items, labels) {
  if (!items.length) return []
  const shown = items.slice(0, MAX_ALERT_ITEMS)
  const isPort = prefix.includes('PORT')
  const lines = shown.map((item) => `${prefix} ${isPort ? describePort(item, labels) : item}`)
  if (items.length > MAX_ALERT_ITEMS) {
    lines.push(`${prefix} … +${items.length - MAX_ALERT_ITEMS}`)
  }
  return lines
}

/**
 * One message for every kind of change: nodes (resolved IPs), open ports and
 * traceroute hops. Works for Discord/Slack webhooks and Telegram chats/channels.
 */
function formatChange(target, change, at, labels = {}, prefix = '\u26a0\ufe0f NETWORK//MAP') {
  const lines = [`${prefix} \u00b7 ${target}`]
  lines.push(...listLines('+ NODE', change.nodesAdded || [], labels))
  lines.push(...listLines('− NODE', change.nodesRemoved || [], labels))
  lines.push(...listLines('+ PORT', change.added || [], labels))
  lines.push(...listLines('− PORT', change.removed || [], labels))
  lines.push(...listLines('+ HOP', change.hopsAdded || [], labels))
  lines.push(...listLines('− HOP', change.hopsRemoved || [], labels))
  lines.push(new Date(at).toISOString().slice(0, 16).replace('T', ' ') + ' UTC')
  return lines.join('\n').slice(0, 1800)
}

const emptyChange = () => ({
  added: [],
  removed: [],
  nodesAdded: [],
  nodesRemoved: [],
  hopsAdded: [],
  hopsRemoved: [],
})

function diffList(previous, current) {
  // Old state files may not have this field yet: treat it as a baseline.
  if (!Array.isArray(previous)) return { added: [], removed: [] }
  return {
    added: current.filter((item) => !previous.includes(item)),
    removed: previous.filter((item) => !current.includes(item)),
  }
}

function diffSnapshot(previous, current) {
  const ports = diffList(previous?.open, current.open)
  const nodes = diffList(previous?.nodes, current.nodes)
  const hops = diffList(previous?.hops, current.hops)
  return {
    added: ports.added,
    removed: ports.removed,
    nodesAdded: nodes.added,
    nodesRemoved: nodes.removed,
    hopsAdded: hops.added,
    hopsRemoved: hops.removed,
  }
}

function hasChange(change) {
  return (
    change.added.length > 0 ||
    change.removed.length > 0 ||
    change.nodesAdded.length > 0 ||
    change.nodesRemoved.length > 0 ||
    change.hopsAdded.length > 0 ||
    change.hopsRemoved.length > 0
  )
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
  const intervalMin = Math.max(MIN_INTERVAL_MIN, Number(env.MONITOR_INTERVAL_MIN) || 60)
  const webhookUrl = String(env.ALERT_WEBHOOK_URL || '').trim()
  const telegramToken = String(env.ALERT_TELEGRAM_TOKEN || '').trim()
  const telegramChat = String(env.ALERT_TELEGRAM_CHAT || '').trim()
  const stateFile = env.MONITOR_STATE_FILE
    ? path.resolve(env.MONITOR_STATE_FILE)
    : path.resolve(process.cwd(), '.monitor-state.json')

  const enabled = targets.length > 0 && ports.length > 0
  const telegram = Boolean(telegramToken && telegramChat)
  const telegramChannel = /^-100/.test(telegramChat)
  // Follow scans started from the UI: any host a visitor scans is compared with
  // the previous snapshot and changes are posted to the same channels. On by
  // default (the owner asked for alerts about every scanned site); set
  // NOTIFY_SCANS=0 to disable.
  const notifyScans = !/^(0|false|no|off)$/i.test(String(env.NOTIFY_SCANS ?? '').trim())
  const notifyFirst = flag(env.NOTIFY_FIRST_SCAN)
  // Traceroute makes monitor scans much slower, so it is opt-in.
  const trace = flag(env.MONITOR_TRACE)

  const issues = []
  if (!targets.length) issues.push('MONITOR_TARGETS не задан или не распознан')
  if (!ports.length) issues.push('MONITOR_PORTS пуст или некорректен — пример: 22,80,443,6379')
  else if (invalidPorts.length) {
    issues.push(`MONITOR_PORTS: пропущено некорректных значений — ${invalidPorts.length}`)
  }
  if (notifyScans && !telegram && !webhookUrl) {
    issues.push('каналы не настроены — изменения сканов пишутся только в лог')
  }

  /**
   * @type {Map<string, {
   *   at: number,
   *   open: string[],
   *   labels: Record<string, string>,
   *   nodes?: string[],
   *   hops?: string[],
   * }>}
   */
  const snapshots = new Map()
  /** @type {Array<Record<string, unknown>>} */
  const history = []
  const status = new Map(
    targets.map((target) => [
      target,
      {
        target,
        lastRun: null,
        nextRun: null,
        open: 0,
        nodes: 0,
        hops: 0,
        added: [],
        removed: [],
        nodeAdded: 0,
        hopAdded: 0,
        error: null,
      },
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
        const snapshot = {
          at: Number(value.at) || 0,
          open: value.open.map(String),
          labels: value.labels && typeof value.labels === 'object' ? value.labels : {},
        }
        // Missing arrays mean "unknown" (state written by an older version):
        // keep them undefined so the first comparison only sets a baseline.
        if (Array.isArray(value.nodes)) snapshot.nodes = value.nodes.map(String)
        if (Array.isArray(value.hops)) snapshot.hops = value.hops.map(String)
        snapshots.set(target, snapshot)
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

  function remember(target, snapshot) {
    snapshots.set(target, snapshot)
    if (snapshots.size > MAX_SNAPSHOTS) {
      const oldest = [...snapshots.entries()].sort((a, b) => (a[1].at || 0) - (b[1].at || 0))[0]
      if (oldest && oldest[0] !== target) snapshots.delete(oldest[0])
    }
  }

  async function deliver(text) {
    const jobs = []
    const results = []
    if (webhookUrl) {
      // `content` is read by Discord, `text` by Slack and most generic hooks.
      jobs.push(
        postJson(webhookUrl, { content: text, text, message: text })
          .then(() => results.push({ channel: 'webhook', ok: true }))
          .catch((error) => {
            logger.warn(`[monitor] webhook failed: ${error.message}`)
            results.push({ channel: 'webhook', ok: false, error: error.message })
          }),
      )
    }
    if (telegram) {
      jobs.push(
        postJson(`https://api.telegram.org/bot${telegramToken}/sendMessage`, {
          chat_id: telegramChat,
          text,
          disable_web_page_preview: true,
        })
          .then(() => results.push({ channel: 'telegram', ok: true }))
          .catch((error) => {
            logger.warn(`[monitor] telegram failed: ${error.message}`)
            results.push({ channel: 'telegram', ok: false, error: error.message })
          }),
      )
    }
    await Promise.all(jobs)
    return results
  }

  async function scanTarget(target) {
    const open = new Set()
    const nodes = new Set()
    const hops = new Set()
    const labels = {}
    let error = null
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 90_000)

    try {
      await runScan(
        {
          target,
          ports: ports.join(','),
          traceroute: trace,
          geo: false,
          udp: false,
          timeout: 1200,
        },
        (event) => {
          if (event.type === 'ip' && event.ip) nodes.add(String(event.ip))
          if (event.type === 'hop' && event.ip) hops.add(`${event.index} \u00b7 ${event.ip}`)
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

    return {
      open: [...open].sort(),
      labels,
      nodes: [...nodes].sort(),
      hops: [...hops],
      error,
    }
  }

  async function scanOne(target) {
    const entry = status.get(target)
    const previous = snapshots.get(target)
    const { open, labels, nodes, hops, error } = await scanTarget(target)
    const at = Date.now()
    const current = { at, open, labels, nodes, hops }
    const change = error || !previous ? emptyChange() : diffSnapshot(previous, current)

    if (!error) {
      remember(target, current)
      await saveState()
    }

    if (entry) {
      entry.lastRun = at
      entry.error = error
      entry.open = open.length
      entry.nodes = nodes.length
      entry.hops = hops.length
      entry.added = change.added
      entry.removed = change.removed
      entry.nodeAdded = change.nodesAdded.length
      entry.hopAdded = change.hopsAdded.length
      entry.nextRun = started ? at + intervalMin * 60_000 : null
    }

    if (hasChange(change)) {
      history.unshift({ at, target, source: 'monitor', ...change })
      if (history.length > MAX_HISTORY) history.pop()
      const text = formatChange(target, change, at, { ...previous?.labels, ...labels })
      logger.log(
        `[monitor] ${target}: +${change.added.length}/-${change.removed.length} ports` +
          `, +${change.nodesAdded.length} nodes, +${change.hopsAdded.length} hops`,
      )
      await deliver(text)
    }

    return {
      target,
      open: open.length,
      nodes: nodes.length,
      hops: hops.length,
      added: change.added,
      removed: change.removed,
      error,
    }
  }

  const unique = (value) =>
    [...new Set((Array.isArray(value) ? value : []).map(String))].sort()

  /**
   * Called after a scan started from the UI. Compares nodes/ports/hops with the
   * last snapshot of that host and posts a diff. The first scan of a host is a
   * silent baseline unless NOTIFY_FIRST_SCAN=1.
   */
  async function observeScan(input = {}) {
    if (!notifyScans) return { skipped: true, reason: 'NOTIFY_SCANS выключен' }
    let host
    try {
      host = normalizeTarget(String(input.target || '')).host
    } catch {
      return { skipped: true, reason: 'нет цели' }
    }

    const current = {
      at: Date.now(),
      open: unique(input.ports),
      labels: input.labels && typeof input.labels === 'object' ? input.labels : {},
      nodes: unique(input.nodes),
      hops: unique(input.hops),
    }
    const previous = snapshots.get(host)
    remember(host, current)
    await saveState()

    if (!previous) {
      if (!notifyFirst) return { target: host, baseline: true, changed: false }
      const initial = {
        ...emptyChange(),
        added: current.open,
        nodesAdded: current.nodes,
        hopsAdded: current.hops,
      }
      history.unshift({ at: current.at, target: host, source: 'scan', ...initial })
      if (history.length > MAX_HISTORY) history.pop()
      const results = await deliver(
        formatChange(host, initial, current.at, current.labels, '\u2139\ufe0f NETWORK//MAP · новая цель'),
      )
      return {
        target: host,
        baseline: true,
        changed: false,
        announced: true,
        sent: results.some((result) => result.ok),
      }
    }

    const change = diffSnapshot(previous, current)
    if (!hasChange(change)) return { target: host, changed: false }

    history.unshift({ at: current.at, target: host, source: 'scan', ...change })
    if (history.length > MAX_HISTORY) history.pop()
    logger.log(
      `[scan-alert] ${host}: +${change.added.length}/-${change.removed.length} ports` +
        `, +${change.nodesAdded.length} nodes, +${change.hopsAdded.length} hops`,
    )
    const results = await deliver(
      formatChange(host, change, current.at, { ...previous.labels, ...current.labels }),
    )
    return { target: host, changed: true, sent: results.some((result) => result.ok), results }
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
    if (started) return
    // Scan alerts alone are useful (no scheduled targets): load the snapshots so
    // a restart does not turn every known host into a silent new baseline.
    if (!enabled && !notifyScans) return
    started = true
    await loadState()
    if (!enabled) {
      logger.log('[monitor] scan alerts only, no scheduled targets')
      return
    }
    logger.log(
      `[monitor] ${targets.length} target(s), ${ports.length} port(s), every ${intervalMin} min` +
        `${webhookUrl ? ', webhook' : ''}${telegram ? ', telegram' : ''}` +
        `${telegramChannel ? ' (channel)' : ''}${notifyScans ? ', scan alerts' : ''}`,
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
      scanAlerts: notifyScans,
      notifyFirst,
      trace,
      telegramChannel,
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
    if (!webhookUrl && !telegram) {
      return { sent: false, results: [], error: 'вебхук и Telegram не настроены' }
    }
    const results = await deliver(
      `\u2705 NETWORK//MAP \u00b7 тестовое уведомление\n` +
        `Цель: ${targets[0] || 'все сканы'} · портов: ${ports.length} · интервал: ${intervalMin} мин\n` +
        `Куда: ${telegramChannel ? 'Telegram-канал' : telegram ? 'Telegram' : 'вебхук'}`,
    )
    return { sent: results.some((result) => result.ok), results }
  }

  return {
    enabled,
    intervalMin,
    notifyScans,
    start,
    stop,
    runNow,
    observeScan,
    sendTest,
    publicStatus,
    targets,
    ports,
  }
}
