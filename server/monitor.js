import fs from 'node:fs/promises'
import net from 'node:net'
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
const MAX_DYNAMIC_TARGETS = 30
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

function isPrivateHost(host) {
  const value = String(host || '').toLowerCase().replace(/^\[|\]$/g, '')
  if (['localhost', '0.0.0.0'].includes(value)) return true
  if (value.endsWith('.local') || value.endsWith('.internal') || value.endsWith('.localhost')) return true
  if (net.isIP(value) === 4) {
    return (
      /^10\./.test(value) ||
      /^127\./.test(value) ||
      /^192\.168\./.test(value) ||
      /^169\.254\./.test(value) ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(value)
    )
  }
  if (net.isIP(value) === 6) {
    return value === '::1' || /^f[cd][0-9a-f]{2}:/i.test(value) || /^fe80:/i.test(value)
  }
  return false
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
  const envTargets = readTargets(env.MONITOR_TARGETS)
  const { ports, invalid: invalidPorts } = readPorts(env.MONITOR_PORTS)
  const intervalMin = Math.max(MIN_INTERVAL_MIN, Number(env.MONITOR_INTERVAL_MIN) || 60)
  const webhookUrl = String(env.ALERT_WEBHOOK_URL || '').trim()
  const telegramToken = String(env.ALERT_TELEGRAM_TOKEN || '').trim()
  const telegramChat = String(env.ALERT_TELEGRAM_CHAT || '').trim()
  const stateFile = env.MONITOR_STATE_FILE
    ? path.resolve(env.MONITOR_STATE_FILE)
    : path.resolve(process.cwd(), '.monitor-state.json')

  const telegram = Boolean(telegramToken && telegramChat)
  const configuredChannel = /^-100/.test(telegramChat)
  let telegramTarget = telegramChat
  let channelFound = configuredChannel
  let lastChannelProbe = 0
  let externalDiscovery = false
  /** Sites added through the bot, oldest first. */
  const dynamicTargets = new Map()
  const isEnabled = () => ports.length > 0 && (envTargets.length > 0 || dynamicTargets.size > 0)
  // Follow scans started from the UI: any host a visitor scans is compared with
  // the previous snapshot and changes are posted to the same channels. On by
  // default (the owner asked for alerts about every scanned site); set
  // NOTIFY_SCANS=0 to disable.
  const notifyScans = !/^(0|false|no|off)$/i.test(String(env.NOTIFY_SCANS ?? '').trim())
  const notifyFirst = flag(env.NOTIFY_FIRST_SCAN)
  // Traceroute makes monitor scans much slower, so it is opt-in.
  const trace = flag(env.MONITOR_TRACE)

  function issuesNow() {
    const list = []
    if (!ports.length) list.push('MONITOR_PORTS пуст или некорректен — пример: 22,80,443,6379')
    else if (invalidPorts.length) {
      list.push(`MONITOR_PORTS: пропущено некорректных значений — ${invalidPorts.length}`)
    }
    if (ports.length && !envTargets.length && !dynamicTargets.size) {
      list.push('целей нет — задай MONITOR_TARGETS или добавь сайт через Telegram-бота')
    }
    if (notifyScans && !telegram && !webhookUrl) {
      list.push('каналы не настроены — изменения сканов пишутся только в лог')
    }
    return list
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
  const status = new Map()
  function ensureStatus(target, source = 'bot') {
    let entry = status.get(target)
    if (!entry) {
      entry = {
        target,
        source,
        lastRun: null,
        nextRun: null,
        open: 0,
        nodes: 0,
        hops: 0,
        added: [],
        removed: [],
        nodeAdded: 0,
        nodeRemoved: 0,
        hopAdded: 0,
        hopRemoved: 0,
        error: null,
      }
      status.set(target, entry)
    }
    return entry
  }
  for (const target of envTargets) ensureStatus(target, 'env')

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

  /**
   * If the operator added the bot to a channel instead of passing a `-100…`
   * chat id, discover it from pending updates (my_chat_member / channel_post).
   * That way "add the bot to the channel" is enough — no env edit needed.
   */
  async function probeChannel(force = false) {
    // The bot owns getUpdates while it runs, so it reports the channel instead.
    if (externalDiscovery || configuredChannel || !telegramToken) return
    if (!force && Date.now() - lastChannelProbe < 5 * 60_000) return
    lastChannelProbe = Date.now()
    try {
      const url =
        `https://api.telegram.org/bot${telegramToken}/getUpdates` +
        `?allowed_updates=${encodeURIComponent('["channel_post","my_chat_member"]')}`
      const response = await fetch(url, { signal: AbortSignal.timeout(8000) })
      if (!response.ok) return
      const data = await response.json()
      let latest = null
      for (const update of Array.isArray(data?.result) ? data.result : []) {
        const chat = update.channel_post?.chat || update.my_chat_member?.chat
        if (chat?.type !== 'channel') continue
        const id = String(chat.id)
        if (!id.startsWith('-100')) continue
        if (!latest || update.update_id > latest.id) latest = { id, updateId: update.update_id, title: chat.title }
      }
      if (latest) {
        telegramTarget = latest.id
        channelFound = true
        // Title is public; the numeric id is only partially logged.
        logger.log(`[monitor] telegram channel: ${latest.title || latest.id.slice(0, 5) + '…'}`)
      }
    } catch {
      // Bot API unreachable or getUpdates conflicts with a webhook: keep chat.
    }
  }

  function resolveHost(raw) {
    try {
      return normalizeTarget(String(raw || '').replace(/^["'`]+|["'`]+$/g, '').trim()).host
    } catch {
      return null
    }
  }

  function hasTarget(host) {
    return envTargets.includes(host) || dynamicTargets.has(host)
  }

  /**
   * Add a site supplied by a bot subscriber. The first scan is a silent
   * baseline; later hourly scans report diffs to the alert channel.
   */
  function addTarget(raw) {
    const host = resolveHost(raw)
    if (!host) return { ok: false, error: 'не похоже на домен или IP' }
    if (isPrivateHost(host)) {
      return { ok: false, error: 'локальные и приватные адреса не сканируются' }
    }
    if (hasTarget(host)) return { ok: false, already: true, host }
    if (dynamicTargets.size >= MAX_DYNAMIC_TARGETS) {
      return { ok: false, error: `лимит ${MAX_DYNAMIC_TARGETS} сайтов — убери лишние` }
    }
    dynamicTargets.set(host, { at: Date.now() })
    ensureStatus(host, 'bot')
    ensureSchedule()
    return { ok: true, host }
  }

  function removeTarget(raw) {
    const host = resolveHost(raw)
    if (!host) return { ok: false, error: 'не похоже на домен или IP' }
    if (envTargets.includes(host)) {
      return { ok: false, error: 'задан в MONITOR_TARGETS и убирается только в окружении' }
    }
    if (!dynamicTargets.has(host)) return { ok: false, error: 'этот сайт не отслеживается' }
    dynamicTargets.delete(host)
    status.delete(host)
    return { ok: true, host }
  }

  function dynamicCount() {
    return dynamicTargets.size
  }

  function useExternalChannelDiscovery() {
    externalDiscovery = true
  }

  /** Called by the bot when it sees the channel in my_chat_member/channel_post. */
  function setTelegramChannel(id, title) {
    const value = String(id || '')
    if (!/^-100\d+$/.test(value)) return false
    const changed = !channelFound || telegramTarget !== value
    telegramTarget = value
    channelFound = true
    return changed
  }

  function primeTarget(host) {
    if (!hasTarget(host)) return
    ensureStatus(host, dynamicTargets.has(host) ? 'bot' : 'env')
    setTimeout(() => {
      scanOne(host).catch((error) => logger.warn(`[monitor] prime ${host}: ${error.message}`))
    }, 400).unref?.()
  }

  async function deliver(text) {
    const jobs = []
    const results = []
    if (telegram) {
      await probeChannel()
    }
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
          chat_id: telegramTarget,
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

  const scanning = new Set()

  async function scanOne(target) {
    if (scanning.has(target)) return { target, skipped: true }
    scanning.add(target)
    try {
      return await scanOneInner(target)
    } finally {
      scanning.delete(target)
    }
  }

  async function scanOneInner(target) {
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
      entry.nodeRemoved = change.nodesRemoved.length
      entry.hopAdded = change.hopsAdded.length
      entry.hopRemoved = change.hopsRemoved.length
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
    if (!isEnabled() || running) return { skipped: true, results: [] }
    running = true
    const results = []
    const startedAt = Date.now()
    // Keep one cycle inside a sane window even with many bot subscriptions.
    const budgetMs = Math.max(5, Math.min(intervalMin, 10)) * 60_000
    try {
      for (const target of [...envTargets, ...dynamicTargets.keys()]) {
        if (Date.now() - startedAt > budgetMs) {
          logger.warn('[monitor] cycle budget exceeded, remaining targets postponed')
          break
        }
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

  /** The bot may add the first site after boot: start the hourly cycle then. */
  function ensureSchedule() {
    if (!ports.length || !isEnabled()) return
    if (!started) {
      // The monitor never started (no targets and no scan alerts): load the
      // snapshots first so known hosts are not silently re-baselined.
      started = true
      loadState()
        .then(() => {
          if (started && !timer) schedule()
        })
        .catch((error) => logger.warn(`[monitor] state load failed: ${error.message}`))
      return
    }
    if (!timer) schedule()
  }

  async function start() {
    if (started) return
    // Scan alerts alone are useful (no scheduled targets): load the snapshots so
    // a restart does not turn every known host into a silent new baseline.
    if (!isEnabled() && !notifyScans) return
    started = true
    await loadState()
    await probeChannel()
    if (!isEnabled()) {
      logger.log('[monitor] scan alerts only, no scheduled targets')
      return
    }
    logger.log(
      `[monitor] ${envTargets.length + dynamicTargets.size} target(s)` +
        ` (${dynamicTargets.size} via bot), ${ports.length} port(s), every ${intervalMin} min` +
        `${webhookUrl ? ', webhook' : ''}${telegram ? ', telegram' : ''}` +
        `${channelFound ? ' (channel)' : ''}${notifyScans ? ', scan alerts' : ''}`,
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
      enabled: isEnabled(),
      intervalMin,
      ports: ports.length,
      alerts: { webhook: Boolean(webhookUrl), telegram },
      scanAlerts: notifyScans,
      notifyFirst,
      trace,
      telegramChannel: channelFound,
      botTargets: dynamicTargets.size,
      // Presence of configuration only: no values, URLs or tokens. Lets an
      // operator see which variable the running process is missing.
      env: {
        targets: envTargets.length,
        telegramToken: Boolean(telegramToken),
        telegramChat: Boolean(telegramChat),
        webhook: Boolean(webhookUrl),
      },
      issues: issuesNow(),
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
    await probeChannel(true)
    const results = await deliver(
      `\u2705 NETWORK//MAP \u00b7 тестовое уведомление\n` +
        `Цель: ${envTargets[0] || 'все сканы'} · портов: ${ports.length} · интервал: ${intervalMin} мин\n` +
        `Куда: ${channelFound ? 'Telegram-канал' : telegram ? 'Telegram' : 'вебхук'}`,
    )
    return { sent: results.some((result) => result.ok), results }
  }

  return {
    get enabled() {
      return isEnabled()
    },
    intervalMin,
    notifyScans,
    start,
    stop,
    runNow,
    observeScan,
    sendTest,
    publicStatus,
    addTarget,
    removeTarget,
    hasTarget,
    resolveHost,
    dynamicCount,
    primeTarget,
    useExternalChannelDiscovery,
    setTelegramChannel,
    targets: envTargets,
    ports,
  }
}
