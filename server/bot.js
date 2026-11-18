import fs from 'node:fs/promises'
import path from 'node:path'

/**
 * Telegram bot that lets a visitor subscribe a site to the perimeter monitor by
 * sending it in a private chat. Subscriptions are scanned with the regular
 * hourly cycle and changes are posted to the alert channel.
 *
 * Anti-spam: one message per 1.5 s, 6 commands per minute, 40 per day, at most
 * BOT_MAX_PER_CHAT sites per chat and a global cap inside the monitor. Groups
 * and channels cannot add sites; they are only used to discover the alert
 * channel.
 */

const MIN_GAP_MS = 1500
const PER_MINUTE = 6
const PER_DAY = 40
const MAX_TEXT = 300
const HELP_COOLDOWN_MS = 5 * 60_000

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

export function createTelegramBot({ token, monitor, env = process.env, logger = console }) {
  const enabled =
    Boolean(token) && !/^(0|false|no|off)$/i.test(String(env.BOT_ENABLED ?? '').trim())
  const stateFile = env.BOT_STATE_FILE
    ? path.resolve(env.BOT_STATE_FILE)
    : path.resolve(process.cwd(), '.bot-state.json')
  const maxPerChat = Math.min(Math.max(Number(env.BOT_MAX_PER_CHAT) || 5, 1), 20)
  const api = `https://api.telegram.org/bot${token}`

  /** @type {{ offset: number, chats: Record<string, { targets: string[] }> }} */
  const state = { offset: 0, chats: {} }
  /** @type {Map<string, number[]>} */
  const hits = new Map()
  /** @type {Map<string, number>} */
  const helpedAt = new Map()
  let polling = false
  let stopped = false
  let loop = null

  const chatTargets = (chatId) => {
    const entry = state.chats[chatId]
    if (!entry) return []
    entry.targets = entry.targets.filter((host) => monitor.hasTarget(host))
    return entry.targets
  }

  async function load() {
    try {
      const raw = JSON.parse(await fs.readFile(stateFile, 'utf8'))
      state.offset = Number(raw?.offset) || 0
      for (const [chatId, value] of Object.entries(raw?.chats || {})) {
        const hosts = []
        for (const host of Array.isArray(value?.targets) ? value.targets : []) {
          if (monitor.addTarget(host).ok) hosts.push(host)
        }
        if (hosts.length) {
          state.chats[chatId] = { targets: hosts }
          logger.log(`[bot] restored ${hosts.length} site(s) for chat ${chatId.slice(0, 4)}…`)
        }
      }
    } catch {
      // First start or ephemeral disk: subscriptions live in memory.
    }
  }

  async function save() {
    try {
      await fs.writeFile(
        stateFile,
        JSON.stringify({
          v: 1,
          offset: state.offset,
          chats: Object.fromEntries(
            Object.entries(state.chats).map(([chatId, value]) => [
              chatId,
              { targets: value.targets },
            ]),
          ),
        }),
        'utf8',
      )
    } catch {
      // Ephemeral filesystem on Render free: ignore.
    }
  }

  async function send(chatId, text) {
    try {
      await fetch(`${api}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, text, disable_web_page_preview: true }),
        signal: AbortSignal.timeout(8000),
      })
    } catch {
      // The chat may have blocked the bot; nothing to do.
    }
  }

  /** Sliding-window throttle, per chat, kept in memory only. */
  function rateLimit(chatId) {
    const now = Date.now()
    const recent = (hits.get(chatId) || []).filter((at) => now - at < 24 * 3600_000)
    if (recent.length) {
      const gap = now - recent[recent.length - 1]
      if (gap < MIN_GAP_MS) return { ok: false, retryAfter: Math.ceil((MIN_GAP_MS - gap) / 1000) }
    }
    const minute = recent.filter((at) => now - at < 60_000).length
    if (minute >= PER_MINUTE) return { ok: false, retryAfter: 60 }
    if (recent.length >= PER_DAY) return { ok: false, retryAfter: 3600 }
    recent.push(now)
    hits.set(chatId, recent)
    return { ok: true }
  }

  function helpText() {
    return (
      'Пришли домен или IP — добавлю сайт в мониторинг.\n' +
      'Раз в час проверяю узлы, порты и хопы, об изменениях пишу в канал.\n\n' +
      '/list — мои сайты\n' +
      '/remove example.com — убрать сайт\n' +
      `/Лимит: ${maxPerChat} сайта на чат.`
    )
  }

  async function handleAdd(chatId, raw) {
    const targets = chatTargets(chatId)
    if (targets.length >= maxPerChat) {
      await send(chatId, `Лимит ${maxPerChat} сайта. Убери лишний: /remove example.com`)
      return
    }
    const result = monitor.addTarget(raw)
    if (!result.ok) {
      await send(chatId, result.already ? 'Этот сайт уже отслеживается.' : `Не вышло: ${result.error}`)
      return
    }
    state.chats[chatId] = { targets: [...targets, result.host] }
    await save()
    // First scan becomes a silent baseline right away, so the next change is real.
    monitor.primeTarget(result.host)
    await send(
      chatId,
      `✅ Добавил ${result.host}\n` +
        `Первый скан — база, дальше шлю только изменения. Сайтов: ${state.chats[chatId].targets.length}/${maxPerChat}.`,
    )
  }

  async function handleRemove(chatId, raw) {
    const host = monitor.resolveHost(raw)
    if (!host) {
      await send(chatId, 'Не понял адрес. Пример: /remove example.com')
      return
    }
    const targets = chatTargets(chatId)
    if (!targets.includes(host)) {
      await send(chatId, `В твоём списке нет ${host}. /list — посмотреть список.`)
      return
    }
    const result = monitor.removeTarget(host)
    if (!result.ok) {
      await send(chatId, `Не вышло: ${result.error}`)
      return
    }
    state.chats[chatId] = { targets: targets.filter((item) => item !== host) }
    await save()
    await send(chatId, `Убрал ${host}. Сайтов: ${state.chats[chatId].targets.length}/${maxPerChat}.`)
  }

  async function handleList(chatId) {
    const targets = chatTargets(chatId)
    if (!targets.length) {
      await send(chatId, 'Список пуст. Пришли домен или IP, например example.com')
      return
    }
    const lines = targets.map((host, index) => `${index + 1}. ${host}`)
    await send(chatId, `Твои сайты (${targets.length}/${maxPerChat}):\n${lines.join('\n')}`)
  }

  async function handleMessage(message) {
    const chat = message?.chat
    if (!chat || chat.type !== 'private' || message.from?.is_bot) return
    const chatId = String(chat.id)
    const text = String(message.text || '').trim()
    if (!text || text.length > MAX_TEXT) {
      const last = helpedAt.get(chatId) || 0
      if (Date.now() - last > HELP_COOLDOWN_MS) {
        helpedAt.set(chatId, Date.now())
        await send(chatId, helpText())
      }
      return
    }

    const limit = rateLimit(chatId)
    if (!limit.ok) {
      await send(chatId, `Слишком часто. Подожди ${limit.retryAfter} с.`)
      return
    }

    const [head, ...rest] = text.split(/\s+/)
    const command = head.toLowerCase().replace(/@[\w_]+$/, '')
    const argument = rest.join(' ').trim()

    if (command === '/start' || command === '/help') {
      await send(chatId, helpText())
      return
    }
    if (command === '/list') {
      await handleList(chatId)
      return
    }
    if (command === '/add') {
      if (!argument) {
        await send(chatId, 'Пришли так: /add example.com')
        return
      }
      await handleAdd(chatId, argument)
      return
    }
    if (['/remove', '/del', '/rm'].includes(command)) {
      if (!argument) {
        await send(chatId, 'Пришли так: /remove example.com')
        return
      }
      await handleRemove(chatId, argument)
      return
    }
    if (command.startsWith('/')) {
      await send(chatId, helpText())
      return
    }
    // Bare text is treated as a site, so "example.com" just works.
    await handleAdd(chatId, text)
  }

  function noteChannel(update) {
    const chat = update?.channel_post?.chat || update?.my_chat_member?.chat
    if (chat?.type !== 'channel') return
    const id = String(chat.id)
    if (!id.startsWith('-100')) return
    if (monitor.setTelegramChannel(id, chat.title)) {
      logger.log(`[bot] alerts go to channel: ${chat.title || id.slice(0, 5) + '…'}`)
    }
  }

  async function handleUpdate(update) {
    noteChannel(update)
    if (update?.message) await handleMessage(update.message)
  }

  async function poll() {
    polling = true
    monitor.useExternalChannelDiscovery()
    let warned = false
    while (!stopped) {
      try {
        const params = new URLSearchParams({
          timeout: '25',
          allowed_updates: JSON.stringify(['message', 'channel_post', 'my_chat_member']),
          offset: String(state.offset),
        })
        const response = await fetch(`${api}/getUpdates?${params}`, {
          signal: AbortSignal.timeout(40_000),
        })
        const data = await response.json()
        if (!data.ok) {
          if (data.error_code === 401) {
            logger.warn('[bot] Telegram rejected the token — polling stopped')
            break
          }
          if (!warned) {
            warned = true
            logger.warn(`[bot] getUpdates: ${data.description || 'error'}`)
          }
          await sleep(5000)
          continue
        }
        warned = false
        const updates = Array.isArray(data.result) ? data.result : []
        for (const update of updates) {
          state.offset = Math.max(state.offset, Number(update.update_id) + 1)
          await handleUpdate(update)
        }
        if (updates.length) await save()
      } catch (error) {
        if (stopped) break
        logger.warn(`[bot] poll failed: ${error?.message || error}`)
        await sleep(5000)
      }
    }
    polling = false
  }

  async function start() {
    if (!enabled || loop) return
    await load()
    stopped = false
    loop = poll()
      .catch((error) => logger.warn(`[bot] stopped: ${error?.message || error}`))
      .finally(() => {
        loop = null
      })
  }

  async function stop() {
    stopped = true
  }

  function publicStatus() {
    return {
      enabled,
      polling,
      chats: Object.keys(state.chats).length,
      targets: monitor.dynamicCount(),
      maxPerChat,
    }
  }

  return { enabled, start, stop, publicStatus }
}
