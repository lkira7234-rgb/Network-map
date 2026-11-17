#!/usr/bin/env node
/**
 * Prints the chat_id(s) the bot can see, so the operator can fill
 * ALERT_TELEGRAM_CHAT without copying it from raw JSON by hand.
 *
 * The token is read from the environment only and never printed.
 *
 *   ALERT_TELEGRAM_TOKEN=123:abc npm run telegram:chat-id
 */
const token = String(process.env.ALERT_TELEGRAM_TOKEN || process.env.TELEGRAM_BOT_TOKEN || '').trim()

if (!token) {
  console.error('Задай ALERT_TELEGRAM_TOKEN (токен от @BotFather) в окружении и повтори.')
  process.exit(1)
}

let response
try {
  response = await fetch(`https://api.telegram.org/bot${token}/getUpdates?limit=100`, {
    signal: AbortSignal.timeout(20_000),
  })
} catch (error) {
  console.error(`Нет связи с Telegram: ${error?.name === 'TimeoutError' ? 'таймаут' : error?.message}`)
  process.exit(1)
}

let payload
try {
  payload = await response.json()
} catch {
  console.error(`Telegram ответил ${response.status} не JSON.`)
  process.exit(1)
}

if (!payload.ok) {
  console.error(`Telegram API: ${payload.description || response.status}`)
  if (/unauthorized/i.test(payload.description || '')) {
    console.error('Токен неверный или отозван — получи новый у @BotFather.')
  }
  process.exit(1)
}

const chats = new Map()
for (const update of payload.result || []) {
  const chat =
    update.message?.chat ||
    update.channel_post?.chat ||
    update.my_chat_member?.chat ||
    update.callback_query?.message?.chat
  if (!chat?.id) continue
  chats.set(chat.id, chat)
}

if (!chats.size) {
  console.log('Бот ещё не видел ни одного чата.')
  console.log('Открой бота в Telegram, нажми Start (или напиши /start) и запусти команду снова.')
  process.exit(0)
}

console.log('Найденные чаты:\n')
for (const chat of chats.values()) {
  const name =
    chat.title || [chat.first_name, chat.last_name].filter(Boolean).join(' ') || chat.username || '—'
  console.log(`  chat_id: ${chat.id}  ·  ${chat.type}  ·  ${name}`)
}
console.log('\nВпиши нужный id в ALERT_TELEGRAM_CHAT рядом с ALERT_TELEGRAM_TOKEN.')
