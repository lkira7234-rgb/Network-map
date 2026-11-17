#!/usr/bin/env node
/**
 * Applies the perimeter monitor environment variables to a Render service and
 * triggers a deploy. Everything is read from the environment, so no secret is
 * ever written to disk or printed.
 *
 *   RENDER_API_KEY=rnd_... \
 *   ALERT_TELEGRAM_TOKEN=123:abc \
 *   ALERT_TELEGRAM_CHAT=8458549640 \
 *   MONITOR_TARGETS=example.com \
 *   npm run render:monitor
 *
 * Optional: RENDER_SERVICE (id `srv-...` or exact name), MONITOR_PORTS,
 * MONITOR_INTERVAL_MIN, ALERT_WEBHOOK_URL, MONITOR_TOKEN.
 *
 * The Render API key grants full account access: revoke it after use.
 */
const API = 'https://api.render.com/v1'

async function call(apiKey, path, init = {}) {
  const response = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${apiKey}`,
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
    signal: AbortSignal.timeout(30_000),
  })
  const text = await response.text()
  let data = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = null
  }
  return { ok: response.ok, status: response.status, data, text }
}

async function main() {
  const env = process.env
  const apiKey = String(env.RENDER_API_KEY || '').trim()
  const serviceRef = String(env.RENDER_SERVICE || 'network-map-3cw5').trim()

  if (!apiKey) {
    console.error('Задай RENDER_API_KEY в окружении (Render → Account Settings → API Keys).')
    process.exitCode = 1
    return
  }

  const values = {
    MONITOR_TARGETS: String(env.MONITOR_TARGETS || '').trim(),
    ALERT_TELEGRAM_TOKEN: String(env.ALERT_TELEGRAM_TOKEN || '').trim(),
    ALERT_TELEGRAM_CHAT: String(env.ALERT_TELEGRAM_CHAT || '').trim(),
    MONITOR_PORTS: String(env.MONITOR_PORTS || '22,80,443,6379').trim(),
    MONITOR_INTERVAL_MIN: String(env.MONITOR_INTERVAL_MIN || '60').trim(),
  }

  for (const key of ['ALERT_WEBHOOK_URL', 'MONITOR_TOKEN']) {
    const value = String(env[key] || '').trim()
    if (value) values[key] = value
  }

  for (const key of ['MONITOR_TARGETS', 'ALERT_TELEGRAM_TOKEN', 'ALERT_TELEGRAM_CHAT']) {
    if (!values[key]) {
      console.error(`Пустое значение ${key} — без него монитор не включится.`)
      process.exitCode = 1
      return
    }
  }

  let serviceId = serviceRef
  if (!serviceId.startsWith('srv-')) {
    const { ok, status, data, text } = await call(
      apiKey,
      `/services?name=${encodeURIComponent(serviceRef)}&limit=50`,
    )
    if (!ok) {
      console.error(`Render API ${status}: ${data?.message || text}`)
      process.exitCode = 1
      return
    }
    const list = Array.isArray(data) ? data : []
    const exact = list.find((item) => (item.service?.name || item.name) === serviceRef)
    if (!exact) {
      console.error(`Сервис «${serviceRef}» не найден. Доступные:`)
      for (const item of list) {
        console.error(`  ${item.service?.name || item.name}  ${item.service?.id || item.id}`)
      }
      console.error('Задай RENDER_SERVICE с точным id (srv-...).')
      process.exitCode = 1
      return
    }
    serviceId = exact.service?.id || exact.id
  }
  console.log(`Сервис: ${serviceId}`)

  for (const [key, value] of Object.entries(values)) {
    let result = await call(apiKey, `/services/${serviceId}/env-vars/${encodeURIComponent(key)}`, {
      method: 'PUT',
      body: JSON.stringify({ value }),
    })
    // Older API versions only had POST /env-vars for new keys.
    if (result.status === 404) {
      result = await call(apiKey, `/services/${serviceId}/env-vars`, {
        method: 'POST',
        body: JSON.stringify({ key, value }),
      })
    }
    if (!result.ok) {
      console.error(`Не удалось записать ${key}: ${result.status} ${result.data?.message || result.text}`)
      process.exitCode = 1
      return
    }
    console.log(`  ${key} → задано`)
  }

  const deploy = await call(apiKey, `/services/${serviceId}/deploys`, {
    method: 'POST',
    body: JSON.stringify({ clearCache: 'do_not_clear' }),
  })
  if (!deploy.ok) {
    console.error(`Переменные записаны, но деплой не запустился: ${deploy.status} ${deploy.data?.message || deploy.text}`)
    console.error('Запусти Manual Deploy в дашборде.')
    process.exitCode = 1
    return
  }
  console.log(`Деплой запущен: ${deploy.data?.id || 'ok'}`)
  console.log('Через 2–4 минуты проверь /api/monitor — блок env должен быть весь зелёный.')
}

main().catch((error) => {
  console.error(error?.name === 'TimeoutError' ? 'Render API не ответил вовремя.' : error?.message || error)
  process.exitCode = 1
})
