import fs from 'node:fs'
import path from 'node:path'
import net from 'node:net'
import dns from 'node:dns/promises'
import { normalizeTarget } from './scan.js'

/**
 * Optional headless screenshot service for web ports.
 *
 * Uses `puppeteer-core` (pure JS) with a locally installed Chrome/Chromium.
 * Nothing is bundled and no browser is downloaded at runtime. When Chrome is
 * not available the endpoint reports `available: false` and the UI simply hides
 * the preview block — scans keep working.
 */

const PREVIEW_TTL = 6 * 3600_000
const SCREENSHOT_TIMEOUT = 5000
const MAX_DATA = 900_000
const WEB_PORTS = new Map([
  [80, 'http'],
  [443, 'https'],
  [8080, 'http'],
  [8443, 'https'],
])

const CHROME_CANDIDATES = [
  process.env.CHROME_PATH,
  process.env.PUPPETEER_EXECUTABLE_PATH,
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
  `${process.env.LOCALAPPDATA || ''}\\Google\\Chrome\\Application\\chrome.exe`,
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/snap/bin/chromium',
]

const HEADLESS_NAMES = new Set([
  'chrome-headless-shell.exe',
  'chrome-headless-shell',
  'headless_shell',
  'chrome.exe',
  'chrome',
])

/**
 * `npm run preview:install` downloads a headless Chromium into `.chrome/`.
 * Locate it without depending on the exact versioned folder name.
 */
function findCachedChrome(root, depth = 0) {
  if (!root || depth > 5) return null
  let entries
  try {
    entries = fs.readdirSync(root, { withFileTypes: true })
  } catch {
    return null
  }
  for (const entry of entries) {
    if (entry.isFile() && HEADLESS_NAMES.has(entry.name)) {
      return path.join(root, entry.name)
    }
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue
    const found = findCachedChrome(path.join(root, entry.name), depth + 1)
    if (found) return found
  }
  return null
}

function executablePath() {
  const cached = findCachedChrome(path.join(process.cwd(), '.chrome'))
  if (cached) return cached
  for (const candidate of CHROME_CANDIDATES) {
    if (!candidate) continue
    try {
      if (fs.existsSync(candidate)) return candidate
    } catch {}
  }
  return null
}

function isPrivateHost(host) {
  const value = String(host || '').toLowerCase().replace(/^\[|\]$/g, '')
  if (!value || ['localhost', '0.0.0.0'].includes(value)) return true
  if (value.endsWith('.local') || value.endsWith('.internal') || value.endsWith('.localhost')) return true
  if (net.isIP(value) === 4) {
    const [a, b] = value.split('.').map(Number)
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 0 || b === 168)) ||
      (a === 100 && b >= 64 && b <= 127)
    )
  }
  if (net.isIP(value) === 6) {
    return value === '::1' || value.startsWith('fc') || value.startsWith('fd') || value.startsWith('fe80')
  }
  return false
}

export function createPreview(env = process.env, store = null, logger = console) {
  const enabled = !/^(0|false|no|off)$/i.test(String(env.PREVIEW_ENABLED ?? '').trim())
  const chrome = executablePath()
  let puppeteer = undefined
  let browserPromise = null

  async function loadPuppeteer() {
    if (puppeteer !== undefined) return puppeteer
    try {
      const module = await import('puppeteer-core')
      puppeteer = module.default || module
    } catch (error) {
      puppeteer = null
      logger?.warn?.(`[preview] puppeteer-core unavailable: ${error?.message || error}`)
    }
    return puppeteer
  }

  async function getBrowser() {
    if (browserPromise) return browserPromise
    browserPromise = (async () => {
      const lib = await loadPuppeteer()
      if (!lib || !chrome) return null
      const browser = await lib.launch({
        executablePath: chrome,
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-gpu',
          '--hide-scrollbars',
          '--ignore-certificate-errors',
          '--window-size=800,500',
        ],
      })
      browser.on?.('disconnected', () => {
        browserPromise = null
      })
      logger?.log?.(`[preview] chrome · ${chrome}`)
      return browser
    })().catch((error) => {
      logger?.warn?.(`[preview] launch failed: ${error?.message || error}`)
      browserPromise = null
      return null
    })
    return browserPromise
  }

  function publicStatus() {
    return {
      enabled,
      available: Boolean(enabled && chrome),
      engine: chrome ? 'chrome' : null,
      ports: [...WEB_PORTS.keys()],
    }
  }

  async function capture(hostRaw, portRaw) {
    if (!enabled) return { ok: false, status: 404, error: 'Скриншоты выключены (PREVIEW_ENABLED=0)' }
    if (!chrome) {
      return {
        ok: false,
        status: 501,
        error: 'Headless Chrome не найден',
        hint: 'Установи Chrome/Chromium, задай CHROME_PATH или выполни npm run preview:install',
        ...publicStatus(),
      }
    }

    let host
    try {
      host = normalizeTarget(String(hostRaw || '')).host
    } catch {
      return { ok: false, status: 400, error: 'Некорректный хост' }
    }
    if (isPrivateHost(host)) return { ok: false, status: 400, error: 'Приватные адреса не скриншотятся' }
    // A public DNS name can still point at an internal address, so resolve it
    // before handing the URL to the browser. This keeps the preview endpoint
    // from becoming a small SSRF proxy.
    if (net.isIP(host) === 0) {
      const addresses = await dns.lookup(host, { all: true, verbatim: true }).catch(() => [])
      if (!addresses.length) return { ok: false, status: 400, error: 'Хост не разрешается в IP' }
      if (addresses.some((entry) => isPrivateHost(entry.address))) {
        return { ok: false, status: 400, error: 'Приватные адреса не скриншотятся' }
      }
    }

    const port = Number(portRaw)
    const scheme = WEB_PORTS.get(port)
    if (!scheme) return { ok: false, status: 400, error: 'Только 80, 443, 8080 и 8443' }

    const key = `${scheme}://${host}:${port}`
    const cached = store?.getPreview?.(key)
    if (cached?.data && Date.now() - (cached.at || 0) < PREVIEW_TTL) {
      return { ok: true, ...cached.data, cached: true }
    }

    const browser = await getBrowser()
    if (!browser) {
      return { ok: false, status: 503, error: 'Браузер не запустился', ...publicStatus() }
    }

    const started = Date.now()
    const url = `${scheme}://${host}${port === 80 || port === 443 ? '' : `:${port}`}/`

    // The very first navigation after a cold start can exceed the 5 s budget
    // while the renderer warms up, so one retry keeps the user-visible timeout
    // strict without failing on the first ever screenshot.
    let lastError = null
    for (let attempt = 0; attempt < 2; attempt++) {
      let page = null
      try {
        page = await browser.newPage()
        await page.setViewport({ width: 800, height: 500, deviceScaleFactor: 1 })
        await page.setUserAgent('NetworkMap/1.0 (headless preview)')
        // Redirects must not tunnel the headless browser into localhost or a
        // private network. The initial host is checked above; this also guards
        // every redirect and subresource with a literal private address.
        await page.setRequestInterception(true)
        page.on('request', (request) => {
          try {
            const target = new URL(request.url())
            if (isPrivateHost(target.hostname)) {
              void request.abort().catch(() => {})
              return
            }
          } catch {}
          void request.continue().catch(() => {})
        })
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: SCREENSHOT_TIMEOUT })
        await new Promise((resolve) => setTimeout(resolve, 650))
        const base64 = await page.screenshot({
          type: 'jpeg',
          quality: 58,
          encoding: 'base64',
          clip: { x: 0, y: 0, width: 800, height: 500 },
        })
        const image = `data:image/jpeg;base64,${base64}`
        if (image.length > MAX_DATA) {
          return { ok: false, status: 413, error: 'Скриншот слишком большой' }
        }
        const data = {
          image,
          url,
          title: await page.title().catch(() => null),
          ms: Date.now() - started,
        }
        store?.setPreview?.(key, data)
        return { ok: true, ...data, cached: false }
      } catch (error) {
        lastError = error
        const retryable = error?.name === 'TimeoutError' || error?.name === 'net::ERR_TIMED_OUT'
        if (!retryable || attempt === 1) break
      } finally {
        try {
          await page?.close()
        } catch {}
      }
    }

    return {
      ok: false,
      status: 502,
      error:
        lastError?.name === 'TimeoutError'
          ? 'Страница не ответила за 5 секунд'
          : lastError?.message || 'Не удалось сделать скриншот',
    }
  }

  async function close() {
    const browser = await browserPromise
    browserPromise = null
    try {
      await browser?.close()
    } catch {}
  }

  return { capture, close, publicStatus }
}
