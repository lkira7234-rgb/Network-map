import { chromium } from 'playwright'

const BASE = 'https://network-map-3cw5.onrender.com/'
const browser = await chromium.launch()

const ctx = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  permissions: ['clipboard-read', 'clipboard-write'],
})
const page = await ctx.newPage()
const errors = []
page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()) })
page.on('pageerror', (e) => errors.push(String(e)))

await page.goto(`${BASE}?target=github.com&ports=80,443&trace=0`, { waitUntil: 'networkidle', timeout: 120000 })
await page.waitForFunction(() => /ГОТОВО|ОШИБКА/.test(document.querySelector('.status-pill')?.textContent || ''), { timeout: 90000 })
await page.waitForTimeout(3000)
console.log('live desktop', await page.evaluate(() => ({
  host: document.querySelector('.target-host')?.textContent,
  ip: document.querySelector('.target-ip')?.textContent,
  ports: document.querySelector('#ports')?.value,
  trace: document.querySelector('.toggle input')?.checked,
  stats: [...document.querySelectorAll('.stat-value')].map((el) => el.textContent),
  providers: [...document.querySelectorAll('.summary-item')].map((el) => el.textContent.trim()),
  cert: document.querySelector('.cert-row')?.textContent?.replace(/\s+/g, ' ').trim() || null,
  score: document.querySelector('.hygiene-score')?.textContent?.trim() || null,
  hygiene: [...document.querySelectorAll('.hygiene')].map((el) => `${el.textContent.trim()}${el.classList.contains('ok') ? '+ ' : '- '}`),
  limit: document.querySelector('.limit-line')?.textContent?.replace(/\s+/g, ' ').trim() || null,
  bundle: [...document.querySelectorAll('script')].map((s) => s.src).join(' '),
  x: document.documentElement.scrollWidth - window.innerWidth,
})), 'errors', errors)
await page.screenshot({ path: 'C:/Users/user/AppData/Local/Temp/opencode/live2-desktop.png' })

await page.getByRole('button', { name: /ССЫЛКА/ }).click()
await page.waitForTimeout(400)
console.log('share', await page.locator('.link-btn').textContent(), await page.evaluate(() => navigator.clipboard.readText()))

const mob = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true })
const pageMob = await mob.newPage()
const mobErrors = []
pageMob.on('console', (m) => { if (m.type() === 'error') mobErrors.push(m.text()) })
pageMob.on('pageerror', (e) => mobErrors.push(String(e)))
await pageMob.goto(BASE, { waitUntil: 'networkidle', timeout: 120000 })
await pageMob.waitForTimeout(1200)
await pageMob.getByRole('button', { name: 'ИНФРА' }).click()
console.log('mobile preset', await pageMob.inputValue('#ports'), await pageMob.locator('.preset-row .chip.active').textContent())
await pageMob.screenshot({ path: 'C:/Users/user/AppData/Local/Temp/opencode/live2-mobile-scan.png' })

await pageMob.getByRole('button', { name: /демо/i }).click()
await pageMob.getByRole('button', { name: /данные/i }).click()
await pageMob.waitForFunction(() => document.querySelectorAll('.stat.hops .stat-value')[0]?.textContent === '8', { timeout: 60000 })
await pageMob.waitForTimeout(1500)
console.log('mobile summary', await pageMob.evaluate(() => ({
  providers: [...document.querySelectorAll('.summary-item')].map((el) => el.textContent.trim()),
  score: document.querySelector('.hygiene-score')?.textContent?.trim(),
  cert: document.querySelector('.cert-row')?.textContent?.replace(/\s+/g, ' ').trim(),
  x: document.documentElement.scrollWidth - window.innerWidth,
})), 'errors', mobErrors)
await pageMob.screenshot({ path: 'C:/Users/user/AppData/Local/Temp/opencode/live2-mobile-summary.png' })

await browser.close()