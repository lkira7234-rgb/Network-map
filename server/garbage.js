import dns from 'node:dns/promises'
import net from 'node:net'

/**
 * "Garbage mode": pick a random target that actually has something behind it.
 *
 * Three kinds of target:
 *   site — a domain whose HTTP(S) page is real content, not a parked/for-sale
 *          placeholder;
 *   dns  — a nameserver of a random domain;
 *   ip   — a public IP that answers on 80/443 (or the A record of a live domain).
 *
 * The pool is server-side only: the browser cannot make the server fetch an
 * arbitrary URL. Operators can extend it with GARBAGE_SITES / GARBAGE_POOL_URL.
 */

const USER_AGENT = 'NetworkMap/1.0 (random live target picker)'
const VERIFY_TIMEOUT = 3800
const MAX_BODY = 64 * 1024
const MAX_TRIES = 8
const BATCH = 4
const RECENT_MAX = 48
const IP_PROBE_TIMEOUT = 1400
const REMOTE_POOL_TTL = 6 * 3600_000
const REMOTE_POOL_MAX = 4000

const KINDS = ['auto', 'site', 'dns', 'ip']

/** Well-known, real, globally reachable sites. No parked domains. */
const SITE_SEEDS = [
  // dev / open source
  'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com', 'stackexchange.com',
  'npmjs.com', 'pypi.org', 'crates.io', 'packagist.org', 'hub.docker.com',
  'nodejs.org', 'deno.com', 'python.org', 'rust-lang.org', 'go.dev', 'php.net',
  'ruby-lang.org', 'java.com', 'kotlinlang.org', 'swift.org', 'dotnet.microsoft.com',
  'developer.mozilla.org', 'dev.to', 'hashnode.com', 'freecodecamp.org', 'codecademy.com',
  'leetcode.com', 'hackerrank.com', 'codepen.io', 'jsfiddle.net', 'replit.com',
  'sourceforge.net', 'savannah.gnu.org', 'gnu.org', 'kernel.org', 'debian.org',
  'ubuntu.com', 'archlinux.org', 'fedoraproject.org', 'opensuse.org', 'freebsd.org',
  'openbsd.org', 'alpinelinux.org', 'linuxmint.com', 'manjaro.org', 'gentoo.org',
  'docker.com', 'kubernetes.io', 'terraform.io', 'ansible.com', 'helm.sh',
  'jenkins.io', 'grafana.com', 'prometheus.io', 'elastic.co', 'mongodb.com',
  'postgresql.org', 'mysql.com', 'redis.io', 'sqlite.org', 'mariadb.org',
  'nginx.org', 'apache.org', 'caddyserver.com', 'traefik.io', 'haproxy.org',
  // cloud / hosting / infra
  'cloudflare.com', 'aws.amazon.com', 'azure.microsoft.com', 'cloud.google.com',
  'digitalocean.com', 'linode.com', 'vultr.com', 'hetzner.com', 'ovhcloud.com',
  'scaleway.com', 'oracle.com', 'ibm.com', 'redhat.com', 'suse.com', 'vmware.com',
  'vercel.com', 'netlify.com', 'render.com', 'fly.io', 'railway.app',
  'heroku.com', 'supabase.com', 'firebase.google.com', 'planetscale.com', 'neon.tech',
  'upstash.com', 'sentry.io', 'datadoghq.com', 'newrelic.com', 'pagerduty.com',
  'statuspage.io', 'uptimerobot.com', 'speedtest.net', 'fast.com', 'nperf.com',
  // security
  'owasp.org', 'mitre.org', 'cve.org', 'nvd.nist.gov', 'cisa.gov', 'kaspersky.com',
  'malwarebytes.com', 'avast.com', 'eset.com', 'trendmicro.com', 'crowdstrike.com',
  'virustotal.com', 'shodan.io', 'censys.io', 'hackerone.com', 'bugcrowd.com',
  'exploit-db.com', 'securityweek.com', 'thehackernews.com', 'bleepingcomputer.com',
  'krebsonsecurity.com', 'schneier.com', 'portswigger.net', 'wireshark.org',
  // news / media
  'bbc.com', 'cnn.com', 'reuters.com', 'apnews.com', 'theguardian.com', 'nytimes.com',
  'washingtonpost.com', 'bloomberg.com', 'ft.com', 'wsj.com', 'economist.com',
  'aljazeera.com', 'dw.com', 'france24.com', 'lemonde.fr', 'spiegel.de', 'elpais.com',
  'corriere.it', 'lefigaro.fr', 'npr.org', 'pbs.org', 'abcnews.go.com', 'nbcnews.com',
  'cbsnews.com', 'usatoday.com', 'latimes.com', 'politico.com', 'axios.com',
  'theatlantic.com', 'newyorker.com', 'wired.com', 'theverge.com', 'techcrunch.com',
  'arstechnica.com', 'engadget.com', 'gizmodo.com', 'cnet.com', 'zdnet.com',
  'venturebeat.com', 'thenextweb.com', 'theregister.com', 'slashdot.org',
  'news.ycombinator.com', 'lobste.rs', 'reddit.com',
  // russian-language
  'yandex.ru', 'ya.ru', 'mail.ru', 'vk.com', 'ok.ru', 'rutube.ru', 'dzen.ru',
  'habr.com', 'lenta.ru', 'rbc.ru', 'kommersant.ru', 'vedomosti.ru', 'forbes.ru',
  'tass.ru', 'ria.ru', 'interfax.ru', 'meduza.io', 'novayagazeta.eu', 'theins.ru',
  'mos.ru', 'gosuslugi.ru', 'kremlin.ru', 'government.ru', 'mchs.gov.ru',
  'sber.ru', 'tbank.ru', 'alfabank.ru', 'vtb.ru', 'gazprombank.ru', 'raiffeisen.ru',
  'wildberries.ru', 'ozon.ru', 'avito.ru', 'dns-shop.ru', 'mvideo.ru', 'eldorado.ru',
  'citilink.ru', 'leroymerlin.ru', 'vseinstrumenti.ru', 'samokat.ru', 'yandex.cloud',
  '2gis.ru', 'ria.ru', 'kinopoisk.ru', 'ivi.ru', 'more.tv', 'premier.one',
  'mail.yandex.ru', 'translate.yandex.ru', 'maps.yandex.ru', 'music.yandex.ru',
  // social / video / music
  'x.com', 'facebook.com', 'instagram.com', 'linkedin.com', 'pinterest.com',
  'tumblr.com', 'mastodon.social', 'threads.net', 'discord.com', 'telegram.org',
  'whatsapp.com', 'signal.org', 'element.io', 'matrix.org', 'slack.com',
  'youtube.com', 'vimeo.com', 'twitch.tv', 'dailymotion.com', 'rumble.com',
  'spotify.com', 'soundcloud.com', 'bandcamp.com', 'deezer.com', 'last.fm',
  'imdb.com', 'letterboxd.com', 'goodreads.com', 'wikidata.org',
  // shopping / services
  'amazon.com', 'ebay.com', 'etsy.com', 'aliexpress.com', 'walmart.com', 'target.com',
  'bestbuy.com', 'homedepot.com', 'ikea.com', 'costco.com', 'alibaba.com',
  'booking.com', 'airbnb.com', 'expedia.com', 'tripadvisor.com', 'skyscanner.net',
  'uber.com', 'lyft.com', 'doordash.com', 'ubereats.com', 'deliveroo.co.uk',
  'paypal.com', 'stripe.com', 'wise.com', 'revolut.com', 'klarna.com',
  'coinbase.com', 'binance.com', 'kraken.com', 'bitstamp.net',
  // education / science / reference
  'wikipedia.org', 'wikimedia.org', 'archive.org', 'openlibrary.org', 'gutenberg.org',
  'britannica.com', 'dictionary.com', 'thesaurus.com', 'merriam-webster.com',
  'coursera.org', 'edx.org', 'khanacademy.org', 'udemy.com', 'duolingo.com',
  'mit.edu', 'harvard.edu', 'stanford.edu', 'berkeley.edu', 'ox.ac.uk', 'cam.ac.uk',
  'ethz.ch', 'sorbonne-universite.fr', 'moscowstate.university', 'spbu.ru', 'hse.ru',
  'arxiv.org', 'nature.com', 'science.org', 'sciencedirect.com', 'springer.com',
  'ieee.org', 'acm.org', 'plos.org', 'cell.com', 'thelancet.com',
  'nasa.gov', 'esa.int', 'noaa.gov', 'usgs.gov', 'who.int', 'un.org', 'worldbank.org',
  // maps / travel / weather
  'openstreetmap.org', 'mapbox.com', 'google.com', 'bing.com', 'duckduckgo.com',
  'weather.com', 'accuweather.com', 'windy.com', 'timeanddate.com', 'time.is',
  'ryanair.com', 'lufthansa.com', 'emirates.com', 'britishairways.com',
  'marriott.com', 'hilton.com', 'hostelworld.com',
  // random useful
  'gandi.net', 'namecheap.com', 'godaddy.com', 'cloudns.net', 'letsencrypt.org',
  'ssllabs.com', 'haveibeenpwned.com', 'ipleak.net', 'whatismyipaddress.com',
  'ipinfo.io', 'ipapi.co', 'db-ip.com', 'maxmind.com', 'ripe.net', 'arin.net',
  'apnic.net', 'lacnic.net', 'afrinic.net', 'icann.org', 'iana.org',
  'python.org', 'json.org', 'yaml.org', 'w3.org', 'whatwg.org', 'ietf.org',
]

/** Registrable domains used by domain-parking services. */
const PARKED_HOSTS = [
  'sedo.com', 'sedoparking.com', 'parkingcrew.net', 'hugedomains.com', 'afternic.com',
  'dan.com', 'undeveloped.com', 'buydomains.com', 'domainmarket.com', 'bodis.com',
  'above.com', 'parklogic.com', 'domainsponsor.com', 'smartname.com', 'voodoo.com',
  'fabulous.com', 'internettraffic.com', 'ztomy.com', 'parkingpage.namecheap.com',
  'namefind.com', 'brandbucket.com', 'squadhelp.com', 'atom.com', 'efty.com',
]

/** Nameserver suffixes of parking providers. */
const PARKED_NS = [
  'parkingcrew.net', 'sedoparking.com', 'above.com', 'bodis.com', 'domainsponsor.com',
  'parklogic.com', 'smartname.com', 'voodoo.com', 'fabulous.com', 'internettraffic.com',
  'ztomy.com', 'dsredirection.com', 'parkingpage.namecheap.com', 'namefind.com',
]

/** Phrases that only appear on a placeholder / for-sale / expired page. */
const PARKED_MARKERS = [
  'domain is for sale',
  'this domain is for sale',
  'domain name is for sale',
  'the domain name is for sale',
  'this domain may be for sale',
  'buy this domain',
  'purchase this domain',
  'make an offer on this domain',
  'make an offer for this domain',
  'inquire about this domain',
  'domain for sale',
  'domain name for sale',
  'this domain is parked',
  'domain parking',
  'parked free',
  'parkingcrew',
  'sedoparking',
  'hugedomains',
  'afternic',
  'dan.com/buy-domain',
  'buydomains.com',
  'domainmarket.com',
  'undeveloped.com',
  'domain has expired',
  'this domain has expired',
  'domain expired',
  'this site is under construction',
  'website coming soon',
  'default web page',
  'apache2 ubuntu default page',
  'apache2 debian default page',
  'welcome to nginx',
  'it works!',
  'index of /',
  'домен продаётся',
  'домен продается',
  'купить домен',
  'домен выставлен на продажу',
  'домен свободен',
  'парковка домена',
  'страница-заглушка',
  'этот домен продается',
  'этот домен продаётся',
]

/** High-density public ranges where random addresses usually answer. */
const IP_RANGES = [
  '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '162.159.128.0/17',
  '142.250.0.0/15', '172.217.0.0/16', '216.58.192.0/19',
  '151.101.0.0/16', '199.232.0.0/16',
  '23.32.0.0/11', '23.192.0.0/11',
  '185.199.108.0/22', '140.82.112.0/20',
  '157.240.0.0/16', '31.13.24.0/21',
]

const WELL_KNOWN_DNS = [
  '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112',
  '77.88.8.8', '77.88.8.1', '208.67.222.222', '208.67.220.220',
  '94.140.14.14', '94.140.15.15', '64.6.64.6', '64.6.65.6', '84.200.69.80',
]

/**
 * Random-name generator. Pairs of common words are used because a random
 * string almost never resolves; word pairs still produce believable names and
 * occasionally hit a registered domain. Candidates are verified exactly like
 * curated seeds and never returned without a live HTTP response.
 */
const GEN_PREFIX = [
  'abandoned', 'analog', 'ancient', 'arcade', 'atlas', 'aurora', 'binary', 'broken',
  'cobalt', 'copper', 'crimson', 'cyber', 'dark', 'decay', 'digital', 'drift',
  'electric', 'ember', 'faded', 'ferro', 'ghost', 'glitch', 'granite', 'hollow',
  'idle', 'iron', 'laser', 'lonely', 'lunar', 'magnetic', 'neon', 'night',
  'old', 'omega', 'orbital', 'pixel', 'quiet', 'radio', 'retro', 'rust',
  'sable', 'scrap', 'shadow', 'silent', 'silver', 'static', 'steel', 'stone',
  'sunken', 'titan', 'velvet', 'vintage', 'void', 'wired', 'zero',
]

const GEN_NOUN = [
  'arcade', 'array', 'beacon', 'bridge', 'bunker', 'cache', 'circuit', 'cluster',
  'console', 'crane', 'delta', 'depot', 'docks', 'domain', 'drone', 'engine',
  'factory', 'farm', 'forge', 'gateway', 'grid', 'harbor', 'haven', 'hub',
  'junction', 'kernel', 'lab', 'layer', 'lighthouse', 'link', 'loop', 'machine',
  'matrix', 'mill', 'mine', 'module', 'node', 'outpost', 'portal', 'probe',
  'reactor', 'relay', 'rig', 'router', 'sector', 'signal', 'station',
  'switch', 'terminal', 'tower', 'transit', 'vault', 'vector', 'works', 'yard',
]

const GEN_TLDS = ['com', 'net', 'org', 'io', 'dev', 'xyz', 'info', 'site', 'online', 'tech']

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

const csv = (value) =>
  String(value || '')
    .split(/[\s,;]+/)
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean)

function randomOf(list) {
  return list[Math.floor(Math.random() * list.length)]
}

function clampInt(value, min, max, fallback) {
  const number = Number(value)
  if (!Number.isFinite(number)) return fallback
  return Math.min(max, Math.max(min, Math.round(number)))
}

function tail2(host) {
  const parts = String(host || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean)
  return parts.slice(-2).join('.')
}

function sameSite(a, b) {
  const x = String(a || '').toLowerCase().replace(/\.$/, '')
  const y = String(b || '').toLowerCase().replace(/\.$/, '')
  if (!x || !y) return false
  return x === y || x.endsWith(`.${y}`) || y.endsWith(`.${x}`) || tail2(x) === tail2(y)
}

function isParkedHost(host) {
  const value = String(host || '').toLowerCase().replace(/\.$/, '')
  if (!value) return false
  return PARKED_HOSTS.some((parked) => value === parked || value.endsWith(`.${parked}`))
}

function isParkedNs(host) {
  const value = String(host || '').toLowerCase().replace(/\.$/, '')
  if (!value) return false
  return PARKED_NS.some((parked) => value === parked || value.endsWith(`.${parked}`))
}

function isPublicIpv4(ip) {
  if (net.isIP(ip) !== 4) return false
  const [a, b] = ip.split('.').map(Number)
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false
  if (a === 100 && b >= 64 && b <= 127) return false
  if (a === 169 && b === 254) return false
  if (a === 172 && b >= 16 && b <= 31) return false
  if (a === 192 && (b === 0 || b === 168)) return false
  if (a === 198 && (b === 18 || b === 19)) return false
  return true
}

function extractTitle(html) {
  const match = /<title[^>]*>([\s\S]{0,240}?)<\/title>/i.exec(html)
  if (!match) return null
  return match[1]
    .replace(/\s+/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .trim()
    .slice(0, 120) || null
}

function analyzeHtml(html) {
  const title = extractTitle(html)
  const stripped = html
    .replace(/<script\b[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript\b[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&[a-z#0-9]+;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim()

  const haystack = `${title || ''}\n${stripped.slice(0, 12000)}`.toLowerCase()
  const marker = PARKED_MARKERS.find((phrase) => haystack.includes(phrase)) || null
  const scripts = (html.match(/<script\b/gi) || []).length
  const links = (html.match(/<a\s/gi) || []).length
  const appShell = /<div[^>]+id=["'](?:root|app|__next|__nuxt)["']/i.test(html)
  const real =
    !marker &&
    (stripped.length >= 120 || (Boolean(title) && (stripped.length >= 40 || (scripts >= 2 && (links >= 3 || appShell)))))

  return { title, textLength: stripped.length, bytes: html.length, scripts, links, marker, real }
}

async function readLimited(response, limit) {
  if (!response.body) return ''
  const reader = response.body.getReader()
  const chunks = []
  let total = 0
  try {
    while (total < limit) {
      const { done, value } = await reader.read()
      if (done) break
      if (value?.length) {
        chunks.push(Buffer.from(value))
        total += value.length
      }
    }
  } finally {
    try {
      await reader.cancel()
    } catch {}
  }
  return Buffer.concat(chunks).subarray(0, limit).toString('utf8')
}

async function inspectSite(host) {
  const attempts = [`https://${host}/`, `http://${host}/`]
  const errors = []

  for (const url of attempts) {
    const started = Date.now()
    try {
      const response = await fetch(url, {
        redirect: 'follow',
        signal: AbortSignal.timeout(VERIFY_TIMEOUT),
        headers: {
          'User-Agent': USER_AGENT,
          Accept: 'text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5',
          'Accept-Language': 'en-US,en;q=0.8,ru;q=0.7',
          'Cache-Control': 'no-cache',
        },
      })

      const status = response.status
      let finalHost = host
      try {
        finalHost = new URL(response.url).hostname
      } catch {}

      if (status >= 400) {
        errors.push({ url, status, error: `HTTP ${status}` })
        continue
      }
      if (isParkedHost(finalHost)) {
        errors.push({ url, status, finalHost, error: 'редирект на парковку' })
        continue
      }
      if (!sameSite(host, finalHost)) {
        errors.push({ url, status, finalHost, error: 'редирект на другой сайт' })
        continue
      }

      const contentType = String(response.headers.get('content-type') || '')
      if (contentType && !/html|xhtml|text\/plain/i.test(contentType)) {
        errors.push({ url, status, error: `не HTML (${contentType.slice(0, 40)})` })
        continue
      }

      const html = await readLimited(response, MAX_BODY)
      if (!html.trim()) {
        errors.push({ url, status, error: 'пустой ответ' })
        continue
      }

      const info = analyzeHtml(html)
      if (info.marker) {
        errors.push({ url, status, error: `заглушка: «${info.marker}»` })
        continue
      }
      if (!info.real) {
        errors.push({ url, status, error: 'слишком мало контента' })
        continue
      }

      return {
        ok: true,
        url,
        status,
        finalHost,
        server: response.headers.get('server') || null,
        contentType: contentType || null,
        title: info.title,
        textLength: info.textLength,
        bytes: info.bytes,
        ms: Date.now() - started,
      }
    } catch (error) {
      errors.push({
        url,
        error: error?.name === 'TimeoutError' ? 'таймаут' : error?.message || 'ошибка сети',
      })
    }
  }

  return { ok: false, errors }
}

function tcpOpen(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = new net.Socket()
    let done = false
    const finish = (ok) => {
      if (done) return
      done = true
      socket.destroy()
      resolve(ok)
    }
    socket.setTimeout(timeoutMs)
    socket.once('connect', () => finish(true))
    socket.once('timeout', () => finish(false))
    socket.once('error', () => finish(false))
    try {
      socket.connect({ host: ip, port })
    } catch {
      finish(false)
    }
  })
}

function randomIpFromCidr(cidr) {
  const [base, bitsRaw] = cidr.split('/')
  const bits = Number(bitsRaw)
  const octets = base.split('.').map(Number)
  const baseInt = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0
  const size = 2 ** (32 - bits)
  const offset = Math.floor(Math.random() * Math.max(1, size - 2)) + 1
  const value = (baseInt + offset) >>> 0
  return [value >>> 24, (value >> 16) & 255, (value >> 8) & 255, value & 255].join('.')
}

async function findFirst(candidates, worker, concurrency = BATCH) {
  const queue = candidates.slice()
  let active = 0
  let settled = false

  return new Promise((resolve) => {
    const next = () => {
      if (settled) return
      if (!queue.length && active === 0) {
        settled = true
        resolve(null)
        return
      }
      while (active < concurrency && queue.length) {
        const item = queue.shift()
        active++
        Promise.resolve()
          .then(() => worker(item))
          .then((result) => {
            active--
            if (result?.ok && !settled) {
              settled = true
              resolve({ item, result })
            } else {
              next()
            }
          })
          .catch(() => {
            active--
            next()
          })
      }
    }
    next()
  })
}

async function safe(promise, ms = VERIFY_TIMEOUT) {
  return Promise.race([
    Promise.resolve(promise).catch(() => null),
    sleep(ms).then(() => null),
  ])
}

export function createGarbage(env = process.env, logger = console) {
  const extraSites = csv(env.GARBAGE_SITES)
  const remotePoolUrl = String(env.GARBAGE_POOL_URL || '').trim()
  const maxTries = clampInt(env.GARBAGE_TRIES, 2, 16, MAX_TRIES)
  const remoteTimeout = clampInt(env.GARBAGE_FETCH_TIMEOUT, 1000, 12000, VERIFY_TIMEOUT)

  let remotePool = []
  let remoteAt = 0
  let remoteLoading = null
  const recent = []

  function nextDomain() {
    const pool = remotePool.length ? [...SITE_SEEDS, ...remotePool] : SITE_SEEDS
    for (let attempt = 0; attempt < 24; attempt++) {
      const host = randomOf(pool)
      if (!host || recent.includes(host)) continue
      recent.push(host)
      if (recent.length > RECENT_MAX) recent.shift()
      return host
    }
    return randomOf(pool)
  }

  function nextCandidates(count) {
    const set = new Set()
    while (set.size < count) set.add(nextDomain())
    return [...set]
  }

  /**
   * Random word-pair names, checked with the same HTTP content filter as the
   * curated pool. They are tried first so every run genuinely explores new
   * names; curated seeds guarantee an answer when the generated ones are dead.
   */
  function nextGenerated(count) {
    const set = new Set()
    let guard = 0
    while (set.size < count && guard < count * 8) {
      guard++
      const host = `${randomOf(GEN_PREFIX)}${randomOf(GEN_NOUN)}.${randomOf(GEN_TLDS)}`
      if (recent.includes(host)) continue
      set.add(host)
    }
    for (const host of set) {
      recent.push(host)
      if (recent.length > RECENT_MAX) recent.shift()
    }
    return [...set]
  }

  async function loadRemotePool() {
    if (!remotePoolUrl) return
    if (remotePool.length && Date.now() - remoteAt < REMOTE_POOL_TTL) return
    if (remoteLoading) return remoteLoading
    remoteLoading = (async () => {
      try {
        const response = await fetch(remotePoolUrl, {
          signal: AbortSignal.timeout(remoteTimeout),
          headers: { 'User-Agent': USER_AGENT, Accept: 'text/plain' },
        })
        if (!response.ok) return
        const text = (await response.text()).slice(0, 1_000_000)
        const values = []
        for (const line of text.split(/[\r\n]+/)) {
          const host = line
            .replace(/#.*$/, '')
            .trim()
            .toLowerCase()
            .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
            .replace(/[/?#].*$/, '')
            .replace(/:\d+$/, '')
            .replace(/\.$/, '')
          if (!host || host.length > 253) continue
          if (!/^(?=.{4,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/.test(host)) continue
          values.push(host)
          if (values.length >= REMOTE_POOL_MAX) break
        }
        if (values.length) {
          remotePool = [...new Set(values)]
          remoteAt = Date.now()
          logger.log(`[garbage] loaded ${remotePool.length} extra site(s) from GARBAGE_POOL_URL`)
        }
      } catch (error) {
        logger.warn(`[garbage] pool url failed: ${error?.message || error}`)
      } finally {
        remoteLoading = null
      }
    })()
    return remoteLoading
  }

  async function pickSite() {
    await loadRemotePool()
    const generated = nextGenerated(4)
    const candidates = [...new Set([...generated, ...nextCandidates(maxTries)])]
    const found = await findFirst(candidates, inspectSite)
    if (!found) return null
    const wasGenerated = generated.includes(found.item)
    return {
      target: found.item,
      kind: 'site',
      verify: {
        http: found.result.status,
        title: found.result.title,
        bytes: found.result.bytes,
        finalHost: found.result.finalHost,
        server: found.result.server,
        ms: found.result.ms,
        generated: wasGenerated,
      },
      meta: {
        pool: remotePool.length ? 'seed+remote' : 'seed',
        candidates: candidates.length,
        generated: wasGenerated,
      },
    }
  }

  async function pickDns() {
    const domains = nextCandidates(Math.min(6, maxTries))
    for (const domain of domains) {
      const records = await safe(dns.resolveNs(domain), 5000)
      const nameservers = (records || []).filter((name) => name && !isParkedNs(name))
      if (!nameservers.length) continue

      const ordered = nameservers
        .map((name) => ({ name: String(name).toLowerCase().replace(/\.$/, ''), order: Math.random() }))
        .sort((a, b) => a.order - b.order)

      for (const nameserver of ordered.slice(0, 3)) {
        const addresses = await safe(dns.resolve4(nameserver.name), 4000)
        const ip = (addresses || []).find(isPublicIpv4)
        if (!ip) continue
        if (!(await tcpOpen(ip, 53, 1800))) continue
        return {
          target: nameserver.name,
          kind: 'dns',
          verify: {
            domain,
            ip,
            ns: nameserver.name,
            tcp53: true,
            reason: `NS-сервер ${domain} отвечает на 53/tcp`,
          },
          meta: { domain, ip },
        }
      }
    }

    // Deterministic fallback: well-known public resolvers.
    const ip = randomOf(WELL_KNOWN_DNS)
    if (await tcpOpen(ip, 53, 1800)) {
      return {
        target: ip,
        kind: 'dns',
        verify: { ip, tcp53: true, reason: 'публичный DNS-резолвер' },
        meta: { resolver: true },
      }
    }
    return null
  }

  async function pickIp() {
    const candidates = Array.from({ length: 6 }, () => randomIpFromCidr(randomOf(IP_RANGES)))
    const found = await findFirst(candidates, async (ip) => {
      const [a, b] = await Promise.all([
        tcpOpen(ip, 443, IP_PROBE_TIMEOUT),
        tcpOpen(ip, 80, IP_PROBE_TIMEOUT),
      ])
      if (!a && !b) return { ok: false }
      return { ok: true, port: a ? 443 : 80 }
    })

    if (found) {
      return {
        target: found.item,
        kind: 'ip',
        verify: {
          ip: found.item,
          port: found.result.port,
          reason: `открыт ${found.result.port}/tcp`,
        },
        meta: { source: 'cdn-range' },
      }
    }

    // Fallback: the A record of a domain that is known to be alive.
    for (const domain of nextCandidates(4)) {
      const addresses = await safe(dns.resolve4(domain), 5000)
      const ip = (addresses || []).find(isPublicIpv4)
      if (!ip) continue
      return {
        target: ip,
        kind: 'ip',
        verify: { ip, domain, reason: `A-запись ${domain}` },
        meta: { domain, source: 'domain' },
      }
    }
    return null
  }

  async function pick(kindRaw = 'auto') {
    const requested = KINDS.includes(String(kindRaw).toLowerCase())
      ? String(kindRaw).toLowerCase()
      : 'auto'

    const order =
      requested === 'auto'
        ? ['site', 'site', 'dns', 'ip']
        : [requested, ...['site', 'dns', 'ip'].filter((item) => item !== requested)]

    for (const kind of order) {
      try {
        const result = await (kind === 'site' ? pickSite() : kind === 'dns' ? pickDns() : pickIp())
        if (result) {
          logger.log(
            `[garbage] ${result.kind} → ${result.target}` +
              (result.verify?.reason ? ` (${result.verify.reason})` : ''),
          )
          return { ok: true, pickedAt: Date.now(), ...result }
        }
      } catch (error) {
        logger.warn(`[garbage] ${kind} failed: ${error?.message || error}`)
      }
    }

    return {
      ok: false,
      kind: requested,
      pickedAt: Date.now(),
      error:
        requested === 'auto'
          ? 'Не нашёл живую цель. Попробуй ещё раз через минуту.'
          : `Не нашёл живую цель типа «${requested}». Попробуй ещё раз или выбери другой тип.`,
    }
  }

  function publicStatus() {
    return {
      kinds: KINDS.filter((kind) => kind !== 'auto'),
      sites: SITE_SEEDS.length + remotePool.length,
      generated: GEN_PREFIX.length * GEN_NOUN.length * GEN_TLDS.length,
      remotePool: remotePool.length,
      maxTries,
    }
  }

  return { pick, publicStatus }
}
