import { HttpInfo, IpEntry, TechCategory, TechHit } from './types'

/* ------------------------------------------------------------------ */
/*  local stack fingerprinting (Wappalyzer-lite)                       */
/* ------------------------------------------------------------------ */

/**
 * Everything here runs in the browser against signals the scanner already
 * received: headers, cookie *names*, <meta generator> and a truncated markup
 * sample. No extra request is made and no cookie value is stored.
 */

export const techColor: Record<TechCategory, string> = {
  cms: '#ff2fd6',
  framework: '#38f6ff',
  language: '#8b5cff',
  server: '#49ff9e',
  cdn: '#c07bff',
  analytics: '#ffb020',
  security: '#ff7a3d',
  ecommerce: '#ff5ee4',
  other: '#8b94a8',
}

export const techCategoryLabel: Record<TechCategory, string> = {
  cms: 'CMS',
  framework: 'FRAMEWORK',
  language: 'LANGUAGE',
  server: 'SERVER',
  cdn: 'CDN',
  analytics: 'ANALYTICS',
  security: 'SECURITY',
  ecommerce: 'ECOMMERCE',
  other: 'OTHER',
}

const CATEGORY_ORDER: TechCategory[] = [
  'cms',
  'ecommerce',
  'framework',
  'language',
  'server',
  'cdn',
  'security',
  'analytics',
  'other',
]

interface Rule {
  name: string
  category: TechCategory
  html?: RegExp
  cookie?: RegExp
  server?: RegExp
  poweredBy?: RegExp
  generator?: RegExp
  header?: [string, RegExp?]
  version?: RegExp
}

interface Context {
  html: string
  headers: Record<string, string>
  cookies: string[]
  server: string
  poweredBy: string
  generator: string
  imported: string[]
}

const RULES: Rule[] = [
  // --- CMS ---------------------------------------------------------
  {
    name: 'WordPress',
    category: 'cms',
    html: /\/wp-content\/|\/wp-includes\/|wp-json/i,
    cookie: /^(?:wordpress_|wp-settings-|wp_woocommerce_session)/i,
    generator: /wordpress/i,
    version: /WordPress\s*([\d.]+)/i,
  },
  { name: 'Drupal', category: 'cms', html: /drupal-settings-json|\/sites\/default\/files|Drupal\.behaviors/i, generator: /drupal/i, version: /Drupal\s*([\d.]+)/i },
  { name: 'Joomla', category: 'cms', html: /\/media\/system\/js\/|com_content|option=com_/i, generator: /joomla/i, version: /Joomla!\s*([\d.]+)/i },
  { name: '1C-Bitrix', category: 'cms', html: /\/bitrix\/(?:js|templates|cache)\//i, cookie: /^BITRIX_/i, generator: /bitrix/i },
  { name: 'Tilda', category: 'cms', html: /tildacdn\.com|tilda-blocks|tilda-module/i, generator: /tilda/i },
  { name: 'Wix', category: 'cms', html: /wixstatic\.com|wix-code-sdk|parastorage\.com/i, header: ['x-wix-request-id'] },
  { name: 'Squarespace', category: 'cms', html: /static1?\.squarespace\.com|squarespace-cdn\.com/i },
  { name: 'Ghost', category: 'cms', html: /ghost-url|content=["']Ghost\s*([\d.]+)/i, generator: /ghost/i, version: /Ghost\s*([\d.]+)/i },
  { name: 'MODX', category: 'cms', html: /\/assets\/components\/|\/manager\/media\//i },
  { name: 'DLE', category: 'cms', html: /\/engine\/classes\/|\/dlestatic\//i },
  { name: 'Magento', category: 'ecommerce', html: /mage\/cookies|Magento_[A-Z]|static\/version\d+/i, cookie: /^mage-/i },
  { name: 'WooCommerce', category: 'ecommerce', html: /\/wp-content\/plugins\/woocommerce\//i, cookie: /^woocommerce_/i },
  { name: 'OpenCart', category: 'ecommerce', html: /index\.php\?route=|catalog\/view\/theme\//i },
  { name: 'PrestaShop', category: 'ecommerce', html: /prestashop|var\/themes\/|modules\/ps_/i },
  { name: 'Shopify', category: 'ecommerce', html: /cdn\.shopify\.com|Shopify\.theme|shopify-section/i, cookie: /^_shopify_/i },
  { name: 'Bitrix.Shop', category: 'ecommerce', html: /\/bitrix\/components\/bitrix:sale\./i },

  // --- frameworks --------------------------------------------------
  { name: 'Next.js', category: 'framework', html: /__NEXT_DATA__|_next\/static\//, header: ['x-nextjs-cache'] },
  { name: 'Nuxt', category: 'framework', html: /__NUXT__|_nuxt\// },
  { name: 'React', category: 'framework', html: /react-dom|data-reactroot|react\.production\.min\.js/i },
  { name: 'Vue.js', category: 'framework', html: /data-v-[0-9a-f]{6,}|vue(?:\.runtime)?(?:\.min)?\.js/i },
  { name: 'Angular', category: 'framework', html: /ng-version=|ng-app=|angular(?:\.min)?\.js/i, version: /ng-version=["']([\d.]+)/i },
  { name: 'SvelteKit', category: 'framework', html: /__sveltekit|sveltekit-/i },
  { name: 'Astro', category: 'framework', html: /astro-island|astro-slot|data-astro-/i },
  { name: 'Gatsby', category: 'framework', html: /gatsby-|___gatsby/i },
  { name: 'jQuery', category: 'framework', html: /jquery(?:-|\.)(\d+\.\d+\.\d+)(?:\.min)?\.js/i, version: /jquery[-.](\d+\.\d+\.\d+)/i },
  { name: 'Bootstrap', category: 'framework', html: /bootstrap(?:@[\d.]+)?(?:\.min)?\.(?:css|js)/i, version: /bootstrap[@/-](\d+\.\d+\.\d+)/i },
  { name: 'Tailwind CSS', category: 'framework', html: /tailwindcss|class="[^"]*\b(?:flex|grid|space-y-\d)\b[^"]*"/i },
  { name: 'Laravel', category: 'framework', cookie: /^(?:laravel_session|XSRF-TOKEN)$/i, html: /laravel/i },
  { name: 'Django', category: 'framework', cookie: /^csrftoken$/i, html: /csrfmiddlewaretoken/i },
  { name: 'Ruby on Rails', category: 'framework', cookie: /_rails|_session_id/i, html: /csrf-token|authenticity_token/i },
  { name: 'Express', category: 'framework', header: ['x-powered-by', /^express/i] },
  { name: 'ASP.NET', category: 'framework', header: ['x-powered-by', /asp\.net/i], cookie: /^ASP\.NET_/i, html: /__viewstate|__eventvalidation/i },
  { name: 'PHP', category: 'language', header: ['x-powered-by', /php\/?([\d.]+)?/i], cookie: /^PHPSESSID$/i, version: /PHP\/([\d.]+)/i },
  { name: 'Spring', category: 'framework', cookie: /^JSESSIONID$/i, html: /whitelabel error page/i },
  { name: 'FastAPI', category: 'framework', server: /uvicorn/i, html: /fastapi|swagger-ui/i },
  { name: 'Flask', category: 'framework', server: /werkzeug/i },
  { name: 'Phoenix', category: 'framework', cookie: /^_phoenix_/i },
  { name: 'CodeIgniter', category: 'framework', cookie: /^ci_session$/i },
  { name: 'Symfony', category: 'framework', cookie: /^symfony/i },
  { name: 'Tomcat', category: 'server', header: ['server', /tomcat|coyote/i] },
  { name: 'Kestrel', category: 'server', header: ['server', /kestrel/i] },
  { name: 'Grafana', category: 'other', html: /grafana-app|public\/build\/.*grafana/i },
  { name: 'Kibana', category: 'other', html: /kbn-injected-metadata|kibana/i },
  { name: 'Jenkins', category: 'other', header: ['x-jenkins', /.+/] },
  { name: 'GitLab', category: 'other', html: /gon\.gitlab|gitlab-(?:logo|features)/i, cookie: /^_gitlab_session$/i },
  { name: 'Atlassian', category: 'other', html: /atlassian|jira|confluence/i },
  { name: 'Prometheus', category: 'other', html: /prometheus|graph\?g0\./i },
  { name: 'phpMyAdmin', category: 'other', html: /phpmyadmin|pma_/i, cookie: /^phpMyAdmin$/i },
  { name: 'SonarQube', category: 'other', html: /sonarqube/i },
  { name: 'Zabbix', category: 'other', html: /zabbix/i },
  { name: 'Roundcube', category: 'other', html: /roundcube/i },
  { name: 'phpLDAPadmin', category: 'other', html: /phpldapadmin/i },

  // --- web servers & edge ------------------------------------------
  { name: 'nginx', category: 'server', server: /nginx(?:\/([\d.]+))?/i, version: /nginx\/([\d.]+)/i },
  { name: 'Apache', category: 'server', server: /apache(?:\/([\d.]+))?/i, version: /Apache\/([\d.]+)/i },
  { name: 'IIS', category: 'server', server: /(?:microsoft-)?iis(?:\/([\d.]+))?/i, version: /IIS\/([\d.]+)/i },
  { name: 'LiteSpeed', category: 'server', server: /litespeed/i },
  { name: 'OpenResty', category: 'server', server: /openresty(?:\/([\d.]+))?/i, version: /openresty\/([\d.]+)/i },
  { name: 'Caddy', category: 'server', server: /caddy/i },
  { name: 'Envoy', category: 'server', header: ['server', /envoy/i] },
  { name: 'Varnish', category: 'cdn', header: ['x-varnish', /.+/], html: /varnish/i },
  { name: 'HAProxy', category: 'server', server: /haproxy/i },
  { name: 'gunicorn', category: 'server', server: /gunicorn(?:\/([\d.]+))?/i, version: /gunicorn\/([\d.]+)/i },
  { name: 'Cloudflare', category: 'cdn', header: ['cf-ray', /.+/], server: /cloudflare/i },
  { name: 'Vercel', category: 'cdn', header: ['x-vercel-id', /.+/], server: /vercel/i },
  { name: 'Netlify', category: 'cdn', header: ['x-nf-request-id', /.+/] },
  { name: 'Akamai', category: 'cdn', header: ['server', /akamai/i] },
  { name: 'Fastly', category: 'cdn', header: ['x-fastly-request-id', /.+/], server: /fastly/i },
  { name: 'Amazon CloudFront', category: 'cdn', header: ['x-amz-cf-id', /.+/] },
  { name: 'GitHub Pages', category: 'cdn', header: ['x-github-request-id', /.+/] },
  { name: 'Bunny CDN', category: 'cdn', header: ['server', /bunnycdn/i] },
  { name: 'DDoS-Guard', category: 'cdn', header: ['server', /ddos-guard/i] },
  { name: 'Sucuri', category: 'security', header: ['x-sucuri-id', /.+/] },
  { name: 'Qrator', category: 'cdn', header: ['server', /qrator/i] },

  // --- analytics ---------------------------------------------------
  { name: 'Google Analytics', category: 'analytics', html: /googletagmanager\.com\/gtag|google-analytics\.com\/analytics|gtag\(/i },
  { name: 'Yandex Metrica', category: 'analytics', html: /mc\.yandex\.ru\/metrika|ym\(\s*\d{5,}/i },
  { name: 'Top.Mail.Ru', category: 'analytics', html: /top-fwz1\.mail\.ru|_tmr\.push/i },
  { name: 'VK Pixel', category: 'analytics', html: /vk\.com\/rtrg|VK\.Retargeting/i },
  { name: 'Hotjar', category: 'analytics', html: /static\.hotjar\.com|hj\(/i },
  { name: 'Meta Pixel', category: 'analytics', html: /connect\.facebook\.net.*fbevents|fbq\(/i },
  { name: 'TikTok Pixel', category: 'analytics', html: /analytics\.tiktok\.com|ttq\.load/i },
  { name: 'Plausible', category: 'analytics', html: /plausible\.io\/js\//i },
  { name: 'Matomo', category: 'analytics', html: /matomo\.js|piwik\.js/i },
  { name: 'Sentry', category: 'analytics', html: /sentry-cdn\.com|@sentry\//i },
  { name: 'Segment', category: 'analytics', html: /cdn\.segment\.com|analytics\.js/i },
  { name: 'Mixpanel', category: 'analytics', html: /cdn\.mxpnl\.com|mixpanel\.init/i },
  { name: 'Microsoft Clarity', category: 'analytics', html: /clarity\.ms\/tag/i },
  { name: 'Umami', category: 'analytics', html: /umami\.js|data-website-id=/i },
  { name: 'HubSpot', category: 'analytics', html: /hs-scripts\.com|hubspot/i },

  // --- security / captcha -----------------------------------------
  { name: 'reCAPTCHA', category: 'security', html: /google\.com\/recaptcha|g-recaptcha|grecaptcha/i },
  { name: 'hCaptcha', category: 'security', html: /hcaptcha\.com|h-captcha/i },
  { name: 'Cloudflare Turnstile', category: 'security', html: /challenges\.cloudflare\.com\/turnstile|cf-turnstile/i },
  { name: 'Wordfence', category: 'security', html: /wordfence/i },
  { name: "Let's Encrypt", category: 'security', html: /letsencrypt|isrg/i },

  // --- front-end assets / services --------------------------------
  { name: 'Google Fonts', category: 'other', html: /fonts\.googleapis\.com\/css/i },
  { name: 'Font Awesome', category: 'other', html: /font-awesome|fontawesome/i },
  { name: 'jsDelivr', category: 'cdn', html: /cdn\.jsdelivr\.net/i },
  { name: 'unpkg', category: 'cdn', html: /unpkg\.com/i },
  { name: 'cdnjs', category: 'cdn', html: /cdnjs\.cloudflare\.com/i },
  { name: 'Stripe', category: 'other', html: /js\.stripe\.com|stripe\.js/i },
  { name: 'Algolia', category: 'other', html: /algolia(?:net)?\.(?:com|net)|algoliasearch/i },
  { name: 'Intercom', category: 'other', html: /widget\.intercom\.io|intercomSettings/i },
  { name: 'Crisp', category: 'other', html: /client\.crisp\.chat/i },
  { name: 'Tawk.to', category: 'other', html: /embed\.tawk\.to/i },
  { name: 'reCAPTCHA Enterprise', category: 'security', html: /recaptcha\/enterprise/i },
]

function matchRule(rule: Rule, ctx: Context): TechHit | null {
  const sources: { label: string; value: string }[] = []
  if (rule.html && rule.html.test(ctx.html)) sources.push({ label: 'markup', value: ctx.html })
  if (rule.cookie && ctx.cookies.some((name) => rule.cookie!.test(name))) {
    sources.push({ label: 'cookie', value: ctx.cookies.join(' ') })
  }
  if (rule.server && ctx.server && rule.server.test(ctx.server)) {
    sources.push({ label: 'server', value: ctx.server })
  }
  if (rule.poweredBy && ctx.poweredBy && rule.poweredBy.test(ctx.poweredBy)) {
    sources.push({ label: 'x-powered-by', value: ctx.poweredBy })
  }
  if (rule.generator && ctx.generator && rule.generator.test(ctx.generator)) {
    sources.push({ label: 'meta generator', value: ctx.generator })
  }
  if (rule.header) {
    const [name, pattern] = rule.header
    const value = ctx.headers[name.toLowerCase()]
    if (value && (!pattern || pattern.test(value))) {
      sources.push({ label: `header ${name}`, value })
    }
  }
  if (!sources.length) return null

  let version: string | undefined
  if (rule.version) {
    for (const source of sources) {
      const match = rule.version.exec(source.value)
      if (match?.[1]) {
        version = match[1]
        break
      }
    }
  }
  return {
    name: rule.name,
    category: rule.category,
    version,
    evidence: sources[0].label,
  }
}

function contextFor(http: HttpInfo): Context {
  const headers: Record<string, string> = {}
  for (const [key, value] of Object.entries(http.headers || {})) {
    headers[key.toLowerCase()] = String(value)
  }
  if (http.server && !headers.server) headers.server = String(http.server)
  if (http.poweredBy && !headers['x-powered-by']) headers['x-powered-by'] = String(http.poweredBy)
  return {
    html: String(http.bodySample || ''),
    headers,
    cookies: (http.cookies || []).map((name) => String(name)),
    server: String(http.server || headers.server || ''),
    poweredBy: String(http.poweredBy || headers['x-powered-by'] || ''),
    generator: String(http.generator || ''),
    imported: (http.tech || []).map((name) => String(name)),
  }
}

function importedCategory(name: string): TechCategory {
  const known = RULES.find((rule) => rule.name.toLowerCase() === name.toLowerCase())
  return known?.category || 'other'
}

export function techForHttp(http: HttpInfo): TechHit[] {
  const ctx = contextFor(http)
  const hits: TechHit[] = []
  for (const rule of RULES) {
    const hit = matchRule(rule, ctx)
    if (hit) hits.push(hit)
  }
  for (const name of ctx.imported) {
    if (!name || hits.some((hit) => hit.name.toLowerCase() === name.toLowerCase())) continue
    hits.push({ name, category: importedCategory(name), evidence: 'httpx' })
  }
  return hits
}

export function techForIp(ip: IpEntry): TechHit[] {
  const entries = ip.httpAll?.length ? ip.httpAll : ip.http ? [ip.http] : []
  const found = new Map<string, TechHit>()
  for (const http of entries) {
    for (const hit of techForHttp(http)) {
      const key = hit.name.toLowerCase()
      const current = found.get(key)
      if (!current || (!current.version && hit.version)) found.set(key, hit)
    }
  }
  return [...found.values()].sort(
    (a, b) =>
      CATEGORY_ORDER.indexOf(a.category) - CATEGORY_ORDER.indexOf(b.category) ||
      a.name.localeCompare(b.name),
  )
}

export function collectTech(state: { ips: IpEntry[] }): TechHit[] {
  const found = new Map<string, TechHit>()
  for (const ip of state.ips) {
    for (const hit of techForIp(ip)) {
      const key = hit.name.toLowerCase()
      const current = found.get(key)
      if (!current || (!current.version && hit.version)) found.set(key, hit)
    }
  }
  return [...found.values()].sort(
    (a, b) =>
      CATEGORY_ORDER.indexOf(a.category) - CATEGORY_ORDER.indexOf(b.category) ||
      a.name.localeCompare(b.name),
  )
}
