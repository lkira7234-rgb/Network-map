import net from 'node:net'

/**
 * AbuseIPDB reputation lookup. Disabled unless ABUSEIPDB_API_KEY is present.
 * Results are cached in the SQLite/JSON store so one scan never hammers the
 * free API quota and repeated scans stay instant.
 */

const CACHE_MS = 24 * 3600_000
const TIMEOUT = 5000

export function createReputation(env = process.env, store = null, logger = console) {
  const apiKey = String(env.ABUSEIPDB_API_KEY || '').trim()
  const enabled = Boolean(apiKey)
  const maxAgeDays = Math.min(365, Math.max(1, Number(env.ABUSEIPDB_MAX_AGE_DAYS) || 90))

  async function fetchScore(ip) {
    const url =
      'https://api.abuseipdb.com/api/v2/check?' +
      new URLSearchParams({ ipAddress: ip, maxAgeInDays: String(maxAgeDays) }).toString()
    const response = await fetch(url, {
      headers: { Key: apiKey, Accept: 'application/json' },
      signal: AbortSignal.timeout(TIMEOUT),
    })
    if (!response.ok) {
      throw new Error(`AbuseIPDB ${response.status}`)
    }
    const payload = await response.json()
    const data = payload?.data || {}
    return {
      score: Math.min(100, Math.max(0, Number(data.abuseConfidenceScore) || 0)),
      totalReports: Number(data.totalReports) || 0,
      distinctUsers: Number(data.numDistinctUsers) || 0,
      lastReportedAt: data.lastReportedAt || null,
      country: data.countryCode || null,
      usageType: data.usageType || null,
      isp: data.isp || null,
      domain: data.domain || null,
      whitelisted: Boolean(data.isWhitelisted),
      source: 'abuseipdb',
    }
  }

  async function lookup(ip) {
    if (!enabled || net.isIP(ip) !== 4) return null

    const cached = store?.getReputation?.(ip)
    if (cached?.data && Date.now() - (cached.at || 0) < CACHE_MS) {
      return { ...cached.data, cached: true }
    }

    try {
      const data = await fetchScore(ip)
      store?.setReputation?.(ip, data)
      return { ...data, cached: false }
    } catch (error) {
      logger?.warn?.(`[reputation] ${ip}: ${error?.message || error}`)
      return cached?.data ? { ...cached.data, cached: true } : null
    }
  }

  return {
    enabled,
    lookup,
    publicStatus: () => ({ enabled, provider: enabled ? 'abuseipdb' : null }),
  }
}
