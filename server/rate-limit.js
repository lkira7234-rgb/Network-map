/* In-memory sliding-window rate limiter for a single Node process. */

export function createRateLimiter({ limit, windowMs }) {
  const hits = new Map()

  const prune = () => {
    const cutoff = Date.now() - windowMs
    for (const [key, times] of hits) {
      const kept = times.filter((time) => time > cutoff)
      if (kept.length) hits.set(key, kept)
      else hits.delete(key)
    }
  }

  // Keep memory flat on a long-running public instance.
  const timer = setInterval(prune, Math.max(10_000, windowMs))
  timer.unref?.()

  return {
    /* Returns { ok: true } or { ok: false, retryAfter } without mutating state on reject. */
    take(key) {
      const id = key || 'unknown'
      const now = Date.now()
      const times = (hits.get(id) || []).filter((time) => now - time < windowMs)

      if (times.length >= limit) {
        const retryAfter = Math.max(1, Math.ceil((windowMs - (now - times[0])) / 1000))
        return { ok: false, retryAfter }
      }

      times.push(now)
      hits.set(id, times)
      return { ok: true }
    },

    stop() {
      clearInterval(timer)
    },
  }
}