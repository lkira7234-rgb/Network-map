import fs from 'node:fs'
import path from 'node:path'

/**
 * Persistent state for the monitor, scan history, reputation and previews.
 *
 * Uses the built-in `node:sqlite` (Node 22.5+, available without a flag on the
 * Node versions used by Render) and transparently falls back to one JSON file
 * on older runtimes or read-only disks. Set `DATA_DIR` to a mounted persistent
 * disk on Render to survive redeploys.
 */

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS monitor_state (
    target TEXT PRIMARY KEY,
    snapshot TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS scans_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    at INTEGER NOT NULL,
    data TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS scans_history_at ON scans_history (at DESC);
  CREATE TABLE IF NOT EXISTS ip_reputation_cache (
    ip TEXT PRIMARY KEY,
    score INTEGER NOT NULL DEFAULT 0,
    data TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS preview_cache (
    key TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );
`

const MAX_SCANS = 600
const MAX_KV = 200

let DatabaseSync = null
try {
  ;({ DatabaseSync } = await import('node:sqlite'))
} catch {
  DatabaseSync = null
}

function parse(value, fallback) {
  try {
    return JSON.parse(value)
  } catch {
    return fallback
  }
}

function createSqliteStore(file, logger) {
  const db = new DatabaseSync(file)
  db.exec('PRAGMA journal_mode = WAL;')
  db.exec('PRAGMA synchronous = NORMAL;')
  db.exec(SCHEMA)

  const monitorAll = db.prepare('SELECT target, snapshot FROM monitor_state ORDER BY updated_at DESC')
  const monitorPut = db.prepare(
    'INSERT INTO monitor_state (target, snapshot, updated_at) VALUES (?, ?, ?) ' +
      'ON CONFLICT(target) DO UPDATE SET snapshot = excluded.snapshot, updated_at = excluded.updated_at',
  )
  const scanInsert = db.prepare('INSERT INTO scans_history (target, at, data) VALUES (?, ?, ?)')
  const scanList = db.prepare('SELECT data FROM scans_history ORDER BY at DESC LIMIT ?')
  const scanTrim = db.prepare(
    'DELETE FROM scans_history WHERE id NOT IN (SELECT id FROM scans_history ORDER BY at DESC LIMIT ?)',
  )
  const scanRecent = db.prepare('SELECT data FROM scans_history WHERE at >= ? ORDER BY at DESC LIMIT 200')
  const repGet = db.prepare('SELECT data, updated_at FROM ip_reputation_cache WHERE ip = ?')
  const repPut = db.prepare(
    'INSERT INTO ip_reputation_cache (ip, score, data, updated_at) VALUES (?, ?, ?, ?) ' +
      'ON CONFLICT(ip) DO UPDATE SET score = excluded.score, data = excluded.data, updated_at = excluded.updated_at',
  )
  const previewGet = db.prepare('SELECT data, updated_at FROM preview_cache WHERE key = ?')
  const previewPut = db.prepare(
    'INSERT INTO preview_cache (key, data, updated_at) VALUES (?, ?, ?) ' +
      'ON CONFLICT(key) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at',
  )
  const kvGet = db.prepare('SELECT value, updated_at FROM kv WHERE key = ?')
  const kvPut = db.prepare(
    'INSERT INTO kv (key, value, updated_at) VALUES (?, ?, ?) ' +
      'ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at',
  )
  const kvTrim = db.prepare(
    'DELETE FROM kv WHERE key NOT IN (SELECT key FROM kv ORDER BY updated_at DESC LIMIT ?)',
  )

  logger?.log?.(`[store] sqlite · ${file}`)

  return {
    kind: 'sqlite',
    monitorSnapshots() {
      return monitorAll.all().map((row) => ({
        target: String(row.target),
        snapshot: parse(row.snapshot, null),
      }))
    },
    saveMonitorSnapshot(target, snapshot) {
      monitorPut.run(String(target), JSON.stringify(snapshot), Date.now())
    },
    addScan(record) {
      scanInsert.run(String(record.target || ''), Number(record.at) || Date.now(), JSON.stringify(record))
      scanTrim.run(MAX_SCANS)
    },
    scans(limit = 50) {
      return scanList.all(Math.min(500, Math.max(1, limit))).map((row) => parse(row.data, null)).filter(Boolean)
    },
    recentScans(sinceMs) {
      return scanRecent.all(Number(sinceMs) || 0).map((row) => parse(row.data, null)).filter(Boolean)
    },
    getReputation(ip) {
      const row = repGet.get(String(ip))
      if (!row) return null
      const data = parse(row.data, null)
      return data ? { data, at: Number(row.updated_at) || 0 } : null
    },
    setReputation(ip, data) {
      repPut.run(String(ip), Number(data?.score) || 0, JSON.stringify(data), Date.now())
    },
    getPreview(key) {
      const row = previewGet.get(String(key))
      if (!row) return null
      return { data: parse(row.data, null), at: Number(row.updated_at) || 0 }
    },
    setPreview(key, data) {
      previewPut.run(String(key), JSON.stringify(data), Date.now())
    },
    getKV(key) {
      const row = kvGet.get(String(key))
      return row ? { value: parse(row.value, null), at: Number(row.updated_at) || 0 } : null
    },
    setKV(key, value) {
      kvPut.run(String(key), JSON.stringify(value), Date.now())
      kvTrim.run(MAX_KV)
    },
    close() {
      try {
        db.close()
      } catch {}
    },
  }
}

function createJsonStore(file, logger) {
  const load = () => {
    try {
      return parse(fs.readFileSync(file, 'utf8'), null) || {}
    } catch {
      return {}
    }
  }

  let data = load()
  data.monitor ||= {}
  data.scans ||= []
  data.reputation ||= {}
  data.preview ||= {}
  data.kv ||= {}

  let saveTimer = null
  const flush = () => {
    saveTimer = null
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true })
      const tmp = `${file}.tmp`
      fs.writeFileSync(tmp, JSON.stringify(data), 'utf8')
      fs.renameSync(tmp, file)
    } catch {
      // Read-only or ephemeral disk: keep the in-memory copy.
    }
  }
  const save = () => {
    if (saveTimer) return
    saveTimer = setTimeout(flush, 250)
    saveTimer.unref?.()
  }

  logger?.log?.(`[store] json fallback · ${file}`)

  return {
    kind: 'json',
    monitorSnapshots() {
      return Object.entries(data.monitor).map(([target, snapshot]) => ({ target, snapshot }))
    },
    saveMonitorSnapshot(target, snapshot) {
      data.monitor[String(target)] = snapshot
      save()
    },
    addScan(record) {
      data.scans.unshift(record)
      if (data.scans.length > MAX_SCANS) data.scans.length = MAX_SCANS
      save()
    },
    scans(limit = 50) {
      return data.scans.slice(0, Math.min(500, Math.max(1, limit)))
    },
    recentScans(sinceMs) {
      return data.scans.filter((item) => Number(item?.at) >= Number(sinceMs || 0)).slice(0, 200)
    },
    getReputation(ip) {
      const entry = data.reputation[String(ip)]
      return entry ? { data: entry.data, at: Number(entry.at) || 0 } : null
    },
    setReputation(ip, value) {
      data.reputation[String(ip)] = { data: value, at: Date.now() }
      save()
    },
    getPreview(key) {
      const entry = data.preview[String(key)]
      return entry ? { data: entry.data, at: Number(entry.at) || 0 } : null
    },
    setPreview(key, value) {
      data.preview[String(key)] = { data: value, at: Date.now() }
      save()
    },
    getKV(key) {
      const entry = data.kv[String(key)]
      return entry ? { value: entry.value, at: Number(entry.at) || 0 } : null
    },
    setKV(key, value) {
      data.kv[String(key)] = { value, at: Date.now() }
      save()
    },
    close() {
      if (saveTimer) clearTimeout(saveTimer)
      flush()
    },
  }
}

export function createStore(env = process.env, logger = console) {
  const dir = path.resolve(env.DATA_DIR || path.join(process.cwd(), '.data'))
  try {
    fs.mkdirSync(dir, { recursive: true })
  } catch {}

  if (DatabaseSync) {
    try {
      return createSqliteStore(path.join(dir, 'network-map.sqlite'), logger)
    } catch (error) {
      logger?.warn?.(`[store] sqlite unavailable: ${error?.message || error}`)
    }
  }
  return createJsonStore(path.join(dir, 'network-map.json'), logger)
}
