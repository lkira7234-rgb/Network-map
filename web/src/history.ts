import { collectCves } from './cve'
import { collectFindings } from './checks'
import { ScanState } from './types'

/* ------------------------------------------------------------------ */
/*  local scan history + diff (IndexedDB, browser only)                */
/* ------------------------------------------------------------------ */

const DB_NAME = 'network-map-history'
const STORE = 'scans'
const KEEP = 20

export interface SnapshotPort {
  ip: string
  port: number
  protocol: 'tcp' | 'udp'
  service: string
}

export interface SnapshotCve {
  id: string
  ip: string
  port: number
}

export interface SnapshotFinding {
  id: string
  title: string
  severity: string
  ip: string
  port?: number
}

export interface Snapshot {
  id: string
  at: number
  host: string
  target: string
  demo: boolean
  open: SnapshotPort[]
  cves: SnapshotCve[]
  findings: SnapshotFinding[]
  counts: { ips: number; open: number }
}

export interface SnapshotDiff {
  previous: Snapshot
  newPorts: SnapshotPort[]
  closedPorts: SnapshotPort[]
  newCves: SnapshotCve[]
  goneCves: SnapshotCve[]
  newFindings: SnapshotFinding[]
  goneFindings: SnapshotFinding[]
  unchanged: number
}

export interface HistoryResult {
  snapshot: Snapshot
  previous: Snapshot | null
  diff: SnapshotDiff | null
  total: number
}

const memory: Snapshot[] = []

const keyOfPort = (port: SnapshotPort) => `${port.ip}|${port.protocol}|${port.port}`
const keyOfCve = (cve: SnapshotCve) => `${cve.id}|${cve.ip}|${cve.port}`
const keyOfFinding = (finding: SnapshotFinding) => `${finding.id}|${finding.ip}|${finding.port ?? ''}`

function openDb(): Promise<IDBDatabase | null> {
  if (typeof indexedDB === 'undefined') return Promise.resolve(null)
  return new Promise((resolve) => {
    let request: IDBOpenDBRequest
    try {
      request = indexedDB.open(DB_NAME, 1)
    } catch {
      resolve(null)
      return
    }
    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains(STORE)) {
        const store = db.createObjectStore(STORE, { keyPath: 'id' })
        store.createIndex('host', 'host')
        store.createIndex('at', 'at')
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => resolve(null)
    request.onblocked = () => resolve(null)
  })
}

function txDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve) => {
    tx.oncomplete = () => resolve()
    tx.onerror = () => resolve()
    tx.onabort = () => resolve()
  })
}

function requestResult<T>(request: IDBRequest<T>): Promise<T | null> {
  return new Promise((resolve) => {
    request.onsuccess = () => resolve(request.result ?? null)
    request.onerror = () => resolve(null)
  })
}

export function snapshotFromModel(model: ScanState): Snapshot | null {
  if (!model.host && !model.target) return null
  const open: SnapshotPort[] = []
  for (const ip of model.ips) {
    for (const port of Object.values(ip.ports)) {
      if (port.state !== 'open') continue
      open.push({
        ip: ip.ip,
        port: port.port,
        protocol: port.protocol,
        service: port.service || 'unknown',
      })
    }
  }
  const hash = `${model.host}|${model.startedAt ?? 0}|${model.ips.length}|${open.length}`
  let acc = 0
  for (let i = 0; i < hash.length; i++) acc = (acc * 31 + hash.charCodeAt(i)) | 0
  return {
    id: `${model.startedAt ?? Date.now()}-${Math.abs(acc).toString(36)}`,
    at: model.stats?.durationMs != null && model.startedAt ? model.startedAt + model.stats.durationMs : Date.now(),
    host: (model.host || model.target).toLowerCase(),
    target: model.target,
    demo: model.demo,
    open,
    cves: collectCves(model).map((match) => ({ id: match.id, ip: match.ip, port: match.port })),
    findings: collectFindings(model).map((finding) => ({
      id: finding.id,
      title: finding.title,
      severity: finding.severity,
      ip: finding.ip,
      ...(finding.port != null ? { port: finding.port } : {}),
    })),
    counts: { ips: model.ips.length, open: open.length },
  }
}

export function diffSnapshots(previous: Snapshot, current: Snapshot): SnapshotDiff {
  const previousPorts = new Set(previous.open.map(keyOfPort))
  const currentPorts = new Set(current.open.map(keyOfPort))
  const previousCves = new Set(previous.cves.map(keyOfCve))
  const currentCves = new Set(current.cves.map(keyOfCve))
  const previousFindings = new Set(previous.findings.map(keyOfFinding))
  const currentFindings = new Set(current.findings.map(keyOfFinding))

  return {
    previous,
    newPorts: current.open.filter((port) => !previousPorts.has(keyOfPort(port))),
    closedPorts: previous.open.filter((port) => !currentPorts.has(keyOfPort(port))),
    newCves: current.cves.filter((cve) => !previousCves.has(keyOfCve(cve))),
    goneCves: previous.cves.filter((cve) => !currentCves.has(keyOfCve(cve))),
    newFindings: current.findings.filter((finding) => !previousFindings.has(keyOfFinding(finding))),
    goneFindings: previous.findings.filter((finding) => !currentFindings.has(keyOfFinding(finding))),
    unchanged: current.open.filter((port) => previousPorts.has(keyOfPort(port))).length,
  }
}

export function hasDiff(diff: SnapshotDiff | null): boolean {
  if (!diff) return false
  return Boolean(
    diff.newPorts.length ||
      diff.closedPorts.length ||
      diff.newCves.length ||
      diff.goneCves.length ||
      diff.newFindings.length ||
      diff.goneFindings.length,
  )
}

async function readHost(host: string): Promise<Snapshot[]> {
  const db = await openDb()
  if (!db) return memory.filter((snapshot) => snapshot.host === host).sort((a, b) => b.at - a.at)
  try {
    const tx = db.transaction(STORE, 'readonly')
    const index = tx.objectStore(STORE).index('host')
    const rows = await requestResult(index.getAll(host) as IDBRequest<Snapshot[]>)
    await txDone(tx)
    return (rows || []).sort((a, b) => b.at - a.at)
  } catch {
    return []
  } finally {
    db.close()
  }
}

/**
 * Saves the current scan and returns the diff against the previous run of the
 * same host. Failures are silent: history is a convenience, not a dependency.
 */
export async function recordScan(model: ScanState): Promise<HistoryResult | null> {
  const snapshot = snapshotFromModel(model)
  if (!snapshot) return null

  const existing = await readHost(snapshot.host)
  const previous = existing.find((item) => item.id !== snapshot.id) || null
  const diff = previous ? diffSnapshots(previous, snapshot) : null
  memory.unshift(snapshot)
  if (memory.length > KEEP) memory.length = KEEP

  const db = await openDb()
  if (db) {
    try {
      const tx = db.transaction(STORE, 'readwrite')
      const store = tx.objectStore(STORE)
      store.put(snapshot)
      await txDone(tx)

      // Keep the newest KEEP scans across all hosts, not per host.
      const allTx = db.transaction(STORE, 'readonly')
      const allRows = await requestResult(allTx.objectStore(STORE).getAll() as IDBRequest<Snapshot[]>)
      await txDone(allTx)
      const keep = (allRows || [])
        .filter((item) => item.id !== snapshot.id)
        .sort((a, b) => b.at - a.at)
        .slice(0, KEEP - 1)
      const keepIds = new Set([snapshot.id, ...keep.map((item) => item.id)])
      const drop = (allRows || []).filter((item) => !keepIds.has(item.id))
      if (drop.length) {
        const cleanup = db.transaction(STORE, 'readwrite')
        const cleanupStore = cleanup.objectStore(STORE)
        for (const item of drop) cleanupStore.delete(item.id)
        await txDone(cleanup)
      }
    } catch {
      // IndexedDB can be blocked in private mode; the in-memory copy still works.
    } finally {
      db.close()
    }
  }

  return {
    snapshot,
    previous,
    diff,
    total: existing.filter((item) => item.id !== snapshot.id).length + 1,
  }
}

export async function clearHistory(): Promise<void> {
  memory.length = 0
  const db = await openDb()
  if (!db) return
  try {
    const tx = db.transaction(STORE, 'readwrite')
    tx.objectStore(STORE).clear()
    await txDone(tx)
  } finally {
    db.close()
  }
}

export function formatSnapshotTime(at: number): string {
  const date = new Date(at)
  const pad = (value: number) => String(value).padStart(2, '0')
  return `${pad(date.getDate())}.${pad(date.getMonth() + 1)} ${pad(date.getHours())}:${pad(date.getMinutes())}`
}
