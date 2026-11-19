import { useEffect, useRef, useState } from 'react'
import { MonitorChange, MonitorStatus, fetchMonitor, testMonitorAlert } from '../api'

const timeOf = (value: number | null) => {
  if (!value) return '—'
  const date = new Date(value)
  return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`
}

/** Short human-readable DIFF: ports keep their labels, nodes and hops are counted. */
const diffSummary = (change: MonitorChange) => {
  const parts: string[] = []
  if (change.added.length) parts.push(`+${change.added.slice(0, 3).join(', ')}`)
  if (change.removed.length) parts.push(`−${change.removed.slice(0, 3).join(', ')}`)
  if (change.nodesAdded?.length) parts.push(`+${change.nodesAdded.length} узл.`)
  if (change.nodesRemoved?.length) parts.push(`−${change.nodesRemoved.length} узл.`)
  if (change.hopsAdded?.length) parts.push(`+${change.hopsAdded.length} хоп.`)
  if (change.hopsRemoved?.length) parts.push(`−${change.hopsRemoved.length} хоп.`)
  return parts.join(' · ')
}

/**
 * Server-side perimeter monitor status. Webhook URLs and bot tokens live in
 * the operator's environment and are never sent to the browser.
 */
export function MonitorPanel() {
  const [status, setStatus] = useState<MonitorStatus | null>(null)
  const [error, setError] = useState('')
  const [token, setToken] = useState(() => {
    try {
      return window.sessionStorage.getItem('network-map:monitor-token') || ''
    } catch {
      return ''
    }
  })
  const [test, setTest] = useState<{ status: 'idle' | 'busy' | 'ok' | 'error'; message: string }>({
    status: 'idle',
    message: '',
  })
  const alive = useRef(true)

  useEffect(() => {
    try {
      if (token) window.sessionStorage.setItem('network-map:monitor-token', token)
      else window.sessionStorage.removeItem('network-map:monitor-token')
    } catch {}
  }, [token])

  useEffect(() => {
    alive.current = true
    const controller = new AbortController()

    const load = async () => {
      try {
        const data = await fetchMonitor(controller.signal, token.trim() || undefined)
        if (alive.current) {
          setStatus(data)
          setError('')
        }
      } catch (err) {
        if ((err as Error)?.name === 'AbortError') return
        if (alive.current) setError((err as Error)?.message || 'Мониторинг недоступен')
      }
    }

    void load()
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') void load()
    }, 60_000)

    return () => {
      alive.current = false
      controller.abort()
      window.clearInterval(timer)
    }
  }, [token])

  const runTest = async () => {
    setTest({ status: 'busy', message: 'Отправляю…' })
    try {
      await testMonitorAlert(token.trim() || undefined)
      setTest({ status: 'ok', message: 'Уведомление отправлено' })
    } catch (err) {
      setTest({ status: 'error', message: (err as Error)?.message || 'Не удалось отправить' })
    }
  }

  const enabled = Boolean(status?.enabled)
  const scanAlerts = Boolean(status?.scanAlerts)
  const admin = Boolean(status?.admin)
  const hasChannel = Boolean(status?.alerts.webhook || status?.alerts.telegram)
  // Without a destination scan alerts only reach the server log, so the panel
  // stays in setup mode until a webhook or Telegram is configured.
  const active = enabled || (scanAlerts && hasChannel)
  const channels = [
    status?.alerts.webhook ? 'WEBHOOK' : '',
    status?.alerts.telegram ? (status.telegramChannel ? 'TG-КАНАЛ' : 'TELEGRAM') : '',
    scanAlerts && hasChannel ? 'ВСЕ СКАНЫ' : '',
  ]
    .filter(Boolean)
    .join(' · ')

  return (
    <section className="panel monitor">
      <div className="panel-head">
        <span>09 / PERIMETER MONITOR</span>
        <span className={`monitor-state ${active ? 'on' : 'off'}`}>
          <i /> {active ? 'ON' : 'OFF'}
        </span>
      </div>

      <div className="monitor-token-row">
        <label htmlFor="monitor-token">X-MONITOR-TOKEN</label>
        <input
          id="monitor-token"
          className="text-input monitor-token-input"
          type="password"
          value={token}
          onChange={(event) => setToken(event.target.value)}
          placeholder="токен оператора"
          spellCheck={false}
          autoComplete="off"
        />
        <span className={`monitor-token-state ${admin ? 'on' : ''}`}>
          {admin ? 'ADMIN' : token ? 'НЕВЕРНЫЙ' : 'ПУБЛИЧНО'}
        </span>
      </div>

      {!admin && (
        <p className="subdomain-note">
          Публичный статус: список целей и история изменений скрыты. Введи{' '}
          <code>X-Monitor-Token</code> из окружения сервера, чтобы увидеть детали и отправлять тест.
        </p>
      )}

      {error && <p className="import-note error">{error}</p>}

      {!status && !error && <p className="history-empty">Читаю состояние монитора…</p>}

      {status && status.issues && status.issues.length > 0 && (
        <ul className="monitor-issues">
          {status.issues.map((issue) => (
            <li key={issue}>{issue}</li>
          ))}
        </ul>
      )}

      {status && !active && (
        <>
          <p className="history-empty">
            {status.bot?.enabled
              ? 'Пока нет сайтов в мониторинге. Пришли домен или IP боту в личные сообщения — сайт появится здесь и будет проверяться раз в час.'
              : 'Серверный мониторинг выключен. Он работает без открытой вкладки и присылает DIFF в Telegram, Discord или любой вебхук.'}
          </p>
          <div className="monitor-env">
            <code>MONITOR_TARGETS=example.com</code>
            <code>MONITOR_PORTS=22,80,443,6379</code>
            <code>ALERT_WEBHOOK_URL=https://…</code>
            <code>ALERT_TELEGRAM_TOKEN=… · ALERT_TELEGRAM_CHAT=…</code>
          </div>
          {status.env && (
            <div className="monitor-env-check" title="Какие переменные видит запущенный процесс (только наличие)">
              <span className={status.env.targets > 0 ? 'on' : ''}>
                TARGETS {status.env.targets > 0 ? '✓' : '—'}
              </span>
              <span className={status.env.telegramToken ? 'on' : ''}>
                TOKEN {status.env.telegramToken ? '✓' : '—'}
              </span>
              <span className={status.env.telegramChat ? 'on' : ''}>
                CHAT {status.env.telegramChat ? '✓' : '—'}
              </span>
              <span className={status.env.webhook ? 'on' : ''}>
                WEBHOOK {status.env.webhook ? '✓' : '—'}
              </span>
            </div>
          )}
          <p className="subdomain-note">
            Переменные задаются в окружении сервера. Токены и URL вебхуков не вводятся в браузере и
            никогда не попадают в клиент.
          </p>
        </>
      )}

      {status && active && (
        <>
          <div className="monitor-meta">
            <span>{status.enabled ? `интервал ${status.intervalMin} мин` : 'только алерты по сканам'}</span>
            <span>{status.ports} портов</span>
            <span>{channels || 'только лог'}</span>
            {status.bot?.enabled && (
              <span>{status.bot.polling ? 'бот онлайн' : 'бот офлайн'}</span>
            )}
          </div>

          {status.alerts.telegram && !status.telegramChannel && (
            <p className="subdomain-note">
              Telegram сейчас пишет в личный чат. Добавь бота администратором канала — доставка
              переключится на канал автоматически.
            </p>
          )}

          {status.targets.length > 0 && (
            <div className="monitor-targets">
              {status.targets.map((item) => (
                <div className="monitor-row" key={item.target}>
                  <div className="monitor-row-head">
                    <b>{item.target}</b>
                    {item.source === 'bot' && (
                      <span className="monitor-src" title="Добавлен через Telegram-бота">
                        TG
                      </span>
                    )}
                    <span className="monitor-open">{item.open} откр.</span>
                    <em title={item.lastRun ? new Date(item.lastRun).toLocaleString() : 'ещё не проверялся'}>
                      {timeOf(item.lastRun)}
                    </em>
                  </div>
                  {item.error ? (
                    <span className="monitor-error">{item.error}</span>
                  ) : (
                    <div className="monitor-diff">
                      {item.added.length > 0 && (
                        <span className="monitor-added">+{item.added.length} новых</span>
                      )}
                      {item.removed.length > 0 && (
                        <span className="monitor-removed">−{item.removed.length} закрылись</span>
                      )}
                      {Boolean(item.nodeAdded) && (
                        <span className="monitor-added">+{item.nodeAdded} узл.</span>
                      )}
                      {Boolean(item.nodeRemoved) && (
                        <span className="monitor-removed">−{item.nodeRemoved} узл.</span>
                      )}
                      {Boolean(item.hopAdded) && (
                        <span className="monitor-added">+{item.hopAdded} хоп.</span>
                      )}
                      {Boolean(item.hopRemoved) && (
                        <span className="monitor-removed">−{item.hopRemoved} хоп.</span>
                      )}
                      {!item.added.length &&
                        !item.removed.length &&
                        !item.nodeAdded &&
                        !item.nodeRemoved &&
                        !item.hopAdded &&
                        !item.hopRemoved && <span className="monitor-same">без изменений</span>}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {status.history.length > 0 && (
            <div className="monitor-history">
              <span className="monitor-history-label">ПОСЛЕДНИЕ ИЗМЕНЕНИЯ</span>
              {status.history.slice(0, 4).map((change) => (
                <div
                  className="monitor-change"
                  key={`${change.at}-${change.target}`}
                  title={change.source === 'scan' ? 'Скан из интерфейса' : 'Серверный монитор'}
                >
                  <em>{timeOf(change.at)}</em>
                  <b>{change.target}</b>
                  <span>{diffSummary(change)}</span>
                </div>
              ))}
            </div>
          )}

          {status.scans && status.scans.length > 0 && (
            <div className="monitor-history">
              <span className="monitor-history-label">ПОСЛЕДНИЕ СКАНЫ · SQLITE</span>
              {status.scans.slice(0, 5).map((scan) => (
                <div className="monitor-change" key={`${scan.at}-${scan.target}`}>
                  <em>{timeOf(scan.at)}</em>
                  <b>{scan.target}</b>
                  <span>
                    {scan.source === 'monitor' ? 'монитор' : 'UI'} ·{' '}
                    {Array.isArray(scan.ports) ? `${scan.ports.length} порт.` : '—'}
                    {Array.isArray(scan.nodes) ? ` · ${scan.nodes.length} IP` : ''}
                  </span>
                </div>
              ))}
            </div>
          )}

          <button
            type="button"
            className="btn ghost small monitor-test"
            onClick={() => void runTest()}
            disabled={!admin || !hasChannel || test.status === 'busy'}
            title={
              !admin
                ? 'Нужен X-Monitor-Token с сервера'
                : hasChannel
                  ? 'Отправить тестовое уведомление в настроенные каналы'
                  : 'Сначала задай вебхук или Telegram в окружении'
            }
          >
            {test.status === 'busy' ? <span className="spinner" /> : '⌁'} ТЕСТ УВЕДОМЛЕНИЯ
          </button>

          {test.status !== 'idle' && test.status !== 'busy' && (
            <p className={`import-note ${test.status === 'ok' ? 'ok' : 'error'}`}>{test.message}</p>
          )}

          <p className="subdomain-note">
            {status.enabled
              ? 'Скан идёт на сервере по расписанию; уведомление уходит только при изменении узлов, открытых портов или хопов.'
              : 'Сканы из интерфейса сравниваются с прошлым снимком; уведомление уходит только при изменении узлов, портов или хопов.'}{' '}
            Состояние хранится на диске сервера.
          </p>
        </>
      )}
    </section>
  )
}
