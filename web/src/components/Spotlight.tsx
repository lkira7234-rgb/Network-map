import { useEffect, useMemo, useRef, useState } from 'react'
import { ScanState } from '../types'
import { SearchResult, searchModel } from '../search'

interface SpotlightProps {
  open: boolean
  model: ScanState
  onClose: () => void
  onPick: (result: SearchResult) => void
}

export function Spotlight({ open, model, onClose, onPick }: SpotlightProps) {
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)
  const [query, setQuery] = useState('')
  const [cursor, setCursor] = useState(0)
  const outcome = useMemo(() => searchModel(model, query), [model, query])

  useEffect(() => {
    if (!open) return
    setCursor(0)
    const id = window.setTimeout(() => inputRef.current?.focus(), 30)
    return () => window.clearTimeout(id)
  }, [open])

  useEffect(() => {
    setCursor(0)
  }, [query])

  useEffect(() => {
    if (!open) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation()
        onClose()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  useEffect(() => {
    if (!open) return
    const el = listRef.current?.querySelector('.spotlight-item.active')
    el?.scrollIntoView({ block: 'nearest' })
  }, [cursor, open])

  if (!open) return null

  const pick = (result: SearchResult | undefined) => {
    if (!result) return
    onPick(result)
    onClose()
  }

  const onKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      setCursor((value) => Math.min(outcome.results.length - 1, value + 1))
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      setCursor((value) => Math.max(0, value - 1))
    } else if (event.key === 'Enter') {
      event.preventDefault()
      pick(outcome.results[cursor])
    } else if (event.key === 'Escape') {
      event.preventDefault()
      onClose()
    }
  }

  return (
    <div className="spotlight" role="dialog" aria-modal="true" aria-label="Поиск по карте">
      <button type="button" className="spotlight-scrim" aria-label="Закрыть поиск" onClick={onClose} />
      <div className="spotlight-box">
        <div className="spotlight-input-row">
          <span className="spotlight-prompt">⌕</span>
          <input
            ref={inputRef}
            className="spotlight-input"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={onKeyDown}
            placeholder="IP, :443, ssh, CVE-2021, nginx, finding…"
            spellCheck={false}
            autoComplete="off"
            aria-label="Строка поиска"
          />
          <kbd className="spotlight-kbd">ESC</kbd>
        </div>

        <div className="spotlight-meta">
          {query.trim()
            ? `${outcome.results.length} совпадений · ${outcome.ips.length} узлов подсвечено`
            : 'Ищи по IP, порту, сервису, CVE, технологии или тексту находки'}
        </div>

        <div className="spotlight-list" role="listbox" ref={listRef}>
          {outcome.results.map((result, index) => (
            <button
              type="button"
              key={result.id}
              role="option"
              aria-selected={index === cursor}
              className={`spotlight-item ${index === cursor ? 'active' : ''}`}
              onMouseEnter={() => setCursor(index)}
              onClick={() => pick(result)}
            >
              <i style={{ background: result.color }} />
              <span className="spotlight-label">{result.label}</span>
              <span className="spotlight-hint">{result.hint}</span>
            </button>
          ))}
          {query.trim() && !outcome.results.length && (
            <div className="spotlight-empty">Ничего не найдено. Попробуй порт, IP или часть имени.</div>
          )}
        </div>

        <div className="spotlight-foot">
          <span><kbd>↑</kbd><kbd>↓</kbd> навигация</span>
          <span><kbd>ENTER</kbd> открыть</span>
          <span><kbd>CTRL</kbd>+<kbd>K</kbd> поиск</span>
        </div>
      </div>
    </div>
  )
}
