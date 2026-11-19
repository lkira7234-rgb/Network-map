import { LinkRef, ReputationInfo } from './types'

/**
 * External lookups. Every URL is built locally from scan data; nothing is
 * fetched by the app itself, and links always open in a new tab.
 */

const ipLinks = (ip: string): LinkRef[] => [
  {
    id: 'shodan',
    label: 'SHODAN',
    url: `https://www.shodan.io/host/${encodeURIComponent(ip)}`,
    hint: 'Открытые сервисы и баннеры по данным Shodan',
  },
  {
    id: 'censys',
    label: 'CENSYS',
    url: `https://search.censys.io/hosts/${encodeURIComponent(ip)}`,
    hint: 'Сертификаты и открытые сервисы в Censys',
  },
  {
    id: 'virustotal',
    label: 'VIRUSTOTAL',
    url: `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`,
    hint: 'Репутация адреса и связанные домены',
  },
  {
    id: 'greynoise',
    label: 'GREYNOISE',
    url: `https://viz.greynoise.io/ip/${encodeURIComponent(ip)}`,
    hint: 'Сканерный шум и классификация IP',
  },
]

export function osintLinks(ip: string | null | undefined): LinkRef[] {
  const value = String(ip || '').trim()
  if (!value) return []
  return ipLinks(value)
}

/**
 * Leak / paste registries. Most do not accept a prefilled query via URL, so
 * the links point at their search page and the UI also offers a copied query.
 */
export function leakLinks(domain: string | null | undefined): LinkRef[] {
  const value = String(domain || '').trim().toLowerCase()
  if (!value) return []
  const query = encodeURIComponent(value)
  return [
    {
      id: 'hibp',
      label: 'HIBP',
      url: `https://haveibeenpwned.com/DomainSearch?q=${query}`,
      hint: 'Have I Been Pwned · поиск по домену',
    },
    {
      id: 'dehashed',
      label: 'DEHASHED',
      url: `https://dehashed.com/search?query=${encodeURIComponent(`domain:${value}`)}`,
      hint: 'DeHashed · domain:<домен>',
    },
    {
      id: 'intelx',
      label: 'INTELLIGENCE X',
      url: `https://intelx.io/?s=${query}`,
      hint: 'Intelligence X · дампы, пасты, документы',
    },
    {
      id: 'leakcheck',
      label: 'LEAKCHECK',
      url: `https://leakcheck.io/?query=${query}`,
      hint: 'LeakCheck · поиск по утечкам',
    },
    {
      id: 'breachdirectory',
      label: 'BREACHDIRECTORY',
      url: `https://breachdirectory.org/?query=${query}`,
      hint: 'BreachDirectory · открытый поиск',
    },
    {
      id: 'leakix',
      label: 'LEAKIX',
      url: `https://leakix.net/search?scope=leak&q=${query}`,
      hint: 'LeakIX · утечки и открытые сервисы',
    },
    {
      id: 'psbdmp',
      label: 'PSBDMP',
      url: `https://psbdmp.ws/search/${query}`,
      hint: 'Pastebin dumps · поиск по пастам',
    },
    {
      id: 'github',
      label: 'GITHUB',
      url: `https://github.com/search?q=${encodeURIComponent(`"${value}" password`)}&type=code`,
      hint: 'Публичный поиск по коду GitHub (нужен вход)',
    },
  ]
}

export type ReputationLevel = 'clean' | 'low' | 'medium' | 'toxic'

export function reputationLevel(score: number): ReputationLevel {
  if (!Number.isFinite(score) || score <= 0) return 'clean'
  if (score <= 20) return 'low'
  if (score <= 50) return 'medium'
  return 'toxic'
}

export function reputationColor(score: number): string {
  const level = reputationLevel(score)
  if (level === 'toxic') return '#ff3b5c'
  if (level === 'medium') return '#ffb020'
  if (level === 'low') return '#b6ff3b'
  return '#49ff9e'
}

export function reputationLabel(info: ReputationInfo | null | undefined): string {
  if (!info) return '—'
  const level = reputationLevel(info.score)
  const words: Record<ReputationLevel, string> = {
    clean: 'чисто',
    low: 'низкий риск',
    medium: 'подозрительно',
    toxic: 'токсичный',
  }
  return `${info.score}% · ${words[level]}`
}
