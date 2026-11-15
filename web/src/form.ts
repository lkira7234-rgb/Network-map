export interface ScanFormValues {
  target: string
  ports: string
  traceroute: boolean
  geo: boolean
  udp: boolean
}

export const DEFAULT_FORM: ScanFormValues = {
  target: 'github.com',
  ports: '22,80,443,8080,8443',
  traceroute: true,
  geo: true,
  udp: false,
}

export interface PortPreset {
  id: string
  label: string
  value: string
  hint: string
}

export const PORT_PRESETS: PortPreset[] = [
  { id: 'top', label: 'ТОП-27', value: '', hint: 'Стандартный набор из 27 портов' },
  { id: 'web', label: 'ВЕБ', value: '80,443,8080,8443', hint: 'HTTP и HTTPS' },
  {
    id: 'infra',
    label: 'ИНФРА',
    value: '21,22,23,25,53,110,143,389,445,587,993,995,3306,3389,5432,6379',
    hint: 'Почта, файлы, БД и удалённый доступ',
  },
  { id: 'all', label: '1–1024', value: '1-1024', hint: 'Первая тысяча портов' },
]

/** Read a shared scan link such as /?target=example.com&ports=80,443 */
export function formFromUrl(search: string): ScanFormValues | null {
  const params = new URLSearchParams(search)
  const target = (params.get('target') || '').trim()
  if (!target) return null

  return {
    target,
    ports: params.get('ports') ?? DEFAULT_FORM.ports,
    traceroute: params.get('trace') !== '0',
    geo: params.get('geo') !== '0',
    udp: params.get('udp') === '1',
  }
}

/** Build a shareable absolute link for the given form values. */
export function formToUrl(values: ScanFormValues, base?: string): string {
  const url = new URL(base || window.location.href)
  url.search = ''
  const params = url.searchParams
  params.set('target', values.target.trim())
  if (values.ports.trim()) params.set('ports', values.ports.trim())
  if (!values.traceroute) params.set('trace', '0')
  if (!values.geo) params.set('geo', '0')
  if (values.udp) params.set('udp', '1')
  return url.toString()
}