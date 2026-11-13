const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/**
 * Scripted scan used by the "DEMO" button. Mirrors the live event protocol
 * so the 3D scene and HUD can be previewed without touching the network.
 */
export async function runDemo(emit, signal) {
  const started = performance.now()
  const host = 'core.neotokyo.net'
  const primary = '203.0.113.42'
  const secondary = '203.0.113.43'

  const send = async (event, delay = 55) => {
    if (signal.aborted) throw new Error('aborted')
    emit(event)
    await wait(delay)
  }

  await send({
    type: 'meta',
    host,
    isIp: false,
    ports: [22, 80, 443, 8080, 8443, 3306, 5432, 6379, 9200, 27017],
    portTimeout: 1400,
    traceroute: true,
    geo: true,
    startedAt: Date.now(),
    demo: true,
  }, 80)

  await send({ type: 'log', level: 'info', message: 'DEMO MODE / синтетическая топология' }, 30)

  await send({
    type: 'dns',
    records: {
      a: [
        { address: primary, ttl: 60 },
        { address: secondary, ttl: 60 },
      ],
      aaaa: [{ address: '2001:db8:4c2:17::42', ttl: 60 }],
      cname: ['edge.neotokyo.net'],
      ns: ['ns1.neotokyo.net', 'ns2.neotokyo.net', 'ns3.neotokyo.net', 'ns4.neotokyo.net'],
      mx: [
        { exchange: 'mx1.neotokyo.net', priority: 10 },
        { exchange: 'mx2.neotokyo.net', priority: 20 },
        { exchange: 'mailbackup.neotokyo.net', priority: 50 },
      ],
      txt: [
        'v=spf1 include:_spf.neotokyo.net -all',
        'google-site-verification=NG7x9-demo-token',
        'neo-grid-node=42',
      ],
      soa: {
        nsname: 'ns1.neotokyo.net',
        hostmaster: 'hostmaster.neotokyo.net',
        serial: 2026111301,
        refresh: 7200,
        retry: 3600,
        expire: 1209600,
        minttl: 300,
      },
    },
  }, 90)

  await send({ type: 'log', level: 'ok', message: 'DNS: 2 A · 1 AAAA · 4 NS · 3 MX' }, 40)

  await send({ type: 'ip', ip: primary, family: 4, primary: true, ttl: 60 }, 60)
  await send({ type: 'ptr', ip: primary, ptr: 'edge-42.neotokyo.net' }, 40)
  await send({ type: 'ip', ip: secondary, family: 4, primary: false, ttl: 60 }, 40)
  await send({ type: 'ip', ip: '2001:db8:4c2:17::42', family: 6, primary: false, ttl: 60 }, 40)

  const geos = {
    [primary]: { country: 'Japan', countryCode: 'JP', city: 'Tokyo', region: 'Tokyo', isp: 'NeoTokyo Grid Systems', org: 'NeoTokyo Grid Systems', asn: 'AS64542', lat: 35.6762, lon: 139.6503, timezone: 'Asia/Tokyo' },
    [secondary]: { country: 'Japan', countryCode: 'JP', city: 'Osaka', region: 'Osaka', isp: 'NeoTokyo Grid Systems', org: 'NeoTokyo Grid Systems', asn: 'AS64542', lat: 34.6937, lon: 135.5023, timezone: 'Asia/Tokyo' },
    '2001:db8:4c2:17::42': { country: 'Japan', countryCode: 'JP', city: 'Tokyo', region: 'Tokyo', isp: 'NeoTokyo Grid Systems', org: 'NeoTokyo Grid Systems', asn: 'AS64542', lat: 35.6762, lon: 139.6503, timezone: 'Asia/Tokyo' },
  }

  for (const [ip, geo] of Object.entries(geos)) {
    await send({ type: 'geo', ip, geo }, 40)
  }

  await send({
    type: 'rdap',
    rdap: {
      name: 'NEOTOKYO.NET',
      handle: 'D-424242',
      type: 'domain',
      country: 'JP',
      registrar: 'Digital Horizon Registrar',
      org: 'NeoTokyo Grid Systems K.K.',
      status: ['client transfer prohibited'],
      registered: '2019-04-12T09:14:00Z',
      changed: '2026-02-03T17:22:11Z',
      expires: '2029-04-12T09:14:00Z',
      nameservers: ['NS1.NEOTOKYO.NET', 'NS2.NEOTOKYO.NET'],
    },
  }, 80)

  const ports = [
    { port: 22, state: 'open', rtt: 18, service: 'ssh', banner: 'SSH-2.0-OpenSSH_9.7' },
    { port: 80, state: 'open', rtt: 21, service: 'http' },
    { port: 443, state: 'open', rtt: 17, service: 'https' },
    { port: 3306, state: 'closed', rtt: 12, service: 'mysql' },
    { port: 5432, state: 'closed', rtt: 14, service: 'postgres' },
    { port: 6379, state: 'closed', rtt: 11, service: 'redis' },
    { port: 8080, state: 'open', rtt: 26, service: 'http-proxy' },
    { port: 8443, state: 'open', rtt: 24, service: 'https-alt' },
    { port: 9200, state: 'filtered', rtt: 1400, service: 'elasticsearch', error: 'TIMEOUT' },
    { port: 27017, state: 'filtered', rtt: 1400, service: 'mongodb', error: 'TIMEOUT' },
  ]

  for (const p of ports) {
    await send({ type: 'port', ip: primary, ...p }, 65)
    if (p.state === 'open') {
      await send({
        type: 'log',
        level: 'open',
        message: `${primary}:${p.port} OPEN · ${p.service} (${p.rtt} ms)`,
      }, 25)
    }
  }

  for (const p of ports.filter((p) => p.state !== 'open').slice(0, 4)) {
    await send({ type: 'port', ip: secondary, ...p, rtt: p.rtt + 6 }, 35)
  }

  await send({
    type: 'tls',
    ip: primary,
    port: 443,
    subject: '*.neotokyo.net',
    issuer: 'NEO Trust Services EV',
    validFrom: 'Sep  1 00:00:00 2026 GMT',
    validTo: 'Sep  1 23:59:59 2027 GMT',
    altNames: ['neotokyo.net', '*.neotokyo.net', 'edge.neotokyo.net'],
    serial: '04:2A:9C:11:7F:DE:00:42',
    fingerprint: 'SHA256 7C:18:9F:42:DE:AD:BE:EF:00:11:22:33:44:55:66:77',
    protocol: 'TLSv1.3',
    cipher: 'TLS_AES_256_GCM_SHA384',
    alpn: 'h2',
  }, 60)

  await send({
    type: 'http',
    ip: primary,
    port: 443,
    status: 200,
    server: 'neo-edge/4.2',
    poweredBy: null,
    contentType: 'text/html; charset=utf-8',
    title: 'NeoTokyo Grid // Access Portal',
    headers: {
      server: 'neo-edge/4.2',
      'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
      'cf-ray': '8d42f00d1c0f-NRT',
      'content-type': 'text/html; charset=utf-8',
    },
  }, 70)

  await send({
    type: 'http',
    ip: primary,
    port: 8080,
    status: 302,
    server: 'envoy',
    poweredBy: null,
    contentType: 'text/plain',
    title: null,
    headers: { server: 'envoy', location: 'https://core.neotokyo.net/' },
  }, 50)

  const hops = [
    { index: 1, ip: '192.168.88.1', rtt: 1, timeout: false },
    { index: 2, ip: '10.64.0.1', rtt: 6, timeout: false },
    { index: 3, ip: '198.51.100.9', rtt: 14, timeout: false },
    { index: 4, ip: '203.0.113.1', rtt: 28, timeout: false },
    { index: 5, ip: null, rtt: null, timeout: true },
    { index: 6, ip: '203.0.113.20', rtt: 121, timeout: false },
    { index: 7, ip: '203.0.113.31', rtt: 178, timeout: false },
    { index: 8, ip: primary, rtt: 201, timeout: false },
  ]

  const hopGeos = {
    '192.168.88.1': { country: 'Local', city: 'LAN', isp: 'Private network' },
    '10.64.0.1': { country: 'Local', city: 'Gateway', isp: 'ISP access' },
    '198.51.100.9': { country: 'Germany', city: 'Frankfurt', isp: 'EuroBackbone AG', asn: 'AS3320' },
    '203.0.113.1': { country: 'Netherlands', city: 'Amsterdam', isp: 'AMS-IX Route Server', asn: 'AS1200' },
    '203.0.113.20': { country: 'Singapore', city: 'Singapore', isp: 'Pacific Transit', asn: 'AS64500' },
    '203.0.113.31': { country: 'Japan', city: 'Tokyo', isp: 'NeoTokyo Grid Systems', asn: 'AS64542' },
    [primary]: geos[primary],
  }

  for (const hop of hops) {
    await send({ type: 'hop', ...hop }, 120)
    const geo = hop.ip ? hopGeos[hop.ip] : null
    if (geo) await send({ type: 'geo', ip: hop.ip, geo }, 30)
  }

  await send({
    type: 'done',
    stats: {
      open: 5,
      closed: 6,
      filtered: 2,
      scanned: ports.length + 4,
      ips: 3,
      hops: hops.length,
      durationMs: Math.round(performance.now() - started),
    },
  }, 0)
}