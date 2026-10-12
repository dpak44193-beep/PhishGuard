export interface ScanResult {
  id: string
  url: string
  score: number
  risk_score: number
  level: 'no_threat_detected' | 'safe' | 'suspicious' | 'malicious' | 'unknown'
  verdict: 'no_threat_detected' | 'safe' | 'suspicious' | 'malicious' | 'unknown'
  scan_mode: 'local' | 'full' | 'degraded' | 'ml_only' | 'failed'
  analysis_method: 'local' | 'backend'
  ml_probability: number | null
  scanned_at: string
  source: 'extension'
  explanation: string[]
  indicators: Array<{ type: string; severity: string; description: string; source?: string }>
  evidence?: {
    ml: {
      score: number
      model_version?: string | null
      thresholds: Record<string, number>
      model_metadata: Record<string, unknown>
    }
  } | null
  cti?: {
    enriched: boolean
    virustotal?: { status: ProviderStatus; hit: boolean | null; score: number | null; error?: string | null } | null
    urlhaus?: { status: ProviderStatus; hit: boolean | null; score: number | null; error?: string | null } | null
    whois?: { status: ProviderStatus; hit: boolean | null; score: number | null; error?: string | null } | null
  } | null
}

export type ProviderStatus = 'live' | 'mock' | 'not_configured' | 'unknown' | 'error' | 'timeout'

const HISTORY_KEY = 'scan_history'
const BACKEND_URL_KEY = 'scan_backend_url'
const DATA_TTL = 24 * 60 * 60 * 1000
const MAX_HISTORY = 100
const cache = new Map<string, { result: ScanResult; ts: number }>()
const CACHE_TTL = 60_000

export async function getBackendUrl(): Promise<string> {
  const stored = await chrome.storage.local.get(BACKEND_URL_KEY)
  return typeof stored[BACKEND_URL_KEY] === 'string' ? stored[BACKEND_URL_KEY] : ''
}

export async function setBackendUrl(url: string): Promise<void> {
  if (url) {
    await chrome.storage.local.set({ [BACKEND_URL_KEY]: url })
  } else {
    await chrome.storage.local.remove(BACKEND_URL_KEY)
  }
}

export async function scanUrl(url: string, force = false): Promise<ScanResult | null> {
  const cached = cache.get(url)
  if (!force && cached && Date.now() - cached.ts < CACHE_TTL) {
    return cached.result
  }

  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return null
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) return null

  const backendUrl = await getBackendUrl()
  let backendUnavailable = false
  if (backendUrl) {
    const controller = new AbortController()
    const timeout = globalThis.setTimeout(() => controller.abort(), 10_000)
    try {
      const response = await fetch(`${backendUrl}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: parsed.href, source: 'extension' }),
        signal: controller.signal,
      })
      if (response.ok) {
        const result = toBackendResult(await response.json(), parsed.href)
        if (result) {
          cache.set(url, { result, ts: Date.now() })
          return result
        }
      }
      backendUnavailable = true
    } catch {
      backendUnavailable = true
    } finally {
      globalThis.clearTimeout(timeout)
    }
  }

  return scanUrlLocally(parsed.href, backendUnavailable)
}

function scanUrlLocally(url: string, backendUnavailable = false): ScanResult {
  const parsed = new URL(url)
  const indicators: ScanResult['indicators'] = []
  let risk = 0
  const addSignal = (type: string, description: string, weight: number) => {
    risk += weight
    indicators.push({
      type,
      description,
      severity: weight >= 0.2 ? 'high' : weight >= 0.12 ? 'medium' : 'low',
    })
  }

  const hostname = parsed.hostname.toLowerCase()
  const hostnameLabels = hostname.split('.').filter(Boolean)
  const fullUrl = `${hostname}${parsed.pathname}${parsed.search}`.toLowerCase()

  if (parsed.protocol !== 'https:') {
    addSignal('unencrypted', 'Connection does not use HTTPS.', 0.12)
  }
  if (parsed.username || parsed.password) {
    addSignal('embedded_credentials', 'URL contains embedded login credentials.', 0.32)
  }
  if (hostname.startsWith('xn--') || hostname.includes('.xn--')) {
    addSignal('punycode', 'Domain uses an encoded internationalized hostname.', 0.2)
  }
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    addSignal('ip_hostname', 'URL uses an IP address instead of a domain name.', 0.2)
  }
  if (hostnameLabels.length >= 5) {
    addSignal('deep_subdomains', 'Domain contains an unusually deep subdomain chain.', 0.14)
  }
  if (/(?:login|verify|secure|account|password|wallet|invoice|payment)/i.test(hostname)) {
    addSignal('sensitive_branding', 'Domain uses language commonly used in credential or payment lures.', 0.14)
  }
  if (/\.(?:zip|mov|top|click|work|country|gq|tk)$/i.test(hostname)) {
    addSignal('uncommon_tld', 'Domain uses a top-level domain frequently abused in deceptive links.', 0.1)
  }
  if (fullUrl.length > 180) {
    addSignal('long_url', 'URL is unusually long and may conceal its destination.', 0.12)
  }
  if (/(?:%[0-9a-f]{2}){3,}/i.test(parsed.pathname)) {
    addSignal('encoded_path', 'Path contains repeated percent-encoded characters.', 0.1)
  }

  const score = Math.min(1, Number(risk.toFixed(4)))
  const verdict = score >= 0.3 ? 'suspicious' : 'unknown'
  const result: ScanResult = {
    id: crypto.randomUUID(),
    url,
    score,
    risk_score: score,
    level: verdict,
    verdict,
    scan_mode: 'local',
    analysis_method: 'local',
    ml_probability: null,
    scanned_at: new Date().toISOString(),
    source: 'extension',
    explanation: [
      backendUnavailable
        ? 'Configured backend unavailable; local URL-pattern checks were used.'
        : 'Analyzed locally. This URL was not sent to a server.',
      ...(indicators.length ? indicators.map(({ description }) => description) : ['No common deceptive URL patterns were detected.']),
    ],
    indicators,
  }
  return result
}

function toBackendResult(value: unknown, url: string): ScanResult | null {
  if (!value || typeof value !== 'object') return null
  const data = value as Record<string, unknown>
  const score = typeof data.risk_score === 'number' ? data.risk_score : data.score
  if (typeof score !== 'number' || !Number.isFinite(score)) return null

  const allowedLevels = ['no_threat_detected', 'safe', 'suspicious', 'malicious', 'unknown'] as const
  const rawVerdict = data.verdict ?? data.level
  const verdict = allowedLevels.includes(rawVerdict as typeof allowedLevels[number])
    ? rawVerdict as ScanResult['verdict']
    : 'unknown'
  const allowedModes = ['full', 'degraded', 'ml_only', 'failed'] as const
  const rawMode = data.scan_mode
  const scanMode = allowedModes.includes(rawMode as typeof allowedModes[number])
    ? rawMode as ScanResult['scan_mode']
    : 'degraded'
  const indicators = Array.isArray(data.indicators)
    ? data.indicators.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === 'object')
      .map(item => ({
        type: String(item.type ?? 'indicator'),
        severity: String(item.severity ?? 'unknown'),
        description: String(item.description ?? ''),
        source: typeof item.source === 'string' ? item.source : undefined,
      }))
    : []

  return {
    id: typeof data.id === 'string' ? data.id : crypto.randomUUID(),
    url: typeof data.url === 'string' ? data.url : url,
    score,
    risk_score: score,
    level: verdict,
    verdict,
    scan_mode: scanMode,
    analysis_method: 'backend',
    ml_probability: typeof data.ml_probability === 'number' ? data.ml_probability : null,
    scanned_at: typeof data.scanned_at === 'string' ? data.scanned_at : new Date().toISOString(),
    source: 'extension',
    explanation: Array.isArray(data.explanation) ? data.explanation.map(String) : [],
    indicators,
    evidence: data.evidence && typeof data.evidence === 'object' ? data.evidence as ScanResult['evidence'] : null,
    cti: data.cti && typeof data.cti === 'object' ? data.cti as ScanResult['cti'] : null,
  }
}

function isFresh(result: ScanResult): boolean {
  return Date.now() - Date.parse(result.scanned_at) < DATA_TTL
}

export async function saveScanResult(result: ScanResult): Promise<void> {
  const stored = await chrome.storage.local.get(HISTORY_KEY)
  const history = Array.isArray(stored[HISTORY_KEY]) ? stored[HISTORY_KEY] as ScanResult[] : []
  const recent = history.filter(item => item && typeof item.scanned_at === 'string' && isFresh(item))
  await chrome.storage.local.set({
    [HISTORY_KEY]: [result, ...recent.filter(item => item.id !== result.id)].slice(0, MAX_HISTORY),
  })
}

export async function getRecentScans(limit = 5): Promise<ScanResult[]> {
  const stored = await chrome.storage.local.get(HISTORY_KEY)
  const history = Array.isArray(stored[HISTORY_KEY]) ? stored[HISTORY_KEY] as ScanResult[] : []
  const recent = history.filter(item => item && typeof item.scanned_at === 'string' && isFresh(item))
  if (recent.length !== history.length) {
    await chrome.storage.local.set({ [HISTORY_KEY]: recent.slice(0, MAX_HISTORY) })
  }
  return recent.slice(0, Math.max(0, limit))
}

export async function clearScanHistory(): Promise<void> {
  await chrome.storage.local.remove(HISTORY_KEY)
}

export async function pruneLocalData(): Promise<void> {
  const stored = await chrome.storage.local.get(null)
  const now = Date.now()
  const expiredKeys = Object.entries(stored).flatMap(([key, value]) => {
    if (key === HISTORY_KEY || !key.startsWith('scan_')) return []
    const record = value as { pending?: boolean; startedAt?: number; scanned_at?: string }
    const timestamp = record.pending ? record.startedAt : Date.parse(record.scanned_at ?? '')
    return typeof timestamp !== 'number' || !Number.isFinite(timestamp) || now - timestamp >= DATA_TTL ? [key] : []
  })
  if (expiredKeys.length) await chrome.storage.local.remove(expiredKeys)
  await getRecentScans(MAX_HISTORY)
}
