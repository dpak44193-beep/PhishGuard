import React, { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import ReactDOM from 'react-dom/client'
import { clearScanHistory, getBackendUrl, getRecentScans, pruneLocalData, saveScanResult, scanUrl, setBackendUrl } from './api'
import type { ScanResult } from './api'

type Level = ScanResult['verdict']

const LEVEL_STYLE: Record<Level | 'pending', { color: string; label: string }> = {
  no_threat_detected: { color: '#8b949e', label: 'NO THREAT DETECTED' },
  safe:       { color: '#8b949e', label: 'NO THREAT DETECTED' },
  suspicious: { color: '#d29922', label: 'SUSPICIOUS' },
  malicious:  { color: '#f85149', label: 'MALICIOUS'  },
  unknown:    { color: '#8b949e', label: 'UNKNOWN'     },
  pending:    { color: '#58a6ff', label: 'SCANNING…'  },
}

const SEV_COLOR: Record<string, string> = {
  critical: '#f85149',
  high:     '#d29922',
  medium:   '#e3b341',
  low:      '#3fb950',
}

function isScannable(url: string): boolean {
  return /^https?:\/\//i.test(url)
}

function normalizeTarget(value: string): string {
  const trimmed = value.trim()
  const candidate = /^[a-z][a-z\d+.-]*:/i.test(trimmed) ? trimmed : `https://${trimmed}`
  const parsed = new URL(candidate)
  if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password) {
    throw new Error('Enter a valid http:// or https:// website URL without login credentials.')
  }
  return parsed.href
}

function normalizeBackend(value: string): { url: string; originPattern: string } {
  const parsed = new URL(value.trim())
  const localHost = ['localhost', '127.0.0.1'].includes(parsed.hostname)
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && localHost)) {
    throw new Error('Use an HTTPS backend URL. HTTP is allowed only for localhost development.')
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error('Backend URL must not contain credentials, a query, or a fragment.')
  }
  const url = `${parsed.origin}${parsed.pathname}`.replace(/\/+$/, '')
  return { url, originPattern: `${parsed.origin}/*` }
}

function Popup() {
  const [result, setResult]     = useState<ScanResult | null>(null)
  const [pending, setPending]   = useState(false)
  const [tabId, setTabId]       = useState<number | null>(null)
  const [tabUrl, setTabUrl]     = useState<string>('')
  const [rescanning, setRescanning] = useState(false)
  const [recentScans, setRecentScans] = useState<ScanResult[]>([])
  const [clearingHistory, setClearingHistory] = useState(false)
  const [scanTarget, setScanTarget] = useState('')
  const [manualScanning, setManualScanning] = useState(false)
  const [targetError, setTargetError] = useState('')
  const [backendUrl, setBackendUrlInput] = useState('')
  const [backendStatus, setBackendStatus] = useState('Local checks only')
  const [savingBackend, setSavingBackend] = useState(false)

  useEffect(() => {
    let interval: number | undefined

    const loadPopup = async () => {
      await pruneLocalData()
      setBackendUrlInput(await getBackendUrl())
      if (await getBackendUrl()) setBackendStatus('Configured; online checks enabled')
      setRecentScans(await getRecentScans(3))
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
      const tab = tabs[0]
      if (tab?.id === undefined) return
      setTabId(tab.id)
      setTabUrl(tab.url ?? '')
      const key = `scan_${tab.id}`
      const data = await chrome.storage.local.get(key)
      const stored = data[key]
      if (!stored) return
      if (stored.pending) {
        setPending(true)
        interval = window.setInterval(async () => {
          const latest = await chrome.storage.local.get(key)
          const updated = latest[key]
          if (!updated?.pending) {
            window.clearInterval(interval)
            setPending(false)
            setResult(updated ?? null)
            setRecentScans(await getRecentScans(3))
          }
        }, 500)
      } else {
        setResult(stored)
      }
    }

    void loadPopup()
    return () => {
      if (interval !== undefined) window.clearInterval(interval)
    }
  }, [])

  async function handleScanTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setTargetError('')
    setManualScanning(true)
    try {
      const url = normalizeTarget(scanTarget)
      setScanTarget(url)
      const fresh = await scanUrl(url, true)
      if (!fresh) throw new Error('Could not analyze this URL.')
      setResult(fresh)
      await saveScanResult(fresh)
      setRecentScans(await getRecentScans(3))
    } catch (error) {
      setTargetError(error instanceof Error ? error.message : 'Could not analyze this URL.')
    } finally {
      setManualScanning(false)
    }
  }

  async function handleSaveBackend(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSavingBackend(true)
    setBackendStatus('')
    try {
      const previousUrl = await getBackendUrl()
      if (!backendUrl.trim()) {
        if (previousUrl) {
          const previous = normalizeBackend(previousUrl)
          await chrome.permissions.remove({ origins: [previous.originPattern] })
        }
        await setBackendUrl('')
        setBackendStatus('Local checks only')
        return
      }

      const normalized = normalizeBackend(backendUrl)
      const granted = await chrome.permissions.request({ origins: [normalized.originPattern] })
      if (!granted) throw new Error('Permission was not granted. The backend was not saved.')
      await setBackendUrl(normalized.url)
      setBackendUrlInput(normalized.url)
      const controller = new AbortController()
      const timeout = window.setTimeout(() => controller.abort(), 5000)
      try {
        const response = await fetch(`${normalized.url}/health`, { signal: controller.signal })
        setBackendStatus(response.ok
          ? 'Backend connected. New scans will include online analysis.'
          : `Saved, but health check returned ${response.status}. Local fallback will be used if scans fail.`)
      } catch {
        setBackendStatus('Saved, but backend is unreachable. Scans will use local fallback until it is online.')
      } finally {
        window.clearTimeout(timeout)
      }
    } catch (error) {
      setBackendStatus(error instanceof Error ? error.message : 'Could not save this backend URL.')
    } finally {
      setSavingBackend(false)
    }
  }

  async function handleRescan() {
    const url = result?.url ?? tabUrl
    if (tabId === null || !url || rescanning || !isScannable(url)) return
    setRescanning(true)
    setResult(null)
    try {
      const fresh = await scanUrl(url, true)
      if (fresh) {
        await chrome.storage.local.set({ [`scan_${tabId}`]: fresh })
        await saveScanResult(fresh)
        setRecentScans(await getRecentScans(3))
      } else {
        await chrome.storage.local.remove(`scan_${tabId}`)
      }
      setResult(fresh)
    } catch {
      setResult(null)
    } finally {
      setRescanning(false)
    }
  }

  async function handleClearHistory() {
    setClearingHistory(true)
    try {
      await clearScanHistory()
      setRecentScans([])
    } finally {
      setClearingHistory(false)
    }
  }

  const displayLevel: Level | 'pending' = rescanning || pending ? 'pending' : result?.verdict ?? 'unknown'
  const style = LEVEL_STYLE[displayLevel] ?? LEVEL_STYLE.unknown
  const score = result ? (result.risk_score * 100).toFixed(0) : '—'

  return (
    <div style={{ width: 340, padding: 16, background: '#0d1117', color: '#c9d1d9', fontFamily: 'monospace', fontSize: 13 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14, paddingBottom: 10, borderBottom: '1px solid #21262d' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 18 }}>🛡</span>
          <span style={{ color: '#58a6ff', fontWeight: 700, letterSpacing: 2 }}>PHISHGUARD</span>
        </div>
        <button
          onClick={handleRescan}
          disabled={rescanning || pending}
          title="Force rescan"
          style={{
            background: 'none', border: '1px solid #30363d', color: rescanning || pending ? '#30363d' : '#8b949e',
            cursor: rescanning || pending ? 'default' : 'pointer', padding: '2px 8px',
            borderRadius: 4, fontSize: 11, fontFamily: 'monospace',
          }}
        >
          {rescanning ? 'scanning…' : '↺ rescan'}
        </button>
      </div>

      {/* Status badge */}
      <div style={{ color: style.color, fontSize: 17, fontWeight: 700, marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
        {displayLevel === 'pending' ? (
          <span style={{ opacity: 0.8 }}>⏳ {style.label}</span>
        ) : (
          <span>{style.label}</span>
        )}
      </div>
      {(result?.verdict === 'no_threat_detected' || result?.verdict === 'safe') && (
        <div style={{ color: '#d29922', fontSize: 10, lineHeight: 1.5, marginTop: -6, marginBottom: 10 }}>
          No threat detected is not a guarantee that this URL is safe. Provider no-matches may reflect missing coverage.
        </div>
      )}

      {/* URL */}
      <div style={{ color: '#8b949e', fontSize: 11, marginBottom: 10, wordBreak: 'break-all', lineHeight: 1.4 }}>
        {(result?.url ?? tabUrl).slice(0, 120)}{(result?.url ?? tabUrl).length > 120 ? '…' : ''}
      </div>

      <form onSubmit={handleScanTarget} style={{ marginBottom: 14 }}>
        <label htmlFor="scan-target" style={{ display: 'block', color: '#8b949e', fontSize: 10, marginBottom: 5, textTransform: 'uppercase' }}>
          Scan any website link
        </label>
        <div style={{ display: 'flex', gap: 6 }}>
          <input
            id="scan-target"
            type="text"
            inputMode="url"
            autoComplete="url"
            placeholder="https://example.com"
            value={scanTarget}
            onChange={event => setScanTarget(event.target.value)}
            style={{ minWidth: 0, flex: 1, border: '1px solid #30363d', borderRadius: 4, background: '#010409', color: '#c9d1d9', padding: '7px 8px', fontSize: 11 }}
          />
          <button
            type="submit"
            disabled={manualScanning || !scanTarget.trim()}
            style={{ border: 0, borderRadius: 4, background: '#238636', color: '#fff', padding: '6px 10px', fontSize: 11, cursor: manualScanning ? 'wait' : 'pointer' }}
          >
            {manualScanning ? 'Checking…' : 'Scan'}
          </button>
        </div>
        {targetError ? <div role="alert" style={{ color: '#f85149', fontSize: 10, marginTop: 5 }}>{targetError}</div> : null}
      </form>

      {result && !pending && !rescanning ? (
        <>
          {/* Scores row */}
          <div style={{ display: 'flex', gap: 20, marginBottom: 12, fontSize: 12 }}>
            <div>
              <div style={{ color: '#8b949e' }}>Risk Score</div>
              <div style={{ color: style.color, fontWeight: 700, fontSize: 22 }}>{score}%</div>
            </div>
            <div>
              <div style={{ color: '#8b949e' }}>Analysis</div>
              <div style={{ color: '#c9d1d9', fontWeight: 700, fontSize: 22 }}>
                {result.analysis_method === 'backend' ? 'ML + CTI' : 'Local'}
              </div>
            </div>
            <div>
              <div style={{ color: '#8b949e' }}>Flags</div>
              <div style={{ color: '#c9d1d9', fontWeight: 700, fontSize: 22 }}>
                {result.indicators.length}
              </div>
            </div>
          </div>

          {/* Indicators */}
          {result.indicators.length > 0 && (
            <div style={{ marginBottom: 10 }}>
              <div style={{ color: '#8b949e', fontSize: 10, marginBottom: 4, textTransform: 'uppercase', letterSpacing: 1 }}>Indicators</div>
              {result.indicators.map((ind, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 6, marginBottom: 4 }}>
                  <span style={{ color: SEV_COLOR[ind.severity] ?? '#8b949e', fontSize: 10, flexShrink: 0, marginTop: 1 }}>●</span>
                  <span style={{ color: '#c9d1d9', fontSize: 11, lineHeight: 1.4 }}>{ind.description}</span>
                </div>
              ))}
            </div>
          )}

          {/* Explanation bullets */}
          {result.explanation.length > 0 && (
            <div style={{ marginBottom: 8 }}>
              <div style={{ color: '#8b949e', fontSize: 10, marginBottom: 4, textTransform: 'uppercase', letterSpacing: 1 }}>Analysis</div>
              <ul style={{ margin: 0, paddingLeft: 14, color: '#8b949e', fontSize: 11, lineHeight: 1.6 }}>
                {result.explanation.slice(0, 4).map((e, i) => <li key={i}>{e}</li>)}
              </ul>
            </div>
          )}

          {result.analysis_method === 'local' ? (
            <div style={{ color: '#d29922', fontSize: 10, marginBottom: 8 }}>
              {result.explanation[0]?.startsWith('Configured backend unavailable')
                ? 'Online service unavailable. This is only a local pattern estimate.'
                : 'Pattern-based estimate only. Configure a backend below for ML and threat-intelligence results.'}
            </div>
          ) : null}

          {result.cti ? (
            <div style={{ marginBottom: 8 }}>
              <div style={{ color: '#8b949e', fontSize: 10, marginBottom: 4, textTransform: 'uppercase' }}>Threat intelligence</div>
              {(['virustotal', 'urlhaus', 'whois'] as const).map(providerName => {
                const provider = result.cti?.[providerName]
                if (!provider) return null
                return (
                  <div key={providerName} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, color: '#c9d1d9', fontSize: 10, marginBottom: 3 }}>
                    <span>{providerName}</span>
                    <span style={{ color: provider.hit ? '#f85149' : '#8b949e' }}>
                      {provider.status}{provider.hit ? ' · flagged' : ''}
                    </span>
                  </div>
                )
              })}
            </div>
          ) : null}
        </>
      ) : !pending && !rescanning ? (
        <div style={{ color: '#8b949e', fontSize: 12, lineHeight: 1.6 }}>
          {!isScannable(tabUrl)
            ? <>This page cannot be scanned.<br />Navigate to an http/https URL.</>
            : <>No scan result for the current tab.<br />Navigate to a page to trigger an automatic scan,<br />or click ↺ rescan above.</>
          }
        </div>
      ) : null}

      <div style={{ marginTop: 14, paddingTop: 10, borderTop: '1px solid #21262d' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
          <span style={{ color: '#8b949e', fontSize: 10, textTransform: 'uppercase' }}>Recent local scans</span>
          <button
            type="button"
            onClick={handleClearHistory}
            disabled={clearingHistory || recentScans.length === 0}
            title="Clear local scan history"
            style={{ background: 'none', border: 0, color: '#8b949e', cursor: recentScans.length ? 'pointer' : 'default', fontSize: 10 }}
          >
            Clear
          </button>
        </div>
        {recentScans.length ? recentScans.map(scan => (
          <div key={scan.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 10, marginBottom: 5, fontSize: 10 }}>
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: '#c9d1d9' }}>
              {new URL(scan.url).hostname}
            </span>
            <span style={{ color: LEVEL_STYLE[scan.verdict]?.color ?? '#8b949e', flexShrink: 0 }}>
              {scan.verdict.replace(/_/g, ' ')} · {(scan.risk_score * 100).toFixed(0)}%
            </span>
          </div>
        )) : <div style={{ color: '#8b949e', fontSize: 10 }}>No recent scans</div>}
        <div style={{ color: '#8b949e', fontSize: 9, marginTop: 6 }}>Stored on this device for 24 hours.</div>
      </div>

      <form onSubmit={handleSaveBackend} style={{ marginTop: 14, paddingTop: 10, borderTop: '1px solid #21262d' }}>
        <label htmlFor="backend-url" style={{ display: 'block', color: '#8b949e', fontSize: 10, marginBottom: 5, textTransform: 'uppercase' }}>
          Online analysis backend
        </label>
        <div style={{ display: 'flex', gap: 6 }}>
          <input
            id="backend-url"
            type="url"
            placeholder="https://your-server.example/api"
            value={backendUrl}
            onChange={event => setBackendUrlInput(event.target.value)}
            style={{ minWidth: 0, flex: 1, border: '1px solid #30363d', borderRadius: 4, background: '#010409', color: '#c9d1d9', padding: '7px 8px', fontSize: 10 }}
          />
          <button
            type="submit"
            disabled={savingBackend}
            style={{ border: '1px solid #30363d', borderRadius: 4, background: 'transparent', color: '#c9d1d9', padding: '6px 8px', fontSize: 10, cursor: savingBackend ? 'wait' : 'pointer' }}
          >
            {savingBackend ? 'Saving…' : backendUrl.trim() ? 'Connect' : 'Disable'}
          </button>
        </div>
        <div role="status" style={{ color: '#8b949e', fontSize: 9, marginTop: 5 }}>{backendStatus}</div>
        <div style={{ color: '#8b949e', fontSize: 9, marginTop: 4 }}>Only this server origin is permissioned. HTTPS required except localhost. No API keys belong here.</div>
      </form>

      <div style={{ marginTop: 14, paddingTop: 10, borderTop: '1px solid #21262d', color: '#30363d', fontSize: 10, textAlign: 'right' }}>
        PhishGuard v1.0.0
      </div>
    </div>
  )
}

ReactDOM.createRoot(document.getElementById('root')!).render(<Popup />)
