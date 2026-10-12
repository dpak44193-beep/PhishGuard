import { useState } from 'react'
import type { FormEvent } from 'react'
import { AlertTriangle, ScanLine, ShieldCheck, LoaderCircle } from 'lucide-react'
import { scanUrl, type ScanResult } from '../api'

export default function ScanPage() {
  const [url, setUrl] = useState('https://example.com')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const providerRows = result?.cti
    ? [result.cti.virustotal, result.cti.urlhaus, result.cti.whois].filter(Boolean)
    : []

  const submitScan = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setLoading(true)
    setError(null)

    try {
      const response = await scanUrl({ url, source: 'frontend' })
      setResult(response)
    } catch (requestError) {
      setResult(null)
      setError(requestError instanceof Error ? requestError.message : 'Scan request failed.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="rounded-2xl border border-soc-border bg-soc-surface p-6">
        <div className="flex items-center gap-3">
          <div className="rounded-xl bg-soc-accent/10 p-2">
            <ScanLine className="h-5 w-5 text-soc-accent" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-soc-text">Scan flow</h1>
            <p className="text-sm text-soc-muted">Submit a URL to the backend and inspect the returned risk analysis.</p>
          </div>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
        <form onSubmit={submitScan} className="rounded-2xl border border-soc-border bg-soc-surface p-6">
          <label className="block text-sm font-medium text-soc-text" htmlFor="scan-url">
            URL to scan
          </label>
          <input
            id="scan-url"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="https://example.com"
            className="mt-2 w-full rounded-xl border border-soc-border bg-soc-bg px-4 py-3 text-sm text-soc-text outline-none transition-colors placeholder:text-soc-muted focus:border-soc-accent/60"
          />
          <button
            type="submit"
            disabled={loading}
            className="mt-4 inline-flex items-center gap-2 rounded-lg bg-soc-accent px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-soc-accent/90 disabled:cursor-not-allowed disabled:opacity-70"
          >
            {loading ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
            {loading ? 'Scanning…' : 'Run scan'}
          </button>

          <p className="mt-3 text-xs text-soc-muted">
            The backend requires http:// or https:// and will return the full ML plus CTI result set.
          </p>

          {error ? (
            <div className="mt-4 flex items-start gap-2 rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{error}</span>
            </div>
          ) : null}
        </form>

        <div className="rounded-2xl border border-soc-border bg-soc-surface p-6">
          <h2 className="text-base font-medium text-soc-text">Result</h2>
          {result ? (
            <div className="mt-4 space-y-4">
              <div className="rounded-xl border border-soc-border bg-soc-bg/60 p-4">
                <div className="text-xs uppercase tracking-[0.2em] text-soc-muted">Risk level</div>
                <div className="mt-2 text-2xl font-semibold text-soc-text">{result.verdict}</div>
                <div className="mt-1 text-sm text-soc-muted">
                  Score {result.risk_score.toFixed(2)} · ML {result.ml_probability.toFixed(2)} · Mode {result.scan_mode}
                </div>
                {result.verdict === 'no_threat_detected' || result.verdict === 'safe' ? (
                  <p className="mt-2 text-xs text-amber-300">
                    No threat detected is not a guarantee that this URL is safe. Provider no-matches may reflect missing coverage.
                  </p>
                ) : null}
              </div>

              <div className="rounded-xl border border-soc-border bg-soc-bg/60 p-4 text-sm text-soc-muted">
                <div className="text-xs uppercase tracking-[0.2em] text-soc-muted">Explanation</div>
                {result.explanation.length === 0 ? (
                  <p className="mt-2 text-soc-text">No explanation returned for this scan.</p>
                ) : (
                  <ul className="mt-2 space-y-2">
                    {result.explanation.map((line) => (
                      <li key={line} className="text-soc-text">
                        {line}
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <div className="rounded-xl border border-soc-border bg-soc-bg/60 p-4 text-sm text-soc-muted">
                <div className="text-xs uppercase tracking-[0.2em] text-soc-muted">Provider status</div>
                {providerRows.length === 0 ? (
                  <p className="mt-2">No CTI provider data returned for this scan.</p>
                ) : (
                  <div className="mt-2 space-y-2">
                    {providerRows.map((provider) => (
                      <div key={provider?.provider} className="rounded-lg border border-soc-border/70 px-3 py-2 text-soc-text">
                        <div className="flex items-center justify-between gap-3">
                          <span className="font-medium">{provider?.provider}</span>
                          <span className="text-xs text-soc-muted">{provider?.status}</span>
                        </div>
                        <p className="mt-1 text-sm text-soc-muted">
                          hit: {provider?.hit === null ? 'unknown' : provider?.hit ? 'yes' : 'no'}
                          {provider?.score !== null && provider?.score !== undefined ? ` · score ${provider.score.toFixed(2)}` : ''}
                        </p>
                        {provider?.error ? <p className="mt-1 text-xs text-red-300">{provider.error}</p> : null}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="rounded-xl border border-soc-border bg-soc-bg/60 p-4 text-sm text-soc-muted">
                <div className="text-xs uppercase tracking-[0.2em] text-soc-muted">Indicators</div>
                {result.indicators.length === 0 ? (
                  <p className="mt-2">No indicators returned for this scan.</p>
                ) : (
                  <ul className="mt-2 space-y-2">
                    {result.indicators.map((indicator) => (
                      <li key={`${indicator.type}-${indicator.source}`} className="rounded-lg border border-soc-border/70 px-3 py-2 text-soc-text">
                        <div className="flex items-center justify-between gap-3">
                          <span className="font-medium">{indicator.type}</span>
                          <span className="text-xs text-soc-muted">{indicator.severity}</span>
                        </div>
                        <p className="mt-1 text-sm text-soc-muted">{indicator.description}</p>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          ) : (
            <p className="mt-4 text-sm text-soc-muted">Submit a URL to see the scan response here.</p>
          )}
        </div>
      </div>
    </div>
  )
}
