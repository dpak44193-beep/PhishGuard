import { Link } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { ArrowRight, ShieldCheck, Search, ScanLine } from 'lucide-react'
import { fetchHistory, type ScanResult } from '../api'

export default function Dashboard() {
  const [recentScans, setRecentScans] = useState<ScanResult[]>([])
  const [summary, setSummary] = useState({ total: 0, suspicious: 0, malicious: 0 })

  useEffect(() => {
    let cancelled = false

    fetchHistory(5)
      .then((items) => {
        if (cancelled) {
          return
        }

        setRecentScans(items)
        setSummary({
          total: items.length,
          suspicious: items.filter((item) => item.level === 'suspicious').length,
          malicious: items.filter((item) => item.level === 'malicious').length,
        })
      })
      .catch(() => {
        if (!cancelled) {
          setRecentScans([])
          setSummary({ total: 0, suspicious: 0, malicious: 0 })
        }
      })

    return () => {
      cancelled = true
    }
  }, [])

  return (
    <div className="space-y-6">
      <div className="rounded-2xl border border-soc-border bg-soc-surface p-6 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="rounded-xl bg-soc-accent/10 p-2">
            <ShieldCheck className="h-5 w-5 text-soc-accent" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-soc-text">PhishGuard SOC Dashboard</h1>
            <p className="text-sm text-soc-muted">Monitor suspicious URLs and review recent scans.</p>
          </div>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <div className="rounded-2xl border border-soc-border bg-soc-surface p-6">
          <div className="text-xs uppercase tracking-[0.2em] text-soc-muted">Scans</div>
          <div className="mt-3 text-3xl font-semibold text-soc-text">{summary.total}</div>
          <div className="mt-2 text-sm text-soc-muted">Latest scan activity loaded from the backend.</div>
        </div>

        <div className="rounded-2xl border border-soc-border bg-soc-surface p-6">
          <div className="text-xs uppercase tracking-[0.2em] text-soc-muted">Suspicious</div>
          <div className="mt-3 text-3xl font-semibold text-soc-text">{summary.suspicious}</div>
          <div className="mt-2 text-sm text-soc-muted">URLs flagged with a suspicious risk level.</div>
        </div>

        <div className="rounded-2xl border border-soc-border bg-soc-surface p-6">
          <div className="text-xs uppercase tracking-[0.2em] text-soc-muted">Malicious</div>
          <div className="mt-3 text-3xl font-semibold text-soc-text">{summary.malicious}</div>
          <div className="mt-2 text-sm text-soc-muted">High-confidence detections from the scan pipeline.</div>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded-2xl border border-soc-border bg-soc-surface p-6">
          <div className="flex items-center gap-2 text-soc-accent">
            <Search className="h-4 w-4" />
            <h2 className="font-medium">Quick Scan</h2>
          </div>
          <p className="mt-3 text-sm text-soc-muted">Use the backend scan endpoint to inspect a URL and review the risk level.</p>
          <Link
            to="/scan"
            className="mt-4 inline-flex items-center gap-2 rounded-lg bg-soc-accent px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-soc-accent/90"
          >
            Open scan flow <ArrowRight className="h-4 w-4" />
          </Link>
        </div>

        <div className="rounded-2xl border border-soc-border bg-soc-surface p-6">
          <div className="flex items-center gap-2 text-soc-accent">
            <ScanLine className="h-4 w-4" />
            <h2 className="font-medium">Recent activity</h2>
          </div>
          {recentScans.length === 0 ? (
            <p className="mt-3 text-sm text-soc-muted">No scan history is available yet. Run a scan to populate this view.</p>
          ) : (
            <div className="mt-3 space-y-3">
              {recentScans.map((scan) => (
                <div key={scan.id} className="rounded-xl border border-soc-border/70 bg-soc-bg/60 px-3 py-2">
                  <div className="flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate text-sm font-medium text-soc-text">{scan.url}</div>
                      <div className="mt-1 text-xs text-soc-muted">{new Date(scan.scanned_at).toLocaleString()}</div>
                    </div>
                    <span className="rounded-full border border-soc-accent/20 bg-soc-accent/10 px-2 py-1 text-xs font-medium text-soc-accent">
                      {scan.level}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
