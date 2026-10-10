import { useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { fetchHistory, type ScanResult } from '../api'

export default function HistoryPage() {
  const [items, setItems] = useState<ScanResult[]>([])
  const [loading, setLoading] = useState(true)

  const loadHistory = async () => {
    setLoading(true)
    try {
      const history = await fetchHistory(50)
      setItems(history)
    } catch {
      setItems([])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void loadHistory()
  }, [])

  return (
    <div className="space-y-4 rounded-2xl border border-soc-border bg-soc-surface p-6">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-soc-text">Scan history</h1>
          <p className="mt-2 text-sm text-soc-muted">Live records from the backend history endpoint.</p>
        </div>
        <button
          type="button"
          onClick={() => void loadHistory()}
          className="inline-flex items-center gap-2 rounded-lg border border-soc-border bg-soc-bg px-3 py-2 text-sm font-medium text-soc-text transition-colors hover:border-soc-accent/40 hover:text-soc-accent"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {items.length === 0 ? (
        <p className="text-sm text-soc-muted">No scan history is available yet. Run a scan to populate this view.</p>
      ) : (
        <div className="overflow-hidden rounded-xl border border-soc-border">
          <table className="min-w-full divide-y divide-soc-border text-sm">
            <thead className="bg-soc-bg/70 text-xs uppercase tracking-[0.18em] text-soc-muted">
              <tr>
                <th className="px-4 py-3 text-left font-medium">URL</th>
                <th className="px-4 py-3 text-left font-medium">Level</th>
                <th className="px-4 py-3 text-left font-medium">Score</th>
                <th className="px-4 py-3 text-left font-medium">Scanned</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border bg-soc-surface">
              {items.map((scan) => (
                <tr key={scan.id} className="hover:bg-soc-bg/50">
                  <td className="max-w-xl px-4 py-3 text-soc-text">
                    <div className="truncate">{scan.url}</div>
                  </td>
                  <td className="px-4 py-3 text-soc-muted">{scan.level}</td>
                  <td className="px-4 py-3 text-soc-muted">{scan.score.toFixed(2)}</td>
                  <td className="px-4 py-3 text-soc-muted">{new Date(scan.scanned_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
