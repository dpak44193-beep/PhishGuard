import { FileJson, FileSpreadsheet } from 'lucide-react'
import { getReportUrl } from '../api'

const reportActions = [
  {
    label: 'Download CSV',
    description: 'Export the latest scan history as a spreadsheet-friendly file.',
    icon: FileSpreadsheet,
    href: getReportUrl('csv'),
  },
  {
    label: 'Download JSON',
    description: 'Export raw scan results for analysis or archival.',
    icon: FileJson,
    href: getReportUrl('json'),
  },
]

export default function ReportPage() {
  return (
    <div className="space-y-4 rounded-2xl border border-soc-border bg-soc-surface p-6">
      <div>
        <h1 className="text-xl font-semibold text-soc-text">Reports</h1>
        <p className="mt-2 text-sm text-soc-muted">Export live scan data from the backend or review summary-ready records here.</p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {reportActions.map(({ label, description, icon: Icon, href }) => (
          <a
            key={label}
            href={href}
            target="_blank"
            rel="noreferrer"
            className="rounded-2xl border border-soc-border bg-soc-bg/60 p-5 transition-colors hover:border-soc-accent/40 hover:bg-soc-accent/5"
          >
            <div className="flex items-center gap-2 text-soc-accent">
              <Icon className="h-4 w-4" />
              <span className="font-medium">{label}</span>
            </div>
            <p className="mt-3 text-sm text-soc-muted">{description}</p>
          </a>
        ))}
      </div>

      <div className="rounded-xl border border-dashed border-soc-border bg-soc-bg/40 p-4 text-sm text-soc-muted">
        Use the export links above to generate a backend report. Each file is served directly from the API.
      </div>
    </div>
  )
}
