import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import { Shield, Clock, FileText, ScanLine } from 'lucide-react'
import Dashboard from './pages/Dashboard'
import HistoryPage from './pages/HistoryPage'
import ReportPage from './pages/ReportPage'
import ScanPage from './pages/ScanPage'

const NAV = [
  { to: '/', label: 'Dashboard', Icon: Shield },
  { to: '/scan', label: 'Scan', Icon: ScanLine },
  { to: '/history', label: 'History', Icon: Clock },
  { to: '/reports', label: 'Reports', Icon: FileText },
]

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen flex bg-soc-bg">
        {/* Sidebar */}
        <nav className="w-52 shrink-0 bg-soc-surface border-r border-soc-border flex flex-col">
          <div className="p-5 border-b border-soc-border">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-soc-accent" />
              <span className="font-bold text-soc-text tracking-widest text-sm">PHISHGUARD</span>
            </div>
            <div className="text-xs text-soc-muted mt-1 font-mono">Threat Intelligence</div>
          </div>

          <div className="p-3 space-y-0.5 flex-1">
            {NAV.map(({ to, label, Icon }) => (
              <NavLink
                key={to}
                to={to}
                end={to === '/'}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-soc-accent/10 text-soc-accent border border-soc-accent/20'
                      : 'text-soc-muted hover:text-soc-text hover:bg-soc-border/40'
                  }`
                }
              >
                <Icon className="w-4 h-4 shrink-0" />
                {label}
              </NavLink>
            ))}
          </div>

          <div className="p-4 border-t border-soc-border text-xs text-soc-muted/50 font-mono">
            v1.0.0 · SOC Edition
          </div>
        </nav>

        {/* Main content */}
        <main className="flex-1 p-8 overflow-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan" element={<ScanPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/reports" element={<ReportPage />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
