import axios from 'axios'

export type RiskLevel = 'no_threat_detected' | 'safe' | 'suspicious' | 'malicious'
export type ProviderStatus = 'live' | 'mock' | 'unknown' | 'error' | 'timeout'
export type ScanMode = 'full' | 'degraded' | 'ml_only' | 'failed'

export type ThreatIndicator = {
  type: string
  severity: string
  description: string
  source: string
  value?: string | number | boolean | null
}

export type ProviderEvidence = {
  provider: string
  status: ProviderStatus
  hit: boolean | null
  score: number | null
  details: Record<string, unknown>
  error?: string | null
  latency_ms?: number | null
}

export type CtiEvidence = {
  virustotal?: ProviderEvidence | null
  urlhaus?: ProviderEvidence | null
  whois?: ProviderEvidence | null
  enriched: boolean
}

export type ScanResult = {
  id: string
  url: string
  score: number
  risk_score: number
  level: RiskLevel
  verdict: RiskLevel
  scan_mode: ScanMode
  ml_probability: number
  scanned_at: string
  source: string
  cti?: CtiEvidence | null
  evidence?: {
    ml: {
      score: number
      model_version?: string | null
      thresholds: Record<string, number>
    }
    cti: CtiEvidence
  } | null
  explanation: string[]
  indicators: ThreatIndicator[]
}

export type ScanRequest = {
  url: string
  source?: string
}

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '/api'

const client = axios.create({
  baseURL: API_BASE_URL,
})

export async function scanUrl(payload: ScanRequest): Promise<ScanResult> {
  const response = await client.post<ScanResult>('/scan', payload)
  return response.data
}

export async function fetchHistory(limit = 25, offset = 0): Promise<ScanResult[]> {
  const response = await client.get<ScanResult[]>('/history', {
    params: { limit, offset },
  })
  return response.data
}

export function getReportUrl(format: 'csv' | 'json'): string {
  return `${API_BASE_URL}/export/${format}`
}
