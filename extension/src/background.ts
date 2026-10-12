import { pruneLocalData, saveScanResult, scanUrl } from './api'

type BadgeLevel = 'no_threat_detected' | 'safe' | 'suspicious' | 'malicious' | 'unknown' | 'pending'

const BADGE_COLORS: Record<BadgeLevel, string> = {
  pending:    '#58a6ff',
  no_threat_detected: '#8b949e',
  safe:       '#8b949e',
  suspicious: '#d29922',
  malicious:  '#f85149',
  unknown:    '#8b949e',
}

const BADGE_TEXT: Record<BadgeLevel, string> = {
  pending:    '...',
  no_threat_detected: 'NTH',
  safe:       'NTH',
  suspicious: '!!',
  malicious:  'BAD',
  unknown:    '?',
}

chrome.runtime.onInstalled.addListener(() => {
  void pruneLocalData()
})

chrome.runtime.onStartup.addListener(() => {
  void pruneLocalData()
})

function setBadge(tabId: number, level: BadgeLevel): void {
  chrome.action.setBadgeText({ tabId, text: BADGE_TEXT[level] })
  chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[level] })
}

chrome.webNavigation.onCompleted.addListener(async ({ tabId, url, frameId }) => {
  if (frameId !== 0 || !/^https?:\/\//i.test(url)) return

  setBadge(tabId, 'pending')
  const key = `scan_${tabId}`
  await chrome.storage.local.set({ [key]: { pending: true, url, startedAt: Date.now() } })

  try {
    const result = await scanUrl(url)

    if (!result) {
      setBadge(tabId, 'unknown')
      await chrome.storage.local.remove(key)
      return
    }

    setBadge(tabId, result.verdict as BadgeLevel)
    await chrome.storage.local.set({ [key]: result })
    await saveScanResult(result)

    if (result.verdict === 'malicious') {
      chrome.notifications.create(`phishguard_${tabId}_${Date.now()}`, {
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: 'PhishGuard: Malicious URL detected',
        message: `Risk: ${(result.score * 100).toFixed(0)}%\n${url.slice(0, 80)}`,
        priority: 2,
      })

      chrome.tabs.sendMessage(tabId, { level: result.verdict, score: result.risk_score }).catch(() => undefined)
    }
  } catch {
    setBadge(tabId, 'unknown')
    await chrome.storage.local.remove(key)
  }
})

chrome.tabs.onRemoved.addListener(tabId => {
  chrome.storage.local.remove(`scan_${tabId}`)
})
