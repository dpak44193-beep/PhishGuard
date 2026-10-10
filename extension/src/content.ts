// Injected into every page. Listens for malicious-page messages from the background
// service worker and renders a dismissible warning banner.

chrome.runtime.onMessage.addListener((msg: { level: string; score: number }) => {
  if (msg.level !== 'malicious') return
  if (document.getElementById('phishguard-banner')) return  // already shown

  const banner = document.createElement('div')
  banner.id = 'phishguard-banner'

  Object.assign(banner.style, {
    position:     'fixed',
    top:          '0',
    left:         '0',
    right:        '0',
    zIndex:       '2147483647',
    background:   '#3d0c0c',
    color:        '#f85149',
    padding:      '10px 16px',
    fontSize:     '13px',
    fontFamily:   'monospace',
    borderBottom: '2px solid #f85149',
    display:      'flex',
    alignItems:   'center',
    gap:          '10px',
  })

  banner.innerHTML = `
    <strong>⚠ PhishGuard:</strong>
    <span>This page has been flagged as <strong>MALICIOUS</strong> (risk score: ${(msg.score * 100).toFixed(0)}%). Proceed with extreme caution.</span>
    <button id="phishguard-dismiss" style="margin-left:auto;background:none;border:1px solid #f85149;color:#f85149;cursor:pointer;padding:2px 8px;border-radius:4px;font-size:12px;font-family:monospace">Dismiss</button>
  `

  document.body.prepend(banner)

  document.getElementById('phishguard-dismiss')?.addEventListener('click', () => {
    banner.remove()
  })
})
