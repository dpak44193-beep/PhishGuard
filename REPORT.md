# PhishGuard — Technical Report

**Project:** ML-Powered Phishing URL Detection with Real-Time CTI Enrichment  
**Audit date:** 2026-10-10  
**Stack:** Python 3.11 · FastAPI · XGBoost · React 18 · Chrome MV3

---

## 1. Executive Summary

PhishGuard is a local-first phishing URL scanner for SOC analyst workflows. It combines a 30-feature lexical URL model with URLhaus, WHOIS, and optional VirusTotal enrichment. The audit found the active model was trained on synthetic data, so the project is not yet validated for production detection claims.

The system has a FastAPI backend, React dashboard, Chrome MV3 extension, and standalone ML training pipeline. Local scan, history persistence, and live URLhaus/WHOIS integration were verified during this audit.

**Key results:**

| Metric | Value |
|---|---|
| Active model source | Synthetic feature vectors; development-only |
| Legacy synthetic holdout accuracy | 99.94%; explicitly ineligible as real-world evaluation |
| Live API smoke scan | `https://example.com` returned HTTP 200 and was stored locally |
| Live CTI providers verified | URLhaus and WHOIS |
| VirusTotal | Unknown / not configured; no API key present |
| Real-world model performance | Not measured |

---

## 2. Problem Statement

Phishing URLs are the primary vector for credential theft and malware delivery. Traditional blocklist-based detection suffers from two fundamental limitations:

1. **Staleness** — a new phishing domain can be live for hours before any blocklist catches it.
2. **Coverage** — attackers continuously register new domains that have never appeared in a blocklist.

A lexical ML classifier operating on URL structure detects zero-day phishing domains with no dependency on prior sightings. Combined with real-time CTI enrichment, it can flag known-malicious infrastructure while simultaneously catching novel attacks via structural signals.

PhishGuard's design goal: a single API call returns a fused risk score that a SOC analyst can act on immediately — no context-switching between VirusTotal, WHOIS lookups, and internal tools.

---

## 3. System Architecture

### 3.1 Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         PhishGuard                              │
│                                                                 │
│  Chrome Extension  ──►  FastAPI Backend  ──►  SQLite / PgSQL   │
│  React Dashboard   ──►  /api/scan        ──►  scan_orchestrator │
│                              │                      │           │
│                    ┌─────────┴──────┐    ┌──────────┴────────┐ │
│                    │  ML Service    │    │   CTI Service     │ │
│                    │  XGBoost + RF  │    │  VT / URLhaus /   │ │
│                    │  30 features   │    │  WHOIS adapters   │ │
│                    └────────────────┘    └───────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Request Flow

1. Client (dashboard or extension) POSTs `{ url, source }` to `/api/scan`.
2. `scan_orchestrator` fans out to `ml_service` and `cti_service` concurrently using `asyncio.gather`.
3. `ml_service` runs `URLFeatureExtractor.extract(url)` → 30 floats → model `.predict_proba()` → scalar ML probability.
4. `cti_service` calls VirusTotal v3, URLhaus, and WHOIS adapters in parallel; each returns a normalized `CTIResponse(score: float, raw: dict)`.
5. `risk_scorer` computes the weighted aggregate:

```
final_score = 0.40·ml + 0.30·vt + 0.20·urlhaus + 0.10·whois
```

6. Score is mapped to a risk level (`safe < 0.30`, `suspicious < 0.65`, `malicious ≥ 0.65`).
7. Indicators are generated from both ML feature analysis and CTI raw fields.
8. Result is persisted to the database and returned as a `ScanResult` JSON response.

### 3.3 Design Decisions

**Why async throughout?**  
CTI API calls are I/O-bound and can block for 300–800ms each. Using `asyncio.gather` for CTI + ML concurrency reduces total latency from ~2s (serial) to ~0.4s (parallel). FastAPI's ASGI model makes this natural.

**Why SQLite for dev, PostgreSQL for prod?**  
SQLAlchemy 2.x with `aiosqlite`/`asyncpg` backends lets us swap the database via a single `DATABASE_URL` env var. No raw SQL anywhere — all queries use ORM expressions. This eliminates dialect-specific bugs and keeps the test suite fast (in-memory SQLite, no containers needed).

**Why a mock CTI layer?**  
VirusTotal's free tier is rate-limited to 4 req/min. Requiring a live API key would break local dev and CI. `CTI_MOCK=true` (the default) swaps in `mock_adapters.py` which returns deterministic, structurally correct responses, so every downstream layer (orchestrator, risk scorer, indicators) exercises its full code path.

---

## 4. Machine Learning Pipeline

### 4.1 Feature Engineering

The feature extractor (`ml/features/extractor.py`) computes 30 lexical features from the URL string alone — no HTTP requests, no DNS resolution. Features are designed around known phishing indicators:

**Length and structure signals** (features 1–10): URL length, domain length, subdomain depth, digit ratio. Phishing URLs tend to be longer and contain more digits to mimic legitimate paths.

**Entropy signal** (feature 11): Shannon entropy of the domain. Random-looking domains (`j4hf92k.xyz`) score higher than dictionary-word domains.

**Keyword signals** (features 12, 26): Count of known phishing keywords (login, verify, secure, update, confirm, account, banking, paypal, apple) and brand names in the domain. Typosquatting typically plants these to deceive users visually.

**Obfuscation signals** (features 17–24): Percent-encoding, double-slash redirects, raw IP addresses, punycode IDN homographs, hex encoding in the domain. Each represents an evasion technique documented in the phishing literature.

**TLD risk signal** (feature 14): Binary flag if the TLD is in a curated high-risk set (`.xyz`, `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.pw`). These free/low-cost TLDs are disproportionately associated with malicious infrastructure.

The `FEATURE_ORDER` list in `extractor.py` is the single source of truth for feature ordering. The same list is used at training time and inference time, guaranteeing no feature mismatch between the model artifact and live scoring.

### 4.2 Model Architecture

**Base model:** A `StandardScaler` pipeline around a soft-voting `VotingClassifier` when XGBoost is installed, otherwise RandomForest alone:
- XGBoost (`n_estimators=300`, `max_depth=6`, `learning_rate=0.05`, `subsample=0.8`)
- RandomForest (`n_estimators=200`, `max_depth=10`)

The runtime uses the base-model phishing probability and applies a threshold selected on the validation split. CTI is combined at scan time by the deterministic decision engine, not used to train a separate score combiner.

**Training data strategy:** Default training requires the real labeled URL dataset at `ml/data/raw/labeled_urls.csv` (columns: `url, label`). Missing, malformed, or unusable data stops training. Synthetic feature vectors are available only through `python ml/train.py --synthetic` and write separate, ineligible development artifacts.

**Why not deep learning?** For tabular lexical features, gradient-boosted trees consistently outperform neural networks while being: (a) faster to train (seconds vs. minutes), (b) directly interpretable via feature importance, (c) deployable without a GPU, and (d) stable across the small feature count.

### 4.3 Evaluation Results

Training split: 70% train, 15% validation, 15% test (stratified).

The existing model and metrics were generated from synthetic vectors. The recorded 99.94% accuracy is a synthetic smoke-test result, not a phishing detection performance claim. Synthetic artifact and metrics metadata set `final_evaluation_eligible` to `false`; no real-world evaluation has been completed.

The repository does not currently generate a feature-importance report. No expected real-world accuracy is asserted until the model is trained and evaluated on a documented, independent real URL dataset.

### 4.4 Inference Latency

No repeatable latency benchmark is checked into the repository. End-to-end scan latency depends on live CTI network requests and should be benchmarked separately from local model inference.

---

## 5. CTI Enrichment Pipeline

### 5.1 Adapter Design

All CTI adapters extend `BaseCTIAdapter` (defined in `cti/base.py`):

```python
class BaseCTIAdapter:
    async def query(self, url: str) -> CTIResponse: ...
```

`CTIResponse` carries a normalized `score` (0–1) and a `raw` dict with the full API response. This interface lets the orchestrator treat all adapters identically and swap mock/live implementations transparently.

### 5.2 VirusTotal v3 Adapter

- Encodes URL to base64-without-padding, hits `/urls/{id}` endpoint
- Maps `last_analysis_stats.malicious / total_engines` to a 0–1 score
- Handles 404 (URL not yet analyzed) by returning score 0
- Rate-limited to 4 req/min on free tier; production deployments should use a paid key

### 5.3 URLhaus Adapter

- POST to `https://urlhaus-api.abuse.ch/v1/url/`
- Maps `query_status == "is_db"` to a threat score
- No API key required; query_status `no_results` returns score 0

### 5.4 WHOIS Adapter

- Uses `python-whois` to resolve domain registration metadata
- Converts domain age (creation_date → days since registration) to a categorical risk score: under 30 days scores 1.0, under 180 days scores 0.5, under 365 days scores 0.2
- New domains are a strong phishing indicator — attackers register disposable domains hours before a campaign

### 5.5 Score Aggregation

```
final = 0.40·ml + 0.30·vt + 0.20·urlhaus + 0.10·whois
```

Weight rationale:
- ML (0.40): Highest weight; operates entirely at request time with no external I/O; most reliable latency
- VirusTotal (0.30): Industry-standard reputation; 72+ engine consensus is highly reliable when data exists
- URLhaus (0.20): Focused specifically on malware distribution URLs; lower weight because coverage is narrower
- WHOIS (0.10): Domain age is a signal, not a verdict; a young legitimate domain should not be flagged malicious

---

## 6. Backend API

### 6.1 Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/scan` | Submit a URL for analysis |
| GET | `/api/history` | Paginated scan history |
| GET | `/api/export/csv` | Download all scans as CSV |
| GET | `/api/export/json` | Download all scans as JSON |
| GET | `/api/health` | Liveness probe |

### 6.2 Validation

`ScanRequest` uses Pydantic v2 with a URL validator that rejects non-HTTP/HTTPS schemes. Passing `ftp://...` or a bare IP returns HTTP 422 with a structured error body. This prevents the ML service from encountering malformed inputs.

### 6.3 Database Layer

All database access flows through `backend/app/services/db_service.py`. The `ScanRecord` ORM model maps directly to the `scans` table. `init_db()` creates tables on startup via `metadata.create_all`, making the system self-initializing with no manual migration step required for development.

Production deployments should use Alembic for schema migrations.

---

## 7. SOC Dashboard

### 7.1 Component Architecture

```
pages/
  Dashboard       — scan form + live risk chart + recent history
  HistoryPage     — full paginated table with CSV/JSON export
  ReportPage      — IoC report grouped by severity (malicious → suspicious)

components/
  ScanForm        — URL input with loading state
  RiskBadge       — color-coded level pill with optional score %
  ThreatDetails   — collapsible indicator list + CTI raw data
  ScanHistory     — table with relative timestamps
  RiskDistChart   — recharts pie chart of safe/suspicious/malicious counts
  ExportButton    — triggers /api/export/{csv|json} download
```

### 7.2 Design Choices

**Dark SOC theme:** The `soc-*` color palette (`soc-bg`, `soc-surface`, `soc-safe`, `soc-suspicious`, `soc-malicious`) is defined in `tailwind.config.js` and maps to the muted dark greens/reds/yellows common in security tooling. High contrast ratios ensure readability under monitor-heavy SOC lighting conditions.

**Live chart updates:** `useScan` accepts an optional `onSuccess` callback. `Dashboard` passes `refresh` from `useHistory` as that callback. Each successful scan increments a `tick` counter in `useHistory`, triggering a re-fetch. This gives the pie chart and statistics table live updates without polling.

**Relative timestamps:** `ScanHistory` renders "just now", "2 min ago", "1 hr ago" rather than ISO timestamps. SOC analysts need triage speed; relative times communicate urgency faster than absolute values.

**Export:** `/api/export/csv` returns a streaming response with `Content-Disposition: attachment` so the browser triggers a file download directly. The CSV includes all scan fields and is suitable for SIEM ingestion.

---

## 8. Chrome Extension

### 8.1 Architecture (MV3)

The extension uses Manifest V3 with three components:

**`background.ts` (service worker):**  
Listens on `chrome.webNavigation.onCompleted` for main-frame navigations. On each navigation it sets a pending badge (`...`), calls the PhishGuard API, stores the result in `chrome.storage.local` keyed by `scan_{tabId}`, and updates the action badge text/color.

**`popup.tsx` (React):**  
Reads the stored result for the active tab on open. Shows URL, risk badge, score bar, top indicators, and a rescan button. The rescan button bypasses the extension's 60-second URL cache and calls the API directly.

**`content.ts` (content script):**  
Injected into every page. Reads `chrome.storage.local` for the current tab's result. If `level === 'malicious'`, injects a red dismissable banner at the top of the page warning the user.

### 8.2 Badge States

| Badge | Color | Meaning |
|---|---|---|
| `...` | Gray | Scan in progress |
| `OK` | Green | Safe (score < 0.30) |
| `!!` | Orange | Suspicious (0.30–0.65) |
| `BAD` | Red | Malicious (≥ 0.65) |

Badge text is ASCII-only (Chrome supports emoji in badge text but rendering is inconsistent across platforms).

### 8.3 Caching

Results are cached 60 seconds per URL in `chrome.storage.local`. This prevents the extension from re-calling the API on every sub-frame navigation (images, iframes, analytics tags) that fire `webNavigation.onCompleted` on the same tab. The popup's rescan button explicitly bypasses the cache when the analyst wants a fresh result.

---

## 9. Testing

### 9.1 Python Test Suite

The audit regression suite covers the URL extractor, decision engine, API/database paths, training source selection, synthetic provenance, and model feature compatibility. All 92 tests passed with `backend/.venv` and the Windows-compatible SQLAlchemy Python fallback.

### 9.2 Frontend Checks

This repository snapshot has no frontend component test cases; `frontend/src/App.test.tsx` is empty. The dashboard production build is the available automated frontend check.

### 9.3 What Is Not Tested

- Live CTI adapter HTTP calls (by design — these require API keys and are non-deterministic)
- Extension service worker (Chrome extension test infrastructure requires a Puppeteer/Playwright harness not yet wired)
- WHOIS timeout behavior (requires mock DNS infrastructure)

---

## 10. Security Considerations

### 10.1 API Security

- **Input validation:** `ScanRequest.url` is a string; the route trims it and checks for an HTTP/HTTPS prefix before normalization. Non-HTTP URLs are rejected with 422. It is not a Pydantic URL type validator.
- **CORS:** `CORS_ORIGINS` env var restricts cross-origin requests. Default allows only localhost dev origins.
- **No authentication on API:** Intended for internal SOC deployment behind a VPN/network perimeter. For public exposure, add JWT middleware via FastAPI's `Depends`.

### 10.2 Extension Security

- **Content Security Policy:** Extension manifest declares strict CSP; popup uses inline React without `unsafe-eval`.
- **Storage:** Scan results stored in `chrome.storage.local` (not `sync`) — results never leave the device.
- **Content script injection:** The warning banner uses `innerHTML` for static markup and interpolates only a numeric score. Replacing this with DOM construction would further reduce injection risk.

### 10.3 ML Model Security

- **Adversarial robustness:** Lexical features are not adversarially robust. A sufficiently sophisticated attacker can craft URLs that score low. CTI enrichment provides a second detection layer. For hardened deployments, consider adding adversarial training examples.
- **Model artifact:** `phishguard_model.joblib` is loaded at startup. The path is configurable via `ML_MODEL_PATH` env var. Ensure the artifact cannot be replaced by an untrusted process (treat it as configuration, not user data).

---

## 11. Deployment

### 11.1 Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./phishguard.db` | Swap to `postgresql+asyncpg://...` for production |
| `CTI_MOCK` | `true` | `false` enables live CTI adapters |
| `VIRUSTOTAL_API_KEY` | _(empty)_ | Required when `CTI_MOCK=false` |
| `ML_MODEL_PATH` | `ml/models/artifacts/phishguard_model.joblib` | Absolute or relative path |
| `CORS_ORIGINS` | `["http://localhost:5173"]` | JSON array of allowed origins |

### 11.2 Docker

`docker-compose.yml` builds and starts the backend (host port 8001) and frontend (port 5173) as separate services. The frontend container runs the Vite dev server; for production, replace with an Nginx container serving the `dist/` output of `npm run build`.

### 11.3 Production Checklist

- [ ] Set `DATABASE_URL` to PostgreSQL
- [ ] Set `CTI_MOCK=false` and provide `VIRUSTOTAL_API_KEY`
- [ ] Serve the frontend build via Nginx (not Vite dev server)
- [ ] Add JWT authentication to the FastAPI API
- [ ] Run `ml/train.py` on a real labeled URL dataset (`ml/data/raw/labeled_urls.csv`)
- [ ] Configure log aggregation (uvicorn access logs → SIEM)
- [ ] Set `CORS_ORIGINS` to the production dashboard URL

---

## 12. Future Work

### 12.1 Short Term

- **Independent real-data evaluation:** Collect and curate labeled URLs, train through the real-CSV path, audit duplicates and label quality, then report held-out results. Do not infer real-world performance from synthetic smoke-test scores.
- **Scan deduplication:** Cache recent scan results in Redis. If the same URL is scanned within 5 minutes, return the cached result without re-running CTI adapters.
- **Extension test harness:** Wire Playwright + Chrome extension testing for the popup and content script.

### 12.2 Medium Term

- **Alembic migrations:** Replace `metadata.create_all` with proper schema versioning for production.
- **Streaming API:** Use Server-Sent Events to push partial scan results to the dashboard as CTI adapters complete, reducing perceived latency.
- **Additional CTI sources:** Google Safe Browsing v4, AlienVault OTX, Shodan domain intel.
- **MITRE ATT&CK mapping:** Map detected indicators to ATT&CK techniques (T1566.002 for spearphishing links, T1036 for masquerading).

### 12.3 Long Term

- **Active URL scanning:** Add a headless browser (Playwright) scan stage that follows redirects and captures page screenshots for visual similarity comparison.
- **Feedback loop:** Allow SOC analysts to mark scan results as false positives/negatives. Route feedback back to a continuous training pipeline.
- **Multi-tenant API:** Organization-scoped scan history, analyst authentication, per-org API rate limits.

---

## 13. Conclusion

PhishGuard demonstrates a local-first prototype composed of a lexical ML classifier, async CTI enrichment, a REST API, and an analyst UI. The current active model is a synthetic development artifact, so this report makes no claim about real-world accuracy or production readiness. Live URLhaus and WHOIS lookups work locally; VirusTotal remains unconfigured without an API key.

The dashboard, local database workflow, backend launcher, and extension remain available. Production evaluation still requires a real labeled URL dataset, independent holdout testing, provider configuration, and deployment security work.
