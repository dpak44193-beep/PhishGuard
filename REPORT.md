# PhishGuard — Technical Report

**Project:** ML-Powered Phishing URL Detection with Real-Time CTI Enrichment
**Audit date:** 2026-10-12
**Stack:** Python 3.12.13 · FastAPI · scikit-learn/XGBoost · React 18 · Chrome MV3

---

## 1. Executive Summary

PhishGuard is a local-first phishing URL scanner for SOC analyst workflows. It combines a 30-feature lexical URL model with separately reported URLhaus, WHOIS, and optional VirusTotal results. The documented UCI PhiUSIIL corpus has been prepared and audited offline, and the active scikit-learn model was trained and evaluated on a registrable-domain-grouped holdout. These are internal same-source results, not independent, time-based, or real-world performance claims. The newly trained artifact was kept separate from the pre-existing default model; the tested API used it via `ML_MODEL_PATH`.

The system has a FastAPI backend, React dashboard, Chrome MV3 extension, and standalone ML training pipeline. Local scan, history persistence, and live URLhaus/WHOIS integration were verified during this audit.

**Key results:**

| Metric | Value |
|---|---|
| Trained artifact | `base-model-v3`, saved separately under `ml/models/artifacts/real_data_grouped_run_20261012_final/` |
| Real URL dataset | 234,687 deduplicated, source-labeled URL records; UCI PhiUSIIL, CC BY 4.0 |
| Dataset classes | 134,849 legitimate (57.47%); 99,838 phishing (42.53%) |
| Split | 70/15/15 by registrable domain; no shared domains; no observation dates for time split |
| Held-out test | Accuracy 0.9905; precision 0.9844; recall 0.9935; F1 0.9889; PR-AUC 0.9983; ROC-AUC 0.9978 |
| 95% interval method | 500-resample bootstrap clustered by held-out registrable domain |
| Baseline | Majority-class accuracy 0.5732; phishing recall 0.0000 |
| Live local scan | API and dashboard returned and persisted the suspicious `example.com` result; root cause traced but not fixed |
| CTI during live test | Mock providers only; no external provider requests or paid API used |
| Independent/time-based performance | Not measured |

---

## 2. Problem Statement

Phishing URLs are the primary vector for credential theft and malware delivery. Traditional blocklist-based detection suffers from two fundamental limitations:

1. **Staleness** — a new phishing domain can be live for hours before any blocklist catches it.
2. **Coverage** — attackers continuously register new domains that have never appeared in a blocklist.

A lexical classifier operating on URL structure is intended to surface suspicious patterns without requiring prior URL reputation. Real zero-day detection and generalization remain unverified until independent real-world evaluation. CTI enrichment can contribute known-threat signals when a provider has matching intelligence; it does not validate the classifier's generalization.

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
2. `scan_orchestrator` computes the local ML prediction, then calls the CTI coordinator; CTI provider requests are gathered concurrently.
3. `ml_service` runs `URLFeatureExtractor.extract(url)` → 30 floats → model `.predict_proba()` → scalar ML probability.
4. `cti_service` independently calls configured VirusTotal v3, URLhaus, and WHOIS adapters in parallel; provider results retain explicit live/mock/not-configured/error/timeout status.
5. The decision engine uses the ML probability and qualifying live CTI matches under the configured thresholds. A no-match result is not evidence that a URL is safe.
6. Indicators are generated from ML predictions and provider-specific evidence/errors.
7. Result is persisted to the database and returned as a `ScanResult` JSON response.

### 3.3 Design Decisions

**Why async throughout?**
CTI API calls are I/O-bound and can block for 300–800ms each. Using `asyncio.gather` for CTI + ML concurrency reduces total latency from ~2s (serial) to ~0.4s (parallel). FastAPI's ASGI model makes this natural.

**Why SQLite for dev, PostgreSQL for prod?**
SQLAlchemy 2.x with `aiosqlite`/`asyncpg` backends lets us swap the database via a single `DATABASE_URL` env var. No raw SQL anywhere — all queries use ORM expressions. This eliminates dialect-specific bugs and keeps the test suite fast (in-memory SQLite, no containers needed).

**Why a non-network CTI placeholder?**
`CTI_MOCK=true` (the default) does not call providers and returns explicitly marked `mock` evidence with null hit/score values. It never synthesizes provider intelligence. Set `CTI_MOCK=false` for live URLhaus/WHOIS; VirusTotal is separately marked `not_configured` unless its API key is supplied. Test and model evaluation do not call CTI.

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

Every newly trained runtime bundle records a versioned 30-feature schema, exact feature names/order, preprocessing pipeline step names, UTC training time, source/dataset checksums, held-out test metrics, and evaluation metadata. Inference rejects a feature-order, schema, pipeline-step, or feature-count mismatch and returns model metadata separately from CTI provider evidence. Older compatible artifacts without full metadata are explicitly marked legacy/unverified.

**Training data strategy:** `python ml/data/download_dataset.py` prepares a local copy of the documented UCI dataset without making any requests to source URLs or rows in the dataset. It produces `ml/data/raw/labeled_urls.csv`, a checksum-bound provenance manifest, and `ml/data/processed/real_dataset_report.json`. Training requires a usable CSV; only a matching manifest with verified source and derived-file checksums and matching offline domain-extractor version can make the evaluation eligible for final claims. The training split groups by registrable domain to avoid domain leakage. Synthetic feature vectors are available only through `python ml/train.py --synthetic` and write separate, ineligible development artifacts.

### 4.2.1 Dataset Provenance and Permitted Use

The selected labeled corpus is the **PhiUSIIL Phishing URL (Website)** dataset from the UCI Machine Learning Repository, attributed to Arvind Prasad and Shalini Chandra. The source dataset is licensed **Creative Commons Attribution 4.0 International (CC BY 4.0)**, which permits sharing and adaptation with appropriate attribution. The prepared manifest records the source page, DOI, license, attribution, original and derived SHA-256 checksums, source label definitions, the exact source-row number for each retained URL, and the offline `tldextract` version used for domain grouping.

| Source | Label semantics and use | License / access | Decision |
|---|---|---|---|
| [UCI PhiUSIIL dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), [DOI](https://doi.org/10.1016/j.cose.2023.103545) | Academic labeled URL/website corpus. Source `0=phishing`, `1=legitimate`; preparation maps to PhishGuard `1=phishing`, `0=legitimate`. | CC BY 4.0; retain attribution and license. | **Used** as the primary labelled corpus. |
| [URLhaus Community API](https://urlhaus.abuse.ch/api/) | Abuse.ch threat-intelligence feed of malware-distribution URLs. Malware URL is not synonymous with phishing URL, and feed observation status is time-dependent. | Authenticated access; free access is subject to fair-use/query limits for non-profit use. Commercial/for-profit use may require a paid subscription and separate terms. | **Not merged into model labels.** Continue to use separately as runtime CTI enrichment. |
| [PhishTank](https://phishtank.org/terms.php) | Community-reviewed phishing submissions; data is explicitly not warranted as accurate. | Current service terms point to Cisco's EULA; permitted API/data use must be checked against current terms and rate limits before collection. | **Not used** in this prepared snapshot. |
| [Tranco](https://tranco-list.eu/) | Reproducible ranking assembled from popular-site lists; ranking is not proof that an individual URL is benign, current, or reachable. | Its methodology page provides archived list details, but the reviewed page did not establish a dataset license for this use; obtain and review applicable terms before redistribution. | **Not used as negative ground truth.** No URL paths are synthesized from ranked domains. |

UCI metadata lists the dataset creation year as **2024** and the repository's last update as **2024-05-12**. It describes the URLs analyzed as mostly latest but does not provide a precise collection window for individual rows; therefore the observation date is recorded as unknown, not invented. Dataset preparation date and file hashes are in the manifest.

### 4.2.2 Offline Dataset Inventory

| Inventory item | Source CSV | Prepared training CSV |
|---|---:|---:|
| Rows | 235,795 | 234,687 |
| Fields | 55 | 6 (`url`, `label`, `registrable_domain`, `source`, `source_label`, `source_row`) |
| Missing cells / URL / label | 0 / 0 / 0 | 0 in retained rows |
| Legitimate | 134,850 (`source_label=1`) | 134,849 (`label=0`, 57.47%) |
| Phishing | 100,945 (`source_label=0`) | 99,838 (`label=1`, 42.53%) |
| Invalid URLs / labels | 0 / 0 | 0 dropped by the current normalizer |
| Same-label duplicate URL rows removed | — | 1,106 |
| Conflicting normalized URL groups removed | — | 1 group (2 source rows) |
| Registrable domains | — | 197,708 groups |
| Domains represented in both labels | — | 105 |

Normalization lowercases scheme/host, converts internationalized hosts to IDNA, removes default ports, and adds a root slash when absent. URL paths and queries remain unchanged; fragments are retained in the recorded URL but ignored when identifying duplicate URL strings. Conflicting-label URL identities are removed rather than choosing one label. The source row number and original source label are retained for traceability. Registrable-domain groups use the locally bundled Public Suffix List snapshot (`tldextract` 5.4.0 here) with private suffix handling enabled; suffix data is not fetched and no DNS lookup is performed.

The local source CSV SHA-256 is `748ae7c7a677ac4ffc0eeefbee653dcef1d685b134ad2f5376596b92d79438ba`. The prepared CSV SHA-256 is `1db2f5ce060de7b073c96d942ff180423e16a01392240bf33e5ca29bb917b4af`. Both hashes and the complete machine-readable inventory are recorded in [`labeled_urls.manifest.json`](./ml/data/raw/labeled_urls.manifest.json) and [`real_dataset_report.json`](./ml/data/processed/real_dataset_report.json). These data files are local inputs/outputs and may be excluded from version control; regenerate them from the cited source as needed.

### 4.2.3 Data Leakage and Safety Controls

- Preparation performs string parsing only. It does not visit, resolve, crawl, or submit any sampled URL to an external service.
- Train/validation/test assignment uses registrable-domain groups rather than a random row split; the splitter rejects any cross-partition domain overlap and requires both labels in all partitions.
- The separate 50-numeric-feature UCI research experiment also deduplicates by normalized URL and uses registrable-domain groups; its feature schema is incompatible with the live 30-feature model and is explicitly research-only.
- Campaign IDs are not available in PhiUSIIL, so campaign-level leakage cannot be independently detected. Domain grouping is a proxy, not proof of campaign independence.
- 105 registrable domains have both source labels. These domains remain in a single partition; label coexistence is preserved as source data, not silently “corrected.”
- The class distribution is moderately imbalanced. Report per-class precision/recall and the confusion matrix alongside accuracy.
- Source labels are inherited annotations and are not independently re-verified. Dataset freshness, label drift, incomplete observation dates, source-selection bias, and offline PLS snapshot age limit generalization.

**Why not deep learning?** For tabular lexical features, gradient-boosted trees consistently outperform neural networks while being: (a) faster to train (seconds vs. minutes), (b) directly interpretable via feature importance, (c) deployable without a GPU, and (d) stable across the small feature count.

### 4.3 Evaluation Results

The active training pipeline completed successfully with the prepared real URL corpus and saved an isolated artifact at `ml/models/artifacts/real_data_grouped_run_20261012_final/`. Its bundle version is `base-model-v3`; its metadata records the training timestamp, UCI source/license and hashes, feature schema, pipeline steps, and held-out metrics. The 30-feature input contract was retained exactly. The model uses a scikit-learn pipeline with a training-fitted scaler and a soft-voting XGBoost/RandomForest classifier when XGBoost is installed; no feature selection is performed.

The split is 70% train, 15% validation, and 15% test, approximated by registrable-domain grouping. Running the splitter against the prepared corpus produced:

| Partition | Rows | Legitimate | Phishing | Registrable domains |
|---|---:|---:|---:|---:|
| Train | 164,281 (70.00%) | 94,459 | 69,822 | 138,563 |
| Validation | 35,203 (15.00%) | 20,211 | 14,992 | 29,631 |
| Test | 35,203 (15.00%) | 20,179 | 15,024 | 29,514 |

No registrable domain is shared across these partitions. The scikit-learn training pipeline fits the model and scaler on the train partition. On validation probabilities it selects the highest-recall threshold meeting 98% precision (falling back to maximum F1 if none meets the target), then evaluates the held-out test partition. The selected suspicious threshold is 0.1285 (safe threshold 0.0643). The test partition was evaluated once after threshold selection; it was not used for tuning. Intervals use 500 cluster-bootstrap resamples of test registrable domains, keeping all rows for a sampled domain together.

The required majority-class baseline predicts legitimate for every test row:

| Model | Threshold | Accuracy | Precision | Recall | F1 | False-positive rate | PR-AUC (average precision) | ROC-AUC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Majority-class baseline | 0.50 | 0.5732 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.4268 | 0.5000 |
| Active scikit-learn model artifact (`base-model-v3`) | 0.1285 | 0.9905 | 0.9844 | 0.9935 | 0.9889 | 0.0117 | 0.9983 | 0.9978 |
| Native XGBoost research alternative (separate run) | 0.4826 | 0.9961 | 0.9992 | 0.9917 | 0.9954 | 0.000595 | 0.9983 | 0.9978 |

At the active model's selected threshold, the test confusion matrix (actual rows / predicted columns; label order legitimate, phishing) is:

|  | Predicted legitimate | Predicted phishing |
|---|---:|---:|
| Actual legitimate | 19,942 | 237 |
| Actual phishing | 98 | 14,926 |

Test class distribution is 20,179 legitimate and 15,024 phishing.

| Metric | Active model 95% domain-cluster bootstrap interval |
|---|---:|
| Accuracy | [0.98927, 0.99165] |
| Precision | [0.98101, 0.98750] |
| Recall | [0.99179, 0.99494] |
| F1 | [0.98668, 0.99088] |
| False-positive rate | [0.01023, 0.01317] |
| PR-AUC (average precision) | [0.99758, 0.99879] |
| ROC-AUC | [0.99700, 0.99834] |

The majority baseline predicts legitimate for every test row: confusion matrix `[[20179, 0], [15024, 0]]`; accuracy 0.5732, precision/recall/F1/FPR 0, PR-AUC 0.4268, ROC-AUC 0.5000. Its cluster-bootstrap accuracy interval is [0.53175, 0.61206], and PR-AUC interval is [0.38794, 0.46825].

**Interpretation and limitations:** These are internal domain-grouped holdout results from one UCI-derived corpus, not an independent, future-time benchmark or proven real-world performance. UCI provides no per-observation collection dates or precise collection window, so a time split cannot be constructed. Domains are isolated across partitions, but campaign overlap cannot be independently measured; labels are inherited and unverified. The reserved `https://example.com/` false positive is now traced to a feature-signature collision: its 30-feature vector exactly matches 46 phishing-labeled corpus rows and no legitimate-labeled rows, while the exact host is absent. Feature ordering and the serialized scaler/model pipeline match between training and inference. The model still returns ML probability 0.8786 and final score 0.7357. This is a demonstrated representation/training-corpus limitation, not a resolved issue; the artifact is not promoted. External temporal/campaign validation and independently verified labels remain required before operational use.

### 4.3.1 Reserved-domain false-positive investigation

For `https://example.com/`, the only nonzero vector values are `url_length=20`, `domain_length=11`, `uses_https=1`, `dot_count=1`, and `entropy=3.0958`; domain spelling/identity is not represented. The artifact schema is the same ordered 30-feature `phishguard-url-lexical-30-v1` contract used by the extractor, with serialized preprocessing steps `StandardScaler` then `VotingClassifier`; direct inference and the running API agree. The voting components returned XGBoost `0.998154`, RandomForest `0.759091`, and ensemble `0.878623`. XGBoost's largest per-example contribution is `dot_count` at `+10.037066` log-odds.

The decision engine maps this score with suspicious threshold `0.1285` to `0.4 + ((0.8786 - 0.1285) / (1 - 0.1285)) * 0.39 = 0.7357`. All CTI providers were mock-only, so the score came from ML and the existing map. The current source-corpus grouped holdout still reproduces 237 legitimate false positives from 20,179 (`0.01174488`); that aggregate rate does not capture an unseen benign feature signature.

`tests/test_model_regression.py` now validates schema/preprocessing and runtime probability parity, this vector collision, the legitimate holdout false-positive count, and legitimate reference URL behavior. The expected safe-threshold checks for `example.com` and the IANA reserved-domain URL remain strict expected failures; the Wikipedia reference case passes. No threshold, model artifact, database, or production configuration was changed. Details and reproduction commands are in [runtime-validation-report.md](./runtime-validation-report.md).

Machine-readable active-model results: [`metrics.json`](./ml/models/artifacts/real_data_grouped_run_20261012_final/metrics.json). The separate native XGBoost alternative remains in [`native_xgboost_experiment.json`](./ml/data/processed/native_xgboost_experiment.json) and is not the runtime model. The legacy synthetic 99.94% figure remains a development-only smoke-test result and is not cited as phishing detection performance.

### 4.4 Inference Latency

No repeatable latency benchmark is checked into the repository. End-to-end scan latency depends on live CTI network requests and should be benchmarked separately from local model inference.

---

## 5. CTI Enrichment Pipeline

### 5.1 Adapter Design

All CTI adapters extend `BaseCTIAdapter` (defined in `cti/base.py`). Each provider response keeps status, nullable hit/score, details, error, and latency distinct:

```python
class BaseCTIAdapter:
    async def lookup(self, url: str) -> CTIResponse: ...
```

Provider statuses are `live`, `mock`, `not_configured`, `unknown`, `error`, and `timeout`. These are not interchangeable with a provider no-match. `CTI_MOCK=true` returns placeholder statuses with null hit/score and does not call an external provider. The result object separates `evidence.ml` from `evidence.cti`; ML evaluation is offline and does not include CTI.

### 5.2 VirusTotal v3 Adapter

- Encodes URL to base64-without-padding and queries `/urls/{id}`
- Maps `last_analysis_stats.malicious / total_engines` to a 0–1 score
- Handles 404 as no stored report; does not submit the URL for analysis or claim that it is safe
- When `VIRUSTOTAL_API_KEY` is empty and `CTI_MOCK=false`, status is `not_configured`, with no fabricated hit/score
- Rate-limited to 4 req/min on free tier; production deployments should use a paid key

### 5.3 URLhaus Adapter

- POST to `https://urlhaus-api.abuse.ch/v1/url/`
- Maps `query_status == "is_db"` to a live match; `no_results` is only a feed non-match, not a safe verdict
- No API key required by this adapter

### 5.4 WHOIS Adapter

- Uses `python-whois` to resolve domain registration metadata
- Converts domain age (creation_date → days since registration) to a categorical risk score: under 30 days scores 1.0, under 180 days scores 0.5, under 365 days scores 0.2
- New domains are a strong phishing indicator — attackers register disposable domains hours before a campaign

### 5.5 Decision and Evidence Separation

The current system does **not** compute a weighted ML+CTI probability or train a CTI combiner. The API returns the model probability and each provider's result separately. The deterministic decision engine may elevate a verdict for a live URLhaus/VirusTotal match or treat recent WHOIS registration as a suspicious signal; provider errors and unconfigured status remain explicit. `full` means all configured providers completed live lookups; `degraded` means some configured providers were mock/unavailable; `ml_only` means no CTI provider was configured or all configured lookups were unavailable. A missing match is never described as proof of safety.

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

The complete Python suite exited 0 with **121 passed, 2 xfailed** after adding `tests/test_model_regression.py`; the strict expected failures are the unresolved safe-threshold assertions for `example.com` and the IANA reserved-domain reference. `compileall` passed for `backend`, `cti`, `ml`, and `tests`. The 234,687-row dataset was trained and evaluated with the domain-grouped split described above. API tests cover feature/prediction contracts, provider states/failures, response metadata, errors, and persistence.

### 9.2 Frontend Checks

The dashboard production build, Chrome extension production build, and strict extension TypeScript check passed. A live dashboard scan and history readback succeeded through the backend on port 8001. The extension popup was loaded in isolated Playwright Chromium with the unpacked MV3 build and its manual local-only URL-string scan completed; the input was not opened or sent to a provider. The optional-permission online-backend flow was attempted but could not pass Chrome's user-approval prompt.

### 9.3 What Is Not Tested

- Live CTI adapter HTTP calls (not used in the final runtime test; CTI was mocked)
- Extension optional-host-permission flow to the backend
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
- [x] Prepare and inventory the documented UCI labeled URL dataset offline
- [x] Train the real-data artifact and review its registrable-domain-grouped holdout metrics
- [ ] Resolve the known legitimate-reference false positives and pass the strict regression checks using independently verified labeled data
- [ ] Evaluate against an independent, time-based or campaign-aware dataset before deployment
- [ ] Set `ML_MODEL_PATH` to a reviewed, independently evaluated artifact only; the pre-existing default artifact was intentionally left unchanged
- [ ] Configure log aggregation (uvicorn access logs → SIEM)
- [ ] Set `CORS_ORIGINS` to the production dashboard URL

---

## 12. Future Work

### 12.1 Short Term

- **False-positive remediation:** The root cause of the reserved-domain false positives is known (feature collision with phishing-only training records), but the issue remains unresolved; the strict expected-failure regression cases must pass with a reviewed model before deployment.
- **External evaluation:** Validate on a separate, time-based or independently sourced holdout before making external performance claims.
- **Scan deduplication:** Cache recent scan results in Redis. If the same URL is scanned within 5 minutes, return the cached result without re-running CTI adapters.
- **Extension backend test:** Extend the current isolated Chromium popup test to cover the user-granted optional-host permission and backend connection.

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

PhishGuard now has a reproducible, metadata-bearing real-data model artifact and internal domain-grouped evaluation on the documented UCI PhiUSIIL corpus. The artifact uses the unchanged 30-feature contract and was successfully loaded by the API; scan responses carry its version, data provenance, feature schema, and test metrics. CTI mock mode returns null placeholder evidence and performs no provider requests. The canonical default model artifact was left untouched, so production configuration must explicitly select the reviewed artifact.

The dashboard, local database workflow, backend on port 8001, and extension popup were exercised locally. The `example.com` smoke string still produces a suspicious output; its feature-collision cause is demonstrated, but there is no safe fix supported by this corpus alone. Two regression expectations remain xfailed. The data has no time labels or campaign IDs. This work does not establish real-world accuracy or production readiness, and the isolated artifact is not promoted. See the reproducible [runtime-validation-report.md](./runtime-validation-report.md) for commands, live checks, and remaining blockers.
