**# PhishGuard**

****ML-powered phishing URL detection with real-time CTI enrichment, FastAPI backend, SOC dashboard, and Chrome extension.****

PhishGuard is a full-stack security tool built for SOC analysts. It returns a 30-feature ML phishing probability alongside separate, status-labelled VirusTotal, URLhaus, and WHOIS evidence. CTI lookups can corroborate a detection; a provider no-match is not proof that a URL is safe.

---

## Architecture Overview**

```
┌─────────────────────────────────────────────────────────────────┐
│                         PhishGuard                              │
│                                                                 │
│  Chrome Extension  ──►  FastAPI Backend  ──►  SQLite / PgSQL   │
│  React Dashboard   ──►  /api/scan        ──►  scan_orchestrator │
│                              │                      │           │
│                    ┌─────────┴──────┐    ┌──────────┴────────┐ │
│                    │  ML Service    │    │   CTI Service     │ │
│                    │  RF / opt. XGB │    │  VT / URLhaus /   │ │
│                    │  30 features   │    │  WHOIS adapters   │ │
│                    └────────────────┘    └───────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

****Scan outcome:**** the ML probability and provider results are returned as separate evidence. The final verdict applies the decision policy to the ML thresholds and qualifying live CTI signals; `no_threat_detected` does not assert that the URL is safe.

---

## Repository Layout**

```
phishguard/
├── backend/            FastAPI service
│   └── app/
│       ├── main.py
│       ├── config.py
│       ├── db/         SQLAlchemy engine + ORM models
│       ├── models/     Pydantic schemas
│       ├── routers/    scan, history, export, health
│       └── services/   scan_orchestrator, ml_service, cti_service,
│                       feature_service, db_service
├── ml/
│   ├── features/       extractor.py (30 features), obfuscation.py,
│   │                   typosquatting.py
│   ├── models/         trainer.py, evaluator.py, artifacts/
│   ├── data/           raw/, processed/metrics.json
│   └── train.py        training pipeline entry point
├── cti/
│   ├── base.py         BaseCTIAdapter + CTIResponse
│   ├── virustotal.py   VirusTotal v3 adapter
│   ├── urlhaus.py      abuse.ch URLhaus adapter
│   ├── whois_lookup.py python-whois adapter
│   ├── mock_adapters.py dev/test mock layer
│   └── risk_scorer.py  legacy scoring utility (not used by scan orchestration)
├── frontend/           React 18 + Vite + Tailwind SOC dashboard
│   └── src/
│       ├── pages/      Dashboard, HistoryPage, ReportPage
│       ├── components/ ScanForm, RiskBadge, ThreatDetails,
│       │               ScanHistory, RiskDistChart, ExportButton
│       ├── hooks/      useScan, useHistory
│       └── api/        axios client
├── extension/          Chrome MV3 extension
│   └── src/
│       ├── background.ts  webNavigation listener + badge
│       ├── popup.tsx      React popup UI
│       ├── content.ts     in-page malicious banner
│       └── api.ts         fetch wrapper with 60s cache
├── tests/              Python regression suite
├── shared/             Python constants + dataclass types
├── .env.example
├── docker-compose.yml
├── pytest.ini
└── REPORT.md
```

---

## Quick Start

### Prerequisites

| Tool | Version | macOS | Windows |
|---|---|---|---|
| Python | 3.11+ | `brew install python@3.11` | Install Python 3.11+ and add it to PATH |
| Node.js | 20+ | `brew install node` | Install Node.js 20+ |
| Git | Recent | `brew install git` | Install Git for Windows |
| libomp | ML dependency | `brew install libomp` | Usually not required |
| Docker | Optional | Docker Desktop | Docker Desktop |

> **Windows:** The commands below use PowerShell. Command Prompt equivalents are provided where needed.
>
> **macOS/Linux:** Use the standard Terminal (`zsh`/`bash`).

---

### 1. Clone the repository

**macOS / Linux**

```bash
git clone <YOUR-REPOSITORY-URL>
cd phishguard
```

**Windows PowerShell**

```powershell
git clone <YOUR-REPOSITORY-URL>
cd phishguard
```

---

### 2. Create virtual environment and install dependencies

**macOS / Linux**

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r backend/requirements.txt -r ml/requirements.txt
```

**Windows PowerShell**

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r backend/requirements.txt -r ml/requirements.txt
```

**Windows Command Prompt**

```cmd
py -3.11 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r backend/requirements.txt -r ml/requirements.txt
```

If PowerShell blocks virtual-environment activation:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then run:

```powershell
.venv\Scripts\Activate.ps1
```

---

### 3. Train the ML model

Make sure the virtual environment is activated.

**macOS / Linux / Windows**

```bash
# Download the source CSV from UCI to the repository root first.
python ml/data/download_dataset.py
python ml/train.py
```

The preparation command reads the local `PhiUSIIL_Phishing_URL_Dataset.csv`; it does not download, resolve, or visit any sample URL. The source is the UCI PhiUSIIL dataset, licensed CC BY 4.0. Its original labels are `0=phishing` and `1=legitimate`; the preparation step maps these to the model's `1=phishing` and `0=legitimate` convention. It writes the URL-only data to `ml/data/raw/labeled_urls.csv` and a provenance/statistics manifest beside it.

Default training requires the prepared CSV. A source-checksum-matched manifest at `ml/data/raw/labeled_urls.manifest.json`, a verified derived-file checksum, and the recorded offline domain-extractor version are required before metrics can be marked eligible for final evaluation claims.
Without that real labeled CSV, training stops with an error and does not replace the current model or metrics. Synthetic vectors are available only as an explicit development smoke test:

```bash
python ml/train.py --synthetic
```

That command writes `phishguard_model.synthetic.joblib` and `synthetic_metrics.json`; those results are marked ineligible for final evaluation and do not overwrite the live model or authoritative `metrics.json`.

Real-data training normalizes and deduplicates URL strings and splits by registrable domain into train, validation, and test sets. The manifest checksum is verified before training. Real-data training generates:

```text
ml/models/artifacts/phishguard_model.joblib
```

New model bundles record training time, data-source attribution/checksums, artifact version, the versioned 30-feature schema and exact order, fitted pipeline steps, and held-out test metrics. The backend checks schema/order, model feature count, and recorded preprocessing steps before accepting a bundle; scans return the ML metadata separately from provider evidence.

XGBoost is optional. The default requirements support local training with RandomForest alone; install `xgboost` separately to enable the soft-voting ensemble.

and prints the evaluation metrics.

When scikit-learn is unavailable but XGBoost's native package works, the separate research evaluation can be run with:

```bash
python ml/evaluate_native_xgboost.py
```

It verifies source and derived checksums, retains the 30-feature contract, uses a registrable-domain-disjoint train/validation/test split, tunes the XGBoost threshold on validation only, and reports a majority-class baseline plus grouped-bootstrap confidence intervals. Its JSON report and model are stored as `ml/data/processed/native_xgboost_experiment.json` and `ml/models/artifacts/phishguard_xgboost_native.research.json`; the artifact embeds its training/source/schema/test-metric metadata. This experiment does not train or replace the active RandomForest/XGBoost soft-voting model and is not deployment eligible.

To use another labeled URL dataset, prepare a matching `labeled_urls.manifest.json` recording the source, collection date, label definitions, license, and attribution. Without a documented, checksum-matched manifest, training may be used for experimentation but is explicitly ineligible for final evaluation claims. Place the CSV at:

```text
ml/data/raw/labeled_urls.csv
```

with the following columns:

```text
url,label
```

where:

- `1` = phishing
- `0` = legitimate

Do not create URLs by appending guessed paths to domains or treat popularity rankings as verified benign URLs. Keep source snapshots and collection dates; labels from feeds are source annotations, not ground truth independently confirmed by PhishGuard.

---

### 4. Configure environment

**macOS / Linux**

```bash
cp .env.example .env
```

**Windows PowerShell**

```powershell
Copy-Item .env.example .env
```

**Windows Command Prompt**

```cmd
copy .env.example .env
```

Key settings in `.env`:

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | SQLite database at the repository root (`phishguard.db`) | Swap to `postgresql+asyncpg://...` for production |
| `CTI_MOCK` | `true` | `true` makes no provider calls and returns null mock evidence; `false` enables live URLhaus/WHOIS and optional VirusTotal |
| `VIRUSTOTAL_API_KEY` | *(empty)* | Optional VirusTotal API key; absent key is explicitly not configured |
| `ML_MODEL_PATH` | `ml/models/artifacts/phishguard_model.joblib` | Path to trained model |
| `CORS_ORIGINS` | `["http://localhost:5173","http://localhost:3000"]` | JSON array |

---

### 5. Start the backend

Keep the virtual environment activated.

**macOS / Linux**

```bash
PYTHONPATH=$(pwd) uvicorn app.main:app --app-dir backend/ --host 0.0.0.0 --port 8001
```

**Windows PowerShell**

```powershell
python backend/run_local.py
```

**Windows Command Prompt**

```cmd
python backend\run_local.py
```

Interactive API documentation:

**http://localhost:8001/docs**

---

### 6. Start the dashboard

Open a **new terminal** and leave the backend running.

**macOS / Linux / Windows**

```bash
cd frontend
npm install
npm run dev
```

Dashboard:

**http://localhost:5173**

The Vite development server proxies `/api/*` to:

**http://localhost:8001**

---

### 7. Build and load the Chrome extension

Open another terminal.

**macOS / Linux / Windows**

```bash
cd extension
npm install
npm run build
```

Then:

1. Open Chrome.
2. Go to `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked**.
5. Select the `extension/dist/` directory.

Without a configured backend, the extension analyzes URL patterns locally. When a backend is configured, completed page navigations and manually submitted URLs are sent to that backend for ML and CTI analysis; suspicious URLs are analyzed as strings and are never opened by the scanner. Per-tab results are removed when a tab closes; recent scan history is stored on the device, limited to 100 entries, and expires after 24 hours. Use **Clear** in the popup to remove it sooner.

For online ML and threat-intelligence results, train the model with `python ml/train.py`, deploy the FastAPI backend at a publicly reachable HTTPS URL, and set `CTI_MOCK=false` plus provider keys in the backend environment (never in the extension). Enter the backend base URL ending in `/api` in the popup and select **Connect**; Chrome asks permission for that backend origin. Without a deployed backend, scans use local URL-pattern checks only and are not a substitute for a reputation-service verdict.

The extension badge updates automatically on page navigation:

| Badge | Meaning |
|---|---|
| `...` | Scanning |
| `NTH` | No threat detected (not a safety guarantee) |
| `!!` | Suspicious |
| `BAD` | Malicious |

---

### Docker (full stack)

Make sure Docker Desktop is installed and running.

**macOS / Windows / Linux**

```bash
docker compose up --build
```

If your Docker installation uses the legacy Compose command:

```bash
docker-compose up --build
```

---

## API Reference**

### POST `/api/scan`**

```json
{
  "url": "https://paypa1-secure-login.xyz/account/verify",
  "source": "dashboard"
}
```

Response:

```json
{
  "id": "c4a8e25c-...",
  "url": "https://paypa1-secure-login.xyz/account/verify",
  "score": 0.4151,
  "level": "suspicious",
  "ml_probability": 0.9858,
  "features": { "url_length": 47, "tld_risk": 1.0, "suspicious_keywords": 3, *...* },
  "cti": {
    "virustotal": { "malicious_count": 5, "total_engines": 72 },
    "urlhaus": { "query_status": "no_results" },
    "whois": { "domain_age_days": 12 }
  },
  "indicators": [
    { "type": "ml_high_confidence", "severity": "high", "description": "ML classifier: 98.6% phishing probability", "source": "ml" },
    { "type": "high_risk_tld", "severity": "medium", "description": "URL uses a high-risk top-level domain", "source": "feature" }
  ],
  "explanation": ["ML classifier: 98.6% phishing probability", "VirusTotal: 5/72 engines flagged as malicious"],
  "scanned_at": "2026-05-18T06:18:57Z",
  "source": "dashboard"
}
```

### GET `/api/history?limit=50&offset=0`**

Returns a paginated list of `ScanResult` objects (most recent first).

### GET `/api/export/csv` · `/api/export/json`**

Downloads all scan records as CSV or JSON. Attach to a report or pipe into a SIEM.

### GET `/api/health`**

```json
{ "status": "ok", "timestamp": "2026-05-18T06:32:33Z" }
```

---

## The 30 URL Features**

The feature extractor (`ml/features/extractor.py`) computes these for every URL at inference time. The same features are used during training, ensuring no feature mismatch.

| # | Feature | Description |
|---|---|---|
| 1 | `url_length` | Total character count |
| 2 | `domain_length` | Length of registered domain |
| 3 | `subdomain_count` | Number of subdomains |
| 4 | `has_ip` | True if domain is a raw IP address |
| 5 | `uses_https` | True if scheme is HTTPS |
| 6 | `dot_count` | Dots in full URL |
| 7 | `hyphen_count` | Hyphens in domain |
| 8 | `at_sign_count` | @ characters (misdirection signal) |
| 9 | `special_char_count` | Sum of @, ?, %, +, = |
| 10 | `digit_ratio` | Fraction of domain chars that are digits |
| 11 | `entropy` | Shannon entropy of domain |
| 12 | `suspicious_keywords` | Count of phishing keywords (login, verify, secure…) |
| 13 | `is_url_shortener` | Domain is a known URL shortener |
| 14 | `tld_risk` | 1.0 if TLD in high-risk set (.xyz, .tk, .ml…) |
| 15 | `path_depth` | Number of path segments |
| 16 | `query_param_count` | Number of query parameters |
| 17 | `has_encoded_chars` | % encoding present |
| 18 | `double_slash_in_path` | // in path (redirect trick) |
| 19 | `has_port` | Non-standard port specified |
| 20 | `is_punycode` | xn-- IDN homograph |
| 21 | `tilde_in_path` | ~ in path |
| 22 | `hex_in_domain` | 0x… hex encoding in domain |
| 23 | `redirect_double_slash` | Multiple // in URL |
| 24 | `domain_digit_count` | Raw digit count in domain |
| 25 | `url_shortener_flag` | Integer version of is_url_shortener |
| 26 | `brand_count` | Known brand names in domain (paypal, apple…) |
| 27 | `num_dots_in_path` | Dots in path segment |
| 28 | `query_length` | Raw length of query string |
| 29 | `fragment_present` | # fragment present |
| 30 | `multi_subdomain` | 1 if more than 3 domain parts |

---

## ML Model**

****Classifier:**** When XGBoost is installed, a soft-voting classifier combines XGBoost (300 estimators, depth 6) and RandomForest (200 estimators, depth 10). Without XGBoost, training uses RandomForest alone. Both run in a `StandardScaler` pipeline.

****Training data:**** `python ml/train.py` uses the prepared labeled raw URLs only. To preserve the existing default artifact, train into a new, non-existing directory:

```powershell
.\backend\.venv\Scripts\python.exe ml\train.py --output-dir ml\models\artifacts\real_data_grouped_run_reproduction
```

The checked-in evaluation run is `ml/models/artifacts/real_data_grouped_run_20261012_final/` (`base-model-v3`). It used 234,687 UCI PhiUSIIL-derived observations and a 70/15/15 registrable-domain-grouped split; held-out accuracy was 0.9905, PR-AUC 0.9983, and ROC-AUC 0.9978. These are internal same-source metrics, not time-based or real-world accuracy. The run includes a 500-resample domain-cluster bootstrap. Training refuses to overwrite an existing `--output-dir`; the default canonical artifact remains unchanged. `python ml/train.py --synthetic` is a separate development smoke test, never real observations.

To run inference with the evaluated artifact, explicitly set `ML_MODEL_PATH` to its `phishguard_model.joblib` path. The scan response includes the artifact version, training timestamp, source/license and hashes, feature schema, pipeline, and test metrics.

The UCI feature-table experiment in `ml/train_kaggle_dataset.py` writes a separate `phiusiil_feature_research_model.joblib` and `phiusiil_feature_metrics.json`. It deduplicates by normalized URL and groups its holdout by registrable domain, but its 50 numeric inputs do not match the live scanner's 30 URL features, so it is research-only and cannot be loaded as the live URL model.

The final live smoke input `https://example.com/` is still classified as suspicious by the trained artifact (ML probability 0.8786). Investigation traced this to a feature collision: its 30-value vector exactly matches 46 phishing-labeled training rows and no legitimate-labeled rows; no feature-order or preprocessing mismatch was found. The strict regression expectations for this and the IANA reserved-domain reference remain xfailed. This is unresolved and blocks promotion; do not interpret same-source holdout results as real-world performance. See [`REPORT.md`](./REPORT.md) and [`runtime-validation-report.md`](./runtime-validation-report.md) for root-cause evidence, metrics, limitations, tests, and reproduction steps.

---

## CTI Adapters**

| Adapter | Source | API key needed? |
|---|---|---|
| `VirusTotalAdapter` | VirusTotal v3 | Yes (free tier available) |
| `URLhausAdapter` | abuse.ch URLhaus | No |
| `WHOISAdapter` | python-whois | No |
| `Mock*Adapter` | Deterministic dev stubs | No |

Set `CTI_MOCK=false` in `.env` for live URLhaus/WHOIS lookups. VirusTotal is optional; set `VIRUSTOTAL_API_KEY` to enable it. Missing API keys are reported as not configured, not as a provider no-match.

---

## Switching to PostgreSQL**

Change one line in `.env`:

```
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/phishguard
```

The ORM layer is fully database-agnostic (SQLAlchemy 2.x, no raw SQL). No code changes required.

---

## Running Tests

### Backend

**macOS / Linux**

```bash
source .venv/bin/activate
pytest -v
```

**Windows PowerShell**

```powershell
.venv\Scripts\Activate.ps1
pytest -v
```

**Windows Command Prompt**

```cmd
.venv\Scripts\activate.bat
pytest -v
```

### Frontend

**macOS / Linux / Windows**

```bash
cd frontend
npm run test -- --run
```

Test coverage:

| Suite | Tests | Scope |
|---|---:|---|
| `test_feature_extractor.py` | 31 | All 30 features, vector shape, edge cases |
| `test_risk_scorer.py` | 19 | Decision thresholds, provider-status behavior, and safety explanations |
| `test_signals.py` | 20 | Obfuscation, URL decoding, Levenshtein, typosquatting |
| `test_api.py` | 13 | All endpoints (health, scan, history, export, 422 validation) |
| `RiskBadge.test.tsx` | 10 | All 4 risk levels, score display, Tailwind classes |
| `ScanHistory.test.tsx` | 9 | Loading/empty states, rows, badges, timestamps |

---

## Development Notes**

- ****Feature source of truth:**** `ml/features/extractor.py:FEATURE_ORDER` — never change the order without retraining the model.
- ****All DB access**** routes through `backend/app/services/db_service.py`. No dialect-specific SQL anywhere.
- ****Retrain**** the model after changing `FEATURE_ORDER`: `python3 ml/train.py`
- ****Extension cache**** is 60 seconds per URL to avoid hammering the API on every sub-frame navigation.
- ****CTI_MOCK=true**** (default) — no provider calls; returns explicit mock statuses and null hit/score values rather than fabricated provider results.

---

## License**

MIT
