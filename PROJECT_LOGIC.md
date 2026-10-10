# PhishGuard Project Logic

This document is the single source of truth for how PhishGuard is put together, how data moves through the system, and what each part is responsible for.

PhishGuard is a hybrid phishing detection platform. It combines:

- a URL feature extractor and ML classifier
- live or mocked CTI enrichment
- a deterministic decision layer
- a FastAPI backend with persistence
- a React SOC dashboard
- a Chrome extension that reuses the same backend API

The most important implementation rule is that training and inference must use the same URL feature order from `ml/features/extractor.py`.

## 1. System Overview

The repository is organized into a few clear layers:

- `backend/` contains the FastAPI app, routers, database layer, and scan orchestration.
- `ml/` contains feature extraction, dataset download, model training, and saved artifacts.
- `cti/` contains threat-intelligence adapters and CTI response types.
- `frontend/` contains the React dashboard used by analysts.
- `extension/` contains the Chrome MV3 extension.
- `shared/` contains cross-cutting constants and helper types.

The live request path is:

1. A URL is submitted from the dashboard, the extension, or a direct API call.
2. The backend validates and normalizes the URL.
3. The feature extractor computes 30 lexical and structural URL features.
4. The ML service loads the trained artifact and returns a phishing probability.
5. CTI adapters enrich the URL with VirusTotal, URLhaus, and WHOIS evidence.
6. The decision engine combines ML probability and CTI status into a final risk verdict.
7. The backend stores the scan result in the database.
8. The same result is returned to the caller and shown in the UI.

## 2. Backend Architecture

The FastAPI app is created in `backend/app/main.py`.

At startup it:

- initializes the database
- configures CORS from `settings.cors_origins_list`
- mounts these routers under `/api`:
  - `/health`
  - `/scan`
  - `/history`
  - `/export/{fmt}`

The backend uses async SQLAlchemy sessions. SQLite is the default local database, but the connection string can be switched to PostgreSQL through `DATABASE_URL` without changing code.

### Request Entry Point

The main scan endpoint is `POST /api/scan` in `backend/app/routers/scan.py`.

That route:

- trims the incoming URL
- rejects anything that does not begin with `http://` or `https://`
- forwards the sanitized request to `orchestrate_scan()`

This means the rest of the pipeline can assume a real URL parser and network-facing CTI adapters are being used.

## 3. Live Scan Workflow

The live scan workflow is implemented in `backend/app/services/scan_orchestrator.py`.

### Step 1: Normalize the URL

The request URL is normalized by `backend/app/services/url_normalizer.py` before any scoring happens.

This keeps the downstream feature extraction and CTI lookups aligned on the same canonical URL string.

### Step 2: Extract Features

`backend/app/services/feature_service.py` wraps `ml.features.extractor.URLFeatureExtractor`.

The extractor computes 30 features, including:

- URL length and domain length
- subdomain count
- HTTPS usage
- special character counts
- digit ratio
- Shannon entropy
- suspicious keyword count
- URL shortener detection
- risky TLD detection
- obfuscation markers
- brand impersonation hints

These features are purely lexical and structural. The model never trains on raw URLs directly.

### Step 3: Run ML Inference

`backend/app/services/ml_service.py` loads `ml/models/artifacts/phishguard_model.joblib` lazily and caches it in memory.

The current runtime behavior is:

- `predict()` uses the bundle's `base_model` and returns a phishing probability
- `decision_thresholds()` reads the thresholds stored in the bundle if present
- `combine_scores()` exists, but the live scan path does not currently use it

So the active scan path is base-model probability plus deterministic decision logic, not a fully learned fusion model at runtime.

### Step 4: Enrich with CTI

`backend/app/services/cti_service.py` runs CTI lookups in parallel.

The adapter plan is:

- `cti/mock_adapters.py` when `CTI_MOCK=true`
- `cti.urlhaus.URLhausAdapter` when live CTI is enabled
- `cti.whois_lookup.WHOISAdapter` when live CTI is enabled
- `cti.virustotal.VirusTotalAdapter` only if `VIRUSTOTAL_API_KEY` is present

If a provider is not configured, the system returns a structured `unknown` result instead of failing the whole scan.

### Step 5: Make the Decision

`backend/app/services/decision_engine.py` is the live verdict layer.

It maps the ML probability and CTI outcomes into:

- `risk_score`
- `verdict`
- `scan_mode`
- human-readable explanation text

Current decision behavior:

- low scores map to `no_threat_detected`
- intermediate scores map to `suspicious`
- live CTI hits can push a result to `malicious`
- `scan_mode` becomes `full`, `degraded`, `ml_only`, or `failed` depending on provider availability

The decision engine is conservative. If live CTI corroborates a detection, the score is pushed upward more aggressively than when only ML is available.

### Step 6: Build Evidence and Indicators

`scan_orchestrator.py` also builds the response payload:

- `ScanResult`
- `CTIResult`
- `ScanEvidence`
- `ThreatIndicator` entries

Important detail: indicators are explanatory. They help the UI show why something was flagged, but they are not the primary scoring mechanism.

### Step 7: Persist the Result

`backend/app/services/db_service.py` stores the final scan in the database.

The persisted row includes:

- scan ID
- URL
- final score
- verdict
- ML probability
- indicator JSON
- explanation JSON
- CTI JSON
- feature JSON
- source channel
- timestamp

The history endpoint reconstructs full `ScanResult` objects from those stored rows.

## 4. ML Training Workflow

The training entry point is `ml/train.py`.

### Dataset Selection

`python ml/train.py` requires `ml/data/raw/labeled_urls.csv`; a missing, unreadable, or unusable dataset is an error and never triggers synthetic fallback. Synthetic vectors are only selected with the explicit `--synthetic` development flag and write to separate model and metrics filenames.

### Real Dataset Path

`ml/data/download_dataset.py` builds the labeled CSV from public sources:

- PhishTank verified URLs
- Mitchell K phishing database
- Tranco top-1M legitimate URLs

The CSV schema is:

- `url`
- `label`

Where `label=1` means phishing and `label=0` means legitimate.

### Feature Consistency

The training pipeline extracts the same 30 URL features used at inference time. That is the key correctness guarantee in the ML stack.

### Model Design

`ml/models/trainer.py` builds:

- a `StandardScaler`
- a soft-voting ensemble of XGBoost and RandomForest
- a validation-derived threshold for the base-model probability used by inference

The training script then:

- splits the dataset into train, validation, and test sets
- trains the base model
- derives decision thresholds from validation base-model probabilities
- writes the artifact bundle to `ml/models/artifacts/phishguard_model.joblib`
- writes evaluation metrics to `ml/data/processed/metrics.json`

CTI is not used to fit or score the model holdout. The live decision engine combines the base-model probability with CTI results at request time.

The bundle and metrics record dataset kind, SHA-256, sample/class counts, feature order, threshold source, and evaluation eligibility. Synthetic smoke-test metrics are marked ineligible for final evaluation. Thresholds are derived from held-out base-model probabilities, matching the probability used by the live decision engine; mocked CTI values are not included in model evaluation.

### Synthetic Smoke Test

`python ml/train.py --synthetic` generates synthetic vectors that roughly match the expected feature distributions for legitimate and phishing URLs. It writes `phishguard_model.synthetic.joblib` and `synthetic_metrics.json`; it never overwrites the live model or `metrics.json`.

This is useful for bootstrapping only. Its holdout scores are not estimates of real-world performance.

The separate Kaggle feature-table experiment has 50 numeric columns, while live inference uses the 30 features in `FEATURE_ORDER`. It writes separate artifacts and is not compatible with the live URL inference endpoint.

## 5. API Surface

The backend exposes these core endpoints:

- `POST /api/scan`
- `GET /api/history`
- `GET /api/export/csv`
- `GET /api/export/json`
- `GET /api/health`

### Scan Response Shape

The response includes:

- `url`
- `score`
- `risk_score`
- `level`
- `verdict`
- `scan_mode`
- `ml_probability`
- `features`
- `cti`
- `evidence`
- `indicators`
- `explanation`
- `scanned_at`
- `source`

There are a couple of compatibility details worth knowing:

- `score` and `risk_score` are both present, and currently carry the same final value.
- `level` and `verdict` are both present for compatibility with older and newer callers.
- The `RiskLevel` enum includes both `safe` and `no_threat_detected`, but the live path primarily uses `no_threat_detected`.

## 6. Frontend Workflow

The React dashboard lives in `frontend/src/`.

`frontend/src/App.tsx` sets up the app shell and routes:

- Dashboard
- Scan
- History
- Reports

### Dashboard

`frontend/src/pages/Dashboard.tsx` loads recent scans from the backend and shows a compact summary of scan activity.

### Scan Page

`frontend/src/pages/ScanPage.tsx` submits a URL to `POST /api/scan` and renders:

- verdict
- risk score
- ML probability
- explanation text
- provider status
- indicators

### History Page

`frontend/src/pages/HistoryPage.tsx` fetches the last 50 scans from the backend and shows them in a table.

### Reports Page

`frontend/src/pages/ReportPage.tsx` links to the CSV and JSON export endpoints.

### Frontend API Layer

`frontend/src/api.ts` centralizes the HTTP calls to the backend and defines the `ScanResult` shape used by the UI.

## 7. Browser Extension Workflow

The extension provides another way to enter the same scan flow.

### Background Worker

`extension/src/background.ts` listens for top-level navigation events on `http(s)` URLs.

For each scannable page it:

- marks the tab as pending
- stores a pending scan state in `chrome.storage.local`
- calls the backend scan API
- updates the tab badge based on the verdict
- sends a notification for malicious URLs
- triggers the content script banner for malicious verdicts

### Popup

`extension/src/popup.tsx` reads the current tab state from storage and shows:

- verdict
- risk score
- ML probability
- indicator list
- explanation list

It also supports a manual rescan of the current tab.

### Content Script

`extension/src/content.ts` injects a dismissible warning banner only when a page is flagged as malicious.

### Extension API

`extension/src/api.ts` talks to the same backend scan endpoint and keeps a short per-URL cache so the extension does not hammer the API on every navigation.

## 8. Persistence And Data

The database layer is in `backend/app/db/database.py`, and the public persistence wrapper is `backend/app/services/db_service.py`.

The system currently uses a local SQLite database by default:

- `phishguard.db` for normal development
- `test_phishguard.db` for tests

Because the ORM layer is SQLAlchemy-based, PostgreSQL can be used by changing `DATABASE_URL`.

## 9. CTI Behavior

The CTI adapters are intentionally mixed-mode:

- mock adapters provide deterministic results for development and test runs
- live URLhaus and WHOIS enrichments are available without keys
- VirusTotal is optional and only runs when an API key is configured

The CTI response contract is defined in `cti/base.py`.

Each provider returns:

- `status`
- `hit`
- `score`
- `details`
- `error`
- `latency_ms`

This makes the scan response predictable even when a provider times out or is not configured.

## 10. Heuristics And Decision Rules

PhishGuard is not a pure black-box ML system. It uses several rule-based signals and helper lists:

- suspicious keywords
- high-risk TLDs
- URL shortener domains
- impersonated brand names
- obfuscation patterns

These heuristics are mainly used for feature extraction and explanation.

The live verdict still comes from the decision engine, which is why the product behaves like a hybrid detector rather than a single model.

There is also a legacy helper in `cti/risk_scorer.py`. It is useful as context, but the current live scan path uses `DecisionEngine` instead.

## 11. Operational Notes

- The backend loads the model lazily, so restart the API after retraining to ensure the new artifact is used.
- `CTI_MOCK=true` is the safest default for local development.
- `CORS_ORIGINS` can be supplied as a comma-separated list or a JSON array.
- If `VIRUSTOTAL_API_KEY` is missing, the system keeps scanning and marks that provider as unavailable.
- The feature order in `ml/features/extractor.py` must stay in sync with `shared/constants.py`.
- Changing feature order requires retraining the model.

## 12. End-To-End Summary

The full workflow is:

1. A user submits a URL from the dashboard, extension, or API.
2. The backend validates and normalizes the URL.
3. Thirty URL features are extracted.
4. The ML model returns a phishing probability.
5. CTI providers add external context.
6. The decision engine turns evidence into a risk score and verdict.
7. The result is saved to the database.
8. The UI and extension display the same scan record.

That is the project in one line: a hybrid phishing detection workflow with a shared backend, shared feature set, and multiple front ends.
