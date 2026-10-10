# PhishGuard Project Audit

**Audit date:** 2026-10-10
**Overall result:** Local scan workflow verified; model is development-only pending real labeled URL data and independent evaluation.

## Scope and Outcome

Inspected the 30-feature URL extractor, dataset loaders, trainer, evaluator, active model artifact, inference service, scan orchestration, API routes, SQLite schema, and existing Python tests.

The silent synthetic fallback is removed. Default training now requires a usable labeled raw-URL CSV. Synthetic data requires `--synthetic`, writes separate artifacts and metrics, and is marked ineligible for final evaluation. Existing local scanning, dashboard proxy, SQLite storage, and backend startup remain operational.

## Feature Contract

`ml/features/extractor.py` defines the inference/training order:

```text
url_length, domain_length, subdomain_count, has_ip, uses_https,
dot_count, hyphen_count, at_sign_count, special_char_count, digit_ratio,
entropy, suspicious_keywords, is_url_shortener, tld_risk, path_depth,
query_param_count, has_encoded_chars, double_slash_in_path, has_port,
is_punycode, tilde_in_path, hex_in_domain, redirect_double_slash,
domain_digit_count, url_shortener_flag, brand_count, num_dots_in_path,
query_length, fragment_present, multi_subdomain
```

The extractor and tests confirm a 30-element float vector. New model bundles record this order, and the inference loader rejects a mismatched order or feature count.

## Findings and Fixes

1. **Synthetic data previously entered the default training/evaluation path.** `ml/train.py` generated 12,000 synthetic feature vectors if the CSV was missing, malformed, or unusable, then overwrote `phishguard_model.joblib` and `metrics.json`. Default training now stops with an actionable error. `python ml/train.py --synthetic` is opt-in and writes `phishguard_model.synthetic.joblib` plus `synthetic_metrics.json`, both marked `final_evaluation_eligible: false`.

2. **The legacy 99.94% accuracy was synthetic.** The existing metric file's bias audit uses the `.example` TLD, and the model was trained on generated feature distributions. The active model bundle and `metrics.json` now identify synthetic provenance and ineligibility. Do not interpret these scores as real-world phishing detection performance.

3. **Threshold and evaluation probabilities previously diverged from inference.** The trainer selected thresholds and reported scores from an ML-plus-mock-CTI logistic combiner, while `scan_orchestrator.py` passed only raw ML probability to `DecisionEngine`. Training now selects thresholds and reports holdout metrics from the same base-model probability used by inference; synthetic/mock CTI values are excluded from those metrics.

4. **The separate Kaggle feature table is not the live input schema.** `PhiUSIIL_Phishing_URL_Dataset.csv` has 50 numeric feature columns excluding the label; live inference consumes the 30 URL-derived features above. The Kaggle script retains a separate research artifact and marks whether it is compatible with live inference. The loader rejects models with an incompatible feature count.

5. **Generic evaluation lacked dataset provenance.** `ml/models/evaluator.py` now requires explicit data provenance and rejects synthetic datasets. Kaggle evaluation records its dataset path, SHA-256, sample count, and model role.

6. **Historical scans do not retain model provenance.** `ScanRecord` stores `id`, `url`, risk `score`, `level`, `ml_probability`, indicator/explanation/CTI/feature JSON, `source`, and `scanned_at`. It has no model-version or training-source column; `DBService.get_history()` therefore cannot reconstruct model provenance. This audit did not change the database schema or existing scan history.

## Runtime Inventory

- `GET /api/health`: service status and timestamp.
- `POST /api/scan`: validates HTTP/HTTPS input, normalizes it, extracts 30 features, runs ML and CTI, decides a verdict, and persists the scan.
- `GET /api/history`: returns paginated scan history.
- `GET /api/export/csv` and `GET /api/export/json`: export stored scans.
- SQLite table `scans`: stores URL, final score/verdict, ML probability, evidence JSON, source, and timestamp.

## Verified Results

- Python regression suite: **92 passed**.
- Frontend production build: passed.
- Chrome extension production build and strict TypeScript check: passed in the preceding extension audit.
- Live dashboard proxy scan of `https://example.com`: HTTP 200; result saved in SQLite.
- Live CTI on the local run: URLhaus and WHOIS returned `live`; VirusTotal returned `unknown` because no API key is configured. The scan mode is `degraded`.
- Backend `/api/health`: `ok` after restart using the local launcher.
- Active model feature order: 30 entries, exactly matching `FEATURE_ORDER`; provenance is synthetic and explicitly ineligible.
- Default training with the labeled CSV absent: exits with code 2 and leaves the canonical model artifact unchanged.
- Explicit synthetic training: writes separate artifacts/metrics and leaves the canonical model artifact unchanged.

## Backup

Before audit edits, model/configuration/source backups were created outside the repository at:

`D:\finnal year project\PhishGuard-main.audit-backup.20261010`

SHA-256 checks confirmed the backed-up model artifact, metrics, backend config, and `.env` matched their pre-audit originals.

## Remaining Requirements for Production Evaluation

- Provide or download a labeled raw-URL CSV at `ml/data/raw/labeled_urls.csv`, review its source, duplicates, label quality, and split strategy, then run default training.
- Evaluate on an independent real-world holdout before making accuracy or production-readiness claims.
- Configure a VirusTotal API key on the backend if VirusTotal coverage is required; keep provider credentials out of the extension.
- Add API authentication, database migrations, and deployment hardening before public exposure.
- The Python suite is present; this repository snapshot has only an empty `frontend/src/App.test.tsx`, so frontend behavior is build-checked rather than covered by component tests.
