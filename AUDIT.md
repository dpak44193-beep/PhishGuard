# PhishGuard Project Audit

**Audit date:** 2026-10-12
**Overall result:** A real-data model artifact was trained and evaluated on a registrable-domain-grouped holdout, and the API/dashboard/extension local flows were exercised. Results remain internal same-source metrics, not independent or future-time performance evidence. The reserved-domain false positive is traced to an exact feature-signature collision with phishing-only records in the prepared corpus. It remains unresolved and blocks promotion.

## Scope and Outcome

Inspected the 30-feature URL extractor, dataset loaders, trainer, evaluator, active model artifact, inference service, scan orchestration, API routes, SQLite schema, and existing Python tests.

The silent synthetic fallback is removed. Default training now requires a usable labeled raw-URL CSV. Synthetic data requires `--synthetic`, writes separate artifacts and metrics, and is marked ineligible for final evaluation. The real dataset path now uses the locally available UCI PhiUSIIL source, records its license/attribution/checksums/label mapping, normalizes and deduplicates URL strings without fetching them, and splits by registrable domain. Existing local scanning, dashboard proxy, SQLite storage, and backend startup remain operational.

The inference service now validates the artifact feature order/schema, feature count, and recorded preprocessing pipeline, and returns training/source/test metadata in ML evidence. CTI evidence remains provider-specific; mock mode returns null placeholder evidence rather than simulated matches, VirusTotal without a key is `not_configured`, provider errors remain explicit, and VT no-report lookups do not submit URLs for analysis. A no-match explanation explicitly says it is not proof the URL is safe.

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

4. **The UCI engineered feature table is not the live input schema.** `PhiUSIIL_Phishing_URL_Dataset.csv` has 50 numeric feature columns excluding the label; live inference consumes the 30 URL-derived features above. The separate research script remains incompatible with the live model, but now deduplicates URLs and uses registrable-domain grouped holdout splits.
5. **Generic evaluation lacked dataset provenance.** `ml/models/evaluator.py` now requires explicit data provenance and rejects synthetic datasets. The UCI feature-table evaluation records source/license/checksum/preprocessing provenance and its research-only model role.

6. **Historical scans do not retain model provenance.** `ScanRecord` stores `id`, `url`, risk `score`, `level`, `ml_probability`, indicator/explanation/CTI/feature JSON, `source`, and `scanned_at`. It has no model-version or training-source column; `DBService.get_history()` therefore cannot reconstruct model provenance. This audit did not change the database schema or existing scan history.
7. **The former data downloader fabricated benign examples and lacked an auditable merged-feed policy.** It appended guessed URL paths to Tranco domains and combined feeds without storing license, collection date, or row-level source. It now performs offline preparation only from the documented local UCI PhiUSIIL source. Tranco rankings are not treated as proof of benignity; URLhaus and PhishTank remain documented but are not merged into this training snapshot.
8. **Row-level random splitting could leak related sites.** Training now groups rows by registrable domain for train/validation/test and records split counts/domain counts. Campaign IDs are unavailable, so domain separation does not establish campaign independence.

## Runtime Inventory

- `GET /api/health`: service status and timestamp.
- `POST /api/scan`: validates HTTP/HTTPS input, normalizes it, extracts 30 features, runs ML and CTI, decides a verdict, and persists the scan.
- `GET /api/history`: returns paginated scan history.
- `GET /api/export/csv` and `GET /api/export/json`: export stored scans.
- SQLite table `scans`: stores URL, final score/verdict, ML probability, evidence JSON, source, and timestamp.

## Verified Results

- The focused model-regression run exited 0 with **4 passed, 2 strict expected failures**; the expected failures are the known `example.com` and IANA reserved-domain legitimate-reference false positives. It also reproduces the saved artifact's legitimate holdout false-positive count.
- The complete Python suite exited 0 with **121 passed, 2 xfailed**; these two xfails are unresolved safety expectations, not fixed behavior. `compileall` passed for backend, CTI, ML, and tests.
- Frontend production build (`npm run build`): passed with existing Vite/module-type warnings.
- Chrome extension production build (`npm run build`) and strict TypeScript check (`npx tsc --noEmit`): passed.
- Dashboard `/scan` and `/history` were exercised against the backend on port 8001; the scan record was persisted and read back.
- The extension popup was launched in isolated Playwright Chromium with the unpacked MV3 build; its manual `https://example.com/` string scan completed in local-only mode, without opening the URL or making provider/API requests. Branded Chrome 155 did not register the extension worker under automation, and the optional localhost permission flow remains blocked on Chrome user approval.
- Backend `/api/health`: `ok`; the process used the separate real-data artifact and an in-memory SQLite database with `CTI_MOCK=true`.
- Live inference returned artifact version `base-model-v3`, the 30-feature schema `phishguard-url-lexical-30-v1`, UCI source metadata, and held-out metrics.
- **False-positive root cause:** The running API process's command line sets `ML_MODEL_PATH` to the isolated run artifact. Its SHA-256 is `ab20ccb9bbbc9f9337639e1b75328e805bc1be88a3d2b9c9783673edbcf08dc7`; the canonical default artifact has a different SHA-256 and was not modified. API and direct-artifact inference both return `0.8786` for the same raw ordered vector.
- **No schema/preprocessing mismatch found:** bundle and runtime agree on all 30 `FEATURE_ORDER` names and schema version. Both use the serialized `StandardScaler` then `VotingClassifier` pipeline; runtime passes the raw ordered vector as metadata specifies.
- **Cause demonstrated:** `https://example.com/` has five nonzero features (`url_length=20`, `domain_length=11`, `uses_https=1`, `dot_count=1`, `entropy=3.0958`). The exact 30-value signature occurs 46 times in the prepared corpus, all phishing-labeled, and no legitimate-labeled; the exact host itself is absent. XGBoost returns 0.998154 and RandomForest 0.759091 (ensemble 0.878623). XGBoost's largest per-vector contribution is `dot_count` at +10.037066 log-odds. This is aggregate-feature aliasing and source-corpus coverage/label association, not a CTI effect.
- The final score is generated by the existing decision map at suspicious threshold 0.1285: `0.4 + ((0.8786 - 0.1285) / (1 - 0.1285)) * 0.39 = 0.7357`. CTI was mock/degraded and did not alter the ML probability or score.
- The grouped holdout's legitimate false positives were independently reproduced from the saved model and prepared data: 237 / 20,179 (`0.01174488`), matching `metrics.json`. This same-source metric does not resolve the unseen benign signature issue.
- Dataset inventory: 235,795 source rows (55 columns), 0 missing cells, source labels `0=phishing` (100,945) and `1=legitimate` (134,850); prepared output contains 234,687 rows: 134,849 legitimate and 99,838 phishing.
- Dataset curation: 1,106 same-label duplicate URL rows removed, 1 conflicting normalized URL group (2 rows) removed, 0 invalid URL/label rows, 197,708 registrable domains, and 105 domains represented in both labels.
- Full-corpus grouped split verification: train 164,281 / validation 35,203 / test 35,203 rows; all partitions contain both labels and no registrable domain crosses partitions.
- Native XGBoost 3.4.1 research experiment completed on the documented corpus: 30-feature contract preserved, train/validation/test held out by registrable domain, threshold selected on validation only, baseline and held-out metrics plus 500-replicate domain-cluster bootstrap intervals recorded in `ml/data/processed/native_xgboost_experiment.json`. This is not the active scikit-learn ensemble and is explicitly not deployment eligible.
- Source/license evidence: UCI PhiUSIIL, CC BY 4.0, source DOI `10.1016/j.cose.2023.103545`; observation collection window is not precisely documented by UCI.
- Offline safety: preparation and domain grouping parse URL strings only; no sample URL is resolved, opened, crawled, or submitted.
- Active model artifact `base-model-v3` trained successfully to `ml/models/artifacts/real_data_grouped_run_20261012_final/`; its test accuracy was 0.9905, with domain-cluster bootstrap intervals recorded in `metrics.json`. The result is an internal same-source holdout only; do not describe it as future-time or real-world accuracy.
- The canonical default runtime artifact was not overwritten. The live API selected the separate artifact through `ML_MODEL_PATH`; deployments must not silently assume that default configuration now uses it.
- No external CTI providers were queried during final live tests. CTI responses were explicit mocks with null matches; this is not a provider success or no-threat result.
- Default training with the labeled CSV absent: exits with code 2 and leaves the canonical model artifact unchanged.
- Explicit synthetic training: writes separate artifacts/metrics and leaves the canonical model artifact unchanged.

## Backup

Before audit edits, model/configuration/source backups were created outside the repository at:

`D:\finnal year project\PhishGuard-main.audit-backup.20261010`

SHA-256 checks confirmed the backed-up model artifact, metrics, backend config, and `.env` matched their pre-audit originals.

## Remaining Requirements for Production Evaluation

- Resolve the `example.com`/IANA false positives with appropriate domain-aware features and independently verified legitimate labels. The strict expected-failure regression tests are intentionally still xfailed; no special-case, threshold weakening, or model promotion was made.
- Evaluate on an independent, future-time or campaign-aware holdout before making accuracy or production-readiness claims; current UCI records do not provide the observation dates or campaign IDs needed for this.
- The original UCI source CSV is not present in the current workspace; only the derived corpus and manifest are available. Obtain and hash-verify the original source before independently reproducing dataset preparation.
- Preserve the 30-feature contract and explicitly configure the isolated `base-model-v3` artifact only after review; do not overwrite the canonical artifact without a separately approved promotion.
- Configure a VirusTotal API key on the backend if VirusTotal coverage is required; keep provider credentials out of the extension.
- Persist model provenance with historical scans only through a deliberate database-schema migration; current scan POST responses expose metadata, but history reconstruction retains only legacy scan fields.
- Add API authentication, database migrations, and deployment hardening before public exposure.
- The Python suite is present; this repository snapshot has only an empty `frontend/src/App.test.tsx`, so frontend behavior is build-checked rather than covered by component tests.

Detailed commands and runtime outcomes are recorded in [`runtime-validation-report.md`](./runtime-validation-report.md).
