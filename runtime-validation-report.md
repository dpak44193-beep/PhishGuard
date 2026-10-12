# PhishGuard real-data training and runtime validation

**Run date:** 2026-10-12
**Status:** False-positive investigation completed; regression coverage added. The existing model still misclassifies two legitimate reference URLs, recorded as expected failures. Real-world performance is not established and the artifact is not promoted.

## Executive result

The active training pipeline successfully trained an isolated `base-model-v3` model from the documented UCI PhiUSIIL-derived URL corpus. The canonical default model file was left unchanged. The model was loaded by the local API using `ML_MODEL_PATH`, and scan responses returned the version, source, schema, and test metrics.

The data split is registrable-domain grouped, not time based or independently sourced. The UCI dataset provides no per-row observation date or campaign identifier. The `https://example.com/` false positive is reproducible and traced to a feature-representation/training-data collision, not a feature-order or preprocessing mismatch. No model, threshold, configuration, or database was changed to mask it. The high internal holdout metrics must not be represented as real-world detection performance.

## Dataset provenance and preparation

- **Source:** UCI PhiUSIIL Phishing URL (Website), [UCI dataset 967](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), DOI [10.1016/j.cose.2023.103545](https://doi.org/10.1016/j.cose.2023.103545), license CC BY 4.0.
- **Source label mapping:** source `0=phishing`, `1=legitimate`; training mapping `0=legitimate`, `1=phishing`.
- **Source file SHA-256:** `748ae7c7a677ac4ffc0eeefbee653dcef1d685b134ad2f5376596b92d79438ba`.
- **Prepared corpus SHA-256:** `1db2f5ce060de7b073c96d942ff180423e16a01392240bf33e5ca29bb917b4af`.
- **Input rows / columns:** 235,795 / 55; missing cells: 0.
- **Invalid URL/label rows:** 0 / 0.
- **Deduplication:** 1,106 duplicate URL rows removed; one conflicting normalized URL group (two rows) removed.
- **Prepared observations:** 234,687; 134,849 legitimate (57.47%) and 99,838 phishing (42.53%).
- **Source availability:** the original UCI CSV is not present in the current workspace; the prepared CSV and manifest are present, including the recorded source-file hash and derived-corpus hash. To reproduce the transformation independently, obtain the source file from UCI and verify its SHA-256 against the manifest first.
- **Domain grouping:** 197,708 registrable domains; 105 domains carry both labels, but all rows for each domain remain in one split. Campaign overlap cannot be evaluated.
- **Safety:** preparation and evaluation analyze URL strings offline. Dataset URLs are not opened, resolved, or crawled.

UCI describes observations as mostly latest but does not specify a precise observation window. Labels are inherited source annotations and were not independently re-verified. These constraints make a time split and campaign-level validation impossible with this corpus.

## Training and evaluation methodology

- **Runtime input contract:** unchanged ordered 30-feature `FEATURE_ORDER`; schema version `phishguard-url-lexical-30-v1`.
- **Model:** `base-model-v3`; training pipeline uses the supported scikit-learn classifier pipeline, with XGBoost included in the soft-voting model when installed. The recorded scaler is fitted on training data only. No feature selection is applied.
- **Split:** train 164,281 (94,459 legitimate / 69,822 phishing; 138,563 domains), validation 35,203 (20,211 / 14,992; 29,631 domains), test 35,203 (20,179 / 15,024; 29,514 domains). No registrable domain is shared across partitions.
- **Threshold:** selected from validation probabilities only as the highest-recall threshold meeting 98% precision (fallback to maximum F1); suspicious threshold `0.1285`, safe threshold `0.0643`. The test partition was used only for final evaluation.
- **CTI:** not used for training or model evaluation.
- **Artifact:** `ml/models/artifacts/real_data_grouped_run_20261012_final/phishguard_model.joblib`.
- **Machine-readable metrics and provenance:** `ml/models/artifacts/real_data_grouped_run_20261012_final/metrics.json`; artifact bundle contains training date, source/license/hashes, artifact version, feature schema, pipeline steps, and held-out metrics.

### Held-out results

Confusion matrix (actual rows / predicted columns; label order legitimate, phishing):

|  | Predicted legitimate | Predicted phishing |
|---|---:|---:|
| Actual legitimate | 19,942 | 237 |
| Actual phishing | 98 | 14,926 |

| Model | Accuracy | Precision | Recall | F1 | False-positive rate | PR-AUC | ROC-AUC |
|---|---:|---:|---:|---:|---:|---:|---:|
| `base-model-v3` | 0.9905 | 0.9844 | 0.9935 | 0.9889 | 0.0117 | 0.9983 | 0.9978 |
| Majority-class baseline (legitimate) | 0.5732 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.4268 | 0.5000 |

The majority baseline confusion matrix is `[[20179, 0], [15024, 0]]`.

95% percentile confidence intervals use 500 bootstrap resamples of held-out registrable domains, keeping all rows for each sampled domain together:

| Metric | 95% interval |
|---|---:|
| Accuracy | [0.98927, 0.99165] |
| Precision | [0.98101, 0.98750] |
| Recall | [0.99179, 0.99494] |
| F1 | [0.98668, 0.99088] |
| False-positive rate | [0.01023, 0.01317] |
| PR-AUC | [0.99758, 0.99879] |
| ROC-AUC | [0.99700, 0.99834] |

These intervals describe sampling variability within this grouped test set, not external or future-world uncertainty. A separate native-XGBoost research evaluation is documented at `ml/data/processed/native_xgboost_experiment.json`; it is not the runtime artifact.

## `example.com` false-positive investigation

The investigation re-ran the scan through the API, extracted the URL features directly, evaluated the configured artifact outside the API, and compared the query vector with every prepared UCI URL. The URL was never opened, resolved, or fetched.

### Input, feature vector, and model probability

`URLFeatureExtractor.extract("https://example.com/")` returns 30 values in the saved artifact's exact `FEATURE_ORDER`:

```text
url_length=20, domain_length=11, subdomain_count=0, has_ip=0,
uses_https=1, dot_count=1, hyphen_count=0, at_sign_count=0,
special_char_count=0, digit_ratio=0.0, entropy=3.0958,
suspicious_keywords=0, is_url_shortener=0, tld_risk=0, path_depth=0,
query_param_count=0, has_encoded_chars=0, double_slash_in_path=0,
has_port=0, is_punycode=0, tilde_in_path=0, hex_in_domain=0,
redirect_double_slash=0, domain_digit_count=0, url_shortener_flag=0,
brand_count=0, num_dots_in_path=0, query_length=0, fragment_present=0,
multi_subdomain=0
```

The vector contains no host-character or domain-identity feature. The artifact and training code both use `FEATURE_ORDER`, the same `phishguard-url-lexical-30-v1` schema, and `StandardScaler` followed by a soft-voting XGBoost/RandomForest `VotingClassifier`. The scaler is inside the serialized pipeline and inference passes the raw ordered vector, as recorded in artifact metadata; direct artifact inference reproduced the API probability. No feature-order, feature-count, or preprocessing mismatch was found.

### Root cause evidence

- The prepared training CSV contains no row for the exact `example.com` host.
- Re-extracting all prepared rows with the same feature extractor found **46 rows with an exactly identical 30-value vector**: all 46 are phishing-labeled and none are legitimate-labeled. Their domains differ, but the current feature schema collapses them to the same representation as `example.com`.
- For this vector, XGBoost produced phishing probability `0.998154`, RandomForest `0.759091`, and the voting ensemble `0.878623` (API rounds to `0.8786`). XGBoost feature contributions put `dot_count=1` at `+10.037066` log-odds; the next largest contributions were `uses_https=-1.364656`, `subdomain_count=-0.859726`, `domain_length=-0.599636`, and `entropy=-0.300092`.
- This is a representation/coverage failure: the aggregate features omit host spelling/identity, and this exact feature signature has only phishing examples in this source corpus. The model therefore generalizes that training signature to the reserved legitimate domain. It is not evidence that the URL is malicious.
- On the saved domain-grouped holdout, re-running the model against the 20,179 legitimately labeled test URLs reproduced the reported **237** false positives (`FPR=0.01174488`) exactly. This dataset-level metric does not protect unseen benign domains that share an underrepresented feature signature.

### Score and CTI path

The running API process was launched with `ML_MODEL_PATH` set to `ml/models/artifacts/real_data_grouped_run_20261012_final/phishguard_model.joblib`, `CTI_MOCK=true`, and in-memory SQLite. Artifact SHA-256: `ab20ccb9bbbc9f9337639e1b75328e805bc1be88a3d2b9c9783673edbcf08dc7`. Its returned `base-model-v3` version, 30-feature schema, and `0.8786` output match direct loading of that file. The canonical artifact remains distinct (SHA-256 `823103f552c8af65ce57b15b52d39be8f02976cf7d1646f8ced46ed47bb3403a3f`).

The decision engine uses suspicious threshold `0.1285` and maps the ML score to risk with `0.4 + ((0.8786 - 0.1285) / (1 - 0.1285)) * 0.39 = 0.7357`. It labels this `suspicious`; malicious threshold is `0.985`. All three CTI responses were `mock`, with null match/score and no provider request. The degraded CTI mode did not create the ML probability or raise the score; the suspicious risk comes from the model score and existing risk mapping.

Regression tests were added in `tests/test_model_regression.py` to verify model/runtime schema and probability parity, reproduce the feature collision, recompute the legitimate held-out false-positive count, and exercise known legitimate reference URLs.

## Automated and runtime checks

| Check | Result |
|---|---|
| Focused model regression tests | PASS with known failures exposed — exit 0; 4 passed, 2 xfailed in 126.68 seconds |
| Full Python suite | PASS with known failures exposed — exit 0; 121 passed, 2 xfailed in 140.56 seconds |
| Python syntax compilation | PASS — `backend`, `cti`, `ml`, `tests` |
| Dashboard production build | PASS — `npm run build` |
| Extension production build | PASS — `npm run build` |
| Extension TypeScript check | PASS — `npx tsc --noEmit` |
| `git diff --check` | PASS |
| API `/api/health` | PASS — `{"status":"ok"}` on port 8001 |
| API `/api/scan` | PASS — returned 30 features, model metadata, explicit mock CTI states |
| Database persistence | PASS — scanned URL appeared in `/api/history` |
| Dashboard browser scan/history | PASS — `/scan` displayed result and provider states; `/history` showed persisted row |
| Chrome MV3 popup | PASS — unpacked build loaded in isolated Playwright Chromium 1187; manual URL-string scan returned local `UNKNOWN` and did not open the URL |

The focused command was `.\backend\.venv\Scripts\python.exe -m pytest -q tests/test_model_regression.py` (exit 0; 4 passed, 2 xfailed). The complete command was `.\backend\.venv\Scripts\python.exe -m pytest -q` (exit 0; 121 passed, 2 xfailed). The two expected failures are the safe-threshold assertions for `example.com` and the IANA reserved-domain reference; they remain unresolved and strict xfails. The grouped-holdout legitimacy and schema-parity regression tests passed. `compileall` passed. The frontend `npm run build` passed with existing Vite/module-type warnings; the extension `npm run build` and `npx tsc --noEmit` both exited 0. `git diff --check` passed with Git line-ending conversion warnings only.

The live API used the trained artifact path, `CTI_MOCK=true`, and an in-memory SQLite database. A scan response returned `base-model-v3`, training timestamp `2026-10-12T03:44:25.502769+00:00`, schema `phishguard-url-lexical-30-v1` (30 names), UCI source, test accuracy 0.9905, and PR-AUC 0.9983. In this investigation, health returned `ok`; `POST /api/scan` again returned ML probability `0.8786`, score `0.7357`, suspicious verdict, and degraded mode; `/api/history` returned the persisted scan. The dashboard scan page displayed the same result and provider states, and its history page displayed the persisted `https://example.com` row. VirusTotal, URLhaus, and WHOIS each returned `mock` with null hit/score and `provider_request_performed=false`; no paid or external CTI API was accessed. The extension test covered local popup scanning only. The installed Google Chrome 155 did not register the extension worker when launched with the automation load flags; the successful popup test used Playwright-managed Chromium 1187. An automated attempt to connect the extension's optional localhost permission stopped at Chrome's user-approval prompt; it did not save the backend URL or send an extension scan request.

The current POST scan response contains complete model metadata. Existing history reconstruction does not persist model version/training metadata; adding historical provenance would require a deliberate database schema migration.

## Reproduction commands

Run from the repository root in PowerShell. Python commands use the project virtual environment.

```powershell
$env:DATABASE_URL = 'sqlite+aiosqlite:///:memory:'
$env:CTI_MOCK = 'true'
.\backend\.venv\Scripts\python.exe -m pytest -q tests\test_model_regression.py
.\backend\.venv\Scripts\python.exe -m pytest -q
.\backend\.venv\Scripts\python.exe -m compileall -q backend cti ml tests

# The exact completed run; its destination now exists and the trainer refuses to overwrite it.
.\backend\.venv\Scripts\python.exe ml\train.py --output-dir ml\models\artifacts\real_data_grouped_run_20261012_final

# For a fresh reproduction, choose a new output directory that does not already exist.
.\backend\.venv\Scripts\python.exe ml\train.py --output-dir ml\models\artifacts\real_data_grouped_run_reproduction

Push-Location frontend
npm run build
Pop-Location

Push-Location extension
npm run build
npx tsc --noEmit
Pop-Location
```

Training reads the prepared, checksum-verified `ml/data/raw/labeled_urls.csv` and its manifest. The `run_20261012_final` command above records the command used for the completed run; after that run, the output path exists, so a repeat must use the new `run_reproduction` path (or another non-existing name). The trainer refuses an existing `--output-dir`, preserving previous run artifacts and the canonical model.

For local API validation, use a second PowerShell terminal from the repository root:

```powershell
$env:ML_MODEL_PATH = (Resolve-Path 'ml\models\artifacts\real_data_grouped_run_20261012_final\phishguard_model.joblib').Path
$env:DATABASE_URL = 'sqlite+aiosqlite:///:memory:'
$env:CTI_MOCK = 'true'
$env:PYTHONPATH = (Join-Path $PWD 'backend')
.\backend\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

With the dashboard dev server at `http://localhost:5173`, verify health, scan, and persistence without visiting the target:

```powershell
Invoke-RestMethod 'http://127.0.0.1:8001/api/health'
$body = @{ url = 'https://example.com/'; source = 'dashboard' } | ConvertTo-Json -Compress
$scan = Invoke-RestMethod 'http://127.0.0.1:8001/api/scan' -Method Post -ContentType 'application/json' -Body $body
$scan.evidence.ml
Invoke-RestMethod 'http://127.0.0.1:8001/api/history?limit=10&offset=0'
```

`example.com` is included only as a harmless string input to exercise feature extraction and the scan flow; neither the API nor the extension test opens it. Its suspicious output should reproduce and is a warning, not a successful safety result.

## Limitations and blockers

1. No time-based split is possible because UCI does not provide per-observation dates or a precise collection window.
2. No campaign identifiers are supplied; registrable-domain grouping reduces one leakage path but does not establish campaign independence.
3. Labels are inherited from one source and are not independently verified; the original UCI CSV is not present in this workspace, although source and derived hashes are recorded in the manifest.
4. The `example.com` and IANA reserved-domain reference tests are expected failures: the same 30-feature vector occurs 46 times in the labeled training corpus, all with phishing labels and none with legitimate labels. Additional host-aware features and appropriately licensed, independently verified labels are needed; changing thresholds or special-casing domains is not an acceptable fix.
5. The newly trained artifact is isolated; the canonical default artifact remains unchanged. Do not promote without review.
6. CTI was mocked for safe, reproducible runtime tests. These checks do not verify live provider availability or coverage.
7. Historical scan rows do not preserve model version/metadata.
8. Branded Chrome 155 extension loading and the online-backend permission flow remain unverified; the latter requires user approval and was not completed in automation.
9. API authentication and production deployment hardening remain out of scope.

**Conclusion:** the false positive is traced to an exact feature-signature collision and learned training-data association; feature ordering/preprocessing mismatch was not found. Regression coverage reproduces the issue and the current grouped-holdout false-positive count. The known legitimate-reference failures remain unresolved, so the artifact is not promoted. The canonical artifact, production settings, and database schema/data were not changed. Independent real-world accuracy and production readiness remain unproven.
