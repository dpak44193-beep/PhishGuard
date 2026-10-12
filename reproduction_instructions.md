# PhishGuard Audit and Experiment Reproduction

Run commands from the repository root in Windows PowerShell. The validated interpreter is `backend\.venv\Scripts\python.exe`; Node dependencies are already installed locally. These commands operate on URL strings and do not visit dataset URLs.

## Dataset and model audit

```powershell
& '.\backend\.venv\Scripts\python.exe' -m ml.data.download_dataset --help
& '.\backend\.venv\Scripts\python.exe' -m pytest tests\test_model_regression.py tests\test_experimental_hostname_features.py -q
```

The local source and prepared CSV are verified against `ml/data/raw/labeled_urls.manifest.json`. Do not regenerate or overwrite either dataset unless explicitly intended; preparation writes the output CSV. The checksums and labels are documented in `dataset_audit.md`.

To reproduce the 30-feature collision query from the regression test:

```powershell
& '.\backend\.venv\Scripts\python.exe' -m pytest tests\test_model_regression.py -q
```

The two strict expected failures are retained for the unresolved legitimate-reference false positives; an expected failure is not a fix.

## Isolated A/C experiment

The completed experiment command used:

```powershell
& '.\backend\.venv\Scripts\python.exe' -m ml.experiments.grouped_feature_experiment `
  --dataset ml\data\raw\labeled_urls.csv `
  --output-dir ml\models\artifacts\experiments\real_data_domain_grouped_seed20261013 `
  --seed 20261013 `
  --bootstrap-replicates 200 `
  --verbose
```

It refuses to overwrite an existing output directory. To repeat it, choose a new unused output-directory name. The ignored local output contains the candidate model bundles and machine-readable `metrics.json`; the committed `evaluation_report.md` records its experiment summary and artifact hashes. Candidate B requires a separate qualifying dataset and is blocked in this run.

## Regression, full suite, and syntax

```powershell
& '.\backend\.venv\Scripts\python.exe' -m pytest tests\test_experimental_hostname_features.py -q
& '.\backend\.venv\Scripts\python.exe' -m pytest -q
& '.\backend\.venv\Scripts\python.exe' -m compileall -q backend\app cti ml tests
```

Capture each process exit code in PowerShell with `$LASTEXITCODE` immediately after its command. Any non-zero result is a failure; preserve expected-failure names and counts rather than translating them to passes.

## Dashboard/API and extension checks

When the existing local services are already running, the non-mutating health/history checks are:

```powershell
curl.exe --noproxy "*" -fsS http://127.0.0.1:8001/api/health
curl.exe --noproxy "*" -fsS "http://127.0.0.1:8001/api/history?limit=1"
```

The history request is read-only. A `/api/scan` request persists a record, so do not use it against the existing database unless the operator has approved the write and test-data cleanup plan. For production builds:

```powershell
npm --prefix frontend run build
npm --prefix extension run build
```

The extension bundle build does not validate Chrome runtime permissions, content-script behavior, or end-to-end scan submission. Perform those separately in a disposable Chrome profile with the user's permission approval and an isolated backend/database. Never open suspicious dataset URLs during a browser test.

## Verified results for this checkout

- Focused regression: **9 passed, 2 xfailed**, exit code 0. The xfails are the intentionally unresolved `example.com` and IANA legitimate-reference checks.
- Full Python suite: **126 passed, 2 xfailed**, exit code 0.
- Python `py_compile` and `compileall` sweeps: exit code 0.
- Dashboard and extension production builds: exit code 0; Vite printed configuration/module warnings.
- API health: HTTP 200 on port 8001. Dashboard home, history, and scan form rendered on port 5173. No scan was submitted to avoid changing persisted history.
- Extension runtime/permission integration: not verified; only bundle compilation passed.
- Candidate A/C training: exit code 0. Full candidate metrics and redacted error references are recorded in `evaluation_report.md`; local serialized bundles are ignored and remain isolated from production.

## Expected scope

- The saved model and metrics are same-source, registrable-domain grouped results.
- No time-based or independent-source guarantee is available.
- Production model path, existing database, CTI credentials/providers, dashboard port 5173, and API port 8001 are not modified by the experiment.
