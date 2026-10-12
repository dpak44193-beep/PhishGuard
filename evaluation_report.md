# PhishGuard Model Evaluation

**Evaluation type:** Preliminary, same-source, registrable-domain grouped holdout.
**Independent-source / time-based evaluation:** Not available.
**Production promotion:** **NO**. The legitimate-reference false positive remains unresolved and an independently sourced evaluation has not been performed.

## Historic v3 result (reproduced)

The stored v3 artifact was evaluated on a 70/15/15 registrable-domain grouped split of the UCI PhiUSIIL-derived corpus. The test domains have no overlap with train or validation, but the artifact's seed-42 result has already been evaluated and inspected in prior project work. It is not a newly untouched or external holdout.

| Test class | Count |
|---|---:|
| Legitimate | 20,179 |
| Phishing | 15,024 |
| Total | 35,203 |

Confusion matrix (actual rows, predicted columns; legitimate then phishing):

|  | Predicted legitimate | Predicted phishing |
|---|---:|---:|
| Actual legitimate | 19,942 | 237 |
| Actual phishing | 98 | 14,926 |

| Measure | Value |
|---|---:|
| Accuracy | 0.99048 |
| Precision (phishing) | 0.98437 |
| Recall (phishing) | 0.99348 |
| F1 (phishing) | 0.98890 |
| Legitimate false-positive count | 237 |
| False-positive rate | 0.01174 |
| Phishing false-negative count | 98 |
| False-negative rate | 0.00652 |
| PR-AUC (average precision) | 0.99827 |
| ROC-AUC | 0.99777 |
| Threshold selected on validation | 0.1285 |

Saved grouped-bootstrap 95% intervals from the previous evaluation are in `ml/models/artifacts/real_data_grouped_run_20261012_final/metrics.json`; these quantify sampling variation within that same-source held-out set, not future-world uncertainty. Per-TLD and keyword-bucket summaries are also in that file; small groups must not be read as reliable rates.

## New isolated comparison

Candidate A is a fresh retraining of the existing `build_pipeline()` recipe on 30 features. Candidate C uses the same recipe and splits, with 64 fixed-hash bins of hostname-only character 3-, 4-, and 5-grams appended. Both use the same seed-`20261013` split; all three pairwise registrable-domain overlaps are zero. Train/validation/test are respectively 164,281 / 35,203 / 35,203 rows. The test class distribution is 20,229 legitimate and 14,974 phishing.

The scaler/classifier fit on train only. Each threshold was selected on validation only to meet 98% precision with maximum recall (maximum F1 fallback); the resulting thresholds are shown below. The shared test set was evaluated after configurations and threshold rules were fixed. Two hundred cluster-bootstrap replicates resampled test registrable domains. This is one same-source comparison and not independent-source or time-based validation.

| Measure | Candidate A: 30 features | Candidate C: 30 + host char-hash | Difference C − A |
|---|---:|---:|---:|
| Validation-selected threshold | 0.131683 | 0.165112 | — |
| Accuracy | 0.990484 | 0.992046 | +0.001562 |
| Precision (phishing) | 0.982530 | 0.986106 | +0.003575 |
| Recall (phishing) | 0.995325 | 0.995325 | 0 |
| F1 (phishing) | 0.988886 | 0.990694 | +0.001808 |
| Legitimate false positives | 265 | 210 | −55 (20.8% fewer) |
| False-positive rate | 0.013100 | 0.010381 | −0.002719 |
| Phishing false negatives | 70 | 70 | 0 |
| False-negative rate | 0.004675 | 0.004675 | 0 |
| PR-AUC (average precision) | 0.998619 | 0.998746 | +0.000127 |
| ROC-AUC | 0.998199 | 0.998435 | +0.000237 |
| False-positive registrable domains | 257 | 204 | −53 |
| False-negative registrable domains | 70 | 70 | 0 |
| Median per-URL latency, including features | 65.09 ms | 71.82 ms | +6.73 ms (+10.3%) |

Confusion matrices (actual rows; legitimate, phishing; predicted columns; legitimate, phishing):

| Candidate | Matrix |
|---|---|
| A | `[[19964, 265], [70, 14904]]` |
| C | `[[20019, 210], [70, 14904]]` |

Clustered percentile 95% intervals (200 domain bootstrap replicates):

| Measure | Candidate A | Candidate C |
|---|---:|---:|
| Accuracy | [0.98935, 0.99165] | [0.99101, 0.99309] |
| Precision | [0.97931, 0.98546] | [0.98323, 0.98833] |
| Recall | [0.99397, 0.99656] | [0.99402, 0.99645] |
| F1 | [0.98698, 0.99063] | [0.98911, 0.99224] |
| FPR | [0.01154, 0.01461] | [0.00904, 0.01170] |
| FNR | [0.00344, 0.00603] | [0.00355, 0.00598] |

The intervals overlap for precision, FPR, and FNR; the small one-split differences do not establish a robust general improvement. The point estimate for A's accuracy happens to match the historical v3 accuracy, but they are separate seeds/splits and the equality is coincidental. Candidate A is the matched fresh-split baseline, **not** a test of the default v2 artifact.

### Legitimate-reference regression

Using the thresholds chosen above, predictions on reference URL strings (no browsing) are:

| URL | Candidate A probability / flagged? | Candidate C probability / flagged? |
|---|---:|---:|
| `https://example.com/` | 0.879971 / yes | 0.976590 / yes |
| `https://www.iana.org/domains/reserved` | 0.878378 / yes | 0.784405 / yes |
| `https://www.wikipedia.org/` | 0.019510 / no | 0.031892 / no |

Candidate C **does not fix** the known `example.com` or IANA false positives; its example.com probability is higher than candidate A. Therefore, despite fewer false positives on this held-out same-source partition, candidate C is not recommended for promotion.

### Redacted error examples

Raw URLs are intentionally excluded. The following SHA-256 prefixes identify actual rows in the isolated test set without disclosing URL paths or query parameters:

| Candidate | Error type | URL hash prefix | Domain hash prefix | Probability |
|---|---|---|---|---:|
| A | Legitimate false positive | `2b0ad50727ad7244` | `3e35d0c1db76ced6` | 0.133237 |
| A | Phishing false negative | `213db91ef6eefb4f` | `52fe3c8e662f67d2` | 0.058284 |
| C | Legitimate false positive | `60f002516d71a5a9` | `14cd7efe06e84dba` | 0.256516 |
| C | Phishing false negative | `729842be374c88ea` | `fd3379cb009b3478` | 0.041280 |

The corpus has only binary labels; attack-category metrics are not available. Full hashed example lists, split counts, environment versions, and experiment metadata were saved with the local output.

### Artifact identities and execution

| Candidate | Artifact version | Feature schema | SHA-256 |
|---|---|---|---|
| A | `candidate_a_30_feature_baseline` | `phishguard-url-lexical-30-v1` | `2f270c646d81335721745ff8246a2878cbdb184bad76fcc83e3d82212a39f5b4` |
| C | `candidate_c_host_charhash64` | `phishguard-url-lexical-30-plus-host-charhash64-v1` | `5496e99372acf0c3c9c8f43f203302652602fa0c84952ff7da966892237ced54` |

Artifacts are local under the ignored `ml/models/artifacts/experiments/real_data_domain_grouped_seed20261013/` directory. Neither artifact was configured for the running API. Environment: Python 3.12.13, scikit-learn 1.9.1, XGBoost 3.4.1. No network or CTI dependency is required at inference; candidate C adds CPU work for hostname n-gram hashing.

The latency values above were remeasured on the serialized candidate models with the finalized reusable hasher, three runs over 256 URLs, measuring feature extraction plus prediction. The hasher initialization was moved out of the per-URL call after the initial training process; direct comparison confirmed the hashed feature arrays are exactly equal (maximum absolute difference 0). Candidate classification metrics and model bytes were produced by the initial run; the implementation adjustment did not alter any feature values or model inputs.

Candidate B (retraining with improved independently sourced legitimate coverage) is blocked: no qualifying second dataset is present, and no unverified archive was downloaded. Candidate C is an exploratory feature experiment, not an alternate production artifact.

## Error analysis

For the held-out v3 evaluation there were 237 false positives and 98 false negatives. Their raw URL strings are not included because URLs can contain credentials, session tokens, and private query parameters. The new experiment records only URL/domain SHA-256 prefixes, scores, aggregate counts, and number of affected registrable domains. No examples are fabricated.

The stored historical API result for `https://example.com/` was `ML probability=0.8786`, `risk score=0.7357`, `suspicious`, `degraded`; VirusTotal, URLhaus, and WHOIS were all explicitly mock. The matching exact feature signature occurs 46 times in the prepared UCI corpus, all source-labeled phishing. This remains a known false positive, not a passing regression.

## Limitations and decision

- One inherited-label dataset, no precise per-record dates, no campaign identifiers.
- No qualifying independent training or test corpus; no time-based generalization evidence.
- No real-world accuracy claim follows from model training or dashboard scans.
- Existing default v2 training-data hash/counts conflict with the current prepared manifest; its old evaluation cannot be reconstructed.
- The running API's latest persisted scan lacks model version and metadata. The probability is consistent with v3 but the exact loaded artifact cannot be established without a new persisted scan or a non-mutating model-info endpoint.
- Candidate A/C comparison cannot resolve these evidence gaps. Keep the configured production artifact unchanged.

## Commands and validation status

- Experiment command (exit code 0): `& '.\backend\.venv\Scripts\python.exe' -m ml.experiments.grouped_feature_experiment --dataset ml\data\raw\labeled_urls.csv --output-dir ml\models\artifacts\experiments\real_data_domain_grouped_seed20261013 --seed 20261013 --bootstrap-replicates 200 --verbose`.
- Focused Python regression command (exit code 0): `& '.\backend\.venv\Scripts\python.exe' -m pytest tests\test_experimental_hostname_features.py tests\test_model_regression.py -q` — 9 passed, 2 strict xfailed. The two expected failures are unresolved legitimate-reference false positives.
- Full Python suite (exit code 0): `& '.\backend\.venv\Scripts\python.exe' -m pytest -q` — 126 passed, 2 xfailed.
- Syntax checks (exit code 0): `py_compile` passed for the new experiment and changed regression tests; `compileall -q backend\app cti ml tests` passed.
- Dashboard production build (exit code 0): `npm --prefix frontend run build`; Vite emitted existing module/config warnings.
- Extension bundle build (exit code 0): `npm --prefix extension run build`.
- Runtime: `curl.exe --noproxy "*" -fsS http://127.0.0.1:8001/api/health` returned status `ok`; GET history returned the stored false-positive record. Browser navigation loaded dashboard home, scan form, and history. No scan was submitted and existing history was not modified.
- Diff validation: `git diff --check` exited 0 before the final documentation updates; it is rerun after all edits.
- Chrome extension runtime/permission flow was not exercised; only its production bundle was built. Do not treat bundle compilation as end-to-end extension validation.
