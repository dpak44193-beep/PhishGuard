# Isolated PhishGuard Experiment Plan

## Objective and boundary

Investigate the confirmed limitation in the 30-feature schema without changing the production model, inference code, feature order, configuration, startup workflow, or database. All candidates use offline URL strings only. CTI and external reputation are excluded from model metrics.

## Candidates

### A — 30-feature reference recipe

Retrain the existing `build_pipeline()` (StandardScaler plus soft-voting XGBoost/RandomForest when XGBoost is installed; otherwise RandomForest) on the existing UCI-derived corpus using a new, fixed registrable-domain split seed. This is a matched, fresh-split reference for candidate C, **not** a valid evaluation of the currently configured v2 binary. The v2 training corpus hash and split provenance do not match the available local corpus.

### B — 30 features with improved independent labeled-data coverage

**Blocked; not trained.** No second labeled URL corpus that is locally available and has verifiable provenance, label definitions, dates, and permitted redistribution/training use was found. The UNB/CIC 2016 page describes useful candidate sources but leaves licensing and some benign-label methodology unclear; it was not downloaded. B can be reconsidered only after the user supplies/approves a qualifying dataset and its use terms are confirmed.

### C — separate hostname feature experiment

Append 64 fixed-hash bins of hostname-only character 3-, 4-, and 5-grams to the existing 30 features. This tests whether spelling cues help distinguish hosts whose current lexical vectors collide. Hashing is fixed and requires no corpus fitting; scaler/classifier are fit only on train data. The model and schema are separately versioned (`phishguard-url-lexical-30-plus-host-charhash64-v1`). This does not change the production schema.

| Design factor | Candidate A | Candidate C |
|---|---|---|
| Source corpus | Current UCI PhiUSIIL-derived CSV, hash recorded in manifest | Same |
| Split | 70/15/15, registrable-domain grouped, seed `20261013` | Same exact indices |
| Classifier | Existing `build_pipeline()` recipe | Same recipe |
| Preprocessing fit | Train partition only | Train partition only; host hashing has no learned state |
| Threshold selection | Validation only; target precision 0.98, maximum recall, maximum-F1 fallback | Same |
| Final test | Used after both model/training configurations and threshold procedure are fixed | Same shared test, one final comparison |
| Uncertainty | 200 bootstrap replicates clustered by test registrable domain | Same |

The final test is same-source and domain-grouped, not independent-source or time-based. It has been inspected in historical runs with another split seed; no claim of a previously untouched source or an external validation is made. The candidates are fixed before the test evaluation; no threshold is tuned from test results.

## Measures and acceptance

Record accuracy, precision, recall, F1, confusion matrix, legitimate false-positive count/rate, phishing false-negative count/rate, PR-AUC, ROC-AUC, class distribution, domain-level error counts, clustered 95% intervals for threshold metrics, and per-URL inference latency including feature extraction. Error examples are represented by URL/domain hash prefixes only; raw potentially sensitive URLs are not written.

Candidate C is an exploratory improvement only if it reduces legitimate false positives meaningfully without materially increasing phishing false negatives, with uncertainty and latency considered. One same-source split is insufficient for production promotion regardless of score. Promotion additionally requires an independently sourced labeled evaluation, acceptable error trade-offs, reproducibility, and explicit approval.

## Executed result

Candidate A and C were trained and compared as planned. Candidate C had 210 false positives vs A's 265 and the same 70 false negatives on the shared test set, but C's reference prediction for `example.com` was 0.976590 (above its validation-selected threshold). Clustered uncertainty intervals overlap for key error rates; latency increased by approximately 10.3%. See `evaluation_report.md` for the full result table, confusion matrices, intervals, redacted error identifiers, artifact hashes, and the explicit no-promotion decision. Candidate B remains blocked.

## Safety and rollback

Artifacts are written only under the unique, ignored experiment output directory. The output command refuses an existing output directory. Candidate bundles have unique version/schema metadata and must not be configured as `ML_MODEL_PATH`. No database writes, live provider calls, URL fetches, or production artifact writes are part of the experiment. To discard the experiment, remove only the specifically named experiment output directory after confirmation; production artifacts/configuration remain unchanged.
