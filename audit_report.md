# PhishGuard Model and Data Audit

**Status:** Audit and isolated A/C experiment completed; independent-data candidate B is blocked.
**Production promotion:** **NO**. The current production model has an unresolved legitimate-reference false positive, and only one source corpus is available.
**Safety:** URL strings were analyzed offline. No dataset URL was opened, resolved, crawled, or submitted to a provider.

## Scope and evidence

Inspected the configured and isolated model bundles, feature extraction and order, training/splitting code, dataset CSV and manifest, inference and decision code, regression tests, API health, and the latest existing history record. The prepared UCI CSV is available locally; its recorded source CSV is also available.

The following artifacts are distinct:

| Role | Version | SHA-256 | Dataset hash in artifact | Metadata |
|---|---|---|---|---|
| Default `ML_MODEL_PATH` from repository settings | `base-model-v2` | `823103f552c8af65ce57b15b52d39be8f02976cf7d1646f8ced46ed47bb3403a3f` | `ed0ea7f53856f18a43457394ba7f76336fb571c1b6f0c1100b155ac115bc41d8` | No complete `model_metadata` |
| Isolated real-data artifact | `base-model-v3` | `ab20ccb9bbbc9f9337639e1b75328e805bc1be88a3d2b9c9783673edbcf08dc7` | `1db2f5ce060de7b073c96d942ff180423e16a01392240bf33e5ca29bb917b4af` | Versioned metadata present |

The experiment-only 30-feature reference recipe and 94-feature hostname-hash candidate ran with a fresh seed-20261013 registrable-domain split. Candidate C had 55 fewer legitimate false positives than A on this same-source test (210 vs 265), with the same 70 phishing false negatives, but the error-rate confidence intervals overlap and C raises `example.com` to 0.976590 (still above its validation threshold). These results are preliminary and do not justify promotion. Full measurements and hashes are in `evaluation_report.md`.

The current prepared CSV hash is `1db2f5ce060de7b073c96d942ff180423e16a01392240bf33e5ca29bb917b4af`. Its 234,687 rows, 134,849 legitimate / 99,838 phishing labels, 197,708 registrable domains, and zero invalid URLs do not match the default v2 artifact's recorded 234,677 rows, 134,849 / 99,828 classes, 175,503 domains, and 10 invalid rows. Both point to the same UCI source-file hash, but the v2 derivation is absent locally. The v2 artifact is therefore not reproducible from the current prepared CSV, and its historical evaluation cannot be treated as comparable to the v3 evaluation.

## Inference path and contract

For the reported scan, the code path is:

`POST /api/scan` → URL normalization → `URLFeatureExtractor.extract` / `to_vector` → `MLService.predict` → CTI provider results → `DecisionEngine.decide` → persistence.

The production contract is the ordered 30-element `phishguard-url-lexical-30-v1` vector. Both inspected artifacts declare that order and contain a `StandardScaler` followed by a `VotingClassifier`; the v3 bundle also records the matching feature schema and preprocessing steps. Inference passes raw ordered features to the serialized pipeline. No feature-order, feature-count, or scaler mismatch was found.

## `example.com` reproduction and root-cause evidence

For `https://example.com/`, the live history record has ML probability **0.8786**, risk score **0.7357**, verdict `suspicious`, and scan mode `degraded`. All three CTI providers are explicitly `mock`; no provider match was fabricated or used in scoring.

Direct inference on the two local artifacts returns:

| Artifact | Probability |
|---|---:|
| `base-model-v2` | 0.871822 |
| `base-model-v3` | 0.878623 |

The latest existing history record's rounded `0.8786` agrees with v3. Its score also agrees with the decision mapping for the v3 suspicious threshold of `0.1285`: `0.4 + ((0.8786 - 0.1285) / (1 - 0.1285)) * 0.39 ≈ 0.7357`. This demonstrates how the stored score was derived; it does not make the classifier output correct.

The exact 30-feature vector is:

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

Re-extracting the current prepared corpus yields **46 rows** with that exact vector, all labeled phishing and none labeled legitimate; no `example.com` host row is present. The URL schema has no hostname spelling or registrable-domain identity feature, so these unlike hosts collapse to an indistinguishable vector. This is direct evidence for a representation/coverage failure in v3 and explains its reproducible prediction without changing a threshold or hardcoding an allowlist. It does not establish which data rows contributed to v2 because v2's recorded dataset hash does not match the local corpus.

The latest stored API record has `model_version: null` and empty `model_metadata`. The running service's `/api/health` endpoint returns `200 {"status":"ok",...}` but does not expose model identity. The historical probability strongly matches the v3 artifact, but the exact binary loaded by the still-running API cannot be proven from non-mutating endpoints. No new scan was submitted because that would append a record to the existing database. This verification gap remains open.

## Existing grouped evaluation (historical, same-source)

The v3 artifact's saved test evaluation is reproducible from the currently available corpus and its recorded split: grouped by registrable domain, with no cross-partition domain overlap.

| Held-out test result | Value |
|---|---:|
| Rows | 35,203 (20,179 legitimate; 15,024 phishing) |
| Confusion matrix (actual rows; legitimate, phishing) | `[[19942, 237], [98, 14926]]` |
| Accuracy / precision / recall / F1 | 0.99048 / 0.98437 / 0.99348 / 0.98890 |
| Legitimate false positives / FPR | 237 / 0.01174 |
| Phishing false negatives / FNR | 98 / 0.00652 |
| PR-AUC / ROC-AUC | 0.99827 / 0.99777 |
| Validation-selected suspicious threshold | 0.1285 |

These are **preliminary, same-source, domain-grouped results**, not time-based or independently sourced performance. This split and its metrics have already been inspected in prior project work; the new experiment uses a different fixed seed and must not be described as an untouched independent-source evaluation.

## Runtime status and limitations

- The API responds on port 8001; current health check passed. The dashboard dev server is listening on port 5173. Health and history were read without writing to the existing database.
- The latest stored scan confirms the score, verdict, degraded mode, and mock provider statuses. The exact live model artifact remains unverified as described above.
- Dataset campaign IDs and per-observation collection dates are unavailable; a time split and campaign-level leakage check cannot be done.
- UCI labels are inherited annotations, not independently re-verified observations.
- The source corpus is from one source. A new held-out domain split within it does not substitute for independent data.
- No raw false-positive or false-negative URLs are published in reports because their query/path components may contain credentials or tokens. New experiment error examples use one-way URL/domain hash prefixes and scores.
- External CTI and reputation services are excluded from ML evaluation.

## Files changed for this audit and experiment

- `ml/experiments/grouped_feature_experiment.py` — reproducible isolated A/C experiment; no production inference changes.
- `tests/test_experimental_hostname_features.py` — protects feature isolation and schema boundary.
- `.gitignore` — excludes local experimental artifact outputs.
- `audit_report.md`, `dataset_audit.md`, `experiment_plan.md`, `evaluation_report.md`, `reproduction_instructions.md` — audit/evaluation deliverables.
