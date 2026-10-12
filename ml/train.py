"""
PhishGuard ML training pipeline entry point.

Usage (from repo root):
    python ml/train.py
    python ml/train.py --output-dir ml/models/artifacts/real_data_grouped_run_<unique-name>
    python ml/train.py --synthetic  # development smoke test only

Default training requires labeled_urls.csv in ml/data/raw/ with columns:
    url,label (1=phishing, 0=legitimate)
"""
import argparse
import hashlib
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import numpy as np
from sklearn.metrics import accuracy_score, average_precision_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml.features.extractor import FEATURE_ORDER, FEATURE_SCHEMA_VERSION, URLFeatureExtractor  # noqa: E402
from ml.models.trainer import train_base_model, fit_calibrated_bundle, save_model  # noqa: E402
from ml.data.url_dataset import domain_group, grouped_split_indices  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent / "data" / "raw"
PROCESSED_DIR = Path(__file__).parent / "data" / "processed"
REPO_ROOT = Path(__file__).resolve().parent.parent


def load_url_csv(path: Path) -> tuple[np.ndarray, np.ndarray, list[str]] | tuple[None, None, None]:
    """Extract features and source URLs from a labeled URL CSV (columns: url, label)."""
    import csv

    extractor = URLFeatureExtractor()
    X_rows, y_rows, url_rows = [], [], []
    skipped = 0
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            url = row.get("url", "").strip()
            label = row.get("label", "").strip()
            if not url or label not in ("0", "1"):
                skipped += 1
                continue
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            try:
                feats = extractor.extract(url)
                X_rows.append(extractor.to_vector(feats))
                y_rows.append(int(label))
                url_rows.append(url)
            except Exception:
                skipped += 1

    if not X_rows:
        return None, None, None
    if skipped:
        log.info(f"Skipped {skipped} malformed rows.")
    return np.array(X_rows, dtype=float), np.array(y_rows), url_rows


def generate_synthetic_data(n: int = 12_000) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """
    Synthetic feature vectors calibrated to FEATURE_ORDER distributions.
    Legitimate: varied-depth HTTPS URLs, low entropy, no risky signals.
    Phishing: long HTTP URLs, high entropy, suspicious keywords, risky TLDs.
    Per-feature std used so binary features stay near {0,1} and continuous
    features get realistic variance.
    """
    log.info("Generating synthetic training data…")
    rng = np.random.default_rng(42)
    half = n // 2

    # Feature order matches FEATURE_ORDER in extractor.py exactly:
    # url_length, domain_length, subdomain_count, has_ip, uses_https,
    # dot_count, hyphen_count, at_sign_count, special_char_count, digit_ratio,
    # entropy, suspicious_keywords, is_url_shortener, tld_risk, path_depth,
    # query_param_count, has_encoded_chars, double_slash_in_path, has_port,
    # is_punycode, tilde_in_path, hex_in_domain, redirect_double_slash,
    # domain_digit_count, url_shortener_flag, brand_count,
    # num_dots_in_path, query_length, fragment_present, multi_subdomain
    legit_means = [40,  12, 0,   0,   1,   3,  0,   0,   1,   0.05, 3.5, 0,   0,   0,   2,  1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   1,  15,  0,   0  ]
    phish_means = [95,  28, 2,   0.3, 0.2, 7,  2,   0.5, 7,   0.25, 4.8, 3,   0.2, 0.4, 3,  2,   0.6, 0.3, 0.2, 0.1, 0.1, 0.2, 0.3, 4,   0.2, 0.8, 2,  30,  0.1, 0.6]
    # Per-feature std — binary/rate features get small std; continuous get larger
    legit_std  = [15,   5, 0.3, 0.1, 0.1, 1,  0.3, 0.1, 1,   0.05, 0.4, 0.2, 0.1, 0.1, 1.5,0.8, 0.1, 0.05,0.05,0.05,0.05,0.05,0.05,1,   0.1, 0.2, 0.8,10,  0.05,0.2 ]
    phish_std  = [25,   8, 1,   0.3, 0.3, 2,  1,   0.3, 3,   0.1,  0.5, 1,   0.3, 0.4, 1.5,1,   0.3, 0.2, 0.2, 0.2, 0.2, 0.3, 0.3, 2,   0.3, 0.4, 1,  15,  0.2, 0.4 ]

    legit_X = rng.normal(loc=legit_means, scale=legit_std, size=(half, 30)).clip(0)
    phish_X = rng.normal(loc=phish_means, scale=phish_std, size=(half, 30)).clip(0)

    X = np.vstack([legit_X, phish_X])
    y = np.concatenate([np.zeros(half), np.ones(half)])
    idx = rng.permutation(len(y))
    urls = [f"https://synthetic-{i}.example/{'secure' if label else 'home'}" for i, label in enumerate(y)]
    urls = [urls[i] for i in idx]
    return X[idx], y[idx], urls


def resolve_training_data(
    csv_path: Path,
    *,
    synthetic: bool = False,
    synthetic_samples: int = 12_000,
) -> tuple[np.ndarray, np.ndarray, list[str], dict[str, object]]:
    if synthetic:
        X, y, urls = generate_synthetic_data(synthetic_samples)
        return X, y, urls, {
            "kind": "synthetic",
            "dataset": "generated_feature_distributions",
            "sample_count": int(len(y)),
            "seed": 42,
            "final_evaluation_eligible": False,
        }

    if not csv_path.is_file():
        raise FileNotFoundError(
            f"Labeled URL dataset not found: {csv_path}. Prepare it from the local "
            "UCI source CSV with python ml/data/download_dataset.py. Synthetic data "
            "is opt-in through --synthetic and is never used for final evaluation."
        )

    try:
        X, y, urls = load_url_csv(csv_path)
    except Exception as exc:
        raise ValueError(f"Could not read labeled URL dataset {csv_path}: {exc}") from exc

    if X is None or y is None or urls is None:
        raise ValueError(f"Labeled URL dataset contains no usable rows: {csv_path}")

    class_counts = {
        "legitimate": int(np.count_nonzero(y == 0)),
        "phishing": int(np.count_nonzero(y == 1)),
    }
    if min(class_counts.values()) < 10:
        raise ValueError("Labeled URL dataset must contain at least 10 rows for each class.")

    manifest_path = csv_path.with_suffix(".manifest.json")
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not read dataset manifest {manifest_path}: {exc}") from exc
        if not isinstance(manifest, dict) or not isinstance(manifest.get("provenance"), dict):
            raise ValueError(f"Dataset manifest {manifest_path} has no valid provenance object.")
        manifest_provenance = manifest["provenance"]
        if manifest_provenance.get("derived_file_sha256") != hashlib.sha256(
            csv_path.read_bytes()
        ).hexdigest():
            raise ValueError(
                f"Dataset manifest checksum does not match {csv_path}; regenerate the "
                "dataset from its documented source before training."
            )
        source_file_value = manifest_provenance.get("source_file")
        source_file_hash = manifest_provenance.get("source_file_sha256")
        if source_file_value is not None and not isinstance(source_file_value, str):
            raise ValueError(f"Dataset manifest {manifest_path} has an invalid source_file.")
        source_file = Path(source_file_value) if source_file_value else None
        if source_file is not None and not source_file.is_absolute():
            source_file = REPO_ROOT / source_file
        source_file_verified = bool(
            source_file
            and source_file.is_file()
            and source_file_hash
            and hashlib.sha256(source_file.read_bytes()).hexdigest() == source_file_hash
        )
        if source_file and source_file.is_file() and not source_file_verified:
            raise ValueError(
                f"Dataset manifest checksum does not match source file {source_file}."
            )
        documented_source = all(
            manifest_provenance.get(field)
            for field in (
                "source_url", "license", "attribution", "prepared_at_utc",
                "source_file_sha256", "source_observation_collection_note",
            )
        ) and "source_observation_collection_window" in manifest_provenance
        recorded_domain_tool = manifest_provenance.get("registrable_domain_extractor")
        if not isinstance(recorded_domain_tool, dict):
            recorded_domain_tool = {}
        try:
            domain_tool_matches = (
                recorded_domain_tool.get("package") == "tldextract"
                and recorded_domain_tool.get("version") == version("tldextract")
                and recorded_domain_tool.get("network_suffix_list_fetch") is False
            )
        except PackageNotFoundError:
            domain_tool_matches = False
        provenance: dict[str, object] = {
            "kind": manifest_provenance.get("kind", "unverified_csv"),
            "source": manifest_provenance,
            "manifest": (
                manifest.get("dataset_summary", {})
                if isinstance(manifest.get("dataset_summary", {}), dict)
                else {}
            ),
            "manifest_path": str(manifest_path.resolve()),
            "final_evaluation_eligible": bool(
                manifest_provenance.get("final_evaluation_eligible")
                and documented_source
                and source_file_verified
                and domain_tool_matches
            ),
        }
        if not source_file_verified:
            provenance["eligibility_limitation"] = (
                "The original source file is missing or its checksum is unavailable."
            )
        if not domain_tool_matches:
            provenance["eligibility_limitation"] = (
                "The offline registrable-domain extractor version does not match "
                "the dataset manifest."
            )
    else:
        log.warning(
            "No dataset manifest found beside %s; results will not be eligible "
            "for final evaluation claims.",
            csv_path,
        )
        provenance = {
            "kind": "unverified_labeled_url_csv",
            "dataset": str(csv_path.resolve()),
            "final_evaluation_eligible": False,
            "limitation": "No source, license, collection-date, and label manifest was found.",
        }

    provenance.update({
        "dataset": str(csv_path.resolve()),
        "sha256": hashlib.sha256(csv_path.read_bytes()).hexdigest(),
        "sample_count": int(len(y)),
        "class_counts": class_counts,
    })
    return X, y, urls, provenance


def training_output_paths(
    synthetic: bool,
    output_dir: Path | None = None,
) -> tuple[Path, Path]:
    from ml.models.trainer import ARTIFACT_DIR

    if output_dir is not None:
        model_name = (
            "phishguard_model.synthetic.joblib"
            if synthetic
            else "phishguard_model.joblib"
        )
        metrics_name = (
            "synthetic_metrics.json" if synthetic else "metrics.json"
        )
        return output_dir / model_name, output_dir / metrics_name

    if synthetic:
        return (
            ARTIFACT_DIR / "phishguard_model.synthetic.joblib",
            PROCESSED_DIR / "synthetic_metrics.json",
        )
    return (
        ARTIFACT_DIR / "phishguard_model.joblib",
        PROCESSED_DIR / "metrics.json",
    )


def _evaluate_scores(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> dict:
    y_pred = (y_prob >= threshold).astype(int)
    matrix = confusion_matrix(y_true, y_pred)
    true_negative, false_positive = (int(value) for value in matrix[0])
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "false_positive_rate": round(
            false_positive / (false_positive + true_negative), 4
        ) if false_positive + true_negative else 0.0,
        "pr_auc_average_precision": round(
            float(average_precision_score(y_true, y_prob)), 4
        ),
        "roc_auc": round(float(roc_auc_score(y_true, y_prob)), 4),
        "confusion_matrix": matrix.tolist(),
        "classification_report": classification_report(
            y_true,
            y_pred,
            target_names=["legitimate", "phishing"],
            output_dict=True,
            zero_division=0,
        ),
    }


def _bootstrap_metric_intervals(
    labels: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    groups: np.ndarray,
    *,
    replicates: int = 500,
    seed: int = 42,
) -> dict[str, list[float]]:
    rng = np.random.default_rng(seed)
    rows_by_group: dict[str, list[int]] = defaultdict(list)
    for row_index, group in enumerate(groups):
        rows_by_group[str(group)].append(row_index)
    group_rows = [np.asarray(indices, dtype=int) for indices in rows_by_group.values()]
    bootstrap_values: dict[str, list[float]] = defaultdict(list)

    for _ in range(replicates):
        sampled_groups = rng.integers(0, len(group_rows), size=len(group_rows))
        indices = np.concatenate([group_rows[index] for index in sampled_groups])
        sample_labels = labels[indices]
        sample_scores = scores[indices]
        sample_predictions = sample_scores >= threshold
        positive = sample_labels == 1
        negative = ~positive
        tp = int(np.count_nonzero(sample_predictions & positive))
        fp = int(np.count_nonzero(sample_predictions & negative))
        fn = int(np.count_nonzero(~sample_predictions & positive))
        tn = int(np.count_nonzero(~sample_predictions & negative))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        values = {
            "accuracy": (tp + tn) / len(indices),
            "precision": precision,
            "recall": recall,
            "f1": (
                2 * precision * recall / (precision + recall)
                if precision + recall
                else 0.0
            ),
            "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
            "pr_auc_average_precision": float(
                average_precision_score(sample_labels, sample_scores)
            ),
        }
        if np.unique(sample_labels).size == 2:
            values["roc_auc"] = float(roc_auc_score(sample_labels, sample_scores))
        for name, value in values.items():
            bootstrap_values[name].append(value)

    return {
        name: [
            float(np.quantile(values, 0.025)),
            float(np.quantile(values, 0.975)),
        ]
        for name, values in bootstrap_values.items()
    }


def _audit_bias(urls: list[str], y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> dict:
    extractor = URLFeatureExtractor()
    y_pred = (y_prob >= threshold).astype(int)
    y_true = np.asarray(y_true)

    tld_buckets: dict[str, list[int]] = defaultdict(list)
    keyword_buckets: dict[str, list[int]] = defaultdict(list)

    for url, truth, pred in zip(urls, y_true, y_pred):
        if truth != 0:
            continue
        parsed = extractor.extract(url)
        domain = url.split("//", 1)[-1].split("/", 1)[0]
        tld = "." + domain.split(".")[-1] if "." in domain else ""
        tld_buckets[tld].append(int(pred == 1))
        keyword_buckets["keyword_present" if parsed["suspicious_keywords"] else "keyword_absent"].append(int(pred == 1))

    def summarize(buckets: dict[str, list[int]]) -> list[dict[str, object]]:
        rows = []
        for bucket, values in sorted(buckets.items(), key=lambda item: item[0]):
            if not values:
                continue
            rows.append({"bucket": bucket, "legit_count": len(values), "false_positive_rate": round(float(sum(values) / len(values)), 4)})
        return rows

    return {"by_tld": summarize(tld_buckets), "by_keyword_bucket": summarize(keyword_buckets)}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Train the PhishGuard 30-feature URL model")
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="run a development smoke test on generated data (not final evaluation)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help=(
            "write the model and metrics into this directory instead of the "
            "default artifact locations; the directory must not already exist"
        ),
    )
    args = parser.parse_args(argv)
    if args.output_dir is not None and args.output_dir.exists():
        parser.error(
            f"Refusing to overwrite existing output directory: {args.output_dir}"
        )

    log.info("=== PhishGuard ML Training Pipeline ===")
    csv_path = DATA_DIR / "labeled_urls.csv"
    try:
        X, y, urls, training_data = resolve_training_data(csv_path, synthetic=args.synthetic)
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
    log.info("Training source: %s (%s samples)", training_data["kind"], training_data["sample_count"])

    train_indices, val_indices, test_indices = grouped_split_indices(urls, y)
    X_train, y_train = X[train_indices], y[train_indices]
    X_val, y_val = X[val_indices], y[val_indices]
    X_test, y_test = X[test_indices], y[test_indices]
    val_urls = [urls[index] for index in val_indices]
    test_urls = [urls[index] for index in test_indices]
    split_indices = {
        "train": train_indices,
        "validation": val_indices,
        "test": test_indices,
    }
    split_summary = {}
    for split_name, indices in split_indices.items():
        split_labels = y[indices]
        split_summary[split_name] = {
            "rows": int(len(indices)),
            "class_counts": {
                "legitimate": int(np.count_nonzero(split_labels == 0)),
                "phishing": int(np.count_nonzero(split_labels == 1)),
            },
            "registrable_domains": len({
                domain_group(urls[index]) for index in indices
            }),
        }

    log.info(f"Train: {len(y_train):,}  |  Val: {len(y_val):,}  |  Test: {len(y_test):,}")

    log.info("Training base classifier (XGBoost + RandomForest when XGBoost is installed)…")
    base_model = train_base_model(X_train, y_train)

    bundle, thresholds_cfg, metadata, threshold_detail = fit_calibrated_bundle(
        base_model,
        X_val,
        y_val,
        val_urls,
        X_test,
        y_test,
        test_urls,
    )

    evaluation = {
        "kind": (
            "synthetic_holdout"
            if args.synthetic
            else "registrable_domain_grouped_url_csv_holdout"
        ),
        "final_evaluation_eligible": bool(
            not args.synthetic and training_data["final_evaluation_eligible"]
        ),
        "test_sample_count": int(len(y_test)),
        "split_group_key": "registrable_domain",
        "split_summary": split_summary,
        "threshold_source": "validation_base_model_probability",
        "cti_used_for_training_metrics": False,
    }
    bundle["training_data"] = training_data
    bundle["evaluation"] = evaluation
    bundle["feature_order"] = list(FEATURE_ORDER)

    metrics = _evaluate_scores(y_test, metadata["test_score"], threshold_detail["suspicious"])
    metrics["thresholds"] = thresholds_cfg
    metrics["bias_audit"] = _audit_bias(test_urls, y_test, metadata["test_score"], threshold_detail["suspicious"])
    majority_label = int(np.bincount(y_train.astype(int)).argmax())
    baseline_scores = np.full(len(y_test), majority_label, dtype=float)
    metrics["majority_class_baseline"] = {
        "training_majority_label": majority_label,
        "threshold": 0.5,
        "metrics": _evaluate_scores(y_test, baseline_scores, 0.5),
    }
    metrics["bootstrap_95_percent_confidence_intervals"] = (
        _bootstrap_metric_intervals(
            y_test,
            metadata["test_score"],
            threshold_detail["suspicious"],
            np.asarray([
                domain_group(test_urls[index])
                for index in range(len(test_urls))
            ], dtype=object),
        )
    )
    metrics["confidence_interval_method"] = (
        "95% percentile cluster bootstrap; 500 resamples of held-out "
        "registrable domains with all rows per sampled domain"
    )
    metrics["training_data"] = training_data
    metrics["evaluation"] = evaluation
    source_provenance = training_data.get("source", {})
    bundle["feature_schema_version"] = FEATURE_SCHEMA_VERSION
    bundle["model_metadata"] = {
        "training_date_utc": datetime.now(timezone.utc).isoformat(),
        "artifact_version": bundle["version"],
        "dataset_sources": {
            "kind": training_data.get("kind"),
            "source_url": (
                source_provenance.get("source_url")
                if isinstance(source_provenance, dict)
                else None
            ),
            "source_sha256": (
                source_provenance.get("source_file_sha256")
                if isinstance(source_provenance, dict)
                else None
            ),
            "license": (
                source_provenance.get("license")
                if isinstance(source_provenance, dict)
                else None
            ),
            "attribution": (
                source_provenance.get("attribution")
                if isinstance(source_provenance, dict)
                else None
            ),
            "derived_dataset_sha256": training_data.get("sha256"),
        },
        "feature_schema": {
            "version": FEATURE_SCHEMA_VERSION,
            "names": list(FEATURE_ORDER),
            "inference_input": "raw ordered URLFeatureExtractor vector",
            "pipeline_steps": [
                name for name, _ in base_model.named_steps.items()
            ] if hasattr(base_model, "named_steps") else [],
        },
        "test_metrics": {
            key: metrics[key]
            for key in (
                "accuracy",
                "precision",
                "recall",
                "f1",
                "false_positive_rate",
                "pr_auc_average_precision",
                "roc_auc",
                "confusion_matrix",
            )
        },
        "evaluation": evaluation,
    }

    if args.synthetic:
        log.warning("Synthetic holdout metrics are development smoke-test results, not final evaluation.")
    elif evaluation["final_evaluation_eligible"] and metrics["accuracy"] < 0.95:
        log.warning(f"Accuracy {metrics['accuracy']:.2%} is below the 95% target!")
    else:
        log.info(f"Target met: accuracy = {metrics['accuracy']:.2%}")

    output_dir = args.output_dir.resolve() if args.output_dir else None
    artifact_path, metrics_path = training_output_paths(
        args.synthetic,
        output_dir=output_dir,
    )
    model_path = save_model(bundle, name=artifact_path)
    log.info(f"Model bundle saved → {model_path}")

    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics, indent=2))
    log.info(f"Metrics saved → {metrics_path}")


if __name__ == "__main__":
    main()
