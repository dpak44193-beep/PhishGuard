"""
PhishGuard ML training pipeline entry point.

Usage (from repo root):
    python ml/train.py
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
from pathlib import Path

import numpy as np
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml.features.extractor import FEATURE_ORDER, URLFeatureExtractor  # noqa: E402
from ml.models.trainer import train_base_model, fit_calibrated_bundle, save_model  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent / "data" / "raw"
PROCESSED_DIR = Path(__file__).parent / "data" / "processed"


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
            f"Labeled URL dataset not found: {csv_path}. Download it with "
            "python ml/data/download_dataset.py. Synthetic data is opt-in "
            "through --synthetic and is never used for final evaluation."
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

    return X, y, urls, {
        "kind": "real_labeled_url_csv",
        "dataset": str(csv_path.resolve()),
        "sha256": hashlib.sha256(csv_path.read_bytes()).hexdigest(),
        "sample_count": int(len(y)),
        "class_counts": class_counts,
        "final_evaluation_eligible": True,
    }


def training_output_paths(synthetic: bool) -> tuple[Path, Path]:
    from ml.models.trainer import ARTIFACT_DIR

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
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred)), 4),
        "recall": round(float(recall_score(y_true, y_pred)), 4),
        "f1": round(float(f1_score(y_true, y_pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, y_prob)), 4),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        "classification_report": classification_report(y_true, y_pred, target_names=["legitimate", "phishing"], output_dict=True),
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
    args = parser.parse_args(argv)

    log.info("=== PhishGuard ML Training Pipeline ===")
    csv_path = DATA_DIR / "labeled_urls.csv"
    try:
        X, y, urls, training_data = resolve_training_data(csv_path, synthetic=args.synthetic)
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
    log.info("Training source: %s (%s samples)", training_data["kind"], training_data["sample_count"])

    X_train, X_holdout, y_train, y_holdout = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)
    X_val, X_test, y_val, y_test = train_test_split(X_holdout, y_holdout, test_size=0.5, stratify=y_holdout, random_state=42)
    _, urls_holdout = train_test_split(urls, test_size=0.3, stratify=y, random_state=42)
    val_urls, test_urls = train_test_split(urls_holdout, test_size=0.5, stratify=y_holdout, random_state=42)

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
        "kind": "synthetic_holdout" if args.synthetic else "real_url_csv_holdout",
        "final_evaluation_eligible": not args.synthetic,
        "test_sample_count": int(len(y_test)),
        "threshold_source": "validation_base_model_probability",
        "cti_used_for_training_metrics": False,
    }
    bundle["training_data"] = training_data
    bundle["evaluation"] = evaluation
    bundle["feature_order"] = list(FEATURE_ORDER)

    metrics = _evaluate_scores(y_test, metadata["test_score"], threshold_detail["suspicious"])
    metrics["thresholds"] = thresholds_cfg
    metrics["bias_audit"] = _audit_bias(test_urls, y_test, metadata["test_score"], threshold_detail["suspicious"])
    metrics["training_data"] = training_data
    metrics["evaluation"] = evaluation

    if args.synthetic:
        log.warning("Synthetic holdout metrics are development smoke-test results, not final evaluation.")
    elif metrics["accuracy"] < 0.95:
        log.warning(f"Accuracy {metrics['accuracy']:.2%} is below the 95% target!")
    else:
        log.info(f"Target met: accuracy = {metrics['accuracy']:.2%}")

    artifact_path, metrics_path = training_output_paths(args.synthetic)
    model_path = save_model(bundle, name=artifact_path.name)
    log.info(f"Model bundle saved → {model_path}")

    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics, indent=2))
    log.info(f"Metrics saved → {metrics_path}")


if __name__ == "__main__":
    main()
