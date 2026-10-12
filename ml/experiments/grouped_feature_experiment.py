"""Run isolated, domain-grouped URL feature experiments without network access."""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from statistics import median
from time import perf_counter
from urllib.parse import urlsplit

import joblib
import numpy as np
from sklearn.feature_extraction import FeatureHasher
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml.data.url_dataset import domain_group, grouped_split_indices  # noqa: E402
from ml.features.extractor import (  # noqa: E402
    FEATURE_ORDER,
    FEATURE_SCHEMA_VERSION,
    URLFeatureExtractor,
)
from ml.models.trainer import build_pipeline  # noqa: E402
from ml.train import resolve_training_data  # noqa: E402

LOG = logging.getLogger("phishguard.feature_experiment")
HOST_HASH_FEATURES = 64
HOST_HASH_SCHEMA_VERSION = "phishguard-url-lexical-30-plus-host-charhash64-v1"
HOST_NGRAM_LENGTHS = (3, 4, 5)
TOKEN_PREFIX = "host-char"
MODEL_SEED = 42
_HOST_HASHER = FeatureHasher(
    n_features=HOST_HASH_FEATURES,
    input_type="string",
    alternate_sign=False,
    dtype=np.float32,
)


def _host_ngrams(url: str) -> list[str]:
    """Extract character n-grams from the hostname only; never visit or resolve a URL."""
    hostname = urlsplit(url).hostname or ""
    hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    bounded = f"^{hostname}$"
    return [
        f"{TOKEN_PREFIX}-{size}:{bounded[index:index + size]}"
        for size in HOST_NGRAM_LENGTHS
        for index in range(max(0, len(bounded) - size + 1))
    ]


def host_character_hash_features(
    urls: list[str],
    *,
    n_features: int = HOST_HASH_FEATURES,
    batch_size: int = 2048,
) -> np.ndarray:
    """Create fixed-width hostname character features without fitting on any split."""
    if n_features < 1 or batch_size < 1:
        raise ValueError("n_features and batch_size must be positive.")
    if n_features != HOST_HASH_FEATURES:
        raise ValueError(f"Experiment schema requires exactly {HOST_HASH_FEATURES} hash bins.")
    result = np.zeros((len(urls), n_features), dtype=np.float32)
    for start in range(0, len(urls), batch_size):
        batch = urls[start:start + batch_size]
        result[start:start + len(batch)] = _HOST_HASHER.transform(
            [_host_ngrams(url) for url in batch]
        ).toarray()
    return result


def build_host_feature_matrix(base_features: np.ndarray, urls: list[str]) -> np.ndarray:
    """Append the experiment-only host representation; keep the production schema intact."""
    if base_features.ndim != 2 or base_features.shape[1] != len(FEATURE_ORDER):
        raise ValueError("Base features do not match the production 30-feature schema.")
    if len(base_features) != len(urls):
        raise ValueError("URL count does not match the feature matrix.")
    host_features = host_character_hash_features(urls)
    return np.hstack((base_features, host_features))


def _choose_threshold(labels: np.ndarray, scores: np.ndarray) -> float:
    from sklearn.metrics import precision_recall_curve

    precision, recall, thresholds = precision_recall_curve(labels, scores)
    chosen: float | None = None
    chosen_recall = -1.0
    fallback = 0.5
    fallback_f1 = -1.0
    for p_value, r_value, threshold in zip(
        precision[1:], recall[1:], thresholds
    ):
        if p_value + r_value:
            score = 2 * p_value * r_value / (p_value + r_value)
            if score > fallback_f1:
                fallback_f1 = float(score)
                fallback = float(threshold)
        if p_value >= 0.98 and r_value >= chosen_recall:
            chosen = float(threshold)
            chosen_recall = float(r_value)
    return chosen if chosen is not None else fallback


def _metrics(
    labels: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    urls: list[str],
) -> dict[str, object]:
    predictions = scores >= threshold
    tn, fp, fn, tp = (
        int(value)
        for value in confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    )
    false_positive_rows = np.flatnonzero((labels == 0) & predictions)
    false_negative_rows = np.flatnonzero((labels == 1) & ~predictions)
    fp_domains = {domain_group(urls[i]) for i in false_positive_rows}
    fn_domains = {domain_group(urls[i]) for i in false_negative_rows}

    def redacted_examples(indices: np.ndarray) -> list[dict[str, object]]:
        return [
            {
                "url_sha256_prefix": hashlib.sha256(
                    urls[int(index)].encode("utf-8")
                ).hexdigest()[:16],
                "domain_sha256_prefix": hashlib.sha256(
                    domain_group(urls[int(index)]).encode("utf-8")
                ).hexdigest()[:16],
                "probability": round(float(scores[int(index)]), 6),
            }
            for index in indices[:10]
        ]

    return {
        "sample_count": int(len(labels)),
        "class_distribution": {
            "legitimate": int(np.count_nonzero(labels == 0)),
            "phishing": int(np.count_nonzero(labels == 1)),
        },
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else 0.0,
        "pr_auc_average_precision": float(average_precision_score(labels, scores)),
        "roc_auc": float(roc_auc_score(labels, scores)),
        "confusion_matrix_actual_rows_predicted_columns": [[tn, fp], [fn, tp]],
        "legitimate_false_positive_count": fp,
        "phishing_false_negative_count": fn,
        "false_positive_domain_count": len(fp_domains),
        "false_negative_domain_count": len(fn_domains),
        "false_positive_examples_redacted": redacted_examples(false_positive_rows),
        "false_negative_examples_redacted": redacted_examples(false_negative_rows),
    }


def _cluster_intervals(
    labels: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    urls: list[str],
    *,
    replicates: int,
    seed: int,
) -> dict[str, list[float]]:
    groups: dict[str, list[int]] = {}
    for index, url in enumerate(urls):
        groups.setdefault(domain_group(url), []).append(index)
    rows_by_group = [np.asarray(indices, dtype=int) for indices in groups.values()]
    rng = np.random.default_rng(seed)
    metrics: dict[str, list[float]] = {
        name: [] for name in ("accuracy", "precision", "recall", "f1", "fpr", "fnr")
    }
    for _ in range(replicates):
        multiplicities = np.bincount(
            rng.integers(0, len(rows_by_group), size=len(rows_by_group)),
            minlength=len(rows_by_group),
        )
        weights = np.zeros(len(labels), dtype=np.int32)
        for group_index, rows in enumerate(rows_by_group):
            if multiplicities[group_index]:
                weights[rows] = multiplicities[group_index]
        predicted = scores >= threshold
        positive = labels == 1
        negative = ~positive
        tp = int(np.sum(weights * (predicted & positive)))
        fp = int(np.sum(weights * (predicted & negative)))
        fn = int(np.sum(weights * (~predicted & positive)))
        tn = int(np.sum(weights * (~predicted & negative)))
        total = tp + fp + fn + tn
        precision_value = tp / (tp + fp) if tp + fp else 0.0
        recall_value = tp / (tp + fn) if tp + fn else 0.0
        values = {
            "accuracy": (tp + tn) / total if total else 0.0,
            "precision": precision_value,
            "recall": recall_value,
            "f1": (
                2 * precision_value * recall_value
                / (precision_value + recall_value)
                if precision_value + recall_value
                else 0.0
            ),
            "fpr": fp / (fp + tn) if fp + tn else 0.0,
            "fnr": fn / (fn + tp) if fn + tp else 0.0,
        }
        for name, value in values.items():
            metrics[name].append(value)
    return {
        name: [
            float(np.quantile(values, 0.025)),
            float(np.quantile(values, 0.975)),
        ]
        for name, values in metrics.items()
    }


def _latency_ms_per_url(
    model,
    urls: list[str],
    extractor: URLFeatureExtractor,
    *,
    include_host_features: bool,
) -> float:
    sample = urls[:256]
    timings: list[float] = []
    for _ in range(3):
        start = perf_counter()
        for url in sample:
            vector = extractor.to_vector(extractor.extract(url)).reshape(1, -1)
            if include_host_features:
                host = host_character_hash_features([url])
                vector = np.hstack((vector, host))
            model.predict_proba(vector)
        timings.append((perf_counter() - start) * 1000 / len(sample))
    return float(median(timings))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _package_version(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def run_experiment(
    output_dir: Path,
    *,
    dataset_path: Path,
    random_state: int,
    bootstrap_replicates: int,
) -> Path:
    if output_dir.exists():
        raise FileExistsError(f"Refusing to overwrite existing output directory: {output_dir}")
    if bootstrap_replicates < 1:
        raise ValueError("bootstrap_replicates must be positive.")

    X, y, urls, source = resolve_training_data(dataset_path)
    y = np.asarray(y, dtype=int)
    X_host = build_host_feature_matrix(X, urls)
    train_indices, validation_indices, test_indices = grouped_split_indices(
        urls, y, random_state=random_state
    )
    partitions = {
        "train": train_indices,
        "validation": validation_indices,
        "test": test_indices,
    }
    domain_sets = {
        name: {domain_group(urls[int(i)]) for i in indices}
        for name, indices in partitions.items()
    }
    overlaps = {
        f"{left}_{right}": len(domain_sets[left] & domain_sets[right])
        for left, right in (
            ("train", "validation"),
            ("train", "test"),
            ("validation", "test"),
        )
    }
    if any(overlaps.values()):
        raise RuntimeError(f"Registrable-domain leakage detected: {overlaps}")

    output_dir.mkdir(parents=True)
    extractor = URLFeatureExtractor()
    candidates: dict[str, tuple[np.ndarray, str, list[str], bool]] = {
        "candidate_a_30_feature_baseline": (
            X,
            FEATURE_SCHEMA_VERSION,
            list(FEATURE_ORDER),
            False,
        ),
        "candidate_c_host_charhash64": (
            X_host,
            HOST_HASH_SCHEMA_VERSION,
            list(FEATURE_ORDER)
            + [f"host_char_hash_{i:02d}" for i in range(HOST_HASH_FEATURES)],
            True,
        ),
    }
    reports: dict[str, object] = {}
    artifacts: dict[str, str] = {}

    for name, (matrix, schema_version, feature_order, use_host_features) in candidates.items():
        LOG.info("Training %s (%s features)", name, matrix.shape[1])
        model = build_pipeline()
        model.fit(matrix[train_indices], y[train_indices])

        validation_scores = model.predict_proba(matrix[validation_indices])[:, 1]
        threshold = _choose_threshold(y[validation_indices], validation_scores)
        test_scores = model.predict_proba(matrix[test_indices])[:, 1]
        test_urls = [urls[int(i)] for i in test_indices]
        candidate_metrics = _metrics(
            y[test_indices], test_scores, threshold, test_urls
        )
        candidate_metrics["confidence_intervals_95_percent_clustered_by_domain"] = (
            _cluster_intervals(
                y[test_indices],
                test_scores,
                threshold,
                test_urls,
                replicates=bootstrap_replicates,
                seed=random_state,
            )
        )
        candidate_metrics["latency_ms_per_url_median_3_runs_including_features"] = (
            _latency_ms_per_url(
                model,
                test_urls,
                extractor,
                include_host_features=use_host_features,
            )
        )
        bundle = {
            "base_model": model,
            "thresholds": {"suspicious": threshold},
            "version": name,
            "feature_order": feature_order,
            "feature_schema_version": schema_version,
            "training_data": source,
            "model_metadata": {
                "artifact_version": name,
                "training_date_utc": datetime.now(timezone.utc).isoformat(),
                "dataset_sha256": _sha256(dataset_path),
                "feature_schema": {
                    "version": schema_version,
                    "names": feature_order,
                    "pipeline_steps": [step_name for step_name, _ in model.steps],
                },
                "threshold_source": "validation_only",
                "split_seed": random_state,
                "model_random_state": MODEL_SEED,
                "metrics": candidate_metrics,
                "external_runtime_dependencies": [],
            },
        }
        artifact_path = output_dir / f"{name}.joblib"
        joblib.dump(bundle, artifact_path)
        artifact_hash = _sha256(artifact_path)
        artifacts[name] = artifact_hash
        candidate_metrics["artifact_sha256"] = artifact_hash
        reports[name] = candidate_metrics

    split_summary = {
        name: {
            "rows": int(len(indices)),
            "legitimate": int(np.count_nonzero(y[indices] == 0)),
            "phishing": int(np.count_nonzero(y[indices] == 1)),
            "registrable_domains": len(domain_sets[name]),
        }
        for name, indices in partitions.items()
    }
    result = {
        "experiment_status": "completed_same_source_domain_grouped_holdout",
        "promotion_status": "not_authorized_or_recommended",
        "dataset": {
            "path": str(dataset_path),
            "sha256": _sha256(dataset_path),
            "rows": int(len(y)),
            "legitimate": int(np.count_nonzero(y == 0)),
            "phishing": int(np.count_nonzero(y == 1)),
            "provenance": source,
        },
        "methodology": {
            "split_group": "registrable_domain",
            "random_state": random_state,
            "proportions": [0.70, 0.15, 0.15],
            "split_summary": split_summary,
            "domain_overlap_counts": overlaps,
            "preprocessing_fit_scope": "training partition only",
            "threshold_tuning_scope": "validation partition only; target precision 0.98, maximum recall, maximum-F1 fallback",
            "test_scope": "evaluated after thresholds fixed; shared once across candidates",
            "cti_used": False,
            "url_visits_or_dns": False,
            "bootstrap_replicates": bootstrap_replicates,
            "bootstrap_seed": random_state,
            "model_random_state": MODEL_SEED,
        },
        "features": {
            "candidate_a": FEATURE_SCHEMA_VERSION,
            "candidate_c": HOST_HASH_SCHEMA_VERSION,
            "candidate_c_description": (
                "The existing ordered 30 lexical features plus 64 fixed-hash bins "
                "of hostname-only 3-, 4-, and 5-character n-grams. Hashing has no "
                "fit state; the StandardScaler and classifier fit on train only."
            ),
        },
        "runtime_versions": {
            "python": sys.version.split()[0],
            "scikit_learn": _package_version("scikit-learn"),
            "xgboost": _package_version("xgboost"),
        },
        "artifacts": artifacts,
        "candidates": reports,
    }
    metrics_path = output_dir / "metrics.json"
    metrics_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return metrics_path


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=REPO_ROOT / "ml/data/raw/labeled_urls.csv")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20261013)
    parser.add_argument("--bootstrap-replicates", type=int, default=200)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )
    output_dir = args.output_dir
    if not output_dir.is_absolute():
        output_dir = REPO_ROOT / output_dir
    dataset_path = args.dataset
    if not dataset_path.is_absolute():
        dataset_path = REPO_ROOT / dataset_path
    metrics_path = run_experiment(
        output_dir,
        dataset_path=dataset_path,
        random_state=args.seed,
        bootstrap_replicates=args.bootstrap_replicates,
    )
    print(metrics_path)


if __name__ == "__main__":
    main()
