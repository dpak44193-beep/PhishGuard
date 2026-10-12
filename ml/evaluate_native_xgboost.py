"""Offline, group-held-out evaluation using XGBoost's native API.

This research experiment avoids scikit-learn because its installed native
extension is blocked in some Windows environments. It does not replace the
runtime model or claim an evaluation of the current RandomForest/XGBoost
ensemble.
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import xgboost as xgb

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ml.data.url_dataset import domain_group, grouped_split_indices
from ml.features.extractor import FEATURE_ORDER, FEATURE_SCHEMA_VERSION, URLFeatureExtractor

CSV_PATH = ROOT / "ml" / "data" / "raw" / "labeled_urls.csv"
MANIFEST_PATH = CSV_PATH.with_suffix(".manifest.json")
REPORT_PATH = ROOT / "ml" / "data" / "processed" / "native_xgboost_experiment.json"
MODEL_PATH = ROOT / "ml" / "models" / "artifacts" / "phishguard_xgboost_native.research.json"
BOOTSTRAP_REPLICATES = 500


def load_verified_data() -> tuple[np.ndarray, np.ndarray, list[str], dict[str, Any]]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    provenance = manifest["provenance"]
    csv_hash = hashlib.sha256(CSV_PATH.read_bytes()).hexdigest()
    source_path = Path(provenance["source_file"])
    if not source_path.is_absolute():
        source_path = ROOT / source_path
    source_hash = hashlib.sha256(source_path.read_bytes()).hexdigest()
    if csv_hash != provenance["derived_file_sha256"]:
        raise ValueError("Prepared dataset checksum does not match its manifest.")
    if source_hash != provenance["source_file_sha256"]:
        raise ValueError("Original source checksum does not match its manifest.")
    if not provenance.get("final_evaluation_eligible"):
        raise ValueError("Dataset manifest does not mark this corpus evaluation-eligible.")

    extractor = URLFeatureExtractor()
    vectors: list[np.ndarray] = []
    labels: list[int] = []
    urls: list[str] = []
    with CSV_PATH.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("label") not in {"0", "1"}:
                raise ValueError("Dataset contains an invalid label.")
            url = row["url"]
            vectors.append(extractor.to_vector(extractor.extract(url)))
            labels.append(int(row["label"]))
            urls.append(url)

    X = np.asarray(vectors, dtype=np.float32)
    y = np.asarray(labels, dtype=np.int8)
    if X.shape != (len(y), len(FEATURE_ORDER)) or len(urls) != len(y):
        raise ValueError("Dataset feature matrix does not match the 30-feature contract.")
    return X, y, urls, provenance


def _rank_auc(labels: np.ndarray, scores: np.ndarray) -> float:
    labels = np.asarray(labels, dtype=np.int8)
    scores = np.asarray(scores, dtype=np.float64)
    positives = int(np.count_nonzero(labels == 1))
    negatives = len(labels) - positives
    if not positives or not negatives:
        return float("nan")
    order = np.argsort(scores, kind="mergesort")
    sorted_scores = scores[order]
    ranks = np.empty(len(scores), dtype=np.float64)
    start = 0
    while start < len(scores):
        end = start + 1
        while end < len(scores) and sorted_scores[end] == sorted_scores[start]:
            end += 1
        ranks[order[start:end]] = (start + 1 + end) / 2
        start = end
    rank_sum = float(ranks[labels == 1].sum())
    return (rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def _average_precision(labels: np.ndarray, scores: np.ndarray) -> float:
    labels = np.asarray(labels, dtype=np.int8)
    scores = np.asarray(scores, dtype=np.float64)
    positives = int(np.count_nonzero(labels == 1))
    if not positives:
        return float("nan")
    order = np.argsort(-scores, kind="mergesort")
    sorted_scores = scores[order]
    sorted_labels = labels[order]
    cumulative_tp = np.cumsum(sorted_labels, dtype=np.int64)
    group_ends = np.r_[np.flatnonzero(sorted_scores[:-1] != sorted_scores[1:]), len(scores) - 1]
    true_positives = cumulative_tp[group_ends]
    predicted_positives = group_ends + 1
    precision = true_positives / predicted_positives
    recall = true_positives / positives
    previous_recall = np.r_[0.0, recall[:-1]]
    return float(np.sum((recall - previous_recall) * precision))


def _threshold_for_best_f1(labels: np.ndarray, scores: np.ndarray) -> float:
    labels = np.asarray(labels, dtype=np.int8)
    scores = np.asarray(scores, dtype=np.float64)
    order = np.argsort(-scores, kind="mergesort")
    sorted_scores = scores[order]
    sorted_labels = labels[order]
    cumulative_tp = np.cumsum(sorted_labels, dtype=np.int64)
    group_ends = np.r_[np.flatnonzero(sorted_scores[:-1] != sorted_scores[1:]), len(scores) - 1]
    tp = cumulative_tp[group_ends]
    predicted_positive = group_ends + 1
    fp = predicted_positive - tp
    fn = int(np.count_nonzero(labels == 1)) - tp
    denominator = 2 * tp + fp + fn
    f1 = np.divide(2 * tp, denominator, out=np.zeros_like(tp, dtype=float), where=denominator > 0)
    best = int(np.argmax(f1))
    return float(sorted_scores[group_ends[best]])


def _metric_values(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, float]:
    labels = np.asarray(labels, dtype=np.int8)
    predictions = np.asarray(scores) >= threshold
    positive = labels == 1
    negative = ~positive
    tp = int(np.count_nonzero(predictions & positive))
    fp = int(np.count_nonzero(predictions & negative))
    fn = int(np.count_nonzero(~predictions & positive))
    tn = int(np.count_nonzero(~predictions & negative))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "accuracy": (tp + tn) / len(labels),
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "pr_auc_average_precision": _average_precision(labels, scores),
        "roc_auc": _rank_auc(labels, scores),
        "confusion_matrix_actual_rows_predicted_columns": [[tn, fp], [fn, tp]],
    }


def _bootstrap_intervals(
    labels: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    groups: np.ndarray,
    *,
    seed: int = 42,
) -> dict[str, list[float]]:
    rng = np.random.default_rng(seed)
    rows_by_group: dict[str, list[int]] = {}
    for row_index, group in enumerate(groups):
        rows_by_group.setdefault(str(group), []).append(row_index)
    group_rows = [np.asarray(indices, dtype=int) for indices in rows_by_group.values()]
    values: dict[str, list[float]] = {}
    for _ in range(BOOTSTRAP_REPLICATES):
        sampled_group_indices = rng.integers(0, len(group_rows), size=len(group_rows))
        indices = np.concatenate([group_rows[index] for index in sampled_group_indices])
        sample = _metric_values(labels[indices], scores[indices], threshold)
        for name, value in sample.items():
            if isinstance(value, (int, float)) and np.isfinite(value):
                values.setdefault(name, []).append(float(value))
    return {
        name: [float(np.quantile(samples, 0.025)), float(np.quantile(samples, 0.975))]
        for name, samples in values.items()
    }


def _evaluate_model(
    y_test: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    test_groups: np.ndarray,
) -> dict[str, Any]:
    return {
        "threshold": float(threshold),
        "metrics": _metric_values(y_test, scores, threshold),
        "bootstrap_95_percent_confidence_intervals": _bootstrap_intervals(
            y_test, scores, threshold, test_groups
        ),
    }


def main() -> None:
    X, y, urls, provenance = load_verified_data()
    train_idx, validation_idx, test_idx = grouped_split_indices(urls, y)
    X_train, y_train = X[train_idx], y[train_idx]
    X_validation, y_validation = X[validation_idx], y[validation_idx]
    X_test, y_test = X[test_idx], y[test_idx]
    all_groups = np.asarray([domain_group(url) for url in urls], dtype=object)
    groups_by_partition = [
        set(all_groups[indices])
        for indices in (train_idx, validation_idx, test_idx)
    ]
    if any(
        groups_by_partition[left].intersection(groups_by_partition[right])
        for left in range(len(groups_by_partition))
        for right in range(left + 1, len(groups_by_partition))
    ):
        raise RuntimeError("Registrable domains overlap across evaluation partitions.")
    test_groups = all_groups[test_idx]

    parameters = {
        "objective": "binary:logistic",
        "eval_metric": "aucpr",
        "tree_method": "hist",
        "max_depth": 6,
        "eta": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "seed": 42,
        "nthread": 4,
    }
    booster = xgb.train(
        parameters,
        xgb.DMatrix(X_train, label=y_train, feature_names=FEATURE_ORDER),
        num_boost_round=500,
        evals=[
            (xgb.DMatrix(X_validation, label=y_validation, feature_names=FEATURE_ORDER), "validation")
        ],
        early_stopping_rounds=30,
        verbose_eval=False,
    )
    validation_scores = booster.predict(
        xgb.DMatrix(X_validation, feature_names=FEATURE_ORDER),
        iteration_range=(0, booster.best_iteration + 1),
    )
    test_scores = booster.predict(
        xgb.DMatrix(X_test, feature_names=FEATURE_ORDER),
        iteration_range=(0, booster.best_iteration + 1),
    )
    selected_threshold = _threshold_for_best_f1(y_validation, validation_scores)

    baseline_label = int(np.bincount(y_train).argmax())
    baseline_scores = np.full(len(y_test), float(baseline_label), dtype=np.float64)
    report = {
        "experiment": "native_xgboost_grouped_url_holdout",
        "status": "completed_alternative_only",
        "current_model_status": (
            "blocked_before_training: scikit-learn sparsefuncs_fast extension denied "
            "by Windows Application Control"
        ),
        "baseline": {
            "model": "majority_class_from_training_partition",
            "training_majority_label": baseline_label,
            "evaluation": _evaluate_model(y_test, baseline_scores, 0.5, test_groups),
        },
        "alternative": {
            "model": "XGBoost native binary:logistic, histogram trees",
            "version": xgb.__version__,
            "parameters": parameters,
            "best_iteration": int(booster.best_iteration),
            "early_stopping_metric": "validation aucpr",
            "threshold_selection": "maximum F1 on validation scores only",
            "evaluation": _evaluate_model(
                y_test, test_scores, selected_threshold, test_groups
            ),
        },
        "feature_contract": {
            "count": len(FEATURE_ORDER),
            "names": FEATURE_ORDER,
            "schema_version": FEATURE_SCHEMA_VERSION,
            "preprocessing": "none; tree model uses raw 30-feature vectors",
            "selection_fit_scope": "no feature selection",
        },
        "split": {
            "strategy": "registrable-domain grouped random split",
            "time_based": False,
            "time_based_limitation": (
                "source has no per-observation dates or documented collection window"
            ),
            "group_overlap": False,
            "random_state": 42,
            "sizes": {
                name: int(len(indices))
                for name, indices in (
                    ("train", train_idx),
                    ("validation", validation_idx),
                    ("test", test_idx),
                )
            },
            "class_counts": {
                name: {
                    "legitimate": int(np.count_nonzero(y[indices] == 0)),
                    "phishing": int(np.count_nonzero(y[indices] == 1)),
                }
                for name, indices in (
                    ("train", train_idx),
                    ("validation", validation_idx),
                    ("test", test_idx),
                )
            },
        },
        "confidence_intervals": {
            "method": (
                "95% percentile cluster bootstrap, 500 resamples of held-out "
                "registrable domains with all rows in each sampled domain"
            ),
            "seed": 42,
        },
        "dataset": {
            "source": provenance["source_url"],
            "license": provenance["license"],
            "derived_csv_sha256": provenance["derived_file_sha256"],
            "source_csv_sha256": provenance["source_file_sha256"],
            "samples": int(len(y)),
            "class_counts": {
                "legitimate": int(np.count_nonzero(y == 0)),
                "phishing": int(np.count_nonzero(y == 1)),
            },
            "urls_fetched": False,
        },
        "deployment_eligible": False,
        "limitations": [
            "The existing scikit-learn RandomForest/XGBoost VotingClassifier was not fit or evaluated.",
            "This native XGBoost alternative is a separate research artifact, not the active runtime model.",
            "No time-based split is possible from the available source metadata.",
            "Registrable-domain isolation cannot guarantee campaign isolation.",
            "Dataset labels are inherited source annotations and were not independently re-verified.",
        ],
    }

    metadata = {
        "training_date_utc": datetime.now(timezone.utc).isoformat(),
        "artifact_version": "native-xgboost-research-v1",
        "dataset_sources": report["dataset"],
        "feature_schema": report["feature_contract"],
        "test_metrics": report["alternative"]["evaluation"]["metrics"],
        "evaluation": report["split"],
        "deployment_eligible": False,
    }
    report["model_metadata"] = metadata
    booster.set_attr(model_metadata=json.dumps(metadata))

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(MODEL_PATH))
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
