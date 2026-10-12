"""Run a research-only evaluation on the UCI PhiUSIIL engineered feature table.

This is separate from ml/train.py because the feature table's engineered
columns do not match the 30 live lexical features. It deduplicates by normalized
URL and uses registrable-domain groups for its research holdout. URL strings
are parsed offline; no row URL is fetched, resolved, or visited.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path
from collections import Counter, defaultdict

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml.models.evaluator import evaluate
from ml.models.trainer import build_pipeline, save_model
from ml.features.extractor import FEATURE_ORDER
from ml.data.url_dataset import domain_group, grouped_split_indices, normalize_url

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET = REPO_ROOT / "PhiUSIIL_Phishing_URL_Dataset.csv"
ALT_DATASET = REPO_ROOT / "ml" / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"
ARTIFACT_NAME = "phiusiil_feature_research_model.joblib"
METRICS_PATH = REPO_ROOT / "ml" / "data" / "processed" / "phiusiil_feature_metrics.json"


def resolve_dataset_path(explicit_path: str | None) -> Path:
    if explicit_path:
        path = Path(explicit_path)
        if not path.exists():
            raise FileNotFoundError(f"Dataset not found: {path}")
        return path

    for candidate in (DEFAULT_DATASET, ALT_DATASET):
        if candidate.exists():
            return candidate

    raise FileNotFoundError(
        "Could not find the UCI PhiUSIIL dataset. Place PhiUSIIL_Phishing_URL_Dataset.csv "
        "at the repo root or under ml/data/raw/, or pass --dataset PATH."
    )


def load_dataset(
    path: Path,
) -> tuple[pd.DataFrame, pd.Series, list[str], list[str], dict[str, int | bool]]:
    frame = pd.read_csv(path)
    if "label" not in frame.columns:
        raise ValueError("Expected a label column in the UCI feature table.")
    url_column = "URL" if "URL" in frame.columns else "url" if "url" in frame.columns else None
    if url_column is None:
        raise ValueError("Expected a URL column for deduplication and domain grouping.")

    numeric = frame.select_dtypes(include="number").copy()
    if "label" not in numeric.columns:
        numeric["label"] = frame["label"]

    feature_columns = [column for column in numeric.columns if column != "label"]
    labels = pd.to_numeric(numeric["label"], errors="coerce")
    first_by_identity: dict[str, int] = {}
    identity_labels: dict[str, set[int]] = defaultdict(set)
    identity_counts: Counter[str] = Counter()
    normalized_by_row: dict[int, str] = {}
    invalid_url_rows = 0
    invalid_label_rows = 0
    for index, (raw_url, raw_label) in enumerate(zip(frame[url_column], labels)):
        if pd.isna(raw_label) or raw_label not in (0, 1):
            invalid_label_rows += 1
            continue
        if pd.isna(raw_url):
            invalid_url_rows += 1
            continue
        normalized = normalize_url(str(raw_url))
        if normalized is None:
            invalid_url_rows += 1
            continue
        identity = normalize_url(normalized, drop_fragment=True)
        if identity is None:
            invalid_url_rows += 1
            continue
        normalized_by_row[index] = normalized
        identity_labels[identity].add(int(raw_label))
        identity_counts[identity] += 1
        first_by_identity.setdefault(identity, index)

    conflicting_identities = {
        identity for identity, values in identity_labels.items() if len(values) > 1
    }
    kept_indices = [
        index for identity, index in first_by_identity.items()
        if identity not in conflicting_identities
    ]
    valid_url_rows = len(normalized_by_row)
    conflicting_rows_removed = sum(identity_counts[identity] for identity in conflicting_identities)
    duplicate_rows_removed = (
        valid_url_rows - conflicting_rows_removed - len(kept_indices)
    )
    if not kept_indices:
        raise ValueError("No valid, non-conflicting URL rows remain in the dataset.")

    X = numeric.loc[kept_indices, feature_columns].reset_index(drop=True)
    y = labels.loc[kept_indices].astype(int).reset_index(drop=True)
    urls = [normalized_by_row[index] for index in kept_indices]
    domain_labels: dict[str, set[int]] = defaultdict(set)
    for url, label in zip(urls, y):
        domain_labels[domain_group(url)].add(int(label))
    preprocessing = {
        "source_rows": int(len(frame)),
        "invalid_url_rows": invalid_url_rows,
        "invalid_label_rows": invalid_label_rows,
        "duplicate_url_rows_removed": int(duplicate_rows_removed),
        "conflicting_url_groups_removed": len(conflicting_identities),
        "conflicting_url_rows_removed": int(conflicting_rows_removed),
        "rows_after_cleaning": int(len(kept_indices)),
        "registrable_domain_groups": len(domain_labels),
        "domains_with_both_labels": sum(len(labels) > 1 for labels in domain_labels.values()),
        "campaign_identifiers_available": False,
    }
    return X, y, feature_columns, urls, preprocessing


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train/test on the UCI PhiUSIIL engineered-feature dataset"
    )
    parser.add_argument("--dataset", type=str, default=None, help="Path to PhiUSIIL_Phishing_URL_Dataset.csv")
    parser.add_argument("--test-size", type=float, default=0.2, help="Fraction of data to hold out for testing")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed for the train/test split")
    args = parser.parse_args()

    dataset_path = resolve_dataset_path(args.dataset)
    log.info(f"Using UCI PhiUSIIL feature table at {dataset_path}")

    X, y, feature_columns, urls, preprocessing = load_dataset(dataset_path)
    log.info(f"Loaded {len(y):,} rows with {len(feature_columns)} numeric features")
    log.info(f"Label distribution: {y.value_counts().to_dict()}")

    train_indices, test_indices = grouped_split_indices(
        urls,
        y.to_numpy(),
        proportions=(1 - args.test_size, args.test_size),
        random_state=args.random_state,
    )
    X_train, X_test = X.iloc[train_indices], X.iloc[test_indices]
    y_train, y_test = y.iloc[train_indices], y.iloc[test_indices]
    log.info(f"Train: {len(y_train):,}  |  Test: {len(y_test):,}")

    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    dataset_provenance = {
        "kind": "uci_phiusiil_feature_table",
        "dataset_path": str(dataset_path.resolve()),
        "sha256": hashlib.sha256(dataset_path.read_bytes()).hexdigest(),
        "sample_count": int(len(y)),
        "source": "UCI PhiUSIIL Phishing URL (Website)",
        "source_url": "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset",
        "source_doi": "https://doi.org/10.1016/j.cose.2023.103545",
        "license": "CC BY 4.0",
        "attribution": (
            "Prasad, A. & Chandra, S. (2024). PhiUSIIL Phishing URL (Website) "
            "[Dataset]. UCI Machine Learning Repository. "
            "https://doi.org/10.1016/j.cose.2023.103545"
        ),
        "source_observation_collection_window": None,
        "source_label_definition": {"0": "phishing", "1": "legitimate"},
        "preprocessing": preprocessing,
    }
    metrics = evaluate(
        pipeline,
        X_test.to_numpy(),
        y_test.to_numpy(),
        data_provenance=dataset_provenance,
    )
    metrics["dataset_path"] = str(dataset_path)
    metrics["feature_count"] = len(feature_columns)
    metrics["feature_columns"] = feature_columns
    metrics["training_data"] = dataset_provenance
    metrics["evaluation"] = {
        "kind": "uci_phiusiil_feature_table_domain_grouped_holdout",
        "final_live_url_model_eligible": feature_columns == FEATURE_ORDER,
        "model_role": "research_only",
        "split_group_key": "registrable_domain",
        "split_summary": {
            "train_rows": int(len(train_indices)),
            "test_rows": int(len(test_indices)),
            "train_domains": len({domain_group(urls[index]) for index in train_indices}),
            "test_domains": len({domain_group(urls[index]) for index in test_indices}),
        },
    }

    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2))
    log.info(f"Metrics saved → {METRICS_PATH}")

    model_path = save_model(pipeline, name=ARTIFACT_NAME)
    log.info(f"Model saved → {model_path}")


if __name__ == "__main__":
    main()
