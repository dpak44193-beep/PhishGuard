"""Train and evaluate PhishGuard on the Kaggle tabular phishing dataset.

This script is separate from ml/train.py because the Kaggle CSV contains a
feature table (numeric engineered signals plus a label) rather than raw URLs.
It performs a stratified train/test split, trains the existing ensemble on the
numeric feature columns, prints evaluation metrics, and saves a separate model
artifact plus metrics file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml.models.evaluator import evaluate
from ml.models.trainer import build_pipeline, save_model
from ml.features.extractor import FEATURE_ORDER

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET = REPO_ROOT / "PhiUSIIL_Phishing_URL_Dataset.csv"
ALT_DATASET = REPO_ROOT / "ml" / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"
ARTIFACT_NAME = "kaggle_phishguard_model.joblib"
METRICS_PATH = REPO_ROOT / "ml" / "data" / "processed" / "kaggle_metrics.json"


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
        "Could not find the Kaggle dataset. Place PhiUSIIL_Phishing_URL_Dataset.csv "
        "at the repo root or under ml/data/raw/, or pass --dataset PATH."
    )


def load_dataset(path: Path) -> tuple[pd.DataFrame, pd.Series, list[str]]:
    frame = pd.read_csv(path)
    if "label" not in frame.columns:
        raise ValueError("Expected a label column in the Kaggle dataset.")

    numeric = frame.select_dtypes(include="number").copy()
    if "label" not in numeric.columns:
        numeric["label"] = frame["label"]

    feature_columns = [column for column in numeric.columns if column != "label"]
    X = numeric[feature_columns]
    y = numeric["label"].astype(int)
    return X, y, feature_columns


def main() -> None:
    parser = argparse.ArgumentParser(description="Train/test on the Kaggle phishing URL dataset")
    parser.add_argument("--dataset", type=str, default=None, help="Path to PhiUSIIL_Phishing_URL_Dataset.csv")
    parser.add_argument("--test-size", type=float, default=0.2, help="Fraction of data to hold out for testing")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed for the train/test split")
    args = parser.parse_args()

    dataset_path = resolve_dataset_path(args.dataset)
    log.info(f"Using Kaggle dataset at {dataset_path}")

    X, y, feature_columns = load_dataset(dataset_path)
    log.info(f"Loaded {len(y):,} rows with {len(feature_columns)} numeric features")
    log.info(f"Label distribution: {y.value_counts().to_dict()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=args.test_size,
        stratify=y,
        random_state=args.random_state,
    )
    log.info(f"Train: {len(y_train):,}  |  Test: {len(y_test):,}")

    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    dataset_provenance = {
        "kind": "kaggle_feature_table",
        "dataset_path": str(dataset_path.resolve()),
        "sha256": hashlib.sha256(dataset_path.read_bytes()).hexdigest(),
        "sample_count": int(len(y)),
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
        "kind": "kaggle_feature_table_holdout",
        "final_live_url_model_eligible": feature_columns == FEATURE_ORDER,
        "model_role": "research_only",
    }

    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2))
    log.info(f"Metrics saved → {METRICS_PATH}")

    model_path = save_model(pipeline, name=ARTIFACT_NAME)
    log.info(f"Model saved → {model_path}")


if __name__ == "__main__":
    main()
