"""Regression checks for the isolated, real-data runtime model."""
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.config import settings
from app.services.ml_service import MLService
from ml.data.url_dataset import grouped_split_indices
from ml.features.extractor import (
    FEATURE_ORDER,
    FEATURE_SCHEMA_VERSION,
    URLFeatureExtractor,
)
from ml.train import load_url_csv


ARTIFACT_DIR = (
    ROOT / "ml" / "models" / "artifacts"
    / "real_data_grouped_run_20261012_final"
)
MODEL_PATH = ARTIFACT_DIR / "phishguard_model.joblib"
METRICS_PATH = ARTIFACT_DIR / "metrics.json"
DATASET_PATH = ROOT / "ml" / "data" / "raw" / "labeled_urls.csv"
EXTRACTOR = URLFeatureExtractor()


@pytest.fixture(scope="module")
def trained_bundle():
    if not MODEL_PATH.is_file():
        pytest.skip(
            "Local real-data model artifact is not checked in; run the documented "
            "training pipeline to create it before model-artifact regression tests."
        )
    return joblib.load(MODEL_PATH)


@pytest.fixture(scope="module")
def labeled_dataset():
    if not DATASET_PATH.is_file():
        pytest.skip(
            "Prepared real-data corpus is local and not checked in; prepare the "
            "documented dataset before corpus-backed regression tests."
        )
    X, y, urls = load_url_csv(DATASET_PATH)
    assert X is not None and y is not None and urls is not None
    return X, y, urls


def test_saved_model_and_runtime_share_feature_and_preprocessing_contract(
    trained_bundle, monkeypatch
):
    metadata = trained_bundle["model_metadata"]
    schema = metadata["feature_schema"]
    model = trained_bundle["base_model"]

    assert trained_bundle["feature_order"] == FEATURE_ORDER
    assert trained_bundle["feature_schema_version"] == FEATURE_SCHEMA_VERSION
    assert schema["version"] == FEATURE_SCHEMA_VERSION
    assert schema["names"] == FEATURE_ORDER
    assert schema["inference_input"] == "raw ordered URLFeatureExtractor vector"
    assert schema["pipeline_steps"] == [name for name, _ in model.steps]

    monkeypatch.setattr(settings, "ml_model_path", str(MODEL_PATH))
    monkeypatch.setattr(MLService, "_bundle", None)
    MLService.load()

    for url in (
        "https://example.com/",
        "https://www.iana.org/domains/reserved",
        "https://www.wikipedia.org/",
    ):
        vector = EXTRACTOR.to_vector(EXTRACTOR.extract(url))
        model_probability = model.predict_proba(vector.reshape(1, -1))[0, 1]
        assert MLService.predict(vector) == round(float(model_probability), 4)


def test_example_com_vector_collision_is_visible_in_labeled_training_data(
    labeled_dataset,
):
    X, y, urls = labeled_dataset
    query = "https://example.com/"
    query_vector = EXTRACTOR.to_vector(EXTRACTOR.extract(query))
    matches = np.all(X == query_vector, axis=1)
    matching_urls = [url for url, matched in zip(urls, matches) if matched]
    matching_labels = set(y[matches].astype(int).tolist())

    assert not any(
        (urlsplit(url).hostname or "").lower().removeprefix("www.")
        == "example.com"
        for url in urls
    )
    assert matching_urls
    assert matching_labels == {1}


def test_grouped_holdout_legitimate_false_positives_match_saved_metrics(
    labeled_dataset, trained_bundle
):
    X, y, urls = labeled_dataset
    _, _, test_indices = grouped_split_indices(urls, y)
    legitimate_indices = test_indices[y[test_indices] == 0]
    probabilities = trained_bundle["base_model"].predict_proba(
        X[legitimate_indices]
    )[:, 1]
    false_positive_count = int(
        np.count_nonzero(
            probabilities >= trained_bundle["thresholds"]["suspicious"]
        )
    )
    metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    reported_count = metrics["confusion_matrix"][0][1]

    assert len(legitimate_indices) == 20_179
    assert false_positive_count == reported_count == 237


@pytest.mark.parametrize(
    "url",
    [
        pytest.param(
            "https://example.com/",
            id="reserved-example-domain",
            marks=pytest.mark.xfail(
                strict=True,
                reason=(
                    "Known unresolved false positive: the current model exceeds "
                    "its suspicious threshold for this legitimate reference URL."
                ),
            ),
        ),
        pytest.param(
            "https://www.iana.org/domains/reserved",
            id="iana-reserved-domain",
            marks=pytest.mark.xfail(
                strict=True,
                reason=(
                    "Known unresolved false positive: the current model exceeds "
                    "its suspicious threshold for this legitimate reference URL."
                ),
            ),
        ),
        pytest.param(
            "https://www.wikipedia.org/",
            id="wikipedia-domain",
        ),
    ],
)
def test_legitimate_reference_urls_remain_below_suspicious_threshold(
    url, trained_bundle
):
    vector = EXTRACTOR.to_vector(EXTRACTOR.extract(url))
    probability = float(
        trained_bundle["base_model"].predict_proba(vector.reshape(1, -1))[0, 1]
    )
    suspicious_threshold = trained_bundle["thresholds"]["suspicious"]

    assert probability < suspicious_threshold
