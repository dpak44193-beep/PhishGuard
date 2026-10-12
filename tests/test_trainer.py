from pathlib import Path
import hashlib
import json

import numpy as np
import pytest
import tldextract
from sklearn.ensemble import RandomForestClassifier

from ml.features.extractor import FEATURE_ORDER
from ml.models.evaluator import evaluate
from ml.train import (
    _bootstrap_metric_intervals,
    resolve_training_data,
    training_output_paths,
)
from ml.models import trainer


def test_build_pipeline_without_xgboost_uses_random_forest(monkeypatch):
    monkeypatch.setattr(trainer, "XGBClassifier", None)

    pipeline = trainer.build_pipeline()

    assert isinstance(pipeline.named_steps["model"], RandomForestClassifier)


def test_missing_real_dataset_fails_without_synthetic_fallback(tmp_path):
    with pytest.raises(FileNotFoundError, match="Synthetic data is opt-in"):
        resolve_training_data(tmp_path / "missing.csv")


def test_invalid_real_dataset_fails_without_synthetic_fallback(tmp_path, monkeypatch):
    csv_path = tmp_path / "labeled_urls.csv"
    csv_path.write_text("not_url,label\nexample,0\n", encoding="utf-8")

    def synthetic_must_not_run(*args, **kwargs):
        raise AssertionError("synthetic fallback was called")

    monkeypatch.setattr("ml.train.generate_synthetic_data", synthetic_must_not_run)
    with pytest.raises(ValueError, match="no usable rows"):
        resolve_training_data(csv_path)


def test_synthetic_training_is_explicit_and_separated(tmp_path):
    X, y, urls, provenance = resolve_training_data(
        tmp_path / "missing.csv",
        synthetic=True,
        synthetic_samples=20,
    )

    assert X.shape == (20, len(FEATURE_ORDER))
    assert len(y) == len(urls) == 20
    assert provenance["kind"] == "synthetic"
    assert provenance["final_evaluation_eligible"] is False
    model_path, metrics_path = training_output_paths(synthetic=True)
    assert model_path.name == "phishguard_model.synthetic.joblib"
    assert metrics_path.name == "synthetic_metrics.json"


def test_training_outputs_can_be_isolated_from_runtime_artifacts(tmp_path):
    model_path, metrics_path = training_output_paths(
        synthetic=False,
        output_dir=tmp_path,
    )

    assert model_path == tmp_path / "phishguard_model.joblib"
    assert metrics_path == tmp_path / "metrics.json"


def test_training_refuses_to_overwrite_existing_output_directory(tmp_path):
    from ml.train import main

    with pytest.raises(SystemExit) as exc_info:
        main(["--output-dir", str(tmp_path)])

    assert exc_info.value.code == 2
    assert list(tmp_path.iterdir()) == []


def test_cluster_bootstrap_returns_test_metric_intervals():
    labels = np.array([0, 1, 0, 1, 0, 1, 0, 1])
    scores = np.array([0.1, 0.9, 0.2, 0.8, 0.3, 0.7, 0.4, 0.6])
    groups = np.array(["a", "a", "b", "b", "c", "c", "d", "d"])

    intervals = _bootstrap_metric_intervals(
        labels,
        scores,
        threshold=0.5,
        groups=groups,
        replicates=20,
        seed=42,
    )

    assert set(intervals) == {
        "accuracy",
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
        "pr_auc_average_precision",
        "roc_auc",
    }
    assert all(len(bounds) == 2 and bounds[0] <= bounds[1] for bounds in intervals.values())


def test_real_url_csv_records_provenance_and_feature_order(tmp_path):
    csv_path = tmp_path / "labeled_urls.csv"
    rows = [f"https://legitimate-{index}.com/,0" for index in range(10)]
    rows += [f"http://fake-login-{index}.xyz/verify,1" for index in range(10)]
    csv_path.write_text("url,label\n" + "\n".join(rows), encoding="utf-8")
    source_path = tmp_path / "documented-source.csv"
    source_path.write_text("source fixture\n", encoding="utf-8")
    manifest = {
        "provenance": {
            "kind": "test_documented_source",
            "source_url": "https://example.org/dataset",
            "license": "CC BY 4.0",
            "attribution": "Test attribution",
            "source_file": str(source_path),
            "source_file_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
            "source_observation_collection_window": None,
            "source_observation_collection_note": "Collection window documented as unknown.",
            "registrable_domain_extractor": {
                "package": "tldextract",
                "version": tldextract.__version__,
                "network_suffix_list_fetch": False,
            },
            "prepared_at_utc": "2026-01-01T00:00:00+00:00",
            "derived_file_sha256": hashlib.sha256(csv_path.read_bytes()).hexdigest(),
            "final_evaluation_eligible": True,
        },
        "dataset_summary": {"rows": 20},
    }
    csv_path.with_suffix(".manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    X, y, urls, provenance = resolve_training_data(csv_path)

    assert X.shape == (20, len(FEATURE_ORDER))
    assert set(np.unique(y)) == {0, 1}
    assert len(urls) == 20
    assert provenance["kind"] == "test_documented_source"
    assert provenance["final_evaluation_eligible"] is True
    assert provenance["class_counts"] == {"legitimate": 10, "phishing": 10}
    assert len(provenance["sha256"]) == 64
    model_path, metrics_path = training_output_paths(synthetic=False)
    assert model_path.name == "phishguard_model.joblib"
    assert metrics_path.name == "metrics.json"


def test_real_url_csv_without_manifest_is_not_final_evaluation_eligible(tmp_path):
    csv_path = tmp_path / "labeled_urls.csv"
    rows = [f"https://legitimate-{index}.com/,0" for index in range(10)]
    rows += [f"http://fake-login-{index}.xyz/verify,1" for index in range(10)]
    csv_path.write_text("url,label\n" + "\n".join(rows), encoding="utf-8")

    _, _, _, provenance = resolve_training_data(csv_path)

    assert provenance["kind"] == "unverified_labeled_url_csv"
    assert provenance["final_evaluation_eligible"] is False


def test_real_url_csv_rejects_manifest_checksum_mismatch(tmp_path):
    csv_path = tmp_path / "labeled_urls.csv"
    rows = [f"https://legitimate-{index}.com/,0" for index in range(10)]
    rows += [f"http://fake-login-{index}.xyz/verify,1" for index in range(10)]
    csv_path.write_text("url,label\n" + "\n".join(rows), encoding="utf-8")
    manifest = {
        "provenance": {
            "source_url": "https://example.org/dataset",
            "license": "CC BY 4.0",
            "attribution": "Test attribution",
            "source_file": str(tmp_path / "documented-source.csv"),
            "source_file_sha256": "0" * 64,
            "source_observation_collection_window": None,
            "source_observation_collection_note": "Collection window documented as unknown.",
            "prepared_at_utc": "2026-01-01T00:00:00+00:00",
            "derived_file_sha256": "0" * 64,
        }
    }
    csv_path.with_suffix(".manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="checksum does not match"):
        resolve_training_data(csv_path)


def test_calibrated_thresholds_use_live_base_model_probability():
    class FixedProbabilityModel:
        def predict_proba(self, values):
            probabilities = values[:, 0]
            return np.column_stack((1 - probabilities, probabilities))

    X_val = np.zeros((20, len(FEATURE_ORDER)))
    X_val[:, 0] = np.linspace(0.01, 0.99, 20)
    X_test = X_val.copy()
    y_val = np.array([0] * 10 + [1] * 10)
    y_test = y_val.copy()
    urls = [f"https://example-{index}.com/" for index in range(20)]

    bundle, _, metadata, _ = trainer.fit_calibrated_bundle(
        FixedProbabilityModel(), X_val, y_val, urls, X_test, y_test, urls
    )

    assert bundle["combiner"] is None
    assert bundle["feature_order"] == FEATURE_ORDER
    np.testing.assert_allclose(metadata["test_score"], X_test[:, 0])


def test_synthetic_model_version_is_marked_development_only(monkeypatch):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
    from app.services.ml_service import MLService

    monkeypatch.setattr(MLService, "_bundle", {
        "version": "base-model-v2",
        "training_data": {"kind": "synthetic", "final_evaluation_eligible": False},
    })

    assert "synthetic development model" in MLService.version()


def test_model_loader_rejects_feature_count_that_differs_from_runtime(monkeypatch, tmp_path):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
    from app.config import settings
    from app.services.ml_service import MLService

    class WrongFeatureModel:
        n_features_in_ = 50

    model_path = tmp_path / "model.joblib"
    model_path.touch()
    monkeypatch.setattr(MLService, "_bundle", None)
    monkeypatch.setattr(settings, "ml_model_path", str(model_path))
    monkeypatch.setattr(
        "app.services.ml_service.joblib.load",
        lambda path: {"base_model": WrongFeatureModel(), "feature_order": FEATURE_ORDER},
    )

    with pytest.raises(ValueError, match="expects 50 features"):
        MLService.load()


def test_evaluator_requires_dataset_provenance():
    with pytest.raises(ValueError, match="requires explicit dataset provenance"):
        evaluate(None, np.zeros((2, 30)), np.array([0, 1]))


def test_evaluator_rejects_synthetic_data_as_final_evaluation():
    with pytest.raises(ValueError, match="Synthetic data cannot"):
        evaluate(
            None,
            np.zeros((2, 30)),
            np.array([0, 1]),
            data_provenance={"kind": "synthetic"},
        )