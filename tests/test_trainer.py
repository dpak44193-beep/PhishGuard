from pathlib import Path

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from ml.features.extractor import FEATURE_ORDER
from ml.models.evaluator import evaluate
from ml.train import resolve_training_data, training_output_paths
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


def test_real_url_csv_records_provenance_and_feature_order(tmp_path):
    csv_path = tmp_path / "labeled_urls.csv"
    rows = [f"https://legitimate-{index}.com/,0" for index in range(10)]
    rows += [f"http://fake-login-{index}.xyz/verify,1" for index in range(10)]
    csv_path.write_text("url,label\n" + "\n".join(rows), encoding="utf-8")

    X, y, urls, provenance = resolve_training_data(csv_path)

    assert X.shape == (20, len(FEATURE_ORDER))
    assert set(np.unique(y)) == {0, 1}
    assert len(urls) == 20
    assert provenance["kind"] == "real_labeled_url_csv"
    assert provenance["final_evaluation_eligible"] is True
    assert provenance["class_counts"] == {"legitimate": 10, "phishing": 10}
    assert len(provenance["sha256"]) == 64
    model_path, metrics_path = training_output_paths(synthetic=False)
    assert model_path.name == "phishguard_model.joblib"
    assert metrics_path.name == "metrics.json"


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