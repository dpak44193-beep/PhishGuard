import joblib
import numpy as np
from pathlib import Path

from app.config import settings
from ml.features.extractor import FEATURE_ORDER


class MLService:
    _bundle = None

    @classmethod
    def load(cls) -> None:
        path = Path(settings.ml_model_path)
        if not path.exists():
            raise FileNotFoundError(
                f"Model not found at {path}. Run: python ml/train.py"
            )
        loaded = joblib.load(path)
        if isinstance(loaded, dict) and "base_model" in loaded:
            cls._bundle = loaded
        else:
            cls._bundle = {
                "base_model": loaded,
                "combiner": None,
                "thresholds": {"safe": 0.25, "suspicious": 0.60},
            }
        artifact_order = cls._bundle.get("feature_order")
        if artifact_order is not None and list(artifact_order) != FEATURE_ORDER:
            raise ValueError("Model artifact feature order does not match the live URL extractor.")
        feature_count = getattr(cls._bundle["base_model"], "n_features_in_", None)
        if feature_count is not None and feature_count != len(FEATURE_ORDER):
            raise ValueError(
                f"Model expects {feature_count} features; the live URL extractor provides {len(FEATURE_ORDER)}."
            )
        if not isinstance(cls._bundle.get("training_data"), dict):
            cls._bundle["training_data"] = {
                "kind": "unverified_legacy",
                "final_evaluation_eligible": False,
            }
        cls._prepare_for_inference(cls._bundle)

    @classmethod
    def _prepare_for_inference(cls, node) -> None:
        if isinstance(node, dict):
            for value in node.values():
                cls._prepare_for_inference(value)
            return

        if isinstance(node, (list, tuple)):
            for value in node:
                cls._prepare_for_inference(value)
            return

        if hasattr(node, "n_jobs"):
            try:
                node.n_jobs = 1
            except Exception:
                pass

        if hasattr(node, "steps"):
            for _, step in node.steps:
                cls._prepare_for_inference(step)

        if hasattr(node, "estimators"):
            for estimator in node.estimators:
                if isinstance(estimator, tuple) and len(estimator) == 2:
                    cls._prepare_for_inference(estimator[1])
                else:
                    cls._prepare_for_inference(estimator)

        if hasattr(node, "estimators_"):
            for estimator in node.estimators_:
                cls._prepare_for_inference(estimator)

    @classmethod
    def predict(cls, feature_vector: np.ndarray) -> float:
        if cls._bundle is None:
            cls.load()
        base_model = cls._bundle["base_model"]
        prob: float = base_model.predict_proba(feature_vector.reshape(1, -1))[0][1]
        return round(float(prob), 4)

    @classmethod
    def is_loaded(cls) -> bool:
        return cls._bundle is not None

    @classmethod
    def version(cls) -> str | None:
        if cls._bundle is None:
            cls.load()
        version = str(cls._bundle.get("version") or "unknown")
        provenance = cls._bundle.get("training_data", {})
        if provenance.get("kind") == "synthetic":
            return f"{version} (synthetic development model; not final evaluation)"
        if not provenance.get("final_evaluation_eligible", False):
            return f"{version} (training provenance unverified; not final evaluation)"
        return version

    @classmethod
    def decision_thresholds(cls) -> dict[str, float]:
        if cls._bundle is None:
            cls.load()
        if "decision_thresholds" in cls._bundle:
            return dict(cls._bundle["decision_thresholds"])

        learned = dict(cls._bundle.get("thresholds", {}))
        suspicious_threshold = float(learned.get("suspicious", 0.7679))
        return {
            "suspicious": suspicious_threshold,
            "malicious": float(learned.get("malicious", 0.985)),
        }

    @classmethod
    def combine_scores(cls, ml_probability: float, cti_scores: dict[str, float]) -> float:
        if cls._bundle is None:
            cls.load()
        combiner = cls._bundle["combiner"]
        if combiner is None:
            return round(min(max(float(ml_probability), 0.0), 1.0), 4)
        row = np.array([[ml_probability, cti_scores.get("virustotal", 0.0), cti_scores.get("urlhaus", 0.0), cti_scores.get("whois", 0.0)]], dtype=float)
        score = float(combiner.predict_proba(row)[0][1])
        return round(min(max(score, 0.0), 1.0), 4)

    @classmethod
    def thresholds(cls) -> dict[str, float]:
        if cls._bundle is None:
            cls.load()
        return dict(cls._bundle.get("thresholds", {"safe": 0.25, "suspicious": 0.60}))
