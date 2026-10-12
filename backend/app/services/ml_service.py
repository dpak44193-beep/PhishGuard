import joblib
import numpy as np
from pathlib import Path
from typing import Any

from app.config import settings
from ml.features.extractor import FEATURE_ORDER, FEATURE_SCHEMA_VERSION


class MLService:
    _bundle: dict[str, Any] | None = None

    @classmethod
    def load(cls) -> None:
        path = Path(settings.ml_model_path)
        if not path.exists():
            raise FileNotFoundError(
                f"Model not found at {path}. Run: python ml/train.py"
            )
        loaded = joblib.load(path)
        if isinstance(loaded, dict) and "base_model" in loaded:
            bundle = loaded
        else:
            bundle = {
                "base_model": loaded,
                "combiner": None,
                "thresholds": {"safe": 0.25, "suspicious": 0.60},
                "version": "legacy-unversioned",
            }
        artifact_order = bundle.get("feature_order")
        if not isinstance(artifact_order, list) or artifact_order != FEATURE_ORDER:
            raise ValueError("Model artifact feature order does not match the live URL extractor.")
        schema_version = bundle.get("feature_schema_version")
        if schema_version is not None and schema_version != FEATURE_SCHEMA_VERSION:
            raise ValueError(
                f"Model feature schema {schema_version!r} does not match "
                f"runtime schema {FEATURE_SCHEMA_VERSION!r}."
            )
        model_metadata = bundle.get("model_metadata")
        if model_metadata is not None:
            if not isinstance(model_metadata, dict):
                raise ValueError("Model metadata must be a dictionary.")
            feature_schema = model_metadata.get("feature_schema")
            if not isinstance(feature_schema, dict):
                raise ValueError("Model metadata is missing its feature schema.")
            if (
                feature_schema.get("version") != FEATURE_SCHEMA_VERSION
                or feature_schema.get("names") != FEATURE_ORDER
            ):
                raise ValueError("Model metadata feature schema does not match runtime.")
            if model_metadata.get("artifact_version") != bundle.get("version"):
                raise ValueError("Model metadata artifact version does not match model bundle.")
            recorded_steps = feature_schema.get("pipeline_steps")
            if recorded_steps is not None:
                model = bundle["base_model"]
                actual_steps = [
                    name for name, _ in model.steps
                ] if hasattr(model, "steps") else []
                if recorded_steps != actual_steps:
                    raise ValueError(
                        "Model preprocessing pipeline does not match its recorded metadata."
                    )
        feature_count = getattr(bundle["base_model"], "n_features_in_", None)
        if feature_count is not None and feature_count != len(FEATURE_ORDER):
            raise ValueError(
                f"Model expects {feature_count} features; the live URL extractor provides {len(FEATURE_ORDER)}."
            )
        if not isinstance(bundle.get("training_data"), dict):
            bundle["training_data"] = {
                "kind": "unverified_legacy",
                "final_evaluation_eligible": False,
            }
        cls._prepare_for_inference(bundle)
        cls._bundle = bundle

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
            node.n_jobs = 1

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
        vector = np.asarray(feature_vector, dtype=float)
        if vector.shape != (len(FEATURE_ORDER),):
            raise ValueError(
                f"Inference requires {len(FEATURE_ORDER)} ordered features; "
                f"received shape {vector.shape}."
            )
        if not np.isfinite(vector).all():
            raise ValueError("Inference feature vector contains non-finite values.")
        base_model = cls._bundle["base_model"]
        prob: float = base_model.predict_proba(vector.reshape(1, -1))[0][1]
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
    def metadata(cls) -> dict[str, Any]:
        if cls._bundle is None:
            cls.load()
        metadata = cls._bundle.get("model_metadata")
        if isinstance(metadata, dict):
            return metadata
        return {
            "artifact_version": cls._bundle.get("version", "legacy-unversioned"),
            "feature_schema": {
                "version": cls._bundle.get("feature_schema_version", "legacy-unknown"),
                "names": cls._bundle.get("feature_order", []),
            },
            "metadata_status": "legacy artifact lacks complete training metadata",
        }

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
