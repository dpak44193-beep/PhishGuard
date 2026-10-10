"""Evaluation metrics for the phishing classifier."""
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline


def evaluate(
    pipeline: Pipeline,
    X_test: np.ndarray,
    y_test: np.ndarray,
    *,
    data_provenance: dict[str, object] | None = None,
) -> dict:
    if not data_provenance or not data_provenance.get("kind"):
        raise ValueError("Evaluation requires explicit dataset provenance.")
    if data_provenance.get("kind") == "synthetic":
        raise ValueError("Synthetic data cannot be used for final model evaluation.")

    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy":  round(float(accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred)), 4),
        "recall":    round(float(recall_score(y_test, y_pred)), 4),
        "f1":        round(float(f1_score(y_test, y_pred)), 4),
        "roc_auc":   round(float(roc_auc_score(y_test, y_prob)), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "data_provenance": data_provenance,
    }

    print("\n=== PhishGuard Model Evaluation ===")
    for k, v in metrics.items():
        if k != "confusion_matrix":
            print(f"  {k:15s}: {v}")
    cm = np.array(metrics["confusion_matrix"])
    print(f"\n  Confusion Matrix (rows=actual, cols=predicted):\n{cm}")
    print(f"\n{classification_report(y_test, y_pred, target_names=['legitimate', 'phishing'])}")

    return metrics
