import numpy as np

from ml.evaluate_native_xgboost import (
    _average_precision,
    _metric_values,
    _rank_auc,
    _threshold_for_best_f1,
)


def test_rank_auc_and_average_precision_for_separated_scores():
    labels = np.array([0, 1, 0, 1])
    scores = np.array([0.1, 0.9, 0.4, 0.7])

    assert _rank_auc(labels, scores) == 1.0
    assert _average_precision(labels, scores) == 1.0


def test_validation_threshold_and_test_confusion_metrics():
    validation_labels = np.array([0, 1, 0, 1])
    validation_scores = np.array([0.1, 0.9, 0.4, 0.7])
    threshold = _threshold_for_best_f1(validation_labels, validation_scores)
    test_labels = np.array([0, 1, 0, 1])

    metrics = _metric_values(test_labels, validation_scores, threshold)

    assert threshold == 0.7
    assert metrics["confusion_matrix_actual_rows_predicted_columns"] == [[2, 0], [0, 2]]
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["false_positive_rate"] == 0.0
