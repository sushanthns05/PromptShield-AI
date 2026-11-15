"""
Unit Tests for SecurityEvaluator
Verifies mathematical metric calculations, zero-division handling, latency statistics,
and domain-specific security metrics.
"""

import pytest
from research.experiments.evaluator import (
    ClassificationMetrics,
    LatencyMetrics,
    PIISecurityMetrics,
    SecurityEvaluator,
    ToolPolicyMetrics,
)


def test_perfect_classification():
    y_true = [0, 0, 1, 1]
    y_pred = [0, 0, 1, 1]
    m = SecurityEvaluator.compute_classification_metrics(y_true, y_pred)

    assert m.accuracy == 1.0
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.f1 == 1.0
    assert m.false_positive_rate == 0.0
    assert m.false_negative_rate == 0.0
    assert m.true_positives == 2
    assert m.true_negatives == 2
    assert m.false_positives == 0
    assert m.false_negatives == 0
    assert m.confusion_matrix == [[2, 0], [0, 2]]


def test_mixed_classification_metrics():
    # 2 TN, 1 FP, 1 FN, 2 TP
    y_true = [0, 0, 0, 1, 1, 1]
    y_pred = [0, 0, 1, 0, 1, 1]
    m = SecurityEvaluator.compute_classification_metrics(y_true, y_pred)

    assert m.true_negatives == 2
    assert m.false_positives == 1
    assert m.false_negatives == 1
    assert m.true_positives == 2

    assert m.accuracy == round(4 / 6, 4)
    assert m.precision == round(2 / 3, 4)
    assert m.recall == round(2 / 3, 4)
    assert m.false_positive_rate == round(1 / 3, 4)
    assert m.false_negative_rate == round(1 / 3, 4)


def test_zero_division_handling():
    # All true negative, all predicted negative -> TP=0, FP=0, FN=0, TN=4
    y_true = [0, 0, 0, 0]
    y_pred = [0, 0, 0, 0]
    m = SecurityEvaluator.compute_classification_metrics(y_true, y_pred)

    assert m.precision == 0.0  # Zero division avoided
    assert m.recall == 0.0     # Zero division avoided
    assert m.f1 == 0.0
    assert m.false_positive_rate == 0.0
    assert m.accuracy == 1.0


def test_empty_predictions():
    m = SecurityEvaluator.compute_classification_metrics([], [])
    assert m.accuracy == 0.0
    assert m.f1 == 0.0
    assert m.confusion_matrix == [[0, 0], [0, 0]]


def test_length_mismatch_raises():
    with pytest.raises(ValueError, match="Length mismatch"):
        SecurityEvaluator.compute_classification_metrics([1, 0], [1])


def test_latency_metrics_computation():
    latencies = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    lat = SecurityEvaluator.compute_latency_metrics(latencies)

    assert lat.mean_ms == 5.5
    assert lat.median_ms == 5.5
    assert lat.min_ms == 1.0
    assert lat.max_ms == 10.0
    assert lat.sample_count == 10
    assert lat.p95_ms > 9.0


def test_empty_latency_metrics():
    lat = SecurityEvaluator.compute_latency_metrics([])
    assert lat.sample_count == 0
    assert lat.mean_ms == 0.0


def test_pii_metrics_computation():
    pii = SecurityEvaluator.compute_pii_metrics(
        total_samples=20,
        detected_count=18,
        properly_redacted_count=18,
        leaked_count=0,
    )
    assert pii.detection_rate == 0.9
    assert pii.redaction_success_rate == 1.0
    assert pii.leakage_rate == 0.0


def test_tool_metrics_computation():
    tool = SecurityEvaluator.compute_tool_metrics(
        total_requests=25,
        unauthorized_count=20,
        unauthorized_blocked_count=20,
        authorized_count=5,
        authorized_allowed_count=5,
        approval_bypass_count=0,
    )
    assert tool.unauthorized_blocking_rate == 1.0
    assert tool.authorized_acceptance_rate == 1.0
    assert tool.approval_bypass_rate == 0.0


def test_per_category_evaluation():
    y_true = [0, 0, 1, 1]
    y_pred = [0, 1, 1, 1]
    categories = ["benign", "benign", "direct_injection", "direct_injection"]

    res = SecurityEvaluator.evaluate_per_category(y_true, y_pred, categories)
    assert "benign" in res
    assert "direct_injection" in res
    assert res["benign"]["sample_count"] == 2
    assert res["benign"]["false_positives"] == 1
    assert res["direct_injection"]["sample_count"] == 2
    assert res["direct_injection"]["recall"] == 1.0
