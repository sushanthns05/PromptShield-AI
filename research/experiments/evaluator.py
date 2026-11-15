"""
PromptShield AI — Security Evaluation Metrics Module
Provides mathematically rigorous evaluation metrics for binary security classification,
per-category performance breakdowns, PII/secret sanitization, and tool authorization policies.
"""

from dataclasses import asdict, dataclass
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from typing import Any, Optional


@dataclass
class ClassificationMetrics:
    """Standard binary classification security metrics."""

    accuracy: float
    precision: float
    recall: float  # True Positive Rate (TPR)
    f1: float
    false_positive_rate: float  # FPR = FP / (FP + TN)
    false_negative_rate: float  # FNR = FN / (TP + FN)
    true_positive_rate: float   # TPR = TP / (TP + FN)
    true_negative_rate: float   # TNR = TN / (TN + FP)
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    confusion_matrix: list[list[int]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LatencyMetrics:
    """Inference execution latency statistics in milliseconds."""

    mean_ms: float
    median_ms: float
    p95_ms: float
    p99_ms: float
    min_ms: float
    max_ms: float
    sample_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PIISecurityMetrics:
    """Specialized evaluation metrics for PII and credential privacy."""

    total_sensitive_samples: int
    detected_samples: int
    missed_samples: int
    detector_recall: float                    # Detected / Total sensitive samples
    redaction_success_on_detected: float      # Redacted / Detected
    unredacted_leakage_count: int             # Samples where raw sensitive data reached output
    overall_leakage_rate: float               # Leaked / Total sensitive samples (True leakage)
    overall_privacy_preservation_rate: float  # (Total - Leaked) / Total sensitive samples

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolPolicyMetrics:
    """Specialized governance metrics for secure tool authorization."""

    total_tool_requests: int
    unauthorized_requests: int
    auth_layer_deny_count: int
    auth_layer_require_approval_count: int
    auth_layer_blocking_rate: float              # (DENY + REQUIRE_APPROVAL) / unauthorized_requests
    auth_layer_strict_deny_rate: float           # DENY / unauthorized_requests
    auth_layer_allowed_unauthorized: int         # Allowed at authorizer (e.g. traversal probes)
    sandbox_executor_interception_count: int     # Intercepted by ToolExecutor sandbox checks
    end_to_end_system_blocking_rate: float       # (Authorizer Blocked + Sandbox Intercepted) / unauthorized
    approval_bypass_rate: float                  # Bypassed without valid approval (target: 0.0%)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SecurityEvaluator:
    """
    Independent benchmarking evaluator for AI security gateways.
    Computes precision, recall, FPR, FNR, confusion matrix, and domain-specific metrics.
    """

    @staticmethod
    def compute_classification_metrics(
        y_true: list[int],
        y_pred: list[int],
    ) -> ClassificationMetrics:
        """
        Compute standard binary classification metrics with zero-division handling.
        Assumes 1 = Malicious / Threat, 0 = Benign.
        """
        if len(y_true) != len(y_pred):
            raise ValueError(f"Length mismatch: y_true ({len(y_true)}) != y_pred ({len(y_pred)})")

        if len(y_true) == 0:
            return ClassificationMetrics(
                accuracy=0.0,
                precision=0.0,
                recall=0.0,
                f1=0.0,
                false_positive_rate=0.0,
                false_negative_rate=0.0,
                true_positive_rate=0.0,
                true_negative_rate=0.0,
                true_positives=0,
                true_negatives=0,
                false_positives=0,
                false_negatives=0,
                confusion_matrix=[[0, 0], [0, 0]],
            )

        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

        # Mathematical metric definitions with zero-division handling
        acc = float(accuracy_score(y_true, y_pred))
        prec = float(precision_score(y_true, y_pred, zero_division=0))
        rec = float(recall_score(y_true, y_pred, zero_division=0))
        f1 = float(f1_score(y_true, y_pred, zero_division=0))

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
        tpr = rec
        tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0

        return ClassificationMetrics(
            accuracy=round(acc, 4),
            precision=round(prec, 4),
            recall=round(rec, 4),
            f1=round(f1, 4),
            false_positive_rate=round(fpr, 4),
            false_negative_rate=round(fnr, 4),
            true_positive_rate=round(tpr, 4),
            true_negative_rate=round(tnr, 4),
            true_positives=tp,
            true_negatives=tn,
            false_positives=fp,
            false_negatives=fn,
            confusion_matrix=[[tn, fp], [fn, tp]],
        )

    @staticmethod
    def compute_latency_metrics(latencies_ms: list[float]) -> LatencyMetrics:
        """
        Compute latency distribution metrics in milliseconds.
        """
        if not latencies_ms:
            return LatencyMetrics(
                mean_ms=0.0,
                median_ms=0.0,
                p95_ms=0.0,
                p99_ms=0.0,
                min_ms=0.0,
                max_ms=0.0,
                sample_count=0,
            )

        arr = np.array(latencies_ms)
        return LatencyMetrics(
            mean_ms=round(float(np.mean(arr)), 3),
            median_ms=round(float(np.median(arr)), 3),
            p95_ms=round(float(np.percentile(arr, 95)), 3),
            p99_ms=round(float(np.percentile(arr, 99)), 3),
            min_ms=round(float(np.min(arr)), 3),
            max_ms=round(float(np.max(arr)), 3),
            sample_count=len(arr),
        )

    @staticmethod
    def compute_pii_metrics(
        total_sensitive_samples: int,
        detected_count: int,
        properly_redacted_count: int,
        unredacted_leaked_count: int,
    ) -> PIISecurityMetrics:
        """
        Calculate PII & secret detection, redaction, and true leakage rates across all sensitive samples.
        """
        missed = total_sensitive_samples - detected_count
        det_rate = detected_count / total_sensitive_samples if total_sensitive_samples > 0 else 0.0
        redact_rate = properly_redacted_count / detected_count if detected_count > 0 else 0.0
        leak_rate = unredacted_leaked_count / total_sensitive_samples if total_sensitive_samples > 0 else 0.0
        privacy_rate = (
            (total_sensitive_samples - unredacted_leaked_count) / total_sensitive_samples
            if total_sensitive_samples > 0
            else 1.0
        )

        return PIISecurityMetrics(
            total_sensitive_samples=total_sensitive_samples,
            detected_samples=detected_count,
            missed_samples=missed,
            detector_recall=round(det_rate, 4),
            redaction_success_on_detected=round(redact_rate, 4),
            unredacted_leakage_count=unredacted_leaked_count,
            overall_leakage_rate=round(leak_rate, 4),
            overall_privacy_preservation_rate=round(privacy_rate, 4),
        )

    @staticmethod
    def compute_tool_metrics(
        total_requests: int,
        unauthorized_count: int,
        auth_layer_deny: int,
        auth_layer_require_approval: int,
        auth_layer_allowed_unauthorized: int,
        sandbox_interceptions: int,
        approval_bypass_count: int,
    ) -> ToolPolicyMetrics:
        """
        Calculate secure tool authorization governance metrics with explicit layer separation.
        """
        auth_blocked = auth_layer_deny + auth_layer_require_approval
        auth_block_rate = auth_blocked / unauthorized_count if unauthorized_count > 0 else 1.0
        strict_deny_rate = auth_layer_deny / unauthorized_count if unauthorized_count > 0 else 1.0
        e2e_blocked = auth_blocked + sandbox_interceptions
        e2e_rate = min(1.0, e2e_blocked / unauthorized_count) if unauthorized_count > 0 else 1.0
        bypass_rate = approval_bypass_count / unauthorized_count if unauthorized_count > 0 else 0.0

        return ToolPolicyMetrics(
            total_tool_requests=total_requests,
            unauthorized_requests=unauthorized_count,
            auth_layer_deny_count=auth_layer_deny,
            auth_layer_require_approval_count=auth_layer_require_approval,
            auth_layer_blocking_rate=round(auth_block_rate, 4),
            auth_layer_strict_deny_rate=round(strict_deny_rate, 4),
            auth_layer_allowed_unauthorized=auth_layer_allowed_unauthorized,
            sandbox_executor_interception_count=sandbox_interceptions,
            end_to_end_system_blocking_rate=round(e2e_rate, 4),
            approval_bypass_rate=round(bypass_rate, 4),
        )

    @classmethod
    def evaluate_per_category(
        cls,
        y_true: list[int],
        y_pred: list[int],
        categories: list[str],
    ) -> dict[str, dict[str, Any]]:
        """
        Compute classification metrics partitioned by attack category.
        """
        unique_cats = sorted(set(categories))
        results = {}

        for cat in unique_cats:
            indices = [i for i, c in enumerate(categories) if c == cat]
            sub_y_true = [y_true[i] for i in indices]
            sub_y_pred = [y_pred[i] for i in indices]

            cat_metrics = cls.compute_classification_metrics(sub_y_true, sub_y_pred)
            cat_dict = cat_metrics.to_dict()
            cat_dict["sample_count"] = len(indices)
            results[cat] = cat_dict

        return results
