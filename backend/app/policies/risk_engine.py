import logging
from typing import Any, Optional

from backend.app.detection.rule_detector import detect_prompt_injection
from backend.app.ml.classifier import PromptClassifier
from backend.app.privacy.pii_detector import detect_sensitive_data, redact_sensitive_data

logger = logging.getLogger("promptshield.risk_engine")


class RiskAssessment:
    """Structured result of the multi-layer risk assessment."""

    def __init__(
        self,
        decision: str,
        risk_score: int,
        risk_level: str,
        sanitized_prompt: Optional[str],
        reasons: list[str],
        rule_findings: list[dict[str, Any]],
        ml_prediction: dict[str, Any],
        sensitive_findings: list[dict[str, Any]],
    ):
        self.decision = decision
        self.risk_score = risk_score
        self.risk_level = risk_level
        self.sanitized_prompt = sanitized_prompt
        self.reasons = reasons
        self.rule_findings = rule_findings
        self.ml_prediction = ml_prediction
        self.sensitive_findings = sensitive_findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "sanitized_prompt": self.sanitized_prompt,
            "reasons": self.reasons,
            "details": {
                "rule_findings": self.rule_findings,
                "ml_prediction": self.ml_prediction,
                "sensitive_data_findings": self.sensitive_findings,
            },
        }


class RiskEngine:
    """
    Multi-layer risk calculation and policy enforcement engine.

    Integrates:
    - Rule-based prompt injection detection (deterministic boundary enforcement)
    - Machine learning threat classification (supporting risk signal)
    - Sensitive data & credential detection and redaction (privacy & secret protection)
    """

    def __init__(self, classifier: Optional[PromptClassifier] = None):
        self.classifier = classifier

    def evaluate(self, prompt: str) -> RiskAssessment:
        if not isinstance(prompt, str):
            raise TypeError("Prompt must be a string")

        reasons: list[str] = []

        # 1. Rule-Based Threat Detection
        rule_findings = detect_prompt_injection(prompt)
        high_severity_rules = [f for f in rule_findings if f.get("severity") == "high"]
        medium_severity_rules = [f for f in rule_findings if f.get("severity") == "medium"]

        rule_score = 0
        if high_severity_rules:
            rule_score += 80
            for f in high_severity_rules:
                reasons.append(
                    f"High-severity prompt injection detected: {f['rule_id']} ({f['category']})"
                )
        if medium_severity_rules:
            rule_score += len(medium_severity_rules) * 25
            for f in medium_severity_rules:
                reasons.append(
                    f"Medium-severity prompt injection pattern: {f['rule_id']} ({f['category']})"
                )

        # 2. Sensitive Data & Secret Detection
        raw_sensitive = detect_sensitive_data(prompt)
        safe_sensitive_findings: list[dict[str, Any]] = []
        secret_types = {
            "OPENAI_API_KEY",
            "SYNTHETIC_API_KEY",
            "AWS_ACCESS_KEY",
            "SYNTHETIC_AWS_KEY",
            "PASSWORD",
        }
        pii_types = {"EMAIL", "PHONE"}

        sensitive_raw_score = 0
        detected_types: set[str] = set()

        for f in raw_sensitive:
            ftype = str(f["type"])
            detected_types.add(ftype)

            # Security requirement: NEVER store raw secrets or passwords in findings or response
            safe_sensitive_findings.append({
                "type": ftype,
                "start": f["start"],
                "end": f["end"],
                "redacted_value": f"[REDACTED_{ftype}]",
                "format": f.get("format", "standard"),
                "category": f.get("category", "SECRET" if ftype in secret_types else "PII"),
            })

            if ftype in secret_types:
                sensitive_raw_score += 25
            elif ftype in pii_types:
                sensitive_raw_score += 15
            else:
                sensitive_raw_score += 15

        # Cap sensitive data score so privacy risk reflects Medium Risk tier (max 40)
        sensitive_score = min(40, sensitive_raw_score)

        if safe_sensitive_findings:
            reasons.append(
                f"Sensitive data detected: {', '.join(sorted(detected_types))}"
            )

        # 3. Machine Learning Threat Classifier (Supporting Signal)
        ml_result: dict[str, Any] = {
            "prediction": "unavailable",
            "confidence": 0.0,
            "class_id": None,
            "status": "unavailable",
        }
        ml_score = 0

        if self.classifier is not None:
            try:
                if getattr(self.classifier, "is_trained", False):
                    pred = self.classifier.predict(prompt)
                    confidence = float(pred.get("confidence", 0.0))
                    prediction = str(pred.get("prediction", "unknown"))

                    ml_result = {
                        "prediction": prediction,
                        "confidence": confidence,
                        "class_id": pred.get("class_id"),
                        "status": "success",
                    }

                    if prediction == "malicious":
                        # Supporting risk signal contribution: up to 30 points
                        ml_score = int(round(confidence * 30))
                        reasons.append(
                            f"ML classifier flagged potential threat (confidence: {confidence:.4f})"
                        )
                else:
                    ml_result["status"] = "not_trained"
            except Exception as exc:
                logger.warning("ML prediction failed safely: %s", exc)
                ml_result["status"] = "error"
                ml_result["error"] = "ML prediction error"

        # 4. Composite Risk Score (0 - 100)
        total_raw_score = rule_score + sensitive_score + ml_score
        risk_score = min(100, max(0, total_raw_score))

        # 5. Risk Level Classification
        if risk_score >= 80:
            risk_level = "critical"
        elif risk_score >= 60:
            risk_level = "high"
        elif risk_score >= 30:
            risk_level = "medium"
        else:
            risk_level = "low"

        # 6. Policy Decision Enforcement
        has_high_severity = len(high_severity_rules) > 0
        has_sensitive = len(safe_sensitive_findings) > 0

        if has_high_severity:
            decision = "BLOCK"
            sanitized_prompt = None
        elif has_sensitive:
            decision = "SANITIZE"
            sanitized_prompt = redact_sensitive_data(prompt)
            reasons.append("Sensitive data sanitized via redaction")
        elif risk_score >= 60:
            decision = "BLOCK"
            sanitized_prompt = None
            reasons.append("High risk threshold exceeded")
        else:
            decision = "ALLOW"
            sanitized_prompt = prompt
            if not reasons:
                reasons.append("Prompt passed all security checks")

        return RiskAssessment(
            decision=decision,
            risk_score=risk_score,
            risk_level=risk_level,
            sanitized_prompt=sanitized_prompt,
            reasons=reasons,
            rule_findings=rule_findings,
            ml_prediction=ml_result,
            sensitive_findings=safe_sensitive_findings,
        )
