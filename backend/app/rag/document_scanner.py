from dataclasses import dataclass, field
import logging
import re
from typing import Any, Optional

from backend.app.detection.rule_detector import detect_prompt_injection
from backend.app.ml.classifier import PromptClassifier
from backend.app.privacy.pii_detector import detect_sensitive_data, redact_sensitive_data

logger = logging.getLogger("promptshield.document_scanner")

# Indirect prompt injection heuristic rules specific to untrusted documents and retrieved context
INDIRECT_INJECTION_RULES = [
    {
        "rule_id": "IND001",
        "category": "embedded_system_tag",
        "severity": "high",
        "pattern": r"(?i)(?:\[(?:system|instruction|admin|developer)\]|<\/?(?:system|instruction|developer_note)>|<!--\s*(?:system|instruction|ai)\b)",
    },
    {
        "rule_id": "IND002",
        "category": "ai_targeted_directive",
        "severity": "high",
        "pattern": r"(?i)\b(?:note|instruction|directive|command|message|guideline|prompt)\s+(?:for|to)\s+(?:the\s+)?(?:ai(?:\s+assistant)?|assistant|model|llm|agent|system)\s*[:\-]\s*(?:ignore|disregard|bypass|override|reveal|print|forget|output|show|disclose)",
    },
    {
        "rule_id": "IND003",
        "category": "conditional_instruction_override",
        "severity": "high",
        "pattern": r"(?i)\b(?:when\s+reading\s+this|if\s+you\s+are\s+an?\s+(?:ai(?:\s+assistant)?|assistant|model|llm|agent))\b.*?\b(?:ignore|override|reveal|bypass|disregard)\b",
    },
    {
        "rule_id": "IND004",
        "category": "pseudo_system_delimiter",
        "severity": "medium",
        "pattern": r"(?i)(?:```\s*system|###\s*System\s*Instruction|---+\s*BEGIN\s+SYSTEM)",
    },
]


@dataclass
class ScanResult:
    """Structured result of a document security inspection."""

    document_id: str
    risk_score: int
    rule_findings: list[dict[str, Any]] = field(default_factory=list)
    indirect_findings: list[dict[str, Any]] = field(default_factory=list)
    sensitive_findings: list[dict[str, Any]] = field(default_factory=list)
    ml_prediction: dict[str, Any] = field(default_factory=dict)
    sanitized_preview: str = ""
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_id": self.document_id,
            "risk_score": self.risk_score,
            "findings": {
                "rule_findings": self.rule_findings,
                "indirect_findings": self.indirect_findings,
                "sensitive_data_findings": self.sensitive_findings,
                "ml_prediction": self.ml_prediction,
            },
            "sanitized_preview": self.sanitized_preview,
            "reasons": self.reasons,
        }


class DocumentScanner:
    """
    Defensive security scanner for untrusted documents in RAG pipelines.
    Identifies direct and indirect prompt injection, sensitive data, and malicious intent.
    """

    def __init__(self, classifier: Optional[PromptClassifier] = None):
        self.classifier = classifier

    def scan(self, content: str, document_id: str = "doc-unknown") -> ScanResult:
        if not isinstance(content, str):
            raise TypeError("Document content must be a string")

        reasons: list[str] = []

        # Handle empty documents safely
        if not content.strip():
            return ScanResult(
                document_id=document_id,
                risk_score=0,
                rule_findings=[],
                indirect_findings=[],
                sensitive_findings=[],
                ml_prediction={"prediction": "unavailable", "confidence": 0.0, "status": "empty_document"},
                sanitized_preview="",
                reasons=["Empty document scanned without findings"],
            )

        # 1. Direct Prompt Injection Rule Detection
        direct_rule_findings = detect_prompt_injection(content)
        high_severity_direct = [f for f in direct_rule_findings if f.get("severity") == "high"]
        medium_severity_direct = [f for f in direct_rule_findings if f.get("severity") == "medium"]

        rule_score = 0
        if high_severity_direct:
            rule_score += 80
            for f in high_severity_direct:
                reasons.append(
                    f"Direct prompt injection detected: {f['rule_id']} ({f['category']})"
                )
        if medium_severity_direct:
            rule_score += len(medium_severity_direct) * 25
            for f in medium_severity_direct:
                reasons.append(
                    f"Medium-severity instruction pattern detected: {f['rule_id']} ({f['category']})"
                )

        # 2. Indirect Prompt Injection & Embedded Instruction Detection
        indirect_findings: list[dict[str, Any]] = []
        for rule in INDIRECT_INJECTION_RULES:
            match = re.search(rule["pattern"], content)
            if match:
                finding = {
                    "rule_id": rule["rule_id"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "matched_pattern": match.group(0),
                }
                indirect_findings.append(finding)
                if rule["severity"] == "high":
                    rule_score += 80
                    reasons.append(
                        f"Indirect prompt injection detected: {rule['rule_id']} ({rule['category']})"
                    )
                else:
                    rule_score += 25
                    reasons.append(
                        f"Suspicious document directive detected: {rule['rule_id']} ({rule['category']})"
                    )

        # 3. Sensitive Data & Secret Detection (PII & Credentials)
        raw_sensitive = detect_sensitive_data(content)
        safe_sensitive_findings: list[dict[str, Any]] = []
        secret_types = {"OPENAI_API_KEY", "AWS_ACCESS_KEY", "PASSWORD"}
        pii_types = {"EMAIL", "PHONE"}

        sensitive_raw_score = 0
        detected_types: set[str] = set()

        for f in raw_sensitive:
            ftype = str(f["type"])
            detected_types.add(ftype)

            # Security requirement: NEVER store raw secrets or passwords in findings
            safe_sensitive_findings.append({
                "type": ftype,
                "start": f["start"],
                "end": f["end"],
                "redacted_value": f"[REDACTED_{ftype}]",
            })

            if ftype in secret_types:
                sensitive_raw_score += 25
            elif ftype in pii_types:
                sensitive_raw_score += 15
            else:
                sensitive_raw_score += 15

        sensitive_score = min(40, sensitive_raw_score)
        if safe_sensitive_findings:
            reasons.append(
                f"Sensitive data detected in document: {', '.join(sorted(detected_types))}"
            )

        # 4. Machine Learning Threat Classifier (Supporting Signal)
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
                    pred = self.classifier.predict(content)
                    confidence = float(pred.get("confidence", 0.0))
                    prediction = str(pred.get("prediction", "unknown"))

                    ml_result = {
                        "prediction": prediction,
                        "confidence": confidence,
                        "class_id": pred.get("class_id"),
                        "status": "success",
                    }

                    if prediction == "malicious":
                        ml_score = int(round(confidence * 30))
                        reasons.append(
                            f"ML classifier flagged potential document threat (confidence: {confidence:.4f})"
                        )
                else:
                    ml_result["status"] = "not_trained"
            except Exception as exc:
                logger.warning("ML prediction on document failed safely: %s", exc)
                ml_result["status"] = "error"
                ml_result["error"] = "ML prediction error"

        # 5. Composite Document Risk Score (0 - 100)
        total_raw_score = rule_score + sensitive_score + ml_score
        risk_score = min(100, max(0, total_raw_score))

        # 6. Sanitized Preview (Safely redacted, max 500 characters)
        redacted_full = redact_sensitive_data(content)
        sanitized_preview = (
            redacted_full[:500] + "..." if len(redacted_full) > 500 else redacted_full
        )

        if not reasons:
            reasons.append("Document passed security inspection without detected threats")

        return ScanResult(
            document_id=document_id,
            risk_score=risk_score,
            rule_findings=direct_rule_findings,
            indirect_findings=indirect_findings,
            sensitive_findings=safe_sensitive_findings,
            ml_prediction=ml_result,
            sanitized_preview=sanitized_preview,
            reasons=reasons,
        )
