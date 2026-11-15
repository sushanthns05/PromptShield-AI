from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from backend.app.rag.context_analyzer import ContextObject, TrustLevel
from backend.app.rag.document_scanner import ScanResult


class ContextDecision(str, Enum):
    ACCEPT_UNTRUSTED = "ACCEPT_UNTRUSTED"
    QUARANTINE = "QUARANTINE"
    REJECT = "REJECT"


@dataclass
class PolicyAssessment:
    """Structured policy decision for retrieved RAG content."""

    document_id: str
    decision: ContextDecision
    trust_level: TrustLevel
    risk_score: int
    reasons: list[str]
    findings: dict[str, Any]
    sanitized_preview: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_id": self.document_id,
            "decision": self.decision.value,
            "trust_level": self.trust_level.value,
            "risk_score": self.risk_score,
            "reasons": self.reasons,
            "findings": self.findings,
            "sanitized_preview": self.sanitized_preview,
        }


class ContextPolicy:
    """
    Enforces defensive context-security policies for RAG documents and external inputs.

    Decisions:
    - REJECT: High-severity prompt injection, instruction overrides, or critical threat.
    - QUARANTINE: Suspicious instructions or sensitive data (credentials/PII) requiring review.
    - ACCEPT_UNTRUSTED: Benign content permitted for processing, strictly retaining UNTRUSTED status.

    CRITICAL INVARIANT: ACCEPT_UNTRUSTED must NEVER be interpreted as trusted content.
    """

    def evaluate(
        self,
        scan_result: ScanResult,
        context: Optional[ContextObject] = None,
    ) -> PolicyAssessment:
        reasons = list(scan_result.reasons)

        # High-severity threats
        has_high_direct = any(
            f.get("severity") == "high" for f in scan_result.rule_findings
        )
        has_high_indirect = any(
            f.get("severity") == "high" for f in scan_result.indirect_findings
        )
        has_high_severity = has_high_direct or has_high_indirect

        has_medium_threats = any(
            f.get("severity") == "medium"
            for f in (scan_result.rule_findings + scan_result.indirect_findings)
        )
        has_sensitive_data = len(scan_result.sensitive_findings) > 0

        # Policy decision enforcement
        if has_high_severity or scan_result.risk_score >= 70:
            decision = ContextDecision.REJECT
            reasons.append("Document rejected due to high-severity injection or critical risk")
        elif has_sensitive_data or has_medium_threats or scan_result.risk_score >= 35:
            decision = ContextDecision.QUARANTINE
            if has_sensitive_data:
                reasons.append("Document quarantined: contains sensitive data or credentials")
            elif has_medium_threats:
                reasons.append("Document quarantined: contains suspicious instruction patterns")
            else:
                reasons.append("Document quarantined: elevated risk threshold exceeded")
        else:
            decision = ContextDecision.ACCEPT_UNTRUSTED
            reasons.append("Document accepted into untrusted context boundary")

        # Determine trust level (strictly UNTRUSTED for documents and tools)
        if context is not None:
            trust_level = context.trust_level
        else:
            trust_level = TrustLevel.UNTRUSTED

        # Core architectural invariant: Document content is NEVER promoted to TRUSTED
        if trust_level == TrustLevel.TRUSTED and context and context.source_type != context.source_type.SYSTEM_TRUSTED:
            trust_level = TrustLevel.UNTRUSTED

        return PolicyAssessment(
            document_id=scan_result.document_id,
            decision=decision,
            trust_level=trust_level,
            risk_score=scan_result.risk_score,
            reasons=reasons,
            findings={
                "rule_findings": scan_result.rule_findings,
                "indirect_findings": scan_result.indirect_findings,
                "sensitive_data_findings": scan_result.sensitive_findings,
                "ml_prediction": scan_result.ml_prediction,
            },
            sanitized_preview=scan_result.sanitized_preview,
        )
