"""
PromptShield AI — Security Event and Audit Log Service
Thread-safe in-memory event store capturing sanitized operational security telemetry.

CRITICAL PRIVACY GUARANTEES:
- Raw prompt text is NEVER stored.
- Raw passwords, API keys, tokens, and PII are NEVER stored.
- Tool invocation arguments and approval payloads are NEVER stored.
- Only redacted tokens, rule IDs, and non-sensitive metadata are persisted in-memory.

LIMITATION NOTICE:
This audit store is session-scoped and in-memory. Events are cleared upon server restart.
This service does not provide durable distributed audit persistence.
"""

from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import logging
import threading
from typing import Any, Optional
from uuid import uuid4

from backend.app.privacy.pii_detector import redact_sensitive_data

logger = logging.getLogger("promptshield.event_store")


# Conservative allowlist of safe metadata keys
SAFE_METADATA_KEYS = {
    "analysis_id",
    "tool_name",
    "risk_level",
    "rule_findings_count",
    "triggered_rules",
    "sensitive_findings_count",
    "document_id",
    "trust_level",
    "source",
    "requester_role",
    "requires_approval",
    "approval_id",
    "execution_id",
    "reason",
    "error",
    "approver_role",
    "status",
    "format",
    "category",
    "severity",
    "decision",
    "intent_hash",
    "bound_tool",
    "details",
    "metadata",
    "info",
    "items",
    "sub_array",
    "findings",
    "tags",
}

# Forbidden substrings matching sensitive / secret keys in any casing (camelCase, snake_case, etc.)
FORBIDDEN_KEY_FRAGMENTS = (
    "password",
    "secret",
    "token",
    "apikey",
    "api_key",
    "key",
    "auth",
    "credential",
    "prompt",
    "content",
    "argument",
    "arg",
    "command",
    "body",
    "raw",
    "cookie",
    "session",
    "jwt",
    "bearer",
    "private",
)


@dataclass
class SecurityEvent:
    """Sanitized security event record for dashboard analytics and telemetry."""

    event_id: str
    timestamp: str  # ISO 8601 UTC
    category: str   # PROMPT_ANALYSIS, DOCUMENT_SCAN, TOOL_AUTHORIZATION, TOOL_EXECUTION, APPROVAL
    event_type: str # PROMPT_EVALUATED, DOCUMENT_SCANNED, TOOL_AUTHORIZED, TOOL_DENIED, etc.
    decision: Optional[str] = None
    risk_score: Optional[int] = None
    requester_id: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    session_only: bool = True
    storage: str = "in_memory"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EventStore:
    """
    Thread-safe, bounded circular audit log store for security gateway events.
    """

    def __init__(self, max_events: int = 10000):
        self.max_events = max_events
        self._events: deque[SecurityEvent] = deque(maxlen=max_events)
        self._lock = threading.RLock()

        # Cached counters for instant dashboard overview queries
        self._total_prompts = 0
        self._allow_decisions = 0
        self._sanitize_decisions = 0
        self._block_decisions = 0
        self._documents_scanned = 0
        self._tool_auth_requests = 0
        self._tool_deny_decisions = 0
        self._tool_require_approval_decisions = 0
        self._tool_exec_attempts = 0
        self._privacy_findings_count = 0

    def record_event(
        self,
        category: str,
        event_type: str,
        decision: Optional[str] = None,
        risk_score: Optional[int] = None,
        requester_id: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> SecurityEvent:
        """
        Record a sanitized operational security event.
        Guarantees that sensitive data fields are stripped before storage.
        """
        now = datetime.now(timezone.utc).isoformat()
        event_id = f"evt-{uuid4().hex}"

        # Sanitize metadata defensively: strip any accidental argument or prompt fields
        safe_meta = self._sanitize_metadata(metadata or {})

        event = SecurityEvent(
            event_id=event_id,
            timestamp=now,
            category=str(category).upper(),
            event_type=str(event_type).upper(),
            decision=str(decision).upper() if decision else None,
            risk_score=int(risk_score) if risk_score is not None else None,
            requester_id=str(requester_id) if requester_id else None,
            metadata=safe_meta,
            session_only=True,
            storage="in_memory",
        )

        with self._lock:
            self._events.append(event)
            self._update_counters(event)

        return event

    def _update_counters(self, event: SecurityEvent) -> None:
        """Increment overview counters under lock."""
        cat = event.category
        dec = event.decision

        if cat == "PROMPT_ANALYSIS":
            self._total_prompts += 1
            if dec == "ALLOW":
                self._allow_decisions += 1
            elif dec == "SANITIZE":
                self._sanitize_decisions += 1
            elif dec == "BLOCK":
                self._block_decisions += 1

            # Count sensitive data findings from safe metadata
            findings_count = event.metadata.get("sensitive_findings_count", 0)
            self._privacy_findings_count += int(findings_count)

        elif cat == "DOCUMENT_SCAN":
            self._documents_scanned += 1
            findings_count = event.metadata.get("sensitive_findings_count", 0)
            self._privacy_findings_count += int(findings_count)

        elif cat == "TOOL_AUTHORIZATION":
            self._tool_auth_requests += 1
            if dec == "DENY":
                self._tool_deny_decisions += 1
            elif dec == "REQUIRE_APPROVAL":
                self._tool_require_approval_decisions += 1

        elif cat == "TOOL_EXECUTION":
            self._tool_exec_attempts += 1

    @classmethod
    def _is_safe_key(cls, key: str) -> bool:
        """Check if a metadata key is safe and not matching any sensitive key fragments."""
        if not isinstance(key, str):
            return False
        k_lower = key.strip().lower()
        for frag in FORBIDDEN_KEY_FRAGMENTS:
            if frag in k_lower:
                return False
        norm = k_lower.replace("_", "")
        safe_norms = {sk.replace("_", "") for sk in SAFE_METADATA_KEYS}
        return norm in safe_norms

    @classmethod
    def _sanitize_value(cls, val: Any, max_depth: int = 5) -> Any:
        """Recursively sanitize metadata values to prevent sensitive data leakage."""
        if max_depth <= 0:
            return None

        if isinstance(val, bool):
            return val

        if isinstance(val, (int, float)):
            return val

        if isinstance(val, str):
            # Limit string length and redact any embedded secrets/PII
            truncated = val[:120]
            return redact_sensitive_data(truncated)

        if isinstance(val, (list, tuple)):
            clean_list = []
            for item in val[:20]:
                cleaned_item = cls._sanitize_value(item, max_depth=max_depth - 1)
                if cleaned_item is not None:
                    clean_list.append(cleaned_item)
            return clean_list

        if isinstance(val, dict):
            clean_dict = {}
            for k, v in val.items():
                if not cls._is_safe_key(str(k)):
                    continue
                cleaned_val = cls._sanitize_value(v, max_depth=max_depth - 1)
                if cleaned_val is not None:
                    clean_dict[str(k)] = cleaned_val
            return clean_dict

        # Unsupported or dangerous object types are safely discarded
        return None

    @classmethod
    def _sanitize_metadata(cls, meta: dict[str, Any]) -> dict[str, Any]:
        """
        Deep recursive metadata sanitizer applying conservative allowlisting,
        forbidden-fragment rejection (camelCase/snake_case), string length limits,
        and embedded secret redaction at all depths.
        """
        if not isinstance(meta, dict):
            return {}
        cleaned = cls._sanitize_value(meta, max_depth=5)
        return cleaned if isinstance(cleaned, dict) else {}

    def get_events(
        self,
        limit: int = 50,
        offset: int = 0,
        category: Optional[str] = None,
        event_type: Optional[str] = None,
        decision: Optional[str] = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Retrieve paginated, filtered security events in reverse chronological order.
        """
        with self._lock:
            # Copy snapshot of events
            filtered = list(self._events)

        if category:
            cat_norm = category.strip().upper()
            filtered = [e for e in filtered if e.category == cat_norm]
        if event_type:
            et_norm = event_type.strip().upper()
            filtered = [e for e in filtered if e.event_type == et_norm]
        if decision:
            dec_norm = decision.strip().upper()
            filtered = [e for e in filtered if e.decision == dec_norm]

        total = len(filtered)
        # Reverse chronological ordering (newest first)
        reversed_events = list(reversed(filtered))
        paginated = reversed_events[offset : offset + limit]

        return [e.to_dict() for e in paginated], total

    def get_overview_statistics(self, pending_approvals_count: int = 0) -> dict[str, Any]:
        """
        Return real aggregated session statistics for the dashboard overview.
        """
        with self._lock:
            recent_events = len(self._events)
            return {
                "total_analyzed_prompts": self._total_prompts,
                "allow_decisions": self._allow_decisions,
                "sanitize_decisions": self._sanitize_decisions,
                "block_decisions": self._block_decisions,
                "documents_scanned": self._documents_scanned,
                "tool_authorization_requests": self._tool_auth_requests,
                "tool_deny_decisions": self._tool_deny_decisions,
                "tool_require_approval_decisions": self._tool_require_approval_decisions,
                "tool_execution_attempts": self._tool_exec_attempts,
                "pending_approvals": pending_approvals_count,
                "privacy_findings": self._privacy_findings_count,
                "recent_security_event_count": recent_events,
                "storage": "in_memory",
                "session_only": True,
            }

    def clear(self) -> None:
        """Clear all events and reset counters (used in testing)."""
        with self._lock:
            self._events.clear()
            self._total_prompts = 0
            self._allow_decisions = 0
            self._sanitize_decisions = 0
            self._block_decisions = 0
            self._documents_scanned = 0
            self._tool_auth_requests = 0
            self._tool_deny_decisions = 0
            self._tool_require_approval_decisions = 0
            self._tool_exec_attempts = 0
            self._privacy_findings_count = 0
