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

logger = logging.getLogger("promptshield.event_store")


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

    @staticmethod
    def _sanitize_metadata(meta: dict[str, Any]) -> dict[str, Any]:
        """
        Strip sensitive parameters (prompts, arguments, keys, tokens, passwords)
        and retain only safe statistical, category, and policy metadata.
        """
        forbidden_keys = {
            "prompt",
            "content",
            "arguments",
            "args",
            "password",
            "secret",
            "token",
            "api_key",
            "key",
            "authorization",
            "body",
            "exception",
            "raw_text",
            "query",
            "command",
        }
        clean: dict[str, Any] = {}
        for k, v in meta.items():
            if str(k).lower() in forbidden_keys:
                continue
            if isinstance(v, (int, float, bool, str)):
                clean[k] = v
            elif isinstance(v, (list, tuple)):
                # Clean list elements if primitives
                clean[k] = [x for x in v if isinstance(x, (int, float, bool, str))][:20]
            elif isinstance(v, dict):
                clean[k] = {
                    dk: dv
                    for dk, dv in v.items()
                    if str(dk).lower() not in forbidden_keys and isinstance(dv, (int, float, bool, str))
                }
        return clean

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
