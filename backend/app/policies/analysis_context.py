"""
PromptShield AI — Server-Controlled Analysis Context Store
Governs server-calculated risk assessments, prevents client-side risk score manipulation,
and securely binds analysis decisions to requester identities.

DEVELOPMENT IDENTITY NOTICE:
Requester IDs and roles are development-only claims and do not represent authenticated
production identities. Production deployments must integrate an authenticated identity
provider (e.g. OAuth2/OIDC, JWT validation).
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import logging
import threading
from typing import Any, Optional
from uuid import uuid4

logger = logging.getLogger("promptshield.analysis_context")


@dataclass(frozen=True)
class ToolIntentBinding:
    """
    Immutable atomic server-side binding between an analysis context and a proposed tool action.
    Prevents analysis context reuse for unrelated tool invocations or tampered arguments.
    """

    tool_name: str
    canonical_arguments_json: str
    intent_hash: str
    bound_at: datetime
    approval_id: Optional[str] = None

    def with_approval_id(self, approval_id: str) -> "ToolIntentBinding":
        """Return a new immutable binding associated with an approval ID."""
        return ToolIntentBinding(
            tool_name=self.tool_name,
            canonical_arguments_json=self.canonical_arguments_json,
            intent_hash=self.intent_hash,
            bound_at=self.bound_at,
            approval_id=approval_id,
        )


from backend.app.policies.canonicalization import (
    canonicalize_arguments,
    canonicalize_tool_intent,
    validate_ttl,
)


class AnalysisContext:
    """
    Server-controlled analysis context record.
    Stores authoritative risk scores and policy decisions calculated by PromptShield AI.
    Protected against accidental in-memory field mutation.
    """

    def __init__(
        self,
        analysis_id: str,
        risk_score: int,
        decision: str,
        requester_id: Optional[str],
        context_trust_level: str,
        created_at: datetime,
        expires_at: datetime,
        bound_intent: Optional[ToolIntentBinding] = None,
    ):
        self._analysis_id = str(analysis_id)
        self._risk_score = int(risk_score)
        self._decision = str(decision).strip().upper()
        self._requester_id = str(requester_id).strip() if requester_id else None
        self._context_trust_level = str(context_trust_level).strip().upper()
        self._created_at = created_at
        self._expires_at = expires_at
        self._bound_intent = bound_intent

    @property
    def analysis_id(self) -> str:
        return self._analysis_id

    @property
    def risk_score(self) -> int:
        return self._risk_score

    @property
    def decision(self) -> str:
        return self._decision

    @property
    def requester_id(self) -> Optional[str]:
        return self._requester_id

    @property
    def context_trust_level(self) -> str:
        return self._context_trust_level

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def expires_at(self) -> datetime:
        return self._expires_at

    @property
    def bound_intent(self) -> Optional[ToolIntentBinding]:
        return self._bound_intent

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self._expires_at

    def bind_requester(self, requester_id: str) -> None:
        """Controlled binding of requester on first use."""
        if self._requester_id is not None:
            raise ValueError(f"Requester already bound to '{self._requester_id}'")
        self._requester_id = str(requester_id).strip()

    def set_bound_intent(self, intent: ToolIntentBinding) -> None:
        """Controlled binding of tool intent."""
        if self._bound_intent is not None:
            raise ValueError("Tool intent is already bound and cannot be overwritten")
        self._bound_intent = intent

    def set_intent_approval_id(self, approval_id: str) -> None:
        """
        Associate an approval_id with the bound intent.
        Rejects empty/invalid approval IDs and prevents overwriting an existing different approval ID.
        """
        if self._bound_intent is None:
            raise ValueError("Cannot set approval_id on unbound context")
        if not isinstance(approval_id, str) or not approval_id.strip():
            raise ValueError("approval_id must be a non-empty string")
        clean_id = approval_id.strip()
        if self._bound_intent.approval_id is not None:
            if self._bound_intent.approval_id != clean_id:
                raise ValueError(
                    f"Approval ID already associated: context '{self._analysis_id}' is bound to approval "
                    f"'{self._bound_intent.approval_id}', cannot replace with '{clean_id}'"
                )
            return
        self._bound_intent = self._bound_intent.with_approval_id(clean_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis_id": self._analysis_id,
            "risk_score": self._risk_score,
            "decision": self._decision,
            "requester_id": self._requester_id,
            "context_trust_level": self._context_trust_level,
            "created_at": self._created_at.isoformat(),
            "expires_at": self._expires_at.isoformat(),
            "is_expired": self.is_expired,
            "bound_tool": self._bound_intent.tool_name if self._bound_intent else None,
            "intent_hash": self._bound_intent.intent_hash if self._bound_intent else None,
            "approval_id": self._bound_intent.approval_id if self._bound_intent else None,
        }


_DEFAULT_TTL = object()


class AnalysisContextStore:
    """
    Thread-safe in-memory store for server-generated prompt analysis contexts.

    LIMITATION NOTICE: This store is session-scoped and in-memory.
    Server restarts clear existing analysis contexts.
    """

    def __init__(self, default_ttl_seconds: int = 300):
        self.default_ttl_seconds = validate_ttl(default_ttl_seconds, "default_ttl_seconds")
        self._contexts: dict[str, AnalysisContext] = {}
        self._lock = threading.RLock()

    def create_context(
        self,
        risk_score: int,
        decision: str,
        requester_id: Optional[str] = None,
        context_trust_level: str = "UNTRUSTED",
        ttl_seconds: Any = _DEFAULT_TTL,
    ) -> AnalysisContext:
        """
        Create a new server-controlled analysis context with a cryptographically unique ID.
        External clients cannot promote context_trust_level to TRUSTED or SYSTEM_TRUSTED.
        Validates that TTL is a positive integer.
        """
        ttl = self.default_ttl_seconds if ttl_seconds is _DEFAULT_TTL else validate_ttl(ttl_seconds, "ttl_seconds")
        now = datetime.now(timezone.utc)
        expires_at = datetime.fromtimestamp(now.timestamp() + ttl, tz=timezone.utc)

        # Security Invariant: Context trust level cannot be promoted to TRUSTED from client input
        safe_trust = "UNTRUSTED"
        if context_trust_level.strip().upper() in ("TRUSTED", "SYSTEM_TRUSTED"):
            logger.warning(
                "Attempted trust promotion on context creation for requester '%s'. Enforcing UNTRUSTED.",
                requester_id,
            )
            safe_trust = "UNTRUSTED"

        analysis_id = f"anls-{uuid4().hex}"
        ctx = AnalysisContext(
            analysis_id=analysis_id,
            risk_score=max(0, min(100, int(risk_score))),
            decision=str(decision).strip().upper(),
            requester_id=requester_id.strip() if requester_id else None,
            context_trust_level=safe_trust,
            created_at=now,
            expires_at=expires_at,
        )

        with self._lock:
            self._contexts[analysis_id] = ctx

        logger.info(
            "Created analysis context: %s (risk_score=%d, decision=%s, requester=%s, expires_in=%ds)",
            analysis_id,
            ctx.risk_score,
            ctx.decision,
            ctx.requester_id,
            ttl,
        )
        return ctx

    def get_context(self, analysis_id: str) -> Optional[AnalysisContext]:
        """Retrieve an analysis context if it exists and has not expired."""
        with self._lock:
            ctx = self._contexts.get(analysis_id)
            if ctx and ctx.is_expired:
                # Remove expired context lazily
                self._contexts.pop(analysis_id, None)
                return None
            return ctx

    def validate_and_get_context(
        self,
        analysis_id: Optional[str],
        requester_id: str,
    ) -> tuple[Optional[AnalysisContext], Optional[str], int]:
        """
        Validate analysis context strictly:
        - Must be present (no fallback to risk_score=0).
        - Must exist in store.
        - Must not be expired.
        - Requester ID must match the bound requester identity.

        Returns (context, error_message, http_status_code).
        """
        if not analysis_id or not isinstance(analysis_id, str) or not analysis_id.strip():
            return None, "Missing analysis context: 'analysis_id' is required for tool authorization and execution", 400

        with self._lock:
            ctx = self._contexts.get(analysis_id.strip())
            if not ctx:
                return None, f"Invalid analysis_id: analysis context '{analysis_id}' not found", 400

            if ctx.is_expired:
                self._contexts.pop(analysis_id.strip(), None)
                return None, f"Expired analysis context: context '{analysis_id}' has expired", 400

            # Bind requester on first use if not already bound
            if ctx.requester_id is None:
                ctx.bind_requester(requester_id.strip())
            elif ctx.requester_id != requester_id.strip():
                logger.warning(
                    "Analysis context requester mismatch: bound to '%s', attempted by '%s'",
                    ctx.requester_id,
                    requester_id,
                )
                return (
                    None,
                    f"Requester binding mismatch: context '{analysis_id}' is bound to requester '{ctx.requester_id}'",
                    403,
                )

            return ctx, None, 200

    @staticmethod
    def validate_analysis_decision(ctx: AnalysisContext) -> tuple[bool, Optional[str], int]:
        """
        Enforce authoritative analysis decision policy:
        - Only ALLOW analysis contexts may authorize tool operations.
        - SANITIZE contexts must be rejected until the sanitized prompt is submitted for a fresh analysis.
        - BLOCK contexts must always be rejected.
        - Unknown or invalid decisions must be rejected.

        Returns (is_permitted, denial_reason, http_status_code).
        """
        decision = str(ctx.decision).strip().upper() if ctx.decision else ""
        if decision == "ALLOW":
            return True, None, 200

        if decision == "SANITIZE":
            return (
                False,
                "Denied: Upstream prompt analysis resulted in SANITIZE decision. "
                "The prompt contained sensitive data or secrets and must be resubmitted "
                "as a sanitized prompt for fresh analysis before tool invocation.",
                403,
            )

        if decision == "BLOCK":
            return (
                False,
                "Denied: Upstream prompt analysis resulted in BLOCK decision due to security policy violations.",
                403,
            )

        return (
            False,
            f"Denied: Invalid or unverified analysis decision '{ctx.decision}'. Only verified ALLOW decisions may authorize tools.",
            403,
        )

    def bind_or_validate_intent(
        self,
        analysis_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        require_previously_bound: bool = False,
    ) -> tuple[bool, Optional[str], int]:
        """
        Atomic server-side binding between an analysis context and its first proposed tool intent.
        Subsequent authorizations and executions must match the exact same tool and arguments.

        Returns (is_valid, error_message, http_status_code).
        """
        try:
            norm_tool, canonical_args, intent_hash = canonicalize_tool_intent(
                tool_name, arguments if arguments is not None else {}
            )
        except (TypeError, ValueError) as exc:
            return False, f"Malformed tool arguments: {exc}", 400

        with self._lock:
            ctx = self._contexts.get(analysis_id.strip())
            if not ctx:
                return False, f"Invalid analysis_id: analysis context '{analysis_id}' not found", 400

            if ctx.is_expired:
                self._contexts.pop(analysis_id.strip(), None)
                return False, f"Expired analysis context: context '{analysis_id}' has expired", 400

            if ctx.bound_intent is None:
                if require_previously_bound:
                    return (
                        False,
                        f"Execution rejected: analysis context '{analysis_id}' has not been bound to a prior authorized tool intent",
                        403,
                    )

                # Bind tool intent atomically on first valid authorization/invocation
                ctx.set_bound_intent(
                    ToolIntentBinding(
                        tool_name=norm_tool,
                        canonical_arguments_json=canonical_args,
                        intent_hash=intent_hash,
                        bound_at=datetime.now(timezone.utc),
                    )
                )
                logger.info(
                    "Bound analysis context '%s' to tool intent: tool='%s', hash='%s'",
                    analysis_id,
                    norm_tool,
                    intent_hash[:12],
                )
                return True, None, 200

            # Context is already bound: verify that tool and canonical arguments match exactly
            bound = ctx.bound_intent
            if (
                bound.tool_name == norm_tool
                and bound.canonical_arguments_json == canonical_args
                and bound.intent_hash == intent_hash
            ):
                return True, None, 200

            # Intent mismatch detected: identify specific deviation
            if bound.tool_name != norm_tool:
                logger.warning(
                    "Tool intent mismatch for context '%s': bound to '%s', attempted '%s'",
                    analysis_id,
                    bound.tool_name,
                    norm_tool,
                )
                return (
                    False,
                    f"Analysis context intent mismatch: context '{analysis_id}' is bound to tool '{bound.tool_name}', cannot execute tool '{norm_tool}'",
                    403,
                )
            else:
                logger.warning(
                    "Argument tampering detected for context '%s' on tool '%s'",
                    analysis_id,
                    norm_tool,
                )
                return (
                    False,
                    f"Analysis context argument tampering: context '{analysis_id}' is bound to original arguments, modified arguments rejected",
                    403,
                )

    def get_bound_approval_id(self, analysis_id: str) -> Optional[str]:
        """Retrieve the approval ID bound to the context's intent, if any."""
        with self._lock:
            ctx = self._contexts.get(analysis_id.strip())
            if ctx and ctx.bound_intent:
                return ctx.bound_intent.approval_id
            return None

    def associate_approval_id(self, analysis_id: str, approval_id: str) -> bool:
        """
        Hardened association of approval_id with analysis context's bound intent.
        - Validates analysis_id and approval_id are non-empty strings.
        - Checks context exists and has not expired.
        - Rejects overwriting an existing different approval_id.
        """
        if not isinstance(analysis_id, str) or not analysis_id.strip():
            raise ValueError("analysis_id must be a non-empty string")
        if not isinstance(approval_id, str) or not approval_id.strip():
            raise ValueError("approval_id must be a non-empty string")

        clean_analysis_id = analysis_id.strip()
        clean_appr_id = approval_id.strip()

        with self._lock:
            ctx = self._contexts.get(clean_analysis_id)
            if not ctx:
                raise ValueError(f"Analysis context '{analysis_id}' not found")
            if ctx.is_expired:
                self._contexts.pop(clean_analysis_id, None)
                raise ValueError(f"Analysis context '{analysis_id}' has expired")
            if not ctx.bound_intent:
                raise ValueError(f"Analysis context '{analysis_id}' has no bound tool intent")

            ctx.set_intent_approval_id(clean_appr_id)
            return True

    def get_or_create_approval_id(
        self,
        analysis_id: str,
        creator_fn: Any,
    ) -> str:
        """
        Thread-safe deduplication: retrieve existing bound approval_id or atomically create,
        bind, and return a new one via creator_fn under store lock.
        Validates context exists, is unexpired, and creator_fn produces a valid non-empty string.
        """
        if not isinstance(analysis_id, str) or not analysis_id.strip():
            raise ValueError("analysis_id must be a non-empty string")
        clean_analysis_id = analysis_id.strip()

        with self._lock:
            ctx = self._contexts.get(clean_analysis_id)
            if not ctx:
                raise ValueError(f"Analysis context '{analysis_id}' not found")
            if ctx.is_expired:
                self._contexts.pop(clean_analysis_id, None)
                raise ValueError(f"Analysis context '{analysis_id}' has expired")
            if not ctx.bound_intent:
                raise ValueError(f"Analysis context '{analysis_id}' has no bound tool intent")

            if ctx.bound_intent.approval_id:
                return ctx.bound_intent.approval_id

            new_id = creator_fn()
            if not isinstance(new_id, str) or not new_id.strip():
                raise ValueError("creator_fn did not return a valid non-empty approval ID string")

            clean_new_id = new_id.strip()
            ctx.set_intent_approval_id(clean_new_id)
            return clean_new_id

    def purge_expired(self) -> int:
        """Purge all expired analysis contexts."""
        now = datetime.now(timezone.utc)
        with self._lock:
            expired_keys = [k for k, v in self._contexts.items() if v.expires_at < now]
            for k in expired_keys:
                self._contexts.pop(k, None)
            return len(expired_keys)
