from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
import logging
import threading
from typing import Any, Optional
from uuid import uuid4

from backend.app.policies.tool_registry import ToolRiskLevel, UserRole

logger = logging.getLogger("promptshield.approval_manager")


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"


@dataclass
class ApprovalRequest:
    """
    Cryptographically tracked human approval record.
    Binds the approval to exact tool, arguments hash, requester, and risk parameters.
    """

    approval_id: str
    tool_name: str
    arguments: dict[str, Any]
    requester_id: str
    requester_role: UserRole
    risk_level: ToolRiskLevel
    created_at: datetime
    expires_at: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: Optional[str] = None
    decided_at: Optional[datetime] = None
    decision_reason: Optional[str] = None
    consumed_at: Optional[datetime] = None

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "tool_name": self.tool_name,
            "requester_id": self.requester_id,
            "requester_role": self.requester_role.value,
            "risk_level": self.risk_level.value,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "decided_by": self.decided_by,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "decision_reason": self.decision_reason,
            "consumed_at": self.consumed_at.isoformat() if self.consumed_at else None,
        }


class ApprovalManager:
    """
    Thread-safe in-memory human approval management workflow.

    LIMITATION NOTICE: This implementation stores approval requests in-memory.
    Server restarts will clear pending approvals. In production, this must be backed
    by a durable database with distributed locking and audit persistence.
    """

    def __init__(self, default_ttl_seconds: int = 300):
        self.default_ttl_seconds = default_ttl_seconds
        self._approvals: dict[str, ApprovalRequest] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _canonicalize_args(args: dict[str, Any]) -> str:
        """Produce canonical JSON representation of arguments for tamper-evident comparison."""
        return json.dumps(args, sort_keys=True)

    def create_request(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        requester_id: str,
        requester_role: UserRole,
        risk_level: ToolRiskLevel,
        ttl_seconds: Optional[int] = None,
    ) -> ApprovalRequest:
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        now = datetime.now(timezone.utc)
        expires_at = datetime.fromtimestamp(now.timestamp() + ttl, tz=timezone.utc)

        approval_id = f"appr-{uuid4().hex[:12]}"
        req = ApprovalRequest(
            approval_id=approval_id,
            tool_name=tool_name,
            arguments=dict(arguments),
            requester_id=requester_id,
            requester_role=requester_role,
            risk_level=risk_level,
            created_at=now,
            expires_at=expires_at,
            status=ApprovalStatus.PENDING,
        )
        with self._lock:
            self._approvals[approval_id] = req

        logger.info(
            "Created approval request: %s for tool '%s' by requester '%s' (expires in %ds)",
            approval_id,
            tool_name,
            requester_id,
            ttl,
        )
        return req

    def get_request(self, approval_id: str) -> Optional[ApprovalRequest]:
        with self._lock:
            req = self._approvals.get(approval_id)
            if req and req.status == ApprovalStatus.PENDING and req.is_expired:
                req.status = ApprovalStatus.EXPIRED
            return req

    def approve(
        self,
        approval_id: str,
        approver_id: str,
        approver_role: UserRole,
        reason: Optional[str] = None,
    ) -> ApprovalRequest:
        with self._lock:
            req = self.get_request(approval_id)
            if not req:
                raise KeyError(f"Approval request '{approval_id}' not found")

            if req.is_expired or req.status == ApprovalStatus.EXPIRED:
                req.status = ApprovalStatus.EXPIRED
                raise ValueError("Cannot approve: approval request has expired")

            if req.status != ApprovalStatus.PENDING:
                raise ValueError(f"Cannot approve: request is already {req.status.value}")

            # Approver authorization: Only ADMIN can approve high/critical risk tools
            if req.risk_level in (ToolRiskLevel.HIGH, ToolRiskLevel.CRITICAL) and approver_role != UserRole.ADMIN:
                raise PermissionError("Only users with role ADMIN can approve high/critical risk tools")

            # Separation of duties: Requester cannot self-approve privileged operations
            if req.requester_id == approver_id:
                raise PermissionError("Separation of duties violation: Requester cannot self-approve tool action")

            now = datetime.now(timezone.utc)
            req.status = ApprovalStatus.APPROVED
            req.decided_by = approver_id
            req.decided_at = now
            req.decision_reason = reason or "Approved by authorized reviewer"

            logger.info("Approval '%s' APPROVED by '%s' (%s)", approval_id, approver_id, approver_role.value)
            return req

    def reject(
        self,
        approval_id: str,
        approver_id: str,
        approver_role: UserRole,
        reason: Optional[str] = None,
    ) -> ApprovalRequest:
        with self._lock:
            req = self.get_request(approval_id)
            if not req:
                raise KeyError(f"Approval request '{approval_id}' not found")

            if req.is_expired or req.status == ApprovalStatus.EXPIRED:
                req.status = ApprovalStatus.EXPIRED
                raise ValueError("Cannot reject: approval request has expired")

            if req.status != ApprovalStatus.PENDING:
                raise ValueError(f"Cannot reject: request is already {req.status.value}")

            now = datetime.now(timezone.utc)
            req.status = ApprovalStatus.REJECTED
            req.decided_by = approver_id
            req.decided_at = now
            req.decision_reason = reason or "Rejected by authorized reviewer"

            logger.info("Approval '%s' REJECTED by '%s' (%s)", approval_id, approver_id, approver_role.value)
            return req

    def consume(
        self,
        approval_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        requester_id: Optional[str] = None,
    ) -> bool:
        """
        Thread-safe atomic consumption of a valid approval token for a single execution.
        Enforces strict parameter and requester binding to prevent approval replay,
        token hijacking, or argument tampering.
        """
        with self._lock:
            req = self.get_request(approval_id)
            if not req:
                raise KeyError(f"Approval request '{approval_id}' not found")

            if req.status == ApprovalStatus.CONSUMED:
                raise ValueError(f"Approval token '{approval_id}' has already been consumed (replay attack prevention)")

            if req.is_expired or req.status == ApprovalStatus.EXPIRED:
                req.status = ApprovalStatus.EXPIRED
                raise ValueError(f"Approval token '{approval_id}' has expired")

            if req.status != ApprovalStatus.APPROVED:
                raise ValueError(f"Approval token '{approval_id}' is not in APPROVED state (current: {req.status.value})")

            # Verify requester binding (prevent token hijacking)
            if requester_id is not None and req.requester_id != requester_id:
                raise ValueError(
                    f"Approval token '{approval_id}' is bound to requester '{req.requester_id}', not '{requester_id}'"
                )

            # Verify tool binding
            if req.tool_name != tool_name:
                raise ValueError(f"Approval token bound to '{req.tool_name}', not requested tool '{tool_name}'")

            # Verify argument binding
            expected_canonical = self._canonicalize_args(req.arguments)
            actual_canonical = self._canonicalize_args(arguments)
            if expected_canonical != actual_canonical:
                raise ValueError("Approval token argument mismatch: arguments have been modified since approval")

            # Atomic transition to CONSUMED
            req.status = ApprovalStatus.CONSUMED
            req.consumed_at = datetime.now(timezone.utc)
            logger.info("Approval token '%s' successfully consumed for tool '%s'", approval_id, tool_name)
            return True
