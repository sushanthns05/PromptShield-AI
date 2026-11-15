from datetime import datetime, timezone
import pytest

from backend.app.policies.approval_manager import (
    ApprovalManager,
    ApprovalStatus,
)
from backend.app.policies.tool_registry import ToolRiskLevel, UserRole


@pytest.fixture
def approval_manager():
    return ApprovalManager(default_ttl_seconds=300)


def test_create_approval_request(approval_manager):
    req = approval_manager.create_request(
        tool_name="send_email",
        arguments={"recipient": "user@example.com", "subject": "Notice", "body": "Hello"},
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        risk_level=ToolRiskLevel.HIGH,
        ttl_seconds=60,
    )
    assert req.approval_id.startswith("appr-")
    assert req.status == ApprovalStatus.PENDING
    assert req.tool_name == "send_email"
    assert req.requester_id == "dev-01"
    assert req.is_expired is False


def test_approve_request_success(approval_manager):
    req = approval_manager.create_request(
        tool_name="send_email",
        arguments={"recipient": "user@example.com"},
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        risk_level=ToolRiskLevel.HIGH,
    )
    approved = approval_manager.approve(
        approval_id=req.approval_id,
        approver_id="admin-01",
        approver_role=UserRole.ADMIN,
        reason="Approved for testing",
    )
    assert approved.status == ApprovalStatus.APPROVED
    assert approved.decided_by == "admin-01"
    assert approved.decision_reason == "Approved for testing"


def test_reject_request_success(approval_manager):
    req = approval_manager.create_request(
        tool_name="send_email",
        arguments={"recipient": "user@example.com"},
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        risk_level=ToolRiskLevel.HIGH,
    )
    rejected = approval_manager.reject(
        approval_id=req.approval_id,
        approver_id="admin-01",
        approver_role=UserRole.ADMIN,
        reason="Policy violation",
    )
    assert rejected.status == ApprovalStatus.REJECTED
    assert rejected.decided_by == "admin-01"


def test_non_admin_cannot_approve_high_risk(approval_manager):
    req = approval_manager.create_request(
        tool_name="send_email",
        arguments={"recipient": "user@example.com"},
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        risk_level=ToolRiskLevel.HIGH,
    )
    with pytest.raises(PermissionError):
        approval_manager.approve(
            approval_id=req.approval_id,
            approver_id="dev-02",
            approver_role=UserRole.DEVELOPER,
        )


def test_separation_of_duties_requester_cannot_self_approve(approval_manager):
    req = approval_manager.create_request(
        tool_name="send_email",
        arguments={"recipient": "user@example.com"},
        requester_id="admin-01",
        requester_role=UserRole.ADMIN,
        risk_level=ToolRiskLevel.HIGH,
    )
    with pytest.raises(PermissionError):
        approval_manager.approve(
            approval_id=req.approval_id,
            approver_id="admin-01",
            approver_role=UserRole.ADMIN,
        )


def test_expired_approval_cannot_be_approved(approval_manager):
    # Expired by setting negative TTL
    req = approval_manager.create_request(
        tool_name="send_email",
        arguments={"recipient": "user@example.com"},
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        risk_level=ToolRiskLevel.HIGH,
        ttl_seconds=-10,
    )
    with pytest.raises(ValueError):
        approval_manager.approve(
            approval_id=req.approval_id,
            approver_id="admin-01",
            approver_role=UserRole.ADMIN,
        )


def test_already_decided_approval_cannot_be_redecided(approval_manager):
    req = approval_manager.create_request(
        tool_name="send_email",
        arguments={"recipient": "user@example.com"},
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        risk_level=ToolRiskLevel.HIGH,
    )
    approval_manager.approve(
        approval_id=req.approval_id,
        approver_id="admin-01",
        approver_role=UserRole.ADMIN,
    )
    with pytest.raises(ValueError):
        approval_manager.reject(
            approval_id=req.approval_id,
            approver_id="admin-01",
            approver_role=UserRole.ADMIN,
        )


def test_consume_approval_success(approval_manager):
    args = {"recipient": "user@example.com", "subject": "A", "body": "B"}
    req = approval_manager.create_request(
        tool_name="send_email",
        arguments=args,
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        risk_level=ToolRiskLevel.HIGH,
    )
    approval_manager.approve(
        approval_id=req.approval_id,
        approver_id="admin-01",
        approver_role=UserRole.ADMIN,
    )
    assert approval_manager.consume(req.approval_id, "send_email", args) is True


def test_consume_approval_replay_rejected(approval_manager):
    args = {"recipient": "user@example.com"}
    req = approval_manager.create_request(
        tool_name="send_email",
        arguments=args,
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        risk_level=ToolRiskLevel.HIGH,
    )
    approval_manager.approve(
        approval_id=req.approval_id,
        approver_id="admin-01",
        approver_role=UserRole.ADMIN,
    )
    approval_manager.consume(req.approval_id, "send_email", args)

    # Second consumption must fail with replay prevention
    with pytest.raises(ValueError, match="already been consumed"):
        approval_manager.consume(req.approval_id, "send_email", args)


def test_consume_approval_argument_tampering_rejected(approval_manager):
    orig_args = {"recipient": "alice@example.com"}
    tampered_args = {"recipient": "attacker@evil.com"}
    req = approval_manager.create_request(
        tool_name="send_email",
        arguments=orig_args,
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        risk_level=ToolRiskLevel.HIGH,
    )
    approval_manager.approve(
        approval_id=req.approval_id,
        approver_id="admin-01",
        approver_role=UserRole.ADMIN,
    )

    with pytest.raises(ValueError, match="argument mismatch"):
        approval_manager.consume(req.approval_id, "send_email", tampered_args)


def test_consume_approval_tool_name_mismatch_rejected(approval_manager):
    args = {"filepath": "report.txt"}
    req = approval_manager.create_request(
        tool_name="read_file",
        arguments=args,
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        risk_level=ToolRiskLevel.MEDIUM,
    )
    approval_manager.approve(
        approval_id=req.approval_id,
        approver_id="admin-01",
        approver_role=UserRole.ADMIN,
    )

    with pytest.raises(ValueError, match="bound to 'read_file'"):
        approval_manager.consume(req.approval_id, "delete_file", args)


def test_consume_approval_requester_mismatch_rejected(approval_manager):
    """Regression test: Approval token cannot be hijacked by a different requester."""
    args = {"recipient": "alice@example.com", "subject": "Test", "body": "Body"}
    req = approval_manager.create_request(
        tool_name="send_email",
        arguments=args,
        requester_id="victim-user",
        requester_role=UserRole.DEVELOPER,
        risk_level=ToolRiskLevel.HIGH,
    )
    approval_manager.approve(
        approval_id=req.approval_id,
        approver_id="admin-01",
        approver_role=UserRole.ADMIN,
    )

    with pytest.raises(ValueError, match="bound to requester 'victim-user'"):
        approval_manager.consume(
            approval_id=req.approval_id,
            tool_name="send_email",
            arguments=args,
            requester_id="attacker-user",
        )


def test_concurrent_approval_token_consumption_is_thread_safe(approval_manager):
    """Regression test: TOCTOU race condition prevention during concurrent token consumption."""
    import concurrent.futures

    args = {"recipient": "user@example.com", "subject": "Notice", "body": "Hello"}
    req = approval_manager.create_request(
        tool_name="send_email",
        arguments=args,
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        risk_level=ToolRiskLevel.HIGH,
    )
    approval_manager.approve(
        approval_id=req.approval_id,
        approver_id="admin-01",
        approver_role=UserRole.ADMIN,
    )

    success_count = 0
    failure_count = 0

    def try_consume():
        try:
            return approval_manager.consume(
                approval_id=req.approval_id,
                tool_name="send_email",
                arguments=args,
                requester_id="dev-01",
            )
        except ValueError:
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(try_consume) for _ in range(10)]
        for f in concurrent.futures.as_completed(futures):
            if f.result() is True:
                success_count += 1
            else:
                failure_count += 1

    assert success_count == 1
    assert failure_count == 9
