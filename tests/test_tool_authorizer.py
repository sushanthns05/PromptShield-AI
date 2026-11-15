import pytest

from backend.app.policies.approval_manager import ApprovalManager
from backend.app.policies.tool_authorizer import AuthDecision, ToolAuthorizer
from backend.app.policies.tool_registry import ToolRegistry, UserRole
from backend.app.rag.context_analyzer import TrustLevel


@pytest.fixture
def registry():
    return ToolRegistry()


@pytest.fixture
def approval_manager():
    return ApprovalManager()


@pytest.fixture
def authorizer(registry, approval_manager):
    return ToolAuthorizer(registry=registry, approval_manager=approval_manager)


def test_authorized_user_invokes_low_risk_tool(authorizer):
    res = authorizer.authorize(
        tool_name="search_knowledge_base",
        arguments={"query": "security architecture"},
        requester_id="user-123",
        requester_role=UserRole.USER,
    )
    assert res.decision == AuthDecision.ALLOW
    assert res.requires_approval is False


def test_unauthorized_role_requests_restricted_tool(authorizer):
    # read_file requires DEVELOPER or ADMIN; USER must be denied
    res = authorizer.authorize(
        tool_name="read_file",
        arguments={"filepath": "config.yaml"},
        requester_id="user-123",
        requester_role=UserRole.USER,
    )
    assert res.decision == AuthDecision.DENY
    assert "not authorized" in res.reasons[0]


def test_read_only_role_denied_modifying_tools(authorizer):
    res = authorizer.authorize(
        tool_name="send_email",
        arguments={"recipient": "a@b.com", "subject": "S", "body": "B"},
        requester_id="reader-1",
        requester_role=UserRole.READ_ONLY,
    )
    assert res.decision == AuthDecision.DENY


def test_unknown_tool_is_denied(authorizer):
    res = authorizer.authorize(
        tool_name="execute_unregistered_exploit",
        arguments={},
        requester_id="admin-01",
        requester_role=UserRole.ADMIN,
    )
    assert res.decision == AuthDecision.DENY
    assert "Unknown tool" in res.reasons[0]


def test_disabled_tool_is_denied(authorizer):
    # delete_file is registered but disabled by default
    res = authorizer.authorize(
        tool_name="delete_file",
        arguments={"filepath": "system.log"},
        requester_id="admin-01",
        requester_role=UserRole.ADMIN,
    )
    assert res.decision == AuthDecision.DENY
    assert "disabled" in res.reasons[0]


def test_critical_tool_is_denied_by_default(authorizer):
    # execute_command is CRITICAL and disabled by default
    res = authorizer.authorize(
        tool_name="execute_command",
        arguments={"command": "whoami"},
        requester_id="admin-01",
        requester_role=UserRole.ADMIN,
    )
    assert res.decision == AuthDecision.DENY
    assert "disabled" in res.reasons[0]


def test_high_risk_tool_requires_approval(authorizer):
    # send_email is HIGH risk and requires approval
    res = authorizer.authorize(
        tool_name="send_email",
        arguments={"recipient": "client@example.com", "subject": "Invoice", "body": "Details"},
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
    )
    assert res.decision == AuthDecision.REQUIRE_APPROVAL
    assert res.requires_approval is True
    assert res.approval_id is not None
    assert res.approval_id.startswith("appr-")


def test_missing_required_arguments_denied(authorizer):
    # search_knowledge_base requires 'query'
    res = authorizer.authorize(
        tool_name="search_knowledge_base",
        arguments={},
        requester_id="user-01",
        requester_role=UserRole.USER,
    )
    assert res.decision == AuthDecision.DENY
    assert "Missing required arguments" in res.reasons[0]


def test_high_prompt_risk_score_prohibits_tool_execution(authorizer):
    # If PromptShield flagged high threat (risk_score >= 70), tools must be denied
    res = authorizer.authorize(
        tool_name="search_knowledge_base",
        arguments={"query": "Python"},
        requester_id="user-01",
        requester_role=UserRole.USER,
        risk_score=85,
    )
    assert res.decision == AuthDecision.DENY
    assert "Elevated PromptShield risk score" in res.reasons[0]


def test_untrusted_context_cannot_execute_critical_tools(authorizer, registry):
    # Even if an admin enables delete_file, untrusted context cannot invoke it
    registry.enable_tool("delete_file")
    res = authorizer.authorize(
        tool_name="delete_file",
        arguments={"filepath": "target.db"},
        requester_id="admin-01",
        requester_role=UserRole.ADMIN,
        context_trust_level=TrustLevel.UNTRUSTED,
    )
    assert res.decision == AuthDecision.DENY
    assert "untrusted context" in res.reasons[0]


def test_client_cannot_assign_itself_admin(authorizer):
    # Requester role is USER; client passes client_supplied_admin=True
    res = authorizer.authorize(
        tool_name="read_file",
        arguments={"filepath": "secret.txt"},
        requester_id="attacker-01",
        requester_role=UserRole.USER,
        client_supplied_admin=True,
    )
    assert res.decision == AuthDecision.DENY
    assert any("Client-supplied admin flag ignored" in r for r in res.reasons)


def test_client_provided_approved_true_is_ignored(authorizer):
    # Client passes client_supplied_approved=True without valid server approval_id
    res = authorizer.authorize(
        tool_name="send_email",
        arguments={"recipient": "boss@corp.com", "subject": "S", "body": "B"},
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        client_supplied_approved=True,
    )
    assert res.decision == AuthDecision.REQUIRE_APPROVAL
    assert res.approval_id is not None
    assert any("Client-supplied approved flag ignored" in r for r in res.reasons)


def test_approval_workflow_full_authorization(authorizer, approval_manager):
    args = {"recipient": "boss@corp.com", "subject": "S", "body": "B"}
    # 1. Request approval
    req_res = authorizer.authorize(
        tool_name="send_email",
        arguments=args,
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
    )
    assert req_res.decision == AuthDecision.REQUIRE_APPROVAL
    appr_id = req_res.approval_id

    # 2. Admin approves via approval manager
    approval_manager.approve(
        approval_id=appr_id,
        approver_id="admin-01",
        approver_role=UserRole.ADMIN,
    )

    # 3. Re-authorize with approval_id
    auth_res = authorizer.authorize(
        tool_name="send_email",
        arguments=args,
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        approval_id=appr_id,
    )
    assert auth_res.decision == AuthDecision.ALLOW
    assert "verified human approval" in auth_res.reasons[-1]


def test_expired_approval_rejected_in_authorizer(authorizer, approval_manager):
    args = {"recipient": "boss@corp.com", "subject": "S", "body": "B"}
    req = approval_manager.create_request(
        tool_name="send_email",
        arguments=args,
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        risk_level=ToolRegistry().get_tool("send_email").risk_level,
        ttl_seconds=-5,  # immediately expired
    )
    res = authorizer.authorize(
        tool_name="send_email",
        arguments=args,
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        approval_id=req.approval_id,
    )
    assert res.decision == AuthDecision.DENY
    assert "expired" in res.reasons[0]


def test_tampered_arguments_rejected_with_approval(authorizer, approval_manager):
    approved_args = {"recipient": "alice@corp.com", "subject": "A", "body": "B"}
    tampered_args = {"recipient": "evil@attacker.com", "subject": "A", "body": "B"}

    req = approval_manager.create_request(
        tool_name="send_email",
        arguments=approved_args,
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        risk_level=ToolRegistry().get_tool("send_email").risk_level,
    )
    approval_manager.approve(req.approval_id, approver_id="admin-01", approver_role=UserRole.ADMIN)

    res = authorizer.authorize(
        tool_name="send_email",
        arguments=tampered_args,
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        approval_id=req.approval_id,
    )
    assert res.decision == AuthDecision.DENY
    assert "arguments do not match" in res.reasons[0]


def test_approval_token_cannot_be_reused_by_different_requester(authorizer, approval_manager):
    """Regression test: Approval token hijacking is denied by authorizer."""
    args = {"recipient": "alice@corp.com", "subject": "A", "body": "B"}
    req = approval_manager.create_request(
        tool_name="send_email",
        arguments=args,
        requester_id="legitimate-dev",
        requester_role=UserRole.DEVELOPER,
        risk_level=ToolRegistry().get_tool("send_email").risk_level,
    )
    approval_manager.approve(req.approval_id, approver_id="admin-01", approver_role=UserRole.ADMIN)

    # Attacker tries to use the approval token with their own requester_id
    res = authorizer.authorize(
        tool_name="send_email",
        arguments=args,
        requester_id="attacker-dev",
        requester_role=UserRole.DEVELOPER,
        approval_id=req.approval_id,
    )
    assert res.decision == AuthDecision.DENY
    assert any("bound to requester 'legitimate-dev', not 'attacker-dev'" in r for r in res.reasons)
