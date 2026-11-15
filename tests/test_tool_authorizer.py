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


# ---------------------------------------------------------------------------
# Day 8.5 Security Hardening Regression Tests: Path Validation in Authorizer
# ---------------------------------------------------------------------------


def test_path_traversal_dot_dot_slash_denied(authorizer):
    res = authorizer.authorize(
        tool_name="read_file",
        arguments={"filepath": "../app.env"},
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
    )
    assert res.decision == AuthDecision.DENY
    assert any("Path traversal" in r for r in res.reasons)


def test_path_traversal_multilevel_denied(authorizer):
    res = authorizer.authorize(
        tool_name="read_file",
        arguments={"filepath": "../../../../var/log/audit.log"},
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
    )
    assert res.decision == AuthDecision.DENY
    assert any("Path traversal" in r for r in res.reasons)


def test_absolute_path_outside_allowed_base_denied(authorizer):
    for bad_path in ["/etc/passwd", "/var/log/audit.log", "C:\\Windows\\System32\\cmd.exe"]:
        res = authorizer.authorize(
            tool_name="read_file",
            arguments={"filepath": bad_path},
            requester_id="dev-01",
            requester_role=UserRole.DEVELOPER,
        )
        assert res.decision == AuthDecision.DENY
        assert any("escapes allowed base" in r or "forbidden" in r or "traversal" in r for r in res.reasons)


def test_url_encoded_path_traversal_denied(authorizer):
    for encoded_path in ["%2e%2e%2fapp.env", "%2e%2e/app.env", "..%2fapp.env", "%252e%252e%252fapp.env"]:
        res = authorizer.authorize(
            tool_name="read_file",
            arguments={"filepath": encoded_path},
            requester_id="dev-01",
            requester_role=UserRole.DEVELOPER,
        )
        assert res.decision == AuthDecision.DENY
        assert any("Path traversal" in r for r in res.reasons)


def test_backslash_path_traversal_denied(authorizer):
    for win_path in ["..\\app.env", "..\\..\\config.yaml", "..\\..\\windows\\system32\\config"]:
        res = authorizer.authorize(
            tool_name="read_file",
            arguments={"filepath": win_path},
            requester_id="dev-01",
            requester_role=UserRole.DEVELOPER,
        )
        assert res.decision == AuthDecision.DENY
        assert any("Path traversal" in r for r in res.reasons)


def test_null_byte_path_traversal_denied(authorizer):
    for null_path in ["config.yaml\0.png", "config.yaml\x00.txt", "config.yaml%00.txt"]:
        res = authorizer.authorize(
            tool_name="read_file",
            arguments={"filepath": null_path},
            requester_id="dev-01",
            requester_role=UserRole.DEVELOPER,
        )
        assert res.decision == AuthDecision.DENY
        assert any("Null byte" in r for r in res.reasons)


def test_symlink_escape_denied(authorizer, tmp_path):
    # Create an outside target and a symlink inside the workspace
    outside_dir = tmp_path / "outside_secret"
    outside_dir.mkdir()
    secret_file = outside_dir / "secret.env"
    secret_file.write_text("SUPER_SECRET=123")

    inside_dir = tmp_path / "sandbox_workspace"
    inside_dir.mkdir()
    symlink_path = inside_dir / "escape_link.env"
    symlink_path.symlink_to(secret_file)

    # Validate safe path with explicit allowed base
    from backend.app.policies.tool_authorizer import validate_safe_path
    is_safe, err = validate_safe_path(str(symlink_path), allowed_base=inside_dir)
    assert not is_safe
    assert "escapes allowed base directory" in err


def test_legitimate_relative_paths_allowed(authorizer):
    for safe_path in ["config.yaml", "docs/README.md", "src/main.py"]:
        res = authorizer.authorize(
            tool_name="read_file",
            arguments={"filepath": safe_path},
            requester_id="dev-01",
            requester_role=UserRole.DEVELOPER,
        )
        assert res.decision == AuthDecision.ALLOW


def test_tool_arguments_schema_validation_unknown_args_rejected(authorizer):
    """Unknown or extra arguments must be rejected by Pydantic schema."""
    res = authorizer.authorize(
        tool_name="search_knowledge_base",
        arguments={"query": "test query", "unauthorized_extra_arg": "injected"},
        requester_id="user-01",
        requester_role=UserRole.USER,
    )
    assert res.decision == AuthDecision.DENY
    assert any("Extra inputs are not permitted" in r or "extra fields" in r for r in res.reasons)


def test_tool_arguments_schema_validation_type_mismatch_rejected(authorizer):
    """Argument type mismatches (e.g., int/list where string expected) must be rejected."""
    # Integer instead of string
    res = authorizer.authorize(
        tool_name="read_file",
        arguments={"filepath": 12345},
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
    )
    assert res.decision == AuthDecision.DENY
    assert any("Input should be a valid string" in r for r in res.reasons)

    # List instead of string
    res_weather = authorizer.authorize(
        tool_name="get_weather",
        arguments={"location": ["San Francisco", "CA"]},
        requester_id="user-01",
        requester_role=UserRole.USER,
    )
    assert res_weather.decision == AuthDecision.DENY
    assert any("Input should be a valid string" in r for r in res_weather.reasons)


def test_tool_arguments_nested_path_traversal_denied(authorizer):
    """Arbitrary nested JSON payloads containing traversal sequences must be denied."""
    nested_payloads = [
        {"config": {"filepath": "../secret.txt"}},
        {"parameters": {"nested": {"dir": "..\\windows\\system32"}}},
        {"items": [{"path": "../../etc/shadow"}]},
        {"data": {"file": "valid.txt\x00malicious.sh"}},
    ]
    for payload in nested_payloads:
        res = authorizer.authorize(
            tool_name="read_file",
            arguments=payload,
            requester_id="dev-01",
            requester_role=UserRole.DEVELOPER,
        )
        assert res.decision == AuthDecision.DENY
        assert any("Path traversal" in r or "Null byte" in r or "Invalid arguments" in r for r in res.reasons)

