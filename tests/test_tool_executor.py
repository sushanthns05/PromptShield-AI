import asyncio
import json
from typing import Any, Optional
import pytest

from backend.app.main import app
from backend.app.policies.approval_manager import ApprovalManager
from backend.app.policies.tool_authorizer import ToolAuthorizer
from backend.app.policies.tool_executor import ToolExecutor
from backend.app.policies.tool_registry import ToolRegistry, UserRole


class ASGIClient:
    """Lightweight ASGI test client using pure Python and ASGI protocol."""

    def __init__(self, application):
        self.application = application

    async def _request(
        self,
        method: str,
        path: str,
        json_data: Optional[Any] = None,
        headers: Optional[dict[str, str]] = None,
    ):
        body = json.dumps(json_data).encode("utf-8") if json_data is not None else b""
        req_headers = [[b"host", b"testserver"]]
        if json_data is not None:
            req_headers.append([b"content-type", b"application/json"])
            req_headers.append([b"content-length", str(len(body)).encode()])
        if headers:
            for k, v in headers.items():
                req_headers.append([k.lower().encode(), v.encode()])

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method.upper(),
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": req_headers,
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "scheme": "http",
            "app": self.application,
        }

        sent = []

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            sent.append(message)

        await self.application(scope, receive, send)

        status_code = 500
        resp_headers: dict[str, str] = {}
        body_chunks = []
        for msg in sent:
            if msg["type"] == "http.response.start":
                status_code = msg["status"]
                for k, v in msg.get("headers", []):
                    resp_headers[k.decode("utf-8").lower()] = v.decode("utf-8")
            elif msg["type"] == "http.response.body":
                body_chunks.append(msg.get("body", b""))

        raw_bytes = b"".join(body_chunks)
        parsed_json = json.loads(raw_bytes.decode("utf-8")) if raw_bytes else None
        return status_code, parsed_json, raw_bytes.decode("utf-8")

    def get(self, path: str, headers: Optional[dict[str, str]] = None):
        return asyncio.run(self._request("GET", path, headers=headers))

    def post(
        self,
        path: str,
        json_data: Optional[Any] = None,
        headers: Optional[dict[str, str]] = None,
    ):
        return asyncio.run(self._request("POST", path, json_data=json_data, headers=headers))


@pytest.fixture
def registry():
    return ToolRegistry()


@pytest.fixture
def approval_manager():
    return ApprovalManager()


@pytest.fixture
def authorizer(registry, approval_manager):
    return ToolAuthorizer(registry=registry, approval_manager=approval_manager)


@pytest.fixture
def executor(authorizer, approval_manager, registry):
    return ToolExecutor(
        authorizer=authorizer,
        approval_manager=approval_manager,
        registry=registry,
    )


@pytest.fixture(scope="module")
def api_client():
    # Initialize application lifespan once for the test module
    async def startup():
        async def receive():
            return {"type": "lifespan.startup"}

        async def send(msg):
            pass

        await app({"type": "lifespan", "state": app.state}, receive, send)

    asyncio.run(startup())
    return ASGIClient(app)


# ---------------------------------------------------------------------------
# Unit Tests: ToolExecutor
# ---------------------------------------------------------------------------


def test_executor_authorized_low_risk_tool(executor):
    result = executor.execute(
        tool_name="search_knowledge_base",
        arguments={"query": "threat modeling"},
        requester_id="user-01",
        requester_role=UserRole.USER,
    )
    assert result.status == "SUCCESS"
    assert result.execution_id.startswith("exec-")
    assert "matches" in result.result


def test_executor_blocks_unauthorized_role(executor):
    # USER cannot execute read_file
    with pytest.raises(PermissionError, match="Unauthorized tool execution: DENY"):
        executor.execute(
            tool_name="read_file",
            arguments={"filepath": "internal.conf"},
            requester_id="user-01",
            requester_role=UserRole.USER,
        )


def test_executor_directory_traversal_protection(executor):
    # Defense-in-depth Layer 1: Authorization layer rejects traversal prior to execution
    with pytest.raises(PermissionError, match="Path traversal"):
        executor.execute(
            tool_name="read_file",
            arguments={"filepath": "../../etc/passwd"},
            requester_id="dev-01",
            requester_role=UserRole.DEVELOPER,
        )

    # Defense-in-depth Layer 2: Executor sandbox independently rejects traversal if authorizer is bypassed
    direct_sim = executor._run_simulated_tool("read_file", {"filepath": "../../etc/passwd"})
    assert "error" in direct_sim
    assert "Directory traversal" in direct_sim["error"]


def test_executor_sandbox_blocks_traversal_if_authorizer_bypassed(registry, approval_manager):
    """
    Defense-in-depth: Even if a permissive or buggy authorizer allows a traversal path,
    the executor's execution sandbox MUST independently detect and block it.
    """
    class PermissiveMockAuthorizer:
        def authorize(self, **kwargs):
            from backend.app.policies.tool_authorizer import AuthDecision, AuthorizationResult
            return AuthorizationResult(
                decision=AuthDecision.ALLOW,
                tool_name=kwargs.get("tool_name", "read_file"),
                requester_id=kwargs.get("requester_id", "dev-01"),
                requester_role="DEVELOPER",
                risk_level="MEDIUM",
            )

    bypassed_executor = ToolExecutor(
        authorizer=PermissiveMockAuthorizer(),
        approval_manager=approval_manager,
        registry=registry,
    )
    result = bypassed_executor.execute(
        tool_name="read_file",
        arguments={"filepath": "../../etc/shadow"},
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
    )
    assert result.status == "SUCCESS"
    assert "error" in result.result
    assert "Directory traversal or invalid path rejected by execution sandbox" in result.result["error"]


def test_executor_command_never_invokes_real_shell(executor, registry, approval_manager):
    # Enable execute_command for testing simulation guarantees
    registry.enable_tool("execute_command")
    cmd_args = {"command": "rm -rf /"}

    # Must have human approval since execute_command is CRITICAL risk
    req = approval_manager.create_request(
        tool_name="execute_command",
        arguments=cmd_args,
        requester_id="admin-01",
        requester_role=UserRole.ADMIN,
        risk_level=registry.get_tool("execute_command").risk_level,
    )
    approval_manager.approve(req.approval_id, approver_id="sec-admin", approver_role=UserRole.ADMIN)

    result = executor.execute(
        tool_name="execute_command",
        arguments=cmd_args,
        requester_id="admin-01",
        requester_role=UserRole.ADMIN,
        context_trust_level="TRUSTED",  # Trusted context required for critical tool
        approval_id=req.approval_id,
    )
    assert result.status == "SUCCESS"
    assert result.result["simulated"] is True
    assert "[SIMULATED SANDBOX OUTPUT" in result.result["stdout"]


def test_executor_high_risk_tool_full_approval_flow(executor, approval_manager):
    args = {"recipient": "client@corp.com", "subject": "Billing", "body": "Attached"}

    # 1. Direct execute without approval raises PermissionError
    with pytest.raises(PermissionError, match="REQUIRE_APPROVAL"):
        executor.execute(
            tool_name="send_email",
            arguments=args,
            requester_id="dev-01",
            requester_role=UserRole.DEVELOPER,
        )

    # 2. Request and approve
    req = approval_manager.create_request(
        tool_name="send_email",
        arguments=args,
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        risk_level=ToolRegistry().get_tool("send_email").risk_level,
    )
    approval_manager.approve(req.approval_id, approver_id="admin-01", approver_role=UserRole.ADMIN)

    # 3. Execute with approval_id
    res = executor.execute(
        tool_name="send_email",
        arguments=args,
        requester_id="dev-01",
        requester_role=UserRole.DEVELOPER,
        approval_id=req.approval_id,
    )
    assert res.status == "SUCCESS"
    assert res.result["status"] == "queued"

    # 4. Attempt replay execution with same approval_id must fail
    with pytest.raises((PermissionError, ValueError), match="already been consumed"):
        executor.execute(
            tool_name="send_email",
            arguments=args,
            requester_id="dev-01",
            requester_role=UserRole.DEVELOPER,
            approval_id=req.approval_id,
        )


# ---------------------------------------------------------------------------
# API Integration Tests: Tools Endpoints
# ---------------------------------------------------------------------------


def test_api_tool_authorize_low_risk(api_client):
    payload = {
        "tool_name": "get_weather",
        "arguments": {"location": "San Francisco"},
        "requester_id": "user-api-01",
        "requester_role": "USER",
    }
    status, body, _ = api_client.post("/api/v1/tools/authorize", json_data=payload)
    assert status == 200
    assert body["decision"] == "ALLOW"
    assert body["requires_approval"] is False


def test_api_tool_authorize_high_risk_requires_approval(api_client):
    payload = {
        "tool_name": "send_email",
        "arguments": {"recipient": "user@test.com", "subject": "Hello", "body": "World"},
        "requester_id": "dev-api-01",
        "requester_role": "DEVELOPER",
    }
    status, body, _ = api_client.post("/api/v1/tools/authorize", json_data=payload)
    assert status == 200
    assert body["decision"] == "REQUIRE_APPROVAL"
    assert body["requires_approval"] is True
    assert body["approval_id"] is not None


def test_api_tool_authorize_spoofed_admin_ignored(api_client):
    payload = {
        "tool_name": "read_file",
        "arguments": {"filepath": "secret.env"},
        "requester_id": "attacker-01",
        "requester_role": "USER",
        "is_admin": True,  # Spoofed admin claim
    }
    status, body, _ = api_client.post("/api/v1/tools/authorize", json_data=payload)
    assert status == 200
    assert body["decision"] == "DENY"
    assert any("Client-supplied admin flag ignored" in r for r in body["reasons"])


def test_api_tool_execute_authorized(api_client):
    payload = {
        "tool_name": "search_knowledge_base",
        "arguments": {"query": "authentication"},
        "requester_id": "user-api-02",
        "requester_role": "USER",
    }
    status, body, _ = api_client.post("/api/v1/tools/execute", json_data=payload)
    assert status == 200
    assert body["status"] == "SUCCESS"
    assert "matches" in body["result"]


def test_api_tool_execute_unauthorized_returns_403(api_client):
    payload = {
        "tool_name": "delete_file",
        "arguments": {"filepath": "db.sqlite"},
        "requester_id": "user-api-03",
        "requester_role": "USER",
    }
    status, body, _ = api_client.post("/api/v1/tools/execute", json_data=payload)
    assert status == 403


def test_api_approval_lifecycle_and_execution(api_client):
    email_args = {"recipient": "team@example.com", "subject": "Status", "body": "All good"}

    # 1. Authorize high-risk tool -> REQUIRE_APPROVAL
    auth_payload = {
        "tool_name": "send_email",
        "arguments": email_args,
        "requester_id": "dev-api-02",
        "requester_role": "DEVELOPER",
    }
    status, auth_body, _ = api_client.post("/api/v1/tools/authorize", json_data=auth_payload)
    assert status == 200
    assert auth_body["decision"] == "REQUIRE_APPROVAL"
    approval_id = auth_body["approval_id"]

    # 2. Non-admin cannot approve -> 403
    decide_fail_payload = {
        "decision": "APPROVE",
        "approver_id": "dev-peer",
        "approver_role": "DEVELOPER",
    }
    status, _, _ = api_client.post(
        f"/api/v1/tools/approvals/{approval_id}/decision",
        json_data=decide_fail_payload,
    )
    assert status == 403

    # 3. Admin approves -> 200 OK
    decide_success_payload = {
        "decision": "APPROVE",
        "approver_id": "admin-super",
        "approver_role": "ADMIN",
        "reason": "Verified change ticket",
    }
    status, decide_body, _ = api_client.post(
        f"/api/v1/tools/approvals/{approval_id}/decision",
        json_data=decide_success_payload,
    )
    assert status == 200
    assert decide_body["status"] == "APPROVED"

    # 4. Execute with approval_id -> 200 OK
    exec_payload = {
        "tool_name": "send_email",
        "arguments": email_args,
        "requester_id": "dev-api-02",
        "requester_role": "DEVELOPER",
        "approval_id": approval_id,
    }
    status, exec_body, _ = api_client.post("/api/v1/tools/execute", json_data=exec_payload)
    assert status == 200
    assert exec_body["status"] == "SUCCESS"
    assert exec_body["result"]["status"] == "queued"

    # 5. Replay attempt with already-consumed approval -> 400 or 403
    status, replay_body, _ = api_client.post("/api/v1/tools/execute", json_data=exec_payload)
    assert status in (400, 403)


def test_executor_denies_hijacked_approval_token(executor, approval_manager):
    """Regression test: ToolExecutor rejects token consumption by unauthorized requester."""
    args = {"recipient": "boss@corp.com", "subject": "Quarterly", "body": "Report"}
    req = approval_manager.create_request(
        tool_name="send_email",
        arguments=args,
        requester_id="victim-user",
        requester_role=UserRole.DEVELOPER,
        risk_level=ToolRegistry().get_tool("send_email").risk_level,
    )
    approval_manager.approve(req.approval_id, approver_id="admin-01", approver_role=UserRole.ADMIN)

    with pytest.raises(PermissionError, match="bound to requester 'victim-user'"):
        executor.execute(
            tool_name="send_email",
            arguments=args,
            requester_id="attacker-user",
            requester_role=UserRole.DEVELOPER,
            approval_id=req.approval_id,
        )


def test_executor_sensitive_data_redacted_in_simulated_output(executor, registry, approval_manager):
    """Regression test: ToolExecutor output redacts sensitive data like API keys."""
    registry.enable_tool("execute_command")
    cmd_args = {"command": "deploy --api-key=sk-123456789012345678901234"}
    req = approval_manager.create_request(
        tool_name="execute_command",
        arguments=cmd_args,
        requester_id="admin-01",
        requester_role=UserRole.ADMIN,
        risk_level=registry.get_tool("execute_command").risk_level,
    )
    approval_manager.approve(req.approval_id, approver_id="sec-admin", approver_role=UserRole.ADMIN)

    res = executor.execute(
        tool_name="execute_command",
        arguments=cmd_args,
        requester_id="admin-01",
        requester_role=UserRole.ADMIN,
        context_trust_level="TRUSTED",
        approval_id=req.approval_id,
    )
    assert "sk-123456789012345678901234" not in res.result["command"]
    assert "sk-123456789012345678901234" not in res.result["stdout"]
    assert "[REDACTED_OPENAI_API_KEY]" in res.result["command"]
    assert "[REDACTED_OPENAI_API_KEY]" in res.result["stdout"]


def test_api_client_cannot_assert_trusted_context_for_critical_tool(api_client):
    """Regression test: External API caller cannot bypass untrusted context check for critical tools."""
    # Ensure delete_file is enabled in the app's tool registry for this test
    app.state.tool_registry.enable_tool("delete_file")

    payload = {
        "tool_name": "delete_file",
        "arguments": {"filepath": "production.db"},
        "requester_id": "admin-01",
        "requester_role": "ADMIN",
        "context_trust_level": "TRUSTED",  # Client attempts to spoof trusted context
    }
    status, body, _ = api_client.post("/api/v1/tools/authorize", json_data=payload)
    assert status == 200
    assert body["decision"] == "DENY"
    assert any("Critical tool invocation rejected from untrusted context" in r for r in body["reasons"])
