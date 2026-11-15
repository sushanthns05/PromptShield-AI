from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from typing import Any, Optional, Union
from uuid import uuid4

from backend.app.policies.approval_manager import ApprovalManager
from backend.app.policies.tool_authorizer import AuthDecision, ToolAuthorizer
from backend.app.policies.tool_registry import ToolRegistry, UserRole
from backend.app.privacy.pii_detector import redact_sensitive_data
from backend.app.rag.context_analyzer import TrustLevel

logger = logging.getLogger("promptshield.tool_executor")


@dataclass
class ExecutionResult:
    """Structured execution outcome of a securely dispatched tool invocation."""

    execution_id: str
    tool_name: str
    status: str  # SUCCESS, FAILED, DENIED
    result: dict[str, Any]
    executed_at: str
    requester_id: str
    approval_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "tool_name": self.tool_name,
            "status": self.status,
            "result": self.result,
            "executed_at": self.executed_at,
            "requester_id": self.requester_id,
            "approval_id": self.approval_id,
        }


class ToolExecutor:
    """
    Secure tool execution sandbox simulator.

    CRITICAL SECURITY GUARANTEES:
    - Never invokes os.system, subprocess, eval, or exec.
    - Never evaluates arbitrary code supplied in prompts, documents, or tool inputs.
    - Strictly rejects any tool execution attempt not authorized by ToolAuthorizer.
    - Consumes approval tokens immediately upon execution to prevent replay attacks.
    """

    def __init__(
        self,
        authorizer: Optional[ToolAuthorizer] = None,
        approval_manager: Optional[ApprovalManager] = None,
        registry: Optional[ToolRegistry] = None,
    ):
        self.registry = registry or ToolRegistry()
        self.approval_manager = approval_manager or ApprovalManager()
        self.authorizer = authorizer or ToolAuthorizer(
            registry=self.registry,
            approval_manager=self.approval_manager,
        )

    def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        requester_id: str,
        requester_role: Union[UserRole, str],
        risk_score: int = 0,
        context_trust_level: Union[TrustLevel, str] = TrustLevel.UNTRUSTED,
        approval_id: Optional[str] = None,
    ) -> ExecutionResult:
        # 1. Independent backend authorization check
        auth_result = self.authorizer.authorize(
            tool_name=tool_name,
            arguments=arguments,
            requester_id=requester_id,
            requester_role=requester_role,
            risk_score=risk_score,
            context_trust_level=context_trust_level,
            approval_id=approval_id,
        )

        if auth_result.decision != AuthDecision.ALLOW:
            reasons_str = "; ".join(auth_result.reasons)
            logger.warning(
                "Execution rejected for '%s' by '%s': %s (Decision: %s)",
                tool_name,
                requester_id,
                reasons_str,
                auth_result.decision.value,
            )
            raise PermissionError(
                f"Unauthorized tool execution: {auth_result.decision.value}. Reasons: {reasons_str}"
            )

        # 2. Consume approval token if tool execution required one
        if approval_id:
            self.approval_manager.consume(
                approval_id=approval_id,
                tool_name=tool_name,
                arguments=arguments,
            )

        execution_id = f"exec-{uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()

        # 3. Controlled sandbox execution simulator
        simulated_output = self._run_simulated_tool(tool_name, arguments)

        logger.info(
            "Tool '%s' executed successfully (ID: %s, Requester: %s)",
            tool_name,
            execution_id,
            requester_id,
        )

        return ExecutionResult(
            execution_id=execution_id,
            tool_name=tool_name,
            status="SUCCESS",
            result=simulated_output,
            executed_at=now,
            requester_id=requester_id,
            approval_id=approval_id,
        )

    def _run_simulated_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """
        Dispatches safely to simulated handlers without executing arbitrary commands.
        """
        if name == "search_knowledge_base":
            query = args.get("query", "")
            return {
                "matches": [
                    {
                        "doc_id": "kb-101",
                        "title": f"Enterprise Guide for {query}",
                        "snippet": f"Verified documentation regarding {query}.",
                        "relevance": 0.94,
                    }
                ],
                "total_results": 1,
            }

        elif name == "get_weather":
            loc = args.get("location", "Unknown")
            return {
                "location": loc,
                "temperature_c": 22,
                "conditions": "Clear",
                "humidity": 45,
            }

        elif name == "read_file":
            filepath = str(args.get("filepath", ""))
            # Prevent directory traversal simulation
            if ".." in filepath:
                return {
                    "error": "Directory traversal characters '..' are forbidden",
                    "filepath": filepath,
                }
            return {
                "filepath": filepath,
                "simulated_content": f"# Content of {filepath}\n[Simulated safe read output]",
                "size_bytes": 1024,
            }

        elif name == "send_email":
            recipient = args.get("recipient", "")
            subject = args.get("subject", "")
            return {
                "status": "queued",
                "recipient": recipient,
                "subject": subject,
                "message": "Email simulated successfully",
            }

        elif name == "delete_file":
            filepath = str(args.get("filepath", ""))
            return {
                "status": "deleted",
                "filepath": filepath,
                "message": f"Simulated deletion of {filepath}",
            }

        elif name == "execute_command":
            cmd = str(args.get("command", ""))
            # SECURITY GUARANTEE: Never invoke subprocess or shell!
            return {
                "simulated": True,
                "command": cmd,
                "stdout": f"[SIMULATED SANDBOX OUTPUT for: {cmd}]",
                "exit_code": 0,
            }

        return {"error": f"No simulated handler for tool: {name}"}
