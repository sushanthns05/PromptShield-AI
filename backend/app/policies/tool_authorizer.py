from dataclasses import dataclass, field
from enum import Enum
import logging
from typing import Any, Optional, Union

from backend.app.policies.approval_manager import ApprovalManager, ApprovalStatus
from backend.app.policies.tool_registry import ToolRegistry, ToolRiskLevel, UserRole
from backend.app.rag.context_analyzer import TrustLevel

logger = logging.getLogger("promptshield.tool_authorizer")


class AuthDecision(str, Enum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"


@dataclass
class AuthorizationResult:
    """Structured decision output from the ToolAuthorizer."""

    decision: AuthDecision
    tool_name: str
    requester_id: str
    requester_role: str
    risk_level: str
    reasons: list[str] = field(default_factory=list)
    approval_id: Optional[str] = None
    requires_approval: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "tool_name": self.tool_name,
            "requester_id": self.requester_id,
            "requester_role": self.requester_role,
            "risk_level": self.risk_level,
            "reasons": self.reasons,
            "approval_id": self.approval_id,
            "requires_approval": self.requires_approval,
        }


class ToolAuthorizer:
    """
    Independent backend authorization authority for tool actions.

    The LLM is NEVER an authorization authority. Every proposed tool call must be
    independently validated against the Tool Registry, RBAC policies, risk metrics,
    trust boundaries, and human approval constraints before execution.
    """

    def __init__(
        self,
        registry: Optional[ToolRegistry] = None,
        approval_manager: Optional[ApprovalManager] = None,
    ):
        self.registry = registry or ToolRegistry()
        self.approval_manager = approval_manager or ApprovalManager()

    @staticmethod
    def _normalize_role(role: Union[UserRole, str]) -> Optional[UserRole]:
        if isinstance(role, UserRole):
            return role
        if not isinstance(role, str):
            return None
        cleaned = role.strip().upper()
        for r in UserRole:
            if r.value == cleaned:
                return r
        return None

    def authorize(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        requester_id: str,
        requester_role: Union[UserRole, str],
        risk_score: int = 0,
        context_trust_level: Union[TrustLevel, str] = TrustLevel.UNTRUSTED,
        approval_id: Optional[str] = None,
        client_supplied_admin: bool = False,
        client_supplied_approved: bool = False,
    ) -> AuthorizationResult:
        reasons: list[str] = []

        # 1. Security Invariant: Neutralize untrusted client-supplied privilege flags
        if client_supplied_admin:
            logger.warning("Ignored client-supplied 'is_admin' claim for requester '%s'", requester_id)
            reasons.append("Security warning: Client-supplied admin flag ignored")

        if client_supplied_approved:
            logger.warning("Ignored client-supplied 'approved' claim for requester '%s'", requester_id)
            reasons.append("Security warning: Client-supplied approved flag ignored")

        # 2. Normalize and validate requester role
        role = self._normalize_role(requester_role)
        if role is None:
            reasons.append(f"Invalid or unrecognized user role: '{requester_role}'")
            return AuthorizationResult(
                decision=AuthDecision.DENY,
                tool_name=tool_name,
                requester_id=requester_id,
                requester_role=str(requester_role),
                risk_level="UNKNOWN",
                reasons=reasons,
            )

        # 3. Lookup tool in registry
        tool = self.registry.get_tool(tool_name)
        if tool is None:
            reasons.append(f"Denied: Unknown tool '{tool_name}'")
            return AuthorizationResult(
                decision=AuthDecision.DENY,
                tool_name=tool_name,
                requester_id=requester_id,
                requester_role=role.value,
                risk_level="UNKNOWN",
                reasons=reasons,
            )

        # 4. Check whether tool is enabled
        if not tool.is_enabled:
            reasons.append(f"Denied: Tool '{tool_name}' is disabled by administrative policy")
            return AuthorizationResult(
                decision=AuthDecision.DENY,
                tool_name=tool_name,
                requester_id=requester_id,
                requester_role=role.value,
                risk_level=tool.risk_level.value,
                reasons=reasons,
            )

        # 5. Validate tool arguments
        is_valid_args, arg_err = self.registry.validate_arguments(tool_name, arguments)
        if not is_valid_args:
            reasons.append(f"Denied: Argument validation failed: {arg_err}")
            return AuthorizationResult(
                decision=AuthDecision.DENY,
                tool_name=tool_name,
                requester_id=requester_id,
                requester_role=role.value,
                risk_level=tool.risk_level.value,
                reasons=reasons,
            )

        # 6. PromptShield Risk Score Enforcement
        if risk_score >= 70:
            reasons.append(f"Denied: Elevated PromptShield risk score ({risk_score}/100) prohibits tool invocation")
            return AuthorizationResult(
                decision=AuthDecision.DENY,
                tool_name=tool_name,
                requester_id=requester_id,
                requester_role=role.value,
                risk_level=tool.risk_level.value,
                reasons=reasons,
            )

        # 7. Role-Based Access Control (RBAC)
        if role not in tool.allowed_roles:
            reasons.append(f"Denied: Role '{role.value}' is not authorized to execute '{tool_name}'")
            return AuthorizationResult(
                decision=AuthDecision.DENY,
                tool_name=tool_name,
                requester_id=requester_id,
                requester_role=role.value,
                risk_level=tool.risk_level.value,
                reasons=reasons,
            )

        # 8. Trust-Boundary Enforcement: Untrusted context cannot trigger critical operations
        normalized_trust = (
            context_trust_level.value
            if isinstance(context_trust_level, TrustLevel)
            else str(context_trust_level).strip().upper()
        )
        if normalized_trust != TrustLevel.TRUSTED.value and tool.risk_level == ToolRiskLevel.CRITICAL:
            reasons.append("Denied: Critical tool invocation rejected from untrusted context")
            return AuthorizationResult(
                decision=AuthDecision.DENY,
                tool_name=tool_name,
                requester_id=requester_id,
                requester_role=role.value,
                risk_level=tool.risk_level.value,
                reasons=reasons,
            )

        # 9. Human Approval Workflow Verification
        needs_approval = tool.requires_approval or tool.risk_level in (ToolRiskLevel.HIGH, ToolRiskLevel.CRITICAL)
        if needs_approval:
            if approval_id:
                appr_req = self.approval_manager.get_request(approval_id)
                if not appr_req:
                    reasons.append(f"Denied: Approval request '{approval_id}' was not found")
                    return AuthorizationResult(
                        decision=AuthDecision.DENY,
                        tool_name=tool_name,
                        requester_id=requester_id,
                        requester_role=role.value,
                        risk_level=tool.risk_level.value,
                        reasons=reasons,
                    )

                if appr_req.is_expired or appr_req.status == ApprovalStatus.EXPIRED:
                    reasons.append("Denied: Human approval token has expired")
                    return AuthorizationResult(
                        decision=AuthDecision.DENY,
                        tool_name=tool_name,
                        requester_id=requester_id,
                        requester_role=role.value,
                        risk_level=tool.risk_level.value,
                        reasons=reasons,
                    )

                if appr_req.status == ApprovalStatus.CONSUMED:
                    reasons.append("Denied: Approval token has already been consumed (replay prevention)")
                    return AuthorizationResult(
                        decision=AuthDecision.DENY,
                        tool_name=tool_name,
                        requester_id=requester_id,
                        requester_role=role.value,
                        risk_level=tool.risk_level.value,
                        reasons=reasons,
                    )

                if appr_req.status != ApprovalStatus.APPROVED:
                    reasons.append(f"Approval status is currently {appr_req.status.value}")
                    return AuthorizationResult(
                        decision=AuthDecision.REQUIRE_APPROVAL,
                        tool_name=tool_name,
                        requester_id=requester_id,
                        requester_role=role.value,
                        risk_level=tool.risk_level.value,
                        approval_id=approval_id,
                        requires_approval=True,
                        reasons=reasons,
                    )

                # SEC-01 FIX: Strict Requester Binding verification (prevent token hijacking)
                if appr_req.requester_id != requester_id:
                    reasons.append(
                        f"Denied: Approval token '{approval_id}' is bound to requester '{appr_req.requester_id}', not '{requester_id}'"
                    )
                    return AuthorizationResult(
                        decision=AuthDecision.DENY,
                        tool_name=tool_name,
                        requester_id=requester_id,
                        requester_role=role.value,
                        risk_level=tool.risk_level.value,
                        reasons=reasons,
                    )

                # Verify argument integrity against approved arguments
                if appr_req.arguments != arguments:
                    reasons.append("Denied: Invocation arguments do not match approved parameters")
                    return AuthorizationResult(
                        decision=AuthDecision.DENY,
                        tool_name=tool_name,
                        requester_id=requester_id,
                        requester_role=role.value,
                        risk_level=tool.risk_level.value,
                        reasons=reasons,
                    )

                # Approved and validated
                reasons.append("Action authorized with verified human approval")
                return AuthorizationResult(
                    decision=AuthDecision.ALLOW,
                    tool_name=tool_name,
                    requester_id=requester_id,
                    requester_role=role.value,
                    risk_level=tool.risk_level.value,
                    approval_id=approval_id,
                    requires_approval=True,
                    reasons=reasons,
                )
            else:
                # No approval ID provided: Generate pending approval request
                appr_req = self.approval_manager.create_request(
                    tool_name=tool_name,
                    arguments=arguments,
                    requester_id=requester_id,
                    requester_role=role,
                    risk_level=tool.risk_level.value,
                )
                reasons.append(f"Tool '{tool_name}' requires human approval before execution")
                return AuthorizationResult(
                    decision=AuthDecision.REQUIRE_APPROVAL,
                    tool_name=tool_name,
                    requester_id=requester_id,
                    requester_role=role.value,
                    risk_level=tool.risk_level.value,
                    approval_id=appr_req.approval_id,
                    requires_approval=True,
                    reasons=reasons,
                )

        # 10. Direct ALLOW for validated low/medium risk actions within policy
        reasons.append("Tool invocation permitted by backend authorization policy")
        return AuthorizationResult(
            decision=AuthDecision.ALLOW,
            tool_name=tool_name,
            requester_id=requester_id,
            requester_role=role.value,
            risk_level=tool.risk_level.value,
            requires_approval=False,
            reasons=reasons,
        )
