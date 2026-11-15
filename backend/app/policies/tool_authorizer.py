from dataclasses import dataclass, field
from enum import Enum
import logging
from pathlib import Path
import re
from typing import Any, Optional, Union
import urllib.parse

from backend.app.policies.approval_manager import ApprovalManager, ApprovalStatus
from backend.app.policies.canonicalization import canonicalize_arguments
from backend.app.policies.tool_registry import ToolRegistry, ToolRiskLevel, UserRole
from backend.app.rag.context_analyzer import TrustLevel

logger = logging.getLogger("promptshield.tool_authorizer")


def validate_safe_path(
    path_input: Any,
    allowed_base: Optional[Path] = None,
) -> tuple[bool, Optional[str]]:
    """
    Validate that a file path parameter does not perform directory traversal,
    null-byte injection, URL-encoding bypass, or absolute/symlink escape.

    Returns (is_valid, error_reason).
    """
    if not isinstance(path_input, str):
        return False, "Path must be a string"

    if not path_input.strip():
        return False, "Path cannot be empty"

    # 1. Null-byte injection check (raw string)
    if "\x00" in path_input or "\0" in path_input or "%00" in path_input.lower():
        return False, "Null byte injection detected in path"

    # 2. URL decoding & iterative unquoting (prevent double/nested URL encoding)
    decoded = path_input
    for _ in range(3):
        unquoted = urllib.parse.unquote(decoded)
        if unquoted == decoded:
            break
        decoded = unquoted

    # Check for null byte post-decode
    if "\x00" in decoded or "\0" in decoded:
        return False, "Null byte injection detected in decoded path"

    # 3. Backslash normalization
    normalized = decoded.replace("\\", "/")

    # 4. Directory traversal sequence checks
    segments = normalized.split("/")
    if ".." in segments or "../" in normalized or "/.." in normalized or normalized == "..":
        return False, "Directory traversal ('..') sequence detected"

    # Reject Windows drive letters (e.g. C:, D:)
    if re.match(r"^[A-Za-z]:", normalized):
        return False, "Drive letter prefix forbidden in path"

    # 5. Base directory containment & absolute path escape check
    base_dir = (allowed_base or Path.cwd()).resolve()

    try:
        if normalized.startswith("/"):
            resolved = Path(normalized).resolve()
        else:
            resolved = (base_dir / normalized).resolve()

        resolved.relative_to(base_dir)
    except (ValueError, RuntimeError):
        return False, "Path escapes allowed base directory"

    # 6. Symlink escape check
    try:
        if resolved.is_symlink():
            target = resolved.resolve()
            target.relative_to(base_dir)
    except (ValueError, RuntimeError):
        return False, "Symlink target escapes allowed base directory"

    return True, None


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

    def evaluate_authorization(
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
        analysis_decision: Optional[str] = None,
        bound_approval_id: Optional[str] = None,
    ) -> AuthorizationResult:
        """
        Side-effect-free evaluation of tool authorization policies.
        Evaluates tool existence, schema, traversal, risk policy, RBAC,
        trust boundary, and approval state WITHOUT creating pending approval requests.
        """
        return self.authorize(
            tool_name=tool_name,
            arguments=arguments,
            requester_id=requester_id,
            requester_role=requester_role,
            risk_score=risk_score,
            context_trust_level=context_trust_level,
            approval_id=approval_id,
            client_supplied_admin=client_supplied_admin,
            client_supplied_approved=client_supplied_approved,
            analysis_decision=analysis_decision,
            create_approval=False,
            bound_approval_id=bound_approval_id,
        )

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
        analysis_decision: Optional[str] = None,
        create_approval: bool = True,
        bound_approval_id: Optional[str] = None,
    ) -> AuthorizationResult:
        reasons: list[str] = []

        # 0. Enforce Authoritative Analysis Decision if supplied
        if analysis_decision is not None:
            norm_dec = str(analysis_decision).strip().upper()
            if norm_dec != "ALLOW":
                if norm_dec == "BLOCK":
                    reasons.append("Denied: Upstream prompt analysis resulted in BLOCK decision")
                elif norm_dec == "SANITIZE":
                    reasons.append(
                        "Denied: Upstream prompt analysis resulted in SANITIZE decision. "
                        "Resubmit sanitized prompt for analysis before tool invocation."
                    )
                else:
                    reasons.append(f"Denied: Invalid or unverified analysis decision '{analysis_decision}'")
                return AuthorizationResult(
                    decision=AuthDecision.DENY,
                    tool_name=tool_name,
                    requester_id=requester_id,
                    requester_role=str(requester_role),
                    risk_level="HIGH",
                    reasons=reasons,
                )

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

        # 5a. Recursively validate path parameters and arbitrary nested JSON for directory traversal & null bytes
        path_param_names = {
            "filepath",
            "file_path",
            "path",
            "filename",
            "file",
            "dest_path",
            "src_path",
            "directory",
            "dir",
        }

        def _find_path_error(obj: Any, key_name: str = "") -> Optional[str]:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    k_str = f"{key_name}.{k}" if key_name else str(k)
                    err = _find_path_error(v, k_str)
                    if err:
                        return err
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    err = _find_path_error(item, f"{key_name}[{idx}]")
                    if err:
                        return err
            elif isinstance(obj, str):
                if any(p in key_name.lower() for p in path_param_names) or ".." in obj or "\x00" in obj:
                    is_safe, err_msg = validate_safe_path(obj)
                    if not is_safe:
                        return f"Path traversal or invalid path in argument '{key_name}': {err_msg}"
            return None

        traversal_err = _find_path_error(arguments)
        if traversal_err:
            reasons.append(f"Denied: {traversal_err}")
            return AuthorizationResult(
                decision=AuthDecision.DENY,
                tool_name=tool_name,
                requester_id=requester_id,
                requester_role=role.value,
                risk_level=tool.risk_level.value,
                reasons=reasons,
            )

        # 5b. Validate tool argument types and strict Pydantic schemas
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
        # Unknown or invalid trust values must fail closed to UNTRUSTED
        raw_trust = (
            context_trust_level.value
            if isinstance(context_trust_level, TrustLevel)
            else str(context_trust_level).strip().upper()
        )
        if raw_trust not in (TrustLevel.TRUSTED.value, "TRUSTED", "SYSTEM_TRUSTED"):
            normalized_trust = TrustLevel.UNTRUSTED.value
        else:
            normalized_trust = raw_trust

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
        if bound_approval_id and approval_id and approval_id != bound_approval_id:
            reasons.append(
                f"Denied: Supplied approval ID '{approval_id}' does not match bound approval ID '{bound_approval_id}'"
            )
            return AuthorizationResult(
                decision=AuthDecision.DENY,
                tool_name=tool_name,
                requester_id=requester_id,
                requester_role=role.value,
                risk_level=tool.risk_level.value,
                reasons=reasons,
            )

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

                # Verify argument integrity against approved arguments using unified canonicalization
                try:
                    if canonicalize_arguments(appr_req.arguments) != canonicalize_arguments(arguments):
                        reasons.append("Denied: Invocation arguments do not match approved parameters")
                        return AuthorizationResult(
                            decision=AuthDecision.DENY,
                            tool_name=tool_name,
                            requester_id=requester_id,
                            requester_role=role.value,
                            risk_level=tool.risk_level.value,
                            reasons=reasons,
                        )
                except (TypeError, ValueError) as exc:
                    reasons.append(f"Denied: Argument canonicalization failed: {exc}")
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
                # No approval ID provided
                if create_approval:
                    appr_req = self.approval_manager.create_request(
                        tool_name=tool_name,
                        arguments=arguments,
                        requester_id=requester_id,
                        requester_role=role,
                        risk_level=tool.risk_level.value,
                    )
                    gen_approval_id = appr_req.approval_id
                else:
                    gen_approval_id = None

                reasons.append(f"Tool '{tool_name}' requires human approval before execution")
                return AuthorizationResult(
                    decision=AuthDecision.REQUIRE_APPROVAL,
                    tool_name=tool_name,
                    requester_id=requester_id,
                    requester_role=role.value,
                    risk_level=tool.risk_level.value,
                    approval_id=gen_approval_id,
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
