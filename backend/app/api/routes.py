from enum import Enum
import json
import logging
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, Request
import pandas as pd
from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.monitoring.event_store import EventStore
from backend.app.policies.analysis_context import AnalysisContextStore
from backend.app.policies.approval_manager import ApprovalManager
from backend.app.policies.risk_engine import RiskEngine
from backend.app.policies.tool_authorizer import AuthDecision, AuthorizationResult, ToolAuthorizer
from backend.app.policies.tool_executor import ToolExecutor
from backend.app.policies.tool_registry import ToolRegistry
from backend.app.privacy.pii_detector import redact_sensitive_data
from backend.app.rag.context_analyzer import ContextAnalyzer
from backend.app.rag.context_policy import ContextPolicy
from backend.app.rag.document_scanner import DocumentScanner

logger = logging.getLogger("promptshield.api")

router = APIRouter()


class DecisionEnum(str, Enum):
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"


# ---------------------------------------------------------------------------
# Request & Response Pydantic Schemas
# ---------------------------------------------------------------------------


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(..., description="Prompt text to inspect and analyze")
    requester_id: Optional[str] = Field(
        default="dev-user",
        description="Development-only requester identity binding",
    )

    @field_validator("prompt")
    @classmethod
    def validate_prompt(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Prompt must be a string")
        if not v.strip():
            raise ValueError("Prompt cannot be empty or whitespace only")
        return v


class RuleFindingItem(BaseModel):
    rule_id: str
    category: str
    severity: str
    matched_pattern: str


class MLPredictionItem(BaseModel):
    prediction: str
    confidence: float
    class_id: Optional[int] = None
    status: str = "success"
    error: Optional[str] = None


class SensitiveFindingItem(BaseModel):
    type: str
    start: int
    end: int
    redacted_value: str


class AnalysisDetails(BaseModel):
    rule_findings: list[RuleFindingItem] = Field(default_factory=list)
    ml_prediction: Optional[MLPredictionItem] = None
    sensitive_data_findings: list[SensitiveFindingItem] = Field(default_factory=list)


class AnalyzeResponse(BaseModel):
    analysis_id: str = Field(..., description="Server-controlled analysis context ID")
    decision: DecisionEnum
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str
    sanitized_prompt: Optional[str] = None
    reasons: list[str] = Field(default_factory=list)
    details: AnalysisDetails


class ScanDocumentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document_id: str = Field(..., min_length=1, description="Unique identifier for the document")
    content: str = Field(..., description="Document content text")
    source: str = Field(default="retrieved_document", description="Source classification of document")

    @field_validator("document_id")
    @classmethod
    def validate_document_id(cls, v: str) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("document_id cannot be empty or whitespace only")
        return v.strip()


class ScanDocumentResponse(BaseModel):
    document_id: str
    trust_level: str
    decision: str
    risk_score: int = Field(..., ge=0, le=100)
    findings: dict[str, Any]
    sanitized_preview: str
    reasons: list[str] = Field(default_factory=list)


# --- Tool Authorization Models ---


class ToolAuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_name: str = Field(..., min_length=1, description="Name of tool to authorize")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Arguments for tool invocation")
    requester_id: str = Field(..., min_length=1, description="Identifier of the requester")
    requester_role: str = Field(default="USER", description="Development-only requester role claim")
    analysis_id: str = Field(
        ...,
        min_length=1,
        description="Required server-controlled analysis context UUID from /api/v1/analyze",
    )
    risk_score: Optional[int] = Field(
        default=None,
        description="Client-supplied risk score (untrusted/ignored; server context is authoritative)",
    )
    context_trust_level: Optional[str] = Field(
        default="UNTRUSTED",
        description="Client-supplied context trust claim (untrusted/ignored; server context is authoritative)",
    )
    approval_id: Optional[str] = Field(default=None, description="Existing human approval token if acquired")
    is_admin: Optional[bool] = Field(default=None, description="Client-supplied admin flag (untrusted/ignored)")
    approved: Optional[bool] = Field(default=None, description="Client-supplied approval flag (untrusted/ignored)")


class ToolAuthorizeResponse(BaseModel):
    decision: str
    tool_name: str
    requester_id: str
    requester_role: str
    risk_level: str
    reasons: list[str] = Field(default_factory=list)
    approval_id: Optional[str] = None
    requires_approval: bool = False


class ToolExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_name: str = Field(..., min_length=1, description="Name of tool to execute")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Arguments for tool invocation")
    requester_id: str = Field(..., min_length=1, description="Identifier of the requester")
    requester_role: str = Field(default="USER", description="Development-only requester role claim")
    analysis_id: str = Field(
        ...,
        min_length=1,
        description="Required server-controlled analysis context UUID from /api/v1/analyze",
    )
    risk_score: Optional[int] = Field(
        default=None,
        description="Client-supplied risk score (untrusted/ignored; server context is authoritative)",
    )
    context_trust_level: Optional[str] = Field(
        default="UNTRUSTED",
        description="Client-supplied context trust claim (untrusted/ignored; server context is authoritative)",
    )
    approval_id: Optional[str] = Field(default=None, description="Approved human approval token")


class ToolExecuteResponse(BaseModel):
    execution_id: str
    tool_name: str
    status: str
    result: dict[str, Any]
    executed_at: str
    requester_id: str
    approval_id: Optional[str] = None


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str = Field(..., description="'APPROVE' or 'REJECT'")
    approver_id: str = Field(
        ...,
        min_length=1,
        description="Development-only claimed identifier of the reviewer/approver (unauthenticated)",
    )
    approver_role: str = Field(
        ...,
        description="Development-only claimed role of the approver (e.g. 'ADMIN') (unauthenticated)",
    )
    reason: Optional[str] = Field(default=None, description="Optional decision notes")

    @field_validator("decision")
    @classmethod
    def validate_decision(cls, v: str) -> str:
        cleaned = v.strip().upper()
        if cleaned not in ("APPROVE", "REJECT"):
            raise ValueError("Decision must be either 'APPROVE' or 'REJECT'")
        return cleaned


class ApprovalDecisionResponse(BaseModel):
    approval_id: str
    status: str
    tool_name: str
    decided_by: str
    decided_at: str
    decision_reason: Optional[str] = None


# ---------------------------------------------------------------------------
# System & Health Routes
# ---------------------------------------------------------------------------


@router.get("/", tags=["System"])
async def root():
    """Service information and status."""
    return {
        "name": "PromptShield AI",
        "description": "Adaptive Runtime Security Gateway for LLM Applications",
        "version": "0.1.0",
        "status": "running",
        "prototype_notice": "Research prototype; in-memory state and development identities only",
    }


@router.get("/health", tags=["System"])
async def health(request: Request):
    """
    Health check endpoint reflecting service, ML classifier, and in-memory storage status.
    """
    classifier = getattr(request.app.state, "classifier", None)
    is_trained = classifier is not None and getattr(classifier, "is_trained", False)

    event_store: Optional[EventStore] = getattr(request.app.state, "event_store", None)
    event_count = len(event_store._events) if event_store else 0

    return {
        "status": "healthy" if is_trained else "degraded",
        "classifier_status": "ready" if is_trained else "unavailable",
        "environment": "development_prototype",
        "in_memory_storage": True,
        "recent_event_count": event_count,
    }


# ---------------------------------------------------------------------------
# Prompt Security Routes
# ---------------------------------------------------------------------------


@router.post("/api/v1/analyze", response_model=AnalyzeResponse, tags=["Security"])
async def analyze_prompt(payload: AnalyzeRequest, request: Request):
    """
    Analyze an incoming prompt for prompt injection, privacy violations, and malicious intent.
    Enforces security policies to ALLOW, SANITIZE, or BLOCK the request.
    Generates and stores a server-controlled AnalysisContext with a unique analysis_id.
    """
    risk_engine: Optional[RiskEngine] = getattr(request.app.state, "risk_engine", None)
    if risk_engine is None:
        classifier = getattr(request.app.state, "classifier", None)
        risk_engine = RiskEngine(classifier=classifier)

    analysis_store: Optional[AnalysisContextStore] = getattr(request.app.state, "analysis_context_store", None)
    if analysis_store is None:
        analysis_store = AnalysisContextStore()
        request.app.state.analysis_context_store = analysis_store

    event_store: Optional[EventStore] = getattr(request.app.state, "event_store", None)
    if event_store is None:
        event_store = EventStore()
        request.app.state.event_store = event_store

    assessment = risk_engine.evaluate(payload.prompt)

    # 1. Store authoritative server-controlled analysis context
    decision_str = str(getattr(assessment.decision, "value", assessment.decision))
    ctx = analysis_store.create_context(
        risk_score=assessment.risk_score,
        decision=decision_str,
        requester_id=payload.requester_id,
        context_trust_level="UNTRUSTED",
    )

    # 2. Record sanitized security event (NEVER raw prompt or secrets)
    rule_ids = [rf.get("rule_id", "") for rf in getattr(assessment, "rule_findings", [])]
    sensitive_count = len(getattr(assessment, "sensitive_findings", []))
    event_store.record_event(
        category="PROMPT_ANALYSIS",
        event_type="PROMPT_EVALUATED",
        decision=decision_str,
        risk_score=assessment.risk_score,
        requester_id=payload.requester_id,
        metadata={
            "analysis_id": ctx.analysis_id,
            "risk_level": assessment.risk_level,
            "rule_findings_count": len(rule_ids),
            "triggered_rules": rule_ids,
            "sensitive_findings_count": sensitive_count,
        },
    )

    # Security logging: NEVER log unredacted prompts containing sensitive data or secrets
    safe_log_prompt = redact_sensitive_data(payload.prompt)
    logger.info(
        "Prompt analyzed: analysis_id=%s, decision=%s, risk_score=%d, prompt_preview=%r",
        ctx.analysis_id,
        assessment.decision,
        assessment.risk_score,
        safe_log_prompt[:60] + "..." if len(safe_log_prompt) > 60 else safe_log_prompt,
    )

    res_dict = assessment.to_dict()
    res_dict["analysis_id"] = ctx.analysis_id
    return res_dict


# ---------------------------------------------------------------------------
# RAG Security Routes
# ---------------------------------------------------------------------------


@router.post("/api/v1/scan-document", response_model=ScanDocumentResponse, tags=["RAG Security"])
async def scan_document_endpoint(payload: ScanDocumentRequest, request: Request):
    """
    Scan retrieved RAG documents or tool outputs for direct and indirect prompt injection,
    sensitive information leakage, and policy violations. Enforces trust boundaries.
    """
    document_scanner: Optional[DocumentScanner] = getattr(request.app.state, "document_scanner", None)
    context_policy: Optional[ContextPolicy] = getattr(request.app.state, "context_policy", None)
    context_analyzer: Optional[ContextAnalyzer] = getattr(request.app.state, "context_analyzer", None)
    event_store: Optional[EventStore] = getattr(request.app.state, "event_store", None)

    if document_scanner is None:
        classifier = getattr(request.app.state, "classifier", None)
        document_scanner = DocumentScanner(classifier=classifier)
    if context_policy is None:
        context_policy = ContextPolicy()
    if context_analyzer is None:
        context_analyzer = ContextAnalyzer()
    if event_store is None:
        event_store = EventStore()
        request.app.state.event_store = event_store

    # Validate and normalize source boundary
    try:
        context = context_analyzer.create_context(
            content=payload.content,
            source=payload.source,
            metadata={"document_id": payload.document_id},
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # Inspect document for direct and indirect threats
    scan_result = document_scanner.scan(
        content=payload.content,
        document_id=payload.document_id,
    )

    # Evaluate context policy
    assessment = context_policy.evaluate(
        scan_result=scan_result,
        context=context,
    )

    # Record sanitized event
    sensitive_count = len(assessment.findings.get("sensitive_data", []))
    event_store.record_event(
        category="DOCUMENT_SCAN",
        event_type="DOCUMENT_SCANNED",
        decision=assessment.decision.value,
        risk_score=assessment.risk_score,
        metadata={
            "document_id": payload.document_id,
            "trust_level": assessment.trust_level.value,
            "source": payload.source,
            "sensitive_findings_count": sensitive_count,
        },
    )

    # Security logging: NEVER log unredacted document content or secrets
    logger.info(
        "Document scanned: doc_id=%s, decision=%s, risk_score=%d, trust_level=%s",
        payload.document_id,
        assessment.decision.value,
        assessment.risk_score,
        assessment.trust_level.value,
    )

    return assessment.to_dict()


# ---------------------------------------------------------------------------
# Policy & Secure Tool Authorization Routes
# ---------------------------------------------------------------------------


@router.post("/api/v1/tools/authorize", response_model=ToolAuthorizeResponse, tags=["Tool Authorization"])
async def authorize_tool_endpoint(payload: ToolAuthorizeRequest, request: Request):
    """
    Independently authorize proposed tool actions against RBAC, server-controlled risk score,
    authoritative analysis decision, and human approval constraints.
    Requires a valid server-generated analysis_id.
    """
    authorizer: Optional[ToolAuthorizer] = getattr(request.app.state, "tool_authorizer", None)
    if authorizer is None:
        authorizer = ToolAuthorizer()

    analysis_store: Optional[AnalysisContextStore] = getattr(request.app.state, "analysis_context_store", None)
    if analysis_store is None:
        analysis_store = AnalysisContextStore()
        request.app.state.analysis_context_store = analysis_store

    event_store: Optional[EventStore] = getattr(request.app.state, "event_store", None)
    if event_store is None:
        event_store = EventStore()
        request.app.state.event_store = event_store

    # 1. Strictly validate analysis_id (no zero-risk fallbacks)
    ctx, err_msg, status_code = analysis_store.validate_and_get_context(
        analysis_id=payload.analysis_id,
        requester_id=payload.requester_id,
    )
    if not ctx:
        raise HTTPException(status_code=status_code, detail=err_msg)

    # 2. Enforce Authoritative Analysis Decision: Only ALLOW contexts may authorize tools
    is_allowed_dec, dec_err, _ = analysis_store.validate_analysis_decision(ctx)
    if not is_allowed_dec:
        logger.warning(
            "Tool authorization rejected: context '%s' has non-ALLOW decision '%s' for requester '%s'",
            ctx.analysis_id,
            ctx.decision,
            payload.requester_id,
        )
        event_store.record_event(
            category="TOOL_AUTHORIZATION",
            event_type="TOOL_DENIED",
            decision="DENY",
            risk_score=ctx.risk_score,
            requester_id=payload.requester_id,
            metadata={
                "tool_name": payload.tool_name,
                "requester_role": payload.requester_role,
                "analysis_id": ctx.analysis_id,
                "reason": dec_err,
            },
        )
        return {
            "decision": "DENY",
            "tool_name": payload.tool_name,
            "requester_id": payload.requester_id,
            "requester_role": payload.requester_role,
            "risk_level": "HIGH",
            "reasons": [dec_err],
            "approval_id": None,
            "requires_approval": False,
        }

    # 3. Server-Controlled Context Trust: Never trust client-supplied trust assertions
    server_trust = ctx.context_trust_level
    if payload.context_trust_level is not None and payload.context_trust_level != server_trust:
        logger.warning(
            "Client attempted to supply context_trust_level '%s' for requester '%s'. Server trust '%s' is authoritative.",
            payload.context_trust_level,
            payload.requester_id,
            server_trust,
        )

    # Unknown or malformed trust values fail closed to UNTRUSTED
    valid_trust_levels = {"UNTRUSTED", "TRUSTED", "SYSTEM_TRUSTED"}
    norm_trust = str(server_trust).strip().upper() if server_trust else ""
    if norm_trust not in valid_trust_levels:
        logger.warning("Unrecognized context trust level '%s'. Failing closed to UNTRUSTED.", server_trust)
        norm_trust = "UNTRUSTED"

    # Server-controlled risk score
    server_risk_score = ctx.risk_score
    if payload.risk_score is not None and payload.risk_score != server_risk_score:
        logger.warning(
            "Client attempted to manipulate risk_score (client=%d, server=%d) for requester '%s'. Ignoring client claim.",
            payload.risk_score,
            server_risk_score,
            payload.requester_id,
        )

    client_admin = payload.is_admin is True
    client_approved = payload.approved is True

    # Retrieve any previously bound approval ID on this analysis context
    bound_approval_id = analysis_store.get_bound_approval_id(payload.analysis_id)
    if bound_approval_id and payload.approval_id and payload.approval_id != bound_approval_id:
        logger.warning(
            "Tool authorization rejected: approval_id mismatch for context '%s' (bound=%s, provided=%s)",
            ctx.analysis_id,
            bound_approval_id,
            payload.approval_id,
        )
        return {
            "decision": "DENY",
            "tool_name": payload.tool_name,
            "requester_id": payload.requester_id,
            "requester_role": payload.requester_role,
            "risk_level": "HIGH",
            "reasons": [
                f"Denied: Approval ID '{payload.approval_id}' does not match approval ID '{bound_approval_id}' bound to analysis context '{ctx.analysis_id}'"
            ],
            "approval_id": None,
            "requires_approval": False,
        }

    # 4-10. Side-effect-free preliminary authorization check
    # Evaluates tool existence, schema, path traversal, risk score, RBAC, trust boundary,
    # and approval state WITHOUT creating pending approvals or binding intent yet.
    prelim_result = authorizer.evaluate_authorization(
        tool_name=payload.tool_name,
        arguments=payload.arguments,
        requester_id=payload.requester_id,
        requester_role=payload.requester_role,
        risk_score=server_risk_score,
        context_trust_level=norm_trust,
        approval_id=payload.approval_id,
        client_supplied_admin=client_admin,
        client_supplied_approved=client_approved,
        analysis_decision=ctx.decision,
        bound_approval_id=bound_approval_id,
    )

    # If preliminary check resulted in DENY, NEVER bind the intent and NEVER create an approval
    if prelim_result.decision == AuthDecision.DENY:
        event_store.record_event(
            category="TOOL_AUTHORIZATION",
            event_type="TOOL_DENIED",
            decision="DENY",
            risk_score=server_risk_score,
            requester_id=payload.requester_id,
            metadata={
                "tool_name": payload.tool_name,
                "requester_role": payload.requester_role,
                "risk_level": prelim_result.risk_level,
                "requires_approval": False,
                "approval_id": None,
                "analysis_id": ctx.analysis_id,
                "reasons": prelim_result.reasons,
            },
        )
        return prelim_result.to_dict()

    # 11. Atomic Intent Binding: Bind or validate tool intent against analysis context
    # Only called when preliminary policy evaluation passes (ALLOW or REQUIRE_APPROVAL)
    is_valid_intent, intent_err, _ = analysis_store.bind_or_validate_intent(
        analysis_id=payload.analysis_id,
        tool_name=payload.tool_name,
        arguments=payload.arguments,
        require_previously_bound=False,
    )
    if not is_valid_intent:
        logger.warning(
            "Tool authorization rejected: intent mismatch for context '%s' (requester: '%s'): %s",
            ctx.analysis_id,
            payload.requester_id,
            intent_err,
        )
        event_store.record_event(
            category="TOOL_AUTHORIZATION",
            event_type="TOOL_DENIED",
            decision="DENY",
            risk_score=server_risk_score,
            requester_id=payload.requester_id,
            metadata={
                "tool_name": payload.tool_name,
                "requester_role": payload.requester_role,
                "risk_level": prelim_result.risk_level,
                "analysis_id": ctx.analysis_id,
                "reason": intent_err,
            },
        )
        return {
            "decision": "DENY",
            "tool_name": payload.tool_name,
            "requester_id": payload.requester_id,
            "requester_role": payload.requester_role,
            "risk_level": prelim_result.risk_level,
            "reasons": [intent_err],
            "approval_id": None,
            "requires_approval": False,
        }

    # 12. Handle Approval Token Management:
    # If the action requires approval and no approval ID was passed (or pending approval is required),
    # atomically retrieve existing bound approval or mint exactly one deduplicated pending request.
    final_approval_id = prelim_result.approval_id
    if prelim_result.decision == AuthDecision.REQUIRE_APPROVAL:
        def _create_appr():
            role = authorizer._normalize_role(payload.requester_role) or payload.requester_role
            req = authorizer.approval_manager.create_request(
                tool_name=payload.tool_name,
                arguments=payload.arguments,
                requester_id=payload.requester_id,
                requester_role=role,
                risk_level=prelim_result.risk_level,
            )
            return req.approval_id

        final_approval_id = analysis_store.get_or_create_approval_id(
            analysis_id=payload.analysis_id,
            creator_fn=_create_appr,
        )

    # 13. Construct and return final authorization decision
    final_result = AuthorizationResult(
        decision=prelim_result.decision,
        tool_name=prelim_result.tool_name,
        requester_id=prelim_result.requester_id,
        requester_role=prelim_result.requester_role,
        risk_level=prelim_result.risk_level,
        reasons=prelim_result.reasons,
        approval_id=final_approval_id,
        requires_approval=prelim_result.requires_approval,
    )

    event_type = (
        "TOOL_AUTHORIZED"
        if final_result.decision == AuthDecision.ALLOW
        else "TOOL_APPROVAL_REQUIRED"
    )
    event_store.record_event(
        category="TOOL_AUTHORIZATION",
        event_type=event_type,
        decision=final_result.decision.value,
        risk_score=server_risk_score,
        requester_id=payload.requester_id,
        metadata={
            "tool_name": payload.tool_name,
            "requester_role": payload.requester_role,
            "risk_level": final_result.risk_level,
            "requires_approval": final_result.requires_approval,
            "approval_id": final_result.approval_id,
            "analysis_id": ctx.analysis_id,
        },
    )

    logger.info(
        "Tool authorization: tool=%s, requester=%s, role=%s, decision=%s, risk=%s, analysis_id=%s",
        payload.tool_name,
        payload.requester_id,
        payload.requester_role,
        final_result.decision.value,
        final_result.risk_level,
        ctx.analysis_id,
    )

    return final_result.to_dict()


@router.post("/api/v1/tools/execute", response_model=ToolExecuteResponse, tags=["Tool Authorization"])
async def execute_tool_endpoint(payload: ToolExecuteRequest, request: Request):
    """
    Securely execute an authorized tool in a controlled sandbox.
    Requires independent authorization against the server-controlled analysis context.
    """
    executor: Optional[ToolExecutor] = getattr(request.app.state, "tool_executor", None)
    if executor is None:
        executor = ToolExecutor()

    analysis_store: Optional[AnalysisContextStore] = getattr(request.app.state, "analysis_context_store", None)
    if analysis_store is None:
        analysis_store = AnalysisContextStore()
        request.app.state.analysis_context_store = analysis_store

    event_store: Optional[EventStore] = getattr(request.app.state, "event_store", None)
    if event_store is None:
        event_store = EventStore()
        request.app.state.event_store = event_store

    # 1. Strictly validate analysis context (no zero-risk fallbacks)
    ctx, err_msg, status_code = analysis_store.validate_and_get_context(
        analysis_id=payload.analysis_id,
        requester_id=payload.requester_id,
    )
    if not ctx:
        raise HTTPException(status_code=status_code, detail=err_msg)

    # 2. Enforce Authoritative Analysis Decision: Only ALLOW contexts may execute tools
    is_allowed_dec, dec_err, _ = analysis_store.validate_analysis_decision(ctx)
    if not is_allowed_dec:
        logger.warning(
            "Tool execution rejected: context '%s' has non-ALLOW decision '%s' for requester '%s'",
            ctx.analysis_id,
            ctx.decision,
            payload.requester_id,
        )
        event_store.record_event(
            category="TOOL_EXECUTION",
            event_type="TOOL_EXECUTION_DENIED",
            decision="FORBIDDEN",
            risk_score=ctx.risk_score,
            requester_id=payload.requester_id,
            metadata={"tool_name": payload.tool_name, "analysis_id": ctx.analysis_id, "error": dec_err},
        )
        raise HTTPException(status_code=403, detail=dec_err)

    # 3. Server-Controlled Context Trust: Never trust client-supplied trust assertions
    server_trust = ctx.context_trust_level
    if payload.context_trust_level is not None and payload.context_trust_level != server_trust:
        logger.warning(
            "Client attempted to supply context_trust_level '%s' for requester '%s'. Server trust '%s' is authoritative.",
            payload.context_trust_level,
            payload.requester_id,
            server_trust,
        )

    valid_trust_levels = {"UNTRUSTED", "TRUSTED", "SYSTEM_TRUSTED"}
    norm_trust = str(server_trust).strip().upper() if server_trust else ""
    if norm_trust not in valid_trust_levels:
        logger.warning("Unrecognized context trust level '%s'. Failing closed to UNTRUSTED.", server_trust)
        norm_trust = "UNTRUSTED"

    # 4. Atomic Intent Binding: Verify tool execution matches previously bound intent
    is_valid_intent, intent_err, status_code = analysis_store.bind_or_validate_intent(
        analysis_id=payload.analysis_id,
        tool_name=payload.tool_name,
        arguments=payload.arguments,
        require_previously_bound=True,
    )
    if not is_valid_intent:
        logger.warning(
            "Tool execution rejected: intent mismatch for context '%s' (requester: '%s'): %s",
            ctx.analysis_id,
            payload.requester_id,
            intent_err,
        )
        event_store.record_event(
            category="TOOL_EXECUTION",
            event_type="TOOL_EXECUTION_DENIED",
            decision="FORBIDDEN",
            risk_score=ctx.risk_score,
            requester_id=payload.requester_id,
            metadata={"tool_name": payload.tool_name, "analysis_id": ctx.analysis_id, "error": intent_err},
        )
        raise HTTPException(status_code=status_code or 403, detail=intent_err)

    # 4.5. Enforce Bound Approval ID Invariant:
    # An execution requiring human approval must use exactly the approval ID associated
    # with the previously authorized analysis context.
    bound_approval_id = analysis_store.get_bound_approval_id(payload.analysis_id)
    tool = executor.registry.get_tool(payload.tool_name)
    tool_requires_approval = bool(
        tool and (tool.requires_approval or tool.risk_level.value in ("HIGH", "CRITICAL"))
    )
    requires_approval = (bound_approval_id is not None) or tool_requires_approval

    if requires_approval:
        if not payload.approval_id:
            logger.warning(
                "Tool execution rejected: context '%s' requires approval, but no approval_id provided",
                ctx.analysis_id,
            )
            event_store.record_event(
                category="TOOL_EXECUTION",
                event_type="TOOL_EXECUTION_DENIED",
                decision="FORBIDDEN",
                risk_score=ctx.risk_score,
                requester_id=payload.requester_id,
                metadata={
                    "tool_name": payload.tool_name,
                    "analysis_id": ctx.analysis_id,
                    "error": "Missing required approval ID",
                },
            )
            raise HTTPException(
                status_code=403,
                detail=f"Execution rejected: tool '{payload.tool_name}' requires human approval, but no approval_id was provided",
            )

        if bound_approval_id and payload.approval_id != bound_approval_id:
            logger.warning(
                "Tool execution rejected: approval substitution attempt on context '%s' (bound=%s, attempted=%s)",
                ctx.analysis_id,
                bound_approval_id,
                payload.approval_id,
            )
            event_store.record_event(
                category="TOOL_EXECUTION",
                event_type="TOOL_EXECUTION_DENIED",
                decision="FORBIDDEN",
                risk_score=ctx.risk_score,
                requester_id=payload.requester_id,
                metadata={
                    "tool_name": payload.tool_name,
                    "analysis_id": ctx.analysis_id,
                    "error": "Cross-context approval substitution attempt",
                },
            )
            raise HTTPException(
                status_code=403,
                detail=f"Execution rejected: approval_id '{payload.approval_id}' does not match the approval token '{bound_approval_id}' bound to analysis context '{ctx.analysis_id}'",
            )

        if bound_approval_id is None and tool_requires_approval:
            logger.warning(
                "Tool execution rejected: tool '%s' requires approval but context '%s' has no bound approval",
                payload.tool_name,
                ctx.analysis_id,
            )
            raise HTTPException(
                status_code=403,
                detail=f"Execution rejected: tool '{payload.tool_name}' requires human approval, but context '{ctx.analysis_id}' has no associated approved token",
            )

    # 5. Server-controlled risk score is authoritative
    server_risk_score = ctx.risk_score

    try:
        exec_result = executor.execute(
            tool_name=payload.tool_name,
            arguments=payload.arguments,
            requester_id=payload.requester_id,
            requester_role=payload.requester_role,
            risk_score=server_risk_score,
            context_trust_level=norm_trust,
            approval_id=payload.approval_id,
            analysis_decision=ctx.decision,
            bound_approval_id=bound_approval_id,
        )

        event_store.record_event(
            category="TOOL_EXECUTION",
            event_type="TOOL_EXECUTED",
            decision=exec_result.status,
            risk_score=server_risk_score,
            requester_id=payload.requester_id,
            metadata={
                "tool_name": payload.tool_name,
                "execution_id": exec_result.execution_id,
                "approval_id": payload.approval_id,
                "analysis_id": ctx.analysis_id,
            },
        )
        return exec_result.to_dict()
    except PermissionError as exc:
        event_store.record_event(
            category="TOOL_EXECUTION",
            event_type="TOOL_EXECUTION_DENIED",
            decision="FORBIDDEN",
            risk_score=server_risk_score,
            requester_id=payload.requester_id,
            metadata={"tool_name": payload.tool_name, "analysis_id": ctx.analysis_id},
        )
        raise HTTPException(status_code=403, detail=str(exc))
    except (KeyError, ValueError) as exc:
        event_store.record_event(
            category="TOOL_EXECUTION",
            event_type="TOOL_EXECUTION_FAILED",
            decision="FAILED",
            risk_score=server_risk_score,
            requester_id=payload.requester_id,
            metadata={"tool_name": payload.tool_name, "analysis_id": ctx.analysis_id},
        )
        raise HTTPException(status_code=400, detail=str(exc))


@router.post(
    "/api/v1/tools/approvals/{approval_id}/decision",
    response_model=ApprovalDecisionResponse,
    tags=["Tool Authorization"],
)
async def decide_approval_endpoint(
    approval_id: str,
    payload: ApprovalDecisionRequest,
    request: Request,
):
    """
    Process human approval or rejection of a pending tool execution request.

    SECURITY & IDENTITY LIMITATION NOTICE (DEVELOPMENT PROTOTYPE):
    The 'approver_id' and 'approver_role' fields accepted from the request body
    are development-only claims and ARE SPOOFABLE by any client.
    This research prototype does NOT perform real cryptographic authentication.
    Production deployments MUST enforce server-validated JWT/OIDC or session
    authentication, where approver identity and roles are resolved securely
    server-side rather than accepted from untrusted request bodies.
    Separation-of-duties checks implemented in ApprovalManager are enforced
    against these development identity claims.
    """
    manager: Optional[ApprovalManager] = getattr(request.app.state, "approval_manager", None)
    if manager is None:
        manager = ApprovalManager()

    event_store: Optional[EventStore] = getattr(request.app.state, "event_store", None)
    if event_store is None:
        event_store = EventStore()
        request.app.state.event_store = event_store

    logger.warning(
        "DEVELOPMENT PROTOTYPE NOTICE: Processing approval '%s' with unauthenticated client-supplied role '%s' for approver '%s'.",
        approval_id,
        payload.approver_role,
        payload.approver_id,
    )

    approver_role_norm = ToolAuthorizer._normalize_role(payload.approver_role)
    if not approver_role_norm:
        raise HTTPException(status_code=422, detail=f"Invalid approver role: '{payload.approver_role}'")

    try:
        if payload.decision == "APPROVE":
            req = manager.approve(
                approval_id=approval_id,
                approver_id=payload.approver_id,
                approver_role=approver_role_norm,
                reason=payload.reason,
            )
        else:
            req = manager.reject(
                approval_id=approval_id,
                approver_id=payload.approver_id,
                approver_role=approver_role_norm,
                reason=payload.reason,
            )

        event_store.record_event(
            category="APPROVAL",
            event_type="APPROVAL_DECIDED",
            decision=req.status.value,
            requester_id=payload.approver_id,
            metadata={
                "approval_id": approval_id,
                "tool_name": req.tool_name,
                "approver_role": payload.approver_role,
            },
        )

        return {
            "approval_id": req.approval_id,
            "status": req.status.value,
            "tool_name": req.tool_name,
            "decided_by": req.decided_by,
            "decided_at": req.decided_at.isoformat() if req.decided_at else "",
            "decision_reason": req.decision_reason,
        }
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ---------------------------------------------------------------------------
# Dashboard Monitoring & Analytics Routes
# ---------------------------------------------------------------------------


@router.get("/api/v1/dashboard/overview", tags=["Dashboard"])
async def dashboard_overview(request: Request):
    """
    Aggregated operational statistics and decision breakdowns for the security dashboard.
    Returns actual session counts from in-memory event and approval stores.
    """
    event_store: Optional[EventStore] = getattr(request.app.state, "event_store", None)
    if event_store is None:
        event_store = EventStore()
        request.app.state.event_store = event_store

    approval_manager: Optional[ApprovalManager] = getattr(request.app.state, "approval_manager", None)
    pending_count = approval_manager.count_pending() if approval_manager else 0

    return event_store.get_overview_statistics(pending_approvals_count=pending_count)


@router.get("/api/v1/dashboard/events", tags=["Dashboard"])
async def list_dashboard_events(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500, description="Max events to return"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    category: Optional[str] = Query(default=None, description="Filter by event category"),
    event_type: Optional[str] = Query(default=None, description="Filter by event type"),
    decision: Optional[str] = Query(default=None, description="Filter by decision"),
):
    """
    Paginated audit log of sanitized security gateway events.
    Stored metadata excludes raw prompts, tool arguments, and sensitive data.
    """
    event_store: Optional[EventStore] = getattr(request.app.state, "event_store", None)
    if event_store is None:
        event_store = EventStore()
        request.app.state.event_store = event_store

    events, total = event_store.get_events(
        limit=limit,
        offset=offset,
        category=category,
        event_type=event_type,
        decision=decision,
    )

    return {
        "items": events,
        "total": total,
        "limit": limit,
        "offset": offset,
        "storage": "in_memory",
        "session_only": True,
    }


@router.get("/api/v1/dashboard/approvals", tags=["Dashboard"])
async def list_dashboard_approvals(
    request: Request,
    status: Optional[str] = Query(default=None, description="Filter by approval status (PENDING, APPROVED, etc.)"),
    limit: int = Query(default=50, ge=1, le=200, description="Max requests to return"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
):
    """
    List human approval requests for the dashboard.
    CRITICAL PRIVACY GUARANTEE: Never exposes stored tool arguments.
    """
    manager: Optional[ApprovalManager] = getattr(request.app.state, "approval_manager", None)
    if manager is None:
        return {"items": [], "total": 0, "limit": limit, "offset": offset}

    items, total = manager.list_requests(status=status, limit=limit, offset=offset)
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "storage": "in_memory",
        "session_only": True,
    }


@router.get("/api/v1/tools/registry", tags=["Dashboard"])
async def list_tools_registry(request: Request):
    """
    Return safe metadata for all registered tools, including risk tiers and argument schemas.
    Does not expose sensitive system paths or execution code.
    """
    registry: Optional[ToolRegistry] = getattr(request.app.state, "tool_registry", None)
    if registry is None:
        registry = ToolRegistry()
        request.app.state.tool_registry = registry

    tools = [tool.to_dict() for tool in registry.list_tools()]
    return {
        "tools": tools,
        "total": len(tools),
    }


# ---------------------------------------------------------------------------
# Benchmark Results API
# ---------------------------------------------------------------------------


@router.get("/api/v1/benchmarks", tags=["Dashboard"])
async def get_benchmarks():
    """
    Retrieve empirical Day 8.5 hardened benchmark evaluation results.
    Loads actual machine-readable artifacts from research/results/day8_5_hardened/.
    Paths are resolved server-side relative to the project root.
    """
    project_root = Path(__file__).resolve().parents[3]
    bench_dir = project_root / "research" / "results" / "day8_5_hardened"

    if not bench_dir.exists():
        raise HTTPException(
            status_code=503,
            detail="Benchmark artifacts directory not found: research/results/day8_5_hardened",
        )

    results_file = bench_dir / "benchmark_results.json"
    stratified_file = bench_dir / "benchmark_results_stratified.json"
    grouped_file = bench_dir / "benchmark_results_grouped.json"
    confusion_file = bench_dir / "confusion_matrices.json"
    summary_csv_file = bench_dir / "metrics_summary.csv"

    required_files = [results_file, stratified_file, grouped_file, confusion_file, summary_csv_file]
    missing = [f.name for f in required_files if not f.exists()]
    if missing:
        raise HTTPException(
            status_code=503,
            detail=f"Incomplete benchmark artifacts. Missing: {', '.join(missing)}",
        )

    try:
        with open(results_file, "r", encoding="utf-8") as f:
            bench_results = json.load(f)
        with open(stratified_file, "r", encoding="utf-8") as f:
            strat_results = json.load(f)
        with open(grouped_file, "r", encoding="utf-8") as f:
            group_results = json.load(f)
        with open(confusion_file, "r", encoding="utf-8") as f:
            confusion_matrices = json.load(f)

        df_summary = pd.read_csv(summary_csv_file)
        summary_rows = df_summary.to_dict(orient="records")
    except Exception as exc:
        logger.error("Failed to read benchmark artifacts: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to parse benchmark artifacts")

    return {
        "status": "success",
        "source": "research/results/day8_5_hardened",
        "metadata": bench_results.get("metadata", {}),
        "metrics_summary_table": summary_rows,
        "confusion_matrices": confusion_matrices,
        "experiment_1_stratified": {
            "name": "Experiment 1: In-Distribution Stratified Split",
            "sample_count": strat_results.get("sample_count", 81),
            "category_counts": strat_results.get("category_counts", {}),
            "label_counts": strat_results.get("label_counts", {}),
            "configurations": strat_results.get("configurations", {}),
            "pii_secret_evaluation": strat_results.get("pii_secret_evaluation", {}),
            "tool_policy_evaluation": strat_results.get("tool_policy_evaluation", {}),
        },
        "experiment_2_grouped_ood": {
            "name": "Experiment 2: Out-of-Distribution Grouped Split",
            "sample_count": group_results.get("sample_count", 215),
            "category_counts": group_results.get("category_counts", {}),
            "label_counts": group_results.get("label_counts", {}),
            "configurations": group_results.get("configurations", {}),
            "pii_secret_evaluation": group_results.get("pii_secret_evaluation", {}),
            "tool_policy_evaluation": group_results.get("tool_policy_evaluation", {}),
        },
        "adversarial_scenarios_evaluation": bench_results.get("adversarial_scenarios_evaluation", {}),
    }
