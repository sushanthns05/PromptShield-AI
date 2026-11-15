from enum import Enum
import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from backend.app.policies.approval_manager import ApprovalManager
from backend.app.policies.risk_engine import RiskEngine
from backend.app.policies.tool_authorizer import ToolAuthorizer
from backend.app.policies.tool_executor import ToolExecutor
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


class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., description="Prompt text to inspect and analyze")

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
    decision: DecisionEnum
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str
    sanitized_prompt: Optional[str] = None
    reasons: list[str] = Field(default_factory=list)
    details: AnalysisDetails


class ScanDocumentRequest(BaseModel):
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
    tool_name: str = Field(..., min_length=1, description="Name of tool to authorize")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Arguments for tool invocation")
    requester_id: str = Field(..., min_length=1, description="Identifier of the requester")
    requester_role: str = Field(default="USER", description="Development-only requester role claim")
    risk_score: int = Field(default=0, ge=0, le=100, description="Upstream PromptShield risk score")
    context_trust_level: str = Field(default="UNTRUSTED", description="Context trust boundary level")
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
    tool_name: str = Field(..., min_length=1, description="Name of tool to execute")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Arguments for tool invocation")
    requester_id: str = Field(..., min_length=1, description="Identifier of the requester")
    requester_role: str = Field(default="USER", description="Development-only requester role claim")
    risk_score: int = Field(default=0, ge=0, le=100, description="Upstream PromptShield risk score")
    context_trust_level: str = Field(default="UNTRUSTED", description="Context trust boundary level")
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
    decision: str = Field(..., description="'APPROVE' or 'REJECT'")
    approver_id: str = Field(..., min_length=1, description="Identifier of the reviewer/approver")
    approver_role: str = Field(..., description="Role of the approver (e.g. 'ADMIN')")
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


# --- System Routes ---


@router.get("/", tags=["System"])
async def root():
    """Service information and status."""
    return {
        "name": "PromptShield AI",
        "description": "Adaptive Runtime Security Gateway for LLM Applications",
        "version": "0.1.0",
        "status": "running",
    }


@router.get("/health", tags=["System"])
async def health(request: Request):
    """Health check endpoint reflecting service and ML model status."""
    classifier = getattr(request.app.state, "classifier", None)
    is_trained = classifier is not None and getattr(classifier, "is_trained", False)

    return {
        "status": "healthy" if is_trained else "degraded",
        "classifier_status": "ready" if is_trained else "unavailable",
    }


# --- Prompt Security Routes ---


@router.post("/api/v1/analyze", response_model=AnalyzeResponse, tags=["Security"])
async def analyze_prompt(payload: AnalyzeRequest, request: Request):
    """
    Analyze an incoming prompt for prompt injection, privacy violations, and malicious intent.
    Enforces security policies to ALLOW, SANITIZE, or BLOCK the request.
    """
    risk_engine: Optional[RiskEngine] = getattr(request.app.state, "risk_engine", None)
    if risk_engine is None:
        classifier = getattr(request.app.state, "classifier", None)
        risk_engine = RiskEngine(classifier=classifier)

    assessment = risk_engine.evaluate(payload.prompt)

    # Security logging: NEVER log unredacted prompts containing sensitive data or secrets
    safe_log_prompt = redact_sensitive_data(payload.prompt)
    logger.info(
        "Prompt analyzed: decision=%s, risk_score=%d, prompt_preview=%r",
        assessment.decision,
        assessment.risk_score,
        safe_log_prompt[:60] + "..." if len(safe_log_prompt) > 60 else safe_log_prompt,
    )

    return assessment.to_dict()


# --- RAG Security Routes ---


@router.post("/api/v1/scan-document", response_model=ScanDocumentResponse, tags=["RAG Security"])
async def scan_document_endpoint(payload: ScanDocumentRequest, request: Request):
    """
    Scan retrieved RAG documents or tool outputs for direct and indirect prompt injection,
    sensitive information leakage, and policy violations. Enforces trust boundaries.
    """
    document_scanner: Optional[DocumentScanner] = getattr(request.app.state, "document_scanner", None)
    context_policy: Optional[ContextPolicy] = getattr(request.app.state, "context_policy", None)
    context_analyzer: Optional[ContextAnalyzer] = getattr(request.app.state, "context_analyzer", None)

    if document_scanner is None:
        classifier = getattr(request.app.state, "classifier", None)
        document_scanner = DocumentScanner(classifier=classifier)
    if context_policy is None:
        context_policy = ContextPolicy()
    if context_analyzer is None:
        context_analyzer = ContextAnalyzer()

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

    # Security logging: NEVER log unredacted document content or secrets
    logger.info(
        "Document scanned: doc_id=%s, decision=%s, risk_score=%d, trust_level=%s",
        payload.document_id,
        assessment.decision.value,
        assessment.risk_score,
        assessment.trust_level.value,
    )

    return assessment.to_dict()


# --- Policy & Secure Tool Authorization Routes ---


@router.post("/api/v1/tools/authorize", response_model=ToolAuthorizeResponse, tags=["Tool Authorization"])
async def authorize_tool_endpoint(payload: ToolAuthorizeRequest, request: Request):
    """
    Independently authorize proposed tool actions against RBAC, risk score, and human approval constraints.
    Prevents autonomous LLM tool execution by enforcing backend policy.
    """
    authorizer: Optional[ToolAuthorizer] = getattr(request.app.state, "tool_authorizer", None)
    if authorizer is None:
        authorizer = ToolAuthorizer()

    # Detect client spoofing attempts
    client_admin = payload.is_admin is True
    client_approved = payload.approved is True

    result = authorizer.authorize(
        tool_name=payload.tool_name,
        arguments=payload.arguments,
        requester_id=payload.requester_id,
        requester_role=payload.requester_role,
        risk_score=payload.risk_score,
        context_trust_level=payload.context_trust_level,
        approval_id=payload.approval_id,
        client_supplied_admin=client_admin,
        client_supplied_approved=client_approved,
    )

    logger.info(
        "Tool authorization: tool=%s, requester=%s, role=%s, decision=%s, risk=%s",
        payload.tool_name,
        payload.requester_id,
        payload.requester_role,
        result.decision.value,
        result.risk_level,
    )

    return result.to_dict()


@router.post("/api/v1/tools/execute", response_model=ToolExecuteResponse, tags=["Tool Authorization"])
async def execute_tool_endpoint(payload: ToolExecuteRequest, request: Request):
    """
    Securely execute an authorized tool in a controlled sandbox.
    Requires independent authorization before execution and consumes any approval token.
    """
    executor: Optional[ToolExecutor] = getattr(request.app.state, "tool_executor", None)
    if executor is None:
        executor = ToolExecutor()

    try:
        exec_result = executor.execute(
            tool_name=payload.tool_name,
            arguments=payload.arguments,
            requester_id=payload.requester_id,
            requester_role=payload.requester_role,
            risk_score=payload.risk_score,
            context_trust_level=payload.context_trust_level,
            approval_id=payload.approval_id,
        )
        return exec_result.to_dict()
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except (KeyError, ValueError) as exc:
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
    Requires authenticated administrator credentials in production.
    """
    manager: Optional[ApprovalManager] = getattr(request.app.state, "approval_manager", None)
    if manager is None:
        manager = ApprovalManager()

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
