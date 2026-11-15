from enum import Enum
import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from backend.app.policies.risk_engine import RiskEngine
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
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except TypeError as exc:
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
