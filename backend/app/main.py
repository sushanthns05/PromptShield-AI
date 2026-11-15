from contextlib import asynccontextmanager
import logging
import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from backend.app.api.routes import router
from backend.app.ml.classifier import PromptClassifier
from backend.app.monitoring.event_store import EventStore
from backend.app.policies.analysis_context import AnalysisContextStore
from backend.app.policies.approval_manager import ApprovalManager
from backend.app.policies.risk_engine import RiskEngine
from backend.app.policies.tool_authorizer import ToolAuthorizer
from backend.app.policies.tool_executor import ToolExecutor
from backend.app.policies.tool_registry import ToolRegistry
from backend.app.rag.context_analyzer import ContextAnalyzer
from backend.app.rag.context_policy import ContextPolicy
from backend.app.rag.document_scanner import DocumentScanner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("promptshield")


def get_dataset_path() -> Path:
    """
    Resolve the CSV dataset path independently of the current working directory.
    Defaults to <project_root>/research/datasets/prompts.csv.
    """
    env_path = os.getenv("PROMPTSHIELD_DATASET_PATH")
    if env_path:
        return Path(env_path).resolve()

    # backend/app/main.py -> parent: backend/app -> parent: backend -> parent: project root
    project_root = Path(__file__).resolve().parents[2]
    return (project_root / "research" / "datasets" / "prompts.csv").resolve()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager.
    Initializes and trains the ML classifier once during startup.
    Handles startup failures gracefully so the gateway remains available in degraded mode.
    """
    logger.info("Initializing PromptShield AI Security Gateway...")
    dataset_path = get_dataset_path()
    classifier: Optional[PromptClassifier] = None

    try:
        if dataset_path.exists():
            logger.info("Training ML classifier from dataset: %s", dataset_path)
            model = PromptClassifier()
            model.train(str(dataset_path))
            classifier = model
            logger.info("ML classifier successfully initialized and ready")
        else:
            logger.warning(
                "Training dataset not found at '%s'. Running in degraded mode without ML classifier.",
                dataset_path,
            )
    except Exception as exc:
        logger.error(
            "Failed to train ML classifier during startup: %s. Continuing in degraded mode.",
            exc,
            exc_info=True,
        )
        classifier = None

    # Attach shared security singletons to app state
    app.state.classifier = classifier
    app.state.risk_engine = RiskEngine(classifier=classifier)
    app.state.document_scanner = DocumentScanner(classifier=classifier)
    app.state.context_policy = ContextPolicy()
    app.state.context_analyzer = ContextAnalyzer()

    # Tool authorization and policy enforcement singletons
    tool_registry = ToolRegistry()
    approval_manager = ApprovalManager()
    tool_authorizer = ToolAuthorizer(
        registry=tool_registry,
        approval_manager=approval_manager,
    )
    tool_executor = ToolExecutor(
        authorizer=tool_authorizer,
        approval_manager=approval_manager,
        registry=tool_registry,
    )

    app.state.tool_registry = tool_registry
    app.state.approval_manager = approval_manager
    app.state.tool_authorizer = tool_authorizer
    app.state.tool_executor = tool_executor

    # Session-scoped analysis context store and audit event store
    app.state.analysis_context_store = AnalysisContextStore()
    app.state.event_store = EventStore()

    yield

    logger.info("Shutting down PromptShield AI Security Gateway...")


app = FastAPI(
    title="PromptShield AI",
    description="Adaptive Runtime Security Gateway for LLM Applications (Research Prototype)",
    version="0.1.0",
    lifespan=lifespan,
)

# Configure development CORS for frontend dashboard (e.g. Vite on port 5173)
env_origins = os.getenv("PROMPTSHIELD_ALLOWED_ORIGINS", "")
if env_origins.strip():
    allowed_origins = [origin.strip() for origin in env_origins.split(",") if origin.strip()]
else:
    allowed_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

# Security Invariant: Never allow wildcard '*' origin when allow_credentials=True
if "*" in allowed_origins:
    logger.warning("Wildcard CORS origin '*' detected. Removing to prevent insecure credential exposure.")
    allowed_origins = [o for o in allowed_origins if o != "*"]
    if not allowed_origins:
        allowed_origins = ["http://localhost:5173"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Register routes
app.include_router(router)


if __name__ == "__main__":
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
