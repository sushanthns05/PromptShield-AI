from dataclasses import dataclass, field
from enum import Enum
import logging
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field, StrictStr, ValidationError

logger = logging.getLogger("promptshield.tool_registry")


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    DEVELOPER = "DEVELOPER"
    USER = "USER"
    READ_ONLY = "READ_ONLY"


class ToolRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Explicit Pydantic Argument Schemas for Registered Tools
# ---------------------------------------------------------------------------


class SearchKnowledgeBaseArgs(BaseModel):
    """Schema for search_knowledge_base tool arguments."""

    model_config = ConfigDict(extra="forbid")
    query: StrictStr = Field(..., min_length=1, description="Knowledge base search query")


class GetWeatherArgs(BaseModel):
    """Schema for get_weather tool arguments."""

    model_config = ConfigDict(extra="forbid")
    location: StrictStr = Field(..., min_length=1, description="Target city, state, or location name")


class ReadFileArgs(BaseModel):
    """Schema for read_file tool arguments."""

    model_config = ConfigDict(extra="forbid")
    filepath: StrictStr = Field(..., min_length=1, description="Relative file path within repository")


class SendEmailArgs(BaseModel):
    """Schema for send_email tool arguments."""

    model_config = ConfigDict(extra="forbid")
    recipient: StrictStr = Field(..., min_length=1, description="Recipient email address")
    subject: StrictStr = Field(..., min_length=1, description="Email subject line")
    body: StrictStr = Field(..., min_length=1, description="Email body content")


class DeleteFileArgs(BaseModel):
    """Schema for delete_file tool arguments."""

    model_config = ConfigDict(extra="forbid")
    filepath: StrictStr = Field(..., min_length=1, description="Relative file path to delete")


class ExecuteCommandArgs(BaseModel):
    """Schema for execute_command tool arguments."""

    model_config = ConfigDict(extra="forbid")
    command: StrictStr = Field(..., min_length=1, description="Command string to execute in sandbox")


# ---------------------------------------------------------------------------
# Tool Definition & Registry
# ---------------------------------------------------------------------------


@dataclass
class ToolDefinition:
    """Specification of an authorized tool and its governance constraints."""

    name: str
    description: str
    allowed_roles: set[UserRole]
    risk_level: ToolRiskLevel
    required_args: list[str] = field(default_factory=list)
    argument_schema: Optional[type[BaseModel]] = None
    requires_approval: bool = False
    is_enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "allowed_roles": [r.value for r in self.allowed_roles],
            "risk_level": self.risk_level.value,
            "required_args": self.required_args,
            "argument_schema": self.argument_schema.__name__ if self.argument_schema else None,
            "requires_approval": self.requires_approval,
            "is_enabled": self.is_enabled,
        }


class ToolRegistry:
    """
    Centralized, least-privilege tool registry.
    Governs tool definitions, role-based permissions, risk classifications, and explicit argument schemas.
    """

    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}
        self._load_default_tools()

    def _load_default_tools(self) -> None:
        """Register default tools applying least-privilege principles and explicit schemas."""
        defaults = [
            ToolDefinition(
                name="search_knowledge_base",
                description="Query the enterprise knowledge base for relevant articles.",
                allowed_roles={UserRole.USER, UserRole.DEVELOPER, UserRole.ADMIN},
                risk_level=ToolRiskLevel.LOW,
                required_args=["query"],
                argument_schema=SearchKnowledgeBaseArgs,
                requires_approval=False,
                is_enabled=True,
            ),
            ToolDefinition(
                name="get_weather",
                description="Retrieve public weather forecast data for a specified location.",
                allowed_roles={UserRole.USER, UserRole.DEVELOPER, UserRole.ADMIN},
                risk_level=ToolRiskLevel.LOW,
                required_args=["location"],
                argument_schema=GetWeatherArgs,
                requires_approval=False,
                is_enabled=True,
            ),
            ToolDefinition(
                name="read_file",
                description="Read repository or log file contents.",
                allowed_roles={UserRole.DEVELOPER, UserRole.ADMIN},
                risk_level=ToolRiskLevel.MEDIUM,
                required_args=["filepath"],
                argument_schema=ReadFileArgs,
                requires_approval=False,
                is_enabled=True,
            ),
            ToolDefinition(
                name="send_email",
                description="Send an outbound email communication.",
                allowed_roles={UserRole.DEVELOPER, UserRole.ADMIN},
                risk_level=ToolRiskLevel.HIGH,
                required_args=["recipient", "subject", "body"],
                argument_schema=SendEmailArgs,
                requires_approval=True,
                is_enabled=True,
            ),
            ToolDefinition(
                name="delete_file",
                description="Permanently delete a file from storage.",
                allowed_roles={UserRole.ADMIN},
                risk_level=ToolRiskLevel.CRITICAL,
                required_args=["filepath"],
                argument_schema=DeleteFileArgs,
                requires_approval=True,
                is_enabled=False,  # Disabled by default for critical risk
            ),
            ToolDefinition(
                name="execute_command",
                description="Simulated administrative command execution.",
                allowed_roles={UserRole.ADMIN},
                risk_level=ToolRiskLevel.CRITICAL,
                required_args=["command"],
                argument_schema=ExecuteCommandArgs,
                requires_approval=True,
                is_enabled=False,  # Disabled by default; unrestricted shell strictly forbidden
            ),
        ]

        for tool in defaults:
            self.register_tool(tool)

    def register_tool(self, tool: ToolDefinition) -> None:
        """Register or update a tool definition in the registry."""
        self._tools[tool.name] = tool
        logger.debug(
            "Registered tool: %s (Risk: %s, Enabled: %s, Schema: %s)",
            tool.name,
            tool.risk_level.value,
            tool.is_enabled,
            tool.argument_schema.__name__ if tool.argument_schema else "None",
        )

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        """Look up a tool definition by name."""
        return self._tools.get(name)

    def list_tools(self) -> list[ToolDefinition]:
        """Return all registered tool definitions."""
        return list(self._tools.values())

    def enable_tool(self, name: str) -> bool:
        """Enable a registered tool."""
        if name in self._tools:
            self._tools[name].is_enabled = True
            logger.info("Tool '%s' enabled by policy.", name)
            return True
        return False

    def disable_tool(self, name: str) -> bool:
        """Disable a registered tool."""
        if name in self._tools:
            self._tools[name].is_enabled = False
            logger.info("Tool '%s' disabled by policy.", name)
            return True
        return False

    def validate_arguments(self, name: str, args: dict[str, Any]) -> tuple[bool, Optional[str]]:
        """
        Validate that arguments match the tool's explicit Pydantic schema and required parameters.
        Rejects:
        - Non-dictionary inputs
        - Missing required parameters
        - Type mismatches (e.g., int passed for filepath)
        - Unknown, extra, or unsupported arguments (ConfigDict extra='forbid')
        - Empty strings

        Returns (is_valid, error_message).
        """
        tool = self.get_tool(name)
        if not tool:
            return False, f"Unknown tool: '{name}'"

        if not isinstance(args, dict):
            return False, "Tool arguments must be a dictionary"

        # 1. Missing required parameters check
        missing = [
            arg for arg in tool.required_args
            if arg not in args or args[arg] is None or (isinstance(args[arg], str) and args[arg] == "")
        ]
        if missing:
            return False, f"Missing required arguments for '{name}': {', '.join(missing)}"

        # 2. Strict Pydantic schema validation
        if tool.argument_schema:
            try:
                tool.argument_schema.model_validate(args)
            except ValidationError as ve:
                errors: list[str] = []
                for err in ve.errors():
                    field_name = ".".join(str(loc) for loc in err["loc"])
                    msg = err["msg"]
                    errors.append(f"{field_name}: {msg}")
                return False, f"Schema validation error for '{name}': {'; '.join(errors)}"

        return True, None
