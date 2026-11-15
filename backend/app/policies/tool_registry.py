from dataclasses import dataclass, field
from enum import Enum
import logging
from typing import Any, Optional

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


@dataclass
class ToolDefinition:
    """Specification of an authorized tool and its governance constraints."""

    name: str
    description: str
    allowed_roles: set[UserRole]
    risk_level: ToolRiskLevel
    required_args: list[str] = field(default_factory=list)
    requires_approval: bool = False
    is_enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "allowed_roles": [r.value for r in self.allowed_roles],
            "risk_level": self.risk_level.value,
            "required_args": self.required_args,
            "requires_approval": self.requires_approval,
            "is_enabled": self.is_enabled,
        }


class ToolRegistry:
    """
    Centralized, least-privilege tool registry.
    Governs tool definitions, role-based permissions, risk classifications, and argument specifications.
    """

    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}
        self._load_default_tools()

    def _load_default_tools(self) -> None:
        """Register default tools applying least-privilege principles."""
        defaults = [
            ToolDefinition(
                name="search_knowledge_base",
                description="Query the enterprise knowledge base for relevant articles.",
                allowed_roles={UserRole.USER, UserRole.DEVELOPER, UserRole.ADMIN},
                risk_level=ToolRiskLevel.LOW,
                required_args=["query"],
                requires_approval=False,
                is_enabled=True,
            ),
            ToolDefinition(
                name="get_weather",
                description="Retrieve public weather forecast data for a specified location.",
                allowed_roles={UserRole.USER, UserRole.DEVELOPER, UserRole.ADMIN},
                risk_level=ToolRiskLevel.LOW,
                required_args=["location"],
                requires_approval=False,
                is_enabled=True,
            ),
            ToolDefinition(
                name="read_file",
                description="Read repository or log file contents.",
                allowed_roles={UserRole.DEVELOPER, UserRole.ADMIN},
                risk_level=ToolRiskLevel.MEDIUM,
                required_args=["filepath"],
                requires_approval=False,
                is_enabled=True,
            ),
            ToolDefinition(
                name="send_email",
                description="Send an outbound email communication.",
                allowed_roles={UserRole.DEVELOPER, UserRole.ADMIN},
                risk_level=ToolRiskLevel.HIGH,
                required_args=["recipient", "subject", "body"],
                requires_approval=True,
                is_enabled=True,
            ),
            ToolDefinition(
                name="delete_file",
                description="Permanently delete a file from storage.",
                allowed_roles={UserRole.ADMIN},
                risk_level=ToolRiskLevel.CRITICAL,
                required_args=["filepath"],
                requires_approval=True,
                is_enabled=False,  # Disabled by default for critical risk
            ),
            ToolDefinition(
                name="execute_command",
                description="Simulated administrative command execution.",
                allowed_roles={UserRole.ADMIN},
                risk_level=ToolRiskLevel.CRITICAL,
                required_args=["command"],
                requires_approval=True,
                is_enabled=False,  # Disabled by default; unrestricted shell strictly forbidden
            ),
        ]

        for tool in defaults:
            self.register_tool(tool)

    def register_tool(self, tool: ToolDefinition) -> None:
        """Register or update a tool definition in the registry."""
        self._tools[tool.name] = tool
        logger.debug("Registered tool: %s (Risk: %s, Enabled: %s)", tool.name, tool.risk_level.value, tool.is_enabled)

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
        Validate that all required arguments are present and non-empty.
        Returns (is_valid, error_message).
        """
        tool = self.get_tool(name)
        if not tool:
            return False, f"Unknown tool: '{name}'"

        if not isinstance(args, dict):
            return False, "Tool arguments must be a dictionary"

        missing = [arg for arg in tool.required_args if arg not in args or args[arg] is None or args[arg] == ""]
        if missing:
            return False, f"Missing required arguments for '{name}': {', '.join(missing)}"

        return True, None
