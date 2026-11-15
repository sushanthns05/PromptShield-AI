from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Union


class SourceType(str, Enum):
    SYSTEM_TRUSTED = "SYSTEM_TRUSTED"
    USER_UNTRUSTED = "USER_UNTRUSTED"
    DOCUMENT_UNTRUSTED = "DOCUMENT_UNTRUSTED"
    TOOL_UNTRUSTED = "TOOL_UNTRUSTED"


class TrustLevel(str, Enum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"


SOURCE_ALIASES: dict[str, SourceType] = {
    # System trusted sources
    "system": SourceType.SYSTEM_TRUSTED,
    "system_trusted": SourceType.SYSTEM_TRUSTED,
    "system_prompt": SourceType.SYSTEM_TRUSTED,
    "developer": SourceType.SYSTEM_TRUSTED,
    # User untrusted sources
    "user": SourceType.USER_UNTRUSTED,
    "user_untrusted": SourceType.USER_UNTRUSTED,
    "user_prompt": SourceType.USER_UNTRUSTED,
    "user_input": SourceType.USER_UNTRUSTED,
    # Document untrusted sources (RAG)
    "document": SourceType.DOCUMENT_UNTRUSTED,
    "document_untrusted": SourceType.DOCUMENT_UNTRUSTED,
    "retrieved_document": SourceType.DOCUMENT_UNTRUSTED,
    "rag": SourceType.DOCUMENT_UNTRUSTED,
    "rag_document": SourceType.DOCUMENT_UNTRUSTED,
    "kb": SourceType.DOCUMENT_UNTRUSTED,
    "knowledge_base": SourceType.DOCUMENT_UNTRUSTED,
    # Tool untrusted sources
    "tool": SourceType.TOOL_UNTRUSTED,
    "tool_untrusted": SourceType.TOOL_UNTRUSTED,
    "tool_output": SourceType.TOOL_UNTRUSTED,
    "function": SourceType.TOOL_UNTRUSTED,
    "function_output": SourceType.TOOL_UNTRUSTED,
}

TRUST_MAPPING: dict[SourceType, TrustLevel] = {
    SourceType.SYSTEM_TRUSTED: TrustLevel.TRUSTED,
    SourceType.USER_UNTRUSTED: TrustLevel.UNTRUSTED,
    SourceType.DOCUMENT_UNTRUSTED: TrustLevel.UNTRUSTED,
    SourceType.TOOL_UNTRUSTED: TrustLevel.UNTRUSTED,
}


@dataclass
class ContextObject:
    """Structured context object encapsulating text, source metadata, and trust boundary."""

    content: str
    source_type: SourceType
    trust_level: TrustLevel
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_trusted(self) -> bool:
        return self.trust_level == TrustLevel.TRUSTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "content": self.content,
            "source_type": self.source_type.value,
            "trust_level": self.trust_level.value,
            "is_trusted": self.is_trusted,
            "metadata": self.metadata,
        }


class ContextAnalyzer:
    """
    Manages trust boundaries for inputs, retrieved documents, tool outputs, and system instructions.
    Enforces strict trust segregation: document and tool content can NEVER be promoted to trusted status.
    """

    @staticmethod
    def normalize_source(source: Union[SourceType, str]) -> SourceType:
        if isinstance(source, SourceType):
            return source
        if not isinstance(source, str):
            raise TypeError("Source must be a string or SourceType enum")

        normalized = source.strip().lower()
        if not normalized:
            raise ValueError("Source cannot be empty")

        if normalized in SOURCE_ALIASES:
            return SOURCE_ALIASES[normalized]

        # Check uppercase enum matches directly
        upper_val = source.strip().upper()
        for member in SourceType:
            if member.value == upper_val:
                return member

        raise ValueError(f"Invalid or unsupported source type: '{source}'")

    def create_context(
        self,
        content: str,
        source: Union[SourceType, str],
        metadata: Optional[dict[str, Any]] = None,
        attempted_trust: Optional[Union[TrustLevel, str]] = None,
    ) -> ContextObject:
        if not isinstance(content, str):
            raise TypeError("Content must be a string")

        source_type = self.normalize_source(source)
        trust_level = TRUST_MAPPING[source_type]
        meta = dict(metadata or {})

        # Security invariant: Never promote document, user, or tool content to trusted status
        if attempted_trust is not None:
            attempted_val = (
                attempted_trust.value
                if isinstance(attempted_trust, TrustLevel)
                else str(attempted_trust).strip().upper()
            )
            if attempted_val == TrustLevel.TRUSTED.value and source_type != SourceType.SYSTEM_TRUSTED:
                # Flag blocked elevation attempt in metadata
                meta["attempted_promotion_blocked"] = True
                trust_level = TrustLevel.UNTRUSTED

        return ContextObject(
            content=content,
            source_type=source_type,
            trust_level=trust_level,
            metadata=meta,
        )

    def promote_to_trusted(self, context: ContextObject) -> None:
        """
        Enforce invariant: Untrusted sources (documents, tools, users) cannot be promoted to trusted status.
        """
        if context.source_type != SourceType.SYSTEM_TRUSTED:
            raise PermissionError(
                f"Security policy violation: Cannot promote {context.source_type.value} to TRUSTED"
            )
