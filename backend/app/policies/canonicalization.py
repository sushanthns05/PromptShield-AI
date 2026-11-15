"""
PromptShield AI — Unified Argument & Intent Canonicalization Engine
Enforces deterministic, tamper-evident JSON serialization for:
- AnalysisContext tool-intent binding
- ApprovalManager argument verification
- Approval token consumption

Guarantees:
- Sorted dictionary keys at all nesting levels
- Compact JSON separators (',', ':') with zero whitespace
- ASCII-safe encoding (ensure_ascii=True)
- allow_nan=False (strictly rejects NaN, Infinity, -Infinity)
- Rejects non-string dictionary keys (prevents silent type coercion e.g. {1: 'a'})
- Rejects unsupported Python objects (sets, functions, custom classes)
- Preserves distinct types (e.g. integer 1 vs string "1")
"""

from copy import deepcopy
import hashlib
import json
import math
from typing import Any, Tuple


def validate_canonical_structure(obj: Any, path: str = "arguments") -> None:
    """
    Recursively validate that dictionary keys are strictly strings,
    floating point numbers are finite (rejecting NaN, Infinity, -Infinity),
    and all objects conform strictly to standard JSON types.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TypeError(
                    f"Non-canonical or invalid argument structure: non-string dictionary key detected at {path}: key {repr(k)} is of type {type(k).__name__}. "
                    "All dictionary keys must be strictly strings."
                )
            validate_canonical_structure(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for idx, item in enumerate(obj):
            validate_canonical_structure(item, f"{path}[{idx}]")
    elif isinstance(obj, (str, int, bool, type(None))):
        pass
    elif isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise ValueError(
                f"Non-canonical or invalid argument structure: non-compliant floating point value at {path}: {obj} is NaN or Infinity"
            )
    else:
        raise TypeError(
            f"Non-canonical or invalid argument structure: unsupported object type at {path}: {type(obj).__name__} ({repr(obj)}) is not JSON serializable"
        )


def canonicalize_arguments(arguments: Any) -> str:
    """
    Deterministically serialize tool arguments into canonical JSON.
    Rejects non-dict top-level arguments, non-string keys, NaN/Infinity, and unsupported types.
    """
    if not isinstance(arguments, dict):
        raise ValueError(f"arguments must be a dictionary, got {type(arguments).__name__}")

    validate_canonical_structure(arguments)

    try:
        return json.dumps(
            arguments,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Canonicalization failure: {exc}") from exc


def canonicalize_tool_intent(tool_name: str, arguments: dict[str, Any]) -> Tuple[str, str, str]:
    """
    Deterministically canonicalize tool name and arguments.
    Returns (normalized_tool_name, canonical_arguments_json, sha256_hash).
    """
    if not isinstance(tool_name, str) or not tool_name.strip():
        raise ValueError("tool_name must be a non-empty string")

    norm_tool = tool_name.strip().lower()
    canonical_args = canonicalize_arguments(arguments if arguments is not None else {})
    intent_payload = f"{norm_tool}:{canonical_args}"
    intent_hash = hashlib.sha256(intent_payload.encode("utf-8")).hexdigest()
    return norm_tool, canonical_args, intent_hash


def validate_ttl(ttl: Any, field_name: str = "TTL") -> int:
    """
    Validate that a TTL parameter is a positive integer.
    Rejects booleans (since bool is a subclass of int in Python), zero, negative numbers, floats, and strings.
    """
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
        raise ValueError(
            f"{field_name} must be a positive integer, got {repr(ttl)} (type: {type(ttl).__name__})"
        )
    return int(ttl)
