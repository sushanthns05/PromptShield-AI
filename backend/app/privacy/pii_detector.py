import re
from typing import Any, Callable, Optional


BENIGN_LOOKALIKE_WORDS = {
    "learn", "model", "image", "pipeline", "stream", "bundle", "cluster",
    "network", "server", "client", "prod", "dev", "test", "fake", "short",
    "abc", "doc", "docs", "data", "base", "system", "build", "run", "lib",
    "library", "framework", "package", "module", "plugin", "component",
}


def _is_valid_sk_token(candidate: str) -> bool:
    """
    Validate that an sk- prefixed candidate is a genuine API key or synthetic secret token,
    and not a benign library, framework, or dictionary lookalike.
    """
    if not candidate.startswith("sk-"):
        return False
    suffix = candidate[3:]
    if len(suffix) < 12:
        return False

    clean = suffix.lower().strip("-_")
    if clean in BENIGN_LOOKALIKE_WORDS:
        return False

    parts = re.split(r"[-_]", clean)
    if all(p in BENIGN_LOOKALIKE_WORDS for p in parts if p):
        return False

    has_digit = any(c.isdigit() for c in suffix)
    has_upper = any(c.isupper() for c in suffix)
    has_indicator = any(kw in suffix.lower() for kw in ("key", "token", "secret", "auth", "cred", "api"))

    return has_digit or (has_upper and len(suffix) >= 14) or has_indicator


CREDENTIAL_SPECIFICATIONS = [
    {
        "type": "OPENAI_API_KEY",
        "category": "SECRET",
        "format": "documented",
        "pattern": re.compile(
            r"\bsk-(?:proj-|admin-|svcacct-|test-)?[A-Za-z0-9_-]{20,}\b"
        ),
        "validator": _is_valid_sk_token,
    },
    {
        "type": "SYNTHETIC_API_KEY",
        "category": "SECRET",
        "format": "synthetic",
        "pattern": re.compile(
            r"\bsk-(?:test-|dev-|staging-|mock-)?[A-Za-z0-9_-]{12,19}\b"
        ),
        "validator": _is_valid_sk_token,
    },
    {
        "type": "AWS_ACCESS_KEY",
        "category": "SECRET",
        "format": "documented",
        "pattern": re.compile(
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
        ),
    },
    {
        "type": "SYNTHETIC_AWS_KEY",
        "category": "SECRET",
        "format": "synthetic",
        "pattern": re.compile(
            r"\bAKIA[0-9A-Z]{17,28}\b"
        ),
    },
    {
        "type": "GITHUB_TOKEN",
        "category": "SECRET",
        "format": "documented",
        "pattern": re.compile(
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{70,95}\b"
        ),
    },
    {
        "type": "SLACK_TOKEN",
        "category": "SECRET",
        "format": "documented",
        "pattern": re.compile(
            r"\bxox[bpar]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32}\b"
        ),
    },
    {
        "type": "STRIPE_API_KEY",
        "category": "SECRET",
        "format": "documented",
        "pattern": re.compile(
            r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b"
        ),
    },
    {
        "type": "GOOGLE_API_KEY",
        "category": "SECRET",
        "format": "documented",
        "pattern": re.compile(
            r"\bAIza[0-9A-Za-z-_]{35,45}\b"
        ),
    },
    {
        "type": "GENERIC_SECRET",
        "category": "SECRET",
        "format": "generic",
        "pattern": re.compile(
            r"""(?i)\b(?:api[_-]?key|secret[_-]?token|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9_-]{16,})["']?"""
        ),
    },
    {
        "type": "PASSWORD",
        "category": "SECRET",
        "format": "documented",
        "pattern": re.compile(
            r"""(?i)\b(?:password|passwd|pwd)\s*[:=]\s*["']?([^\s"'&,;]{4,})"""
        ),
    },
    {
        "type": "EMAIL",
        "category": "PII",
        "format": "standard",
        "pattern": re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
    },
    {
        "type": "PHONE",
        "category": "PII",
        "format": "standard",
        "pattern": re.compile(
            r"(?<!\w)(?:\+91[\s-]?)?[6-9]\d{9}(?!\w)"
        ),
    },
]

# Legacy PATTERNS dictionary for backwards compatibility
PATTERNS = {
    spec["type"]: spec["pattern"] for spec in CREDENTIAL_SPECIFICATIONS
}


def detect_sensitive_data(text: str) -> list[dict[str, Any]]:
    """
    Detect sensitive credentials and PII in text across documented provider formats,
    synthetic development tokens, and generic secret assignments.

    Strictly filters out benign dictionary lookalikes, library names, and short strings.

    Returns findings containing the type, matched value, character positions,
    format classification ('documented', 'synthetic', 'standard', 'generic'), and category.
    """
    if not isinstance(text, str):
        raise TypeError("Input must be a string")

    raw_matches: list[dict[str, Any]] = []

    for spec in CREDENTIAL_SPECIFICATIONS:
        data_type = spec["type"]
        pattern = spec["pattern"]
        category = spec["category"]
        cred_format = spec["format"]
        validator = spec.get("validator")

        for match in pattern.finditer(text):
            is_captured_group = data_type in ("PASSWORD", "GENERIC_SECRET")
            value = match.group(1) if is_captured_group else match.group(0)

            # Optional post-match validator (e.g., lookalike filter)
            if validator and not validator(value):
                continue

            start = match.start(1) if is_captured_group else match.start()
            end = match.end(1) if is_captured_group else match.end()

            raw_matches.append({
                "type": data_type,
                "value": value,
                "start": start,
                "end": end,
                "format": cred_format,
                "category": category,
            })

    # Sort matches by start position, then by descending span length
    raw_matches.sort(key=lambda m: (m["start"], -(m["end"] - m["start"])))

    # Deduplicate overlapping matches (prefer longer/earlier match)
    deduped_findings: list[dict[str, Any]] = []
    last_end = -1

    for match in raw_matches:
        if match["start"] >= last_end:
            deduped_findings.append(match)
            last_end = match["end"]

    return deduped_findings


def redact_sensitive_data(text: str) -> str:
    """
    Replace detected sensitive values with safe placeholders.
    Never exposes raw secrets or PII in sanitized output.
    """
    findings = detect_sensitive_data(text)

    redacted_text = text

    # Replace from right to left so earlier positions remain valid
    for finding in reversed(findings):
        start = finding["start"]
        end = finding["end"]
        placeholder = f"[REDACTED_{finding['type']}]"

        redacted_text = (
            redacted_text[:start]
            + placeholder
            + redacted_text[end:]
        )

    return redacted_text
