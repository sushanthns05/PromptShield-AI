import re
from typing import Any


CREDENTIAL_SPECIFICATIONS = [
    {
        "type": "OPENAI_API_KEY",
        "category": "SECRET",
        "format": "documented",
        "pattern": re.compile(
            r"\bsk-(?:proj-|admin-|svcacct-)?[A-Za-z0-9_-]{20,}\b"
        ),
    },
    {
        "type": "SYNTHETIC_API_KEY",
        "category": "SECRET",
        "format": "synthetic",
        "pattern": re.compile(
            r"\bsk-(?=[A-Za-z0-9]{12,19}\b)(?:[A-Za-z0-9]*(?:Key|Token|Secret)[A-Za-z0-9]*|(?=[A-Za-z0-9]*[A-Z])(?=[A-Za-z0-9]*\d)[A-Za-z0-9]+)\b"
        ),
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
    Detect sensitive credentials and PII in text.

    Supports documented production formats as well as synthetic benchmark tokens,
    while strictly avoiding overly broad regular expressions that match benign
    terms (e.g., 'sk-learn', 'sk-model', 'AKIA123').

    Returns findings containing the type, matched value, character positions,
    format classification ('documented', 'synthetic', 'standard'), and category.
    """
    if not isinstance(text, str):
        raise TypeError("Input must be a string")

    raw_matches: list[dict[str, Any]] = []

    for spec in CREDENTIAL_SPECIFICATIONS:
        data_type = spec["type"]
        pattern = spec["pattern"]
        category = spec["category"]
        cred_format = spec["format"]

        for match in pattern.finditer(text):
            value = match.group(1) if data_type == "PASSWORD" else match.group(0)

            # For password matches, locate only the captured value
            start = match.start(1) if data_type == "PASSWORD" else match.start()
            end = match.end(1) if data_type == "PASSWORD" else match.end()

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


if __name__ == "__main__":
    sample = (
        "Contact student@example.com or +91 9876543210. "
        "Production key: sk-123456789012345678901234. "
        "Synthetic token: sk-attackerKey123456. "
        "AWS standard: AKIAIOSFODNN7EXAMPLE. "
        "MinIO token: AKIAMINIOSTORAGEUSER12. "
        "Benign terms: sk-learn, sk-model, AKIA123. "
        "password=ExamplePass123"
    )

    print("SENSITIVE DATA DETECTION")
    print("-----------------------")

    for finding in detect_sensitive_data(sample):
        print(f"[{finding['type']} ({finding['format']})]: {finding['value']} @ ({finding['start']}-{finding['end']})")

    print("\nREDACTED TEXT")
    print("-------------")
    print(redact_sensitive_data(sample))
