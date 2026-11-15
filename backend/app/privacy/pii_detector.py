import re
from typing import Any


PATTERNS = {
    "EMAIL": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),

    "PHONE": re.compile(
        r"(?<!\w)(?:\+91[\s-]?)?[6-9]\d{9}(?!\w)"
    ),

    "OPENAI_API_KEY": re.compile(
        r"\bsk-[A-Za-z0-9_-]{20,}\b"
    ),

    "AWS_ACCESS_KEY": re.compile(
        r"\bAKIA[0-9A-Z]{16}\b"
    ),

    "PASSWORD": re.compile(
        r"""(?i)\b(?:password|passwd|pwd)\s*[:=]\s*["']?([^\s"'&,;]{4,})"""
    ),
}


def detect_sensitive_data(text: str) -> list[dict[str, Any]]:
    """
    Detect sensitive information in text.

    Returns findings containing the type, matched value,
    and character positions.
    """
    if not isinstance(text, str):
        raise TypeError("Input must be a string")

    findings = []

    for data_type, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(1) if data_type == "PASSWORD" else match.group(0)

            # For password matches, locate only the captured value.
            start = match.start(1) if data_type == "PASSWORD" else match.start()
            end = match.end(1) if data_type == "PASSWORD" else match.end()

            findings.append({
                "type": data_type,
                "value": value,
                "start": start,
                "end": end,
            })

    findings.sort(key=lambda item: (item["start"], item["end"]))

    return findings


def redact_sensitive_data(text: str) -> str:
    """
    Replace detected sensitive values with safe placeholders.
    """
    findings = detect_sensitive_data(text)

    redacted_text = text

    # Replace from right to left so earlier positions remain valid.
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
        "API key: sk-123456789012345678901234. "
        "password=ExamplePass123"
    )

    print("SENSITIVE DATA DETECTION")
    print("-----------------------")

    for finding in detect_sensitive_data(sample):
        print(finding)

    print("\nREDACTED TEXT")
    print("-------------")
    print(redact_sensitive_data(sample))
