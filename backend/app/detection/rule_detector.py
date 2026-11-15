
import re
from typing import TypedDict


class Detection(TypedDict):
    rule_id: str
    category: str
    severity: str
    matched_pattern: str


# Known suspicious instruction patterns.
# These are initial heuristic rules, not a complete
# prompt injection detection solution.

RULES = [
    {
        "rule_id": "PI001",
        "category": "instruction_override",
        "severity": "high",
        "pattern": r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    },
    {
        "rule_id": "PI002",
        "category": "instruction_override",
        "severity": "high",
        "pattern": r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions",
    },
    {
        "rule_id": "PI003",
        "category": "system_prompt_extraction",
        "severity": "high",
        "pattern": r"(reveal|show|print|disclose)\s+(the\s+)?(system|hidden)\s+prompt",
    },
    {
        "rule_id": "PI004",
        "category": "safety_bypass",
        "severity": "high",
        "pattern": r"(bypass|disable|override)\s+(all\s+)?(safety|security)\s+(rules|restrictions|filters)",
    },
    {
        "rule_id": "PI005",
        "category": "role_manipulation",
        "severity": "medium",
        "pattern": r"you\s+are\s+now\s+(an?\s+)?(unrestricted|unfiltered|unlimited)",
    },
    {
        "rule_id": "PI006",
        "category": "instruction_override",
        "severity": "medium",
        "pattern": r"forget\s+(everything|all)\s+(you\s+know|you\s+were\s+told)",
    },
    {
        "rule_id": "PI007",
        "category": "system_prompt_extraction",
        "severity": "medium",
        "pattern": r"(repeat|output|display)\s+(your\s+)?(hidden\s+)?system\s+instructions",
    },
]


def detect_prompt_injection(prompt: str) -> list[Detection]:
    """
    Scan a prompt for known prompt injection patterns.

    Returns a list of detection findings.
    Does not block or modify the prompt.
    """

    if not isinstance(prompt, str):
        raise TypeError("Prompt must be a string")

    findings: list[Detection] = []

    for rule in RULES:
        match = re.search(
            rule["pattern"],
            prompt,
            flags=re.IGNORECASE,
        )

        if match:
            findings.append({
                "rule_id": rule["rule_id"],
                "category": rule["category"],
                "severity": rule["severity"],
                "matched_pattern": match.group(0),
            })

    return findings


def analyze_prompt(prompt: str) -> dict:
    """
    Return a structured detection report.
    """

    findings = detect_prompt_injection(prompt)

    return {
        "is_suspicious": len(findings) > 0,
        "total_findings": len(findings),
        "findings": findings,
        "detection_method": "rule_based",
    }
