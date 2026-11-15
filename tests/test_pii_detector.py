import pytest

from backend.app.privacy.pii_detector import (
    detect_sensitive_data,
    redact_sensitive_data,
)


def test_detect_email():
    findings = detect_sensitive_data(
        "Contact me at student@example.com"
    )
    assert any(item["type"] == "EMAIL" for item in findings)


def test_detect_phone():
    findings = detect_sensitive_data(
        "Call me at +91 9876543210"
    )
    assert any(item["type"] == "PHONE" for item in findings)


def test_detect_api_key():
    findings = detect_sensitive_data(
        "API key: sk-123456789012345678901234"
    )
    assert any(item["type"] == "OPENAI_API_KEY" for item in findings)


def test_detect_aws_key():
    findings = detect_sensitive_data(
        "AWS key: AKIAIOSFODNN7EXAMPLE"
    )
    assert any(item["type"] == "AWS_ACCESS_KEY" for item in findings)


def test_detect_password():
    findings = detect_sensitive_data(
        "password=ExamplePass123"
    )
    assert any(item["type"] == "PASSWORD" for item in findings)


def test_redact_email():
    result = redact_sensitive_data(
        "Email: student@example.com"
    )
    assert "student@example.com" not in result
    assert "[REDACTED_EMAIL]" in result


def test_redact_multiple_secrets():
    text = (
        "Email: student@example.com, "
        "password=ExamplePass123"
    )

    result = redact_sensitive_data(text)

    assert "student@example.com" not in result
    assert "ExamplePass123" not in result


def test_benign_text():
    text = "Explain Python programming and machine learning."
    assert detect_sensitive_data(text) == []
    assert redact_sensitive_data(text) == text


def test_empty_text():
    assert detect_sensitive_data("") == []
    assert redact_sensitive_data("") == ""


def test_invalid_input():
    with pytest.raises(TypeError):
        detect_sensitive_data(None)


# ---------------------------------------------------------------------------
# Day 8.5 Security Hardening Regression Tests: PII & Credential Detector
# ---------------------------------------------------------------------------


def test_detect_documented_openai_project_and_admin_keys():
    text = (
        "Project key: sk-proj-123456789012345678901234 and "
        "admin key: sk-admin-098765432109876543210987 and "
        "service key: sk-svcacct-112233445566778899001122"
    )
    findings = detect_sensitive_data(text)
    openai_findings = [f for f in findings if f["type"] == "OPENAI_API_KEY"]
    assert len(openai_findings) == 3
    for f in openai_findings:
        assert f["format"] == "documented"
        assert f["category"] == "SECRET"


def test_detect_synthetic_benchmark_tokens():
    text = (
        "Probe 1: sk-attackerKey123456. "
        "Probe 2: sk-summaryToken1234. "
        "Probe 3: sk-exfilToken123456789. "
        "Probe 4: sk-articleKey12345."
    )
    findings = detect_sensitive_data(text)
    syn_findings = [f for f in findings if f["type"] == "SYNTHETIC_API_KEY"]
    assert len(syn_findings) == 4
    for f in syn_findings:
        assert f["format"] == "synthetic"
        assert f["category"] == "SECRET"

    redacted = redact_sensitive_data(text)
    assert "sk-attackerKey123456" not in redacted
    assert "sk-summaryToken1234" not in redacted
    assert "[REDACTED_SYNTHETIC_API_KEY]" in redacted


def test_detect_synthetic_aws_keys():
    text = (
        "MinIO user: AKIAMINIOSTORAGEUSER12, "
        "deploy token: AKIAPRODDEPLOY123456789, "
        "terraform: AKIATERRAFORMUSER9988"
    )
    findings = detect_sensitive_data(text)
    syn_aws = [f for f in findings if f["type"] == "SYNTHETIC_AWS_KEY"]
    assert len(syn_aws) == 3
    for f in syn_aws:
        assert f["format"] == "synthetic"
        assert f["category"] == "SECRET"

    redacted = redact_sensitive_data(text)
    assert "AKIAMINIOSTORAGEUSER12" not in redacted
    assert "[REDACTED_SYNTHETIC_AWS_KEY]" in redacted


def test_detect_documented_aws_keys_and_sts():
    text = "IAM user: AKIAIOSFODNN7EXAMPLE, STS session: ASIAIOSFODNN7EXAMPLE"
    findings = detect_sensitive_data(text)
    aws_findings = [f for f in findings if f["type"] == "AWS_ACCESS_KEY"]
    assert len(aws_findings) == 2
    for f in aws_findings:
        assert f["format"] == "documented"
        assert f["category"] == "SECRET"


def test_benign_lookalikes_not_detected():
    benign_text = (
        "We use sk-learn and scikit-learn for model training. "
        "The sk-model pipeline and sk-image library are standard tools. "
        "Check sk-test and sk-fake-token in development documentation."
    )
    findings = detect_sensitive_data(benign_text)
    assert len(findings) == 0
    assert redact_sensitive_data(benign_text) == benign_text


def test_short_and_malformed_tokens_not_detected():
    malformed_samples = [
        "sk-",
        "sk-1",
        "sk-abc",
        "sk-123",
        "sk-short",
        "AKIA",
        "AKIA123",
        "AKIAMALFORMED",
        "AKIA_TEST",
        "AKIA-KEY",
        "akiaiosfodnn7example",
        "AKIA" + "A" * 35,  # 39 chars total, exceeds max 32
    ]
    for sample in malformed_samples:
        findings = detect_sensitive_data(sample)
        assert len(findings) == 0, f"Malformed sample '{sample}' was falsely detected as sensitive: {findings}"


def test_detect_generalized_credential_formats():
    """Verify detection of GitHub PATs, Slack tokens, Stripe keys, Google API keys, and generic assignments."""
    ghp_sample = "gh" + "p_" + "123456789012345678901234567890123456"
    gh_pat_sample = "github_" + "pat_" + "11AAAAAAA0123456789012_abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ12"
    xoxb_sample = "xo" + "xb-" + "123456789012-123456789012-abcdefghijklmnopqrstuvwx"
    xoxp_sample = "xo" + "xp-" + "987654321098-987654321098-zyxwvutsrqponmlkjihgfedc"
    stripe_live_sample = "sk_" + "live_" + "51Abcdefghijklmnopqrstuvwx123456"
    stripe_test_sample = "sk_" + "test_" + "51Abcdefghijklmnopqrstuvwx123456"
    google_sample = "AI" + "zaSyD-" + "1234567890abcdefghijklmnopqrstuv"

    test_cases = [
        (ghp_sample, "GITHUB_TOKEN", "documented"),
        (gh_pat_sample, "GITHUB_TOKEN", "documented"),
        (xoxb_sample, "SLACK_TOKEN", "documented"),
        (xoxp_sample, "SLACK_TOKEN", "documented"),
        (stripe_live_sample, "STRIPE_API_KEY", "documented"),
        (stripe_test_sample, "STRIPE_API_KEY", "documented"),
        (google_sample, "GOOGLE_API_KEY", "documented"),
        ("api_key = 'secKey1234567890abcdef'", "GENERIC_SECRET", "generic"),
        ('secret_token: "supersecrettoken998877"', "GENERIC_SECRET", "generic"),
    ]

    for snippet, expected_type, expected_format in test_cases:
        findings = detect_sensitive_data(snippet)
        matching = [f for f in findings if f["type"] == expected_type]
        assert len(matching) >= 1, f"Expected {expected_type} in '{snippet}', found {findings}"
        assert matching[0]["category"] == "SECRET"
        assert matching[0]["format"] == expected_format

        redacted = redact_sensitive_data(snippet)
        assert expected_type in redacted
        assert matching[0]["value"] not in redacted


def test_unseen_benign_lookalikes_not_detected():
    """Verify unseen benign patterns and code snippets are not falsely flagged as secrets."""
    unseen_lookalikes = [
        "sk-stream",
        "sk-bundle",
        "sk-cluster",
        "sk-network",
        "sk-server",
        "sk-client",
        "sk-prod",
        "sk-dev",
        "sk-9",
        "AKIA-PROD-KEY",
        "AKIAMOCK",
        "const sk = 42;",
        "sk_lookup = {}",
        "let sk = function() { return 10; };",
        "var apiKey = null;",
    ]

    for item in unseen_lookalikes:
        findings = detect_sensitive_data(item)
        assert len(findings) == 0, f"Unseen lookalike '{item}' falsely triggered detection: {findings}"
        assert redact_sensitive_data(item) == item

