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
