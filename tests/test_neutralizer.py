from agentguard.models import Finding, Severity
from agentguard.neutralizer import Neutralizer


def test_neutralizer_redacts_credential_leak():
    neutralizer = Neutralizer()

    finding = Finding(
        rule_id="SEC001",
        category="credential_leak",
        severity=Severity.MEDIUM,
        match="api_key=abc123",
    )

    result = neutralizer.neutralize(
        "The value is api_key=abc123.",
        [finding],
    )

    assert result == "The value is [REDACTED_SECRET]."


def test_neutralizer_replaces_prompt_injection():
    neutralizer = Neutralizer()

    finding = Finding(
        rule_id="PI001",
        category="prompt_injection",
        severity=Severity.MEDIUM,
        match="ignore previous instructions",
    )

    result = neutralizer.neutralize(
        "Please ignore previous instructions.",
        [finding],
    )

    assert result == "Please [NEUTRALIZED_INSTRUCTION]."