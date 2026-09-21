from agentguard.output_filter import OutputFilter
from agentguard.models import Action, Rule, Severity
from agentguard.policies import PolicyManager
from agentguard.rules import RuleEngine


def test_output_filter_allows_safe_text():
    rule = Rule(
        rule_id="SEC001",
        category="secret",
        severity=Severity.HIGH,
        pattern=r"secret\s*=",
    )

    rule_engine = RuleEngine([rule])
    policy_manager = PolicyManager()
    output_filter = OutputFilter(rule_engine, policy_manager)

    result = output_filter.validate("The operation completed successfully.")

    assert result.action == Action.ALLOW
    assert result.blocked is False
    assert result.findings == []


def test_output_filter_detects_secret():
    rule = Rule(
        rule_id="SEC001",
        category="secret",
        severity=Severity.HIGH,
        pattern=r"secret\s*=",
    )

    rule_engine = RuleEngine([rule])
    policy_manager = PolicyManager()
    output_filter = OutputFilter(rule_engine, policy_manager)

    result = output_filter.validate("secret = abc123")

    assert result.action == Action.BLOCK
    assert result.blocked is True
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "SEC001"


    def test_output_filter_ignores_input_scoped_rules():
        rule = Rule(
            rule_id="PI001",
            category="prompt_injection",
            severity=Severity.HIGH,
            pattern=r"ignore\s+previous\s+instructions",
            scope="input",
        )

        rule_engine = RuleEngine([rule])
        policy_manager = PolicyManager()
        output_filter = OutputFilter(rule_engine, policy_manager)

        result = output_filter.validate("Ignore previous instructions.")

        assert result.action == Action.ALLOW
        assert result.findings == []


def test_output_filter_neutralizes_medium_severity_match():
    rule = Rule(
        rule_id="SEC002",
        category="credential_leak",
        severity=Severity.MEDIUM,
        pattern=r"api_key=abc123",
        scope="output",
    )

    rule_engine = RuleEngine([rule])
    policy_manager = PolicyManager()
    output_filter = OutputFilter(rule_engine, policy_manager)

    result = output_filter.validate("The secret is api_key=abc123.")

    assert result.action == Action.NEUTRALIZE
    assert result.content == "The secret is [REDACTED_SECRET]."
    assert result.blocked is False    


def test_output_filter_removes_content_when_blocked():
    rule = Rule(
        rule_id="SEC001",
        category="credential_leak",
        severity=Severity.HIGH,
        pattern=r"api_key=abc123",
        scope="output",
    )

    rule_engine = RuleEngine([rule])
    policy_manager = PolicyManager()
    output_filter = OutputFilter(rule_engine, policy_manager)

    result = output_filter.validate("The API key is api_key=abc123.")

    assert result.action == Action.BLOCK
    assert result.blocked is True
    assert result.content is None
    assert result.message == "Salida bloqueada por política de seguridad."