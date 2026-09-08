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