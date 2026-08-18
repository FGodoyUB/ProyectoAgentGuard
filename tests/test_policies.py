from agentguard.models import Action, Finding, Severity
from agentguard.policies import PolicyManager


def test_policy_allows_when_no_findings():
    manager = PolicyManager()

    action = manager.decide([])

    assert action == Action.ALLOW


def test_policy_blocks_high_severity():
    manager = PolicyManager()

    findings = [
        Finding(
            rule_id="TEST001",
            category="test",
            severity=Severity.HIGH,
            match="example",
        )
    ]

    action = manager.decide(findings)

    assert action == Action.BLOCK


def test_policy_neutralizes_medium_severity():
    manager = PolicyManager()

    findings = [
        Finding(
            rule_id="TEST002",
            category="test",
            severity=Severity.MEDIUM,
            match="example",
        )
    ]

    action = manager.decide(findings)

    assert action == Action.NEUTRALIZE


def test_policy_warns_low_severity():
    manager = PolicyManager()

    findings = [
        Finding(
            rule_id="TEST003",
            category="test",
            severity=Severity.LOW,
            match="example",
        )
    ]

    action = manager.decide(findings)

    assert action == Action.WARN


def test_policy_uses_highest_severity():
    manager = PolicyManager()

    findings = [
        Finding(
            rule_id="TEST001",
            category="test",
            severity=Severity.LOW,
            match="low",
        ),
        Finding(
            rule_id="TEST002",
            category="test",
            severity=Severity.HIGH,
            match="high",
        ),
    ]

    action = manager.decide(findings)

    assert action == Action.BLOCK