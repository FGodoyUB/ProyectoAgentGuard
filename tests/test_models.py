from agentguard.models import Action, Finding, Severity, FilterResult


def test_filter_result_has_independent_findings_lists():
    result_a = FilterResult(
        action=Action.ALLOW,
        content="A",
    )

    result_b = FilterResult(
        action=Action.ALLOW,
        content="B",
    )

    finding = Finding(
        rule_id="TEST001",
        category="test",
        severity=Severity.LOW,
        match="example",
    )

    result_a.findings.append(finding)

    assert len(result_a.findings) == 1
    assert len(result_b.findings) == 0

