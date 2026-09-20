import re

from agentguard.models import Finding, Rule


class RuleEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def evaluate(self, text: str, scope: str | None = None) -> list[Finding]:
        findings = []

        for rule in self.rules:
            if scope is not None and rule.scope not in (scope, "both"):
                continue

            match = re.search(rule.pattern, text, re.IGNORECASE)

            if match:
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        category=rule.category,
                        severity=rule.severity,
                        match=match.group(),
                    )
                )

        return findings
    