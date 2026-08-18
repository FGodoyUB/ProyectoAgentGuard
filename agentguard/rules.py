import re

from agentguard.models import Finding, Rule


class RuleEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def evaluate(self, text: str) -> list[Finding]:
        findings = []

        for rule in self.rules:
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
    