from agentguard.models import Action, Finding, Severity


class PolicyManager:
    def decide(self, findings: list[Finding]) -> Action:
        if not findings:
            return Action.ALLOW

        severities = [finding.severity for finding in findings]

        if Severity.HIGH in severities:
            return Action.BLOCK

        if Severity.MEDIUM in severities:
            return Action.NEUTRALIZE

        return Action.WARN