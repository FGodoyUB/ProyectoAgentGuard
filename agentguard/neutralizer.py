from agentguard.models import Finding


class Neutralizer:
    def neutralize(self, text: str, findings: list[Finding]) -> str:
        neutralized_text = text

        for finding in findings:
            if finding.match:
                neutralized_text = neutralized_text.replace(
                    finding.match,
                    self._replacement_for(finding),
                )

        return neutralized_text

    def _replacement_for(self, finding: Finding) -> str:
        if finding.category == "credential_leak":
            return "[REDACTED_SECRET]"

        if finding.category == "prompt_injection":
            return "[NEUTRALIZED_INSTRUCTION]"

        return "[NEUTRALIZED_CONTENT]"