import json
from datetime import datetime, timezone
from pathlib import Path

from agentguard.models import Action, Finding


class SecurityLogger:
    def __init__(self, log_path: str | Path = "agentguard.log", log_allow: bool = False):
        self.log_path = Path(log_path)
        self.log_allow = log_allow

    def should_log(self, action: Action) -> bool:
        if action == Action.ALLOW:
            return self.log_allow

        return action in {
            Action.WARN,
            Action.NEUTRALIZE,
            Action.BLOCK,
        }

    def log(
        self,
        *,
        component: str,
        action: Action,
        findings: list[Finding],
        text_length: int,
    ) -> None:
        if not self.should_log(action):
            return

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": component,
            "action": action.value,
            "text_length": text_length,
            "findings": [self._serialize_finding(finding) for finding in findings],
        }

        with self.log_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event, ensure_ascii=False) + "\n")

    def _serialize_finding(self, finding: Finding) -> dict:
        return {
            "rule_id": finding.rule_id,
            "category": finding.category,
            "severity": finding.severity.value,
            "match": self._safe_match(finding),
        }

    def _safe_match(self, finding: Finding) -> str:
        if finding.category == "credential_leak":
            return "[REDACTED_SECRET]"

        return finding.match
