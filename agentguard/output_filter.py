from agentguard.models import Action, FilterResult
from agentguard.policies import PolicyManager
from agentguard.rules import RuleEngine
from agentguard.neutralizer import Neutralizer

class OutputFilter:
    def __init__(self, rule_engine, policy_manager, neutralizer=None):
        self.rule_engine = rule_engine
        self.policy_manager = policy_manager
        self.neutralizer = neutralizer or Neutralizer()

    def validate(self, text: str) -> FilterResult:
        findings = self.rule_engine.evaluate(text, scope="output")
        action = self.policy_manager.decide(findings)

        content = text
        message = ""

        if action == Action.WARN:
            message = "Salida permitida con advertencias."

        if action == Action.NEUTRALIZE:
            content = self.neutralizer.neutralize(text, findings)
            message = "Salida neutralizada por política de seguridad."

        if action == Action.BLOCK:
            content = None
            message = "Salida bloqueada por política de seguridad."

        return FilterResult(
            action=action,
            content=content,
            findings=findings,
            blocked=action == Action.BLOCK,
            message=message,
        )