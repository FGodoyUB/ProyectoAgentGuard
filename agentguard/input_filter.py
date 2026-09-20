from agentguard.models import Action, FilterResult
from agentguard.policies import PolicyManager
from agentguard.rules import RuleEngine
from agentguard.neutralizer import Neutralizer


class InputFilter:
    def __init__(self, rule_engine, policy_manager, neutralizer=None):
        self.rule_engine = rule_engine
        self.policy_manager = policy_manager
        self.neutralizer = neutralizer or Neutralizer()

    def validate(self, text: str) -> FilterResult:
        findings = self.rule_engine.evaluate(text, scope="input")
        action = self.policy_manager.decide(findings)

        content = text

        if action == Action.NEUTRALIZE:
            content = self.neutralizer.neutralize(text, findings)

        return FilterResult(
            action=action,
            content=content,
            findings=findings,
            blocked=action == Action.BLOCK,
        )