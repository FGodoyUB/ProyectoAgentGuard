from agentguard.models import Action, FilterResult
from agentguard.policies import PolicyManager
from agentguard.rules import RuleEngine


class InputFilter:
    def __init__(
        self,
        rule_engine: RuleEngine,
        policy_manager: PolicyManager,
    ):
        self.rule_engine = rule_engine
        self.policy_manager = policy_manager

    def validate(self, text: str) -> FilterResult:
        findings = self.rule_engine.evaluate(text, scope="input")
        action = self.policy_manager.decide(findings)

        return FilterResult(
            action=action,
            content=text,
            findings=findings,
            blocked=action == Action.BLOCK,
        )