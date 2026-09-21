from agentguard.models import Action, FilterResult
from agentguard.policies import PolicyManager
from agentguard.rules import RuleEngine
from agentguard.neutralizer import Neutralizer
from agentguard.logger import SecurityLogger


class InputFilter:
    def __init__(
        self,
        rule_engine,
        policy_manager,
        neutralizer=None,
        logger=None,
    ):
        self.rule_engine = rule_engine
        self.policy_manager = policy_manager
        self.neutralizer = neutralizer or Neutralizer()
        self.logger = logger

    def validate(self, text: str) -> FilterResult:
        findings = self.rule_engine.evaluate(text, scope="input")
        action = self.policy_manager.decide(findings)

        content = text
        message = ""

        if action == Action.WARN:
            message = "Entrada permitida con advertencias."

        if action == Action.NEUTRALIZE:
            content = self.neutralizer.neutralize(text, findings)
            message = "Entrada neutralizada por política de seguridad."

        if action == Action.BLOCK:
            content = None
            message = "Entrada bloqueada por política de seguridad."

        if self.logger is not None:
            self.logger.log(
                component="input_filter",
                action=action,
                findings=findings,
                text_length=len(text),
            )

        return FilterResult(
            action=action,
            content=content,
            findings=findings,
            blocked=action == Action.BLOCK,
            message=message,
        )