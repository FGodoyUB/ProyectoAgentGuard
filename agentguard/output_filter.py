from agentguard.models import Action, FilterResult
from agentguard.policies import PolicyManager
from agentguard.rules import RuleEngine
from agentguard.neutralizer import Neutralizer
from agentguard.logger import SecurityLogger

class OutputFilter:
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

        if self.logger is not None:
            self.logger.log(
                component="output_filter",
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