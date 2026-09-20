from dataclasses import dataclass, field
from enum import Enum


class Action(Enum):
    ALLOW = "allow"
    WARN = "warn"
    NEUTRALIZE = "neutralize"
    BLOCK = "block"


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: Severity
    match: str


@dataclass
class FilterResult:
    action: Action
    content: str
    findings: list[Finding] = field(default_factory=list)
    blocked: bool = False
    message: str = ""


@dataclass
class Rule:
    rule_id: str
    category: str
    severity: Severity
    pattern: str
    scope: str = "both"
    name: str = ""