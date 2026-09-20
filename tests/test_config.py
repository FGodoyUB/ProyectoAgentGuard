import json

from agentguard.config import load_rules
from agentguard.models import Severity


def test_load_rules_from_json_file(tmp_path):
    config_file = tmp_path / "rules.json"

    config_file.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "PI-001",
                        "name": "Ignore previous instructions",
                        "scope": "input",
                        "category": "prompt_injection",
                        "severity": "high",
                        "pattern": "ignore previous instructions",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    rules = load_rules(config_file)

    assert len(rules) == 1
    assert rules[0].rule_id == "PI-001"
    assert rules[0].name == "Ignore previous instructions"
    assert rules[0].scope == "input"
    assert rules[0].category == "prompt_injection"
    assert rules[0].severity == Severity.HIGH
    assert rules[0].pattern == "ignore previous instructions"
