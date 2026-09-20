import json
from pathlib import Path

from agentguard.models import Rule, Severity


def load_rules(config_path: str | Path) -> list[Rule]:
    """
    Carga reglas de seguridad desde un archivo de configuración JSON.

    Se espera que el archivo JSON contenga una lista "rules".
    Cada elemento se convierte en un objeto Rule.
    """
    path = Path(config_path)

    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    rules_data = data.get("rules", [])
    rules: list[Rule] = []

    for item in rules_data:
        rule = Rule(
            rule_id=item["id"],
            name=item.get("name", ""),
            scope=item.get("scope", "both"),
            category=item["category"],
            severity=Severity(item["severity"]),
            pattern=item["pattern"],
        )
        rules.append(rule)

    return rules