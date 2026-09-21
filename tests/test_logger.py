import json

from agentguard.logger import SecurityLogger
from agentguard.models import Action, Finding, Severity


def test_logger_writes_block_event(tmp_path):
    log_file = tmp_path / "agentguard.log"
    logger = SecurityLogger(log_file)

    finding = Finding(
        rule_id="PI001",
        category="prompt_injection",
        severity=Severity.HIGH,
        match="ignore previous instructions",
    )

    logger.log(
        component="input_filter",
        action=Action.BLOCK,
        findings=[finding],
        text_length=42,
    )

    lines = log_file.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 1

    event = json.loads(lines[0])

    assert event["component"] == "input_filter"
    assert event["action"] == "block"
    assert event["text_length"] == 42
    assert event["findings"][0]["rule_id"] == "PI001"
    assert event["findings"][0]["category"] == "prompt_injection"
    assert event["findings"][0]["severity"] == "high"
    assert event["findings"][0]["match"] == "ignore previous instructions"


def test_logger_does_not_log_allow_by_default(tmp_path):
    log_file = tmp_path / "agentguard.log"
    logger = SecurityLogger(log_file)

    logger.log(
        component="input_filter",
        action=Action.ALLOW,
        findings=[],
        text_length=20,
    )

    assert not log_file.exists()


def test_logger_can_log_allow_when_enabled(tmp_path):
    log_file = tmp_path / "agentguard.log"
    logger = SecurityLogger(log_file, log_allow=True)

    logger.log(
        component="input_filter",
        action=Action.ALLOW,
        findings=[],
        text_length=20,
    )

    lines = log_file.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 1

    event = json.loads(lines[0])

    assert event["action"] == "allow"
    assert event["findings"] == []


def test_logger_redacts_credential_matches(tmp_path):
    log_file = tmp_path / "agentguard.log"
    logger = SecurityLogger(log_file)

    finding = Finding(
        rule_id="SEC001",
        category="credential_leak",
        severity=Severity.HIGH,
        match="api_key=abcd1234",
    )

    logger.log(
        component="output_filter",
        action=Action.BLOCK,
        findings=[finding],
        text_length=30,
    )

    lines = log_file.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[0])

    assert event["findings"][0]["match"] == "[REDACTED_SECRET]"
    