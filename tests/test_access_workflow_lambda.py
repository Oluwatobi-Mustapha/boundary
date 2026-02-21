"""
Unit tests for workflow Lambda bootstrap and SQS handling.
"""
import json
import os
import sys

import pytest

# Add repo root to import path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.workflows import access_workflow


class _FakeSSM:
    def __init__(self, token: str):
        self.token = token
        self.calls = 0

    def get_parameter(self, Name, WithDecryption):  # noqa: N803 - boto3 shape
        self.calls += 1
        return {"Parameter": {"Value": self.token}}


def test_get_bot_token_uses_warm_cache(monkeypatch):
    fake_ssm = _FakeSSM("xoxb-cached-token")
    monkeypatch.setattr(access_workflow, "ssm", fake_ssm)
    monkeypatch.setattr(access_workflow, "CACHED_BOT_TOKEN", None)
    monkeypatch.setenv("SLACK_BOT_TOKEN_PARAM", "/boundary/slack/bot_token")

    first = access_workflow.get_bot_token()
    second = access_workflow.get_bot_token()

    assert first == "xoxb-cached-token"
    assert second == "xoxb-cached-token"
    assert fake_ssm.calls == 1


def test_bootstrap_requires_identity_store_id(monkeypatch):
    monkeypatch.delenv("IDENTITY_STORE_ID", raising=False)
    monkeypatch.setattr(access_workflow, "get_bot_token", lambda: "xoxb-test-token")

    with pytest.raises(access_workflow.WorkflowBootstrapError, match="IDENTITY_STORE_ID"):
        access_workflow._bootstrap_workflow()


def test_lambda_handler_processes_valid_and_discards_malformed(monkeypatch):
    processed_events = []

    class _FakeWorkflow:
        def process_request(self, event):
            processed_events.append(event)

    monkeypatch.setattr(access_workflow, "_bootstrap_workflow", lambda: _FakeWorkflow())

    event = {
        "Records": [
            {"messageId": "bad-1", "body": "{not-json}"},
            {"messageId": "ok-1", "body": json.dumps({"user_id": "U12345678", "response_url": "https://hooks.slack.com/test"})},
        ]
    }

    result = access_workflow.lambda_handler(event, None)

    assert result["processed"] == 1
    assert result["malformed"] == 1
    assert len(processed_events) == 1


def test_lambda_handler_raises_for_record_processing_errors(monkeypatch):
    class _FailingWorkflow:
        def process_request(self, event):
            raise RuntimeError("boom")

    monkeypatch.setattr(access_workflow, "_bootstrap_workflow", lambda: _FailingWorkflow())

    event = {
        "Records": [
            {"messageId": "ok-1", "body": json.dumps({"user_id": "U12345678", "response_url": "https://hooks.slack.com/test"})}
        ]
    }

    with pytest.raises(RuntimeError, match="boom"):
        access_workflow.lambda_handler(event, None)
