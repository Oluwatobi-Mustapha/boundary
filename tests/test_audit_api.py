import json
import os
import sys
from decimal import Decimal

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from src import audit_api


class _FakeTable:
    def __init__(self):
        self.calls = []

    def query(self, **kwargs):
        self.calls.append(kwargs)
        status = kwargs["ExpressionAttributeValues"][":status"]
        counts = {
            "PENDING_APPROVAL": 2,
            "APPROVED": 1,
            "ACTIVE": 3,
            "REVOKED": 4,
            "DENIED": 1,
            "ERROR": 0,
        }
        return {"Count": counts.get(status, 0), "Items": []}


class _FakeStateStore:
    def __init__(self, table_name):
        self.table_name = table_name
        self.table = _FakeTable()

    def list_requests_by_status(self, *_args, **_kwargs):
        return {
            "items": [
                {
                    "request_id": "req-1",
                    "status": "ACTIVE",
                    "account_id": "111122223333",
                    "permission_set_name": "ReadOnlyAccess",
                    "requester_slack_user_id": "UREQ1111111",
                    "created_at": Decimal("1700000000"),
                }
            ],
            "next_key": {"request_id": "req-1"},
        }

    def list_requests_by_account(self, *_args, **_kwargs):
        return {"items": [], "next_key": None}

    def list_requests_by_permission_set(self, *_args, **_kwargs):
        return {"items": [], "next_key": None}

    def list_requests_by_requester(self, *_args, **_kwargs):
        return {"items": [], "next_key": None}

    def get_request(self, _request_id):
        return {
            "request_id": "req-sensitive",
            "status": "ACTIVE",
            "account_id": "999900001111",
            "permission_set_name": "AdministratorAccess",
            "requester_slack_user_id": "UOTHER000000",
        }


def _event(path, method="GET", query=None, principal_arn="arn:aws:iam::123456789012:role/TestRole"):
    return {
        "rawPath": path,
        "queryStringParameters": query or {},
        "requestContext": {
            "http": {"method": method, "path": path},
            "authorizer": {"iam": {"userArn": principal_arn}},
        },
    }


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("DYNAMODB_TABLE", "boundary-dev-active-requests")
    monkeypatch.setenv("AUDIT_API_MAX_PAGE_SIZE", "200")
    monkeypatch.setattr(audit_api, "StateStore", _FakeStateStore)


def _set_map(monkeypatch, mapping):
    monkeypatch.setenv("AUDIT_API_PRINCIPAL_MAP", json.dumps(mapping))


def test_deny_when_principal_not_mapped(monkeypatch):
    _set_map(monkeypatch, {})
    resp = audit_api.lambda_handler(_event("/api/requests", query={"status": "ACTIVE"}), None)
    body = json.loads(resp["body"])
    assert resp["statusCode"] == 403
    assert "Principal not mapped" in body["error"]


def test_list_requests_with_rbac_and_abac(monkeypatch):
    _set_map(
        monkeypatch,
        {
            "arn:aws:iam::123456789012:role/TestRole": {
                "roles": ["viewer"],
                "accounts": ["111122223333"],
                "requesters": ["UREQ1111111"],
                "permission_sets": ["ReadOnlyAccess"],
                "statuses": ["ACTIVE"],
            }
        },
    )

    resp = audit_api.lambda_handler(
        _event("/api/requests", query={"status": "ACTIVE", "account_id": "111122223333"}),
        None,
    )
    body = json.loads(resp["body"])
    assert resp["statusCode"] == 200
    assert body["count"] == 1
    assert body["items"][0]["request_id"] == "req-1"
    assert body["next_token"]


def test_abac_denies_out_of_scope_filter(monkeypatch):
    _set_map(
        monkeypatch,
        {
            "arn:aws:iam::123456789012:role/TestRole": {
                "roles": ["viewer"],
                "accounts": ["111122223333"],
                "requesters": ["*"],
                "permission_sets": ["*"],
                "statuses": ["*"],
            }
        },
    )
    resp = audit_api.lambda_handler(
        _event("/api/requests", query={"status": "ACTIVE", "account_id": "444455556666"}),
        None,
    )
    body = json.loads(resp["body"])
    assert resp["statusCode"] == 403
    assert "ABAC denied for account_id" in body["error"]


def test_get_request_by_id_hidden_when_out_of_scope(monkeypatch):
    _set_map(
        monkeypatch,
        {
            "arn:aws:iam::123456789012:role/TestRole": {
                "roles": ["viewer"],
                "accounts": ["111122223333"],
                "requesters": ["UREQ1111111"],
                "permission_sets": ["ReadOnlyAccess"],
                "statuses": ["ACTIVE"],
            }
        },
    )
    resp = audit_api.lambda_handler(_event("/api/requests/req-sensitive"), None)
    assert resp["statusCode"] == 404


def test_export_requires_auditor_or_security_admin(monkeypatch):
    _set_map(
        monkeypatch,
        {
            "arn:aws:iam::123456789012:role/TestRole": {
                "roles": ["viewer"],
                "accounts": ["*"],
                "requesters": ["*"],
                "permission_sets": ["*"],
                "statuses": ["*"],
            }
        },
    )
    resp = audit_api.lambda_handler(_event("/api/exports.csv", query={"status": "ACTIVE"}), None)
    body = json.loads(resp["body"])
    assert resp["statusCode"] == 403
    assert "RBAC denied" in body["error"]


def test_metrics_for_auditor(monkeypatch):
    _set_map(
        monkeypatch,
        {
            "arn:aws:iam::123456789012:role/TestRole": {
                "roles": ["auditor"],
                "accounts": ["*"],
                "requesters": ["*"],
                "permission_sets": ["*"],
                "statuses": ["*"],
            }
        },
    )
    resp = audit_api.lambda_handler(_event("/api/metrics"), None)
    body = json.loads(resp["body"])
    assert resp["statusCode"] == 200
    assert body["total_requests"] == 11
    assert body["by_status"]["ACTIVE"] == 3


def test_assumed_role_principal_matches_iam_role_mapping(monkeypatch):
    _set_map(
        monkeypatch,
        {
            "arn:aws:iam::123456789012:role/BoundaryAuditorApiRole": {
                "roles": ["auditor"],
                "accounts": ["*"],
                "requesters": ["*"],
                "permission_sets": ["*"],
                "statuses": ["*"],
            }
        },
    )
    sts_principal = "arn:aws:sts::123456789012:assumed-role/BoundaryAuditorApiRole/cli-session"
    resp = audit_api.lambda_handler(_event("/api/metrics", principal_arn=sts_principal), None)
    assert resp["statusCode"] == 200


def test_identity_context_principal_supported(monkeypatch):
    _set_map(
        monkeypatch,
        {
            "arn:aws:iam::123456789012:role/BoundaryAuditorApiRole": {
                "roles": ["auditor"],
                "accounts": ["*"],
                "requesters": ["*"],
                "permission_sets": ["*"],
                "statuses": ["*"],
            }
        },
    )
    event = {
        "rawPath": "/api/metrics",
        "queryStringParameters": {},
        "requestContext": {
            "http": {"method": "GET", "path": "/api/metrics"},
            "identity": {"userArn": "arn:aws:iam::123456789012:role/BoundaryAuditorApiRole"},
        },
    }
    resp = audit_api.lambda_handler(event, None)
    assert resp["statusCode"] == 200
