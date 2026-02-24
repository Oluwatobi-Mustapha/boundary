import json
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

import audit_dashboard


class _FakeStateStore:
    def __init__(self, table_name):
        self.table_name = table_name

    def list_requests_by_status(self, status, **_kwargs):
        fixtures = {
            "ACTIVE": [
                {
                    "request_id": "req-active-1",
                    "status": "ACTIVE",
                    "account_id": "111122223333",
                    "permission_set_name": "ReadOnlyAccess",
                    "requester_slack_user_id": "UREQ1",
                    "created_at": 1700000000,
                    "policy_hash": "pol-1",
                }
            ],
            "PENDING_APPROVAL": [
                {
                    "request_id": "req-pending-1",
                    "status": "PENDING_APPROVAL",
                    "account_id": "111122223333",
                    "permission_set_name": "AdministratorAccess",
                    "requester_slack_user_id": "UREQ2",
                    "created_at": 1700000000,
                    "reason": "Approval required by policy",
                    "policy_hash": "pol-2",
                }
            ],
            "REVOKED": [],
            "DENIED": [
                {
                    "request_id": "req-denied-1",
                    "status": "DENIED",
                    "account_id": "111122223333",
                    "permission_set_name": "PowerUserAccess",
                    "requester_slack_user_id": "UREQ3",
                    "created_at": 1700000000,
                    "reason": "None of your groups are authorized for this request.",
                    "policy_hash": "pol-3",
                }
            ],
        }
        return {"items": fixtures.get(status, []), "next_key": None}

    def get_request(self, request_id):
        if request_id == "req-detail-1":
            return {
                "request_id": "req-detail-1",
                "status": "ACTIVE",
                "account_id": "111122223333",
                "permission_set_name": "ReadOnlyAccess",
                "requester_slack_user_id": "UREQ1",
                "approver_slack_user_id": "UAPPROVER1",
                "ticket_id": "INC-12345",
                "policy_hash": "pol-4",
                "created_at": 1700000000,
                "updated_at": 1700000100,
            }
        if request_id == "req-hidden-1":
            return {
                "request_id": "req-hidden-1",
                "status": "ACTIVE",
                "account_id": "999900001111",
                "permission_set_name": "AdministratorAccess",
                "requester_slack_user_id": "UOTHER",
            }
        return None


def _event(path, method="GET", principal_arn="arn:aws:iam::123456789012:role/TestViewer"):
    return {
        "rawPath": path,
        "queryStringParameters": {},
        "requestContext": {
            "http": {"method": method, "path": path},
            "authorizer": {"iam": {"userArn": principal_arn}},
        },
    }


def _set_principal_map(monkeypatch, mapping):
    monkeypatch.setenv("AUDIT_API_PRINCIPAL_MAP", json.dumps(mapping))


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("DYNAMODB_TABLE", "boundary-dev-active-requests")
    monkeypatch.setattr(audit_dashboard, "StateStore", _FakeStateStore)


def test_dashboard_home_renders(monkeypatch):
    _set_principal_map(
        monkeypatch,
        {
            "arn:aws:iam::123456789012:role/TestViewer": {
                "roles": ["viewer"],
                "accounts": ["111122223333"],
                "requesters": ["*"],
                "permission_sets": ["*"],
                "statuses": ["*"],
            }
        },
    )

    resp = audit_dashboard.lambda_handler(_event("/dashboard"), None)
    assert resp["statusCode"] == 200
    assert "text/html" in resp["headers"]["Content-Type"]
    assert "Boundary Audit Dashboard" in resp["body"]
    assert "Pending Approvals" in resp["body"]
    assert "req-pending-1" in resp["body"]


def test_dashboard_denies_unmapped_principal(monkeypatch):
    _set_principal_map(monkeypatch, {})
    resp = audit_dashboard.lambda_handler(_event("/dashboard"), None)
    assert resp["statusCode"] == 403
    assert "Forbidden" in resp["body"]


def test_dashboard_detail_in_scope(monkeypatch):
    _set_principal_map(
        monkeypatch,
        {
            "arn:aws:iam::123456789012:role/TestViewer": {
                "roles": ["viewer"],
                "accounts": ["111122223333"],
                "requesters": ["*"],
                "permission_sets": ["*"],
                "statuses": ["*"],
            }
        },
    )

    resp = audit_dashboard.lambda_handler(_event("/dashboard/requests/req-detail-1"), None)
    assert resp["statusCode"] == 200
    assert "Request req-detail-1" in resp["body"]
    assert "INC-12345" in resp["body"]


def test_dashboard_detail_hidden_when_out_of_scope(monkeypatch):
    _set_principal_map(
        monkeypatch,
        {
            "arn:aws:iam::123456789012:role/TestViewer": {
                "roles": ["viewer"],
                "accounts": ["111122223333"],
                "requesters": ["*"],
                "permission_sets": ["*"],
                "statuses": ["*"],
            }
        },
    )

    resp = audit_dashboard.lambda_handler(_event("/dashboard/requests/req-hidden-1"), None)
    assert resp["statusCode"] == 404


def test_dashboard_method_not_allowed(monkeypatch):
    _set_principal_map(
        monkeypatch,
        {
            "arn:aws:iam::123456789012:role/TestViewer": {
                "roles": ["viewer"],
                "accounts": ["*"],
                "requesters": ["*"],
                "permission_sets": ["*"],
                "statuses": ["*"],
            }
        },
    )
    resp = audit_dashboard.lambda_handler(_event("/dashboard", method="POST"), None)
    assert resp["statusCode"] == 405


def test_dashboard_filters_apply(monkeypatch):
    _set_principal_map(
        monkeypatch,
        {
            "arn:aws:iam::123456789012:role/TestViewer": {
                "roles": ["viewer"],
                "accounts": ["111122223333"],
                "requesters": ["*"],
                "permission_sets": ["*"],
                "statuses": ["*"],
            }
        },
    )
    event = _event("/dashboard")
    event["queryStringParameters"] = {"status": "DENIED", "reason_contains": "authorized"}
    resp = audit_dashboard.lambda_handler(event, None)
    assert resp["statusCode"] == 200
    assert "None of your groups are authorized for this request." in resp["body"]
    assert "req-active-1" not in resp["body"]


def test_dashboard_invalid_filter_returns_400(monkeypatch):
    _set_principal_map(
        monkeypatch,
        {
            "arn:aws:iam::123456789012:role/TestViewer": {
                "roles": ["viewer"],
                "accounts": ["*"],
                "requesters": ["*"],
                "permission_sets": ["*"],
                "statuses": ["*"],
            }
        },
    )
    event = _event("/dashboard")
    event["queryStringParameters"] = {"status": "NOT_A_REAL_STATE"}
    resp = audit_dashboard.lambda_handler(event, None)
    assert resp["statusCode"] == 400
    assert "Bad request" in resp["body"]
