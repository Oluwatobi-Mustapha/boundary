import csv
import io
import json
import os
import sys
from dataclasses import fields

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

import audit_api
from contracts import (
    API_LIST_RESPONSE_KEYS,
    API_METRICS_RESPONSE_KEYS,
    CONTRACT_VERSION,
    CSV_EXPORT_COLUMNS,
    IMMUTABLE_AUDIT_FIELDS,
    REQUEST_STATUS_VALUES,
)
from models.request import AccessRequest
from models.request_states import can_transition, canonicalize_status, is_valid_status


class _FakeTable:
    def query(self, **kwargs):
        status = str(kwargs["ExpressionAttributeValues"][":status"])
        count_by_status = {
            "PENDING_APPROVAL": 2,
            "APPROVED": 1,
            "ACTIVE": 3,
            "REVOKED": 1,
            "DENIED": 1,
            "ERROR": 0,
        }
        return {"Count": count_by_status.get(status, 0), "Items": [], "LastEvaluatedKey": None}


class _FakeStateStore:
    def __init__(self, table_name):
        self.table_name = table_name
        self.table = _FakeTable()

    def list_requests_by_status(self, *_args, **_kwargs):
        return {
            "items": [
                {
                    "request_id": "req-contract-1",
                    "status": "ACTIVE",
                    "account_id": "111122223333",
                    "permission_set_name": "ReadOnlyAccess",
                    "requester_slack_user_id": "UREQ1111111",
                    "created_at": 1700000000,
                    "updated_at": 1700000100,
                    "requested_at": 1700000000,
                    "expires_at": 1700003600,
                    "rule_id": "r-1",
                    "ticket_id": "INC-12345",
                }
            ],
            "next_key": {"request_id": "req-contract-1"},
        }

    def list_requests_by_account(self, *_args, **_kwargs):
        return {"items": [], "next_key": None}

    def list_requests_by_permission_set(self, *_args, **_kwargs):
        return {"items": [], "next_key": None}

    def list_requests_by_requester(self, *_args, **_kwargs):
        return {"items": [], "next_key": None}

    def get_request(self, _request_id):
        return None


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
    monkeypatch.setenv(
        "AUDIT_API_PRINCIPAL_MAP",
        json.dumps(
            {
                "arn:aws:iam::123456789012:role/TestRole": {
                    "roles": ["security_admin"],
                    "accounts": ["*"],
                    "requesters": ["*"],
                    "permission_sets": ["*"],
                    "statuses": ["*"],
                }
            }
        ),
    )
    monkeypatch.setattr(audit_api, "StateStore", _FakeStateStore)


def test_v1_status_values_are_frozen():
    expected = (
        "PENDING_APPROVAL",
        "APPROVED",
        "ACTIVE",
        "REVOKED",
        "DENIED",
        "ERROR",
    )
    assert REQUEST_STATUS_VALUES == expected
    assert all(is_valid_status(s) for s in REQUEST_STATUS_VALUES)


def test_v1_transition_matrix_is_frozen():
    allowed = {
        "PENDING_APPROVAL": {"APPROVED", "ACTIVE", "DENIED", "ERROR"},
        "APPROVED": {"ACTIVE", "ERROR"},
        "ACTIVE": {"REVOKED", "ERROR"},
        "REVOKED": set(),
        "DENIED": set(),
        "ERROR": set(),
    }
    for src in REQUEST_STATUS_VALUES:
        for dst in REQUEST_STATUS_VALUES:
            expected = dst == src or dst in allowed[src]
            assert can_transition(src, dst) is expected, f"unexpected transition {src} -> {dst}"
            # Canonical states should remain canonical.
            assert canonicalize_status(src) == src


def test_v1_immutable_audit_fields_exist_on_request_model():
    model_fields = {f.name for f in fields(AccessRequest)}
    missing = sorted(set(IMMUTABLE_AUDIT_FIELDS) - model_fields)
    assert not missing, f"missing immutable fields on AccessRequest: {missing}"


def test_v1_requests_response_shape_is_frozen():
    resp = audit_api.lambda_handler(_event("/api/requests", query={"status": "ACTIVE"}), None)
    body = json.loads(resp["body"])
    assert resp["statusCode"] == 200
    assert resp["headers"]["X-Boundary-Contract-Version"] == CONTRACT_VERSION
    assert tuple(body.keys()) == API_LIST_RESPONSE_KEYS


def test_v1_metrics_response_shape_is_frozen():
    resp = audit_api.lambda_handler(_event("/api/metrics"), None)
    body = json.loads(resp["body"])
    assert resp["statusCode"] == 200
    assert resp["headers"]["X-Boundary-Contract-Version"] == CONTRACT_VERSION
    assert tuple(body.keys()) == API_METRICS_RESPONSE_KEYS
    assert set(body["by_status"].keys()).issubset(set(REQUEST_STATUS_VALUES))


def test_v1_export_csv_columns_are_frozen():
    resp = audit_api.lambda_handler(_event("/api/exports.csv", query={"status": "ACTIVE"}), None)
    assert resp["statusCode"] == 200
    assert resp["headers"]["X-Boundary-Contract-Version"] == CONTRACT_VERSION
    reader = csv.reader(io.StringIO(resp["body"]))
    first_row = next(reader)
    assert tuple(first_row) == CSV_EXPORT_COLUMNS


def test_v1_error_shape_is_frozen():
    # Force 404 route and ensure error payload contract is stable.
    resp = audit_api.lambda_handler(_event("/api/nope"), None)
    body = json.loads(resp["body"])
    assert resp["statusCode"] == 404
    assert tuple(body.keys()) == ("error",)
