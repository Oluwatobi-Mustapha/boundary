"""
Unit tests for Step 3 query paths (DynamoDB GSI-backed reads).
"""
import importlib
import os
import sys
from decimal import Decimal

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

# Other test files may inject fake stub modules into sys.modules at import
# time (e.g. test_permission_set_env_lookup.py replaces adapters.state_store
# with a MagicMock-backed stub).  Purge those entries so we always get the
# *real* modules for this test file.
_MODULES_TO_RELOAD = [
    "adapters",
    "adapters.state_store",
    "models",
    "models.request",
    "models.request_states",
]
for _mod_name in _MODULES_TO_RELOAD:
    sys.modules.pop(_mod_name, None)

# Also restore the real boto3 if it was replaced by a MagicMock
import boto3 as _boto3_check
if not hasattr(_boto3_check, "__file__"):
    sys.modules.pop("boto3", None)
    importlib.invalidate_caches()

from adapters.state_store import StateStore  # noqa: E402
from models.request import AccessRequest  # noqa: E402
from models.request_states import STATE_PENDING_APPROVAL  # noqa: E402


class _FakeTable:
    def __init__(self):
        self.query_calls = []
        self.put_item_calls = []

    def query(self, **kwargs):
        self.query_calls.append(kwargs)
        return {
            "Items": [{"request_id": "req-1"}],
            "LastEvaluatedKey": {"request_id": "req-1"},
        }

    def put_item(self, **kwargs):
        self.put_item_calls.append(kwargs)
        return {}


class _FakeDynamo:
    def __init__(self, table):
        self._table = table

    def Table(self, _table_name):
        return self._table


def _build_store(monkeypatch):
    import boto3

    table = _FakeTable()
    fake_dynamo = _FakeDynamo(table)

    def _fake_resource(_service_name, **_kwargs):
        return fake_dynamo

    monkeypatch.setattr(boto3, "resource", _fake_resource)
    return StateStore("boundary-dev-active-requests"), table


def test_list_requests_by_status_uses_status_created_index(monkeypatch):
    store, table = _build_store(monkeypatch)

    result = store.list_requests_by_status(
        "PENDING",
        start_created_at=1000.0,
        end_created_at=2000.0,
        limit=25,
        next_key={"request_id": "req-0"},
        ascending=True,
    )

    assert result["items"] == [{"request_id": "req-1"}]
    assert result["next_key"] == {"request_id": "req-1"}

    call = table.query_calls[-1]
    assert call["IndexName"] == "StatusCreatedAtIndex"
    assert call["KeyConditionExpression"] == "#pk = :pk AND #created BETWEEN :start AND :end"
    assert call["ExpressionAttributeNames"] == {"#pk": "status", "#created": "created_at"}
    assert call["ExpressionAttributeValues"][":pk"] == STATE_PENDING_APPROVAL
    assert call["Limit"] == 25
    assert call["ScanIndexForward"] is True
    assert call["ExclusiveStartKey"] == {"request_id": "req-0"}


def test_list_requests_by_account_uses_account_created_index(monkeypatch):
    store, table = _build_store(monkeypatch)

    store.list_requests_by_account("123456789012", start_created_at=500.0)

    call = table.query_calls[-1]
    assert call["IndexName"] == "AccountCreatedAtIndex"
    assert call["KeyConditionExpression"] == "#pk = :pk AND #created >= :start"
    assert call["ExpressionAttributeNames"] == {"#pk": "account_id", "#created": "created_at"}
    assert call["ExpressionAttributeValues"][":pk"] == "123456789012"


def test_list_requests_by_requester_uses_requester_created_index(monkeypatch):
    store, table = _build_store(monkeypatch)

    store.list_requests_by_requester("U1234567890", end_created_at=800.0)

    call = table.query_calls[-1]
    assert call["IndexName"] == "RequesterCreatedAtIndex"
    assert call["KeyConditionExpression"] == "#pk = :pk AND #created <= :end"
    assert call["ExpressionAttributeNames"] == {
        "#pk": "requester_slack_user_id",
        "#created": "created_at",
    }
    assert call["ExpressionAttributeValues"][":pk"] == "U1234567890"


def test_list_requests_by_permission_set_uses_role_created_index(monkeypatch):
    store, table = _build_store(monkeypatch)

    store.list_requests_by_permission_set("ReadOnlyAccess")

    call = table.query_calls[-1]
    assert call["IndexName"] == "RoleCreatedAtIndex"
    assert call["KeyConditionExpression"] == "#pk = :pk"
    assert call["ExpressionAttributeNames"] == {"#pk": "permission_set_name"}
    assert call["ExpressionAttributeValues"][":pk"] == "ReadOnlyAccess"
    assert call["Limit"] == 50
    assert call["ScanIndexForward"] is False


def test_invalid_query_inputs_raise(monkeypatch):
    store, _ = _build_store(monkeypatch)

    with pytest.raises(ValueError, match="Invalid status filter"):
        store.list_requests_by_status("NOT_A_REAL_STATUS")

    with pytest.raises(ValueError, match="start_created_at cannot be greater"):
        store.list_requests_by_account(
            "123456789012",
            start_created_at=99.0,
            end_created_at=10.0,
        )

    with pytest.raises(ValueError, match="limit must be greater than 0"):
        store.list_requests_by_permission_set("PowerUserAccess", limit=0)


def test_save_request_converts_float_fields_to_decimal(monkeypatch):
    store, table = _build_store(monkeypatch)
    req = AccessRequest(
        request_id="req-float-1",
        principal_id="user-1",
        principal_type="USER",
        permission_set_arn="arn:aws:sso:::permissionSet/ssoins-123/ps-123",
        permission_set_name="ReadOnlyAccess",
        account_id="123456789012",
        instance_arn="arn:aws:sso:::instance/ssoins-123",
        rule_id="rule-1",
        requested_at=1700000000.1,
        created_at=1700000000.2,
        updated_at=1700000000.3,
        expires_at=1700003600.4,
        evaluated_at=1700000000.5,
    )

    store.save_request(req)

    item = table.put_item_calls[-1]["Item"]
    assert isinstance(item["requested_at"], Decimal)
    assert isinstance(item["created_at"], Decimal)
    assert isinstance(item["updated_at"], Decimal)
    assert isinstance(item["expires_at"], Decimal)
    assert isinstance(item["evaluated_at"], Decimal)
