import base64
import csv
import io
import json
import os
import re
import time
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Dict, List, Optional, Set, Tuple

from adapters.state_store import StateStore
from models.request_states import (
    STATE_ACTIVE,
    STATE_APPROVED,
    STATE_DENIED,
    STATE_ERROR,
    STATE_PENDING_APPROVAL,
    STATE_REVOKED,
    canonicalize_status,
    is_valid_status,
)


ALL_STATUSES = [
    STATE_PENDING_APPROVAL,
    STATE_APPROVED,
    STATE_ACTIVE,
    STATE_REVOKED,
    STATE_DENIED,
    STATE_ERROR,
]

READ_ROLES = {"security_admin", "auditor", "viewer"}
EXPORT_ROLES = {"security_admin", "auditor"}
METRICS_ROLES = {"security_admin", "auditor"}
WILDCARD = "*"


@dataclass
class PrincipalScope:
    principal_arn: str
    roles: Set[str]
    accounts: Set[str]
    requesters: Set[str]
    permission_sets: Set[str]
    statuses: Set[str]


def _response(status_code: int, body: Any, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    out_headers = {"Content-Type": "application/json"}
    if headers:
        out_headers.update(headers)
    return {
        "statusCode": status_code,
        "headers": out_headers,
        "body": json.dumps(body),
    }


def _csv_response(filename: str, content: str) -> Dict[str, Any]:
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "text/csv",
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
        "body": content,
    }


def _normalize_json(value: Any) -> Any:
    if isinstance(value, Decimal):
        if value % 1 == 0:
            return int(value)
        return float(value)
    if isinstance(value, dict):
        return {k: _normalize_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize_json(v) for v in value]
    return value


def _to_ddb(value: Any) -> Any:
    if isinstance(value, float):
        return Decimal(str(value))
    return value


def _parse_float(name: str, raw: Optional[str]) -> Optional[float]:
    if raw is None or raw == "":
        return None
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc


def _parse_int(name: str, raw: Optional[str], default: int) -> int:
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _encode_next_token(last_evaluated_key: Optional[Dict[str, Any]]) -> Optional[str]:
    if not last_evaluated_key:
        return None
    payload = json.dumps(last_evaluated_key).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("utf-8")


def _decode_next_token(raw: Optional[str]) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    try:
        payload = base64.urlsafe_b64decode(raw.encode("utf-8")).decode("utf-8")
        decoded = json.loads(payload)
        if not isinstance(decoded, dict):
            raise ValueError("next_token payload must be an object")
        return decoded
    except Exception as exc:
        raise ValueError("next_token is invalid") from exc


def _parse_scopes_map(raw: str) -> Dict[str, Dict[str, Any]]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("AUDIT_API_PRINCIPAL_MAP is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("AUDIT_API_PRINCIPAL_MAP must be a JSON object")
    return parsed


def _as_scope_set(values: Any, *, normalize_status: bool = False) -> Set[str]:
    if values is None:
        return {WILDCARD}
    if isinstance(values, str):
        if values.strip() == "":
            return {WILDCARD}
        items = [v.strip() for v in values.split(",") if v.strip()]
    elif isinstance(values, list):
        items = [str(v).strip() for v in values if str(v).strip()]
    else:
        raise ValueError("Scope values must be list or comma-separated string")

    if not items:
        return {WILDCARD}
    if WILDCARD in items:
        return {WILDCARD}

    out: Set[str] = set()
    for item in items:
        if normalize_status:
            item = canonicalize_status(item)
            if not is_valid_status(item):
                raise ValueError(f"Invalid status in principal scope: {item}")
        out.add(item)
    return out


def _is_in_scope(value: str, allowed: Set[str]) -> bool:
    return WILDCARD in allowed or value in allowed


def _extract_principal(event: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    # HTTP API v2 IAM authorizer shape
    request_context = event.get("requestContext", {})
    authorizer = request_context.get("authorizer", {})
    iam_ctx = authorizer.get("iam", {})
    principal_arn = iam_ctx.get("userArn")
    if principal_arn:
        return principal_arn, "iam"

    # HTTP API payload format 1.0 often carries IAM identity here.
    identity_ctx = request_context.get("identity", {})
    principal_arn = identity_ctx.get("userArn")
    if principal_arn:
        return principal_arn, "identity"

    # Generic fallback shapes (for tests / future authorizers)
    principal_arn = authorizer.get("principalArn") or authorizer.get("principalId")
    if principal_arn:
        return principal_arn, "custom"
    return None, None


def _principal_lookup_candidates(principal_arn: str) -> List[str]:
    """
    Returns lookup keys for principal mapping.
    Includes exact ARN plus normalized IAM role ARN for STS assumed-role callers.
    """
    candidates = [principal_arn]
    match = re.match(
        r"^arn:(?P<partition>[^:]+):sts::(?P<account>\d+):assumed-role/(?P<role_path>.+)/(?P<session>[^/]+)$",
        principal_arn,
    )
    if match:
        partition = match.group("partition")
        account = match.group("account")
        role_path = match.group("role_path")
        candidates.append(f"arn:{partition}:iam::{account}:role/{role_path}")
    return candidates


def _build_scope(event: Dict[str, Any]) -> PrincipalScope:
    principal_arn, auth_mode = _extract_principal(event)
    if not principal_arn:
        raise PermissionError("Unauthenticated request")

    raw_map = os.environ.get("AUDIT_API_PRINCIPAL_MAP", "")
    scopes_map = _parse_scopes_map(raw_map)
    principal_cfg = None
    for candidate in _principal_lookup_candidates(principal_arn):
        principal_cfg = scopes_map.get(candidate)
        if principal_cfg is not None:
            break

    # Optional wildcard fallback for controlled bootstrap.
    if principal_cfg is None and WILDCARD in scopes_map:
        principal_cfg = scopes_map[WILDCARD]

    if principal_cfg is None:
        raise PermissionError(
            f"Principal not mapped for audit API access: {principal_arn} ({auth_mode})"
        )
    if not isinstance(principal_cfg, dict):
        raise PermissionError("Principal mapping must be an object")

    roles = _as_scope_set(principal_cfg.get("roles"))
    roles.discard(WILDCARD)
    if not roles:
        raise PermissionError("Principal has no RBAC roles configured")
    unknown_roles = roles - READ_ROLES
    if unknown_roles:
        raise PermissionError(f"Unknown RBAC roles configured: {sorted(unknown_roles)}")

    return PrincipalScope(
        principal_arn=principal_arn,
        roles=roles,
        accounts=_as_scope_set(principal_cfg.get("accounts")),
        requesters=_as_scope_set(principal_cfg.get("requesters")),
        permission_sets=_as_scope_set(principal_cfg.get("permission_sets")),
        statuses=_as_scope_set(principal_cfg.get("statuses"), normalize_status=True),
    )


def _require_any_role(scope: PrincipalScope, allowed_roles: Set[str]) -> None:
    if scope.roles.isdisjoint(allowed_roles):
        raise PermissionError(f"RBAC denied. Required one of: {sorted(allowed_roles)}")


def _enforce_scope_filter(value: Optional[str], allowed_values: Set[str], field_name: str) -> Optional[str]:
    if value is None:
        return value
    if not _is_in_scope(value, allowed_values):
        raise PermissionError(f"ABAC denied for {field_name}")
    return value


def _item_in_scope(item: Dict[str, Any], scope: PrincipalScope) -> bool:
    account_id = str(item.get("account_id", ""))
    requester = str(item.get("requester_slack_user_id") or item.get("slack_user_id") or "")
    permission_set = str(item.get("permission_set_name", ""))
    status = canonicalize_status(str(item.get("status", "")))
    return (
        _is_in_scope(account_id, scope.accounts)
        and _is_in_scope(requester, scope.requesters)
        and _is_in_scope(permission_set, scope.permission_sets)
        and _is_in_scope(status, scope.statuses)
    )


def _parse_request_filters(query: Dict[str, str], scope: PrincipalScope) -> Dict[str, Any]:
    status = query.get("status")
    if status is not None:
        status = canonicalize_status(status)
        if not is_valid_status(status):
            raise ValueError("status filter is invalid")
        _enforce_scope_filter(status, scope.statuses, "status")

    account_id = _enforce_scope_filter(query.get("account_id"), scope.accounts, "account_id")
    requester = _enforce_scope_filter(
        query.get("requester_slack_user_id"),
        scope.requesters,
        "requester_slack_user_id",
    )
    permission_set_name = _enforce_scope_filter(
        query.get("permission_set_name"),
        scope.permission_sets,
        "permission_set_name",
    )

    created_after = _parse_float("created_after", query.get("created_after"))
    created_before = _parse_float("created_before", query.get("created_before"))
    if created_after is not None and created_before is not None and created_after > created_before:
        raise ValueError("created_after cannot be greater than created_before")

    page_size = _parse_int("page_size", query.get("page_size"), 50)
    max_page_size = _parse_int("AUDIT_API_MAX_PAGE_SIZE", os.environ.get("AUDIT_API_MAX_PAGE_SIZE"), 200)
    if page_size <= 0:
        raise ValueError("page_size must be greater than 0")
    if page_size > max_page_size:
        page_size = max_page_size

    next_token = _decode_next_token(query.get("next_token"))

    return {
        "status": status,
        "account_id": account_id,
        "requester_slack_user_id": requester,
        "permission_set_name": permission_set_name,
        "created_after": created_after,
        "created_before": created_before,
        "page_size": page_size,
        "next_token": next_token,
    }


def _pick_primary_query(filters: Dict[str, Any]) -> Tuple[str, str]:
    # Priority keeps behavior deterministic and avoids scans.
    if filters["status"]:
        return "status", filters["status"]
    if filters["account_id"]:
        return "account_id", filters["account_id"]
    if filters["permission_set_name"]:
        return "permission_set_name", filters["permission_set_name"]
    if filters["requester_slack_user_id"]:
        return "requester_slack_user_id", filters["requester_slack_user_id"]
    raise ValueError(
        "Provide at least one primary filter: status, account_id, permission_set_name, requester_slack_user_id"
    )


def _query_requests(store: StateStore, filters: Dict[str, Any]) -> Dict[str, Any]:
    start = filters["created_after"]
    end = filters["created_before"]
    limit = filters["page_size"]
    next_key = filters["next_token"]

    primary_key, primary_value = _pick_primary_query(filters)
    if primary_key == "status":
        return store.list_requests_by_status(
            primary_value,
            start_created_at=start,
            end_created_at=end,
            limit=limit,
            next_key=next_key,
        )
    if primary_key == "account_id":
        return store.list_requests_by_account(
            primary_value,
            start_created_at=start,
            end_created_at=end,
            limit=limit,
            next_key=next_key,
        )
    if primary_key == "permission_set_name":
        return store.list_requests_by_permission_set(
            primary_value,
            start_created_at=start,
            end_created_at=end,
            limit=limit,
            next_key=next_key,
        )
    return store.list_requests_by_requester(
        primary_value,
        start_created_at=start,
        end_created_at=end,
        limit=limit,
        next_key=next_key,
    )


def _matches_secondary_filters(item: Dict[str, Any], filters: Dict[str, Any]) -> bool:
    if filters["status"] and canonicalize_status(str(item.get("status", ""))) != filters["status"]:
        return False
    if filters["account_id"] and str(item.get("account_id", "")) != filters["account_id"]:
        return False
    item_requester = str(item.get("requester_slack_user_id") or item.get("slack_user_id") or "")
    if filters["requester_slack_user_id"] and item_requester != filters["requester_slack_user_id"]:
        return False
    if filters["permission_set_name"] and str(item.get("permission_set_name", "")) != filters["permission_set_name"]:
        return False
    return True


def _query_params(event: Dict[str, Any]) -> Dict[str, str]:
    params = event.get("queryStringParameters") or {}
    return {str(k): str(v) for k, v in params.items() if v is not None}


def _request_path(event: Dict[str, Any]) -> str:
    if event.get("rawPath"):
        return event["rawPath"]
    request_context = event.get("requestContext", {})
    http_ctx = request_context.get("http", {})
    if http_ctx.get("path"):
        return http_ctx["path"]
    return event.get("path", "")


def _http_method(event: Dict[str, Any]) -> str:
    request_context = event.get("requestContext", {})
    http_ctx = request_context.get("http", {})
    if http_ctx.get("method"):
        return http_ctx["method"].upper()
    return str(event.get("httpMethod", "GET")).upper()


def _count_by_status(
    store: StateStore,
    status: str,
    created_after: Optional[float],
    created_before: Optional[float],
) -> int:
    expression_names: Dict[str, str] = {"#s": "status"}
    expression_values: Dict[str, Any] = {":status": _to_ddb(status)}
    key_condition = "#s = :status"
    if created_after is not None and created_before is not None:
        expression_names["#created"] = "created_at"
        expression_values[":start"] = _to_ddb(created_after)
        expression_values[":end"] = _to_ddb(created_before)
        key_condition = "#s = :status AND #created BETWEEN :start AND :end"
    elif created_after is not None:
        expression_names["#created"] = "created_at"
        expression_values[":start"] = _to_ddb(created_after)
        key_condition = "#s = :status AND #created >= :start"
    elif created_before is not None:
        expression_names["#created"] = "created_at"
        expression_values[":end"] = _to_ddb(created_before)
        key_condition = "#s = :status AND #created <= :end"

    total = 0
    last_key = None
    while True:
        query_kwargs = {
            "IndexName": "StatusCreatedAtIndex",
            "KeyConditionExpression": key_condition,
            "ExpressionAttributeNames": expression_names,
            "ExpressionAttributeValues": expression_values,
            "Select": "COUNT",
        }
        if last_key:
            query_kwargs["ExclusiveStartKey"] = last_key
        response = store.table.query(**query_kwargs)
        total += int(response.get("Count", 0))
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            break
    return total


def _handle_get_requests(store: StateStore, scope: PrincipalScope, event: Dict[str, Any]) -> Dict[str, Any]:
    _require_any_role(scope, READ_ROLES)
    filters = _parse_request_filters(_query_params(event), scope)

    data = _query_requests(store, filters)
    items = []
    for raw_item in data["items"]:
        item = _normalize_json(raw_item)
        if not _item_in_scope(item, scope):
            continue
        if not _matches_secondary_filters(item, filters):
            continue
        items.append(item)

    return _response(
        200,
        {
            "items": items,
            "next_token": _encode_next_token(data.get("next_key")),
            "count": len(items),
            "generated_at": int(time.time()),
        },
    )


def _handle_get_request_by_id(store: StateStore, scope: PrincipalScope, request_id: str) -> Dict[str, Any]:
    _require_any_role(scope, READ_ROLES)
    item = store.get_request(request_id)
    if not item:
        return _response(404, {"error": "Request not found"})
    normalized = _normalize_json(item)
    if not _item_in_scope(normalized, scope):
        # Hide existence when out of scope.
        return _response(404, {"error": "Request not found"})
    return _response(200, normalized)


def _handle_get_metrics(store: StateStore, scope: PrincipalScope, event: Dict[str, Any]) -> Dict[str, Any]:
    _require_any_role(scope, METRICS_ROLES)
    if (
        WILDCARD not in scope.accounts
        or WILDCARD not in scope.requesters
        or WILDCARD not in scope.permission_sets
    ):
        raise PermissionError("Metrics endpoint requires global ABAC scope")

    query = _query_params(event)
    created_after = _parse_float("created_after", query.get("created_after"))
    created_before = _parse_float("created_before", query.get("created_before"))
    if created_after is not None and created_before is not None and created_after > created_before:
        raise ValueError("created_after cannot be greater than created_before")

    statuses_to_count = [s for s in ALL_STATUSES if _is_in_scope(s, scope.statuses)]
    by_status = {
        status: _count_by_status(store, status, created_after, created_before)
        for status in statuses_to_count
    }
    total = sum(by_status.values())
    body = {
        "total_requests": total,
        "by_status": by_status,
        "created_after": created_after,
        "created_before": created_before,
        "generated_at": int(time.time()),
    }
    return _response(200, body)


def _iter_requests_for_export(store: StateStore, scope: PrincipalScope, filters: Dict[str, Any], max_rows: int) -> List[Dict[str, Any]]:
    all_rows: List[Dict[str, Any]] = []
    next_key = filters["next_token"]

    while len(all_rows) < max_rows:
        filters["next_token"] = next_key
        page = _query_requests(store, filters)
        rows = page.get("items", [])
        for raw_item in rows:
            item = _normalize_json(raw_item)
            if not _item_in_scope(item, scope):
                continue
            if not _matches_secondary_filters(item, filters):
                continue
            all_rows.append(item)
            if len(all_rows) >= max_rows:
                break
        next_key = page.get("next_key")
        if not next_key:
            break
    return all_rows


def _handle_export_csv(store: StateStore, scope: PrincipalScope, event: Dict[str, Any]) -> Dict[str, Any]:
    _require_any_role(scope, EXPORT_ROLES)
    filters = _parse_request_filters(_query_params(event), scope)
    max_rows = _parse_int("max_rows", _query_params(event).get("max_rows"), 1000)
    if max_rows <= 0:
        raise ValueError("max_rows must be greater than 0")
    if max_rows > 5000:
        max_rows = 5000

    rows = _iter_requests_for_export(store, scope, filters, max_rows=max_rows)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "request_id",
            "status",
            "created_at",
            "updated_at",
            "requested_at",
            "expires_at",
            "revoked_at",
            "account_id",
            "permission_set_name",
            "requester_slack_user_id",
            "approver_slack_user_id",
            "rule_id",
            "reason",
            "ticket_id",
        ]
    )
    for row in rows:
        writer.writerow(
            [
                row.get("request_id", ""),
                row.get("status", ""),
                row.get("created_at", ""),
                row.get("updated_at", ""),
                row.get("requested_at", ""),
                row.get("expires_at", ""),
                row.get("revoked_at", ""),
                row.get("account_id", ""),
                row.get("permission_set_name", ""),
                row.get("requester_slack_user_id") or row.get("slack_user_id", ""),
                row.get("approver_slack_user_id", ""),
                row.get("rule_id", ""),
                row.get("reason", ""),
                row.get("ticket_id", ""),
            ]
        )

    filename = f"boundary-audit-export-{int(time.time())}.csv"
    return _csv_response(filename, output.getvalue())


def lambda_handler(event, context):  # pragma: no cover - entrypoint
    del context
    method = _http_method(event)
    path = _request_path(event)

    if method != "GET":
        return _response(405, {"error": "Method not allowed"})

    table_name = os.environ.get("DYNAMODB_TABLE")
    if not table_name:
        return _response(500, {"error": "DYNAMODB_TABLE is not configured"})

    try:
        scope = _build_scope(event)
        store = StateStore(table_name=table_name)

        if path == "/api/requests":
            return _handle_get_requests(store, scope, event)
        if path == "/api/metrics":
            return _handle_get_metrics(store, scope, event)
        if path == "/api/exports.csv":
            return _handle_export_csv(store, scope, event)
        if path.startswith("/api/requests/"):
            request_id = path.rsplit("/", 1)[-1].strip()
            if not request_id:
                return _response(400, {"error": "request_id is required"})
            return _handle_get_request_by_id(store, scope, request_id)

        return _response(404, {"error": "Not found"})
    except PermissionError as exc:
        return _response(403, {"error": str(exc)})
    except ValueError as exc:
        return _response(400, {"error": str(exc)})
    except Exception as exc:  # pragma: no cover - defensive
        return _response(500, {"error": f"Internal error: {exc}"})
