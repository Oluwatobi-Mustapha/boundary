import html
import json
import os
import time
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

from adapters.state_store import StateStore
from models.request_states import (
    STATE_ACTIVE,
    STATE_DENIED,
    STATE_PENDING_APPROVAL,
    STATE_REVOKED,
    canonicalize_status,
    is_valid_status,
)

# Reuse auth/scope behavior from audit API so UI and API stay consistent.
from audit_api import _build_scope, _item_in_scope, _normalize_json, _require_any_role


ALLOWED_DASHBOARD_ROLES = {"security_admin", "auditor", "viewer"}
ALL_SECTION_STATUSES = [STATE_PENDING_APPROVAL, STATE_ACTIVE, STATE_REVOKED, STATE_DENIED]


def _html_response(status_code: int, body: str) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": body,
    }


def _escape(value: Any) -> str:
    return html.escape("" if value is None else str(value))


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


def _request_query(event: Dict[str, Any]) -> Dict[str, str]:
    raw = event.get("queryStringParameters") or {}
    out: Dict[str, str] = {}
    for key, value in raw.items():
        if value is None:
            continue
        out[str(key)] = str(value)
    return out


def _parse_float(name: str, raw: Optional[str]) -> Optional[float]:
    if raw is None or raw == "":
        return None
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be numeric") from exc


def _parse_dashboard_filters(query: Dict[str, str]) -> Dict[str, Any]:
    status_raw = (query.get("status") or "").strip()
    status: Optional[str] = None
    if status_raw:
        status = canonicalize_status(status_raw)
        if not is_valid_status(status):
            raise ValueError("status is invalid")

    account_id = (query.get("account_id") or "").strip() or None
    permission_set_name = (query.get("permission_set_name") or "").strip() or None
    requester_slack_user_id = (query.get("requester_slack_user_id") or "").strip() or None
    reason_contains = (query.get("reason_contains") or "").strip() or None
    created_after = _parse_float("created_after", query.get("created_after"))
    created_before = _parse_float("created_before", query.get("created_before"))
    if created_after is not None and created_before is not None and created_after > created_before:
        raise ValueError("created_after cannot be greater than created_before")

    return {
        "status": status,
        "account_id": account_id,
        "permission_set_name": permission_set_name,
        "requester_slack_user_id": requester_slack_user_id,
        "reason_contains": reason_contains,
        "created_after": created_after,
        "created_before": created_before,
    }


def _status_class(status: str) -> str:
    status = (status or "").upper()
    if status == STATE_ACTIVE:
        return "status-active"
    if status == STATE_PENDING_APPROVAL:
        return "status-pending"
    if status == STATE_REVOKED:
        return "status-revoked"
    if status == STATE_DENIED:
        return "status-denied"
    return "status-other"


def _age_badge(item: Dict[str, Any]) -> str:
    created = item.get("created_at") or item.get("requested_at")
    if not created:
        return '<span class="pill pill-muted">unknown</span>'
    age_seconds = max(0, int(time.time() - float(created)))
    if age_seconds >= 3600:
        return f'<span class="pill pill-danger">{age_seconds // 3600}h old</span>'
    if age_seconds >= 900:
        return f'<span class="pill pill-warn">{age_seconds // 60}m old</span>'
    return f'<span class="pill pill-ok">{age_seconds // 60}m old</span>'


def _matches_filters(item: Dict[str, Any], filters: Dict[str, Any]) -> bool:
    if filters["status"] and canonicalize_status(str(item.get("status", ""))) != filters["status"]:
        return False
    if filters["account_id"] and str(item.get("account_id", "")) != filters["account_id"]:
        return False
    if filters["permission_set_name"] and str(item.get("permission_set_name", "")) != filters["permission_set_name"]:
        return False
    if filters["requester_slack_user_id"]:
        requester = str(item.get("requester_slack_user_id") or item.get("slack_user_id") or "")
        if requester != filters["requester_slack_user_id"]:
            return False
    if filters["reason_contains"]:
        reason = str(item.get("reason") or "").lower()
        if filters["reason_contains"].lower() not in reason:
            return False

    created = item.get("created_at") or item.get("requested_at")
    if created is not None:
        created_num = float(created)
        if filters["created_after"] is not None and created_num < float(filters["created_after"]):
            return False
        if filters["created_before"] is not None and created_num > float(filters["created_before"]):
            return False
    elif filters["created_after"] is not None or filters["created_before"] is not None:
        return False

    return True


def _filter_query_pairs(filters: Dict[str, Any], *, include_empty: bool = False) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    ordered_keys = [
        "status",
        "account_id",
        "permission_set_name",
        "requester_slack_user_id",
        "reason_contains",
        "created_after",
        "created_before",
    ]
    for key in ordered_keys:
        value = filters.get(key)
        if value is None or value == "":
            if include_empty:
                pairs.append((key, ""))
            continue
        pairs.append((key, str(value)))
    return pairs


def _with_query(path: str, filters: Dict[str, Any]) -> str:
    pairs = _filter_query_pairs(filters)
    if not pairs:
        return path
    return f"{path}?{urlencode(pairs)}"


def _query_status_items(
    store: StateStore,
    scope,
    status: str,
    filters: Dict[str, Any],
    limit: int = 80,
) -> List[Dict[str, Any]]:
    page = store.list_requests_by_status(
        status,
        start_created_at=filters["created_after"],
        end_created_at=filters["created_before"],
        limit=limit,
        ascending=False,
    )
    results: List[Dict[str, Any]] = []
    for raw in page.get("items", []):
        item = _normalize_json(raw)
        if not _item_in_scope(item, scope):
            continue
        if not _matches_filters(item, filters):
            continue
        results.append(item)
    return results


def _render_rows(rows: List[Dict[str, Any]], filters: Dict[str, Any], include_age: bool = False) -> str:
    if not rows:
        return '<tr><td colspan="9" class="empty">No records</td></tr>'
    output = []
    for item in rows:
        request_id_raw = str(item.get("request_id", ""))
        request_id = _escape(request_id_raw)
        status = _escape(item.get("status"))
        account_id = _escape(item.get("account_id"))
        role = _escape(item.get("permission_set_name"))
        requester = _escape(item.get("requester_slack_user_id") or item.get("slack_user_id") or "-")
        reason = _escape(item.get("reason", "-"))
        created_at = _escape(item.get("created_at") or item.get("requested_at") or "-")
        policy_hash = _escape(item.get("policy_hash", "-"))
        detail_link = _escape(_with_query(f"/dashboard/requests/{request_id_raw}", filters))
        age_cell = f"<td>{_age_badge(item)}</td>" if include_age else ""
        output.append(
            f"""
            <tr>
              <td><a href="{detail_link}">{request_id}</a></td>
              <td><span class="status { _status_class(status) }">{status}</span></td>
              <td>{account_id}</td>
              <td>{role}</td>
              <td>{requester}</td>
              <td class="reason">{reason}</td>
              <td class="mono">{created_at}</td>
              <td class="mono">{policy_hash}</td>
              {age_cell}
            </tr>
            """
        )
    return "".join(output)


def _render_denials_chart(denied_rows: List[Dict[str, Any]]) -> str:
    if not denied_rows:
        return '<div class="empty">No denial data</div>'
    reasons = [str(r.get("reason") or "Unknown") for r in denied_rows]
    counts = Counter(reasons).most_common(8)
    max_count = max(c for _, c in counts)
    parts: List[str] = []
    for reason, count in counts:
        width = int((count / max_count) * 100) if max_count else 0
        parts.append(
            f"""
            <div class="bar-row">
              <div class="bar-label">{_escape(reason)}</div>
              <div class="bar-track"><div class="bar-fill" style="width:{width}%"></div></div>
              <div class="bar-count">{count}</div>
            </div>
            """
        )
    return "".join(parts)


def _render_filter_bar(filters: Dict[str, Any]) -> str:
    status_options = "".join(
        [
            '<option value="">Any</option>',
            f'<option value="{STATE_PENDING_APPROVAL}" {"selected" if filters["status"] == STATE_PENDING_APPROVAL else ""}>{STATE_PENDING_APPROVAL}</option>',
            f'<option value="{STATE_ACTIVE}" {"selected" if filters["status"] == STATE_ACTIVE else ""}>{STATE_ACTIVE}</option>',
            f'<option value="{STATE_REVOKED}" {"selected" if filters["status"] == STATE_REVOKED else ""}>{STATE_REVOKED}</option>',
            f'<option value="{STATE_DENIED}" {"selected" if filters["status"] == STATE_DENIED else ""}>{STATE_DENIED}</option>',
        ]
    )
    return f"""
    <section class="card">
      <h2>Filters</h2>
      <form method="GET" action="/dashboard" class="filters">
        <label>Status
          <select name="status">{status_options}</select>
        </label>
        <label>Account
          <input type="text" name="account_id" value="{_escape(filters['account_id'] or '')}" placeholder="12-digit account" />
        </label>
        <label>Role
          <input type="text" name="permission_set_name" value="{_escape(filters['permission_set_name'] or '')}" placeholder="ReadOnlyAccess" />
        </label>
        <label>Requester
          <input type="text" name="requester_slack_user_id" value="{_escape(filters['requester_slack_user_id'] or '')}" placeholder="U123..." />
        </label>
        <label>Reason Contains
          <input type="text" name="reason_contains" value="{_escape(filters['reason_contains'] or '')}" placeholder="authorized" />
        </label>
        <label>Created After (epoch)
          <input type="text" name="created_after" value="{_escape(filters['created_after'] if filters['created_after'] is not None else '')}" />
        </label>
        <label>Created Before (epoch)
          <input type="text" name="created_before" value="{_escape(filters['created_before'] if filters['created_before'] is not None else '')}" />
        </label>
        <div class="filter-actions">
          <button type="submit">Apply</button>
          <a href="/dashboard">Reset</a>
          <button type="button" id="copyLink">Copy Deep Link</button>
        </div>
      </form>
      <div class="hint">Tip: use filtered URL as a bookmark for auditors and incident reviews.</div>
    </section>
    """


def _render_dashboard(
    scope,
    active_rows: List[Dict[str, Any]],
    pending_rows: List[Dict[str, Any]],
    revoked_rows: List[Dict[str, Any]],
    denied_rows: List[Dict[str, Any]],
    filters: Dict[str, Any],
) -> str:
    export_filters = dict(filters)
    if not any(
        [
            export_filters.get("status"),
            export_filters.get("account_id"),
            export_filters.get("permission_set_name"),
            export_filters.get("requester_slack_user_id"),
        ]
    ):
        export_filters["status"] = STATE_ACTIVE
    export_link = _escape(_with_query("/api/exports.csv", export_filters))

    active_count = len(active_rows)
    pending_count = len(pending_rows)
    revoked_count = len(revoked_rows)
    denied_count = len(denied_rows)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Boundary Audit Dashboard</title>
  <style>
    :root {{
      --bg: #f5f7fb;
      --ink: #0f172a;
      --muted: #64748b;
      --card: #ffffff;
      --line: #dbe3ef;
      --teal: #0f766e;
      --orange: #b45309;
      --red: #b91c1c;
      --blue: #1d4ed8;
      --violet: #6d28d9;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at 10% 20%, rgba(29,78,216,.08), transparent 35%),
        radial-gradient(circle at 90% 10%, rgba(15,118,110,.08), transparent 35%),
        var(--bg);
    }}
    .wrap {{ max-width: 1260px; margin: 0 auto; padding: 20px; }}
    .hero {{
      display: flex; justify-content: space-between; align-items: center; gap: 16px;
      padding: 18px 20px; border: 1px solid var(--line); border-radius: 16px; background: var(--card);
      box-shadow: 0 10px 30px rgba(2,6,23,.06);
    }}
    .hero h1 {{ margin: 0; font-size: 1.5rem; }}
    .hero .sub {{ color: var(--muted); margin-top: 4px; font-size: .92rem; }}
    .hero .actions a {{
      text-decoration: none; color: #fff; background: var(--blue); padding: 10px 14px;
      border-radius: 10px; font-weight: 700; font-size: .88rem;
    }}
    .kpi-grid {{
      margin-top: 14px; display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 12px;
    }}
    .kpi {{
      background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 14px;
    }}
    .kpi .label {{ font-size: .82rem; color: var(--muted); text-transform: uppercase; letter-spacing: .7px; }}
    .kpi .value {{ margin-top: 4px; font-size: 1.7rem; font-weight: 800; }}
    .card {{
      margin-top: 14px; background: var(--card); border: 1px solid var(--line); border-radius: 14px;
      padding: 14px; box-shadow: 0 8px 24px rgba(2,6,23,.04);
    }}
    .card h2 {{ margin: 0 0 10px; font-size: 1.05rem; }}
    .filters {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; align-items: end; }}
    .filters label {{ display: flex; flex-direction: column; gap: 4px; font-size: .82rem; color: var(--muted); }}
    .filters input, .filters select {{
      height: 36px; border: 1px solid var(--line); border-radius: 10px; padding: 6px 10px; color: var(--ink);
      background: #fff; font-size: .9rem;
    }}
    .filter-actions {{ display: flex; gap: 8px; align-items: center; }}
    .filter-actions button, .filter-actions a {{
      border: 1px solid var(--line); background: #fff; border-radius: 10px; height: 36px; padding: 0 12px;
      display: inline-flex; align-items: center; text-decoration: none; color: var(--ink); font-size: .85rem; font-weight: 700;
      cursor: pointer;
    }}
    .filter-actions button[type="submit"] {{ background: var(--blue); border-color: var(--blue); color: #fff; }}
    .hint {{ margin-top: 10px; color: var(--muted); font-size: .82rem; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid var(--line); text-align: left; padding: 9px 8px; font-size: .86rem; vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 700; text-transform: uppercase; font-size: .75rem; letter-spacing: .7px; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    .status {{
      display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 999px;
      font-size: .74rem; font-weight: 700;
    }}
    .status-active {{ background: rgba(15,118,110,.13); color: var(--teal); }}
    .status-pending {{ background: rgba(180,83,9,.13); color: var(--orange); }}
    .status-revoked {{ background: rgba(109,40,217,.13); color: var(--violet); }}
    .status-denied {{ background: rgba(185,28,28,.13); color: var(--red); }}
    .status-other {{ background: rgba(100,116,139,.13); color: var(--muted); }}
    .pill {{
      display: inline-block; border-radius: 999px; padding: 2px 8px; font-size: .72rem; font-weight: 700;
    }}
    .pill-ok {{ color: #0f766e; background: rgba(15,118,110,.12); }}
    .pill-warn {{ color: #b45309; background: rgba(180,83,9,.12); }}
    .pill-danger {{ color: #b91c1c; background: rgba(185,28,28,.12); }}
    .pill-muted {{ color: var(--muted); background: rgba(100,116,139,.12); }}
    .reason {{ max-width: 260px; }}
    .empty {{ color: var(--muted); }}
    .bar-row {{ display: grid; grid-template-columns: 280px 1fr 46px; gap: 10px; align-items: center; margin: 8px 0; }}
    .bar-label {{ color: var(--ink); font-size: .86rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
    .bar-track {{ background: #eef2f7; border-radius: 8px; height: 12px; overflow: hidden; }}
    .bar-fill {{ background: linear-gradient(90deg, var(--red), #ef4444); height: 100%; }}
    .bar-count {{ font-size: .82rem; font-weight: 700; color: var(--muted); text-align: right; }}
    .foot {{ margin-top: 16px; color: var(--muted); font-size: .8rem; }}
    @media (max-width: 980px) {{
      .kpi-grid {{ grid-template-columns: repeat(2, minmax(0,1fr)); }}
      .hero {{ flex-direction: column; align-items: flex-start; }}
      .filters {{ grid-template-columns: 1fr; }}
      .bar-row {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div>
        <h1>Boundary Audit Dashboard</h1>
        <div class="sub">Read-only evidence view for active access, approvals, revocations, and denials.</div>
      </div>
      <div class="actions">
        <a href="{export_link}">Export CSV</a>
      </div>
    </section>

    {_render_filter_bar(filters)}

    <section class="kpi-grid">
      <div class="kpi"><div class="label">Active Access</div><div class="value">{active_count}</div></div>
      <div class="kpi"><div class="label">Pending Approval</div><div class="value">{pending_count}</div></div>
      <div class="kpi"><div class="label">Recent Revocations</div><div class="value">{revoked_count}</div></div>
      <div class="kpi"><div class="label">Denied Requests</div><div class="value">{denied_count}</div></div>
    </section>

    <section class="card">
      <h2>Pending Approvals (SLA Focus)</h2>
      <table>
        <thead><tr><th>Request</th><th>Status</th><th>Account</th><th>Role</th><th>Requester</th><th>Reason</th><th>Created</th><th>Policy Hash</th><th>Age</th></tr></thead>
        <tbody>{_render_rows(pending_rows, filters, include_age=True)}</tbody>
      </table>
    </section>

    <section class="card">
      <h2>Active Access</h2>
      <table>
        <thead><tr><th>Request</th><th>Status</th><th>Account</th><th>Role</th><th>Requester</th><th>Reason</th><th>Created</th><th>Policy Hash</th></tr></thead>
        <tbody>{_render_rows(active_rows, filters)}</tbody>
      </table>
    </section>

    <section class="card">
      <h2>Recent Revocations</h2>
      <table>
        <thead><tr><th>Request</th><th>Status</th><th>Account</th><th>Role</th><th>Requester</th><th>Reason</th><th>Created</th><th>Policy Hash</th></tr></thead>
        <tbody>{_render_rows(revoked_rows, filters)}</tbody>
      </table>
    </section>

    <section class="card">
      <h2>Denials by Reason</h2>
      {_render_denials_chart(denied_rows)}
    </section>

    <div class="foot">
      Signed-in principal: <span class="mono">{_escape(scope.principal_arn)}</span>
    </div>
  </div>

  <script>
    (function() {{
      var copyBtn = document.getElementById("copyLink");
      if (!copyBtn || !navigator.clipboard) return;
      copyBtn.addEventListener("click", function() {{
        navigator.clipboard.writeText(window.location.href);
      }});
    }})();
  </script>
</body>
</html>
"""


def _timeline_events(item: Dict[str, Any]) -> List[Tuple[float, str, str]]:
    events: List[Tuple[float, str, str]] = []

    def add_event(ts: Any, title: str, detail: str) -> None:
        if ts is None:
            return
        try:
            num = float(ts)
        except (TypeError, ValueError):
            return
        events.append((num, title, detail))

    add_event(item.get("created_at") or item.get("requested_at"), "Requested", "Request created")
    add_event(item.get("approved_at"), "Approved", f"Approved by {item.get('approved_by') or item.get('approver_slack_user_id') or 'unknown'}")
    add_event(item.get("denied_at"), "Denied", f"Denied by {item.get('denied_by') or 'unknown'}")
    add_event(item.get("expires_at"), "Expires", "Configured access expiry")
    add_event(item.get("revoked_at"), "Revoked", "Access revoked by janitor/workflow")
    add_event(item.get("updated_at"), "Last Update", "Last persisted update")

    events.sort(key=lambda entry: entry[0])
    return events


def _render_timeline(item: Dict[str, Any]) -> str:
    events = _timeline_events(item)
    if not events:
        return '<div class="empty">No timeline events available.</div>'
    parts: List[str] = []
    for ts, title, detail in events:
        parts.append(
            f"""
            <div class="line-item">
              <div class="line-time mono">{_escape(ts)}</div>
              <div class="line-dot"></div>
              <div class="line-body">
                <div class="line-title">{_escape(title)}</div>
                <div class="line-detail">{_escape(detail)}</div>
              </div>
            </div>
            """
        )
    return "".join(parts)


def _render_request_detail(scope, item: Dict[str, Any], filters: Dict[str, Any]) -> str:
    request_id = _escape(item.get("request_id"))
    status = _escape(item.get("status"))
    requester = _escape(item.get("requester_slack_user_id") or item.get("slack_user_id") or "-")
    approver = _escape(item.get("approver_slack_user_id") or item.get("approved_by") or item.get("denied_by") or "-")
    account = _escape(item.get("account_id"))
    role = _escape(item.get("permission_set_name"))
    reason = _escape(item.get("reason", "-"))
    policy_hash = _escape(item.get("policy_hash", "-"))
    engine_version = _escape(item.get("engine_version", "-"))
    created = _escape(item.get("created_at") or item.get("requested_at") or "-")
    updated = _escape(item.get("updated_at") or "-")
    expires = _escape(item.get("expires_at") or "-")
    revoked = _escape(item.get("revoked_at") or "-")
    ticket = _escape(item.get("ticket_id") or "-")
    back_href = _escape(_with_query("/dashboard", filters))
    raw_json = html.escape(json.dumps(item, indent=2, default=str))

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Request {request_id}</title>
  <style>
    body {{ margin: 0; background: #f8fafc; color: #0f172a; font-family: "IBM Plex Sans", "Segoe UI", sans-serif; }}
    .wrap {{ max-width: 1040px; margin: 24px auto; padding: 0 16px; }}
    .card {{ background: #fff; border: 1px solid #dbe3ef; border-radius: 14px; padding: 18px; }}
    h1 {{ margin: 0 0 12px; font-size: 1.3rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 12px; }}
    .item {{ border: 1px solid #e6ebf3; border-radius: 12px; padding: 10px; }}
    .label {{ color: #64748b; font-size: .78rem; text-transform: uppercase; letter-spacing: .6px; }}
    .value {{ margin-top: 4px; font-size: .93rem; word-break: break-word; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    .back {{ display: inline-block; margin-bottom: 12px; text-decoration: none; color: #1d4ed8; font-weight: 700; }}
    .timeline {{ margin-top: 14px; border: 1px solid #e6ebf3; border-radius: 12px; padding: 12px; }}
    .line-item {{ display: grid; grid-template-columns: 170px 16px 1fr; gap: 8px; align-items: start; margin: 8px 0; }}
    .line-time {{ color: #64748b; font-size: .84rem; }}
    .line-dot {{ width: 10px; height: 10px; border-radius: 999px; background: #1d4ed8; margin-top: 4px; }}
    .line-title {{ font-weight: 700; font-size: .9rem; }}
    .line-detail {{ color: #64748b; font-size: .84rem; margin-top: 2px; }}
    pre {{ margin: 0; background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 10px; overflow: auto; font-size: .8rem; }}
    @media (max-width: 760px) {{ .grid {{ grid-template-columns: 1fr; }} .line-item {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <div class="wrap">
    <a class="back" href="{back_href}">&larr; Back to dashboard</a>
    <div class="card">
      <h1>Request {request_id}</h1>
      <div class="grid">
        <div class="item"><div class="label">Status</div><div class="value">{status}</div></div>
        <div class="item"><div class="label">Account</div><div class="value mono">{account}</div></div>
        <div class="item"><div class="label">Role</div><div class="value">{role}</div></div>
        <div class="item"><div class="label">Requester</div><div class="value mono">{requester}</div></div>
        <div class="item"><div class="label">Approver</div><div class="value mono">{approver}</div></div>
        <div class="item"><div class="label">Ticket</div><div class="value mono">{ticket}</div></div>
        <div class="item"><div class="label">Reason</div><div class="value">{reason}</div></div>
        <div class="item"><div class="label">Policy Hash</div><div class="value mono">{policy_hash}</div></div>
        <div class="item"><div class="label">Engine Version</div><div class="value">{engine_version}</div></div>
        <div class="item"><div class="label">Created</div><div class="value mono">{created}</div></div>
        <div class="item"><div class="label">Updated</div><div class="value mono">{updated}</div></div>
        <div class="item"><div class="label">Expires</div><div class="value mono">{expires}</div></div>
        <div class="item"><div class="label">Revoked At</div><div class="value mono">{revoked}</div></div>
      </div>

      <div class="timeline">
        <div class="label">Timeline</div>
        {_render_timeline(item)}
      </div>

      <div style="margin-top:14px;">
        <div class="label">Raw Evidence</div>
        <pre>{raw_json}</pre>
      </div>

      <p style="margin-top:14px;color:#64748b;font-size:.83rem;">
        Signed-in principal: <span class="mono">{_escape(scope.principal_arn)}</span>
      </p>
    </div>
  </div>
</body>
</html>
"""


def lambda_handler(event, context):  # pragma: no cover - entrypoint
    del context
    if _http_method(event) != "GET":
        return _html_response(405, "<h1>Method Not Allowed</h1>")

    table_name = os.environ.get("DYNAMODB_TABLE")
    if not table_name:
        return _html_response(500, "<h1>DYNAMODB_TABLE is not configured</h1>")

    try:
        scope = _build_scope(event)
        _require_any_role(scope, ALLOWED_DASHBOARD_ROLES)
        store = StateStore(table_name=table_name)
        path = _request_path(event)
        query = _request_query(event)
        filters = _parse_dashboard_filters(query)

        try:
            section_limit = int(os.environ.get("AUDIT_DASHBOARD_SECTION_LIMIT", "80"))
        except ValueError:
            section_limit = 80
        section_limit = min(max(section_limit, 10), 200)

        if path == "/dashboard":
            pending_rows = _query_status_items(store, scope, STATE_PENDING_APPROVAL, filters, limit=section_limit)
            active_rows = _query_status_items(store, scope, STATE_ACTIVE, filters, limit=section_limit)
            revoked_rows = _query_status_items(store, scope, STATE_REVOKED, filters, limit=section_limit)
            denied_rows = _query_status_items(store, scope, STATE_DENIED, filters, limit=section_limit)
            return _html_response(
                200,
                _render_dashboard(scope, active_rows, pending_rows, revoked_rows, denied_rows, filters),
            )

        if path.startswith("/dashboard/requests/"):
            request_id = path.rsplit("/", 1)[-1].strip()
            item = store.get_request(request_id)
            if not item:
                return _html_response(404, "<h1>Request not found</h1>")
            normalized = _normalize_json(item)
            if not _item_in_scope(normalized, scope):
                return _html_response(404, "<h1>Request not found</h1>")
            return _html_response(200, _render_request_detail(scope, normalized, filters))

        return _html_response(404, "<h1>Not found</h1>")
    except ValueError as exc:
        return _html_response(400, f"<h1>Bad request</h1><p>{_escape(str(exc))}</p>")
    except PermissionError as exc:
        return _html_response(403, f"<h1>Forbidden</h1><p>{_escape(str(exc))}</p>")
    except Exception as exc:  # pragma: no cover
        return _html_response(500, f"<h1>Internal error</h1><p>{_escape(str(exc))}</p>")
