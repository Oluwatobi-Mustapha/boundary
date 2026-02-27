import html
import json
import os
import time
from datetime import datetime, timezone
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


def _short_hash(value: Any, prefix: int = 12, suffix: int = 8) -> str:
    text = "" if value is None else str(value)
    if not text:
        return "-"
    if len(text) <= prefix + suffix + 1:
        return text
    return f"{text[:prefix]}...{text[-suffix:]}"


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


def _format_epoch_utc(value: Any) -> str:
    """
    Render epoch seconds as ISO-8601 UTC for human-readable audit timelines.
    Falls back to string form when value is not numeric.
    """
    if value is None or value == "":
        return "-"
    try:
        return (
            datetime.fromtimestamp(float(value), tz=timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except (TypeError, ValueError, OverflowError):
        return str(value)


def _parse_dashboard_filters(query: Dict[str, str]) -> Dict[str, Any]:
    status_raw = (query.get("status") or "").strip()
    status: Optional[str] = None
    if status_raw:
        status = canonicalize_status(status_raw)
        if not is_valid_status(status):
            raise ValueError("status is invalid")

    account_id = (query.get("account_id") or "").strip() or None
    permission_set_name = (query.get("permission_set_name") or "").strip() or None
    request_id = (query.get("request_id") or "").strip() or None
    if request_id and len(request_id) > 128:
        raise ValueError("request_id is too long")
    reason_contains = (query.get("reason_contains") or "").strip() or None
    created_after = _parse_float("created_after", query.get("created_after"))
    created_before = _parse_float("created_before", query.get("created_before"))
    if created_after is not None and created_before is not None and created_after > created_before:
        raise ValueError("created_after cannot be greater than created_before")

    return {
        "status": status,
        "request_id": request_id,
        "account_id": account_id,
        "permission_set_name": permission_set_name,
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
    if filters["request_id"] and str(item.get("request_id", "")) != filters["request_id"]:
        return False
    if filters["account_id"] and str(item.get("account_id", "")) != filters["account_id"]:
        return False
    if filters["permission_set_name"] and str(item.get("permission_set_name", "")) != filters["permission_set_name"]:
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
        "request_id",
        "account_id",
        "permission_set_name",
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
        reason_full = _escape(item.get("reason", "-"))
        created_at = _escape(_format_epoch_utc(item.get("created_at") or item.get("requested_at")))
        policy_hash_full = _escape(item.get("policy_hash", "-"))
        policy_hash_short = _escape(_short_hash(item.get("policy_hash", "-")))
        detail_link = _escape(_with_query(f"/dashboard/requests/{request_id_raw}", filters))
        age_cell = f"<td>{_age_badge(item)}</td>" if include_age else ""
        output.append(
            f"""
            <tr>
              <td>
                <div class="copy-cell">
                  <a href="{detail_link}" title="{request_id}">{request_id}</a>
                  <button type="button" class="copy-btn" data-copy="{request_id}" aria-label="Copy request ID">Copy</button>
                </div>
              </td>
              <td><span class="status { _status_class(status) }">{status}</span></td>
              <td>{account_id}</td>
              <td>{role}</td>
              <td>{requester}</td>
              <td class="reason"><span class="reason-text" title="{reason_full}">{reason_full}</span></td>
              <td class="mono">{created_at}</td>
              <td class="mono policy-hash" title="{policy_hash_full}">
                <div class="copy-cell">
                  <span class="policy-hash-text">{policy_hash_short}</span>
                  <button type="button" class="copy-btn" data-copy="{policy_hash_full}" aria-label="Copy policy hash">Copy</button>
                </div>
              </td>
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
        <label>Request ID
          <input type="text" id="requestIdInput" name="request_id" value="{_escape(filters['request_id'] or '')}" placeholder="req-..." />
        </label>
        <label>Reason Contains
          <input type="text" name="reason_contains" value="{_escape(filters['reason_contains'] or '')}" placeholder="authorized" />
        </label>
        <label>Created After
          <input type="text" name="created_after" value="{_escape(filters['created_after'] if filters['created_after'] is not None else '')}" />
        </label>
        <label>Created Before
          <input type="text" name="created_before" value="{_escape(filters['created_before'] if filters['created_before'] is not None else '')}" />
        </label>
        <div class="filter-actions">
          <button type="submit">Apply</button>
          <a href="/dashboard">Reset</a>
          <button type="button" id="copyLink">Copy Deep Link</button>
        </div>
      </form>
      <div class="hint">Pro Tip: filter by Request ID for a direct evidence lookup, then bookmark the URL.</div>
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
        ]
    ):
        export_filters["status"] = STATE_ACTIVE
    export_link = _escape(_with_query("/api/exports.csv", export_filters))

    active_count = len(active_rows)
    pending_count = len(pending_rows)
    revoked_count = len(revoked_rows)
    denied_count = len(denied_rows)
    request_focus = bool(filters.get("request_id"))
    no_focus_match = request_focus and not any([pending_rows, active_rows, revoked_rows, denied_rows])

    pending_section = (
        f"""
        <section class="card">
          <h2>Pending Approvals (SLA Focus) ({pending_count})</h2>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Request</th><th>Status</th><th>Account</th><th>Role</th><th>Requester</th><th>Reason</th><th>Created</th><th class="policy-hash-col">Policy Hash</th><th>Age</th></tr></thead>
              <tbody>{_render_rows(pending_rows, filters, include_age=True)}</tbody>
            </table>
          </div>
        </section>
        """
        if (pending_rows or not request_focus)
        else ""
    )
    active_section = (
        f"""
        <section class="card">
          <h2>Active Access ({active_count})</h2>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Request</th><th>Status</th><th>Account</th><th>Role</th><th>Requester</th><th>Reason</th><th>Created</th><th class="policy-hash-col">Policy Hash</th></tr></thead>
              <tbody>{_render_rows(active_rows, filters)}</tbody>
            </table>
          </div>
        </section>
        """
        if (active_rows or not request_focus)
        else ""
    )
    revoked_section = (
        f"""
        <section class="card">
          <h2>Recent Revocations ({revoked_count})</h2>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Request</th><th>Status</th><th>Account</th><th>Role</th><th>Requester</th><th>Reason</th><th>Created</th><th class="policy-hash-col">Policy Hash</th></tr></thead>
              <tbody>{_render_rows(revoked_rows, filters)}</tbody>
            </table>
          </div>
        </section>
        """
        if (revoked_rows or not request_focus)
        else ""
    )
    denials_section = (
        f"""
        <section class="card">
          <h2>Denials by Reason ({denied_count})</h2>
          {_render_denials_chart(denied_rows)}
        </section>
        """
        if (denied_rows or not request_focus)
        else ""
    )
    no_match_section = (
        f"""
        <section class="card">
          <h2>No Matching Request</h2>
          <div class="empty">No in-scope records found for Request ID: <span class="mono">{_escape(filters.get("request_id"))}</span></div>
          <div class="no-match-actions"><a class="inline-link" href="/dashboard">Clear filters</a></div>
        </section>
        """
        if no_focus_match
        else ""
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Boundary Audit Dashboard</title>
  <script>
    (function() {{
      try {{
        var key = "boundary_dashboard_theme";
        var theme = localStorage.getItem(key);
        if (theme !== "light" && theme !== "dark") {{
          theme = (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) ? "dark" : "dark";
        }}
        document.documentElement.setAttribute("data-theme", theme);
      }} catch (_err) {{
        document.documentElement.setAttribute("data-theme", "dark");
      }}
    }})();
  </script>
  <style>
    :root {{
      --bg: #f3f5f9;
      --bg-elev: #ffffff;
      --bg-soft: #f8fafc;
      --ink: #12161d;
      --muted: #5b6676;
      --line: #d8dfe8;
      --accent: #d81e2e;
      --accent-strong: #b5121f;
      --accent-soft: rgba(216, 30, 46, .14);
      --success: #008c53;
      --warning: #cb8408;
      --danger: #d81e2e;
      --info: #2b66c3;
      --ring: 0 0 0 3px rgba(216, 30, 46, .22);
      --shadow: 0 14px 34px rgba(19, 26, 37, 0.09);
    }}
    html[data-theme="dark"] {{
      --bg: #070b11;
      --bg-elev: #0d1622;
      --bg-soft: #101b29;
      --ink: #e8edf5;
      --muted: #96a5ba;
      --line: #25374c;
      --accent: #ff4b57;
      --accent-strong: #e93343;
      --accent-soft: rgba(255, 75, 87, .18);
      --success: #4be08f;
      --warning: #ffbe5a;
      --danger: #ff7581;
      --info: #7aabff;
      --ring: 0 0 0 3px rgba(255, 75, 87, .24);
      --shadow: 0 20px 48px rgba(0, 0, 0, 0.42);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Avenir Next", "IBM Plex Sans", "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        linear-gradient(130deg, rgba(216, 30, 46, .12), transparent 26%),
        radial-gradient(circle at 86% -8%, rgba(35, 100, 200, .12), transparent 34%),
        var(--bg);
      transition: background .25s ease, color .25s ease;
    }}
    .wrap {{ max-width: 1320px; margin: 0 auto; padding: 24px; }}
    .hero {{
      position: relative;
      overflow: hidden;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 18px;
      padding: 20px 22px;
      border: 1px solid var(--line);
      border-radius: 16px;
      background: linear-gradient(180deg, var(--bg-elev), var(--bg-soft));
      box-shadow: var(--shadow);
      animation: fadeSlide .3s ease;
    }}
    .hero::after {{
      content: "";
      position: absolute;
      left: 0;
      bottom: 0;
      width: 48%;
      height: 2px;
      background: linear-gradient(90deg, var(--accent), transparent 80%);
    }}
    .hero h1 {{ margin: 0; font-size: 1.62rem; letter-spacing: .2px; }}
    .hero .sub {{ color: var(--muted); margin-top: 5px; font-size: .93rem; }}
    .hero .meta {{
      margin-top: 8px;
      display: flex;
      gap: 14px;
      flex-wrap: wrap;
      align-items: center;
      font-size: .79rem;
      color: var(--muted);
    }}
    .hero .auto-refresh {{
      display: inline-flex;
      gap: 6px;
      align-items: center;
      cursor: pointer;
      user-select: none;
    }}
    .hero .auto-refresh input {{
      accent-color: var(--accent);
      width: 14px;
      height: 14px;
      margin: 0;
    }}
    .hero .actions {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }}
    .hero .actions a, .hero .actions button {{
      text-decoration: none;
      color: #fff;
      background: linear-gradient(135deg, var(--accent), var(--accent-strong));
      padding: 9px 14px;
      border-radius: 10px;
      font-weight: 700;
      font-size: .84rem;
      border: 1px solid transparent;
      cursor: pointer;
      transition: transform .18s ease, box-shadow .18s ease, filter .18s ease;
      box-shadow: 0 8px 20px rgba(216, 30, 46, .3);
    }}
    .hero .actions a:hover, .hero .actions button:hover {{
      transform: translateY(-1px);
      filter: brightness(1.06);
      box-shadow: 0 11px 24px rgba(216, 30, 46, .34);
    }}
    .hero .actions .ghost {{
      background: transparent;
      color: var(--ink);
      border-color: var(--line);
      box-shadow: none;
    }}
    .hero .actions .ghost:hover {{
      background: var(--accent-soft);
      color: var(--ink);
      box-shadow: none;
    }}
    .kpi-grid {{
      margin-top: 14px;
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
    }}
    .kpi {{
      background: linear-gradient(180deg, var(--bg-elev), var(--bg-soft));
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 14px;
      box-shadow: var(--shadow);
    }}
    .kpi .label {{
      font-size: .78rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: .8px;
      font-weight: 700;
    }}
    .kpi .value {{ margin-top: 6px; font-size: 1.9rem; font-weight: 800; line-height: 1; }}
    .card {{
      margin-top: 14px;
      background: linear-gradient(180deg, var(--bg-elev), var(--bg-soft));
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 14px;
      box-shadow: var(--shadow);
      animation: fadeSlide .3s ease;
    }}
    .card h2 {{ margin: 0 0 10px; font-size: 1.1rem; letter-spacing: .2px; }}
    .filters {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
      align-items: end;
    }}
    .filters label {{
      display: flex;
      flex-direction: column;
      gap: 4px;
      font-size: .8rem;
      color: var(--muted);
      font-weight: 600;
      letter-spacing: .2px;
    }}
    .filters input, .filters select {{
      height: 38px;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 6px 10px;
      color: var(--ink);
      background: var(--bg-elev);
      font-size: .9rem;
      outline: none;
      transition: border-color .16s ease, box-shadow .16s ease;
    }}
    .filters input:focus, .filters select:focus {{
      border-color: var(--accent);
      box-shadow: var(--ring);
    }}
    .filter-actions {{ display: flex; gap: 8px; align-items: center; }}
    .filter-actions button, .filter-actions a {{
      border: 1px solid var(--line);
      background: var(--bg-elev);
      border-radius: 10px;
      height: 36px;
      padding: 0 12px;
      display: inline-flex;
      align-items: center;
      text-decoration: none;
      color: var(--ink);
      font-size: .84rem;
      font-weight: 700;
      cursor: pointer;
      transition: border-color .16s ease, background .16s ease;
    }}
    .filter-actions button:hover, .filter-actions a:hover {{ border-color: var(--accent); }}
    .filter-actions button[type="submit"] {{
      background: linear-gradient(135deg, var(--accent), var(--accent-strong));
      border-color: transparent;
      color: #fff;
      box-shadow: 0 8px 20px rgba(216, 30, 46, .3);
    }}
    .filter-actions button[type="submit"]:hover {{ filter: brightness(1.06); }}
    .hint {{ margin-top: 10px; color: var(--muted); font-size: .82rem; }}
    .table-wrap {{
      border: 1px solid var(--line);
      border-radius: 12px;
      overflow: auto;
      max-height: 460px;
      background: var(--bg-elev);
    }}
    table {{
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      table-layout: fixed;
      min-width: 980px;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      text-align: left;
      padding: 10px 8px;
      font-size: .86rem;
      vertical-align: top;
      word-break: break-word;
    }}
    th {{
      color: var(--muted);
      font-weight: 700;
      text-transform: uppercase;
      font-size: .74rem;
      letter-spacing: .75px;
      position: sticky;
      top: 0;
      z-index: 3;
      background: linear-gradient(180deg, var(--bg-soft), var(--bg-elev));
    }}
    td {{ color: var(--ink); }}
    tbody tr:hover {{ background: var(--accent-soft); }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    a {{ color: var(--accent); }}
    a:hover {{ color: var(--accent-strong); }}
    .copy-cell {{
      display: flex;
      align-items: center;
      gap: 6px;
      min-width: 0;
      width: 100%;
    }}
    .copy-cell a {{
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .copy-btn {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--bg-elev);
      color: var(--muted);
      font-size: .7rem;
      font-weight: 700;
      letter-spacing: .2px;
      height: 24px;
      padding: 0 8px;
      cursor: pointer;
      flex: 0 0 auto;
    }}
    .copy-btn:hover {{
      border-color: var(--accent);
      color: var(--accent);
      background: var(--accent-soft);
    }}
    .copy-btn:focus-visible {{
      outline: none;
      box-shadow: var(--ring);
      border-color: var(--accent);
    }}
    .status {{
      display: inline-flex;
      align-items: center;
      padding: 2px 9px;
      border-radius: 999px;
      font-size: .73rem;
      font-weight: 800;
      letter-spacing: .2px;
    }}
    .status-active {{ background: rgba(0, 140, 83, .18); color: var(--success); }}
    .status-pending {{ background: rgba(203, 132, 8, .20); color: var(--warning); }}
    .status-revoked {{ background: rgba(43, 102, 195, .19); color: var(--info); }}
    .status-denied {{ background: rgba(216, 30, 46, .18); color: var(--danger); }}
    .status-other {{ background: rgba(91, 102, 118, .16); color: var(--muted); }}
    .pill {{
      display: inline-block;
      border-radius: 999px;
      padding: 2px 8px;
      font-size: .72rem;
      font-weight: 700;
    }}
    .pill-ok {{ color: var(--success); background: rgba(0, 140, 83, .18); }}
    .pill-warn {{ color: var(--warning); background: rgba(203, 132, 8, .18); }}
    .pill-danger {{ color: var(--danger); background: rgba(216, 30, 46, .18); }}
    .pill-muted {{ color: var(--muted); background: rgba(91, 102, 118, .16); }}
    .reason {{ max-width: 280px; }}
    .reason-text {{
      display: -webkit-box;
      -webkit-box-orient: vertical;
      -webkit-line-clamp: 2;
      line-clamp: 2;
      overflow: hidden;
      text-overflow: ellipsis;
    }}
    .policy-hash-col {{ width: 170px; }}
    .policy-hash .copy-cell {{
      max-width: 170px;
    }}
    .policy-hash-text {{
      min-width: 0;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      display: inline-block;
    }}
    .empty {{ color: var(--muted); }}
    .no-match-actions {{
      margin-top: 10px;
    }}
    .inline-link {{
      display: inline-flex;
      align-items: center;
      border: 1px solid var(--line);
      border-radius: 9px;
      padding: 6px 10px;
      text-decoration: none;
      background: var(--bg-elev);
      color: var(--ink);
      font-size: .82rem;
      font-weight: 700;
    }}
    .inline-link:hover {{
      border-color: var(--accent);
      color: var(--accent);
      background: var(--accent-soft);
    }}
    .bar-row {{
      display: grid;
      grid-template-columns: 280px 1fr 46px;
      gap: 10px;
      align-items: center;
      margin: 8px 0;
    }}
    .bar-label {{
      color: var(--ink);
      font-size: .86rem;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}
    .bar-track {{ background: rgba(91, 102, 118, .22); border-radius: 8px; height: 12px; overflow: hidden; }}
    .bar-fill {{ background: linear-gradient(90deg, var(--accent), var(--accent-strong)); height: 100%; }}
    .bar-count {{ font-size: .82rem; font-weight: 700; color: var(--muted); text-align: right; }}
    .foot {{ margin-top: 16px; color: var(--muted); font-size: .8rem; }}
    .floating-nav {{
      position: fixed;
      right: 16px;
      bottom: 16px;
      display: flex;
      flex-direction: column;
      gap: 8px;
      z-index: 20;
    }}
    .floating-nav button {{
      width: 44px;
      height: 44px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: linear-gradient(180deg, var(--bg-elev), var(--bg-soft));
      color: var(--ink);
      box-shadow: var(--shadow);
      cursor: pointer;
      font-size: 1rem;
      transition: border-color .16s ease, transform .16s ease;
    }}
    .floating-nav button:hover {{
      border-color: var(--accent);
      transform: translateY(-1px);
    }}
    .toast {{
      position: fixed;
      left: 16px;
      bottom: 16px;
      background: linear-gradient(135deg, var(--accent), var(--accent-strong));
      color: #fff;
      border-radius: 10px;
      padding: 10px 12px;
      font-size: .82rem;
      font-weight: 700;
      letter-spacing: .2px;
      box-shadow: var(--shadow);
      opacity: 0;
      transform: translateY(8px);
      pointer-events: none;
      transition: opacity .16s ease, transform .16s ease;
      z-index: 40;
    }}
    .toast.show {{
      opacity: 1;
      transform: translateY(0);
    }}
    @keyframes fadeSlide {{
      from {{ opacity: 0; transform: translateY(8px); }}
      to {{ opacity: 1; transform: translateY(0); }}
    }}
    @media (max-width: 1080px) {{
      .kpi-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .hero {{ flex-direction: column; align-items: flex-start; }}
      .filters {{ grid-template-columns: 1fr; }}
      .bar-row {{ grid-template-columns: 1fr; }}
      th, td {{ font-size: .82rem; }}
      .policy-hash-col {{ width: 136px; }}
      .policy-hash .copy-cell {{ max-width: 136px; }}
      .table-wrap {{ max-height: 380px; }}
      .copy-btn {{ height: 22px; padding: 0 7px; }}
      .toast {{
        left: 12px;
        right: 12px;
        bottom: 12px;
        text-align: center;
      }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div>
        <h1>Boundary Audit Dashboard</h1>
        <div class="sub">Read-only evidence view for active access, approvals, revocations, and denials.</div>
        <div class="meta">
          <span>Last refreshed: <span class="mono" id="lastRefreshed">-</span></span>
          <label class="auto-refresh"><input type="checkbox" id="autoRefreshToggle" />Auto-refresh (15s)</label>
        </div>
      </div>
      <div class="actions">
        <a href="{export_link}">Export CSV</a>
        <button class="ghost" type="button" id="themeToggle">Dark Mode</button>
      </div>
    </section>

    {_render_filter_bar(filters)}

    <section class="kpi-grid">
      <div class="kpi"><div class="label">Active Access</div><div class="value">{active_count}</div></div>
      <div class="kpi"><div class="label">Pending Approval</div><div class="value">{pending_count}</div></div>
      <div class="kpi"><div class="label">Recent Revocations</div><div class="value">{revoked_count}</div></div>
      <div class="kpi"><div class="label">Denied Requests</div><div class="value">{denied_count}</div></div>
    </section>

    {pending_section}
    {active_section}
    {revoked_section}
    {denials_section}
    {no_match_section}

    <div class="floating-nav">
      <button type="button" id="scrollTopBtn" title="Scroll to top" aria-label="Scroll to top">↑</button>
      <button type="button" id="scrollBottomBtn" title="Scroll to bottom" aria-label="Scroll to bottom">↓</button>
    </div>
    <div id="copyToast" class="toast" role="status" aria-live="polite">Copied</div>

    <div class="foot">
      Signed-in principal: <span class="mono">{_escape(scope.principal_arn)}</span>
    </div>
  </div>

  <script>
    (function() {{
      function copyTextFallback(text) {{
        var area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "absolute";
        area.style.left = "-9999px";
        document.body.appendChild(area);
        area.select();
        document.execCommand("copy");
        document.body.removeChild(area);
        return true;
      }}

      function copyText(text) {{
        if (!text) {{
          return Promise.resolve(false);
        }}
        if (navigator.clipboard && navigator.clipboard.writeText) {{
          return navigator.clipboard
            .writeText(text)
            .then(function() {{ return true; }})
            .catch(function() {{ return copyTextFallback(text); }});
        }}
        return Promise.resolve(copyTextFallback(text));
      }}

      var toast = document.getElementById("copyToast");
      var toastTimer = null;
      function showToast(message) {{
        if (!toast) {{
          return;
        }}
        toast.textContent = message || "Copied";
        toast.classList.add("show");
        if (toastTimer) {{
          clearTimeout(toastTimer);
        }}
        toastTimer = setTimeout(function() {{
          toast.classList.remove("show");
        }}, 1300);
      }}

      var copyBtn = document.getElementById("copyLink");
      if (copyBtn) {{
        copyBtn.addEventListener("click", function() {{
          copyText(window.location.href).then(function(ok) {{
            showToast(ok ? "Deep link copied" : "Copy failed");
          }});
        }});
      }}

      document.addEventListener("click", function(event) {{
        var target = event.target;
        if (!target || !target.closest) {{
          return;
        }}
        var copyTarget = target.closest("[data-copy]");
        if (!copyTarget) {{
          return;
        }}
        event.preventDefault();
        var value = copyTarget.getAttribute("data-copy") || "";
        copyText(value).then(function(ok) {{
          showToast(ok ? "Copied" : "Copy failed");
        }});
      }});

      var themeToggle = document.getElementById("themeToggle");
      var topBtn = document.getElementById("scrollTopBtn");
      var bottomBtn = document.getElementById("scrollBottomBtn");
      var requestIdInput = document.getElementById("requestIdInput");
      var refreshedLabel = document.getElementById("lastRefreshed");
      var autoRefreshToggle = document.getElementById("autoRefreshToggle");
      var root = document.documentElement;
      var THEME_KEY = "boundary_dashboard_theme";
      var AUTO_REFRESH_KEY = "boundary_dashboard_auto_refresh";
      var autoRefreshTimer = null;

      function formatUtcNow() {{
        var now = new Date();
        return now.toISOString().replace(/\\.\\d{{3}}Z$/, "Z");
      }}

      function updateRefreshedLabel() {{
        if (refreshedLabel) {{
          refreshedLabel.textContent = formatUtcNow();
        }}
      }}

      function scheduleAutoRefresh() {{
        if (autoRefreshTimer) {{
          clearTimeout(autoRefreshTimer);
          autoRefreshTimer = null;
        }}
        if (!autoRefreshToggle || !autoRefreshToggle.checked) {{
          return;
        }}
        autoRefreshTimer = setTimeout(function() {{
          window.location.reload();
        }}, 15000);
      }}

      function applyTheme(theme) {{
        root.setAttribute("data-theme", theme);
        if (themeToggle) {{
          themeToggle.textContent = theme === "dark" ? "Light Mode" : "Dark Mode";
        }}
      }}

      var stored = localStorage.getItem(THEME_KEY);
      if (stored === "light" || stored === "dark") {{
        applyTheme(stored);
      }} else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {{
        applyTheme("dark");
      }} else {{
        applyTheme("dark");
      }}

      if (themeToggle) {{
        themeToggle.addEventListener("click", function() {{
          var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
          applyTheme(next);
          localStorage.setItem(THEME_KEY, next);
        }});
      }}

      updateRefreshedLabel();
      if (autoRefreshToggle) {{
        autoRefreshToggle.checked = localStorage.getItem(AUTO_REFRESH_KEY) === "1";
        autoRefreshToggle.addEventListener("change", function() {{
          localStorage.setItem(AUTO_REFRESH_KEY, autoRefreshToggle.checked ? "1" : "0");
          scheduleAutoRefresh();
          showToast(autoRefreshToggle.checked ? "Auto-refresh enabled (15s)" : "Auto-refresh disabled");
        }});
        scheduleAutoRefresh();
      }}

      document.addEventListener("keydown", function(event) {{
        if (event.key !== "/") {{
          return;
        }}
        if (event.metaKey || event.ctrlKey || event.altKey) {{
          return;
        }}
        var target = event.target;
        if (target) {{
          var tag = (target.tagName || "").toLowerCase();
          if (tag === "input" || tag === "textarea" || target.isContentEditable) {{
            return;
          }}
        }}
        if (!requestIdInput) {{
          return;
        }}
        event.preventDefault();
        requestIdInput.focus();
        requestIdInput.select();
      }});

      if (topBtn) {{
        topBtn.addEventListener("click", function() {{
          window.scrollTo({{ top: 0, behavior: "smooth" }});
        }});
      }}
      if (bottomBtn) {{
        bottomBtn.addEventListener("click", function() {{
          window.scrollTo({{ top: document.body.scrollHeight, behavior: "smooth" }});
        }});
      }}
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
              <div class="line-time mono">{_escape(_format_epoch_utc(ts))}</div>
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
    created = _escape(_format_epoch_utc(item.get("created_at") or item.get("requested_at")))
    updated = _escape(_format_epoch_utc(item.get("updated_at")))
    expires = _escape(_format_epoch_utc(item.get("expires_at")))
    revoked = _escape(_format_epoch_utc(item.get("revoked_at")))
    ticket = _escape(item.get("ticket_id") or "-")
    back_href = _escape(_with_query("/dashboard", filters))
    raw_json = html.escape(json.dumps(item, indent=2, default=str))

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Request {request_id}</title>
  <script>
    (function() {{
      try {{
        var key = "boundary_dashboard_theme";
        var theme = localStorage.getItem(key);
        if (theme !== "light" && theme !== "dark") {{
          theme = (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) ? "dark" : "dark";
        }}
        document.documentElement.setAttribute("data-theme", theme);
      }} catch (_err) {{
        document.documentElement.setAttribute("data-theme", "dark");
      }}
    }})();
  </script>
  <style>
    :root {{
      --bg: #f3f5f9;
      --bg-elev: #ffffff;
      --bg-soft: #f8fafc;
      --ink: #12161d;
      --muted: #5b6676;
      --line: #d8dfe8;
      --accent: #d81e2e;
      --accent-strong: #b5121f;
      --accent-soft: rgba(216, 30, 46, .14);
      --shadow: 0 14px 34px rgba(19, 26, 37, 0.09);
      --code-bg: #111827;
      --code-ink: #e6edf8;
    }}
    html[data-theme="dark"] {{
      --bg: #070b11;
      --bg-elev: #0d1622;
      --bg-soft: #101b29;
      --ink: #e8edf5;
      --muted: #96a5ba;
      --line: #25374c;
      --accent: #ff4b57;
      --accent-strong: #e93343;
      --accent-soft: rgba(255, 75, 87, .18);
      --shadow: 0 20px 48px rgba(0, 0, 0, .42);
      --code-bg: #0b1119;
      --code-ink: #dfe8f7;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background:
        linear-gradient(130deg, rgba(216, 30, 46, .12), transparent 26%),
        radial-gradient(circle at 86% -8%, rgba(35, 100, 200, .12), transparent 34%),
        var(--bg);
      color: var(--ink);
      font-family: "Avenir Next", "IBM Plex Sans", "Segoe UI", sans-serif;
      transition: background .25s ease, color .25s ease;
    }}
    .wrap {{ max-width: 1080px; margin: 24px auto; padding: 0 16px 24px; }}
    .card {{
      background: linear-gradient(180deg, var(--bg-elev), var(--bg-soft));
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 18px;
      box-shadow: var(--shadow);
    }}
    h1 {{ margin: 0 0 12px; font-size: 1.35rem; letter-spacing: .2px; }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }}
    .item {{
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 10px;
      background: var(--bg-elev);
    }}
    .label {{
      color: var(--muted);
      font-size: .76rem;
      text-transform: uppercase;
      letter-spacing: .8px;
      font-weight: 700;
    }}
    .value {{ margin-top: 4px; font-size: .93rem; word-break: break-word; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    .topbar {{
      display: flex;
      gap: 8px;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
    }}
    .back {{
      display: inline-flex;
      align-items: center;
      text-decoration: none;
      color: var(--accent);
      font-weight: 700;
    }}
    .back:hover {{ color: var(--accent-strong); }}
    .theme-toggle {{
      border: 1px solid var(--line);
      background: var(--bg-elev);
      color: var(--ink);
      border-radius: 10px;
      height: 36px;
      padding: 0 12px;
      font-size: .84rem;
      font-weight: 700;
      cursor: pointer;
      transition: border-color .16s ease, background .16s ease;
    }}
    .theme-toggle:hover {{ border-color: var(--accent); background: var(--accent-soft); }}
    .timeline {{
      margin-top: 14px;
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 12px;
      background: var(--bg-elev);
    }}
    .line-item {{ display: grid; grid-template-columns: 170px 16px 1fr; gap: 8px; align-items: start; margin: 8px 0; }}
    .line-time {{ color: var(--muted); font-size: .84rem; }}
    .line-dot {{ width: 10px; height: 10px; border-radius: 999px; background: var(--accent); margin-top: 4px; }}
    .line-title {{ font-weight: 700; font-size: .9rem; }}
    .line-detail {{ color: var(--muted); font-size: .84rem; margin-top: 2px; }}
    pre {{
      margin: 0;
      background: var(--code-bg);
      color: var(--code-ink);
      padding: 12px;
      border-radius: 10px;
      overflow: auto;
      font-size: .8rem;
      border: 1px solid var(--line);
    }}
    .floating-nav {{
      position: fixed; right: 16px; bottom: 16px; display: flex; flex-direction: column; gap: 8px; z-index: 20;
    }}
    .floating-nav button {{
      width: 44px; height: 44px; border-radius: 999px; border: 1px solid var(--line);
      background: linear-gradient(180deg, var(--bg-elev), var(--bg-soft));
      color: var(--ink);
      box-shadow: var(--shadow);
      cursor: pointer;
      font-size: 1rem;
      transition: border-color .16s ease, transform .16s ease;
    }}
    .floating-nav button:hover {{ border-color: var(--accent); transform: translateY(-1px); }}
    @media (max-width: 760px) {{ .grid {{ grid-template-columns: 1fr; }} .line-item {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <a class="back" href="{back_href}">&larr; Back to dashboard</a>
      <button class="theme-toggle" type="button" id="themeToggleDetail">Dark Mode</button>
    </div>
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

      <p style="margin-top:14px;color:var(--muted);font-size:.83rem;">
        Signed-in principal: <span class="mono">{_escape(scope.principal_arn)}</span>
      </p>
    </div>
  </div>
  <div class="floating-nav">
    <button type="button" id="scrollTopBtn" title="Scroll to top" aria-label="Scroll to top">↑</button>
    <button type="button" id="scrollBottomBtn" title="Scroll to bottom" aria-label="Scroll to bottom">↓</button>
  </div>
  <script>
    (function() {{
      var root = document.documentElement;
      var toggle = document.getElementById("themeToggleDetail");
      var topBtn = document.getElementById("scrollTopBtn");
      var bottomBtn = document.getElementById("scrollBottomBtn");
      var THEME_KEY = "boundary_dashboard_theme";

      function applyTheme(theme) {{
        root.setAttribute("data-theme", theme);
        if (toggle) {{
          toggle.textContent = theme === "dark" ? "Light Mode" : "Dark Mode";
        }}
      }}

      var stored = localStorage.getItem(THEME_KEY);
      if (stored === "light" || stored === "dark") {{
        applyTheme(stored);
      }} else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {{
        applyTheme("dark");
      }} else {{
        applyTheme("dark");
      }}

      if (toggle) {{
        toggle.addEventListener("click", function() {{
          var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
          applyTheme(next);
          localStorage.setItem(THEME_KEY, next);
        }});
      }}
      if (topBtn) {{
        topBtn.addEventListener("click", function() {{
          window.scrollTo({{ top: 0, behavior: "smooth" }});
        }});
      }}
      if (bottomBtn) {{
        bottomBtn.addEventListener("click", function() {{
          window.scrollTo({{ top: document.body.scrollHeight, behavior: "smooth" }});
        }});
      }}
    }})();
  </script>
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
            if filters.get("request_id"):
                pending_rows: List[Dict[str, Any]] = []
                active_rows: List[Dict[str, Any]] = []
                revoked_rows: List[Dict[str, Any]] = []
                denied_rows: List[Dict[str, Any]] = []

                item = store.get_request(str(filters["request_id"]))
                if item:
                    normalized = _normalize_json(item)
                    if _item_in_scope(normalized, scope) and _matches_filters(normalized, filters):
                        status = canonicalize_status(str(normalized.get("status", "")))
                        if status == STATE_PENDING_APPROVAL:
                            pending_rows.append(normalized)
                        elif status == STATE_ACTIVE:
                            active_rows.append(normalized)
                        elif status == STATE_REVOKED:
                            revoked_rows.append(normalized)
                        elif status == STATE_DENIED:
                            denied_rows.append(normalized)

                return _html_response(
                    200,
                    _render_dashboard(scope, active_rows, pending_rows, revoked_rows, denied_rows, filters),
                )

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
