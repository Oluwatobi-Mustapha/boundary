from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Optional, Any, Dict, Iterable, Tuple

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from src.models.request import AccessRequest
from src.core.engine import EvaluationResult
from src.ui import __version__


# ---------- Helpers ----------

def _iso_utc_now_seconds() -> str:
    """UTC ISO 8601, second precision, with Z suffix."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _iso_utc_from_epoch_seconds(epoch_seconds: Optional[float]) -> str:
    if epoch_seconds is None:
        return "-"
    return (
        datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _normalize_iso_utc_string(ts: str) -> str:
    """
    Normalize common ISO strings to the same look:
    - convert +00:00 -> Z
    - strip fractional seconds
    Keeps other offsets intact.
    """
    if not ts:
        return "-"
    s = ts.strip()

    # Convert +00:00 to Z when present
    if s.endswith("+00:00"):
        s = s[:-6] + "Z"

    # Strip fractional seconds if present (e.g., 2026-...:05.092154Z)
    if s.endswith("Z") and "." in s:
        left, _ = s.split(".", 1)
        s = left + "Z"

    return s


def _safe_get(obj: Any, key: str, default: Any = None) -> Any:
    """Supports dataclass, dict-like, or attribute access."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    if is_dataclass(obj):
        return asdict(obj).get(key, default)
    return getattr(obj, key, default)


def _stringify_dictlike(x: Any) -> Dict[str, Any]:
    if x is None:
        return {}
    if isinstance(x, dict):
        return x
    if is_dataclass(x):
        return asdict(x)
    if hasattr(x, "__dict__"):
        return dict(x.__dict__)
    return {"value": str(x)}


def _fmt_hours(hours: Optional[float]) -> str:
    if hours is None:
        return "-"
    h = float(hours)
    if abs(h - round(h)) < 1e-9:
        return f"{int(round(h))}h"
    return f"{h:.1f}h"


def _redact(s: str, show: int = 12) -> str:
    if not s:
        return "-"
    return s if len(s) <= show else s[:show] + "…"


def _normalize_effect(effect: str) -> str:
    e = (effect or "").upper()
    if e in ("ALLOW", "DENY", "ERROR"):
        return e
    return "ERROR"


def _effect_style(effect: str) -> str:
    effect = _normalize_effect(effect)
    if effect == "ALLOW":
        return "bold green"
    if effect == "DENY":
        return "bold red"
    return "bold yellow"


def _category_for(effect: str, reason: str) -> str:
    """
    A more useful replacement for vague LOW/MEDIUM/HIGH.
    """
    effect = _normalize_effect(effect)
    r = (reason or "").lower()

    if effect == "ALLOW":
        return "authorized"
    if effect == "DENY":
        if r.startswith("infrastructure error"):
            return "infra_fail_closed"
        if "ticket" in r or "approval" in r:
            return "approval_required"
        return "policy_denied"
    return "infra_error"


def _kv_pairs_from_evidence(evidence: Dict[str, Any]) -> Iterable[Tuple[str, str]]:
    """
    Normalize evidence values into tidy strings:
    - dict -> k1=v1, k2=v2
    - list -> comma joined
    - others -> str
    """
    for k in evidence.keys():
        v = evidence[k]
        if isinstance(v, dict):
            parts = [f"{kk}={v[kk]}" for kk in sorted(v.keys())]
            yield k, ", ".join(parts) if parts else "-"
        elif isinstance(v, list):
            yield k, ", ".join(map(str, v)) if v else "-"
        else:
            yield k, str(v)


def _divider(console: Console, title: Optional[str] = None) -> None:
    """
    Subtle section divider that adapts to terminal width.
    Example:
      ─────── CONTEXT ─────────────────────────────
    """
    width = console.size.width if console.is_terminal else 80
    width = max(40, width)

    if title:
        label = f" {title.strip().upper()} "
        # Keep the divider subtle and readable
        left = "─" * 6
        remaining = max(0, width - len(left) - len(label))
        right = "─" * remaining
        console.print(f"[dim]{left}{label}{right}[/dim]")
    else:
        console.print(f"[dim]{'─' * width}[/dim]")


# ---------- UI ----------

def print_banner(console: Console) -> None:
    """
    No-wall Boundary banner (cleaner / more premium) + prowler-like subtitle.
    """
    fancy = r"""
  ____                        _
 | __ )  ___  _   _ _ __   __| | __ _ _ __ _   _
 |  _ \ / _ \| | | | '_ \ / _` |/ _` | '__| | | |
 | |_) | (_) | |_| | | | | (_| | (_| | |  | |_| |
 |____/ \___/ \__,_|_| |_|\__,_|\__,_|_|   \__, |
                                           |___/
""".strip("\n")

    plain = "BOUNDARY"

    # If non-TTY or narrow terminal, keep it minimal.
    if (not console.is_terminal) or (console.size and console.size.width < 70):
        console.print(plain, style="bold green")
    else:
        console.print(fancy, style="bold green")

    # Subtitle color that pairs nicely with green (prowler-like vibe).
    console.print("least-privilege access audits", style="bold cyan")
    console.print("")


def print_verdict(
    req: AccessRequest,
    res: EvaluationResult,
    *,
    artifact_path: Optional[str] = None,
    verbose: bool = False,
    redact_mode: str = "safe",  # "safe" | "none"
) -> None:
    """
    Production-grade CLI verdict output:
    - Consistent UTC ISO timestamps (second precision, Z suffix)
    - Evidence rendered as a table (no raw Python dicts)
    - Premium, restrained color palette
    - Optional enterprise metadata if present (engine/policy versions, rule id, etc.)
    - FULL ARN display (as requested)
    """
    console = Console(highlight=False)

    print_banner(console)

    # ----- Normalize + Extract -----
    effect = _normalize_effect(_safe_get(res, "effect", "ERROR"))
    reason = _safe_get(res, "reason", "-") or "-"

    request_id = _safe_get(req, "request_id", "-")
    principal_id = _safe_get(req, "principal_id", "")
    principal_type = _safe_get(req, "principal_type", "-")
    account_id = _safe_get(req, "account_id", "-")

    ps_name = _safe_get(req, "permission_set_name", "-")
    ps_arn = _safe_get(req, "permission_set_arn", "") or "-"
    instance_arn = _safe_get(req, "instance_arn", "") or "-"

    requested_utc = _iso_utc_from_epoch_seconds(_safe_get(req, "requested_at", None))
    expires_utc = _iso_utc_from_epoch_seconds(_safe_get(res, "effective_expires_at", None))

    # evaluated_at can come from engine as a string; normalize it.
    evaluated_at = _safe_get(res, "evaluated_at", None)
    if isinstance(evaluated_at, str) and evaluated_at.strip():
        evaluated_utc = _normalize_iso_utc_string(evaluated_at)
    else:
        evaluated_utc = _iso_utc_now_seconds()

    now_utc = _iso_utc_now_seconds()

    policy_hash = _safe_get(res, "policy_hash", "") or ""
    policy_hash_short = f"{policy_hash[:16]}…" if policy_hash else "-"

    # Optional enterprise metadata (only show if present)
    policy_version = _safe_get(res, "policy_version", None)
    engine_version = _safe_get(res, "engine_version", None) or _safe_get(res, "engine", None)
    decision_id = _safe_get(res, "decision_id", None) or _safe_get(res, "decision_hash", None)
    correlation_id = _safe_get(res, "correlation_id", None) or _safe_get(req, "correlation_id", None)
    matched_rule = _safe_get(res, "matched_rule", None) or _safe_get(res, "matched_rule_id", None)

    # Evidence
    evidence = _stringify_dictlike(_safe_get(res, "context_evidence", None) or _safe_get(res, "evidence", None))

    # ----- Redaction ----
    def show_id(val: str, show: int = 12) -> str:
        if not val:
            return "-"
        if redact_mode == "none" or verbose:
            return val
        return _redact(val, show=show)

    principal_display = show_id(principal_id, show=12)

    # FULL ARN DISPLAY (no shortening), as requested.
    ps_arn_display = ps_arn
    instance_arn_display = instance_arn

    # =========================
    # TIMESTAMPS + HEADLINE
    # =========================
    _divider(console, "UTC")
    console.print(f"[green]Requested At:[/green] [dim]{now_utc}[/dim]")
    console.print(f"[green]Evaluated At:[/green] [dim]{evaluated_utc}[/dim]")
    console.print(f"[green]Expired At:[/green] [dim]{expires_utc}[/dim]\n")

    

    category = _category_for(effect, reason)

    # CONTEXT
    _divider(console, "EVALUATION CONTEXT")
    console.print(f" • Request ID:   [yellow]{request_id}[/yellow]")
    console.print(f" • Principal:    [yellow]{principal_display}[/yellow] [dim]({principal_type})[/dim]")
    console.print(f" • Account:      [yellow]{account_id}[/yellow]")
    console.print(f" • Instance ARN: [yellow]{instance_arn_display}[/yellow]")

    if correlation_id:
        console.print(f" • Correlation: [yellow]{correlation_id}[/yellow]")
    if decision_id:
        console.print(f" • Decision ID: [yellow]{decision_id}[/yellow]")
    if matched_rule:
        console.print(f" • Matched Rule: [yellow]{matched_rule}[/yellow]")
    if engine_version:
        console.print(f" • Engine:       [yellow]{engine_version}[/yellow]")
    if policy_version:
        console.print(f" • Policy:   [yellow]{policy_version}[/yellow]")

    console.print(f" • Policy Hash:  [yellow]{policy_hash_short}[/yellow]\n")

  
    # DECISION CONTEXT
   
    if evidence:
        _divider(console, "DECISION CONTEXT")
        ev_table = Table(
            box=box.SIMPLE_HEAD if console.is_terminal else box.SIMPLE,
            show_header=True,
            header_style="bold white",
            border_style="dim",
            expand=True,
        )
        ev_table.add_column("KEY", ratio=1, no_wrap=True, style="white")
        ev_table.add_column("VALUE", ratio=4, no_wrap=False, style="dim")

        preferred = [
            "account_ou_path",
            "account_tags",
            "matched_selector",
            "principal_group",
            "permission_set_name",
            "permission_set_arn",
        ]

        seen = set()
        for k in preferred:
            if k in evidence:
                for kk, vv in _kv_pairs_from_evidence({k: evidence[k]}):
                    ev_table.add_row(kk, vv)
                seen.add(k)

        for k in sorted(evidence.keys()):
            if k in seen:
                continue
            for kk, vv in _kv_pairs_from_evidence({k: evidence[k]}):
                ev_table.add_row(kk, vv)

        console.print(ev_table)
        console.print("")


   
    # DECISION
    
    _divider(console, "DECISION")
    table_box = box.SQUARE if console.is_terminal else box.SIMPLE
    table = Table(
        box=table_box,
        show_header=True,
        header_style="bold white",
        border_style="dim",   # softer than harsh white
        expand=True,
        pad_edge=True,
    )

    table.add_column("PERMISSION SET", ratio=3, no_wrap=False)
    table.add_column("DURATION", justify="center", ratio=1, no_wrap=True)
    table.add_column("STATUS", justify="center", ratio=1, no_wrap=True)
    table.add_column("CATEGORY", justify="center", ratio=1, no_wrap=True)
    table.add_column("REASON", ratio=4, no_wrap=False)

    perm_cell = f"{ps_name}\n[dim]{ps_arn_display}[/dim]"

    was_capped = bool(_safe_get(res, "was_capped", False))
    dur_txt = _fmt_hours(_safe_get(res, "effective_duration_hours", None))

    if effect == "ALLOW":
        if was_capped and dur_txt != "-":
            dur_txt = f"{dur_txt} [yellow](CAPPED)[/yellow]"
    elif effect == "DENY":
        dur_txt = "-"
    else:
        dur_txt = "0h"

    status_txt = f"[{_effect_style(effect)}]{effect}[/{_effect_style(effect)}]"
    table.add_row(perm_cell, dur_txt, status_txt, category, reason)

    console.print(table)
    console.print("")

    
    # SUMMARY
   
    allowed = 1 if effect == "ALLOW" else 0
    denied = 1 if effect == "DENY" else 0
    errored = 1 if effect == "ERROR" else 0

    console.print(
        f"[black on green] {allowed} Allowed [/black on green] "
        f"[white on red] {denied} Denied [/white on red] "
        f"[black on yellow] {errored} Errors [/black on yellow]"
    )

    
    # ARTIFACT
    
    if artifact_path:
        _divider(console, "ARTIFACT")
        console.print(f"[dim]Audit Artifact saved to:[/dim] [cyan]{artifact_path}[/cyan]\n")
