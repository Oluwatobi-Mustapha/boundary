"""
Canonical request states and transition helpers.

This module keeps status handling consistent across workflow, janitor, and storage.
It also preserves backward compatibility with legacy values already in DynamoDB.
"""
from typing import Dict, Set


STATE_PENDING_APPROVAL = "PENDING_APPROVAL"
STATE_APPROVED = "APPROVED"
STATE_ACTIVE = "ACTIVE"
STATE_REVOKED = "REVOKED"
STATE_DENIED = "DENIED"
STATE_ERROR = "ERROR"

# Legacy values kept for compatibility with older records/CLI paths.
_ALIASES: Dict[str, str] = {
    "PENDING": STATE_PENDING_APPROVAL,
}

VALID_STATES: Set[str] = {
    STATE_PENDING_APPROVAL,
    STATE_APPROVED,
    STATE_ACTIVE,
    STATE_REVOKED,
    STATE_DENIED,
    STATE_ERROR,
}

# Intentionally permissive enough to avoid breaking existing live paths.
_ALLOWED_TRANSITIONS: Dict[str, Set[str]] = {
    STATE_PENDING_APPROVAL: {STATE_APPROVED, STATE_ACTIVE, STATE_DENIED, STATE_ERROR},
    STATE_APPROVED: {STATE_ACTIVE, STATE_ERROR},
    STATE_ACTIVE: {STATE_REVOKED, STATE_ERROR},
    STATE_DENIED: set(),
    STATE_REVOKED: set(),
    STATE_ERROR: set(),
}


def canonicalize_status(status: str) -> str:
    """Normalizes incoming status values to canonical uppercase constants."""
    if not status:
        return status
    normalized = str(status).strip().upper()
    return _ALIASES.get(normalized, normalized)


def status_equivalents(status: str) -> Set[str]:
    """
    Returns all raw values that should be treated as equivalent.
    Example: PENDING_APPROVAL <-> PENDING.
    """
    canonical = canonicalize_status(status)
    values = {canonical}
    for alias, mapped in _ALIASES.items():
        if mapped == canonical:
            values.add(alias)
    return values


def is_valid_status(status: str) -> bool:
    return canonicalize_status(status) in VALID_STATES


def can_transition(current_status: str, new_status: str) -> bool:
    """
    Checks whether a transition is allowed after canonicalization.
    Same-state updates are allowed to keep idempotent writes safe.
    """
    current = canonicalize_status(current_status)
    new = canonicalize_status(new_status)

    if current == new:
        return True
    if current not in VALID_STATES or new not in VALID_STATES:
        return False

    return new in _ALLOWED_TRANSITIONS.get(current, set())
