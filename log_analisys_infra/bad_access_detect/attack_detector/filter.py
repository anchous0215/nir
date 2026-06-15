"""
filter.py
=========

Pre-analysis filtering of container log events.

Only *access-related* events are forwarded to the statistical analysis. 
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

def contains_any(text: str, keywords: Iterable[str]) -> bool:
    """True if *text* contains at least one of *keywords* (case-insensitive)."""
    return any(k.lower() in text for k in keywords)

def contains_all(text: str, keywords: Iterable[str]) -> bool:
    """True if *text* contains every one of *keywords* (case-insensitive)."""
    return all(k.lower() in text for k in keywords)

def _norm(value: Any) -> str:
    """Normalise an arbitrary field to a lowercase string for matching."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return " ".join(str(v) for v in value).lower()
    return str(value).lower()


def _is_stderr(log_entry: Dict[str, Any]) -> bool:
    return _norm(log_entry.get("stream")) == "stderr"


def _has_capability(log_entry: Dict[str, Any], *caps: str) -> bool:
    """
    True if any of *caps* appears either in the explicit 
    ``capabilities`` field or anywhere in the raw log line.
    """
    haystack = _norm(log_entry.get("capabilities")) + " " + _norm(log_entry.get("log"))
    return contains_any(haystack, caps)

def _rule_1(e: Dict[str, Any], log: str) -> bool:
    mandatory = (
        (contains_all(log, ["grep"]) and contains_any(log, ["password", "shadow"]))
        or "permission denied" in log
    )
    additional = _is_stderr(e) and contains_any(log, ["/etc", "/home"])
    return mandatory or additional


def _rule_2(e: Dict[str, Any], log: str) -> bool:
    mandatory = contains_any(log, ["sudo"]) or "authentication failure" in log
    additional = _is_stderr(e) and contains_any(log, ["ssh"])
    return mandatory or additional


def _rule_3(e: Dict[str, Any], log: str) -> bool:
    mandatory = contains_any(log, ["failed password", "invalid user"])
    additional = _is_stderr(e)
    return mandatory or additional


def _rule_4(e: Dict[str, Any], log: str) -> bool:
    mandatory = contains_any(log, ["tcpdump", "gcc"])
    additional = _has_capability(e, "net_raw", "net_admin") or contains_any(log, ["sudo"])
    return mandatory or additional


def _rule_5(e: Dict[str, Any], log: str) -> bool:
    mandatory = contains_any(log, ["cookies", "chrome"])
    additional = contains_any(log, ["whitechocolatemacademianut", "whitechocolatemacadamianut"])
    return mandatory or additional


def _rule_6(e: Dict[str, Any], log: str) -> bool:
    mandatory = contains_any(log, [".netr", "find"])
    additional = _is_stderr(e)
    return mandatory or additional


def _rule_7(e: Dict[str, Any], log: str) -> bool:
    credential_stores = ["lazagne", "credential", "/etc/shadow", "keyring", "secretservice"]
    mandatory = contains_any(log, credential_stores)
    additional = _is_stderr(e) and "access denied" in log
    return mandatory or additional


def _rule_8(e: Dict[str, Any], log: str) -> bool:
    mandatory = contains_any(log, ["pam", "sed", "1s,^,"])
    additional = _is_stderr(e) and "permission denied" in log
    return mandatory or additional

_RULES = (
    _rule_1,
    _rule_2,
    _rule_3,
    _rule_4,
    _rule_5,
    _rule_6,
    _rule_7,
    _rule_8,
)

def is_access_event(log_entry: Dict[str, Any]) -> bool:
    """
    Return ``True`` if the log event is access-related and must be included
    in the analysis.

    Rule: a row matches when its **mandatory** signal is present **OR** when
    **all** of its **additional** signals are present.  The event qualifies if
    **any** of the 8 rows matches.
    """
    if not isinstance(log_entry, dict):
        return False

    log = _norm(log_entry.get("log"))
    if not log and not log_entry.get("stream"):
        # nothing to inspect
        return False

    for rule in _RULES:
        if rule(log_entry, log):
            return True
    return False


def matched_rules(log_entry: Dict[str, Any]) -> List[int]:
    """
    Diagnostic helper: return the 1-based indices of every rule group that
    matched the event (useful for tests and explainability).
    """
    if not isinstance(log_entry, dict):
        return []
    log = _norm(log_entry.get("log"))
    return [i + 1 for i, rule in enumerate(_RULES) if rule(log_entry, log)]


def filter_events(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return the sub-list of *events* that pass :func:`is_access_event`."""
    return [e for e in events if is_access_event(e)]
