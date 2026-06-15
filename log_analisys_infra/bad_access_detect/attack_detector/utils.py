"""
utils.py
========

I/O and helper utilities:

* connecting to Loki and pulling the raw log stream;
* parsing a single Loki/JSON log line into the canonical event ``dict``;
* timestamp normalisation;
* sliding-window slicing;
* console + JSON reporting.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger("attack_detector")


LOKI_URL = "http://localhost:3100"
NAMESPACE = "study"
TIME_WINDOW_SEC = 3600 * 24


LOGQL_QUERY = f"""
{{namespace="{NAMESPACE}"}}
| json
|~ "grep|sudo|ssh|tcpdump|pam|sed|find|\\.netrc|lazagne|gcc|chrome|Cookies"
|~ "password|shadow|/etc|/home|Cookies|chrome|1s,^,|denied|failure|Invalid user"
""".strip()


def parse_timestamp(value: Any) -> datetime:
    """
    Normalise a timestamp to a naive ``datetime`` (UTC).
    """
    if isinstance(value, datetime):
        return value.replace(tzinfo=None) if value.tzinfo else value

    if isinstance(value, (int, float)):
        v = float(value)
        if v > 1e17:
            v = v / 1e9
        elif v > 1e14:
            v = v / 1e6  
        elif v > 1e11:
            v = v / 1e3 
        return datetime.fromtimestamp(v, tz=timezone.utc).replace(tzinfo=None)

    if isinstance(value, str):
        s = value.strip()
        if s.isdigit():
            return parse_timestamp(int(s))
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return dt.replace(tzinfo=None) if dt.tzinfo else dt
        except ValueError:
            pass

    raise ValueError(f"Unrecognised timestamp: {value!r}")


def parse_log_line(line: str, ts: Any) -> Optional[Dict[str, Any]]:
    """
    Parse one raw Loki value pair ``(line, ts)`` into a canonical event dict.
    """
    try:
        parsed = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None

    kube = parsed.get("kubernetes", {}) or {}
    return {
        "log": parsed.get("log", "") or "",
        "stream": parsed.get("stream", "") or "",
        "pod_name": kube.get("pod_name", parsed.get("pod_name", "unknown")),
        "timestamp": parse_timestamp(ts),
        "capabilities": parsed.get("capabilities", kube.get("capabilities", "")),
    }


def normalize_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalise an already-dict event into the canonical schema, coercing the timestamp.
    """
    pod = raw.get("pod_name", raw.get("pod", "unknown"))
    return {
        "log": raw.get("log", "") or "",
        "stream": raw.get("stream", "") or "",
        "pod_name": pod,
        "timestamp": parse_timestamp(raw["timestamp"]) if raw.get("timestamp") is not None else None,
        "capabilities": raw.get("capabilities", ""),
    }


def parse_loki_response(loki_response: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten a Loki ``query_range`` JSON response into canonical events."""
    events: List[Dict[str, Any]] = []
    for result in loki_response.get("data", {}).get("result", []):
        for line, ts in result.get("values", []):
            event = parse_log_line(line, ts)
            if event is not None:
                events.append(event)
    return events


def query_loki(
    loki_url: str = LOKI_URL,
    query: str = LOGQL_QUERY,
    window_sec: int = TIME_WINDOW_SEC,
    limit: int = 5000,
) -> List[Dict[str, Any]]:
    """
    Pull logs from Loki's ``query_range`` API.
    """
    import time

    import requests  # local import on purpose

    end_ns = int(time.time() * 1e9)
    start_ns = end_ns - window_sec * 1_000_000_000

    resp = requests.get(
        f"{loki_url}/loki/api/v1/query_range",
        params={"query": query, "start": start_ns, "end": end_ns, "limit": limit},
        timeout=30,
    )
    resp.raise_for_status()
    return parse_loki_response(resp.json())


def load_logs_from_file(path: str) -> List[Dict[str, Any]]:
    """
    Load events from a JSON file.
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    if isinstance(data, dict) and "data" in data:
        return parse_loki_response(data)

    if isinstance(data, list):
        events = []
        for raw in data:
            try:
                events.append(normalize_event(raw))
            except (KeyError, ValueError) as exc:  # pragma: no cover - defensive
                logger.warning("Skipping malformed record: %s (%s)", raw, exc)
        return events

    raise ValueError("Unsupported log file format")


def sliding_windows(
    events: List[Dict[str, Any]],
    window: timedelta,
    step: Optional[timedelta] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
):
    """
    Yield ``(window_start, [events within [window_start, window_start+window) ])``.
    """
    if not events:
        return

    ordered = sorted(events, key=lambda e: e["timestamp"])
    if start is None:
        start = ordered[0]["timestamp"]
    if end is None:
        end = ordered[-1]["timestamp"]
    if step is None:
        step = window

    win_start = start
    while win_start <= end:
        win_end = win_start + window
        bucket = [e for e in ordered if win_start <= e["timestamp"] < win_end]
        yield win_start, bucket
        win_start = win_start + step


def format_window_line(record: Dict[str, Any]) -> str:
    """Render a single detection-window result as a human-readable log line."""
    ts = record["window_start"]
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts)
    if record["is_attack"]:
        label = "⚠️ ATTACK"
    else:
        label = "NORMAL "
    pod = record.get("top_pod")
    pod_str = f" | pod={pod}" if record["is_attack"] and pod else ""
    return (
        f"[{ts_str}] {label} | "
        f"χ²={record['chi2']:.2f} | "
        f"df={record['df']} | "
        f"χ²_crit={record['chi2_crit']:.2f} | "
        f"events={record['filtered_events_count']}{pod_str}"
    )


def write_json_report(records: Iterable[Dict[str, Any]], path: str) -> None:
    """Persist the per-window results as a JSON report."""
    serialisable = []
    for r in records:
        ts = r["window_start"]
        serialisable.append(
            {
                "window_start": ts.isoformat() if isinstance(ts, datetime) else str(ts),
                "chi2": round(float(r["chi2"]), 4),
                "chi2_crit": round(float(r["chi2_crit"]), 4),
                "df": int(r["df"]),
                "is_attack": bool(r["is_attack"]),
                "filtered_events_count": int(r["filtered_events_count"]),
                "top_pod": r.get("top_pod"),
            }
        )
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(serialisable, fh, ensure_ascii=False, indent=2)
