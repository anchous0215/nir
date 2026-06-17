"""
I/O and helper utilities for the cipher-stage (ransomware encryption) detector:

* timestamp normalisation;
* sliding-window slicing of a metric time-series;
* console + JSON reporting of per-window results;
* pushing detection results to Loki).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("cipher_detector")


LOKI_URL = "http://localhost:3100"
NAMESPACE = "study"


def parse_timestamp(value: Any) -> datetime:
    """
    Normalise a timestamp to a naive (UTC).
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


def sliding_windows(
    samples: List[Dict[str, Any]],
    window: timedelta,
    step: Optional[timedelta] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> Iterable[Tuple[datetime, List[Dict[str, Any]]]]:
    """
    Yield ``(window_start, [samples within [window_start, window_start+window) ])``.
    """
    if not samples:
        return

    ordered = sorted(samples, key=lambda s: s["timestamp"])
    if start is None:
        start = ordered[0]["timestamp"]
    if end is None:
        end = ordered[-1]["timestamp"]
    if step is None:
        step = window

    win_start = start
    while win_start <= end:
        win_end = win_start + window
        bucket = [s for s in ordered if win_start <= s["timestamp"] < win_end]
        yield win_start, bucket
        win_start = win_start + step


def _fmt_bytes(num_bytes: float) -> str:
    """Human-readable byte size."""
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024.0 or unit == "TB":
            return f"{value:.1f}{unit}"
        value /= 1024.0
    return f"{value:.1f}TB"


def format_window_line(record: Dict[str, Any]) -> str:
    """Render a single detection-window result as a human-readable log line."""
    ts = record["window_start"]
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts)
    label = "⚠️ CIPHER" if record["is_attack"] else "NORMAL  "
    metrics = record.get("metrics", {})
    return (
        f"[{ts_str}] {label} | "
        f"D²={record['mahalanobis_d2']:.2f} | "
        f"D²_max={record['d2_max']:.2f} | "
        f"CPU={metrics.get('cpu', 0.0):.1f}% | "
        f"Disk={_fmt_bytes(metrics.get('disk', 0.0))} | "
        f"IO={metrics.get('io', 0.0):.0f} ops/s | "
        f"Inodes={int(metrics.get('inodes', 0))}"
    )


def write_json_report(records: Iterable[Dict[str, Any]], path: str) -> None:
    """Persist the per-window results as a JSON report."""
    serialisable = []
    for r in records:
        ts = r["window_start"]
        serialisable.append(
            {
                "window_start": ts.isoformat() if isinstance(ts, datetime) else str(ts),
                "mahalanobis_d2": round(float(r["mahalanobis_d2"]), 4),
                "d2_max": round(float(r["d2_max"]), 4),
                "is_attack": bool(r["is_attack"]),
                "metrics": {
                    "cpu": round(float(r["metrics"].get("cpu", 0.0)), 4),
                    "disk": float(r["metrics"].get("disk", 0.0)),
                    "io": round(float(r["metrics"].get("io", 0.0)), 4),
                    "inodes": int(r["metrics"].get("inodes", 0)),
                },
            }
        )
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(serialisable, fh, ensure_ascii=False, indent=2)


def push_to_loki(
    record: Dict[str, Any],
    loki_url: str = LOKI_URL,
    severity: str = "critical",
    pod: str = "unknown",
) -> None:
    """
    Push a single cipher-detection result to Loki's API.
    """
    import requests

    url = f"{loki_url}/loki/api/v1/push"

    ts = record["window_start"]
    ts_dt = ts if isinstance(ts, datetime) else parse_timestamp(ts)
    ts_ns = str(int(ts_dt.timestamp() * 1e9))

    metrics = record.get("metrics", {})
    payload = {
        "streams": [
            {
                "stream": {
                    "job": "cipher-detector",
                    "severity": severity,
                    "attack": "T1486_Data_Encrypted_for_Impact",
                    "pod": pod,
                },
                "values": [
                    [
                        ts_ns,
                        json.dumps(
                            {
                                "message": "Cipher stage detected: anomalous "
                                "filesystem activity",
                                "pod": pod,
                                "mahalanobis_d2": round(
                                    float(record["mahalanobis_d2"]), 4
                                ),
                                "d2_max": round(float(record["d2_max"]), 4),
                                "metrics": {
                                    "cpu": round(float(metrics.get("cpu", 0.0)), 4),
                                    "disk": float(metrics.get("disk", 0.0)),
                                    "io": round(float(metrics.get("io", 0.0)), 4),
                                    "inodes": int(metrics.get("inodes", 0)),
                                },
                            }
                        ),
                    ]
                ],
            }
        ]
    }

    headers = {"Content-Type": "application/json"}
    resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
    resp.raise_for_status()
