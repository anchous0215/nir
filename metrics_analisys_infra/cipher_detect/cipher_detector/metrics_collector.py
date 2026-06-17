"""
Collection of the 4-dimensional container filesystem metric vector.
For each time interval of length an observation vector is built.

Two data sources are supported:
* **Prometheus**  — live cluster metrics;
* a **JSON file** — pre-recorded samples for offline analysis and testing.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from .utils import parse_timestamp

logger = logging.getLogger("cipher_detector")

PROMETHEUS_URL = "http://localhost:9090"
NAMESPACE = "study"

PROM_QUERIES: Dict[str, str] = {
    "cpu_usage_seconds_total": 'sum(container_cpu_usage_seconds_total{{namespace="{ns}"}})',
    "fs_usage_bytes": 'sum(container_fs_usage_bytes{{namespace="{ns}"}})',
    "fs_io_current": 'sum(container_fs_io_current{{namespace="{ns}"}})',
    "fs_inodes_total": 'sum(container_fs_inodes_total{{namespace="{ns}"}})',
    "fs_inodes_free": 'sum(container_fs_inodes_free{{namespace="{ns}"}})',
}

RAW_FIELDS = (
    "cpu_usage_seconds_total",
    "fs_usage_bytes",
    "fs_io_current",
    "fs_inodes_total",
    "fs_inodes_free",
)


def compute_metric_vector(
    first: Dict[str, Any],
    last: Dict[str, Any],
    delta_t: float,
) -> List[float]:
    """
    Build the 4-D observation vector from the first and last raw samples of one
    window, given the window length in seconds.
    """
    if delta_t <= 0:
        raise ValueError("delta_t must be positive")

    cpu_delta = float(last["cpu_usage_seconds_total"]) - float(
        first["cpu_usage_seconds_total"]
    )
    io_delta = float(last["fs_io_current"]) - float(first["fs_io_current"])

    cpu_pct = max(cpu_delta, 0.0) / delta_t * 100.0
    disk_bytes = float(last["fs_usage_bytes"])
    io_ops = max(io_delta, 0.0) / delta_t
    inodes_used = float(last["fs_inodes_total"]) - float(last["fs_inodes_free"])

    return [cpu_pct, disk_bytes, io_ops, inodes_used]


def vector_to_metrics(vector: List[float]) -> Dict[str, float]:
    """Map a 4-D vector to the named metric dict used by the reporting layer."""
    return {
        "cpu": float(vector[0]),
        "disk": float(vector[1]),
        "io": float(vector[2]),
        "inodes": float(vector[3]),
    }


def _normalize_sample(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Coerce a raw record into the canonical sample schema."""
    if "timestamp" not in raw:
        return None
    try:
        sample: Dict[str, Any] = {"timestamp": parse_timestamp(raw["timestamp"])}
    except ValueError:
        return None
    for field in RAW_FIELDS:
        if field not in raw:
            return None
        sample[field] = float(raw[field])
    return sample


def load_metrics_from_file(path: str) -> List[Dict[str, Any]]:
    """
    Load raw metric samples from a JSON file.
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    if isinstance(data, dict) and "samples" in data:
        data = data["samples"]

    if not isinstance(data, list):
        raise ValueError("Unsupported metrics file format")

    samples: List[Dict[str, Any]] = []
    for raw in data:
        sample = _normalize_sample(raw)
        if sample is None:
            logger.warning("Skipping malformed metric record: %s", raw)
            continue
        samples.append(sample)
    return samples


def query_prometheus(
    prometheus_url: str = PROMETHEUS_URL,
    namespace: str = NAMESPACE,
    window_sec: int = 24 * 3600,
    step_sec: int = 60,
) -> List[Dict[str, Any]]:
    """
    Pull the raw metric counters/gauges from Prometheus over *window_sec* seconds
    and return them as a chronologically ordered list of canonical samples.
    """
    import time

    import requests

    end = int(time.time())
    start = end - window_sec

    merged: Dict[float, Dict[str, Any]] = {}

    for field, template in PROM_QUERIES.items():
        query = template.format(ns=namespace)
        resp = requests.get(
            f"{prometheus_url}/api/v1/query_range",
            params={"query": query, "start": start, "end": end, "step": step_sec},
            timeout=30,
        )
        resp.raise_for_status()
        payload = resp.json()

        results = payload.get("data", {}).get("result", [])
        for series in results:
            for ts, value in series.get("values", []):
                ts_f = float(ts)
                bucket = merged.setdefault(ts_f, {})
                bucket[field] = bucket.get(field, 0.0) + float(value)

    samples: List[Dict[str, Any]] = []
    for ts_f in sorted(merged):
        bucket = merged[ts_f]
        if not all(f in bucket for f in RAW_FIELDS):
            continue
        sample = {"timestamp": parse_timestamp(ts_f)}
        sample.update({f: bucket[f] for f in RAW_FIELDS})
        samples.append(sample)

    return samples


def window_to_vector(
    bucket: List[Dict[str, Any]],
    window: timedelta,
) -> Optional[List[float]]:
    """
    Convert one window's worth of raw samples into a 4-D observation vector.
    """
    if not bucket:
        return None

    ordered = sorted(bucket, key=lambda s: s["timestamp"])
    first = ordered[0]
    last = ordered[-1]

    span = (last["timestamp"] - first["timestamp"]).total_seconds()
    delta_t = span if span > 0 else window.total_seconds()

    return compute_metric_vector(first, last, delta_t)
