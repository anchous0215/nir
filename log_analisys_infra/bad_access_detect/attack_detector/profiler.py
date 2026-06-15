"""
profiler.py
===========

Builds the reference behaviour profile.

Profiling procedure:

1. Filter the 24h of events.
2. Slice with a 1-hour sliding window  →  intervals ``T0 .. TM``.
3. For each interval ``Ti``:
     * build keys ``(log, pod_name, stream)`` for every event,
     * group into equivalence classes,
     * compute propabilities for log events.
4. Persist.
"""

from __future__ import annotations

import pickle
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, Hashable, List, Tuple

from .filter import is_access_event
from .utils import sliding_windows

ClassKey = Tuple[str, str, str]

PROFILE_WINDOW = timedelta(hours=1)


def make_class_key(log_entry: Dict[str, Any]) -> ClassKey:
    """
    Build the hashable equivalence-class key ``(log, pod_name, stream)``.
    """
    return (
        str(log_entry.get("log", "")),
        str(log_entry.get("pod_name", log_entry.get("pod", "unknown"))),
        str(log_entry.get("stream", "")),
    )


def build_equivalence_classes(events: List[Dict[str, Any]]) -> Dict[ClassKey, int]:
    """
    Group *events* into equivalence classes and return a mapping
    ``class_key -> cardinality``.
    """
    counter: Counter = Counter()
    for event in events:
        counter[make_class_key(event)] += 1
    return dict(counter)


def compute_baseline(
    events: List[Dict[str, Any]],
    window: timedelta = PROFILE_WINDOW,
    apply_filter: bool = True,
) -> Dict[int, Dict[ClassKey, float]]:
    """
    Build the per-hour reference profile.

    Returns ``{hour_of_day -> {class_key -> probability}}``

    Parameters
    ----------
    events:
        Raw events spanning ~24 hours.
    window:
        Profiling window length.
    apply_filter:
        Whether to apply :func:`is_access_event` first.
    """
    if apply_filter:
        events = [e for e in events if is_access_event(e)]

    delta_t = window.total_seconds()  # Δt in seconds

    per_hour: Dict[int, List[Dict[ClassKey, float]]] = defaultdict(list)

    for win_start, bucket in sliding_windows(events, window=window):
        if not bucket:
            continue
        classes = build_equivalence_classes(bucket)
        probabilities = {key: card / delta_t for key, card in classes.items()}
        hour = win_start.hour if isinstance(win_start, datetime) else 0
        per_hour[hour].append(probabilities)

    baseline: Dict[int, Dict[ClassKey, float]] = {}
    for hour, window_list in per_hour.items():
        agg: Dict[ClassKey, float] = defaultdict(float)
        for probs in window_list:
            for key, p in probs.items():
                agg[key] += p
        n = len(window_list)
        baseline[hour] = {key: total / n for key, total in agg.items()}

    return baseline


def get_hour_profile(
    baseline: Dict[int, Dict[ClassKey, float]], hour: int
) -> Dict[ClassKey, float]:
    """
    Return the profile slice for *hour*.
    """
    if hour in baseline:
        return baseline[hour]
    if not baseline:
        return {}
    # nearest hour on the 24h clock
    nearest = min(baseline.keys(), key=lambda h: min(abs(h - hour), 24 - abs(h - hour)))
    return baseline[nearest]


def save_profile(baseline: Dict[int, Dict[ClassKey, float]], path: str) -> None:
    """Serialise the baseline profile with :mod:`pickle`."""
    with open(path, "wb") as fh:
        pickle.dump(baseline, fh, protocol=pickle.HIGHEST_PROTOCOL)


def load_profile(path: str) -> Dict[int, Dict[ClassKey, float]]:
    """Load a baseline profile previously saved by :func:`save_profile`."""
    with open(path, "rb") as fh:
        return pickle.load(fh)
