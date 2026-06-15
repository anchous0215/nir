"""
main.py
=======

entry point for the χ² Kubernetes intrusion detector.
------------

``profile``
    Build the baseline behaviour profile from 24h of logs and save it
    (pickle).  Source can be a Loki instance or a JSON file.

``detect``
    Stream a log source through 3-minute sliding windows, score each window
    with the χ² test against the baseline, print a per-window line and
    optionally write a JSON report.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List

from . import utils
from .detector import detect_attack
from .filter import is_access_event
from .profiler import (
    build_equivalence_classes,
    compute_baseline,
    get_hour_profile,
    load_profile,
    save_profile,
)

logger = logging.getLogger("attack_detector")

DETECTION_WINDOW = timedelta(minutes=3)  # section 5


def _load_events(args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Load events either from a JSON file or from Loki, per CLI args."""
    if args.file:
        logger.info("Loading logs from file: %s", args.file)
        return utils.load_logs_from_file(args.file)
    logger.info("Querying Loki at %s", args.loki_url)
    window_sec = args.window_hours * 3600
    return utils.query_loki(loki_url=args.loki_url, window_sec=window_sec)


def cmd_profile(args: argparse.Namespace) -> int:
    events = _load_events(args)
    logger.info("Loaded %d raw events", len(events))

    baseline = compute_baseline(events)
    n_classes = sum(len(v) for v in baseline.values())
    logger.info(
        "Baseline built: %d hour-slices, %d class entries", len(baseline), n_classes
    )

    save_profile(baseline, args.profile_out)
    logger.info("Profile saved to %s", args.profile_out)
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    baseline = load_profile(args.profile)
    logger.info("Loaded profile with %d hour-slices", len(baseline))

    events = _load_events(args)
    access_events = [e for e in events if is_access_event(e)]
    logger.info(
        "Loaded %d raw events, %d access events after filtering",
        len(events),
        len(access_events),
    )

    records: List[Dict[str, Any]] = []
    attacks = 0

    for win_start, bucket in utils.sliding_windows(
        access_events, window=DETECTION_WINDOW, step=DETECTION_WINDOW
    ):
        observed = build_equivalence_classes(bucket)

        hour = win_start.hour if isinstance(win_start, datetime) else 0
        hour_profile = get_hour_profile(baseline, hour)

        result = detect_attack(observed, hour_profile)

        top_pod = None
        if bucket:
            pod_counts: Dict[str, int] = {}
            for e in bucket:
                pod = str(e.get("pod_name", "unknown"))
                pod_counts[pod] = pod_counts.get(pod, 0) + 1
            top_pod = max(pod_counts, key=pod_counts.get)

        record = {
            "window_start": win_start,
            "chi2": result["chi2"],
            "chi2_crit": result["chi2_crit"],
            "df": result["df"],
            "is_attack": bool(result["is_attack"]),
            "filtered_events_count": len(bucket),
            "top_pod": top_pod,
        }
        records.append(record)
        attacks += int(record["is_attack"])

        print(utils.format_window_line(record))

    total = len(records)
    logger.info(
        "Processed %d windows, %d flagged as attacks (%.1f%%)",
        total,
        attacks,
        (100.0 * attacks / total) if total else 0.0,
    )

    if args.report:
        utils.write_json_report(records, args.report)
        logger.info("JSON report written to %s", args.report)

    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attack_detector",
        description="χ²-based unauthorized-access detector for Kubernetes logs.",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="enable debug logging"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    def add_source_opts(p: argparse.ArgumentParser) -> None:
        p.add_argument("--file", help="path to a JSON log file (Loki response or flat list)")
        p.add_argument("--loki-url", default=utils.LOKI_URL, help="Loki base URL")
        p.add_argument(
            "--window-hours",
            type=int,
            default=24,
            help="hours of history to pull from Loki (default 24)",
        )

    p_profile = sub.add_parser("profile", help="build the baseline profile")
    add_source_opts(p_profile)
    p_profile.add_argument(
        "--profile-out", default="profile.pkl", help="output path for the pickled profile"
    )
    p_profile.set_defaults(func=cmd_profile)

    p_detect = sub.add_parser("detect", help="detect attacks against a baseline")
    add_source_opts(p_detect)
    p_detect.add_argument("--profile", required=True, help="path to the pickled profile")
    p_detect.add_argument("--report", help="optional path for the JSON report")
    p_detect.set_defaults(func=cmd_detect)

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
