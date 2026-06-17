"""
CLI entry point for the Mahalanobis-distance cipher-stage detector.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List

from . import metrics_collector as mc
from . import utils
from .detector import detect_attack
from .profiler import (
    PROFILE_WINDOW,
    build_profile,
    load_profile,
    save_profile,
)

logger = logging.getLogger("cipher_detector")

DETECTION_WINDOW = timedelta(minutes=15)

def _load_samples(args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Load raw metric samples from a JSON file or from Prometheus."""
    if args.file:
        logger.info("Loading metrics from file: %s", args.file)
        return mc.load_metrics_from_file(args.file)
    logger.info("Querying Prometheus at %s", args.prometheus_url)
    window_sec = args.window_hours * 3600
    return mc.query_prometheus(
        prometheus_url=args.prometheus_url,
        namespace=args.namespace,
        window_sec=window_sec,
        step_sec=args.step_sec,
    )


def _windows_to_vectors(
    samples: List[Dict[str, Any]],
    window: timedelta,
):
    """Yield ``(window_start, vector)`` for every non-empty window."""
    for win_start, bucket in utils.sliding_windows(
        samples, window=window, step=window
    ):
        vector = mc.window_to_vector(bucket, window)
        if vector is not None:
            yield win_start, vector


def cmd_profile(args: argparse.Namespace) -> int:
    samples = _load_samples(args)
    logger.info("Loaded %d raw metric samples", len(samples))

    vectors = [vec for _, vec in _windows_to_vectors(samples, PROFILE_WINDOW)]
    if not vectors:
        logger.error("No observation vectors produced — cannot build a profile")
        return 1

    profile = build_profile(vectors)
    logger.info(
        "Profile built from %d window-vectors; D²_max=%.4f",
        profile["n_samples"],
        profile["d2_max"],
    )

    save_profile(profile, args.profile_out)
    logger.info("Profile saved to %s", args.profile_out)
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile)
    logger.info("Loaded profile (D²_max=%.4f)", profile["d2_max"])

    samples = _load_samples(args)
    logger.info("Loaded %d raw metric samples", len(samples))

    records: List[Dict[str, Any]] = []
    attacks = 0

    for win_start, vector in _windows_to_vectors(samples, DETECTION_WINDOW):
        result = detect_attack(vector, profile)

        record = {
            "window_start": win_start,
            "mahalanobis_d2": result["mahalanobis_d2"],
            "d2_max": result["d2_max"],
            "is_attack": bool(result["is_attack"]),
            "metrics": mc.vector_to_metrics(vector),
        }
        records.append(record)
        attacks += int(record["is_attack"])

        print(utils.format_window_line(record))

        if record["is_attack"] and not args.no_loki:
            try:
                utils.push_to_loki(
                    record, loki_url=args.loki_url, severity="critical"
                )
            except Exception as exc: 
                logger.warning("Failed to push to Loki: %s", exc)

    total = len(records)
    logger.info(
        "Processed %d windows, %d flagged as cipher attacks (%.1f%%)",
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
        prog="cipher_detector",
        description="Mahalanobis-distance ransomware cipher-stage detector for "
        "Kubernetes filesystem metrics.",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="enable debug logging"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    def add_source_opts(p: argparse.ArgumentParser) -> None:
        p.add_argument("--file", help="path to a JSON metrics file")
        p.add_argument(
            "--prometheus-url",
            default=mc.PROMETHEUS_URL,
            help="Prometheus base URL",
        )
        p.add_argument(
            "--namespace", default=mc.NAMESPACE, help="Kubernetes namespace"
        )
        p.add_argument(
            "--window-hours",
            type=int,
            default=24,
            help="hours of history to pull from Prometheus (default 24)",
        )
        p.add_argument(
            "--step-sec",
            type=int,
            default=60,
            help="Prometheus query_range step in seconds (default 60)",
        )

    p_profile = sub.add_parser("profile", help="build the baseline profile")
    add_source_opts(p_profile)
    p_profile.add_argument(
        "--profile-out",
        default="cipher_profile.pkl",
        help="output path for the pickled profile",
    )
    p_profile.set_defaults(func=cmd_profile)

    p_detect = sub.add_parser("detect", help="detect cipher stage against a baseline")
    add_source_opts(p_detect)
    p_detect.add_argument(
        "--profile", required=True, help="path to the pickled profile"
    )
    p_detect.add_argument("--report", help="optional path for the JSON report")
    p_detect.add_argument(
        "--loki-url", default=utils.LOKI_URL, help="Loki base URL for push"
    )
    p_detect.add_argument(
        "--no-loki",
        action="store_true",
        help="do not push detected attacks to Loki",
    )
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
