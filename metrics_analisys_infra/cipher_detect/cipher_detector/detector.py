"""
Real-time cipher-stage detection.

For the current 15-minute window an observation vector is built and
its squared Mahalanobis distance to the baseline mean is computed
"""

from __future__ import annotations
from typing import Any, Dict, List
import numpy as np
from .profiler import compute_mahalanobis

__all__ = ["compute_mahalanobis", "detect_attack"]


def detect_attack(
    vector: List[float],
    profile: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Score one detection-window observation vector against the baseline profile.

    Parameters
    ----------
    vector:
        The 4-D observation vector for the current window.
    profile:
        The trained profile.

    Returns a result dict with keys ``mahalanobis_d2``, ``d2_max`` and ``is_attack``.
    """
    mu = np.asarray(profile["mu"], dtype=float)
    inv_cov = np.asarray(profile["inv_cov"], dtype=float)
    d2_max = float(profile["d2_max"])

    d2_cur = compute_mahalanobis(np.asarray(vector, dtype=float), mu, inv_cov)
    is_attack = 1 if d2_cur > d2_max else 0

    return {
        "mahalanobis_d2": d2_cur,
        "d2_max": d2_max,
        "is_attack": is_attack,
    }
