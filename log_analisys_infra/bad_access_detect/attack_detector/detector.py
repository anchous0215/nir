"""
detector.py
===========

χ² attack detection over a 3-minute sliding window

Pipeline per window:

1. Filter eventsand build observed equivalence classes
2. Apply Laplace smoothing
3. Compute expected counts
4. Merge classes with "expected counts" < 5 into a single aggregate class
5. Compute χ² value
6. Compute df value
7. Compute χ²_critvalue
8. Get analisys result
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from scipy.stats import chi2 as _chi2_dist

from .profiler import ClassKey

ALPHA = 0.05
MIN_EXPECTED = 5.0  # E_{i,k} threshold for merging

def apply_laplace_smoothing(
    observed: Dict[ClassKey, int],
    profile: Dict[ClassKey, float],
) -> Tuple[Dict[ClassKey, float], Dict[ClassKey, float]]:
    """
    Apply Laplace smoothing across the union of profile classes and
    currently observed classes.

    Returns ``(smoothed_observed, smoothed_profile)`` over the **same** key
    set, so the two distributions are directly comparable.
    """
    keys = set(observed) | set(profile)

    smoothed_observed: Dict[ClassKey, float] = {}
    smoothed_profile: Dict[ClassKey, float] = {}
    for key in keys:
        smoothed_observed[key] = observed.get(key, 0) + 1.0
        smoothed_profile[key] = profile.get(key, 0.0) + 1.0

    return smoothed_observed, smoothed_profile


def compute_expected(
    smoothed_observed: Dict[ClassKey, float],
    smoothed_profile: Dict[ClassKey, float],
) -> Dict[ClassKey, float]:
    """
    Compute expected counts
    """
    total_observed = sum(smoothed_observed.values())
    total_profile = sum(smoothed_profile.values())
    if total_profile <= 0:
        n = len(smoothed_observed) or 1
        return {k: total_observed / n for k in smoothed_observed}

    return {
        key: (smoothed_profile[key] / total_profile) * total_observed
        for key in smoothed_observed
    }

def merge_low_expected(
    observed: Dict[ClassKey, float],
    expected: Dict[ClassKey, float],
    min_expected: float = MIN_EXPECTED,
) -> Tuple[List[float], List[float]]:
    """
    Merge every class whose expected count is ``< min_expected`` into a single
    aggregate class.

    Returns two aligned lists ``(observed_counts, expected_counts)`` ready for
    the χ² summation.
    """
    obs_out: List[float] = []
    exp_out: List[float] = []
    merged_obs = 0.0
    merged_exp = 0.0
    has_merged = False

    for key, exp in expected.items():
        obs = observed.get(key, 0.0)
        if exp < min_expected:
            merged_obs += obs
            merged_exp += exp
            has_merged = True
        else:
            obs_out.append(obs)
            exp_out.append(exp)

    if has_merged:
        obs_out.append(merged_obs)
        exp_out.append(merged_exp)

    return obs_out, exp_out

def compute_chi2(
    observed: List[float],
    expected: List[float],
) -> float:
    """
    Pearson χ² statistic.
    """
    chi2_value = 0.0
    for o, e in zip(observed, expected):
        if e > 0:
            chi2_value += (o - e) ** 2 / e
    return chi2_value


def degrees_of_freedom(num_classes: int) -> int:
    """``df = |L_i/R| − 1`` (formula 10), clamped to a minimum of 1."""
    return max(num_classes - 1, 1)


def chi2_critical(df: int, alpha: float = ALPHA) -> float:
    """``χ²_crit = scipy.stats.chi2.ppf(1 − α, df)`` (default α = 0.05)."""
    return float(_chi2_dist.ppf(1.0 - alpha, df))

def detect_attack(
    observed_classes: Dict[ClassKey, int],
    profile: Dict[ClassKey, float],
    alpha: float = ALPHA,
    min_expected: float = MIN_EXPECTED,
) -> Dict[str, object]:
    """
    Run the full χ² decision for a single detection window.

    Parameters
    ----------
    observed_classes:
        ``class_key -> count`` for the window events.
    profile:
        The baseline hour-slice ``class_key -> probability``.
    alpha:
        Significance level.
    min_expected:
        Threshold below which classes are merged.

    Returns a result dict with keys ``chi2``, ``chi2_crit``, ``df``,
    ``is_attack`` (``F(L) ∈ {0,1}``) and ``num_classes``.
    """
    if not observed_classes:
        return {
            "chi2": 0.0,
            "chi2_crit": chi2_critical(1, alpha),
            "df": 1,
            "is_attack": 0,
            "num_classes": 0,
        }

    smoothed_obs, smoothed_prof = apply_laplace_smoothing(observed_classes, profile)

    df = degrees_of_freedom(len(smoothed_obs))

    expected = compute_expected(smoothed_obs, smoothed_prof)

    obs_list, exp_list = merge_low_expected(smoothed_obs, expected, min_expected)

    chi2_value = compute_chi2(obs_list, exp_list)

    crit = chi2_critical(df, alpha)

    is_attack = 1 if chi2_value > crit else 0

    return {
        "chi2": chi2_value,
        "chi2_crit": crit,
        "df": df,
        "is_attack": is_attack,
        "num_classes": len(smoothed_obs),
    }
