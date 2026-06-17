"""
Builds the reference behaviour profile for the encryption stage using
the **Mahalanobis distance** method.

Procedure:
1. Collect ~24h of raw metric samples during normal operation.
2. Discretise with a 1-hour sliding window  →  observation vectors.
3. Stack them into the observation matrix.
4. Mean vector.
5. Covariance matrix.
6. Regularisation.
7. Inverse covariance.
8. Mahalanobis distances.
9. Threshold.
"""

from __future__ import annotations

import pickle
from datetime import timedelta
from typing import Any, Dict, List

import numpy as np

PROFILE_WINDOW = timedelta(minutes=15)
ALPHA = 0.95
LAMBDA = 0.01
DET_EPS = 1e-12


def build_observation_matrix(vectors: List[List[float]]) -> np.ndarray:
    """
    Stack a list of 4-D observation vectors into an matrix.
    """
    if not vectors:
        raise ValueError("No observation vectors supplied")
    matrix = np.asarray(vectors, dtype=float)
    if matrix.ndim != 2 or matrix.shape[1] != 4:
        raise ValueError("Observation matrix must have shape (N, 4)")
    return matrix


def compute_mean_vector(matrix: np.ndarray) -> np.ndarray:
    """``μ_j = (1/N) Σ_i x_{i,j}`` — column means of the observation matrix."""
    return matrix.mean(axis=0)


def compute_covariance_matrix(
    matrix: np.ndarray,
    lam: float = LAMBDA,
    det_eps: float = DET_EPS,
) -> np.ndarray:
    """
    Sample covariance.
    When the matrix is singular the regularisation is applied. 
    A single observation yields a zero covariance which is likewise regularised.
    """
    n = matrix.shape[0]
    if n < 2:
        return np.eye(matrix.shape[1]) * lam

    cov = np.cov(matrix, rowvar=False, bias=False)
    cov = np.atleast_2d(cov)

    if abs(np.linalg.det(cov)) < det_eps:
        cov = cov + lam * np.eye(cov.shape[0])

    return cov


def compute_inverse_covariance(
    cov: np.ndarray,
    lam: float = LAMBDA,
) -> np.ndarray:
    """
    Invert the covariance matrix. Falls back to the Moore–Penrose
    pseudo-inverse after an extra regularisation pass if is singular.
    """
    try:
        return np.linalg.inv(cov)
    except np.linalg.LinAlgError:
        regularised = cov + lam * np.eye(cov.shape[0])
        try:
            return np.linalg.inv(regularised)
        except np.linalg.LinAlgError:
            return np.linalg.pinv(regularised)


def compute_mahalanobis(
    vector: np.ndarray,
    mu: np.ndarray,
    inv_cov: np.ndarray,
) -> float:
    """
    Squared Mahalanobis distance.
    """
    diff = np.asarray(vector, dtype=float) - np.asarray(mu, dtype=float)
    d2 = float(diff.T @ inv_cov @ diff)
    # numerical floor — D² is non-negative by definition
    return max(d2, 0.0)


def compute_threshold(
    matrix: np.ndarray,
    mu: np.ndarray,
    inv_cov: np.ndarray,
    alpha: float = ALPHA,
) -> float:
    """
    Оver all baseline observation vectors.
    """
    distances = [compute_mahalanobis(row, mu, inv_cov) for row in matrix]
    return max(distances) * alpha if distances else 0.0


def build_profile(
    vectors: List[List[float]],
    alpha: float = ALPHA,
    lam: float = LAMBDA,
) -> Dict[str, Any]:
    """
    Run the complete training pipeline on the baseline observation vectors and
    return the profile dict.
    """
    matrix = build_observation_matrix(vectors)
    mu = compute_mean_vector(matrix)
    cov = compute_covariance_matrix(matrix, lam=lam)
    inv_cov = compute_inverse_covariance(cov, lam=lam)
    d2_max = compute_threshold(matrix, mu, inv_cov, alpha=alpha)

    return {
        "mu": mu,
        "inv_cov": inv_cov,
        "d2_max": d2_max,
        "n_samples": int(matrix.shape[0]),
    }


def save_profile(profile: Dict[str, Any], path: str) -> None:
    """Serialise the profile"""
    with open(path, "wb") as fh:
        pickle.dump(profile, fh, protocol=pickle.HIGHEST_PROTOCOL)


def load_profile(path: str) -> Dict[str, Any]:
    """Load a profile previously saved by :func:`save_profile`."""
    with open(path, "rb") as fh:
        return pickle.load(fh)
