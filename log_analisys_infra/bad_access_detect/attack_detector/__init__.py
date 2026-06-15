"""
attack_detector
================

Statistical (χ²) intrusion-detection package for Kubernetes container logs.

1. ``filter.is_access_event``      — keep only access-related log events.
2. ``profiler.compute_baseline``   — build the per-hour reference profile
   (probabilities of equivalence classes over a 1-hour sliding window).
3. ``detector.detect_attack``      — for every 3-minute sliding window compare
   the observed class distribution against the baseline using Pearson's χ²
   goodness-of-fit test (with Laplace smoothing and low-expected merging).
"""

from . import filter as filter
from . import profiler as profiler
from . import detector as detector 
from . import utils as utils 

__all__ = ["filter", "profiler", "detector", "utils"]
__version__ = "1.0.0"
