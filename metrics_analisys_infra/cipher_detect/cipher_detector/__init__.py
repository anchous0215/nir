"""
Statistical (Mahalanobis-distance) detector for the **encryption stage** of a 
ransomware attack in a Kubernetes cluster.

The pipeline:
1. ``metrics_collector`` — collect the 4-D filesystem metric vector
   ``(CPU%, Disk bytes, I/O ops/s, Inodes used)`` from Prometheus.
2. ``profiler.build_profile`` — build the reference profile over a 1-hour
   sliding window across 24h of normal operation``.
3. ``detector.detect_attack`` — for every 15-minute window compute the squared
   Mahalanobis distance and flag an attack.

Detected attacks are pushed to Loki.
"""

from . import detector as detector  # noqa: F401
from . import metrics_collector as metrics_collector  # noqa: F401
from . import profiler as profiler  # noqa: F401
from . import utils as utils  # noqa: F401

__all__ = ["metrics_collector", "profiler", "detector", "utils"]
__version__ = "1.0.0"
