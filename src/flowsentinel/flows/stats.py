"""One-pass online running statistics using Welford's algorithm.

Provides O(1) memory and time per packet for min, mean, max, and standard deviation
without retaining historical packets (FR-FLW, FR-FEA-01, NFR-SCL-01).
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(slots=True)
class RunningStats:
    """Computes online min, mean, max, and sample standard deviation."""

    count: int = 0
    min_val: float = 0.0
    max_val: float = 0.0
    mean_val: float = 0.0
    m2: float = 0.0

    def update(self, x: float) -> None:
        """Add a new observation x."""
        self.count += 1
        if self.count == 1:
            self.min_val = float(x)
            self.max_val = float(x)
            self.mean_val = float(x)
            self.m2 = 0.0
            return

        if x < self.min_val:
            self.min_val = float(x)
        if x > self.max_val:
            self.max_val = float(x)

        delta = x - self.mean_val
        self.mean_val += delta / self.count
        delta2 = x - self.mean_val
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        """Sample variance (0.0 if count < 2)."""
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def std(self) -> float:
        """Sample standard deviation (0.0 if count < 2)."""
        if self.count < 2:
            return 0.0
        return math.sqrt(max(0.0, self.variance))
