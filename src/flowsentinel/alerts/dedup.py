from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from flowsentinel.detectors.base import Alert

DEFAULT_COOLDOWN_S: Final[float] = 60.0


@dataclass(slots=True)
class _AlertDeduplicationRecord:
    last_emitted_ts: float
    suppressed_count: int


class AlertDeduplicator:
    """Suppresses duplicate alerts matching (type, src_ip, dst_ip, dst_port) within cooldown_s.

    Reference: FR-DET-08.
    """

    def __init__(self, cooldown_s: float = DEFAULT_COOLDOWN_S) -> None:
        if cooldown_s <= 0:
            raise ValueError(f"cooldown_s must be positive, got {cooldown_s}")
        self.cooldown_s = float(cooldown_s)
        self._history: dict[tuple[str, str, str, int | None], _AlertDeduplicationRecord] = {}

    def _make_key(self, alert: Alert) -> tuple[str, str, str, int | None]:
        return (alert.type, alert.src_ip, alert.dst_ip, alert.dst_port)

    def prune(self, current_time: float) -> None:
        """Discard suppression records older than 2 * cooldown_s to prevent memory growth."""
        cutoff = current_time - (2 * self.cooldown_s)
        for key in list(self._history.keys()):
            if self._history[key].last_emitted_ts < cutoff:
                del self._history[key]

    def process_alert(self, alert: Alert, current_ts: float | None = None) -> Alert | None:
        """Process an alert: emit if new or cooldown elapsed, else increment suppression counter."""
        ts = time.time() if current_ts is None else current_ts
        self.prune(ts)

        key = self._make_key(alert)
        record = self._history.get(key)

        if record is not None and (ts - record.last_emitted_ts) < self.cooldown_s:
            # Within cooldown: suppress and increment counter
            record.suppressed_count += 1
            return None

        # Outside cooldown or first time seeing key: emit alert
        suppressed_so_far = record.suppressed_count if record is not None else 0
        alert.suppressed_count = suppressed_so_far

        self._history[key] = _AlertDeduplicationRecord(
            last_emitted_ts=ts,
            suppressed_count=0,
        )
        return alert
