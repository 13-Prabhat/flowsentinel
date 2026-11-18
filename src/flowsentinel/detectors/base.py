from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class Alert:
    """Standard FlowSentinel intrusion alert record (SRS Section 7.4)."""

    type: str
    severity: str
    detector: str
    src_ip: str
    dst_ip: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    )
    id: int | None = None
    dst_port: int | None = None
    protocol: str = "tcp"
    flow_id: str | None = None
    score: float | None = None
    reasons: list[str] = field(default_factory=list)
    suppressed_count: int = 0
    model_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert alert to serializable dictionary."""
        return asdict(self)


class BaseDetector(ABC):
    """Abstract base class for all rule and ML intrusion detectors (FR-DET-07)."""

    def __init__(self, name: str, enabled: bool = True) -> None:
        self.name = name
        self.enabled = bool(enabled)

    @staticmethod
    def validate_range(
        key: str,
        value: float | int,
        min_val: float | int,
        max_val: float | int,
    ) -> None:
        """Validate threshold parameter range, raising ValueError if invalid (FR-DET-05)."""
        if not (min_val <= value <= max_val):
            raise ValueError(
                f"Invalid configuration for '{key}': value {value} is out of allowed range "
                f"[{min_val}, {max_val}]."
            )

    @abstractmethod
    def evaluate(self, *args: Any, **kwargs: Any) -> list[Alert]:
        """Evaluate traffic evidence and return any detected intrusion alerts."""
        raise NotImplementedError
