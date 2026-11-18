"""Export flow features to CSV and pandas DataFrame.

Reference: FlowSentinel SRS v1.0 FR-FEA-06.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable
from dataclasses import fields
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO

from flowsentinel.features.flow import FlowFeatures

if TYPE_CHECKING:
    import pandas as pd


def _to_record_dict(item: FlowFeatures | dict[str, Any]) -> dict[str, Any]:
    if isinstance(item, FlowFeatures):
        return item.to_dict()
    return dict(item)


def export_csv(
    features: Iterable[FlowFeatures | dict[str, Any]],
    target: str | Path | TextIO,
) -> None:
    """Export flow features to a CSV destination (filepath or writable stream).

    Uses only the Python standard library csv module.
    """
    records = [_to_record_dict(f) for f in features]
    if not records:
        fieldnames = [f.name for f in fields(FlowFeatures)]
    else:
        fieldnames = list(records[0].keys())

    if isinstance(target, (str, Path)):
        path = Path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            if records:
                writer.writerows(records)
    else:
        writer = csv.DictWriter(target, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        if records:
            writer.writerows(records)


def export_dataframe(features: Iterable[FlowFeatures | dict[str, Any]]) -> pd.DataFrame:
    """Export flow features as a pandas DataFrame.

    Raises ImportError if pandas is not installed.
    """
    try:
        import pandas as pd
    except ImportError as exc:
        raise ImportError(
            "pandas is required for export_dataframe; install flowsentinel[ml] or pandas."
        ) from exc

    records = [_to_record_dict(f) for f in features]
    if not records:
        columns = [f.name for f in fields(FlowFeatures)]
        return pd.DataFrame(columns=columns)
    return pd.DataFrame.from_records(records)
