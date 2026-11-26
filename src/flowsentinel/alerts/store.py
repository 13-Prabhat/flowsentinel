from __future__ import annotations

import csv
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, TextIO

from flowsentinel.detectors.base import Alert

SCHEMA_VERSION = 1


class AlertStore:
    """Thread-safe SQLite storage for intrusion alerts with WAL mode (FR-ALR-03, NFR-REL-03)."""

    def __init__(
        self,
        db_path: str | Path = ":memory:",
        auto_purge_days: int | None = None,
    ) -> None:
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

        if self.db_path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL;")

        self._init_schema()

        if auto_purge_days is not None and auto_purge_days > 0:
            self.purge_older_than(days=auto_purge_days)

    def _init_schema(self) -> None:
        with self.conn:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    detector TEXT NOT NULL,
                    score REAL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER,
                    protocol TEXT NOT NULL,
                    flow_id TEXT,
                    reasons TEXT NOT NULL,
                    suppressed_count INTEGER DEFAULT 0,
                    model_version TEXT
                );
                """
            )
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(type);")
            self.conn.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?);",
                (str(SCHEMA_VERSION),),
            )

    @property
    def schema_version(self) -> int:
        cur = self.conn.execute("SELECT value FROM meta WHERE key = 'schema_version';")
        row = cur.fetchone()
        return int(row["value"]) if row else SCHEMA_VERSION

    def add_alert(self, alert: Alert) -> int:
        """Insert an alert into SQLite and set its auto-increment ID (FR-ALR-01, FR-ALR-03)."""
        reasons_json = json.dumps(alert.reasons)
        query = """
            INSERT INTO alerts (
                ts, type, severity, detector, score, src_ip, dst_ip, dst_port,
                protocol, flow_id, reasons, suppressed_count, model_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        with self.conn:
            cur = self.conn.execute(
                query,
                (
                    alert.timestamp,
                    alert.type,
                    alert.severity,
                    alert.detector,
                    alert.score,
                    alert.src_ip,
                    alert.dst_ip,
                    alert.dst_port,
                    alert.protocol,
                    alert.flow_id,
                    reasons_json,
                    alert.suppressed_count,
                    alert.model_version,
                ),
            )
            alert_id = int(cur.lastrowid)  # type: ignore[arg-type]
            alert.id = alert_id
            return alert_id

    def get_alert(self, alert_id: int) -> Alert | None:
        """Fetch single alert by primary key ID."""
        cur = self.conn.execute("SELECT * FROM alerts WHERE id = ?;", (alert_id,))
        row = cur.fetchone()
        if not row:
            return None
        return self._row_to_alert(row)

    def count_alerts(self) -> int:
        """Return total number of alerts recorded."""
        cur = self.conn.execute("SELECT COUNT(*) AS cnt FROM alerts;")
        return int(cur.fetchone()["cnt"])

    def query_alerts(
        self,
        since: str | None = None,
        until: str | None = None,
        alert_type: str | None = None,
        severity: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Alert]:
        """Query stored alerts with filtering and pagination (FR-ALR-05)."""
        conditions = []
        params: list[Any] = []

        if since:
            conditions.append("ts >= ?")
            params.append(since)
        if until:
            conditions.append("ts <= ?")
            params.append(until)
        if alert_type:
            conditions.append("type = ?")
            params.append(alert_type)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if src_ip:
            conditions.append("src_ip = ?")
            params.append(src_ip)
        if dst_ip:
            conditions.append("dst_ip = ?")
            params.append(dst_ip)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"""
            SELECT * FROM alerts
            {where_clause}
            ORDER BY id DESC
            LIMIT ? OFFSET ?;
        """
        params.extend([max(1, limit), max(0, offset)])

        cur = self.conn.execute(query, params)
        return [self._row_to_alert(row) for row in cur.fetchall()]

    def purge_older_than(self, days: int = 30) -> int:
        """Purge alerts older than a configurable retention period (FR-ALR-06)."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        with self.conn:
            cur = self.conn.execute("DELETE FROM alerts WHERE ts < ?;", (cutoff,))
            return cur.rowcount

    def export_jsonl(self, target: str | Path | TextIO) -> int:
        """Export all alerts as UTF-8 JSON Lines, one object per line (FR-ALR-04, NFR-PRT-05)."""
        alerts = self.query_alerts(limit=1_000_000)
        lines = [json.dumps(a.to_dict()) + "\n" for a in alerts]

        if isinstance(target, (str, Path)):
            path = Path(target)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="utf-8") as f:
                f.writelines(lines)
        else:
            target.writelines(lines)
        return len(lines)

    def export_csv(self, target: str | Path | TextIO) -> int:
        """Export all alerts to CSV format (FR-ALR-04)."""
        alerts = self.query_alerts(limit=1_000_000)
        fieldnames = [
            "id",
            "timestamp",
            "type",
            "severity",
            "detector",
            "score",
            "src_ip",
            "dst_ip",
            "dst_port",
            "protocol",
            "flow_id",
            "reasons",
            "suppressed_count",
            "model_version",
        ]

        def _format_row(a: Alert) -> dict[str, Any]:
            d = a.to_dict()
            d["reasons"] = "; ".join(a.reasons)
            return d

        if isinstance(target, (str, Path)):
            path = Path(target)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
                writer.writeheader()
                for a in alerts:
                    writer.writerow(_format_row(a))
        else:
            writer = csv.DictWriter(target, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            for a in alerts:
                writer.writerow(_format_row(a))

        return len(alerts)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> AlertStore:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> Alert:
        reasons_raw = row["reasons"]
        reasons = json.loads(reasons_raw) if reasons_raw else []
        return Alert(
            id=row["id"],
            timestamp=row["ts"],
            type=row["type"],
            severity=row["severity"],
            detector=row["detector"],
            score=row["score"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            dst_port=row["dst_port"],
            protocol=row["protocol"],
            flow_id=row["flow_id"],
            reasons=reasons,
            suppressed_count=row["suppressed_count"],
            model_version=row["model_version"],
        )
