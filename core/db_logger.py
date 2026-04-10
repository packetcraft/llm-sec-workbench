"""
core/db_logger.py
─────────────────
Lightweight SQLite persistence layer for completed PipelinePayload runs.

Uses SQLAlchemy Core (no ORM session complexity) with a single table:
  pipeline_runs

Every finalized payload is serialised into one row. Complex fields
(metrics list, raw_traces dict) are stored as JSON strings so the schema
stays flat and query-friendly without a separate normalisation step.

Usage
-----
    from core.db_logger import DBLogger

    logger = DBLogger()                      # creates workbench.sqlite if absent
    logger.save(payload)                     # persist one completed run
    rows = logger.get_recent(limit=50)       # list[dict] newest-first
    logger.close()

The logger is intentionally optional — the pipeline continues if the DB
write fails (errors are printed, not raised).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
    select,
    text,
)
from sqlalchemy import MetaData, Table

if TYPE_CHECKING:
    # Imported only for type hints; avoids a hard dependency on Phase 2 code.
    from core.payload import PipelinePayload

# ── Database file path ────────────────────────────────────────────────────────
_DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "workbench.sqlite",
)

# ── Schema ────────────────────────────────────────────────────────────────────
_metadata = MetaData()

pipeline_runs = Table(
    "pipeline_runs",
    _metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    # Timestamps
    Column("created_at", DateTime(timezone=True), nullable=False),
    # Core payload fields
    Column("original_input", Text, nullable=False),
    Column("current_text", Text, nullable=False),
    Column("output_text", Text, nullable=True),
    Column("is_blocked", Boolean, nullable=False, default=False),
    Column("block_reason", String(512), nullable=True),
    # Token telemetry
    Column("prompt_tokens", Integer, nullable=True),
    Column("completion_tokens", Integer, nullable=True),
    Column("tokens_per_second", Float, nullable=True),
    # JSON-encoded complex fields
    Column("metrics_json", Text, nullable=True),      # list[dict]
    Column("raw_traces_json", Text, nullable=True),   # dict
)


class DBLogger:
    """Persists completed pipeline runs to a local SQLite database.

    Args:
        db_path: Absolute or relative path to the SQLite file.
                 Defaults to ``workbench.sqlite`` in the project root.
    """

    def __init__(self, db_path: str = _DEFAULT_DB_PATH) -> None:
        self._engine = create_engine(
            f"sqlite:///{db_path}",
            connect_args={"check_same_thread": False},
            echo=False,
        )
        _metadata.create_all(self._engine)

    # ── Public API ────────────────────────────────────────────────────────────

    def save(self, payload: "PipelinePayload") -> int | None:
        """Insert a completed payload row.

        Accepts any object that exposes the PipelinePayload attribute names
        (duck typing), so the logger can be exercised before Phase 2 lands.

        Returns:
            The new row ``id`` on success, or ``None`` if the write failed.
        """
        try:
            row = self._payload_to_row(payload)
            with self._engine.begin() as conn:
                result = conn.execute(pipeline_runs.insert().values(**row))
                return result.inserted_primary_key[0]
        except Exception as exc:  # noqa: BLE001
            print(f"[DBLogger] Failed to save payload: {exc}")
            return None

    def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return the most recent ``limit`` rows, newest first.

        Returns:
            A list of plain dicts, one per row.
        """
        try:
            stmt = (
                select(pipeline_runs)
                .order_by(pipeline_runs.c.id.desc())
                .limit(limit)
            )
            with self._engine.connect() as conn:
                rows = conn.execute(stmt).mappings().all()
            return [self._deserialise_row(dict(r)) for r in rows]
        except Exception as exc:  # noqa: BLE001
            print(f"[DBLogger] Failed to fetch rows: {exc}")
            return []

    def get_by_id(self, run_id: int) -> dict[str, Any] | None:
        """Fetch a single run by primary key.

        Returns:
            A plain dict, or ``None`` if not found.
        """
        try:
            stmt = select(pipeline_runs).where(pipeline_runs.c.id == run_id)
            with self._engine.connect() as conn:
                row = conn.execute(stmt).mappings().first()
            if row is None:
                return None
            return self._deserialise_row(dict(row))
        except Exception as exc:  # noqa: BLE001
            print(f"[DBLogger] Failed to fetch run {run_id}: {exc}")
            return None

    def clear(self) -> None:
        """Delete all rows (useful for test teardown)."""
        with self._engine.begin() as conn:
            conn.execute(pipeline_runs.delete())

    def close(self) -> None:
        """Dispose of the connection pool."""
        self._engine.dispose()

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _payload_to_row(payload: Any) -> dict[str, Any]:
        """Serialise a PipelinePayload (or duck-typed equivalent) to a row dict."""
        return {
            "created_at": datetime.now(tz=timezone.utc),
            "original_input": getattr(payload, "original_input", ""),
            "current_text": getattr(payload, "current_text", ""),
            "output_text": getattr(payload, "output_text", None),
            "is_blocked": bool(getattr(payload, "is_blocked", False)),
            "block_reason": getattr(payload, "block_reason", None),
            "prompt_tokens": getattr(payload, "prompt_tokens", None),
            "completion_tokens": getattr(payload, "completion_tokens", None),
            "tokens_per_second": getattr(payload, "tokens_per_second", None),
            "metrics_json": json.dumps(
                getattr(payload, "metrics", []), default=str
            ),
            "raw_traces_json": json.dumps(
                getattr(payload, "raw_traces", {}), default=str
            ),
        }

    @staticmethod
    def _deserialise_row(row: dict[str, Any]) -> dict[str, Any]:
        """Expand JSON columns back to Python objects."""
        for json_col, target_key in (
            ("metrics_json", "metrics"),
            ("raw_traces_json", "raw_traces"),
        ):
            raw = row.pop(json_col, None)
            try:
                row[target_key] = json.loads(raw) if raw else ([] if target_key == "metrics" else {})
            except (json.JSONDecodeError, TypeError):
                row[target_key] = [] if target_key == "metrics" else {}
        return row
