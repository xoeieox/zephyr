"""Settlement intent queue - append-only SQLite log for settlement intents.

Separate from the attribution DB, with its own connection (never shares
the attribution log's thread-unsafe SQLite handle). Written from a background
thread to avoid blocking record().

Append-only: intents cycle through statuses pending → in_flight → settled/no-route/failed.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

DEFAULT_QUEUE_DB = Path(
    os.environ.get("ZEPHYR_INTENT_QUEUE_DB", "/data/zephyr/intent_queue.db")
)

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS settlement_intents (
    manifest_hash   TEXT PRIMARY KEY,
    pubkey_id       TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    amount          INTEGER NOT NULL,
    asset_code      TEXT NOT NULL,
    asset_scale     INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    worker_id       TEXT,
    op_payment_id   TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS intents_status ON settlement_intents(status);
CREATE INDEX IF NOT EXISTS intents_pubkey ON settlement_intents(pubkey_id);
"""


class SettlementIntentQueue:
    """SQLite-backed append-only intent queue with background thread writes."""

    def __init__(self, db_path: Path | str = DEFAULT_QUEUE_DB):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.Lock()
        # Own connection (not shared with attribution log)
        self._write_conn = sqlite3.connect(
            str(self.db_path), check_same_thread=False, timeout=10.0
        )
        self._write_conn.row_factory = sqlite3.Row
        self._write_conn.executescript(_SCHEMA)
        self._write_conn.commit()

    def append(self, manifest_hash: str, provenance: dict) -> bool:
        """Append a new settlement intent for a signed deposit.

        Returns True if the intent was appended (new), False if it already existed.

        The intent's initial status is 'pending'. It carries the deposit's
        manifest_hash, pubkey_id, agent_id, and timestamp, plus v0 flat nominal
        values (amount=$0.01 USD, asset_scale=2).
        """
        now = datetime.now(timezone.utc).isoformat()
        manifest_hash = provenance.get("manifest_hash")
        pubkey_id = provenance.get("pubkey_id")
        agent_id = provenance.get("agent_id", "")
        timestamp = provenance.get("timestamp", now)

        with self._write_lock:
            cur = self._write_conn.execute(
                "INSERT OR IGNORE INTO settlement_intents "
                "(manifest_hash, pubkey_id, agent_id, timestamp, "
                " amount, asset_code, asset_scale, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    manifest_hash,
                    pubkey_id,
                    agent_id,
                    timestamp,
                    1,  # amount in cents: $0.01
                    "USD",
                    2,  # asset_scale
                    "pending",
                    now,
                    now,
                ),
            )
            self._write_conn.commit()
            return cur.rowcount > 0

    def get(self, manifest_hash: str) -> dict | None:
        """Retrieve an intent by manifest_hash."""
        with self._write_lock:
            row = self._write_conn.execute(
                "SELECT * FROM settlement_intents WHERE manifest_hash = ?",
                (manifest_hash,),
            ).fetchone()
        return dict(row) if row else None

    def pending(self, limit: int = 100) -> list[dict]:
        """Return pending intents, oldest first."""
        with self._write_lock:
            rows = self._write_conn.execute(
                "SELECT * FROM settlement_intents WHERE status = 'pending' "
                "ORDER BY created_at ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def claim(self, manifest_hash: str) -> bool:
        """Atomically transition an intent from 'pending' to 'in_flight'.

        Returns True if the transition succeeded (intent was pending).
        Returns False if the intent was not pending (already claimed or settled).

        Used by the settler to claim intents for processing without double-processing.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._write_lock:
            cur = self._write_conn.execute(
                "UPDATE settlement_intents SET status = 'in_flight', updated_at = ? "
                "WHERE manifest_hash = ? AND status = 'pending'",
                (now, manifest_hash),
            )
            self._write_conn.commit()
            return cur.rowcount > 0

    def settle(
        self, manifest_hash: str, op_payment_id: str | None = None, worker_id: str | None = None
    ) -> bool:
        """Mark an intent as settled with optional OP payment ID and worker ID."""
        now = datetime.now(timezone.utc).isoformat()
        with self._write_lock:
            self._write_conn.execute(
                "UPDATE settlement_intents "
                "SET status = 'settled', op_payment_id = ?, worker_id = ?, updated_at = ? "
                "WHERE manifest_hash = ?",
                (op_payment_id, worker_id, now, manifest_hash),
            )
            self._write_conn.commit()

    def mark_no_route(self, manifest_hash: str) -> bool:
        """Mark an intent as 'no-route' (missing/broken wallet hint).

        Returns True if the transition succeeded.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._write_lock:
            cur = self._write_conn.execute(
                "UPDATE settlement_intents "
                "SET status = 'no-route', updated_at = ? "
                "WHERE manifest_hash = ? AND status = 'in_flight'",
                (now, manifest_hash),
            )
            self._write_conn.commit()
            return cur.rowcount > 0

    def mark_failed(self, manifest_hash: str, worker_id: str | None = None) -> bool:
        """Mark an intent as failed (max retries exceeded).

        Returns True if the transition succeeded.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._write_lock:
            cur = self._write_conn.execute(
                "UPDATE settlement_intents "
                "SET status = 'failed', worker_id = ?, updated_at = ? "
                "WHERE manifest_hash = ? AND status = 'in_flight'",
                (worker_id, now, manifest_hash),
            )
            self._write_conn.commit()
            return cur.rowcount > 0

    def count(self, status: str | None = None) -> int:
        """Count intents, optionally filtered by status."""
        with self._write_lock:
            if status:
                return self._write_conn.execute(
                    "SELECT COUNT(*) AS n FROM settlement_intents WHERE status = ?",
                    (status,),
                ).fetchone()["n"]
            return self._write_conn.execute(
                "SELECT COUNT(*) AS n FROM settlement_intents"
            ).fetchone()["n"]


# Process-wide singleton
_QUEUE: SettlementIntentQueue | None = None
_QUEUE_LOCK = threading.Lock()


def get_queue() -> SettlementIntentQueue:
    """Return the process-wide SettlementIntentQueue singleton."""
    global _QUEUE
    if _QUEUE is None:
        with _QUEUE_LOCK:
            if _QUEUE is None:
                _QUEUE = SettlementIntentQueue()
    return _QUEUE
