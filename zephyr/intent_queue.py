"""Settlement intent queue - append-only SQLite log for settlement intents.

Separate from the attribution DB, with its own connection (never shares
the attribution log's thread-unsafe SQLite handle). Written from a background
thread to avoid blocking record().

Append-only: intents cycle through statuses pending → in_flight → settled/no-route/failed.

Retained as a module per decision/zephyr-stops-minting-payment-claims-2026-08-11
(R2/R3): Zephyr does not mint payment claims, so ``record()`` in attribution.py
no longer calls the append path here on every signed deposit. This writer
stays available for a future, explicitly declared dry run. The rows minted
by the removed default behavior were relabelled ``status='simulation'`` by
``zephyr/relabel_settlement_intents.py`` — see that module and
``zephyr/settlement_intent_readout.py`` for the residue and its readout.
``simulation`` was never an intended mode; it is defect residue.
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


def _default_queue_db() -> Path:
    """Resolve the default queue DB path from the environment, at call time.

    Deliberately NOT a frozen module-level constant: a module-level default
    is read once at import time, so a test that sets ZEPHYR_INTENT_QUEUE_DB
    after zephyr.intent_queue has already been imported (e.g. via an autouse
    pytest fixture) would silently miss it and fall through to the
    production path. This is exactly the mechanism that let test runs write
    7,141 test-shaped rows into /data/zephyr/intent_queue.db.
    """
    return Path(os.environ.get("ZEPHYR_INTENT_QUEUE_DB", "/data/zephyr/intent_queue.db"))


# Kept for introspection / backward compatibility. Reflects the environment
# at import time only — prefer _default_queue_db() (or just omit db_path,
# which resolves lazily) anywhere the current value matters.
DEFAULT_QUEUE_DB = _default_queue_db()

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

# Additive-only migration column (decision/zephyr-stops-minting-payment-claims-
# 2026-08-11, Leg 2): carries the relabel reason for rows moved out of
# 'pending'. Nullable; historical rows keep reading. Guarded by PRAGMA
# table_info in _migrate() so opening an already-migrated DB is a no-op.
_MIGRATION_COLS = [
    ("reason", "TEXT"),
]


class SettlementIntentQueue:
    """SQLite-backed append-only intent queue with background thread writes."""

    def __init__(self, db_path: Path | str | None = None):
        self.db_path = Path(db_path) if db_path is not None else _default_queue_db()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.Lock()
        # Own connection (not shared with attribution log)
        self._write_conn = sqlite3.connect(
            str(self.db_path), check_same_thread=False, timeout=10.0
        )
        self._write_conn.row_factory = sqlite3.Row
        self._write_conn.executescript(_SCHEMA)
        self._migrate()
        self._write_conn.commit()

    def _migrate(self) -> None:
        """Additive schema migration: add nullable columns if absent."""
        existing = {
            r["name"]
            for r in self._write_conn.execute(
                "PRAGMA table_info(settlement_intents)"
            ).fetchall()
        }
        for col, coltype in _MIGRATION_COLS:
            if col not in existing:
                self._write_conn.execute(
                    f"ALTER TABLE settlement_intents ADD COLUMN {col} {coltype}"
                )

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

    def relabel_pending_to_simulation(self, reason: str, *, execute: bool) -> int:
        """Move every 'pending' row to 'simulation', stamping *reason* on each.

        Used by zephyr/relabel_settlement_intents.py (decision/zephyr-stops-
        minting-payment-claims-2026-08-11, Leg 2). Touches only rows currently
        in 'pending' — never in_flight/settled/no-route/failed/simulation.

        *execute=False* (the safe default callers should use for a dry run)
        counts and returns the affected total without writing.
        *execute=True* performs the UPDATE and returns the number of rows
        changed. Idempotent: a second call with execute=True affects 0 rows,
        since the WHERE clause only ever matches status='pending'.
        """
        with self._write_lock:
            (pending_count,) = self._write_conn.execute(
                "SELECT COUNT(*) FROM settlement_intents WHERE status = 'pending'"
            ).fetchone()
            if execute and pending_count > 0:
                self._write_conn.execute(
                    "UPDATE settlement_intents "
                    "SET status = 'simulation', reason = ? "
                    "WHERE status = 'pending'",
                    (reason,),
                )
                self._write_conn.commit()
        return pending_count

    def simulation_summary(self) -> dict:
        """Read-only summary of 'simulation'-status rows (Leg 3 readout).

        Never writes. Returns count, (agent_id, count) pairs sorted by count
        descending, the created_at date range, and the summed nominal amount
        (a hardcoded placeholder, not a valuation — see
        zephyr/settlement_intent_readout.py).
        """
        with self._write_lock:
            (count,) = self._write_conn.execute(
                "SELECT COUNT(*) FROM settlement_intents WHERE status = 'simulation'"
            ).fetchone()
            by_agent = self._write_conn.execute(
                "SELECT agent_id, COUNT(*) AS n FROM settlement_intents "
                "WHERE status = 'simulation' GROUP BY agent_id ORDER BY n DESC"
            ).fetchall()
            date_range = self._write_conn.execute(
                "SELECT MIN(created_at), MAX(created_at) FROM settlement_intents "
                "WHERE status = 'simulation'"
            ).fetchone()
            (total_amount,) = self._write_conn.execute(
                "SELECT COALESCE(SUM(amount), 0) FROM settlement_intents "
                "WHERE status = 'simulation'"
            ).fetchone()

        return {
            "count": count,
            "by_agent": [(r["agent_id"], r["n"]) for r in by_agent],
            "date_range": (date_range[0], date_range[1]),
            "total_amount_cents": total_amount,
        }


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
