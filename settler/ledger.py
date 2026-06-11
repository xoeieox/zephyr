"""Settlement ledger - SQLite-backed record of settled intents.

Persists the outcome of each settlement attempt: which manifest_hash,
op_payment_id, pubkey_id, amount, etc.

Separate from the intent queue (they each have their own SQLite file).
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DEFAULT_LEDGER_DB = Path(
    os.environ.get("ZEPHYR_SETTLEMENT_LEDGER_DB", "/data/zephyr/settlement_ledger.db")
)

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS settlement_ledger (
    manifest_hash   TEXT NOT NULL,
    op_payment_id   TEXT,
    pubkey_id       TEXT NOT NULL,
    settled_at      TEXT,
    amount          INTEGER NOT NULL,
    asset_code      TEXT NOT NULL,
    status          TEXT NOT NULL,
    error_detail    TEXT,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (manifest_hash)
);
CREATE INDEX IF NOT EXISTS ledger_pubkey ON settlement_ledger(pubkey_id);
CREATE INDEX IF NOT EXISTS ledger_status ON settlement_ledger(status);
CREATE INDEX IF NOT EXISTS ledger_settled_at ON settlement_ledger(settled_at);
"""


class SettlementLedger:
    """SQLite-backed settlement ledger."""

    def __init__(self, db_path: Path | str = DEFAULT_LEDGER_DB):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.Lock()
        self._write_conn = sqlite3.connect(
            str(self.db_path), check_same_thread=False, timeout=10.0
        )
        self._write_conn.row_factory = sqlite3.Row
        self._write_conn.executescript(_SCHEMA)
        self._write_conn.commit()

    def record_settled(
        self,
        manifest_hash: str,
        pubkey_id: str,
        op_payment_id: str,
        amount: int,
        asset_code: str,
    ) -> None:
        """Record a successful settlement."""
        now = datetime.now(timezone.utc).isoformat()
        with self._write_lock:
            self._write_conn.execute(
                "INSERT OR REPLACE INTO settlement_ledger "
                "(manifest_hash, op_payment_id, pubkey_id, settled_at, "
                " amount, asset_code, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    manifest_hash,
                    op_payment_id,
                    pubkey_id,
                    now,
                    amount,
                    asset_code,
                    "settled",
                    now,
                ),
            )
            self._write_conn.commit()

    def record_no_route(
        self, manifest_hash: str, pubkey_id: str, amount: int, asset_code: str
    ) -> None:
        """Record an intent that had no wallet routing."""
        now = datetime.now(timezone.utc).isoformat()
        with self._write_lock:
            self._write_conn.execute(
                "INSERT OR REPLACE INTO settlement_ledger "
                "(manifest_hash, pubkey_id, amount, asset_code, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (manifest_hash, pubkey_id, amount, asset_code, "no-route", now),
            )
            self._write_conn.commit()

    def record_failed(
        self,
        manifest_hash: str,
        pubkey_id: str,
        amount: int,
        asset_code: str,
        error_detail: str,
    ) -> None:
        """Record a settlement that failed."""
        now = datetime.now(timezone.utc).isoformat()
        with self._write_lock:
            self._write_conn.execute(
                "INSERT OR REPLACE INTO settlement_ledger "
                "(manifest_hash, pubkey_id, amount, asset_code, status, "
                " error_detail, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (manifest_hash, pubkey_id, amount, asset_code, "failed", error_detail, now),
            )
            self._write_conn.commit()

    def get(self, manifest_hash: str) -> dict | None:
        """Retrieve a ledger entry by manifest_hash."""
        with self._write_lock:
            row = self._write_conn.execute(
                "SELECT * FROM settlement_ledger WHERE manifest_hash = ?",
                (manifest_hash,),
            ).fetchone()
        return dict(row) if row else None

    def all(self) -> list[dict]:
        """Return all entries in creation order."""
        with self._write_lock:
            rows = self._write_conn.execute(
                "SELECT * FROM settlement_ledger ORDER BY created_at ASC"
            ).fetchall()
        return [dict(r) for r in rows]

    def all_settled(self) -> list[dict]:
        """Return all settled entries."""
        with self._write_lock:
            rows = self._write_conn.execute(
                "SELECT * FROM settlement_ledger WHERE status = 'settled' "
                "ORDER BY settled_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def count(self, status: str | None = None) -> int:
        """Count ledger entries, optionally filtered by status."""
        with self._write_lock:
            if status:
                return self._write_conn.execute(
                    "SELECT COUNT(*) AS n FROM settlement_ledger WHERE status = ?",
                    (status,),
                ).fetchone()["n"]
            return self._write_conn.execute(
                "SELECT COUNT(*) AS n FROM settlement_ledger"
            ).fetchone()["n"]


# Process-wide singleton
_LEDGER: SettlementLedger | None = None
_LEDGER_LOCK = threading.Lock()


def get_ledger() -> SettlementLedger:
    """Return the process-wide SettlementLedger singleton."""
    global _LEDGER
    if _LEDGER is None:
        with _LEDGER_LOCK:
            if _LEDGER is None:
                _LEDGER = SettlementLedger()
    return _LEDGER
