"""Zephyr per-leg execution-state store (rail U2b, D2).

Crash-safe MUTABLE working state that lets the Node executor avoid a blind
retry on restart - own SQLite file (default ``/data/zephyr/route_exec.db``,
override with ``ZEPHYR_ROUTE_EXEC_DB``), never claims.db. claims.db's
route_receipts table (zephyr.claims) is the immutable, authoritative signed
audit record; this module is disposable working state only.

**Authority rule (normative): a claims.route_receipts TERMINAL receipt is
always authoritative over this store's state.** This module exists only to
avoid re-quoting/re-submitting a leg still in flight - it is never the
source of truth for "is this leg done." A Node executor MUST check
zephyr.claims.route_receipts_for_manifest() first; leg_execution state here
is advisory recovery hint, not settlement truth.

State machine (the ONLY legal edges):
  (absent)                    -> pending   via claim_leg
  pending                     -> quoted    via record_quote
  quoted                      -> submitted via record_submitted
  submitted                   -> settled   via record_settled  (terminal)
  pending | quoted | submitted -> failed   via record_failed   (non-terminal)
  pending | quoted            -> skipped   via record_skipped  (terminal)
  failed                      -> pending   via claim_leg (re-claim, attempt += 1)
No transition out of settled/skipped. Every other edge raises LegStateError.
A re-claimed leg (failed -> pending) MUST traverse pending -> quoted ->
submitted again in full - there is no pending -> submitted shortcut, even if
an outgoing_payment_id is already persisted from a prior attempt.

Every setter is a read-check-write inside one BEGIN IMMEDIATE transaction
(TOCTOU guard between two executor processes), mirroring zephyr.claims's
insert_route_manifest discipline. Every setter accepts an injectable
`timestamp` - never call datetime.now() in a spot a test cannot pin.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "LegExecutionStore",
    "LegStateError",
    "get_route_exec_store",
    "claim_leg",
    "record_quote",
    "record_submitted",
    "record_settled",
    "record_failed",
    "record_skipped",
    "get_leg_state",
    "legs_for_manifest",
]

DEFAULT_ROUTE_EXEC_DB = Path(os.environ.get("ZEPHYR_ROUTE_EXEC_DB", "/data/zephyr/route_exec.db"))

_LOCK_RETRY_ATTEMPTS = 5
_LOCK_RETRY_BASE_DELAY = 0.05  # seconds, doubles each attempt

_SCHEMA = """
CREATE TABLE IF NOT EXISTS leg_execution (
    manifest_hash          TEXT NOT NULL,
    beneficiary_pubkey_id  TEXT NOT NULL,
    state                  TEXT NOT NULL,
    quote_id               TEXT,
    outgoing_payment_id    TEXT,
    attempt                INTEGER NOT NULL DEFAULT 0,
    last_error              TEXT,
    updated_at              TEXT NOT NULL,
    PRIMARY KEY (manifest_hash, beneficiary_pubkey_id)
);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_locked_error(exc: sqlite3.OperationalError) -> bool:
    return "locked" in str(exc).lower()


class LegStateError(Exception):
    """An illegal leg_execution state transition was attempted.

    .from_state is the state the leg was actually in (None if absent).
    .to_state is the state the caller attempted to move it to.
    """

    def __init__(self, message: str, *, from_state: str | None, to_state: str):
        super().__init__(message)
        self.from_state = from_state
        self.to_state = to_state


class LegExecutionStore:
    """SQLite-backed leg execution-state store. Thread-safe; one connection guarded by a lock."""

    def __init__(self, db_path: Path | str = DEFAULT_ROUTE_EXEC_DB):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # -- transaction helper --------------------------------------------------

    def _run_txn(self, body):
        """Retry-acquire BEGIN IMMEDIATE, run body(conn), commit, return result.

        LegStateError (a correct refusal) and any other non-OperationalError
        exception roll back and re-raise unchanged, without retry.
        sqlite3.OperationalError("database is locked") retries with bounded
        backoff (5 attempts, 50ms doubling).
        """
        delay = _LOCK_RETRY_BASE_DELAY
        for attempt in range(_LOCK_RETRY_ATTEMPTS):
            is_last_attempt = attempt == _LOCK_RETRY_ATTEMPTS - 1
            with self._lock:
                try:
                    self._conn.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError as exc:
                    if _is_locked_error(exc) and not is_last_attempt:
                        pass
                    else:
                        raise
                else:
                    try:
                        result = body(self._conn)
                        self._conn.commit()
                        return result
                    except Exception:
                        self._conn.rollback()
                        raise
            time.sleep(delay)
            delay *= 2
        raise sqlite3.OperationalError(
            f"LegExecutionStore: database locked after {_LOCK_RETRY_ATTEMPTS} attempts"
        )

    def _get_row(self, conn, manifest_hash: str, beneficiary_pubkey_id: str) -> dict | None:
        row = conn.execute(
            "SELECT * FROM leg_execution WHERE manifest_hash = ? AND beneficiary_pubkey_id = ?",
            (manifest_hash, beneficiary_pubkey_id),
        ).fetchone()
        return dict(row) if row is not None else None

    def _require_row(self, conn, manifest_hash: str, beneficiary_pubkey_id: str, *, to_state: str) -> dict:
        row = self._get_row(conn, manifest_hash, beneficiary_pubkey_id)
        if row is None:
            raise LegStateError(
                f"illegal transition (absent) -> {to_state} for "
                f"(manifest_hash={manifest_hash!r}, beneficiary_pubkey_id={beneficiary_pubkey_id!r}) "
                f"- claim_leg must run first",
                from_state=None,
                to_state=to_state,
            )
        return row

    def _illegal(self, row_state: str | None, to_state: str, manifest_hash: str, beneficiary_pubkey_id: str) -> LegStateError:
        return LegStateError(
            f"illegal transition {row_state} -> {to_state} for "
            f"(manifest_hash={manifest_hash!r}, beneficiary_pubkey_id={beneficiary_pubkey_id!r})",
            from_state=row_state,
            to_state=to_state,
        )

    # -- state machine setters -----------------------------------------------

    def claim_leg(self, manifest_hash: str, beneficiary_pubkey_id: str, *, timestamp: str | None = None) -> dict:
        """(absent) -> pending, or failed -> pending (re-claim, attempt += 1).
        Idempotent if already pending. Illegal from quoted/submitted/settled/skipped."""
        ts = timestamp or _now_iso()

        def body(conn):
            row = self._get_row(conn, manifest_hash, beneficiary_pubkey_id)
            if row is None:
                conn.execute(
                    "INSERT INTO leg_execution "
                    "(manifest_hash, beneficiary_pubkey_id, state, attempt, updated_at) "
                    "VALUES (?, ?, 'pending', 0, ?)",
                    (manifest_hash, beneficiary_pubkey_id, ts),
                )
            elif row["state"] == "pending":
                pass  # idempotent re-claim of an already-pending leg
            elif row["state"] == "failed":
                conn.execute(
                    "UPDATE leg_execution SET state='pending', attempt=attempt+1, "
                    "last_error=NULL, updated_at=? WHERE manifest_hash=? AND beneficiary_pubkey_id=?",
                    (ts, manifest_hash, beneficiary_pubkey_id),
                )
            else:
                raise self._illegal(row["state"], "pending", manifest_hash, beneficiary_pubkey_id)
            return self._get_row(conn, manifest_hash, beneficiary_pubkey_id)

        return self._run_txn(body)

    def record_quote(self, manifest_hash: str, beneficiary_pubkey_id: str, quote_id: str, *, timestamp: str | None = None) -> dict:
        """pending -> quoted."""
        ts = timestamp or _now_iso()

        def body(conn):
            row = self._require_row(conn, manifest_hash, beneficiary_pubkey_id, to_state="quoted")
            if row["state"] != "pending":
                raise self._illegal(row["state"], "quoted", manifest_hash, beneficiary_pubkey_id)
            conn.execute(
                "UPDATE leg_execution SET state='quoted', quote_id=?, updated_at=? "
                "WHERE manifest_hash=? AND beneficiary_pubkey_id=?",
                (quote_id, ts, manifest_hash, beneficiary_pubkey_id),
            )
            return self._get_row(conn, manifest_hash, beneficiary_pubkey_id)

        return self._run_txn(body)

    def record_submitted(self, manifest_hash: str, beneficiary_pubkey_id: str, outgoing_payment_id: str, *, timestamp: str | None = None) -> dict:
        """quoted -> submitted. Persists outgoing_payment_id before any terminal
        transition, so a crash mid-send is recoverable by GET-ing that payment
        (U2c's job), never by re-creating it."""
        ts = timestamp or _now_iso()

        def body(conn):
            row = self._require_row(conn, manifest_hash, beneficiary_pubkey_id, to_state="submitted")
            if row["state"] != "quoted":
                raise self._illegal(row["state"], "submitted", manifest_hash, beneficiary_pubkey_id)
            conn.execute(
                "UPDATE leg_execution SET state='submitted', outgoing_payment_id=?, updated_at=? "
                "WHERE manifest_hash=? AND beneficiary_pubkey_id=?",
                (outgoing_payment_id, ts, manifest_hash, beneficiary_pubkey_id),
            )
            return self._get_row(conn, manifest_hash, beneficiary_pubkey_id)

        return self._run_txn(body)

    def record_settled(self, manifest_hash: str, beneficiary_pubkey_id: str, *, timestamp: str | None = None) -> dict:
        """submitted -> settled (terminal)."""
        ts = timestamp or _now_iso()

        def body(conn):
            row = self._require_row(conn, manifest_hash, beneficiary_pubkey_id, to_state="settled")
            if row["state"] != "submitted":
                raise self._illegal(row["state"], "settled", manifest_hash, beneficiary_pubkey_id)
            conn.execute(
                "UPDATE leg_execution SET state='settled', updated_at=? "
                "WHERE manifest_hash=? AND beneficiary_pubkey_id=?",
                (ts, manifest_hash, beneficiary_pubkey_id),
            )
            return self._get_row(conn, manifest_hash, beneficiary_pubkey_id)

        return self._run_txn(body)

    def record_failed(self, manifest_hash: str, beneficiary_pubkey_id: str, error: str, *, timestamp: str | None = None) -> dict:
        """pending | quoted | submitted -> failed (non-terminal; re-claimable)."""
        ts = timestamp or _now_iso()

        def body(conn):
            row = self._require_row(conn, manifest_hash, beneficiary_pubkey_id, to_state="failed")
            if row["state"] not in ("pending", "quoted", "submitted"):
                raise self._illegal(row["state"], "failed", manifest_hash, beneficiary_pubkey_id)
            conn.execute(
                "UPDATE leg_execution SET state='failed', last_error=?, updated_at=? "
                "WHERE manifest_hash=? AND beneficiary_pubkey_id=?",
                (error, ts, manifest_hash, beneficiary_pubkey_id),
            )
            return self._get_row(conn, manifest_hash, beneficiary_pubkey_id)

        return self._run_txn(body)

    def record_skipped(self, manifest_hash: str, beneficiary_pubkey_id: str, reason: str, *, timestamp: str | None = None) -> dict:
        """pending | quoted -> skipped (terminal; leg reverify found unpayable before submit)."""
        ts = timestamp or _now_iso()

        def body(conn):
            row = self._require_row(conn, manifest_hash, beneficiary_pubkey_id, to_state="skipped")
            if row["state"] not in ("pending", "quoted"):
                raise self._illegal(row["state"], "skipped", manifest_hash, beneficiary_pubkey_id)
            conn.execute(
                "UPDATE leg_execution SET state='skipped', last_error=?, updated_at=? "
                "WHERE manifest_hash=? AND beneficiary_pubkey_id=?",
                (reason, ts, manifest_hash, beneficiary_pubkey_id),
            )
            return self._get_row(conn, manifest_hash, beneficiary_pubkey_id)

        return self._run_txn(body)

    # -- reads ----------------------------------------------------------------

    def get_leg_state(self, manifest_hash: str, beneficiary_pubkey_id: str) -> dict | None:
        with self._lock:
            return self._get_row(self._conn, manifest_hash, beneficiary_pubkey_id)

    def legs_for_manifest(self, manifest_hash: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM leg_execution WHERE manifest_hash = ?", (manifest_hash,)
            ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Singleton factory (parallel to zephyr.claims.get_claims_store)
# ---------------------------------------------------------------------------

_STORE: LegExecutionStore | None = None
_STORE_LOCK = threading.Lock()


def get_route_exec_store() -> LegExecutionStore:
    """Return the process-wide LegExecutionStore singleton.

    Re-reads ZEPHYR_ROUTE_EXEC_DB on each (re)creation, matching
    zephyr.claims.get_claims_store, so tests can monkeypatch the env var +
    call _reset_route_exec_store() and get a genuinely fresh, isolated store.
    """
    global _STORE
    if _STORE is None:
        with _STORE_LOCK:
            if _STORE is None:
                db_path = Path(os.environ.get("ZEPHYR_ROUTE_EXEC_DB", str(DEFAULT_ROUTE_EXEC_DB)))
                _STORE = LegExecutionStore(db_path)
    return _STORE


def _reset_route_exec_store() -> None:
    """For tests - force reload of the route-exec store on next use."""
    global _STORE
    _STORE = None


# ---------------------------------------------------------------------------
# Module-level convenience wrappers
# ---------------------------------------------------------------------------


def claim_leg(manifest_hash: str, beneficiary_pubkey_id: str, *, store: LegExecutionStore | None = None, timestamp: str | None = None) -> dict:
    st = store if store is not None else get_route_exec_store()
    return st.claim_leg(manifest_hash, beneficiary_pubkey_id, timestamp=timestamp)


def record_quote(manifest_hash: str, beneficiary_pubkey_id: str, quote_id: str, *, store: LegExecutionStore | None = None, timestamp: str | None = None) -> dict:
    st = store if store is not None else get_route_exec_store()
    return st.record_quote(manifest_hash, beneficiary_pubkey_id, quote_id, timestamp=timestamp)


def record_submitted(manifest_hash: str, beneficiary_pubkey_id: str, outgoing_payment_id: str, *, store: LegExecutionStore | None = None, timestamp: str | None = None) -> dict:
    st = store if store is not None else get_route_exec_store()
    return st.record_submitted(manifest_hash, beneficiary_pubkey_id, outgoing_payment_id, timestamp=timestamp)


def record_settled(manifest_hash: str, beneficiary_pubkey_id: str, *, store: LegExecutionStore | None = None, timestamp: str | None = None) -> dict:
    st = store if store is not None else get_route_exec_store()
    return st.record_settled(manifest_hash, beneficiary_pubkey_id, timestamp=timestamp)


def record_failed(manifest_hash: str, beneficiary_pubkey_id: str, error: str, *, store: LegExecutionStore | None = None, timestamp: str | None = None) -> dict:
    st = store if store is not None else get_route_exec_store()
    return st.record_failed(manifest_hash, beneficiary_pubkey_id, error, timestamp=timestamp)


def record_skipped(manifest_hash: str, beneficiary_pubkey_id: str, reason: str, *, store: LegExecutionStore | None = None, timestamp: str | None = None) -> dict:
    st = store if store is not None else get_route_exec_store()
    return st.record_skipped(manifest_hash, beneficiary_pubkey_id, reason, timestamp=timestamp)


def get_leg_state(manifest_hash: str, beneficiary_pubkey_id: str, *, store: LegExecutionStore | None = None) -> dict | None:
    st = store if store is not None else get_route_exec_store()
    return st.get_leg_state(manifest_hash, beneficiary_pubkey_id)


def legs_for_manifest(manifest_hash: str, *, store: LegExecutionStore | None = None) -> list[dict]:
    st = store if store is not None else get_route_exec_store()
    return st.legs_for_manifest(manifest_hash)
