"""Zephyr claims domain store - wallet_binding + routing_terms (rail U0).

attribution.db stores only the provenance ENVELOPE (signature, pubkey_id,
manifest_hash, ...); claim payloads live here, in a domain store, per the
attestation-spine precedent. Own SQLite file (default
``/data/zephyr/claims.db``, override with ``ZEPHYR_CLAIMS_DB``), WAL.

One signing act, two homes: each ``record_*`` helper calls
``zephyr.attribution.record_signed`` FIRST; only on success does it insert
the domain row (deposit failure -> raise, no domain row - an unsigned claim
can never exist in the store).

Two claim kinds:
  wallet_binding - SELF-SIGNED ONLY. A key binds only itself; there is no
    field with which to bind a wallet for another party (Erah's 2026-07-20
    ratification removed the proxy/declared-wallet backdoor entirely).
  routing_terms  - a DECLARED share (basis="declared-contract") naming a
    beneficiary who already holds a registered key. Route-not-compute: this
    module validates bounds only and never derives a ratio from anything.

Integrity bind on read: a claim consumed from this store is untrusted cache
until re-verified against its attribution.db envelope - recompute the
canonical manifest_hash from the domain row's content and require it to
match, then require verify_row(...).status == "verified". See verify_claim()
/ verify_wallet_binding_row() / verify_routing_terms_row() /
verify_route_manifest_row(). The signed deposit is the sole authority; this
store can never make a claim more true than its envelope says it is.

Supersedes chain (rail U2a hardening): route_manifests are selected by
walking the ``supersedes`` edges, never by ``recorded_at`` (caller-supplied,
never load-bearing for correctness - see route_manifest_chain_for_event()).
Wallet bindings are selected by store-assigned ``seq`` (a monotonic
AUTOINCREMENT column), never by ``recorded_at`` either - see resolve_wallet().
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from zephyr.attribution import AttributionLog
    from zephyr.registry import PubkeyRegistry
    from zephyr.signing import AgentSigner

_log = logging.getLogger(__name__)

__all__ = [
    "ClaimsStore",
    "RouteChainError",
    "RouteReceiptError",
    "ClaimIntegrityResult",
    "USE_VOCAB",
    "get_claims_store",
    "record_wallet_binding",
    "record_routing_terms",
    "record_route_receipt",
    "record_use_terms",
    "resolve_wallet",
    "resolve_use_terms",
    "check_use",
    "route_receipts_for_manifest",
    "verify_claim",
    "verify_wallet_binding_row",
    "verify_routing_terms_row",
    "verify_route_manifest_row",
    "verify_route_receipt_row",
    "verify_use_terms_row",
]

# Closed vocabulary of use declarations (rail zephyr-use-terms-consent-v0, DD3).
# A declaration may only allow/deny tokens from this tuple; anything else is
# rejected at declare time. The machine REPORTS declarations - it settles
# nothing about permission.
USE_VOCAB: tuple[str, ...] = ("training", "remix", "redistribution")

DEFAULT_CLAIMS_DB = Path(os.environ.get("ZEPHYR_CLAIMS_DB", "/data/zephyr/claims.db"))

_LOCK_RETRY_ATTEMPTS = 5
_LOCK_RETRY_BASE_DELAY = 0.05  # seconds, doubles each attempt

_SCHEMA = """
CREATE TABLE IF NOT EXISTS wallet_bindings (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    manifest_hash   TEXT NOT NULL UNIQUE,
    subject         TEXT,
    wallet_address  TEXT,
    revokes         INTEGER,
    note            TEXT,
    summary         TEXT,
    recorded_at     TEXT
);
CREATE INDEX IF NOT EXISTS wallet_bindings_subject ON wallet_bindings(subject);

CREATE TABLE IF NOT EXISTS routing_terms (
    seq                    INTEGER PRIMARY KEY AUTOINCREMENT,
    manifest_hash          TEXT NOT NULL UNIQUE,
    subject                TEXT,
    beneficiary_pubkey_id  TEXT,
    share_bps              INTEGER,
    basis                  TEXT,
    scope                  TEXT,
    declared_by            TEXT,
    note                   TEXT,
    summary                TEXT,
    recorded_at            TEXT
);
CREATE INDEX IF NOT EXISTS routing_terms_subject ON routing_terms(subject);

CREATE TABLE IF NOT EXISTS route_manifests (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    manifest_hash   TEXT NOT NULL UNIQUE,
    event_ref       TEXT,
    payload_json    TEXT,
    summary         TEXT,
    recorded_at     TEXT,
    supersedes      TEXT
);
CREATE INDEX IF NOT EXISTS route_manifests_event ON route_manifests(event_ref);
CREATE UNIQUE INDEX IF NOT EXISTS route_manifests_chain_unique
    ON route_manifests(event_ref, COALESCE(supersedes, 'ROOT'));

CREATE TABLE IF NOT EXISTS route_receipts (
    seq                    INTEGER PRIMARY KEY AUTOINCREMENT,
    manifest_hash          TEXT NOT NULL,
    beneficiary_pubkey_id  TEXT NOT NULL,
    outcome                TEXT NOT NULL,
    op_payment_id          TEXT,
    sent_value             INTEGER,
    sent_asset_code        TEXT,
    sent_asset_scale       INTEGER,
    leg_status             TEXT NOT NULL,
    reason                 TEXT,
    receipt_hash           TEXT NOT NULL UNIQUE,
    recorded_at            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS route_receipts_manifest ON route_receipts(manifest_hash);
CREATE UNIQUE INDEX IF NOT EXISTS route_receipts_terminal_unique
    ON route_receipts(manifest_hash, beneficiary_pubkey_id)
    WHERE outcome IN ('settled', 'skipped');

CREATE TABLE IF NOT EXISTS use_terms (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    manifest_hash   TEXT NOT NULL UNIQUE,
    subject         TEXT NOT NULL,
    declared_by     TEXT NOT NULL,
    allowed_uses    TEXT NOT NULL,
    denied_uses     TEXT NOT NULL DEFAULT '[]',
    scope           TEXT NOT NULL,
    revokes         INTEGER NOT NULL DEFAULT 0,
    note            TEXT NOT NULL DEFAULT '',
    summary         TEXT NOT NULL,
    recorded_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS use_terms_subject ON use_terms(subject);
"""

# Rebuild specs for the D1b seq-column migration. SQLite forbids adding an
# INTEGER PRIMARY KEY AUTOINCREMENT column to an existing table (ALTER TABLE
# ADD COLUMN), so a table missing `seq` is rebuilt wholesale: manifest_hash
# demotes from PRIMARY KEY to a plain UNIQUE constraint so seq can take the
# primary-key slot AUTOINCREMENT requires.
_TABLE_REBUILD_SPECS = {
    "wallet_bindings": {
        "columns": [
            "manifest_hash", "subject", "wallet_address", "revokes",
            "note", "summary", "recorded_at",
        ],
        "create": """
            CREATE TABLE {name} (
                seq             INTEGER PRIMARY KEY AUTOINCREMENT,
                manifest_hash   TEXT NOT NULL UNIQUE,
                subject         TEXT,
                wallet_address  TEXT,
                revokes         INTEGER,
                note            TEXT,
                summary         TEXT,
                recorded_at     TEXT
            )
        """,
        "indexes": [
            "CREATE INDEX IF NOT EXISTS wallet_bindings_subject ON wallet_bindings(subject)",
        ],
    },
    "routing_terms": {
        "columns": [
            "manifest_hash", "subject", "beneficiary_pubkey_id", "share_bps",
            "basis", "scope", "declared_by", "note", "summary", "recorded_at",
        ],
        "create": """
            CREATE TABLE {name} (
                seq                    INTEGER PRIMARY KEY AUTOINCREMENT,
                manifest_hash          TEXT NOT NULL UNIQUE,
                subject                TEXT,
                beneficiary_pubkey_id  TEXT,
                share_bps              INTEGER,
                basis                  TEXT,
                scope                  TEXT,
                declared_by            TEXT,
                note                   TEXT,
                summary                TEXT,
                recorded_at            TEXT
            )
        """,
        "indexes": [
            "CREATE INDEX IF NOT EXISTS routing_terms_subject ON routing_terms(subject)",
        ],
    },
    "route_manifests": {
        "columns": [
            "manifest_hash", "event_ref", "payload_json", "summary",
            "recorded_at", "supersedes",
        ],
        "create": """
            CREATE TABLE {name} (
                seq             INTEGER PRIMARY KEY AUTOINCREMENT,
                manifest_hash   TEXT NOT NULL UNIQUE,
                event_ref       TEXT,
                payload_json    TEXT,
                summary         TEXT,
                recorded_at     TEXT,
                supersedes      TEXT
            )
        """,
        "indexes": [
            "CREATE INDEX IF NOT EXISTS route_manifests_event ON route_manifests(event_ref)",
            "CREATE UNIQUE INDEX IF NOT EXISTS route_manifests_chain_unique "
            "ON route_manifests(event_ref, COALESCE(supersedes, 'ROOT'))",
        ],
    },
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_locked_error(exc: sqlite3.OperationalError) -> bool:
    return "locked" in str(exc).lower()


def _migrate_add_seq(conn: sqlite3.Connection) -> None:
    """Idempotent transactional rebuild adding a store-assigned `seq` PK.

    Guarded by PRAGMA table_info so re-opening an already-migrated (or
    freshly created) store is a no-op. All DDL for a given table's rebuild
    runs inside one BEGIN IMMEDIATE transaction - SQLite DDL is
    transactional, so a half-upgraded schema (an orphaned `_new` table or a
    dropped original) is impossible; it commits or rolls back as a unit.
    """
    needs_rebuild = []
    for table in _TABLE_REBUILD_SPECS:
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        if cols and "seq" not in cols:
            needs_rebuild.append(table)
    if not needs_rebuild:
        return

    delay = _LOCK_RETRY_BASE_DELAY
    for attempt in range(_LOCK_RETRY_ATTEMPTS):
        try:
            conn.execute("BEGIN IMMEDIATE")
            break
        except sqlite3.OperationalError as exc:
            if _is_locked_error(exc) and attempt < _LOCK_RETRY_ATTEMPTS - 1:
                time.sleep(delay)
                delay *= 2
                continue
            raise
    else:  # pragma: no cover - unreachable, loop always breaks or raises
        raise sqlite3.OperationalError("_migrate_add_seq: could not acquire write lock")

    try:
        for table in needs_rebuild:
            spec = _TABLE_REBUILD_SPECS[table]
            new_name = f"{table}_new"
            conn.execute(spec["create"].format(name=new_name))
            col_list = ", ".join(spec["columns"])
            conn.execute(
                f"INSERT INTO {new_name} ({col_list}) "
                f"SELECT {col_list} FROM {table} ORDER BY recorded_at, manifest_hash"
            )
            conn.execute(f"DROP TABLE {table}")
            conn.execute(f"ALTER TABLE {new_name} RENAME TO {table}")
            for idx_sql in spec["indexes"]:
                conn.execute(idx_sql)
        conn.commit()
    except Exception:
        conn.rollback()
        raise


# ---------------------------------------------------------------------------
# RouteChainError - defined here (not routing.py) to avoid a cycle: routing.py
# imports claims.py, so claims.py cannot import routing.py at module level.
# Re-exported as zephyr.routing.RouteChainError - the executor's entry module.
# ---------------------------------------------------------------------------


class RouteChainError(Exception):
    """A route_manifests supersedes chain is malformed, or a write would fork it.

    .failure_mode is one of: "cycle", "forked_chain", "orphaned",
    "multiple_roots", "supersedes_not_head". .event_ref names the affected
    event_ref. Never guess a head when the chain is malformed - raise instead.
    """

    def __init__(self, message: str, *, failure_mode: str, event_ref: str):
        super().__init__(message)
        self.failure_mode = failure_mode
        self.event_ref = event_ref


class RouteReceiptError(ValueError):
    """A route_receipt write was refused against manifest/leg state (rail U2b, D1).

    .failure_mode is one of: "unknown_manifest" (no head exists for the cited
    event_ref), "not_head" (the cited manifest_hash is not the current chain
    head), "no_such_leg" (beneficiary_pubkey_id is not a leg of the head
    manifest), "not_routable" (a settled receipt against a credited-unpaid
    leg), "amount_mismatch" (sent amount != the leg's manifest amount), or
    "outcome_conflict" (a conflicting terminal receipt already exists for
    this leg). A structural ValueError (missing settled amount fields, etc.)
    is raised as a bare ValueError, not this class - see record_route_receipt.
    """

    def __init__(self, message: str, *, failure_mode: str):
        super().__init__(message)
        self.failure_mode = failure_mode


# ---------------------------------------------------------------------------
# ClaimsStore
# ---------------------------------------------------------------------------


class ClaimsStore:
    """SQLite-backed claims domain store. Thread-safe; one connection guarded by a lock."""

    def __init__(self, db_path: Path | str = DEFAULT_CLAIMS_DB):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        _migrate_add_seq(self._conn)

    # -- wallet_bindings ---------------------------------------------------

    def insert_wallet_binding(
        self,
        *,
        manifest_hash: str,
        subject: str,
        wallet_address: str,
        revokes: bool,
        note: str,
        summary: str,
        recorded_at: str,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO wallet_bindings "
                "(manifest_hash, subject, wallet_address, revokes, note, summary, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (manifest_hash, subject, wallet_address, int(bool(revokes)), note, summary, recorded_at),
            )
            self._conn.commit()

    def list_wallet_bindings_for_subject(self, subject: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM wallet_bindings WHERE subject = ?", (subject,)
            ).fetchall()
        return [dict(r) for r in rows]

    # -- routing_terms -------------------------------------------------------

    def insert_routing_terms(
        self,
        *,
        manifest_hash: str,
        subject: str,
        beneficiary_pubkey_id: str,
        share_bps: int,
        basis: str,
        scope: str,
        declared_by: str,
        note: str,
        summary: str,
        recorded_at: str,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO routing_terms "
                "(manifest_hash, subject, beneficiary_pubkey_id, share_bps, basis, scope, "
                " declared_by, note, summary, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    manifest_hash,
                    subject,
                    beneficiary_pubkey_id,
                    share_bps,
                    basis,
                    scope,
                    declared_by,
                    note,
                    summary,
                    recorded_at,
                ),
            )
            self._conn.commit()

    def list_routing_terms_for_subject(self, subject: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM routing_terms WHERE subject = ?", (subject,)
            ).fetchall()
        return [dict(r) for r in rows]

    # -- route_manifests -------------------------------------------------

    def insert_route_manifest(
        self,
        *,
        manifest_hash: str,
        event_ref: str,
        payload_json: str,
        summary: str,
        recorded_at: str,
        supersedes: str | None,
    ) -> None:
        """Insert a route_manifest row, rejecting a fork at write time.

        If any manifest already exists for event_ref, *supersedes* MUST equal
        the current head's manifest_hash - otherwise RouteChainError
        ("supersedes_not_head"), nothing inserted. The first manifest for an
        event_ref must have supersedes=None. Re-inserting an identical
        manifest_hash is a no-op (idempotent recompile), checked BEFORE the
        guard so routing.py's replay path never raises.

        Head-read + guard-check + insert run inside one BEGIN IMMEDIATE
        transaction on self._conn, so two concurrent compiles for the same
        event_ref cannot both read the same head and both insert (the TOCTOU
        this guard exists to prevent). BEGIN IMMEDIATE acquires SQLite's
        write lock up front; "database is locked" is retried with bounded
        backoff (5 attempts, 50ms doubling). A RouteChainError from the guard
        firing is a correct refusal (rolled back, re-raised unchanged, no
        retry). sqlite3.IntegrityError means a schema guarantee was violated
        - rolled back and re-raised, never absorbed.
        """
        delay = _LOCK_RETRY_BASE_DELAY
        for attempt in range(_LOCK_RETRY_ATTEMPTS):
            is_last_attempt = attempt == _LOCK_RETRY_ATTEMPTS - 1
            with self._lock:
                try:
                    self._conn.execute("BEGIN IMMEDIATE")
                    self._insert_route_manifest_txn(
                        manifest_hash=manifest_hash,
                        event_ref=event_ref,
                        payload_json=payload_json,
                        summary=summary,
                        recorded_at=recorded_at,
                        supersedes=supersedes,
                    )
                    return
                except (RouteChainError, sqlite3.IntegrityError):
                    raise
                except sqlite3.OperationalError as exc:
                    if not (_is_locked_error(exc) and not is_last_attempt):
                        raise
            time.sleep(delay)
            delay *= 2
        raise sqlite3.OperationalError(
            f"insert_route_manifest: database locked after {_LOCK_RETRY_ATTEMPTS} attempts"
        )

    def _insert_route_manifest_txn(
        self,
        *,
        manifest_hash: str,
        event_ref: str,
        payload_json: str,
        summary: str,
        recorded_at: str,
        supersedes: str | None,
    ) -> bool:
        """One BEGIN IMMEDIATE attempt's body. Caller has already opened the
        transaction. Returns True on commit. Rolls back and re-raises on any
        error - RouteChainError (a correct refusal), IntegrityError (a
        violated schema guarantee), OperationalError (lock contention, for
        the caller to retry), or anything else (propagated unchanged)."""
        try:
            existing = self._conn.execute(
                "SELECT 1 FROM route_manifests WHERE manifest_hash = ?",
                (manifest_hash,),
            ).fetchone()
            if existing is not None:
                self._conn.commit()
                return True

            rows = self._conn.execute(
                "SELECT manifest_hash, supersedes FROM route_manifests WHERE event_ref = ?",
                (event_ref,),
            ).fetchall()
            if rows:
                superseded = {r["supersedes"] for r in rows if r["supersedes"]}
                heads = [r["manifest_hash"] for r in rows if r["manifest_hash"] not in superseded]
                current_head = heads[0] if len(heads) == 1 else None
                if current_head is None or supersedes != current_head:
                    raise RouteChainError(
                        f"supersedes_not_head: attempted supersedes={supersedes!r} "
                        f"but current head is {current_head!r} for event_ref={event_ref!r}",
                        failure_mode="supersedes_not_head",
                        event_ref=event_ref,
                    )
            elif supersedes is not None:
                raise RouteChainError(
                    f"supersedes_not_head: first manifest for event_ref={event_ref!r} "
                    f"must have supersedes=None, got {supersedes!r}",
                    failure_mode="supersedes_not_head",
                    event_ref=event_ref,
                )

            self._conn.execute(
                "INSERT OR IGNORE INTO route_manifests "
                "(manifest_hash, event_ref, payload_json, summary, recorded_at, supersedes) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (manifest_hash, event_ref, payload_json, summary, recorded_at, supersedes),
            )
            self._conn.commit()
            return True
        except Exception:
            self._conn.rollback()
            raise

    def route_manifest_chain_for_event(self, event_ref: str) -> list[dict]:
        """All manifests for event_ref ordered oldest -> newest by supersedes edges.

        Never sorts by recorded_at or manifest_hash - the chain is walked via
        the supersedes graph, which is the only load-bearing ordering.
        Raises RouteChainError on any malformed chain. Empty list if none.
        """
        with self._lock:
            rows = self._fetch_route_manifest_rows_locked(event_ref)
        return self._chain_from_rows(event_ref, rows)

    def _fetch_route_manifest_rows_locked(self, event_ref: str) -> list[dict]:
        """Raw SELECT only - caller must already hold (or not need) self._lock."""
        rows = self._conn.execute(
            "SELECT * FROM route_manifests WHERE event_ref = ?", (event_ref,)
        ).fetchall()
        return [dict(r) for r in rows]

    def _chain_from_rows(self, event_ref: str, rows: list[dict]) -> list[dict]:
        """Pure chain-walk over already-fetched rows - no locking, no I/O.

        Factored out of route_manifest_chain_for_event so a caller already
        holding self._lock (e.g. the route_receipts atomic head re-check) can
        reuse the exact same walk/raise semantics without re-entering the
        (non-reentrant) lock.
        """
        if not rows:
            return []

        # Two independent NULL-supersedes rows is checked FIRST and takes
        # priority over the heads-count check below: a root with no
        # descendant pointing at it is, by construction, ALSO an unsuperseded
        # "head" - so without this early check, any duplicate-root scenario
        # would always present as forked_chain instead, and multiple_roots
        # (a more specific, more informative diagnosis - which history is
        # the true start?) would never be reachable.
        roots = [r for r in rows if r["supersedes"] is None]
        if len(roots) > 1:
            root_hashes = sorted(r["manifest_hash"] for r in roots)
            raise RouteChainError(
                f"multiple_roots: more than one supersedes=NULL row for event_ref={event_ref!r}: "
                f"{root_hashes}",
                failure_mode="multiple_roots",
                event_ref=event_ref,
            )

        by_hash = {r["manifest_hash"]: r for r in rows}
        superseded = {r["supersedes"] for r in rows if r["supersedes"]}
        heads = [r for r in rows if r["manifest_hash"] not in superseded]

        if not heads:
            raise RouteChainError(
                f"cycle: every row supersedes/is-superseded-by another for event_ref={event_ref!r} "
                f"- no chain head exists",
                failure_mode="cycle",
                event_ref=event_ref,
            )
        if len(heads) > 1:
            head_hashes = sorted(h["manifest_hash"] for h in heads)
            raise RouteChainError(
                f"forked_chain: multiple chain heads for event_ref={event_ref!r}: {head_hashes}",
                failure_mode="forked_chain",
                event_ref=event_ref,
            )

        head = heads[0]

        # Walk supersedes back from the head; must visit every row exactly
        # once and terminate at the (now known-unique) NULL-supersedes root.
        visited = []
        seen_hashes: set[str] = set()
        current: dict | None = head
        while current is not None:
            if current["manifest_hash"] in seen_hashes:
                raise RouteChainError(
                    f"cycle: chain revisits {current['manifest_hash']!r} for event_ref={event_ref!r}",
                    failure_mode="cycle",
                    event_ref=event_ref,
                )
            seen_hashes.add(current["manifest_hash"])
            visited.append(current)
            supersedes = current["supersedes"]
            if supersedes is None:
                break
            current = by_hash.get(supersedes)

        unreached = [r for r in rows if r["manifest_hash"] not in seen_hashes]
        if unreached:
            # A duplicate root was already ruled out above, so any row left
            # unreached here is a disconnected component (e.g. a cycle) that
            # never touches the head's own chain at all.
            raise RouteChainError(
                f"orphaned: rows for event_ref={event_ref!r} not reachable from the chain head: "
                f"{sorted(r['manifest_hash'] for r in unreached)}",
                failure_mode="orphaned",
                event_ref=event_ref,
            )

        visited.reverse()  # oldest -> newest
        return visited

    def latest_route_manifest_for_event(self, event_ref: str) -> dict | None:
        """The unique chain head - the manifest no other manifest supersedes.

        Raises RouteChainError rather than guessing when the chain is malformed.
        `recorded_at` is never read here - see route_manifest_chain_for_event.
        """
        chain = self.route_manifest_chain_for_event(event_ref)
        if not chain:
            return None
        return chain[-1]

    def raw_route_manifest_rows(self, event_ref: str) -> list[dict]:
        """Every route_manifests row for event_ref, exactly as stored, unordered
        and uninterpreted. For describe_manifest_chain() diagnostics only -
        never used for selection logic."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM route_manifests WHERE event_ref = ?", (event_ref,)
            ).fetchall()
        return [dict(r) for r in rows]

    # -- route_receipts (rail U2b, D1) --------------------------------------

    def insert_route_receipt(
        self,
        *,
        event_ref: str,
        manifest_hash: str,
        beneficiary_pubkey_id: str,
        outcome: str,
        op_payment_id: str | None,
        sent_value: int | None,
        sent_asset_code: str | None,
        sent_asset_scale: int | None,
        leg_status: str,
        reason: str | None,
        receipt_hash: str,
        recorded_at: str,
    ) -> dict:
        """Atomically re-assert head-currency and reconcile the route_receipts row.

        Domain-BEFORE-sign (Facets round-2): this is the atomic claims.db
        critical section that MUST commit before record_route_receipt calls
        record_signed - re-asserts *manifest_hash* is still the chain head for
        *event_ref* on this same connection (a supersession landing after the
        caller's cheap pre-check aborts with RouteReceiptError("not_head")),
        then reconciles the (manifest_hash, beneficiary_pubkey_id) terminal
        slot: a byte-identical repeat of an existing terminal row is a no-op
        (newly_recorded=False), a conflicting terminal submission raises
        RouteReceiptError("outcome_conflict"), and a `failed` submission
        always inserts (failed rows are non-terminal and unconstrained).

        Returns {"row": <dict>, "newly_recorded": bool}. Head-read +
        reconcile + insert run inside one BEGIN IMMEDIATE transaction, so two
        concurrent writers for the same leg cannot both pass the terminal
        check and both insert - the partial unique index
        (route_receipts_terminal_unique) is the backstop if they somehow did;
        a resulting sqlite3.IntegrityError is caught and mapped back into the
        same reconcile-by-read logic, never surfaced raw.
        """
        delay = _LOCK_RETRY_BASE_DELAY
        for attempt in range(_LOCK_RETRY_ATTEMPTS):
            is_last_attempt = attempt == _LOCK_RETRY_ATTEMPTS - 1
            with self._lock:
                try:
                    self._conn.execute("BEGIN IMMEDIATE")
                    return self._insert_route_receipt_txn(
                        event_ref=event_ref,
                        manifest_hash=manifest_hash,
                        beneficiary_pubkey_id=beneficiary_pubkey_id,
                        outcome=outcome,
                        op_payment_id=op_payment_id,
                        sent_value=sent_value,
                        sent_asset_code=sent_asset_code,
                        sent_asset_scale=sent_asset_scale,
                        leg_status=leg_status,
                        reason=reason,
                        receipt_hash=receipt_hash,
                        recorded_at=recorded_at,
                    )
                except (RouteReceiptError, RouteChainError, sqlite3.IntegrityError):
                    raise
                except sqlite3.OperationalError as exc:
                    if not (_is_locked_error(exc) and not is_last_attempt):
                        raise
            time.sleep(delay)
            delay *= 2
        raise sqlite3.OperationalError(
            f"insert_route_receipt: database locked after {_LOCK_RETRY_ATTEMPTS} attempts"
        )

    def _insert_route_receipt_txn(
        self,
        *,
        event_ref: str,
        manifest_hash: str,
        beneficiary_pubkey_id: str,
        outcome: str,
        op_payment_id: str | None,
        sent_value: int | None,
        sent_asset_code: str | None,
        sent_asset_scale: int | None,
        leg_status: str,
        reason: str | None,
        receipt_hash: str,
        recorded_at: str,
    ) -> dict:
        """One BEGIN IMMEDIATE attempt's body. Caller has already opened the
        transaction. Commits on success. Rolls back and re-raises on any
        error - a correct refusal (RouteReceiptError/RouteChainError), a
        schema-level conflict re-raised after reconciliation failed to
        explain it, or anything else (propagated unchanged)."""
        try:
            rows = self._fetch_route_manifest_rows_locked(event_ref)
            chain = self._chain_from_rows(event_ref, rows)
            current_head = chain[-1]["manifest_hash"] if chain else None
            if current_head != manifest_hash:
                raise RouteReceiptError(
                    f"not_head: cited manifest_hash={manifest_hash!r} is no longer the "
                    f"current head for event_ref={event_ref!r} (current head="
                    f"{current_head!r})",
                    failure_mode="not_head",
                )

            result = self._reconcile_route_receipt_insert(
                manifest_hash=manifest_hash,
                beneficiary_pubkey_id=beneficiary_pubkey_id,
                outcome=outcome,
                op_payment_id=op_payment_id,
                sent_value=sent_value,
                sent_asset_code=sent_asset_code,
                sent_asset_scale=sent_asset_scale,
                leg_status=leg_status,
                reason=reason,
                receipt_hash=receipt_hash,
                recorded_at=recorded_at,
            )
            self._conn.commit()
            return result
        except Exception:
            self._conn.rollback()
            raise

    def _reconcile_route_receipt_insert(
        self,
        *,
        manifest_hash: str,
        beneficiary_pubkey_id: str,
        outcome: str,
        op_payment_id: str | None,
        sent_value: int | None,
        sent_asset_code: str | None,
        sent_asset_scale: int | None,
        leg_status: str,
        reason: str | None,
        receipt_hash: str,
        recorded_at: str,
    ) -> dict:
        """Body of the reconcile+insert, assuming an open transaction. No
        commit/rollback here - that is the caller's job."""
        existing = self._conn.execute(
            "SELECT * FROM route_receipts WHERE manifest_hash = ? AND beneficiary_pubkey_id = ? "
            "AND outcome IN ('settled', 'skipped') ORDER BY seq DESC LIMIT 1",
            (manifest_hash, beneficiary_pubkey_id),
        ).fetchone()
        if existing is not None and outcome in ("settled", "skipped"):
            return self._match_or_conflict(
                dict(existing), outcome, op_payment_id, sent_value, sent_asset_code,
                sent_asset_scale, reason,
            )

        try:
            self._conn.execute(
                "INSERT INTO route_receipts "
                "(manifest_hash, beneficiary_pubkey_id, outcome, op_payment_id, sent_value, "
                " sent_asset_code, sent_asset_scale, leg_status, reason, receipt_hash, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    manifest_hash, beneficiary_pubkey_id, outcome, op_payment_id, sent_value,
                    sent_asset_code, sent_asset_scale, leg_status, reason, receipt_hash, recorded_at,
                ),
            )
        except sqlite3.IntegrityError:
            by_hash = self._conn.execute(
                "SELECT * FROM route_receipts WHERE receipt_hash = ?", (receipt_hash,)
            ).fetchone()
            if by_hash is not None:
                return {"row": dict(by_hash), "newly_recorded": False}
            existing2 = self._conn.execute(
                "SELECT * FROM route_receipts WHERE manifest_hash = ? AND beneficiary_pubkey_id = ? "
                "AND outcome IN ('settled', 'skipped') ORDER BY seq DESC LIMIT 1",
                (manifest_hash, beneficiary_pubkey_id),
            ).fetchone()
            if existing2 is None:
                raise
            return self._match_or_conflict(
                dict(existing2), outcome, op_payment_id, sent_value, sent_asset_code,
                sent_asset_scale, reason,
            )

        row = self._conn.execute(
            "SELECT * FROM route_receipts WHERE receipt_hash = ?", (receipt_hash,)
        ).fetchone()
        return {"row": dict(row), "newly_recorded": True}

    def _match_or_conflict(
        self, existing: dict, outcome: str, op_payment_id, sent_value, sent_asset_code,
        sent_asset_scale, reason,
    ) -> dict:
        same = (
            existing["outcome"] == outcome
            and existing["op_payment_id"] == op_payment_id
            and existing["sent_value"] == sent_value
            and existing["sent_asset_code"] == sent_asset_code
            and existing["sent_asset_scale"] == sent_asset_scale
            and existing["reason"] == reason
        )
        if same:
            return {"row": existing, "newly_recorded": False}
        raise RouteReceiptError(
            f"outcome_conflict: manifest_hash={existing['manifest_hash']!r} "
            f"beneficiary_pubkey_id={existing['beneficiary_pubkey_id']!r} already has a "
            f"terminal receipt (outcome={existing['outcome']!r}) that conflicts with this "
            f"submission (outcome={outcome!r})",
            failure_mode="outcome_conflict",
        )

    def list_route_receipts_for_manifest(self, manifest_hash: str) -> list[dict]:
        """Every route_receipts row for manifest_hash, exactly as stored - the
        raw domain rows; per-leg selection + integrity re-verification is
        route_receipts_for_manifest()'s job, not this store's."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM route_receipts WHERE manifest_hash = ?", (manifest_hash,)
            ).fetchall()
        return [dict(r) for r in rows]

    # -- use_terms (rail zephyr-use-terms-consent-v0) ------------------------

    def insert_use_terms(
        self,
        *,
        manifest_hash: str,
        subject: str,
        declared_by: str,
        allowed_uses: list[str],
        denied_uses: list[str],
        scope: str,
        revokes: bool,
        note: str,
        summary: str,
        recorded_at: str,
    ) -> None:
        """Insert a use_terms domain row, LOUD on conflict (mirrors
        insert_route_manifest's pattern, NOT INSERT OR IGNORE).

        Re-inserting byte-identical content is an explicit no-op checked
        BEFORE the write (idempotent re-record). An existing row at the same
        manifest_hash with ANY differing column means a schema guarantee was
        violated: sqlite3.IntegrityError is re-raised, never absorbed - bare
        OR IGNORE would let a pre-seeded row at a predictable future envelope
        hash silently swallow the real declaration. `seq` is store-assigned
        (AUTOINCREMENT) and never caller-settable.
        """
        allowed_json = json.dumps(list(allowed_uses), separators=(",", ":"), sort_keys=True)
        denied_json = json.dumps(list(denied_uses), separators=(",", ":"), sort_keys=True)
        with self._lock:
            existing = self._conn.execute(
                "SELECT * FROM use_terms WHERE manifest_hash = ?", (manifest_hash,)
            ).fetchone()
            if existing is not None:
                row = dict(existing)
                same = (
                    row["subject"] == subject
                    and row["declared_by"] == declared_by
                    and row["allowed_uses"] == allowed_json
                    and row["denied_uses"] == denied_json
                    and row["scope"] == scope
                    and row["revokes"] == int(bool(revokes))
                    and row["note"] == note
                    and row["summary"] == summary
                    and row["recorded_at"] == recorded_at
                )
                if same:
                    return  # byte-identical re-record: no-op
                raise sqlite3.IntegrityError(
                    f"insert_use_terms: a row already exists at manifest_hash={manifest_hash!r} "
                    f"with differing content - refusing to absorb it"
                )
            try:
                self._conn.execute(
                    "INSERT INTO use_terms "
                    "(manifest_hash, subject, declared_by, allowed_uses, denied_uses, scope, "
                    " revokes, note, summary, recorded_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        manifest_hash,
                        subject,
                        declared_by,
                        allowed_json,
                        denied_json,
                        scope,
                        int(bool(revokes)),
                        note,
                        summary,
                        recorded_at,
                    ),
                )
            except sqlite3.IntegrityError:
                # A concurrent insert raced us at the same manifest_hash. If
                # the landed row is byte-identical this is an idempotent
                # re-record; otherwise the guarantee violation stays loud.
                landed = self._conn.execute(
                    "SELECT * FROM use_terms WHERE manifest_hash = ?", (manifest_hash,)
                ).fetchone()
                if landed is None:
                    raise
                row = dict(landed)
                same = (
                    row["subject"] == subject
                    and row["declared_by"] == declared_by
                    and row["allowed_uses"] == allowed_json
                    and row["denied_uses"] == denied_json
                    and row["scope"] == scope
                    and row["revokes"] == int(bool(revokes))
                    and row["note"] == note
                    and row["summary"] == summary
                    and row["recorded_at"] == recorded_at
                )
                if not same:
                    raise
                return
            self._conn.commit()

    def list_use_terms_for_subject(self, subject: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM use_terms WHERE subject = ?", (subject,)
            ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Singleton factory (parallel to get_recorder() / get_registry() / get_signer())
# ---------------------------------------------------------------------------

_STORE: ClaimsStore | None = None
_STORE_LOCK = threading.Lock()


def get_claims_store() -> ClaimsStore:
    """Return the process-wide ClaimsStore singleton.

    Re-reads ZEPHYR_CLAIMS_DB on each (re)creation rather than relying on the
    module-level default (a stale, import-time-frozen constant) so that
    tests can monkeypatch the env var + call _reset_claims_store() and get a
    genuinely fresh, isolated store.
    """
    global _STORE
    if _STORE is None:
        with _STORE_LOCK:
            if _STORE is None:
                db_path = Path(os.environ.get("ZEPHYR_CLAIMS_DB", str(DEFAULT_CLAIMS_DB)))
                _STORE = ClaimsStore(db_path)
    return _STORE


def _reset_claims_store() -> None:
    """For tests - force reload of the claims store on next use."""
    global _STORE
    _STORE = None


# ---------------------------------------------------------------------------
# Canonical hash + integrity bind (attestation-spine read procedure)
# ---------------------------------------------------------------------------


@dataclass
class ClaimIntegrityResult:
    """Result of re-verifying a claims-store domain row against its envelope."""

    ok: bool
    failure_mode: str | None
    payload: dict | None
    envelope: dict | None


def _compute_manifest_hash(payload: dict, prov_dict: dict, summary: str) -> str:
    """Byte-for-byte the archetypes_core.provenance canonical hash algorithm."""
    from archetypes_core.provenance import _canonical_json

    hashable = _canonical_json({"payload": payload, "provenance": prov_dict, "summary": summary})
    return "sha256:" + hashlib.sha256(hashable.encode("utf-8")).hexdigest()


def verify_claim(domain_row: dict, payload: dict, *, log=None, registry=None) -> ClaimIntegrityResult:
    """Recompute + re-verify a domain row's manifest_hash against its attribution.db envelope.

    Steps 2-4 of the D1 read procedure (step 1 - domain row presence - is the
    caller's job, since the caller is the one who looked the row up).
    Never raises; callers decide what a failed result means for them
    (routing.py raises RouteTamperError; resolve_wallet fails closed).
    """
    from zephyr.attribution import get_recorder

    lg = log if log is not None else get_recorder()
    mh = domain_row["manifest_hash"]

    envelope = lg.get(mh, registry=registry)
    if envelope is None:
        return ClaimIntegrityResult(False, "missing_envelope", payload, None)

    prov_dict = json.loads(envelope["provenance_json"])
    for k in ("manifest_hash", "signature", "pubkey_id"):
        prov_dict.pop(k, None)

    recomputed = _compute_manifest_hash(payload, prov_dict, domain_row.get("summary") or "")
    if recomputed != mh:
        return ClaimIntegrityResult(False, "hash_mismatch", payload, envelope)

    if envelope.get("verification_status") != "verified":
        return ClaimIntegrityResult(False, envelope.get("verification_status"), payload, envelope)

    return ClaimIntegrityResult(True, None, payload, envelope)


def _wallet_binding_payload(row: dict) -> dict:
    return {
        "wallet_binding": {
            "subject": row["subject"],
            "wallet_address": row["wallet_address"],
            "revokes": bool(row["revokes"]),
            "note": row["note"] or "",
        }
    }


def _routing_terms_payload(row: dict) -> dict:
    return {
        "routing_terms": {
            "subject": row["subject"],
            "beneficiary_pubkey_id": row["beneficiary_pubkey_id"],
            "share_bps": row["share_bps"],
            "basis": row["basis"],
            "scope": row["scope"],
            "declared_by": row["declared_by"],
            "note": row["note"] or "",
        }
    }


def _route_manifest_payload(row: dict) -> dict:
    return json.loads(row["payload_json"])


def verify_wallet_binding_row(row: dict, *, log=None, registry=None) -> ClaimIntegrityResult:
    return verify_claim(row, _wallet_binding_payload(row), log=log, registry=registry)


def verify_routing_terms_row(row: dict, *, log=None, registry=None) -> ClaimIntegrityResult:
    return verify_claim(row, _routing_terms_payload(row), log=log, registry=registry)


def verify_route_manifest_row(row: dict, *, log=None, registry=None) -> ClaimIntegrityResult:
    return verify_claim(row, _route_manifest_payload(row), log=log, registry=registry)


_ROUTE_RECEIPT_TOOL = "zephyr:route-receipt"


def _route_receipt_summary(manifest_hash: str, beneficiary_pubkey_id: str, outcome: str) -> str:
    """Deterministic from (manifest_hash, beneficiary_pubkey_id, outcome) alone -
    route_receipts has no summary column, so this is recomputed identically
    at write time and at read time rather than stored."""
    return f"route receipt: {manifest_hash} -> {beneficiary_pubkey_id} ({outcome})"


def _route_receipt_payload(row: dict) -> dict:
    sent_amount = (
        {
            "value": row["sent_value"],
            "asset_code": row["sent_asset_code"],
            "asset_scale": row["sent_asset_scale"],
        }
        if row["outcome"] == "settled"
        else None
    )
    return {
        "route_receipt": {
            "manifest_hash": row["manifest_hash"],
            "beneficiary_pubkey_id": row["beneficiary_pubkey_id"],
            "op_payment_id": row["op_payment_id"],
            "sent_amount": sent_amount,
            "leg_status": row["leg_status"],
            "outcome": row["outcome"],
            "reason": row["reason"],
        }
    }


def verify_route_receipt_row(row: dict, *, log=None, registry=None) -> ClaimIntegrityResult:
    """Recompute + re-verify a route_receipts domain row against its own deposit envelope.

    Unlike verify_wallet_binding_row/verify_routing_terms_row/
    verify_route_manifest_row, the envelope is looked up by the row's OWN
    receipt_hash, not by domain_row["manifest_hash"] (which here names the
    CITED route manifest, not the receipt's envelope) - so this cannot
    delegate to verify_claim() directly. Never raises; a crash between the
    domain-row commit and the record_signed deposit (D1's documented residual
    failure) surfaces here as failure_mode="missing_envelope" - the orphan
    domain row is permanently, fail-closed inert to any reader.
    """
    from zephyr.attribution import get_recorder

    lg = log if log is not None else get_recorder()
    payload = _route_receipt_payload(row)
    summary = _route_receipt_summary(row["manifest_hash"], row["beneficiary_pubkey_id"], row["outcome"])
    receipt_hash = row["receipt_hash"]

    envelope = lg.get(receipt_hash, registry=registry)
    if envelope is None:
        return ClaimIntegrityResult(False, "missing_envelope", payload, None)

    prov_dict = json.loads(envelope["provenance_json"])
    for k in ("manifest_hash", "signature", "pubkey_id"):
        prov_dict.pop(k, None)

    recomputed = _compute_manifest_hash(payload, prov_dict, summary)
    if recomputed != receipt_hash:
        return ClaimIntegrityResult(False, "hash_mismatch", payload, envelope)

    if envelope.get("verification_status") != "verified":
        return ClaimIntegrityResult(False, envelope.get("verification_status"), payload, envelope)

    return ClaimIntegrityResult(True, None, payload, envelope)


# ---------------------------------------------------------------------------
# record_wallet_binding - self-signed only
# ---------------------------------------------------------------------------


def record_wallet_binding(
    *,
    subject: str,
    wallet_address: str,
    agent_id: str,
    revokes: bool = False,
    note: str = "",
    signer: "AgentSigner | None" = None,
    registry: "PubkeyRegistry | None" = None,
    recorder: "AttributionLog | None" = None,
    timestamp: str | None = None,
) -> dict:
    """Record a self-signed wallet binding. Returns record_signed's return dict.

    A key binds only itself: the resolved signer's own pubkey_id_str MUST
    equal *subject*. There is no parameter with which to bind a wallet on
    behalf of another party (ratified 2026-07-20 - the proxy/declared-wallet
    backdoor does not exist in this rail).
    """
    from zephyr.attribution import record_signed
    from zephyr.signing import get_signer

    s = signer if signer is not None else get_signer()

    if s.pubkey_id_str != subject:
        raise ValueError(
            f"record_wallet_binding: subject={subject!r} must equal the signer's own "
            f"pubkey_id={s.pubkey_id_str!r} - wallet bindings are self-signed only, "
            f"a key binds only itself."
        )

    parsed = urlparse(wallet_address)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(
            f"record_wallet_binding: wallet_address must be an https URL, got {wallet_address!r}"
        )

    revokes = bool(revokes)
    payload = {
        "wallet_binding": {
            "subject": subject,
            "wallet_address": wallet_address,
            "revokes": revokes,
            "note": note,
        }
    }
    summary = (
        f"wallet binding revocation for {subject}"
        if revokes
        else f"wallet binding: {subject} -> {wallet_address}"
    )

    result = record_signed(
        payload,
        agent_id=agent_id,
        tool="zephyr:wallet-binding",
        store_kind="wallet_binding",
        key=subject,
        signer=s,
        registry=registry,
        recorder=recorder,
        summary=summary,
        timestamp=timestamp,
    )

    store = get_claims_store()
    store.insert_wallet_binding(
        manifest_hash=result["manifest_hash"],
        subject=subject,
        wallet_address=wallet_address,
        revokes=revokes,
        note=note,
        summary=summary,
        recorded_at=timestamp or _now_iso(),
    )
    return result


# ---------------------------------------------------------------------------
# record_routing_terms
# ---------------------------------------------------------------------------


def record_routing_terms(
    *,
    subject: str,
    beneficiary_pubkey_id: str,
    share_bps: int,
    scope: str,
    declared_by: str,
    agent_id: str,
    note: str = "",
    signer: "AgentSigner | None" = None,
    registry: "PubkeyRegistry | None" = None,
    recorder: "AttributionLog | None" = None,
    timestamp: str | None = None,
) -> dict:
    """Record a declared routing term. Returns record_signed's return dict.

    *basis* is fixed to "declared-contract" in v0: a DECLARED ratio, taken as
    given - this helper validates bounds only and never derives a share from
    any property of the contribution (route-not-compute).

    *beneficiary_pubkey_id* must already be registered (hard ValueError
    otherwise): routing terms target only cryptographic identities, never a
    pending/soft identity - key provisioning precedes term declaration.
    """
    from zephyr.attribution import record_signed
    from zephyr.registry import get_registry
    from zephyr.signing import get_signer

    s = signer if signer is not None else get_signer()
    reg = registry if registry is not None else get_registry()

    if not (0 <= share_bps <= 10000):
        raise ValueError(
            f"record_routing_terms: share_bps={share_bps!r} must be in [0, 10000]"
        )

    if not (scope == "standing" or scope.startswith("event:")):
        raise ValueError(
            f"record_routing_terms: scope={scope!r} must be 'standing' or 'event:<ref>'"
        )

    if reg.lookup(beneficiary_pubkey_id) is None:
        raise ValueError(
            f"record_routing_terms: beneficiary_pubkey_id={beneficiary_pubkey_id!r} is not "
            f"registered. Routing terms target only cryptographic identities - provision "
            f"the beneficiary's key before declaring a term for them."
        )

    basis = "declared-contract"
    payload = {
        "routing_terms": {
            "subject": subject,
            "beneficiary_pubkey_id": beneficiary_pubkey_id,
            "share_bps": share_bps,
            "basis": basis,
            "scope": scope,
            "declared_by": declared_by,
            "note": note,
        }
    }
    summary = f"routing term: {subject} -> {beneficiary_pubkey_id} {share_bps}bps ({scope})"

    result = record_signed(
        payload,
        agent_id=agent_id,
        tool="zephyr:routing-terms",
        store_kind="routing_terms",
        key=subject,
        signer=s,
        registry=reg,
        recorder=recorder,
        summary=summary,
        timestamp=timestamp,
    )

    store = get_claims_store()
    store.insert_routing_terms(
        manifest_hash=result["manifest_hash"],
        subject=subject,
        beneficiary_pubkey_id=beneficiary_pubkey_id,
        share_bps=share_bps,
        basis=basis,
        scope=scope,
        declared_by=declared_by,
        note=note,
        summary=summary,
        recorded_at=timestamp or _now_iso(),
    )
    return result


# ---------------------------------------------------------------------------
# resolve_wallet
# ---------------------------------------------------------------------------


def resolve_wallet(
    subject: str,
    *,
    store: "ClaimsStore | None" = None,
    log=None,
    registry: "PubkeyRegistry | None" = None,
) -> str | None:
    """Latest non-revoked, integrity-bound wallet_binding for *subject*.

    "Latest" is store-assigned `seq` (a monotonic AUTOINCREMENT column),
    never caller-supplied `recorded_at` - see D1b. None if absent, revoked,
    or the latest binding fails the integrity bind (fail closed - money must
    not follow an unverifiable claim). Never falls back to an older binding
    when the latest is untrustworthy.

    The attribution log's wallet_binding deposit set is authoritative on
    what bindings exist (D2): every such deposit for *subject* MUST have a
    corresponding domain row here, or RouteTamperError("missing_domain_row")
    - a deleted domain row for a still-deposited binding is tamper, not
    absence.
    """
    from zephyr.attribution import get_recorder
    from zephyr.routing import RouteTamperError  # deferred: routing.py imports claims.py

    st = store if store is not None else get_claims_store()
    lg = log if log is not None else get_recorder()

    deposits = lg.list_by_store_kind_and_key("wallet_binding", subject)
    domain_rows = st.list_wallet_bindings_for_subject(subject)
    domain_by_hash = {r["manifest_hash"]: r for r in domain_rows}

    for dep in deposits:
        mh = dep["manifest_hash"]
        if mh not in domain_by_hash:
            raise RouteTamperError(
                f"missing_domain_row: {mh} (subject={subject})",
                failure_mode="missing_domain_row",
            )

    if not domain_rows:
        return None

    latest = max(domain_rows, key=lambda r: r["seq"])

    result = verify_wallet_binding_row(latest, log=log, registry=registry)
    if not result.ok:
        return None

    if latest["revokes"]:
        return None

    return latest["wallet_address"]


# ---------------------------------------------------------------------------
# use_terms (rail zephyr-use-terms-consent-v0) - signed, revocable use
# declarations on works. The machine REPORTS declarations; it settles nothing
# about permission.
# ---------------------------------------------------------------------------

# The real hash shape this ecosystem produces: "sha256:" + 64 lowercase hex
# (claims.py's own _compute_manifest_hash, demo/run_demo.py's
# compute_manifest_hash). Validated BEFORE any decode or DB write; a
# bare-64-hex gate would reject every real work hash.
_USE_SUBJECT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

_USE_TERMS_TOOL = "zephyr:use-terms"
_USE_TERMS_STORE_KIND = "use_terms"


def _validate_use_subject(subject: str) -> None:
    """DD1: subject is the work's manifest_hash - shape "sha256:"+64 lowercase hex.

    Shape, not work-ness: the gate cannot distinguish sha256(email) from the
    hash of a work, and no existence check runs against attribution.db (the
    work may live on another node - federation forbids coupling the consent
    record to the deposit record's presence). A consent record for a
    nonexistent work is inert, not a defect.
    """
    if not isinstance(subject, str) or not _USE_SUBJECT_RE.match(subject):
        raise ValueError(
            f"use_terms: subject={subject!r} must be a work manifest_hash - "
            f"'sha256:' followed by 64 lowercase hex characters"
        )


def _validate_use_tokens(uses: list[str], field: str) -> list[str]:
    """Closed vocabulary (DD3): every token MUST be in USE_VOCAB."""
    out = []
    for tok in uses:
        if tok not in USE_VOCAB:
            raise ValueError(
                f"use_terms: {field} contains {tok!r} which is not in the use "
                f"vocabulary {USE_VOCAB}"
            )
        out.append(tok)
    return out


def _validate_use_scope(scope: str) -> None:
    """Same grammar as routing_terms (the real check in record_routing_terms):
    "standing" or "event:<ref>" - and additionally rejects a bare "event:"
    with an empty ref. v0 stores+hashes scope but never consults it."""
    if not (scope == "standing" or (isinstance(scope, str) and scope.startswith("event:") and len(scope) > len("event:"))):
        raise ValueError(
            f"use_terms: scope={scope!r} must be 'standing' or 'event:<ref>' "
            f"(with a non-empty ref)"
        )


def _validate_use_declaration(
    allowed_uses: list[str], denied_uses: list[str], revokes: bool
) -> tuple[list[str], list[str]]:
    """DD4/DD5 validator. Applies ONLY to revokes=False rows (DD5's tombstone
    contract exempts them); tombstones declare nothing and MUST carry two
    empty lists, so no semantically meaningless permission is ever signed
    into a tombstone's hash."""
    if revokes:
        if allowed_uses or denied_uses:
            raise ValueError(
                f"use_terms: a revocation (revokes=True) must declare nothing - "
                f"allowed_uses and denied_uses must both be empty, got "
                f"allowed_uses={allowed_uses!r} denied_uses={denied_uses!r}"
            )
        return [], []

    allowed = _validate_use_tokens(list(allowed_uses or []), "allowed_uses")
    denied = _validate_use_tokens(list(denied_uses or []), "denied_uses")

    overlap = set(allowed) & set(denied)
    if overlap:
        raise ValueError(
            f"use_terms: allowed_uses and denied_uses overlap on {sorted(overlap)} - "
            f"a use cannot be both permitted and denied by one declaration "
            f"(vocabulary: {USE_VOCAB})"
        )
    if not allowed and not denied:
        raise ValueError(
            f"use_terms: a declaration must say something - allowed_uses and "
            f"denied_uses must not both be empty (a revocation is the row that "
            f"declares nothing; use revokes=True). Vocabulary: {USE_VOCAB}"
        )
    return allowed, denied


def _use_terms_payload(row: dict) -> dict:
    """The pinned signed envelope (DD8): every verdict-affecting column is
    INSIDE the signed envelope - an omitted field would be DB-flippable while
    verify stays ok. The 4-field wallet sibling is a shape precedent, not a
    field list."""
    return {
        "use_terms": {
            "subject": row["subject"],
            "declared_by": row["declared_by"],
            "allowed_uses": json.loads(row["allowed_uses"]),
            "denied_uses": json.loads(row["denied_uses"]),
            "scope": row["scope"],
            "revokes": bool(row["revokes"]),
            "note": row["note"] or "",
        }
    }


def verify_use_terms_row(row: dict, *, log=None, registry=None) -> ClaimIntegrityResult:
    """Re-verify a use_terms domain row against its deposit envelope.

    Never raises (verify_claim's guarantee): a tampered uses cell that is not
    valid JSON surfaces as failure_mode="malformed_uses_json" instead of
    crashing out of the verify path - a crash would be fail-open-by-crash
    into whatever the consumer's except-block does.
    """
    try:
        payload = _use_terms_payload(row)
    except (json.JSONDecodeError, TypeError, ValueError, KeyError):
        # KeyError too: the try body performs seven bare row[...] subscripts
        # via _use_terms_payload, and a key-missing row dict must land on the
        # same named failure as malformed JSON rather than escape the "never
        # raises" guarantee above (fail-open-by-crash into the caller's
        # except-block is the failure mode this guards).
        return ClaimIntegrityResult(False, "malformed_uses_json", None, None)
    return verify_claim(row, payload, log=log, registry=registry)


def record_use_terms(
    *,
    subject: str,
    allowed_uses: list[str],
    denied_uses: list[str] | None = None,
    scope: str = "standing",
    agent_id: str,
    revokes: bool = False,
    note: str = "",
    signer: "AgentSigner | None" = None,
    registry: "PubkeyRegistry | None" = None,
    recorder: "AttributionLog | None" = None,
    timestamp: str | None = None,
) -> dict:
    """Record a self-declared use declaration on a work. Returns record_signed's return dict.

    SELF-DECLARED ONLY, STRUCTURALLY (DD2): there is NO declared_by parameter
    at all - the value is derived internally as the resolved signer's own
    pubkey_id_str, exactly as record_wallet_binding treats the signer as the
    only declarant. There is no parameter with which to declare use terms on
    another party's behalf: the proxy backdoor does not exist by absence of
    any parameter from which a non-self declared_by could survive.

    *subject* is the work's manifest_hash (DD1 - shape validated before any
    decode or DB write). *revokes=True* writes an additive tombstone that must
    carry empty allowed_uses/denied_uses (DD5): it withdraws, it does not
    redistribute - "credited-but-unpaid, never dropped" applies to the history
    too, so every prior declaration keeps verifying for its era.

    One signing act, two homes (DD7): the deposit (tool="zephyr:use-terms",
    store_kind="use_terms", key=subject) is recorded FIRST via record_signed;
    only then the claims.db domain row, keyed by the consent's OWN envelope
    hash - never the work hash (the work hash is *subject*).
    """
    from zephyr.attribution import record_signed
    from zephyr.signing import get_signer

    _validate_use_subject(subject)
    allowed, denied = _validate_use_declaration(
        list(allowed_uses or []), list(denied_uses or []), bool(revokes)
    )
    _validate_use_scope(scope)

    s = signer if signer is not None else get_signer()
    declared_by = s.pubkey_id_str  # DD2: derived, never caller-supplied
    revokes = bool(revokes)

    payload = {
        "use_terms": {
            "subject": subject,
            "declared_by": declared_by,
            "allowed_uses": allowed,
            "denied_uses": denied,
            "scope": scope,
            "revokes": revokes,
            "note": note,
        }
    }
    summary = (
        f"use terms revocation for {subject}"
        if revokes
        else f"use terms: {subject} allowed={allowed} denied={denied} ({scope})"
    )

    result = record_signed(
        payload,
        agent_id=agent_id,
        tool=_USE_TERMS_TOOL,
        store_kind=_USE_TERMS_STORE_KIND,
        key=subject,
        signer=s,
        registry=registry,
        recorder=recorder,
        summary=summary,
        timestamp=timestamp,
    )

    store = get_claims_store()
    store.insert_use_terms(
        manifest_hash=result["manifest_hash"],
        subject=subject,
        declared_by=declared_by,
        allowed_uses=allowed,
        denied_uses=denied,
        scope=scope,
        revokes=revokes,
        note=note,
        summary=summary,
        recorded_at=timestamp or _now_iso(),
    )
    return result


def _assert_use_terms_deposit_parity(
    subject: str, deposits: list[dict], domain_rows: list[dict]
) -> None:
    """DD7's both-ways deposit-authoritative check.

    Forward (deposit-authoritative): every use_terms deposit for *subject*
    MUST have its domain row - a deleted domain row for a still-deposited
    declaration is tamper, not absence.

    Reverse: every domain row MUST have its deposit still tagged
    (store_kind="use_terms", target_key=subject). Without it, a writer who
    re-tags a tombstone's deposit and deletes its domain row erases a
    revocation into a benign "undeclared" - the transparency log cannot see
    it (leaves cover (seq, manifest_hash) only; store_kind/target_key are
    plain columns outside Merkle coverage).

    Stated honestly (residual): a writer on BOTH dbs who *re-tags* rather than
    deletes can still erase a declaration invisibly to this check; Merkle
    audit detects row deletion, not tag mutation. Reaching that requires a RAW
    write to attribution.db - the same adversary that can reach the Merkle
    anchor; artifact self-certification cannot cover its own host.
    """
    from zephyr.routing import RouteTamperError  # deferred: routing.py imports claims.py

    domain_by_hash = {r["manifest_hash"]: r for r in domain_rows}
    for dep in deposits:
        mh = dep["manifest_hash"]
        if mh not in domain_by_hash:
            raise RouteTamperError(
                f"missing_domain_row: {mh} (subject={subject})",
                failure_mode="missing_domain_row",
            )

    deposit_by_hash = {d["manifest_hash"]: d for d in deposits}
    for row in domain_rows:
        mh = row["manifest_hash"]
        dep = deposit_by_hash.get(mh)
        if (
            dep is None
            or dep.get("store_kind") != _USE_TERMS_STORE_KIND
            or dep.get("target_key") != subject
        ):
            raise RouteTamperError(
                f"orphan_domain_row: {mh} (subject={subject})",
                failure_mode="orphan_domain_row",
            )


def resolve_use_terms(
    subject: str,
    *,
    store: "ClaimsStore | None" = None,
    log=None,
    registry: "PubkeyRegistry | None" = None,
) -> dict | None:
    """The active (seq-max, integrity-ok, non-revoked) use declaration for *subject*.

    Selection mirrors resolve_wallet exactly: the seq-max row over ALL rows
    (tombstones included) is the ONLY candidate; that single row is
    integrity-checked; then its revokes flag is consulted. No older row is
    ever consulted - fail closed, never fall back to an older declaration when
    the latest is untrustworthy. Filtering tombstones out BEFORE selection
    would re-grant permission after revocation.

    Returns None when no active declaration exists (absent, revoked, or the
    latest row fails the integrity bind - each integrity failure logs a WARN
    naming the manifest_hash and its distinct failure_mode, so tamper is never
    a silent "undeclared"). Otherwise returns the pinned consumer-visible
    shape, read from the VERIFIED ClaimIntegrityResult.payload - never from
    raw domain-row columns.

    declared_by is present in the return because the entitlement cross-check
    is the CONSUMER's job: a third party CAN declare on any work hash and
    every integrity check passes - the machine reports WHO declared, never who
    was entitled. Disputes go to the social layer.
    """
    from zephyr.attribution import get_recorder

    st = store if store is not None else get_claims_store()
    lg = log if log is not None else get_recorder()

    _validate_use_subject(subject)

    deposits = lg.list_by_store_kind_and_key(_USE_TERMS_STORE_KIND, subject)
    domain_rows = st.list_use_terms_for_subject(subject)
    _assert_use_terms_deposit_parity(subject, deposits, domain_rows)

    if not domain_rows:
        return None

    latest = max(domain_rows, key=lambda r: r["seq"])

    result = verify_use_terms_row(latest, log=log, registry=registry)
    if not result.ok:
        _log.warning(
            "resolve_use_terms: failing closed on seq=%s manifest_hash=%s (subject=%s) "
            "- integrity bind failed (%s)",
            latest["seq"], latest["manifest_hash"], subject, result.failure_mode,
        )
        return None

    # Read the revocation verdict off the VERIFIED payload, not the raw column,
    # honoring this function's own pinned law: every verdict field comes from
    # the verified ClaimIntegrityResult.payload.
    body = result.payload["use_terms"]

    if body["revokes"]:
        return None

    return {
        "subject": body["subject"],
        "declared_by": body["declared_by"],
        "allowed_uses": list(body["allowed_uses"]),
        "denied_uses": list(body["denied_uses"]),
        "scope": body["scope"],
        "revokes": body["revokes"],
        "seq": latest["seq"],
        "manifest_hash": latest["manifest_hash"],
        "verification": (result.envelope or {}).get("verification_status") or "verified",
    }


def check_use(
    subject: str,
    use: str,
    *,
    store: "ClaimsStore | None" = None,
    log=None,
    registry: "PubkeyRegistry | None" = None,
) -> str:
    """Tri-state report on *use* for the work *subject*: permitted|denied|undeclared.

    The permission-void, mirrored from SplitPolicy: the machine makes no claim
    about what you may do - it proves what was DECLARED, and the absence of a
    declaration is itself visible. "undeclared" is never permission and is
    never more permissive than a prior "denied"; what "undeclared" means for an
    activity is the DOWNSTREAM CONSUMER's call, never Zephyr's.

    An unknown *use* token raises ValueError listing USE_VOCAB - an unknown
    token is never tri-stated.
    """
    if use not in USE_VOCAB:
        raise ValueError(
            f"check_use: use={use!r} is not in the use vocabulary {USE_VOCAB}"
        )

    declaration = resolve_use_terms(subject, store=store, log=log, registry=registry)
    if declaration is None:
        return "undeclared"
    if use in declaration["denied_uses"]:
        return "denied"
    if use in declaration["allowed_uses"]:
        return "permitted"
    return "undeclared"


# ---------------------------------------------------------------------------
# record_route_receipt / route_receipts_for_manifest (rail U2b, D1)
# ---------------------------------------------------------------------------


def record_route_receipt(
    *,
    event_ref: str,
    manifest_hash: str,
    beneficiary_pubkey_id: str,
    outcome: str,
    op_payment_id: str | None = None,
    sent_value: int | None = None,
    sent_asset_code: str | None = None,
    sent_asset_scale: int | None = None,
    reason: str | None = None,
    agent_id: str,
    signer: "AgentSigner | None" = None,
    recorder: "AttributionLog | None" = None,
    store: "ClaimsStore | None" = None,
    log=None,
    registry: "PubkeyRegistry | None" = None,
    timestamp: str | None = None,
) -> dict:
    """Record a per-leg route_receipt: the executor's deposit-back for one
    executed leg of a RouteManifest (rail U2b, D1).

    Python owns signing; a Node executor calls this seam and never touches
    keys, canonical JSON, or SQLite directly. *signer* defaults to the node
    signing key (get_signer()'s process singleton) - there is no parameter
    with which a caller can override it, so a production caller structurally
    cannot sign a route_receipt as anything but the node key.

    Dual-write mirroring record_wallet_binding's shape, but with the ORDER
    INVERTED (Facets round-2 consensus): the atomic claims.db reconciliation
    (ClaimsStore.insert_route_receipt - re-asserts head-currency, enforces
    single-terminal-per-leg) runs and COMMITS FIRST; only after that commit
    is record_signed called to sign and deposit to attribution.db. This makes
    an orphan SIGNED deposit impossible - the only residual failure (a crash
    between the two) leaves an inert orphan DOMAIN row with no envelope,
    which verify_route_receipt_row reports as failure_mode="missing_envelope"
    and route_receipts_for_manifest skips fail-closed. No money moves in this
    unit either way.

    Fail-closed order:
      1. Structural validation of *outcome*'s required fields (ValueError).
      2. Cheap fail-fast head lookup (get_manifest_for_event) - propagates
         RouteChainError/RouteTamperError unchanged; None -> unknown_manifest;
         hash mismatch -> not_head; leg absent -> no_such_leg.
      3. settled-only business checks: leg_status must be "routable"
         (not_routable) and sent_value/asset must equal the leg's manifest
         amount exactly (amount_mismatch).
      4. Atomic claims.db reconciliation (re-asserts head-currency on the
         same connection, closing the TOCTOU window step 2 cannot) - may
         raise RouteReceiptError("not_head") or ("outcome_conflict"), or
         return an idempotent exact-repeat with newly_recorded=False.
      5. Only on a newly-recorded domain row: sign + deposit via record_signed.
    """
    from archetypes_core.provenance import SCHEMA_VERSION_V01, Provenance

    from zephyr.attribution import get_recorder, record_signed
    from zephyr.registry import get_registry
    from zephyr.routing import get_manifest_for_event
    from zephyr.signing import get_signer

    if outcome not in ("settled", "failed", "skipped"):
        raise ValueError(
            f"record_route_receipt: outcome={outcome!r} must be one of "
            f"'settled', 'failed', 'skipped'"
        )

    if outcome == "settled":
        if (
            op_payment_id is None
            or sent_value is None
            or sent_asset_code is None
            or sent_asset_scale is None
        ):
            raise ValueError(
                "record_route_receipt: outcome='settled' requires op_payment_id and all "
                "of sent_value/sent_asset_code/sent_asset_scale to be non-null"
            )
    elif outcome == "skipped":
        if sent_value is not None or sent_asset_code is not None or sent_asset_scale is not None:
            raise ValueError(
                "record_route_receipt: outcome='skipped' must not carry sent_amount fields"
            )
        if reason is None:
            raise ValueError("record_route_receipt: outcome='skipped' requires a reason")

    ts = timestamp or _now_iso()

    if log is None and recorder is not None:
        log = recorder
    if recorder is None and log is not None:
        recorder = log
    lg = log if log is not None else get_recorder()
    rec = recorder if recorder is not None else get_recorder()
    reg = registry if registry is not None else get_registry()
    s = signer if signer is not None else get_signer()
    st = store if store is not None else get_claims_store()

    # ---- Fail-closed head + leg lookup -------------------------------------

    head = get_manifest_for_event(event_ref, store=st, log=lg, registry=reg)
    if head is None:
        raise RouteReceiptError(
            f"unknown_manifest: no manifest exists for event_ref={event_ref!r}",
            failure_mode="unknown_manifest",
        )
    if head["manifest_hash"] != manifest_hash:
        raise RouteReceiptError(
            f"not_head: manifest_hash={manifest_hash!r} is not the current head for "
            f"event_ref={event_ref!r} (current head={head['manifest_hash']!r})",
            failure_mode="not_head",
        )

    route_manifest = head["manifest"]["route_manifest"]
    leg = next(
        (l for l in route_manifest["legs"] if l["beneficiary_pubkey_id"] == beneficiary_pubkey_id),
        None,
    )
    if leg is None:
        raise RouteReceiptError(
            f"no_such_leg: beneficiary_pubkey_id={beneficiary_pubkey_id!r} is not a leg of "
            f"manifest_hash={manifest_hash!r}",
            failure_mode="no_such_leg",
        )

    if outcome == "settled":
        if leg["leg_status"] != "routable":
            raise RouteReceiptError(
                f"not_routable: leg for beneficiary_pubkey_id={beneficiary_pubkey_id!r} has "
                f"leg_status={leg['leg_status']!r}, not 'routable' - a credited-unpaid leg "
                f"cannot be settled",
                failure_mode="not_routable",
            )
        amount_in = route_manifest["amount_in"]
        if (
            sent_value != leg["amount"]
            or sent_asset_code != amount_in["asset_code"]
            or sent_asset_scale != amount_in["asset_scale"]
        ):
            raise RouteReceiptError(
                f"amount_mismatch: sent_value={sent_value!r}/{sent_asset_code!r}/"
                f"{sent_asset_scale!r} does not match leg amount={leg['amount']!r}/"
                f"{amount_in['asset_code']!r}/{amount_in['asset_scale']!r}",
                failure_mode="amount_mismatch",
            )

    # ---- Build payload + precompute receipt_hash ---------------------------

    sent_amount = (
        {"value": sent_value, "asset_code": sent_asset_code, "asset_scale": sent_asset_scale}
        if outcome == "settled"
        else None
    )
    payload = {
        "route_receipt": {
            "manifest_hash": manifest_hash,
            "beneficiary_pubkey_id": beneficiary_pubkey_id,
            "op_payment_id": op_payment_id,
            "sent_amount": sent_amount,
            "leg_status": leg["leg_status"],
            "outcome": outcome,
            "reason": reason,
        }
    }
    summary = _route_receipt_summary(manifest_hash, beneficiary_pubkey_id, outcome)

    # Byte-for-byte the same canonicalization record_signed's to_lapis_return
    # will perform - constructed with the SAME frozen timestamp so both
    # computations land on an identical hash (never a fresh now() each time).
    provenance = Provenance(
        schema_version=SCHEMA_VERSION_V01,
        agent_id=agent_id,
        tool=_ROUTE_RECEIPT_TOOL,
        timestamp=ts,
        manifest_hash="",
    )
    prov_dict = provenance.to_dict()
    for k in ("manifest_hash", "signature", "pubkey_id"):
        prov_dict.pop(k, None)
    receipt_hash = _compute_manifest_hash(payload, prov_dict, summary)

    # ---- Atomic claims.db reconciliation, domain-BEFORE-sign ---------------

    txn_result = st.insert_route_receipt(
        event_ref=event_ref,
        manifest_hash=manifest_hash,
        beneficiary_pubkey_id=beneficiary_pubkey_id,
        outcome=outcome,
        op_payment_id=op_payment_id,
        sent_value=sent_value,
        sent_asset_code=sent_asset_code,
        sent_asset_scale=sent_asset_scale,
        leg_status=leg["leg_status"],
        reason=reason,
        receipt_hash=receipt_hash,
        recorded_at=ts,
    )

    if not txn_result["newly_recorded"]:
        row = txn_result["row"]
        envelope = lg.get(row["receipt_hash"], registry=reg)
        return {
            "receipt_hash": row["receipt_hash"],
            "pubkey_id": (envelope or {}).get("pubkey_id"),
            "signature": (envelope or {}).get("signature"),
            "newly_recorded": False,
            "receipt": payload,
        }

    # ---- Sign + deposit (only after the domain-row commit) -----------------

    result = record_signed(
        payload,
        agent_id=agent_id,
        tool=_ROUTE_RECEIPT_TOOL,
        store_kind="route_receipt",
        key=f"{manifest_hash}:{beneficiary_pubkey_id}",
        signer=s,
        registry=reg,
        recorder=rec,
        summary=summary,
        timestamp=ts,
    )
    assert result["manifest_hash"] == receipt_hash, (
        "record_route_receipt: precomputed receipt_hash does not match record_signed's "
        "own recomputation - canonicalization drifted"
    )

    return {
        "receipt_hash": result["manifest_hash"],
        "pubkey_id": result["pubkey_id"],
        "signature": result["signature"],
        "newly_recorded": True,
        "receipt": payload,
    }


def route_receipts_for_manifest(
    manifest_hash: str, *, store: "ClaimsStore | None" = None, log=None, registry=None
) -> list[dict]:
    """The latest terminal (else latest failed) route_receipt per leg of manifest_hash.

    Queries the route_receipts DOMAIN TABLE by manifest_hash (NOT
    list_by_store_kind_and_key, which is an exact-match on one leg's key and
    cannot enumerate a manifest's receipts). For each leg, selects the latest
    terminal (settled/skipped) row if one exists, else the latest failed row,
    by max(seq) - never by recorded_at. Each candidate is re-verified via
    verify_route_receipt_row(); a row failing the integrity bind for ANY
    reason (including missing_envelope, the orphan-domain-row case) is
    skipped fail-closed and logged, never raised.
    """
    from zephyr.attribution import get_recorder

    st = store if store is not None else get_claims_store()
    lg = log if log is not None else get_recorder()

    rows = st.list_route_receipts_for_manifest(manifest_hash)
    by_leg: dict[str, list[dict]] = {}
    for row in rows:
        by_leg.setdefault(row["beneficiary_pubkey_id"], []).append(row)

    results = []
    for bpid, leg_rows in by_leg.items():
        terminal = [r for r in leg_rows if r["outcome"] in ("settled", "skipped")]
        candidates = terminal if terminal else [r for r in leg_rows if r["outcome"] == "failed"]
        if not candidates:
            continue
        latest = max(candidates, key=lambda r: r["seq"])

        vr = verify_route_receipt_row(latest, log=lg, registry=registry)
        if not vr.ok:
            _log.info(
                "route_receipts_for_manifest: skipping receipt seq=%s beneficiary=%s "
                "manifest_hash=%s - integrity bind failed (%s)",
                latest["seq"], bpid, manifest_hash, vr.failure_mode,
            )
            continue

        results.append(
            {
                "beneficiary_pubkey_id": latest["beneficiary_pubkey_id"],
                "outcome": latest["outcome"],
                "op_payment_id": latest["op_payment_id"],
                "sent_amount": (
                    {
                        "value": latest["sent_value"],
                        "asset_code": latest["sent_asset_code"],
                        "asset_scale": latest["sent_asset_scale"],
                    }
                    if latest["sent_value"] is not None
                    else None
                ),
                "leg_status": latest["leg_status"],
                "reason": latest["reason"],
                "receipt_hash": latest["receipt_hash"],
                "seq": latest["seq"],
            }
        )
    return results
