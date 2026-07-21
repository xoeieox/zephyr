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
import os
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

__all__ = [
    "ClaimsStore",
    "RouteChainError",
    "ClaimIntegrityResult",
    "get_claims_store",
    "record_wallet_binding",
    "record_routing_terms",
    "resolve_wallet",
    "verify_claim",
    "verify_wallet_binding_row",
    "verify_routing_terms_row",
    "verify_route_manifest_row",
]

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
            rows = self._conn.execute(
                "SELECT * FROM route_manifests WHERE event_ref = ?", (event_ref,)
            ).fetchall()
        rows = [dict(r) for r in rows]
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
