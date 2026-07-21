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
/ verify_wallet_binding_row() / verify_routing_terms_row(). The signed
deposit is the sole authority; this store can never make a claim more true
than its envelope says it is.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from zephyr.attribution import AttributionLog
    from zephyr.registry import PubkeyRegistry
    from zephyr.signing import AgentSigner

DEFAULT_CLAIMS_DB = Path(os.environ.get("ZEPHYR_CLAIMS_DB", "/data/zephyr/claims.db"))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS wallet_bindings (
    manifest_hash   TEXT PRIMARY KEY,
    subject         TEXT,
    wallet_address  TEXT,
    revokes         INTEGER,
    note            TEXT,
    summary         TEXT,
    recorded_at     TEXT
);
CREATE INDEX IF NOT EXISTS wallet_bindings_subject ON wallet_bindings(subject);

CREATE TABLE IF NOT EXISTS routing_terms (
    manifest_hash          TEXT PRIMARY KEY,
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
    manifest_hash   TEXT PRIMARY KEY,
    event_ref       TEXT,
    payload_json    TEXT,
    summary         TEXT,
    recorded_at     TEXT,
    supersedes      TEXT
);
CREATE INDEX IF NOT EXISTS route_manifests_event ON route_manifests(event_ref);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# ClaimsStore
# ---------------------------------------------------------------------------


class ClaimsStore:
    """SQLite-backed claims domain store. Thread-safe; one connection guarded by a lock."""

    def __init__(self, db_path: Path | str = DEFAULT_CLAIMS_DB):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

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
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO route_manifests "
                "(manifest_hash, event_ref, payload_json, summary, recorded_at, supersedes) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (manifest_hash, event_ref, payload_json, summary, recorded_at, supersedes),
            )
            self._conn.commit()

    def latest_route_manifest_for_event(self, event_ref: str) -> dict | None:
        """Latest (by recorded_at, tie-break manifest_hash ascending) manifest for event_ref."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM route_manifests WHERE event_ref = ?", (event_ref,)
            ).fetchall()
        if not rows:
            return None
        rows = [dict(r) for r in rows]
        return max(rows, key=lambda r: (r["recorded_at"], r["manifest_hash"]))


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


def verify_wallet_binding_row(row: dict, *, log=None, registry=None) -> ClaimIntegrityResult:
    return verify_claim(row, _wallet_binding_payload(row), log=log, registry=registry)


def verify_routing_terms_row(row: dict, *, log=None, registry=None) -> ClaimIntegrityResult:
    return verify_claim(row, _routing_terms_payload(row), log=log, registry=registry)


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

    None if absent, revoked, or the latest binding fails the integrity bind
    (fail closed - money must not follow an unverifiable claim). Never falls
    back to an older binding when the latest is untrustworthy.
    """
    st = store if store is not None else get_claims_store()

    rows = st.list_wallet_bindings_for_subject(subject)
    if not rows:
        return None

    latest = max(rows, key=lambda r: (r["recorded_at"], r["manifest_hash"]))

    result = verify_wallet_binding_row(latest, log=log, registry=registry)
    if not result.ok:
        return None

    if latest["revokes"]:
        return None

    return latest["wallet_address"]
