"""Zephyr attribution log - canonical deposit/provenance record.

Own SQLite file (default ``/data/zephyr/attribution.db``, override with
``ZEPHYR_ATTRIBUTION_DB``), owned by the zephyr repo - deliberately NOT a table
inside mem.db and NOT a loose jsonl: queryable, layer-independent, and decoupled
from mem.db's convergence/replication lifecycle, so the future ATProto lexicon
projection (lapis.zephyr.work-record / .attribution) stays clean.

One row per unique ``provenance.manifest_hash`` -> the dedup + integrity anchor.
``record()`` is INSERT-OR-IGNORE on that key, so a re-deposited identical envelope
(construct-once / retry-identical-bytes, per the deposit spec's HIGH-1 discipline)
is a no-op and reports ``newly_recorded=False``.

Schema v0.1 additions (nullable, backward-compatible):
  deposits.signature  TEXT  -- hex Ed25519 signature over manifest_hash
  deposits.pubkey_id  TEXT  -- content-addressed key identity ("ed25519:<16hex>")

Signing enforcement is controlled by ZEPHYR_SIGNING_MODE:
  observe (default) -- unsigned deposits accepted + logged as warning
  enforce           -- unsigned deposits rejected

The Tier-0 human-namespace guard fires regardless of ZEPHYR_SIGNING_MODE:
any deposit claiming a human agent_id (``Erah`` or ``human:*``) MUST carry
a valid signature from a registered role="human" key.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from zephyr.signing import AgentSigner
    from zephyr.registry import PubkeyRegistry

DEFAULT_DB = Path(os.environ.get("ZEPHYR_ATTRIBUTION_DB", "/data/zephyr/attribution.db"))

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS deposits (
    manifest_hash   TEXT PRIMARY KEY,
    agent_id        TEXT,
    tool            TEXT,
    model           TEXT,
    timestamp       TEXT,
    store_kind      TEXT,
    target_key      TEXT,
    schema_version  TEXT,
    provenance_json TEXT NOT NULL,
    recorded_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS deposits_agent    ON deposits(agent_id);
CREATE INDEX IF NOT EXISTS deposits_tool     ON deposits(tool);
CREATE INDEX IF NOT EXISTS deposits_recorded ON deposits(recorded_at);
CREATE INDEX IF NOT EXISTS deposits_store    ON deposits(store_kind);
"""

_MIGRATION_COLS = [
    ("signature", "TEXT"),
    ("pubkey_id", "TEXT"),
    ("derived_from", "TEXT"),
]
_MIGRATION_INDEXES = """
CREATE INDEX IF NOT EXISTS deposits_pubkey ON deposits(pubkey_id);
"""


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------


@dataclass
class VerificationResult:
    """Result of verifying a single deposit row at read time."""

    status: str
    """One of: ``verified``, ``unsigned``, ``invalid``, ``unknown_key``,
    ``revoked_key``, ``suspect``."""
    verified: bool
    pubkey_id: str | None = None
    assurance_tier: str | None = None
    """Assurance tier of the signing key (if verified/revoked/suspect)."""
    detail: str | None = None


# ---------------------------------------------------------------------------
# AttributionLog
# ---------------------------------------------------------------------------


class AttributionLog:
    """SQLite-backed deposit log. Thread-safe; one connection guarded by a lock."""

    def __init__(self, db_path: Path | str = DEFAULT_DB):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Additive schema migration: add nullable columns if absent."""
        existing = {
            r["name"]
            for r in self._conn.execute("PRAGMA table_info(deposits)").fetchall()
        }
        for col, coltype in _MIGRATION_COLS:
            if col not in existing:
                self._conn.execute(
                    f"ALTER TABLE deposits ADD COLUMN {col} {coltype}"
                )
        self._conn.executescript(_MIGRATION_INDEXES)

    # -- DepositRecorder Protocol surface ---------------------------------

    def already_recorded(self, manifest_hash: str) -> bool:
        """True if a deposit with this manifest_hash has been recorded."""
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM deposits WHERE manifest_hash = ?", (manifest_hash,)
            ).fetchone()
        return row is not None

    def record(
        self,
        provenance: dict,
        *,
        store_kind: str = "mem",
        key: str | None = None,
        registry: "PubkeyRegistry | None" = None,
    ) -> bool:
        """Append a deposit's provenance.

        Enforcement order (per agent-key-management spec §2):
        1. manifest_hash required.
        2. Tier-0 human-namespace guard (unconditional, regardless of signing mode).
           - Requires signature + pubkey_id.
           - Key must be role='human' and anchor-trusted.
           - Key must not be revoked (strict: no compromise window).
           - Exact-match on agent_id.
        3. Node-vouches rule: if signing key role='node', permit any non-human agent_id.
           Otherwise (role='agent'), require exact agent_id match.
           Reject revoked keys (same as human: cannot deposit with revoked key).
        4. If signature present (non-human): verify (invalid sig is always fatal).
        5. No signature: mode-gated (observe: warn+store NULL; enforce: reject).
        6. Store (INSERT OR IGNORE on manifest_hash).

        Returns True if newly recorded, False if duplicate (idempotent).
        *registry* defaults to the process singleton; pass explicitly in tests.
        """
        from zephyr.registry import (
            get_registry,
            is_human_namespace,
            verify_human_anchor_chain,
        )
        from zephyr.signing import verify_manifest

        mh = provenance.get("manifest_hash")
        if not mh:
            raise ValueError("provenance.manifest_hash is required to record a deposit")

        agent_id = provenance.get("agent_id") or ""
        signature = provenance.get("signature")
        pkid = provenance.get("pubkey_id")

        reg = registry if registry is not None else get_registry()

        # Step 2: Tier-0 human-namespace guard — enforced regardless of signing mode
        if is_human_namespace(agent_id):
            if not signature or not pkid:
                raise PermissionError(
                    f"Tier-0 guard: human-namespace deposit for agent_id={agent_id!r} "
                    f"requires a valid human-role signature and pubkey_id. "
                    f"No signature provided — deposit rejected."
                )
            entry = reg.lookup(pkid)
            if entry is None:
                raise PermissionError(
                    f"Tier-0 guard: human-namespace deposit for agent_id={agent_id!r}: "
                    f"pubkey_id={pkid!r} is not registered. "
                    f"Register the human key out-of-band before depositing."
                )
            if entry.get("role") != "human":
                raise PermissionError(
                    f"Tier-0 guard: human-namespace deposit for agent_id={agent_id!r}: "
                    f"key {pkid!r} has role={entry.get('role')!r}, not 'human'. "
                    f"Only role='human' keys may sign human-namespace deposits."
                )
            if entry.get("agent_id") != agent_id:
                raise PermissionError(
                    f"Tier-0 guard: human-namespace deposit for agent_id={agent_id!r}: "
                    f"key {pkid!r} is registered to agent_id={entry.get('agent_id')!r}. "
                    f"Key/identity mismatch — deposit rejected."
                )

            # Check anchor-chain: human key must be anchor-trusted
            trusted, chain_detail = verify_human_anchor_chain(entry, registry=reg)
            if not trusted:
                raise PermissionError(
                    f"Tier-0 guard: human-namespace deposit for agent_id={agent_id!r}: "
                    f"key {pkid!r} is not anchor-trusted. {chain_detail} — "
                    f"Deposit rejected."
                )

            # Check revocation: human keys must be active (no compromise window at write time)
            if entry.get("status") == "revoked":
                raise PermissionError(
                    f"Tier-0 guard: human-namespace deposit for agent_id={agent_id!r}: "
                    f"key {pkid!r} is revoked (reason={entry.get('revoked_reason')!r}). "
                    f"Deposit rejected."
                )

            # Verify signature
            pub_bytes = bytes.fromhex(entry["public_key_hex"])
            if not verify_manifest(mh, signature, pub_bytes):
                raise PermissionError(
                    f"Tier-0 guard: human-namespace deposit for agent_id={agent_id!r}: "
                    f"signature verification failed — deposit rejected."
                )

        # Step 3: Signature present (non-human-namespace) — always fatal if invalid
        elif signature is not None:
            if not pkid:
                raise ValueError(
                    f"Deposit carries signature but no pubkey_id — cannot verify. "
                    f"agent_id={agent_id!r}"
                )
            entry = reg.lookup(pkid)
            if entry is None:
                raise ValueError(
                    f"Deposit carries unknown pubkey_id={pkid!r}. "
                    f"Register the key before depositing. agent_id={agent_id!r}"
                )

            # Reject deposits via revoked keys (can only deposit with active keys)
            if entry.get("status") == "revoked":
                raise ValueError(
                    f"Deposit signed by revoked key {pkid!r} "
                    f"(reason={entry.get('revoked_reason')!r}). "
                    f"Cannot deposit with a revoked key. agent_id={agent_id!r} — "
                    f"deposit rejected."
                )

            # Node-vouches rule: relax exact-match for node keys
            signing_role = entry.get("role")
            if signing_role == "node":
                # Node can sign for any non-human agent_id
                # (human-namespace already caught above, so we're safe)
                pass
            elif signing_role == "agent":
                # Agent keys require exact agent_id match
                if entry.get("agent_id") != agent_id:
                    raise ValueError(
                        f"Key/agent mismatch: key {pkid!r} is registered to "
                        f"agent_id={entry.get('agent_id')!r} but deposit claims "
                        f"agent_id={agent_id!r} — deposit rejected."
                    )
            else:
                # Unknown role: reject (shouldn't happen if registry.register validates)
                raise ValueError(
                    f"Deposit signed by key {pkid!r} with unknown role={signing_role!r} — "
                    f"deposit rejected."
                )

            pub_bytes = bytes.fromhex(entry["public_key_hex"])
            if not verify_manifest(mh, signature, pub_bytes):
                raise ValueError(
                    f"Signature verification failed for manifest_hash={mh!r}. "
                    f"agent_id={agent_id!r} — deposit rejected."
                )

        # Step 4: No signature — mode-gated
        else:
            mode = os.environ.get("ZEPHYR_SIGNING_MODE", "observe")
            if mode == "enforce":
                raise ValueError(
                    f"ZEPHYR_SIGNING_MODE=enforce: unsigned deposit rejected. "
                    f"agent_id={agent_id!r} manifest_hash={mh!r}. "
                    f"Sign the deposit before recording."
                )
            log.warning(
                "zephyr.attribution: unsigned deposit accepted (observe mode) "
                "agent_id=%r manifest_hash=%r",
                agent_id,
                mh,
            )

        # Step 5: Store
        now = datetime.now(timezone.utc).isoformat()
        newly_recorded = False
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO deposits "
                "(manifest_hash, agent_id, tool, model, timestamp, store_kind, "
                " target_key, schema_version, provenance_json, recorded_at, "
                " signature, pubkey_id, derived_from) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    mh,
                    provenance.get("agent_id"),
                    provenance.get("tool"),
                    provenance.get("model"),
                    provenance.get("timestamp"),
                    store_kind,
                    key,
                    provenance.get("schema_version"),
                    json.dumps(provenance, sort_keys=True),
                    now,
                    signature,
                    pkid,
                    provenance.get("derived_from"),
                ),
            )
            self._conn.commit()
            newly_recorded = cur.rowcount > 0

        # Emit settlement intent if newly recorded and signed
        if newly_recorded and signature and pkid:
            _emit_settlement_intent(provenance)

        return newly_recorded

    # -- read / introspection (human-readable surface feeds; not agent-as-dest) --

    def get(
        self,
        manifest_hash: str,
        *,
        verify: bool = True,
        registry: "PubkeyRegistry | None" = None,
    ) -> dict | None:
        """Return the deposit row for *manifest_hash*, or None.

        Adds a ``verified`` bool and ``verification_status`` str from
        verify_row() when *verify* is True (default).  Pass *registry* to
        use a specific registry instead of the process singleton (useful in tests).
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM deposits WHERE manifest_hash = ?", (manifest_hash,)
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        if verify:
            vr = verify_row(d, registry=registry)
            d["verified"] = vr.verified
            d["verification_status"] = vr.status
        return d

    def recent(
        self,
        limit: int = 50,
        store_kind: str | None = None,
        *,
        verify: bool = True,
        registry: "PubkeyRegistry | None" = None,
    ) -> list[dict]:
        """Return the most recent deposits, newest first.

        *verify=False* skips signature re-check (useful for large bulk reads;
        cost is ~tens of µs per row for Ed25519 verify).  Pass *registry* to
        use a specific registry instead of the process singleton.
        """
        sql = "SELECT * FROM deposits"
        params: tuple = ()
        if store_kind:
            sql += " WHERE store_kind = ?"
            params = (store_kind,)
        sql += " ORDER BY recorded_at DESC LIMIT ?"
        params = params + (limit,)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if verify:
                vr = verify_row(d, registry=registry)
                d["verified"] = vr.verified
                d["verification_status"] = vr.status
            result.append(d)
        return result

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) AS n FROM deposits").fetchone()["n"]

    def list_by_store_kind_and_key(self, store_kind: str, key: str) -> list[dict]:
        """All deposits for (store_kind, key), oldest first. Read-only; no verification.

        The deposit set is the authority on what claims exist for a given
        (store_kind, target_key) pair (rail U2a, D2) - callers require a
        claims-store domain row for every row returned here, raising tamper
        if one is missing, rather than iterating from the domain store (which
        a deletion can silently shrink). Filters target_key in SQL on top of
        the existing deposits_store index; a linear scan within one
        store_kind is acceptable at this scale.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM deposits WHERE store_kind = ? AND target_key = ? "
                "ORDER BY recorded_at ASC",
                (store_kind, key),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_by_pubkey(
        self, pubkey_id: str, *, verify: bool = False, registry: "PubkeyRegistry | None" = None
    ) -> dict | None:
        """Return the first deposit row for a pubkey_id, or None.

        Used by the settler to cross-check that a pubkey_id exists in the attribution DB
        before settling (ensures the key is known, even if attribution is incomplete).

        Returns the most recent deposit by this key (verify=False by default for performance;
        the settler doesn't need signature re-check, just existence).
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM deposits WHERE pubkey_id = ? ORDER BY recorded_at DESC LIMIT 1",
                (pubkey_id,),
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        if verify:
            vr = verify_row(d, registry=registry)
            d["verified"] = vr.verified
            d["verification_status"] = vr.status
        return d

    def write_settlement_info(
        self, manifest_hash: str, op_payment_id: str, settlement_status: str = "settled"
    ) -> bool:
        """Write settlement info back to provenance after Open Payments settlement.

        Best-effort: catches exceptions, logs warnings, returns False on error.
        Never raises or propagates errors.

        Args:
            manifest_hash: The deposit's manifest_hash
            op_payment_id: The resulting Open Payments payment ID
            settlement_status: Status to write (default: 'settled')

        Returns:
            True if written successfully, False on error
        """
        try:
            with self._lock:
                # Read existing row
                row = self._conn.execute(
                    "SELECT provenance_json FROM deposits WHERE manifest_hash = ?",
                    (manifest_hash,),
                ).fetchone()
                if row is None:
                    log.warning(
                        "write_settlement_info: manifest_hash=%r not found in DB",
                        manifest_hash,
                    )
                    return False

                # Update provenance_json with settlement info
                prov = json.loads(row["provenance_json"])
                prov["settlement"] = {
                    "op_payment_id": op_payment_id,
                    "status": settlement_status,
                    "written_at": datetime.now(timezone.utc).isoformat(),
                }

                # Write back (UPDATE)
                self._conn.execute(
                    "UPDATE deposits SET provenance_json = ? WHERE manifest_hash = ?",
                    (json.dumps(prov, sort_keys=True), manifest_hash),
                )
                self._conn.commit()
            return True
        except Exception as e:
            log.warning(
                "write_settlement_info failed for manifest_hash=%r: %s",
                manifest_hash,
                e,
            )
            return False


# ---------------------------------------------------------------------------
# Verify-on-read
# ---------------------------------------------------------------------------


def verify_row(
    row: dict, registry: "PubkeyRegistry | None" = None
) -> VerificationResult:
    """Re-verify a deposit row's signature at read time, with revocation awareness.

    Never raises on a bad signature — surfaces status ``invalid`` instead.
    Reads are always safe even if the registry changes or a key is absent.

    *registry* defaults to the process singleton (get_registry()); pass an
    explicit instance in tests to avoid touching the global singleton.

    Revocation rule (per §3 of agent-key-management spec):
      - Key active: signature valid → verified
      - Key revoked, reason in {rotated, retired}: → verified (clean retirement, history OK)
      - Key revoked, reason=compromised:
          row.timestamp < compromise_suspected_at → verified
          row.timestamp >= compromise_suspected_at → suspect (verified=False)
      - (Signature mismatch is always invalid, regardless of key status)

    Statuses:
      verified    -- signature present, valid, and key is active or cleanly retired
      suspect     -- signature valid but key compromised and row timestamp in suspect window
      unsigned    -- no signature (v0 row or observe-mode deposit)
      unknown_key -- signature present but pubkey_id not in registry
      invalid     -- signature present but verification failed
      revoked_key -- signature valid but key revoked and reason is unknown/missing
    """
    from zephyr.registry import get_registry
    from zephyr.signing import verify_manifest

    sig = row.get("signature")
    pkid = row.get("pubkey_id")
    mh = row.get("manifest_hash", "")

    if not sig or not pkid:
        return VerificationResult(status="unsigned", verified=False)

    try:
        reg = registry if registry is not None else get_registry()
        entry = reg.lookup(pkid)
        if entry is None:
            return VerificationResult(
                status="unknown_key",
                verified=False,
                pubkey_id=pkid,
                detail=f"pubkey_id={pkid!r} not in registry",
            )

        pub_bytes = bytes.fromhex(entry["public_key_hex"])
        ok = verify_manifest(mh, sig, pub_bytes)
        if not ok:
            return VerificationResult(
                status="invalid",
                verified=False,
                pubkey_id=pkid,
                assurance_tier=entry.get("assurance_tier"),
                detail="signature does not verify against registered pubkey",
            )

        # Signature is valid. Now check revocation status.
        status = entry.get("status", "active")
        if status == "active":
            return VerificationResult(
                status="verified",
                verified=True,
                pubkey_id=pkid,
                assurance_tier=entry.get("assurance_tier"),
            )

        # Key is revoked. Check reason and compromise window.
        revoked_reason = entry.get("revoked_reason")
        if revoked_reason in ("rotated", "retired"):
            # Clean retirement: signature is still valid regardless of timestamp
            return VerificationResult(
                status="verified",
                verified=True,
                pubkey_id=pkid,
                assurance_tier=entry.get("assurance_tier"),
                detail=f"key revoked ({revoked_reason}); signature valid before retirement",
            )

        if revoked_reason == "compromised":
            # Check if deposit timestamp is before/after the suspected compromise
            row_timestamp = row.get("timestamp")
            compromise_suspected = entry.get("compromise_suspected_at")

            if not row_timestamp or not compromise_suspected:
                # Can't determine: treat as suspect
                return VerificationResult(
                    status="suspect",
                    verified=False,
                    pubkey_id=pkid,
                    assurance_tier=entry.get("assurance_tier"),
                    detail="key compromised but cannot determine if deposit predates compromise",
                )

            # String comparison (ISO8601 sorts lexicographically)
            is_before_compromise = row_timestamp < compromise_suspected
            if is_before_compromise:
                role = entry.get("role")
                advisory_marker = " (advisory; node/agent key, timestamp self-asserted)" if role in ("node", "agent") else " (cryptographic; human key, anchor-chained)"
                return VerificationResult(
                    status="verified",
                    verified=True,
                    pubkey_id=pkid,
                    assurance_tier=entry.get("assurance_tier"),
                    detail=f"key compromised at {compromise_suspected}; "
                    f"deposit signed before ({row_timestamp}) — before suspect window{advisory_marker}",
                )

            # Signature valid but within compromise window
            role = entry.get("role")
            advisory_marker = " (advisory; node/agent key, timestamp self-asserted)" if role in ("node", "agent") else " (cryptographic; human key, anchor-chained)"
            return VerificationResult(
                status="suspect",
                verified=False,
                pubkey_id=pkid,
                assurance_tier=entry.get("assurance_tier"),
                detail=f"key compromised at {compromise_suspected}; "
                f"deposit signed after ({row_timestamp}) — within suspect window{advisory_marker}",
            )

        # Revoked but reason is unknown/missing
        return VerificationResult(
            status="revoked_key",
            verified=False,
            pubkey_id=pkid,
            assurance_tier=entry.get("assurance_tier"),
            detail=f"key revoked but reason is missing",
        )

    except Exception as exc:
        return VerificationResult(
            status="invalid",
            verified=False,
            pubkey_id=pkid,
            detail=f"verification error: {exc}",
        )


# ---------------------------------------------------------------------------
# Self-signing reference depositor
# ---------------------------------------------------------------------------


def record_signed(
    payload,
    *,
    agent_id: str,
    tool: str,
    store_kind: str = "mem",
    key: str | None = None,
    signer: "AgentSigner | None" = None,
    registry: "PubkeyRegistry | None" = None,
    recorder: "AttributionLog | None" = None,
    summary: str = "",
    **prov_kwargs,
) -> dict:
    """Build a v0.1 signed envelope, auto-register the agent key (TOFU), and record.

    This is the end-to-end signed path Unit 2 will wire the mem-server producer
    to.  It proves: entity signs its own deposit, log stores sig+pubkey_id, reads
    verify.

    Returns a dict with manifest_hash, pubkey_id, signature, newly_recorded.

    Raises ValueError if auto-registration would violate the human-namespace guard
    (agent context may never claim a human agent_id).
    """
    from archetypes_core.provenance import SCHEMA_VERSION_V01, to_lapis_return

    from zephyr.registry import get_registry, is_human_namespace
    from zephyr.signing import get_signer

    if is_human_namespace(agent_id):
        raise ValueError(
            f"record_signed: agent_id={agent_id!r} is in the human namespace. "
            f"Human deposits require a human signing key (Unit 3, out-of-band). "
            f"Use a synthetic or agent-namespace agent_id for automated deposits."
        )

    s = signer if signer is not None else get_signer()
    reg = registry if registry is not None else get_registry()
    rec = recorder if recorder is not None else get_recorder()

    # Build v0.1 envelope (manifest_hash computed by to_lapis_return)
    ltr = to_lapis_return(
        payload,
        agent_id=agent_id,
        tool=tool,
        summary=summary,
        schema_version=SCHEMA_VERSION_V01,
        **prov_kwargs,
    )
    mh = ltr.provenance.manifest_hash

    # TOFU: auto-register if absent (hard guard: human namespace refused above)
    pkid = s.pubkey_id_str
    if reg.lookup(pkid) is None:
        reg.register(pkid, s.public_key_bytes.hex(), agent_id, role="agent")

    # Sign
    sig = s.sign(mh)

    # Build provenance dict with signature + pubkey_id attached
    prov_dict = ltr.provenance.to_dict()
    prov_dict["signature"] = sig
    prov_dict["pubkey_id"] = pkid

    newly_recorded = rec.record(prov_dict, store_kind=store_kind, key=key, registry=reg)

    return {
        "manifest_hash": mh,
        "pubkey_id": pkid,
        "signature": sig,
        "newly_recorded": newly_recorded,
    }


# ---------------------------------------------------------------------------
# Recorder singleton + factory (the injection point for substrate servers)
# ---------------------------------------------------------------------------

_RECORDER: AttributionLog | None = None
_RECORDER_LOCK = threading.Lock()


def get_recorder() -> AttributionLog:
    """Return the process-wide AttributionLog singleton.

    This is the callable substrate servers load via their
    ``*_DEPOSIT_RECORDER=zephyr.attribution:get_recorder`` env (dynamic import,
    so agents-core / weaver never statically import zephyr)."""
    global _RECORDER
    if _RECORDER is None:
        with _RECORDER_LOCK:
            if _RECORDER is None:
                _RECORDER = AttributionLog()
    return _RECORDER


# ---------------------------------------------------------------------------
# Settlement intent emitter singleton + factory
# ---------------------------------------------------------------------------

_EMITTER: callable | None = None
_EMITTER_LOCK = threading.Lock()


def set_emitter(emitter: callable) -> None:
    """Set the settlement intent emitter callable for testing."""
    global _EMITTER
    with _EMITTER_LOCK:
        _EMITTER = emitter


def get_emitter() -> callable | None:
    """Return the configured settlement intent emitter, or None if unconfigured.

    The emitter is loaded from ZEPHYR_DEPOSIT_EVENT_EMITTER=<module>:<callable>.
    If unconfigured, returns None and no intents are emitted.

    The emitter callable receives (provenance: dict) -> None and must not raise
    exceptions that propagate to record(). Any exception is caught and logged."""
    global _EMITTER
    if _EMITTER is not None:
        return _EMITTER

    with _EMITTER_LOCK:
        # Double-check after acquiring lock
        if _EMITTER is not None:
            return _EMITTER

        env_spec = os.environ.get("ZEPHYR_DEPOSIT_EVENT_EMITTER")
        if not env_spec:
            return None

        # Parse <module>:<callable>
        try:
            module_name, func_name = env_spec.rsplit(":", 1)
            import importlib

            module = importlib.import_module(module_name)
            emitter = getattr(module, func_name)
            _EMITTER = emitter
            return emitter
        except (ValueError, ImportError, AttributeError) as e:
            log.error(
                "Failed to load ZEPHYR_DEPOSIT_EVENT_EMITTER=%r: %s",
                env_spec,
                e,
            )
            return None


def _emit_settlement_intent(provenance: dict) -> None:
    """Emit a settlement intent after a signed deposit is recorded.

    Fires outside the attribution DB lock. Any exception is caught and logged
    (never propagates to record() caller). If no emitter is configured, appends
    to the default intent queue.

    Intended to be called once per newly-recorded signed deposit, from record().
    """
    emitter = get_emitter()
    if emitter is None:
        # Default behavior: append to the intent queue
        try:
            from zephyr.intent_queue import get_queue

            queue = get_queue()
            manifest_hash = provenance.get("manifest_hash")
            if manifest_hash:
                queue.append(manifest_hash, provenance)
        except Exception as e:
            log.warning(
                "Failed to append settlement intent to queue: %s",
                e,
                exc_info=True,
            )
        return

    try:
        emitter(provenance)
    except Exception as e:
        log.warning(
            "Settlement intent emitter raised exception (caught, not propagated): %s",
            e,
            exc_info=True,
        )
