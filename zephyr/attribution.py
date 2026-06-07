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
    """One of: ``verified``, ``unsigned``, ``invalid``, ``unknown_key``."""
    verified: bool
    pubkey_id: str | None = None
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

        Enforcement order:
        1. manifest_hash required.
        2. Tier-0 human-namespace guard (unconditional, regardless of signing mode).
        3. If signature present: verify (invalid sig is always fatal).
        4. No signature: mode-gated (observe: warn+store NULL; enforce: reject).
        5. Store (INSERT OR IGNORE on manifest_hash).

        Returns True if newly recorded, False if duplicate (idempotent).
        *registry* defaults to the process singleton; pass explicitly in tests.
        """
        from zephyr.registry import get_registry, is_human_namespace
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
            if entry.get("agent_id") != agent_id:
                raise ValueError(
                    f"Key/agent mismatch: key {pkid!r} is registered to "
                    f"agent_id={entry.get('agent_id')!r} but deposit claims "
                    f"agent_id={agent_id!r} — deposit rejected."
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
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO deposits "
                "(manifest_hash, agent_id, tool, model, timestamp, store_kind, "
                " target_key, schema_version, provenance_json, recorded_at, "
                " signature, pubkey_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                ),
            )
            self._conn.commit()
            return cur.rowcount > 0

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


# ---------------------------------------------------------------------------
# Verify-on-read
# ---------------------------------------------------------------------------


def verify_row(
    row: dict, registry: "PubkeyRegistry | None" = None
) -> VerificationResult:
    """Re-verify a deposit row's signature at read time.

    Never raises on a bad signature — surfaces status ``invalid`` instead.
    Reads are always safe even if the registry changes or a key is absent.

    *registry* defaults to the process singleton (get_registry()); pass an
    explicit instance in tests to avoid touching the global singleton.

    Statuses:
      verified    -- signature present and valid
      unsigned    -- no signature (v0 row or observe-mode deposit)
      unknown_key -- signature present but pubkey_id not in registry
      invalid     -- signature present but verification failed
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
        if ok:
            return VerificationResult(status="verified", verified=True, pubkey_id=pkid)
        return VerificationResult(
            status="invalid",
            verified=False,
            pubkey_id=pkid,
            detail="signature does not verify against registered pubkey",
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
