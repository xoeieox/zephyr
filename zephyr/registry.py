"""Zephyr pubkey registry — flat, human-readable directory of known public keys.

One JSON file per key: ``<pubkey_id>.json`` under ZEPHYR_KEYS_DIR
(default ``/data/zephyr/keys/``).

Schema per entry (backward-compatible additive):
  {pubkey_id, public_key_hex, agent_id, role: "agent"|"node"|"human", added_at, note,
   status: "active"|"revoked" (default "active"),
   valid_from: ISO8601 (default added_at),
   revoked_at: ISO8601 | null,
   revoked_reason: "rotated"|"retired"|"compromised" | null,
   compromise_suspected_at: ISO8601 | null,
   assurance_tier: "warm"|"hardware"|"node" (default by role),
   node_binding: {node, hostname, tailscale_ip} | null,
   registered_by: {signer_pkid, signature} | null}

Human-role entries are added out-of-band (never from an agent context).
Agent/node keys auto-register on first deposit (TOFU) but may not claim the
human namespace — the hard rule enforced here and in record().

Human keys require anchor-chain verification: a depth-1 signature from the
pinned root anchor (ZEPHYR_HUMAN_ROOT_ANCHOR), unless the key *is* the anchor itself.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_KEYS_DIR = Path(os.environ.get("ZEPHYR_KEYS_DIR", "/data/zephyr/keys"))

# Pinned root anchor for human-key trust chain (must be set/overridden before trust is granted)
ZEPHYR_HUMAN_ROOT_ANCHOR: str | None = os.environ.get(
    "ZEPHYR_HUMAN_ROOT_ANCHOR", None
)

# ---------------------------------------------------------------------------
# Human-namespace constants (single definition; attribution.py imports these)
# ---------------------------------------------------------------------------

# Exact agent_ids that are reserved as human
HUMAN_EXACT: frozenset[str] = frozenset({"Erah"})
# Prefixes that mark an agent_id as human-namespace
HUMAN_PREFIXES: tuple[str, ...] = ("human:",)


def is_human_namespace(agent_id: str) -> bool:
    """Return True if *agent_id* falls in the reserved human namespace."""
    if agent_id in HUMAN_EXACT:
        return True
    return any(agent_id.startswith(p) for p in HUMAN_PREFIXES)


# ---------------------------------------------------------------------------
# PubkeyRegistry
# ---------------------------------------------------------------------------


class PubkeyRegistry:
    """Flat-file pubkey registry.  Thread-safe read/write (per-file lock)."""

    def __init__(self, keys_dir: Path = DEFAULT_KEYS_DIR):
        self._dir = keys_dir
        self._lock = threading.Lock()

    def _path(self, pkid: str) -> Path:
        return self._dir / f"{pkid}.json"

    def register(
        self,
        pkid: str,
        public_key_hex: str,
        agent_id: str,
        role: str,
        note: str = "",
        valid_from: str | None = None,
        assurance_tier: str | None = None,
        node_binding: dict[str, Any] | None = None,
        registered_by: dict[str, str] | None = None,
    ) -> dict:
        """Write a new pubkey entry.  Idempotent: returns existing entry unchanged
        if *pkid* is already registered.

        Hard rule: an agent-context registration may not claim the human namespace
        (role="agent" + human-namespace agent_id → ValueError).
        role="node" may not claim human namespace either (same guard applies).

        *node_binding* is required when role="node"; a dict {node, hostname, tailscale_ip}.
        *registered_by* is required for role="human" entries that are not the root anchor.
        *assurance_tier* defaults by role if omitted:
          role="human" → "hardware"
          role="node" → "node"
          role="agent" → "warm"
        """
        if role not in ("agent", "node", "human"):
            raise ValueError(f"role must be 'agent', 'node', or 'human', got {role!r}")

        if (role in ("agent", "node")) and is_human_namespace(agent_id):
            raise ValueError(
                f"auto-registration refused: {role} context cannot claim "
                f"human-namespace agent_id {agent_id!r}. "
                f"Human-role entries are added out-of-band only."
            )

        if role == "node" and node_binding is None:
            raise ValueError(
                f"register: role='node' requires node_binding "
                f"(dict with node, hostname, tailscale_ip)"
            )

        existing = self.lookup(pkid)
        if existing is not None:
            return existing

        try:
            self._dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise OSError(
                f"Cannot create keys directory {self._dir} — "
                f"run: mkdir -p {self._dir} && chown user {self._dir}\n"
                f"Original error: {exc}"
            ) from exc

        now = datetime.now(timezone.utc).isoformat()
        default_tier = {"human": "hardware", "node": "node", "agent": "warm"}.get(role, "warm")

        entry = {
            "pubkey_id": pkid,
            "public_key_hex": public_key_hex,
            "agent_id": agent_id,
            "role": role,
            "added_at": now,
            "note": note,
            "status": "active",
            "valid_from": valid_from or now,
            "revoked_at": None,
            "revoked_reason": None,
            "compromise_suspected_at": None,
            "assurance_tier": assurance_tier or default_tier,
        }
        if node_binding is not None:
            entry["node_binding"] = node_binding
        if registered_by is not None:
            entry["registered_by"] = registered_by

        path = self._path(pkid)
        with self._lock:
            if not path.exists():
                path.write_text(json.dumps(entry, indent=2, sort_keys=True))
                log.info(
                    "zephyr.registry: registered %s role=%s agent_id=%r",
                    pkid, role, agent_id,
                )
        return entry

    def revoke(
        self,
        pkid: str,
        *,
        reason: str,
        suspected_at: str | None = None,
        note: str = "",
    ) -> dict:
        """Revoke a registered key (idempotent; once revoked, always revoked).

        *reason* must be one of: "rotated", "retired", "compromised".
        *suspected_at* (ISO8601) is used for reason="compromised" to record when
        the compromise was suspected. If omitted and reason="compromised",
        defaults to revoked_at and logs a warning that the window is unknown.

        Monotonic: revoking an already-revoked key returns the existing entry unchanged.
        There is no un-revoke; re-trust = register a new key.

        Returns the revoked entry.

        NOTE: This method does NOT enforce human-key authorization here; that gating
        lives in attribution.record() per §2 of the spec (it's a write-path concern,
        not a registry concern). A future binding may add a credential parameter
        if registry enforcement becomes desirable.
        """
        if reason not in ("rotated", "retired", "compromised"):
            raise ValueError(
                f"revoke: reason must be 'rotated', 'retired', or 'compromised', "
                f"got {reason!r}"
            )

        entry = self.lookup(pkid)
        if entry is None:
            raise ValueError(f"revoke: pubkey_id={pkid!r} not in registry")

        # Idempotent: if already revoked, return unchanged
        if entry.get("status") == "revoked":
            return entry

        now = datetime.now(timezone.utc).isoformat()
        entry["status"] = "revoked"
        entry["revoked_at"] = now
        entry["revoked_reason"] = reason

        if reason == "compromised":
            if suspected_at is None:
                entry["compromise_suspected_at"] = now
                log.warning(
                    "zephyr.registry: revoke %s reason=compromised with window unknown "
                    "(suspected_at omitted; defaulted to revoked_at)",
                    pkid,
                )
            else:
                entry["compromise_suspected_at"] = suspected_at

        path = self._path(pkid)
        with self._lock:
            path.write_text(json.dumps(entry, indent=2, sort_keys=True))
            log.info(
                "zephyr.registry: revoked %s reason=%s agent_id=%r",
                pkid, reason, entry.get("agent_id"),
            )
        return entry

    def lookup(self, pkid: str) -> dict | None:
        """Return the registry entry for *pkid*, or None if not found.

        Backward-compatible: entries without new fields (v0 legacy) read with
        defaults: status="active", valid_from=added_at, revoked_*=None,
        assurance_tier defaulted by role.
        """
        path = self._path(pkid)
        if not path.exists():
            return None
        try:
            entry = json.loads(path.read_text())
            return self._normalize_entry(entry)
        except Exception as exc:
            log.warning("zephyr.registry: corrupt entry at %s: %s", path, exc)
            return None

    def _normalize_entry(self, entry: dict) -> dict:
        """Ensure an entry has all expected fields (backward compatibility)."""
        # Defaults for new v0.2 fields
        if "status" not in entry:
            entry["status"] = "active"
        if "valid_from" not in entry:
            entry["valid_from"] = entry.get("added_at", datetime.now(timezone.utc).isoformat())
        if "revoked_at" not in entry:
            entry["revoked_at"] = None
        if "revoked_reason" not in entry:
            entry["revoked_reason"] = None
        if "compromise_suspected_at" not in entry:
            entry["compromise_suspected_at"] = None

        # Assurance tier defaults by role
        if "assurance_tier" not in entry:
            role = entry.get("role", "agent")
            entry["assurance_tier"] = {
                "human": "hardware",
                "node": "node",
                "agent": "warm",
            }.get(role, "warm")

        return entry

    def load_all(self) -> list[dict]:
        """Return all registry entries (unsorted).  Returns [] if dir absent.

        Backward-compatible: entries are normalized to include all new fields.
        """
        if not self._dir.exists():
            return []
        entries = []
        for p in sorted(self._dir.glob("*.json")):
            try:
                entry = json.loads(p.read_text())
                entries.append(self._normalize_entry(entry))
            except Exception as exc:
                log.warning("zephyr.registry: skipping corrupt entry %s: %s", p, exc)
        return entries


# ---------------------------------------------------------------------------
# Singleton factory (parallel to get_recorder())
# ---------------------------------------------------------------------------

_REGISTRY: PubkeyRegistry | None = None
_REGISTRY_LOCK = threading.Lock()


def get_registry() -> PubkeyRegistry:
    """Return the process-wide PubkeyRegistry singleton."""
    global _REGISTRY
    if _REGISTRY is None:
        with _REGISTRY_LOCK:
            if _REGISTRY is None:
                _REGISTRY = PubkeyRegistry()
    return _REGISTRY


# ---------------------------------------------------------------------------
# Human-key anchor-chain verification
# ---------------------------------------------------------------------------


def verify_human_anchor_chain(
    entry: dict, registry: "PubkeyRegistry | None" = None
) -> tuple[bool, str]:
    """Verify that a role='human' registry entry chains to the pinned root anchor.

    Returns (trusted, detail) where:
      (True, "...")  -- the entry is anchor-trusted and may be used for deposits
      (False, "...") -- the entry is NOT trusted (no/invalid registered_by or wrong anchor)

    A human entry is trusted iff:
      1. Its pubkey_id IS the pinned root anchor (the bootstrap case), OR
      2. It carries a valid registered_by signature from the anchor key itself

    Signature target is the canonical UTF-8 bytes of
    json.dumps([pubkey_id, public_key_hex, agent_id, valid_from], separators=(',', ':'))
    (fixed order, no whitespace).

    If ZEPHYR_HUMAN_ROOT_ANCHOR is unset, all human entries are untrusted.
    """
    from zephyr.signing import verify_manifest

    if entry.get("role") != "human":
        return False, "entry is not role='human'"

    # Anchor is unset: no human entries are trusted
    if ZEPHYR_HUMAN_ROOT_ANCHOR is None:
        return False, "ZEPHYR_HUMAN_ROOT_ANCHOR is not configured"

    pkid = entry.get("pubkey_id")
    if not pkid:
        return False, "entry has no pubkey_id"

    # Bootstrap: the entry IS the anchor
    if pkid == ZEPHYR_HUMAN_ROOT_ANCHOR:
        return True, "entry is the pinned root anchor"

    # Non-anchor: must have a valid registered_by signature from the anchor
    registered_by = entry.get("registered_by")
    if not registered_by:
        return False, "non-anchor entry has no registered_by signature"

    signer_pkid = registered_by.get("signer_pkid")
    signature = registered_by.get("signature")
    if not signer_pkid or not signature:
        return False, "registered_by missing signer_pkid or signature"

    if signer_pkid != ZEPHYR_HUMAN_ROOT_ANCHOR:
        return (
            False,
            f"registered_by signer_pkid {signer_pkid!r} is not the pinned anchor "
            f"{ZEPHYR_HUMAN_ROOT_ANCHOR!r}",
        )

    # Load the anchor key from the registry
    reg = registry if registry is not None else get_registry()
    anchor_entry = reg.lookup(ZEPHYR_HUMAN_ROOT_ANCHOR)
    if anchor_entry is None:
        return False, f"pinned anchor {ZEPHYR_HUMAN_ROOT_ANCHOR!r} not in registry"

    # Verify signature over the canonical signing target
    signing_target = json.dumps(
        [pkid, entry["public_key_hex"], entry["agent_id"], entry.get("valid_from", "")],
        separators=(",", ":"),
    )
    anchor_pubkey_hex = anchor_entry.get("public_key_hex")
    if not anchor_pubkey_hex:
        return False, f"anchor {ZEPHYR_HUMAN_ROOT_ANCHOR!r} has no public_key_hex"

    try:
        anchor_pubkey_bytes = bytes.fromhex(anchor_pubkey_hex)
    except ValueError:
        return False, f"anchor {ZEPHYR_HUMAN_ROOT_ANCHOR!r} public_key_hex is invalid hex"

    # The signature must verify the signing_target (not a manifest_hash)
    # We use verify_manifest but pass signing_target as manifest_hash
    if not verify_manifest(signing_target, signature, anchor_pubkey_bytes):
        return False, "registered_by signature does not verify"

    return True, "registered_by signature verified from anchor"


def _reset_registry() -> None:
    """For tests — force reload of registry on next use."""
    global _REGISTRY
    _REGISTRY = None
