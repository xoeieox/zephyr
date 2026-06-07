"""Zephyr pubkey registry — flat, human-readable directory of known public keys.

One JSON file per key: ``<pubkey_id>.json`` under ZEPHYR_KEYS_DIR
(default ``/data/zephyr/keys/``).

Schema per entry:
  {pubkey_id, public_key_hex, agent_id, role: "agent"|"human", added_at, note}

Human-role entries are added out-of-band (never from an agent context).
Agent keys auto-register on first deposit (TOFU) but may not claim the
human namespace — the hard rule enforced here and in record().
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_KEYS_DIR = Path(os.environ.get("ZEPHYR_KEYS_DIR", "/data/zephyr/keys"))

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
    ) -> dict:
        """Write a new pubkey entry.  Idempotent: returns existing entry unchanged
        if *pkid* is already registered.

        Hard rule: an agent-context registration may not claim the human namespace
        (role="agent" + human-namespace agent_id → ValueError).
        """
        if role not in ("agent", "human"):
            raise ValueError(f"role must be 'agent' or 'human', got {role!r}")
        if role == "agent" and is_human_namespace(agent_id):
            raise ValueError(
                f"auto-registration refused: an agent context cannot claim "
                f"human-namespace agent_id {agent_id!r}. "
                f"Human-role entries are added out-of-band only."
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

        entry = {
            "pubkey_id": pkid,
            "public_key_hex": public_key_hex,
            "agent_id": agent_id,
            "role": role,
            "added_at": datetime.now(timezone.utc).isoformat(),
            "note": note,
        }
        path = self._path(pkid)
        with self._lock:
            if not path.exists():
                path.write_text(json.dumps(entry, indent=2, sort_keys=True))
                log.info(
                    "zephyr.registry: registered %s role=%s agent_id=%r",
                    pkid, role, agent_id,
                )
        return entry

    def lookup(self, pkid: str) -> dict | None:
        """Return the registry entry for *pkid*, or None if not found."""
        path = self._path(pkid)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text())
        except Exception as exc:
            log.warning("zephyr.registry: corrupt entry at %s: %s", path, exc)
            return None

    def load_all(self) -> list[dict]:
        """Return all registry entries (unsorted).  Returns [] if dir absent."""
        if not self._dir.exists():
            return []
        entries = []
        for p in sorted(self._dir.glob("*.json")):
            try:
                entries.append(json.loads(p.read_text()))
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


def _reset_registry() -> None:
    """For tests — force reload of registry on next use."""
    global _REGISTRY
    _REGISTRY = None
