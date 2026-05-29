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
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = Path(os.environ.get("ZEPHYR_ATTRIBUTION_DB", "/data/zephyr/attribution.db"))

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


class AttributionLog:
    """SQLite-backed deposit log. Thread-safe; one connection guarded by a lock."""

    def __init__(self, db_path: Path | str = DEFAULT_DB):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

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
    ) -> bool:
        """Append a deposit's provenance. Returns True if newly recorded, False if
        the manifest_hash was already present (idempotent duplicate)."""
        mh = provenance.get("manifest_hash")
        if not mh:
            raise ValueError("provenance.manifest_hash is required to record a deposit")
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO deposits "
                "(manifest_hash, agent_id, tool, model, timestamp, store_kind, "
                " target_key, schema_version, provenance_json, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                ),
            )
            self._conn.commit()
            return cur.rowcount > 0

    # -- read / introspection (human-readable surface feeds; not agent-as-dest) --

    def get(self, manifest_hash: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM deposits WHERE manifest_hash = ?", (manifest_hash,)
            ).fetchone()
        return dict(row) if row else None

    def recent(self, limit: int = 50, store_kind: str | None = None) -> list[dict]:
        sql = "SELECT * FROM deposits"
        params: tuple = ()
        if store_kind:
            sql += " WHERE store_kind = ?"
            params = (store_kind,)
        sql += " ORDER BY recorded_at DESC LIMIT ?"
        params = params + (limit,)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) AS n FROM deposits").fetchone()["n"]


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
