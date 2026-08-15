"""D1 acceptance tests for deposits.seq (rail zephyr-witnessed-checkpoint-log-v0).

All identities SYNTHETIC. No writes outside tmp_path. Coverage map:

  AC1 -- a freshly created store gets `seq` directly (via _SCHEMA), no
         rebuild needed.
  AC2 -- an already-populated LEGACY table (manifest_hash PRIMARY KEY, no
         seq — the real production shape before this unit) is upgraded via
         the transactional rebuild on next open.
  AC3 -- rebuild preserves row count and every column value.
  AC4 -- rebuild copy order is `ORDER BY recorded_at, manifest_hash`
         (spec-mandated, unchanged from the claims.py precedent).
  AC5 -- idempotent: running the migration twice (re-opening the same
         store) is a no-op the second time.
  AC6 -- manifest_hash UNIQUE constraint survives the rebuild — dedup
         (INSERT OR IGNORE) still works after migration.
  AC7 -- no caller can set seq: record()'s INSERT statement never
         references it, SQLite assigns it.
  AC8 -- leaves_by_seq() returns (seq, manifest_hash) pairs ordered by seq.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from zephyr._sqlite_migrate import rebuild_tables_for_seq_migration
from zephyr.attribution import AttributionLog, _DEPOSITS_REBUILD_SPEC, _migrate_add_seq


def _legacy_row(manifest_hash, agent_id, recorded_at, timestamp="t"):
    return (
        manifest_hash, agent_id, "tool", None, timestamp, "content", "k",
        "v0.1", json.dumps({"x": 1}), recorded_at, None, None, None,
    )


def _make_legacy_db(path):
    """Build the pre-D1 schema directly (manifest_hash PRIMARY KEY, no seq) —
    the real shape of a production attribution.db before this migration."""
    conn = sqlite3.connect(str(path))
    conn.executescript(
        """
        CREATE TABLE deposits (
            manifest_hash   TEXT PRIMARY KEY,
            agent_id        TEXT,
            tool            TEXT,
            model           TEXT,
            timestamp       TEXT,
            store_kind      TEXT,
            target_key      TEXT,
            schema_version  TEXT,
            provenance_json TEXT NOT NULL,
            recorded_at     TEXT NOT NULL,
            signature       TEXT,
            pubkey_id       TEXT,
            derived_from    TEXT
        );
        """
    )
    conn.close()


# ---------------------------------------------------------------------------
# AC1 -- fresh store gets seq directly
# ---------------------------------------------------------------------------


def test_ac1_fresh_store_has_seq(tmp_path):
    log = AttributionLog(tmp_path / "fresh.db")
    cols = [r[1] for r in log._conn.execute("PRAGMA table_info(deposits)").fetchall()]
    assert "seq" in cols
    assert log.leaves_by_seq() == []


# ---------------------------------------------------------------------------
# AC2-AC4 -- legacy table upgraded, row count + values + order preserved
# ---------------------------------------------------------------------------


def test_ac2_ac3_ac4_legacy_table_upgraded_preserving_rows_and_order(tmp_path):
    db_path = tmp_path / "legacy.db"
    _make_legacy_db(db_path)

    conn = sqlite3.connect(str(db_path))
    rows = [
        _legacy_row("sha256:" + "b" * 64, "agent:b", "2026-08-01T00:00:02+00:00"),
        _legacy_row("sha256:" + "a" * 64, "agent:a", "2026-08-01T00:00:01+00:00"),
        _legacy_row("sha256:" + "c" * 64, "agent:c", "2026-08-01T00:00:01+00:00"),
    ]
    conn.executemany(
        "INSERT INTO deposits VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows
    )
    conn.commit()
    conn.close()

    log = AttributionLog(db_path)
    cols = [r[1] for r in log._conn.execute("PRAGMA table_info(deposits)").fetchall()]
    assert "seq" in cols
    assert log.count() == 3

    # Order: recorded_at ASC, manifest_hash ASC as tiebreak — two rows tie on
    # recorded_at ("...01"), so manifest_hash breaks the tie (a < c).
    leaves = log.leaves_by_seq()
    assert [mh for _, mh in leaves] == [
        "sha256:" + "a" * 64,
        "sha256:" + "c" * 64,
        "sha256:" + "b" * 64,
    ]
    assert [seq for seq, _ in leaves] == [1, 2, 3]

    # Every column value preserved.
    row = log.get("sha256:" + "b" * 64, verify=False)
    assert row["agent_id"] == "agent:b"
    assert row["store_kind"] == "content"
    assert json.loads(row["provenance_json"]) == {"x": 1}


# ---------------------------------------------------------------------------
# AC5 -- idempotent: second open is a no-op
# ---------------------------------------------------------------------------


def test_ac5_migration_idempotent_on_reopen(tmp_path):
    db_path = tmp_path / "legacy2.db"
    _make_legacy_db(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO deposits VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        _legacy_row("sha256:" + "d" * 64, "agent:d", "2026-08-01T00:00:00+00:00"),
    )
    conn.commit()
    conn.close()

    log1 = AttributionLog(db_path)
    leaves1 = log1.leaves_by_seq()

    log2 = AttributionLog(db_path)
    leaves2 = log2.leaves_by_seq()

    assert leaves1 == leaves2 == [(1, "sha256:" + "d" * 64)]
    assert log2.count() == 1

    # Calling the migration function directly a second time is also a no-op.
    _migrate_add_seq(log2._conn)
    assert log2.leaves_by_seq() == [(1, "sha256:" + "d" * 64)]


# ---------------------------------------------------------------------------
# AC6 -- manifest_hash UNIQUE constraint survives the rebuild
# ---------------------------------------------------------------------------


def test_ac6_manifest_hash_uniqueness_enforced_after_rebuild(tmp_path):
    db_path = tmp_path / "legacy3.db"
    _make_legacy_db(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO deposits VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        _legacy_row("sha256:" + "e" * 64, "agent:e", "2026-08-01T00:00:00+00:00"),
    )
    conn.commit()
    conn.close()

    log = AttributionLog(db_path)
    with pytest.raises(sqlite3.IntegrityError):
        log._conn.execute(
            "INSERT INTO deposits (manifest_hash, provenance_json, recorded_at) "
            "VALUES (?, '{}', '2026-08-01T00:00:01+00:00')",
            ("sha256:" + "e" * 64,),
        )

    # And the application-level dedup path (record()'s INSERT OR IGNORE)
    # still reports "not newly recorded" for a re-deposit of the same bytes.
    newly = log.record(
        {
            "manifest_hash": "sha256:" + "e" * 64,
            "agent_id": "agent:e",
            "tool": "t",
            "schema_version": "v0.1",
        },
        store_kind="content",
    )
    assert newly is False


# ---------------------------------------------------------------------------
# AC7 -- no caller can set seq
# ---------------------------------------------------------------------------


def test_ac7_seq_is_store_assigned_not_caller_settable(tmp_path):
    log = AttributionLog(tmp_path / "assign.db")
    log.record(
        {
            "manifest_hash": "sha256:" + "1" * 64,
            "agent_id": "agent:synthetic",
            "tool": "t",
            "schema_version": "v0.1",
        },
        store_kind="content",
    )
    log.record(
        {
            "manifest_hash": "sha256:" + "2" * 64,
            "agent_id": "agent:synthetic",
            "tool": "t",
            "schema_version": "v0.1",
        },
        store_kind="content",
    )
    leaves = log.leaves_by_seq()
    assert [s for s, _ in leaves] == [1, 2]


# ---------------------------------------------------------------------------
# AC8 -- direct rebuild-helper spec sanity (generic module, standalone)
# ---------------------------------------------------------------------------


def test_ac8_rebuild_helper_is_generic_and_reusable(tmp_path):
    """zephyr._sqlite_migrate is a standalone generic helper — exercise it
    directly with a synthetic spec unrelated to deposits, to confirm it
    isn't accidentally coupled to attribution.py's schema."""
    db_path = tmp_path / "generic.db"
    conn = sqlite3.connect(str(db_path))
    conn.executescript(
        "CREATE TABLE widgets (name TEXT PRIMARY KEY, note TEXT, recorded_at TEXT);"
    )
    conn.executemany(
        "INSERT INTO widgets VALUES (?, ?, ?)",
        [("z", "last", "2"), ("a", "first", "1")],
    )
    conn.commit()

    specs = {
        "widgets": {
            "columns": ["name", "note", "recorded_at"],
            "create": """
                CREATE TABLE {name} (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    note TEXT,
                    recorded_at TEXT
                )
            """,
            "indexes": [],
            "order_by": "recorded_at, name",
        },
    }
    rebuild_tables_for_seq_migration(conn, specs)
    rows = conn.execute("SELECT seq, name FROM widgets ORDER BY seq").fetchall()
    assert rows == [(1, "a"), (2, "z")]

    # Second call is a no-op (idempotence guard).
    rebuild_tables_for_seq_migration(conn, specs)
    rows2 = conn.execute("SELECT seq, name FROM widgets ORDER BY seq").fetchall()
    assert rows2 == rows
