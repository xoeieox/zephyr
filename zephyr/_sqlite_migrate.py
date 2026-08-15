"""zephyr/_sqlite_migrate.py — shared transactional table-rebuild helper.

SQLite forbids adding an ``INTEGER PRIMARY KEY AUTOINCREMENT`` column to an
existing table via ``ALTER TABLE ADD COLUMN``, so any store that needs a
store-assigned monotonic sequence on an already-populated table must rebuild
it: create a ``_new`` table with the new schema, copy every row across in a
caller-chosen order, drop the old table, rename the new one into place — all
inside one ``BEGIN IMMEDIATE`` transaction, so a half-upgraded schema (an
orphaned ``_new`` table or a dropped original) is impossible; SQLite DDL is
transactional, so it commits or rolls back as a unit.

This is the GENERIC form of ``zephyr/claims.py``'s ``_migrate_add_seq`` (rail
U2a), factored out for ``zephyr/attribution.py``'s D1 (rail
zephyr-witnessed-checkpoint-log-v0 — store-assigned ``deposits.seq``, the
leaf-ordering prerequisite for the RFC 6962 transparency log in
``zephyr/transparency.py``).

Deliberately a NEW module, not a refactor of ``claims.py``:

1. ``claims.py``'s ``_TABLE_REBUILD_SPECS`` registers ``wallet_bindings``,
   ``routing_terms``, and ``route_manifests`` — never ``deposits``.
2. ``claims.py`` operates against ``ZEPHYR_CLAIMS_DB`` (``claims.db``);
   ``deposits`` lives in ``attribution.py`` against a different file
   (``ZEPHYR_ATTRIBUTION_DB``, default ``/data/zephyr/attribution.db``).
   ``claims.py`` already imports ``attribution.py`` (for
   ``AttributionLog.list_by_store_kind_and_key``), so ``attribution.py``
   must not import ``claims.py`` — the same cycle constraint that already
   forced ``RouteChainError`` to live in ``claims.py`` rather than
   ``routing.py``. A neutral third module (this one) is safe in both
   directions.

``claims.py``'s ``_migrate_add_seq`` is left exactly as it is — it carries
the route-manifest chain-integrity guards and the terminal-receipt
uniqueness index, and converging the two call sites onto this helper is an
explicit, separate follow-up, not part of this unit.

Every caller supplies its own idempotence guard scope (the *specs* dict —
only tables present in it are ever touched) and its own rebuild specs; this
module owns only the mechanical, generic part: the ``BEGIN IMMEDIATE``, the
lock-retry backoff, and the create/copy/drop/rename sequence.
"""

from __future__ import annotations

import sqlite3
import time

_LOCK_RETRY_ATTEMPTS = 5
_LOCK_RETRY_BASE_DELAY = 0.05  # seconds, doubles each attempt


def _is_locked_error(exc: sqlite3.OperationalError) -> bool:
    return "locked" in str(exc).lower()


def rebuild_tables_for_seq_migration(
    conn: sqlite3.Connection,
    specs: dict,
    *,
    lock_retry_attempts: int = _LOCK_RETRY_ATTEMPTS,
    lock_retry_base_delay: float = _LOCK_RETRY_BASE_DELAY,
) -> None:
    """Idempotent transactional rebuild adding a store-assigned ``seq`` PK.

    *specs* maps table name -> ``{"columns": [...], "create": "<CREATE TABLE
    {name} (...)>", "indexes": [...], "order_by": "<ORDER BY clause body>"}``.
    Only tables that EXIST and are missing a ``seq`` column are rebuilt — a
    table not yet created, or one whose schema already includes ``seq``
    (e.g. a freshly created store), is left untouched. Re-opening an
    already-migrated or freshly created store is therefore a no-op.

    All DDL for every table needing a rebuild runs inside ONE
    ``BEGIN IMMEDIATE`` transaction — SQLite DDL is transactional, so a
    half-upgraded schema is impossible; it commits or rolls back as a unit.
    """
    needs_rebuild = []
    for table in specs:
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        if cols and "seq" not in cols:
            needs_rebuild.append(table)
    if not needs_rebuild:
        return

    delay = lock_retry_base_delay
    for attempt in range(lock_retry_attempts):
        try:
            conn.execute("BEGIN IMMEDIATE")
            break
        except sqlite3.OperationalError as exc:
            if _is_locked_error(exc) and attempt < lock_retry_attempts - 1:
                time.sleep(delay)
                delay *= 2
                continue
            raise
    else:  # pragma: no cover - unreachable, loop always breaks or raises
        raise sqlite3.OperationalError(
            "rebuild_tables_for_seq_migration: could not acquire write lock"
        )

    try:
        for table in needs_rebuild:
            spec = specs[table]
            new_name = f"{table}_new"
            conn.execute(spec["create"].format(name=new_name))
            col_list = ", ".join(spec["columns"])
            order_by = spec["order_by"]
            conn.execute(
                f"INSERT INTO {new_name} ({col_list}) "
                f"SELECT {col_list} FROM {table} ORDER BY {order_by}"
            )
            conn.execute(f"DROP TABLE {table}")
            conn.execute(f"ALTER TABLE {new_name} RENAME TO {table}")
            for idx_sql in spec["indexes"]:
                conn.execute(idx_sql)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
