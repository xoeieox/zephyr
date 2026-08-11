"""Shared pytest fixtures for the zephyr test suite.

Autouse settlement-intent-queue isolation guard (decision/zephyr-stops-
minting-payment-claims-2026-08-11 — "Test isolation" section, blocking).

zephyr/intent_queue.py's default queue DB is /data/zephyr/intent_queue.db —
the production log. 7,141 of the 8,120 rows measured in production before
this fix carried test-shaped agent_ids: tests that forgot to override
ZEPHYR_INTENT_QUEUE_DB fell straight through to that default and wrote real
rows there. "Every test author remembers to override the env var" is the
convention that produced that pollution, so this makes isolation ENFORCED
rather than remembered — an autouse fixture, general to the whole suite, not
opt-in per test file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import zephyr.intent_queue as intent_queue

_PRODUCTION_INTENT_QUEUE_DB = Path("/data/zephyr/intent_queue.db").resolve()


@pytest.fixture(autouse=True)
def _isolate_settlement_intent_queue_db(tmp_path, monkeypatch):
    """Force every test's settlement-intent queue onto a scratch DB.

    Two layers, because a monkeypatched env var alone is not sufficient —
    see _default_queue_db()'s docstring in zephyr/intent_queue.py for why a
    frozen module-level default would silently miss a post-import env
    change:

    1. Points ZEPHYR_INTENT_QUEUE_DB at a fresh tmp_path for this test and
       drops the process-wide singleton, so the next get_queue() call
       re-resolves against the tmp path instead of reusing a queue opened
       by an earlier test.
    2. Wraps SettlementIntentQueue.__init__ so that ANY queue a test
       constructs — via get_queue(), a bare SettlementIntentQueue(), or one
       given an explicit path — fails the test outright if it ever resolves
       to the real production DB, however that happened. This is the part
       that makes the guard bite even when a test overrides the env var
       back to production mid-test, or passes the production path directly.
    """
    tmp_db = tmp_path / "intent_queue.db"
    monkeypatch.setenv("ZEPHYR_INTENT_QUEUE_DB", str(tmp_db))
    monkeypatch.setattr(intent_queue, "_QUEUE", None)

    real_init = intent_queue.SettlementIntentQueue.__init__

    def _guarded_init(self, db_path=None):
        # Resolve and check BEFORE opening any connection, so a caught
        # attempt never even reaches the production file — not for a write,
        # not for the idempotent CREATE TABLE / ALTER TABLE either.
        resolved = (
            Path(db_path).resolve()
            if db_path is not None
            else intent_queue._default_queue_db().resolve()
        )
        if resolved == _PRODUCTION_INTENT_QUEUE_DB:
            pytest.fail(
                f"Test resolved the PRODUCTION settlement intent queue "
                f"({_PRODUCTION_INTENT_QUEUE_DB}). Tests must never write "
                f"there — override ZEPHYR_INTENT_QUEUE_DB or pass an "
                f"explicit scratch db_path instead."
            )
        real_init(self, db_path)

    monkeypatch.setattr(intent_queue.SettlementIntentQueue, "__init__", _guarded_init)

    yield
