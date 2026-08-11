"""DoD #12 -- the autouse test-isolation fixture (tests/conftest.py) exists
and bites.

This deliberately tries to resolve the PRODUCTION settlement intent queue
path from within a test, to prove the guard actually fires rather than
sitting unused. The attempt is expected to fail — caught here via
pytest.raises so that expected, deliberate failure does not itself fail the
suite (the outer test passes because the guard did its job).
"""

from __future__ import annotations

from pathlib import Path

import pytest

import zephyr.intent_queue as intent_queue

_PRODUCTION_INTENT_QUEUE_DB = Path("/data/zephyr/intent_queue.db").resolve()


def test_fixture_forces_scratch_db_by_default():
    """Sanity check: without any deliberate attempt to escape it, get_queue()
    resolves to a tmp path, never production."""
    queue = intent_queue.get_queue()
    assert Path(queue.db_path).resolve() != _PRODUCTION_INTENT_QUEUE_DB


def test_deliberate_production_path_via_env_var_fails(monkeypatch):
    """A test that overrides ZEPHYR_INTENT_QUEUE_DB back to the production
    path mid-test, then constructs a queue, must be caught by the guard."""
    monkeypatch.setenv("ZEPHYR_INTENT_QUEUE_DB", str(_PRODUCTION_INTENT_QUEUE_DB))
    # Drop the singleton so the next get_queue() call re-resolves against
    # the (now production-pointing) env var instead of reusing the tmp
    # queue the autouse fixture already created for this test.
    monkeypatch.setattr(intent_queue, "_QUEUE", None)

    with pytest.raises(pytest.fail.Exception):
        intent_queue.get_queue()


def test_deliberate_production_path_via_explicit_arg_fails():
    """A test that passes the production path directly to the constructor,
    bypassing the env var entirely, must also be caught."""
    with pytest.raises(pytest.fail.Exception):
        intent_queue.SettlementIntentQueue(_PRODUCTION_INTENT_QUEUE_DB)
