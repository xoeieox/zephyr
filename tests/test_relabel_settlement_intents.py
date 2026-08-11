"""Tests for zephyr/relabel_settlement_intents.py (Leg 2 of
decision/zephyr-stops-minting-payment-claims-2026-08-11).

Every test operates on an explicit tmp_path DB — never production. The
autouse fixture in tests/conftest.py additionally forbids any
SettlementIntentQueue in this suite from resolving to the production path.

Coverage map (spec DoD + Leg 2 acceptance):
  DoD6/7 -- dry-run is the default (no flags -> no write); --execute writes
  DoD11  -- every relabelled row carries a non-null, non-empty reason naming
            the defect and the decision key
  --     -- idempotent: a second --execute run relabels zero rows and exits 0
  --     -- only status='pending' rows are touched; other statuses untouched
  --     -- nothing is deleted (row count unchanged)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from zephyr.intent_queue import SettlementIntentQueue
from zephyr.relabel_settlement_intents import RELABEL_REASON, main, relabel

REPO_ROOT = Path(__file__).resolve().parents[1]


def _seed(queue: SettlementIntentQueue, manifest_hash: str, status: str | None = None):
    prov = {
        "manifest_hash": manifest_hash,
        "pubkey_id": "ed25519:0000000000000000",
        "agent_id": "agent:relabel-test",
        "timestamp": "2026-06-10T12:00:00+00:00",
    }
    queue.append(manifest_hash, prov)
    if status and status != "pending":
        # Route through the real state machine for realistic non-pending rows.
        queue.claim(manifest_hash)
        if status == "settled":
            queue.settle(manifest_hash, op_payment_id="op-1")
        elif status == "no-route":
            queue.mark_no_route(manifest_hash)
        elif status == "failed":
            queue.mark_failed(manifest_hash)
        elif status == "in_flight":
            pass  # already there after claim()


# ---------------------------------------------------------------------------
# Dry-run default / --execute opt-in
# ---------------------------------------------------------------------------


def test_dry_run_is_the_default_no_write(tmp_path):
    db = tmp_path / "intent_queue.db"
    queue = SettlementIntentQueue(db)
    _seed(queue, "sha256:dryrun-1")
    _seed(queue, "sha256:dryrun-2")

    result = relabel(db, execute=False)

    assert result["affected"] == 2
    assert result["executed"] is False
    # Nothing written: re-open and confirm both rows are still pending.
    reopened = SettlementIntentQueue(db)
    assert reopened.count(status="pending") == 2
    assert reopened.count(status="simulation") == 0


def test_execute_flag_performs_the_relabel(tmp_path):
    db = tmp_path / "intent_queue.db"
    queue = SettlementIntentQueue(db)
    _seed(queue, "sha256:exec-1")
    _seed(queue, "sha256:exec-2")

    result = relabel(db, execute=True)

    assert result["affected"] == 2
    assert result["executed"] is True
    assert queue.count(status="pending") == 0
    assert queue.count(status="simulation") == 2


def test_cli_no_flags_performs_no_write(tmp_path, capsys):
    db = tmp_path / "intent_queue.db"
    queue = SettlementIntentQueue(db)
    _seed(queue, "sha256:cli-noflags")

    with pytest.raises(SystemExit) as exc_info:
        main(["--db", str(db)])
    assert exc_info.value.code == 0

    assert queue.count(status="pending") == 1
    assert queue.count(status="simulation") == 0


def test_cli_execute_flag_writes(tmp_path):
    db = tmp_path / "intent_queue.db"
    queue = SettlementIntentQueue(db)
    _seed(queue, "sha256:cli-execute")

    with pytest.raises(SystemExit) as exc_info:
        main(["--db", str(db), "--execute"])
    assert exc_info.value.code == 0

    assert queue.count(status="pending") == 0
    assert queue.count(status="simulation") == 1


def test_cli_dry_run_wins_over_execute_if_both_given(tmp_path):
    db = tmp_path / "intent_queue.db"
    queue = SettlementIntentQueue(db)
    _seed(queue, "sha256:cli-both-flags")

    with pytest.raises(SystemExit) as exc_info:
        main(["--db", str(db), "--execute", "--dry-run"])
    assert exc_info.value.code == 0

    assert queue.count(status="pending") == 1
    assert queue.count(status="simulation") == 0


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_second_execute_run_relabels_zero_rows(tmp_path):
    db = tmp_path / "intent_queue.db"
    queue = SettlementIntentQueue(db)
    _seed(queue, "sha256:idempotent-1")

    first = relabel(db, execute=True)
    assert first["affected"] == 1
    assert first["executed"] is True

    second = relabel(db, execute=True)
    assert second["affected"] == 0
    assert second["executed"] is False


# ---------------------------------------------------------------------------
# Only 'pending' is touched
# ---------------------------------------------------------------------------


def test_only_pending_rows_are_touched(tmp_path):
    db = tmp_path / "intent_queue.db"
    queue = SettlementIntentQueue(db)
    _seed(queue, "sha256:touch-pending")
    _seed(queue, "sha256:touch-settled", status="settled")
    _seed(queue, "sha256:touch-no-route", status="no-route")
    _seed(queue, "sha256:touch-failed", status="failed")
    _seed(queue, "sha256:touch-in-flight", status="in_flight")

    total_before = queue.count()
    result = relabel(db, execute=True)
    assert result["affected"] == 1

    assert queue.get("sha256:touch-pending")["status"] == "simulation"
    assert queue.get("sha256:touch-settled")["status"] == "settled"
    assert queue.get("sha256:touch-no-route")["status"] == "no-route"
    assert queue.get("sha256:touch-failed")["status"] == "failed"
    assert queue.get("sha256:touch-in-flight")["status"] == "in_flight"

    # Nothing deleted.
    assert queue.count() == total_before


# ---------------------------------------------------------------------------
# DoD11 -- reason is non-null, non-empty, and names the defect + decision key
# ---------------------------------------------------------------------------


def test_relabelled_rows_carry_a_reason_naming_defect_and_decision_key(tmp_path):
    db = tmp_path / "intent_queue.db"
    queue = SettlementIntentQueue(db)
    _seed(queue, "sha256:reason-1")
    _seed(queue, "sha256:reason-2")

    relabel(db, execute=True)

    for mh in ("sha256:reason-1", "sha256:reason-2"):
        row = queue.get(mh)
        assert row["reason"], f"{mh} has a null/empty reason"
        assert "defect-residue" in row["reason"]
        assert "decision/zephyr-stops-minting-payment-claims-2026-08-11" in row["reason"]

    # Never phrased as if simulation were an intended mode.
    assert "never an intended mode" in RELABEL_REASON


def test_non_relabelled_rows_keep_a_null_reason(tmp_path):
    db = tmp_path / "intent_queue.db"
    queue = SettlementIntentQueue(db)
    _seed(queue, "sha256:reason-settled", status="settled")

    relabel(db, execute=True)

    row = queue.get("sha256:reason-settled")
    assert row["reason"] is None


# ---------------------------------------------------------------------------
# Subprocess smoke test -- the real python -m entry point
# ---------------------------------------------------------------------------


def test_subprocess_entry_point_dry_run_then_execute(tmp_path):
    db = tmp_path / "intent_queue.db"
    queue = SettlementIntentQueue(db)
    _seed(queue, "sha256:subprocess-1")

    dry = subprocess.run(
        [sys.executable, "-m", "zephyr.relabel_settlement_intents", "--db", str(db)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert dry.returncode == 0, dry.stderr
    assert "Would relabel 1 row" in dry.stdout
    assert queue.count(status="pending") == 1

    execute = subprocess.run(
        [
            sys.executable, "-m", "zephyr.relabel_settlement_intents",
            "--db", str(db), "--execute",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert execute.returncode == 0, execute.stderr
    assert "Relabelled 1 row" in execute.stdout
    assert queue.count(status="pending") == 0
    assert queue.count(status="simulation") == 1
