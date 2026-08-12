"""Tests for zephyr/settlement_intent_readout.py (Leg 3 of
decision/zephyr-stops-minting-payment-claims-2026-08-11).

Coverage map:
  DoD9 -- run live, prints the placeholder disclaimer, the no-claim
          statement, and the never-an-intended-mode statement with the
          decision key
  --   -- prints count, distinct agent_id with counts, date range, summed
          amount for the simulation rows
  --   -- read-only: no writes, no status transitions
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from zephyr.intent_queue import SettlementIntentQueue
from zephyr.relabel_settlement_intents import RELABEL_REASON
from zephyr.settlement_intent_readout import DECISION_KEY, gather, main, render

REPO_ROOT = Path(__file__).resolve().parents[1]


def _seed_and_relabel(queue: SettlementIntentQueue, manifest_hash: str, agent_id: str):
    prov = {
        "manifest_hash": manifest_hash,
        "pubkey_id": "ed25519:0000000000000000",
        "agent_id": agent_id,
        "timestamp": "2026-06-10T12:00:00+00:00",
    }
    queue.append(manifest_hash, prov)


# ---------------------------------------------------------------------------
# gather() / render() — content correctness
# ---------------------------------------------------------------------------


def test_gather_reports_count_agents_daterange_and_amount(tmp_path):
    db = tmp_path / "intent_queue.db"
    queue = SettlementIntentQueue(db)
    _seed_and_relabel(queue, "sha256:readout-1", "agent:readout-a")
    _seed_and_relabel(queue, "sha256:readout-2", "agent:readout-a")
    _seed_and_relabel(queue, "sha256:readout-3", "agent:readout-b")
    queue.relabel_pending_to_simulation(RELABEL_REASON, execute=True)

    data = gather(db)

    assert data["count"] == 3
    assert dict(data["by_agent"]) == {"agent:readout-a": 2, "agent:readout-b": 1}
    assert data["date_range"][0] is not None
    assert data["date_range"][1] is not None
    assert data["total_amount_cents"] == 3  # 1 cent placeholder * 3 rows


def test_gather_zero_rows_when_nothing_relabelled(tmp_path):
    db = tmp_path / "intent_queue.db"
    SettlementIntentQueue(db)  # empty DB

    data = gather(db)

    assert data["count"] == 0
    assert data["by_agent"] == []
    assert data["total_amount_cents"] == 0


# ---------------------------------------------------------------------------
# DoD9 -- mandatory disclaimers printed verbatim
# ---------------------------------------------------------------------------


def test_render_prints_placeholder_and_no_claim_and_never_intended_mode(tmp_path):
    db = tmp_path / "intent_queue.db"
    queue = SettlementIntentQueue(db)
    _seed_and_relabel(queue, "sha256:disclaimer-1", "agent:disclaimer-test")
    queue.relabel_pending_to_simulation(RELABEL_REASON, execute=True)

    output = render(gather(db))

    assert "HARDCODED ONE-CENT PLACEHOLDER, NOT A VALUATION" in output
    assert "NO CLAIM EXISTS AND NOTHING WILL SETTLE" in output
    assert "never an intended mode" in output
    assert DECISION_KEY in output
    assert DECISION_KEY == "decision/zephyr-stops-minting-payment-claims-2026-08-11"


def test_render_prints_disclaimers_even_with_zero_rows(tmp_path):
    """A dry run that reads like a ledger is the same defect with a different
    label — the disclaimer must print unconditionally, even for an empty queue."""
    db = tmp_path / "intent_queue.db"
    SettlementIntentQueue(db)

    output = render(gather(db))

    assert "HARDCODED ONE-CENT PLACEHOLDER, NOT A VALUATION" in output
    assert "NO CLAIM EXISTS AND NOTHING WILL SETTLE" in output
    assert DECISION_KEY in output


# ---------------------------------------------------------------------------
# Read-only: no writes, no status transitions
# ---------------------------------------------------------------------------


def test_readout_is_read_only(tmp_path):
    db = tmp_path / "intent_queue.db"
    queue = SettlementIntentQueue(db)
    _seed_and_relabel(queue, "sha256:readonly-1", "agent:readonly-test")
    queue.relabel_pending_to_simulation(RELABEL_REASON, execute=True)

    before = queue.get("sha256:readonly-1")

    gather(db)
    gather(db)  # run it twice for good measure

    after = queue.get("sha256:readonly-1")
    assert after == before
    assert after["status"] == "simulation"


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------


def test_cli_exits_zero_and_prints_disclaimers(tmp_path):
    db = tmp_path / "intent_queue.db"
    queue = SettlementIntentQueue(db)
    _seed_and_relabel(queue, "sha256:cli-readout-1", "agent:cli-readout-test")
    queue.relabel_pending_to_simulation(RELABEL_REASON, execute=True)

    with pytest.raises(SystemExit) as exc_info:
        main(["--db", str(db)])
    assert exc_info.value.code == 0


def test_subprocess_entry_point(tmp_path):
    db = tmp_path / "intent_queue.db"
    queue = SettlementIntentQueue(db)
    _seed_and_relabel(queue, "sha256:subprocess-readout-1", "agent:subprocess-readout-test")
    queue.relabel_pending_to_simulation(RELABEL_REASON, execute=True)

    result = subprocess.run(
        [sys.executable, "-m", "zephyr.settlement_intent_readout", "--db", str(db)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "HARDCODED ONE-CENT PLACEHOLDER, NOT A VALUATION" in result.stdout
    assert "NO CLAIM EXISTS AND NOTHING WILL SETTLE" in result.stdout
    assert DECISION_KEY in result.stdout
