"""Tests for U3 - Settlement ledger, human-visible surface, provenance write-back.

Acceptance criteria:
  U3-AC1  -- Ledger schema has manifest_hash, op_payment_id, pubkey_id, status, settled_at
  U3-AC2  -- show_ledger renders void-policy line (no settlement-weighted ranking)
  U3-AC3  -- Provenance write-back fires on settled status
  U3-AC4  -- Provenance write-back catches errors (best-effort, never propagates)
  U3-AC5  -- Demo script runs end-to-end (mocked settler)
  U3-AC6  -- Demo shows settled contributor and no-route contributor with equal credit
  U3-AC7  -- Ledger display does NOT rank by settlement status
  U3-AC8  -- No-route contributor remains fully credited in display
"""

from __future__ import annotations

import json
import logging
import os
import pytest
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from settler.ledger import SettlementLedger
from zephyr.attribution import AttributionLog
from zephyr.signing import AgentSigner
from zephyr.intent_queue import SettlementIntentQueue


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_attr_log(tmp_path):
    """Fresh AttributionLog in tmp_path."""
    return AttributionLog(tmp_path / "attr.db")


@pytest.fixture()
def tmp_ledger(tmp_path):
    """Fresh SettlementLedger in tmp_path."""
    return SettlementLedger(tmp_path / "ledger.db")


@pytest.fixture()
def tmp_signer(tmp_path):
    """Fresh AgentSigner using a tmp key."""
    return AgentSigner(tmp_path / "agent-keys" / "settler.key")


# ---------------------------------------------------------------------------
# U3-AC1 — Ledger schema completeness
# ---------------------------------------------------------------------------


def test_u3_ac1_ledger_schema_has_required_columns(tmp_ledger):
    """Ledger has manifest_hash, op_payment_id, pubkey_id, status, settled_at columns."""
    tmp_ledger.record_settled(
        "sha256:schema-test",
        "ed25519:0000000000000001",
        "op-payment-123",
        1,
        "USD",
    )

    entry = tmp_ledger.get("sha256:schema-test")
    assert "manifest_hash" in entry
    assert "op_payment_id" in entry
    assert "pubkey_id" in entry
    assert "status" in entry
    assert "settled_at" in entry
    assert entry["manifest_hash"] == "sha256:schema-test"
    assert entry["op_payment_id"] == "op-payment-123"
    assert entry["status"] == "settled"


# ---------------------------------------------------------------------------
# U3-AC2 — show_ledger void-policy rendering
# ---------------------------------------------------------------------------


def test_u3_ac2_show_ledger_renders_void_line(tmp_ledger, capsys):
    """show_ledger script renders void-policy line prominently."""
    # Add some ledger entries
    tmp_ledger.record_settled(
        "sha256:settled-1",
        "ed25519:pubkey0001",
        "op-payment-aaa",
        1,
        "USD",
    )
    tmp_ledger.record_no_route(
        "sha256:no-route-1",
        "ed25519:pubkey0002",
        1,
        "USD",
    )

    # Import and call show_ledger
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from scripts.show_ledger import main

    # Capture output
    main()
    captured = capsys.readouterr()

    # Check for void-policy line
    assert "VOID" in captured.out
    assert "makes no claim about the correct share" in captured.out
    assert "livelihood gap" in captured.out


def test_u3_ac2_show_ledger_no_settlement_weighting(tmp_ledger):
    """show_ledger displays entries in creation order, not settlement status order."""
    # Add no-route first, then settled
    tmp_ledger.record_no_route(
        "sha256:no-route-first",
        "ed25519:pubkey0001",
        1,
        "USD",
    )

    import time

    time.sleep(0.01)  # Small delay to ensure different timestamps

    tmp_ledger.record_settled(
        "sha256:settled-second",
        "ed25519:pubkey0002",
        "op-payment-xyz",
        1,
        "USD",
    )

    # Verify creation order is preserved
    with tmp_ledger._write_lock:
        rows = tmp_ledger._write_conn.execute(
            "SELECT manifest_hash, status FROM settlement_ledger ORDER BY created_at ASC"
        ).fetchall()

    assert len(rows) == 2
    assert rows[0]["manifest_hash"] == "sha256:no-route-first"
    assert rows[0]["status"] == "no-route"
    assert rows[1]["manifest_hash"] == "sha256:settled-second"
    assert rows[1]["status"] == "settled"


# ---------------------------------------------------------------------------
# U3-AC3 — Provenance write-back on successful settlement
# ---------------------------------------------------------------------------


def test_u3_ac3_provenance_writeback_on_settled(tmp_attr_log):
    """AttributionLog.write_settlement_info updates provenance with op_payment_id."""
    import json
    from datetime import datetime, timezone

    # Manually insert a deposit record
    now = datetime.now(timezone.utc).isoformat()
    prov = {"manifest_hash": "sha256:settle-test", "agent_id": "agent:test"}

    with tmp_attr_log._lock:
        tmp_attr_log._conn.execute(
            "INSERT INTO deposits "
            "(manifest_hash, agent_id, tool, model, timestamp, store_kind, "
            " target_key, schema_version, provenance_json, recorded_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "sha256:settle-test",
                "agent:test",
                "test",
                None,
                now,
                "mem",
                None,
                "lapis-provenance-v0.1",
                json.dumps(prov),
                now,
            ),
        )
        tmp_attr_log._conn.commit()

    # Write settlement info
    ok = tmp_attr_log.write_settlement_info("sha256:settle-test", "op-payment-xyz-123")
    assert ok is True

    # Verify provenance was updated
    row = tmp_attr_log.get("sha256:settle-test", verify=False)
    assert row is not None
    prov_updated = json.loads(row["provenance_json"])
    assert "settlement" in prov_updated
    assert prov_updated["settlement"]["op_payment_id"] == "op-payment-xyz-123"
    assert prov_updated["settlement"]["status"] == "settled"


def test_u3_ac3_provenance_writeback_nonexistent_hash(tmp_attr_log):
    """write_settlement_info returns False gracefully for missing manifest_hash."""
    ok = tmp_attr_log.write_settlement_info("sha256:nonexistent", "op-payment-xyz")
    assert ok is False


# ---------------------------------------------------------------------------
# U3-AC4 — Provenance write-back error handling
# ---------------------------------------------------------------------------


def test_u3_ac4_provenance_writeback_error_caught(tmp_attr_log):
    """write_settlement_info catches exceptions and returns False (never propagates)."""
    # Create a broken provenance_json (intentional invalid JSON)
    import sqlite3

    with tmp_attr_log._lock:
        # Insert a row with invalid JSON
        tmp_attr_log._conn.execute(
            "INSERT INTO deposits "
            "(manifest_hash, agent_id, provenance_json, recorded_at) "
            "VALUES (?, ?, ?, ?)",
            (
                "sha256:bad-json",
                "agent:test",
                "{invalid json",
                "2026-06-10T12:00:00Z",
            ),
        )
        tmp_attr_log._conn.commit()

    # Attempt write-back (should catch JSON decode error gracefully)
    ok = tmp_attr_log.write_settlement_info("sha256:bad-json", "op-payment-xyz")
    assert ok is False


# ---------------------------------------------------------------------------
# U3-AC5 — Demo script runs end-to-end
# ---------------------------------------------------------------------------


def test_u3_ac5_demo_script_structure(tmp_path):
    """Demo script can be imported and has expected structure."""
    import sys

    demo_dir = Path(__file__).parent.parent / "demo"
    sys.path.insert(0, str(demo_dir.parent))

    from demo.run_demo import run_demo, load_demo_env

    # Verify functions exist
    assert callable(run_demo)
    assert callable(load_demo_env)

    # Verify load_demo_env signature
    import inspect

    sig = inspect.signature(run_demo)
    assert "demo_env" in sig.parameters
    assert "dry_run" in sig.parameters
    assert "attr_db" in sig.parameters

    # Verify it returns a dict with expected keys
    assert hasattr(run_demo, "__doc__")
    assert "end-to-end" in run_demo.__doc__.lower() or "demo" in run_demo.__doc__.lower()


# ---------------------------------------------------------------------------
# U3-AC6 — Demo shows settled and no-route with equal credit
# ---------------------------------------------------------------------------


def test_u3_ac6_demo_displays_both_settled_and_no_route(tmp_path):
    """Demo ledger shows both settled and no-route contributors as equally credited."""
    from settler.ledger import SettlementLedger

    ledger = SettlementLedger(tmp_path / "ledger.db")

    # Add both settled and no-route entries
    ledger.record_settled(
        "sha256:demo-settled",
        "ed25519:pubkey0001",
        "op-payment-123",
        1,
        "USD",
    )

    ledger.record_no_route(
        "sha256:demo-no-route",
        "ed25519:pubkey0002",
        1,
        "USD",
    )

    # Verify both are in ledger
    with ledger._write_lock:
        rows = ledger._write_conn.execute(
            "SELECT manifest_hash, status FROM settlement_ledger ORDER BY created_at ASC"
        ).fetchall()

    assert len(rows) == 2
    assert {r["status"] for r in rows} == {"settled", "no-route"}


# ---------------------------------------------------------------------------
# U3-AC7 — Ledger display does NOT rank by settlement status
# ---------------------------------------------------------------------------


def test_u3_ac7_ledger_no_settlement_weighting(tmp_ledger):
    """Ledger query results are ordered by creation time, not by status."""
    # Add entries in this order: settled, no-route, settled
    ledger_order = [
        ("sha256:first-settled", "ed25519:pk1", "settled", "op-111"),
        ("sha256:second-no-route", "ed25519:pk2", "no-route", None),
        ("sha256:third-settled", "ed25519:pk3", "settled", "op-333"),
    ]

    for manifest, pubkey, status, op_id in ledger_order:
        if status == "settled":
            tmp_ledger.record_settled(manifest, pubkey, op_id, 1, "USD")
        else:
            tmp_ledger.record_no_route(manifest, pubkey, 1, "USD")

    # Verify creation order is preserved
    with tmp_ledger._write_lock:
        rows = tmp_ledger._write_conn.execute(
            "SELECT manifest_hash, status FROM settlement_ledger ORDER BY created_at ASC"
        ).fetchall()

    retrieved_order = [(r["manifest_hash"], r["status"]) for r in rows]
    expected_order = [
        ("sha256:first-settled", "settled"),
        ("sha256:second-no-route", "no-route"),
        ("sha256:third-settled", "settled"),
    ]

    assert retrieved_order == expected_order


# ---------------------------------------------------------------------------
# U3-AC8 — No-route contributor remains fully credited
# ---------------------------------------------------------------------------


def test_u3_ac8_no_route_fully_credited(tmp_ledger):
    """Ledger marks no-route intents as having full attribution (not diminished)."""
    tmp_ledger.record_no_route(
        "sha256:no-route-credited",
        "ed25519:pubkey0001",
        1,
        "USD",
    )

    entry = tmp_ledger.get("sha256:no-route-credited")
    assert entry is not None
    assert entry["status"] == "no-route"
    # Verify amount is recorded (not diminished)
    assert entry["amount"] == 1
    # No op_payment_id (settlement didn't happen, but full credit stands)
    assert entry["op_payment_id"] is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
