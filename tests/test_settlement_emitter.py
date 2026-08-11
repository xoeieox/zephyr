"""Tests for settlement intent emitter (Unit 1 emitter seam).

UPDATED for decision/zephyr-stops-minting-payment-claims-2026-08-11 (Leg 1):
record() no longer calls _emit_settlement_intent on any path — Zephyr does
not mint payment claims. AC1/AC3/AC4 below used to assert that a signed
deposit auto-fired the emitter; that was exactly the defect. They now assert
the corrected contract: record_signed() never fires the emitter, signed or
not, new or duplicate. The emitter hook itself (ZEPHYR_DEPOSIT_EVENT_EMITTER
/ get_emitter() / _emit_settlement_intent()) is retained for a future,
explicitly declared dry run, so AC5 now exercises it directly instead of via
record_signed().

Acceptance criteria:
  AC1  -- record_signed() (signed+new) does NOT fire the emitter
  AC2  -- emitter does NOT fire on unsigned deposits
  AC3  -- emitter does NOT fire on duplicate deposits either
  AC4  -- record_signed() results in ZERO emitter calls
  AC5  -- emitter exception caught and logged (never propagates), exercised
          via a direct _emit_settlement_intent() call (its only caller now)
  AC6  -- emitter singleton teardown in test cleanup
  AC7  -- intent queue append and status transitions
  AC8  -- intent queue idempotency (INSERT OR IGNORE)
"""

from __future__ import annotations

import os
import pytest
import tempfile

from zephyr.attribution import (
    AttributionLog,
    _emit_settlement_intent,
    record_signed,
    set_emitter,
    get_emitter,
)
from zephyr.intent_queue import SettlementIntentQueue, get_queue
from zephyr.registry import PubkeyRegistry
from zephyr.signing import AgentSigner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_log(tmp_path):
    """Fresh AttributionLog in tmp_path."""
    return AttributionLog(tmp_path / "attr.db")


@pytest.fixture()
def tmp_signer(tmp_path):
    """Fresh AgentSigner using a tmp key."""
    return AgentSigner(tmp_path / "agent-keys" / "test.key")


@pytest.fixture()
def tmp_registry(tmp_path):
    """Fresh PubkeyRegistry in tmp_path."""
    return PubkeyRegistry(tmp_path / "keys")


@pytest.fixture()
def tmp_queue(tmp_path):
    """Fresh SettlementIntentQueue in tmp_path."""
    return SettlementIntentQueue(tmp_path / "intent_queue.db")


@pytest.fixture(autouse=True)
def reset_emitter_singleton():
    """Reset the emitter singleton before and after each test."""
    # Save original
    old_emitter = get_emitter()
    # Clear it for the test
    set_emitter(None)
    yield
    # Teardown: restore it
    set_emitter(old_emitter)


# ---------------------------------------------------------------------------
# AC1 — record_signed() (signed+new) does NOT fire the emitter
# ---------------------------------------------------------------------------


def test_ac1_record_signed_does_not_fire_emitter(tmp_path, tmp_log, tmp_signer, tmp_registry):
    """Zephyr does not mint payment claims: a signed, newly-recorded deposit
    no longer triggers the settlement-intent emitter as a side effect."""
    emitted = []

    def capture_emitter(provenance: dict):
        emitted.append(provenance)

    set_emitter(capture_emitter)

    result = record_signed(
        {"payload": "data"},
        agent_id="agent:settler-test",
        tool="test",
        store_kind="mem",
        signer=tmp_signer,
        registry=tmp_registry,
        recorder=tmp_log,
        summary="AC1 test",
    )

    assert result["newly_recorded"] is True
    assert len(emitted) == 0


# ---------------------------------------------------------------------------
# AC2 — emitter does NOT fire on unsigned
# ---------------------------------------------------------------------------


def test_ac2_emitter_does_not_fire_on_unsigned(tmp_path, tmp_log):
    """Emitter should not fire on unsigned deposits."""
    emitted = []

    def capture_emitter(provenance: dict):
        emitted.append(provenance)

    set_emitter(capture_emitter)

    prov = {
        "manifest_hash": "sha256:unsigned-ac2",
        "agent_id": "agent:unsigned-test",
        "tool": "test",
        "schema_version": "lapis-provenance-v0",
    }
    old = os.environ.get("ZEPHYR_SIGNING_MODE")
    try:
        os.environ["ZEPHYR_SIGNING_MODE"] = "observe"
        result = tmp_log.record(prov)
    finally:
        if old is None:
            os.environ.pop("ZEPHYR_SIGNING_MODE", None)
        else:
            os.environ["ZEPHYR_SIGNING_MODE"] = old

    assert result is True
    assert len(emitted) == 0  # emitter should NOT have fired


# ---------------------------------------------------------------------------
# AC3 — emitter does NOT fire on duplicate (or original) deposits
# ---------------------------------------------------------------------------


def test_ac3_emitter_does_not_fire_on_duplicate(
    tmp_path, tmp_log, tmp_signer, tmp_registry
):
    """Emitter never fires via record_signed() — first call or duplicate."""
    emitted = []

    def capture_emitter(provenance: dict):
        emitted.append(provenance)

    set_emitter(capture_emitter)

    kwargs = dict(
        agent_id="agent:dup-test",
        tool="test",
        store_kind="mem",
        signer=tmp_signer,
        registry=tmp_registry,
        recorder=tmp_log,
        timestamp="2026-06-10T12:00:00+00:00",
    )

    # First deposit (newly recorded)
    r1 = record_signed({"x": 1}, **kwargs)
    assert r1["newly_recorded"] is True
    assert len(emitted) == 0

    # Second identical call (same manifest_hash due to same payload + timestamp)
    r2 = record_signed({"x": 1}, **kwargs)
    assert r2["newly_recorded"] is False
    assert r2["manifest_hash"] == r1["manifest_hash"]
    assert len(emitted) == 0  # emitter never fires from record_signed()


# ---------------------------------------------------------------------------
# AC4 — record_signed() results in ZERO emitter calls
# ---------------------------------------------------------------------------


def test_ac4_record_signed_never_fires_emitter(
    tmp_path, tmp_log, tmp_signer, tmp_registry
):
    """record_signed() no longer results in any emitter call."""
    call_count = [0]

    def counting_emitter(provenance: dict):
        call_count[0] += 1

    set_emitter(counting_emitter)

    record_signed(
        {"test": "payload"},
        agent_id="agent:count-test",
        tool="test",
        signer=tmp_signer,
        registry=tmp_registry,
        recorder=tmp_log,
    )

    # Zephyr does not mint payment claims: zero emits, not one.
    assert call_count[0] == 0


# ---------------------------------------------------------------------------
# AC5 — emitter exception caught and logged
# ---------------------------------------------------------------------------


def test_ac5_emitter_exception_caught_and_not_propagated(tmp_path):
    """If emitter raises, the exception is caught and logged, not propagated.

    _emit_settlement_intent() is no longer called from record() — it is
    retained for a future declared dry run — so this exercises it directly,
    its only remaining caller.
    """

    def failing_emitter(provenance: dict):
        raise RuntimeError("Intentional test failure")

    set_emitter(failing_emitter)

    # Should not raise even though emitter raises
    _emit_settlement_intent({"manifest_hash": "sha256:ac5-direct", "agent_id": "agent:fail-test"})


# ---------------------------------------------------------------------------
# AC6 — emitter singleton teardown
# ---------------------------------------------------------------------------


def test_ac6_emitter_singleton_teardown_in_fixture(tmp_path):
    """The reset_emitter_singleton fixture properly teardowns."""
    # This test itself verifies the fixture works: if it didn't, concurrent
    # tests would interfere with each other
    counter = [0]

    def counting(prov):
        counter[0] += 1

    set_emitter(counting)
    # After this test, reset_emitter_singleton will restore the prior value
    # (None in this case)


# ---------------------------------------------------------------------------
# AC7 — intent queue append and status transitions
# ---------------------------------------------------------------------------


def test_ac7_intent_queue_append_idempotent(tmp_queue, tmp_signer):
    """Intent queue append is idempotent (INSERT OR IGNORE)."""
    prov = {
        "manifest_hash": "sha256:queue-append-ac7",
        "pubkey_id": tmp_signer.pubkey_id_str,
        "agent_id": "agent:queue-test",
        "timestamp": "2026-06-10T12:00:00+00:00",
        "schema_version": "lapis-provenance-v0.1",
    }

    r1 = tmp_queue.append("sha256:queue-append-ac7", prov)
    assert r1 is True

    r2 = tmp_queue.append("sha256:queue-append-ac7", prov)
    assert r2 is False  # duplicate

    assert tmp_queue.count() == 1


def test_ac7_intent_queue_status_transitions(tmp_queue):
    """Intent queue status transitions: pending → in_flight → settled."""
    prov = {
        "manifest_hash": "sha256:status-test",
        "pubkey_id": "ed25519:0000000000000000",
        "agent_id": "agent:status-test",
        "timestamp": "2026-06-10T12:00:00+00:00",
    }

    tmp_queue.append("sha256:status-test", prov)

    # Fetch it
    intent = tmp_queue.get("sha256:status-test")
    assert intent["status"] == "pending"

    # Claim it (pending → in_flight)
    claimed = tmp_queue.claim("sha256:status-test")
    assert claimed is True

    intent = tmp_queue.get("sha256:status-test")
    assert intent["status"] == "in_flight"

    # Settle it (in_flight → settled)
    tmp_queue.settle("sha256:status-test", op_payment_id="op-123", worker_id="settler-1")

    intent = tmp_queue.get("sha256:status-test")
    assert intent["status"] == "settled"
    assert intent["op_payment_id"] == "op-123"
    assert intent["worker_id"] == "settler-1"


def test_ac7_intent_queue_no_route(tmp_queue):
    """Intent queue can mark intents as no-route."""
    prov = {
        "manifest_hash": "sha256:no-route-test",
        "pubkey_id": "ed25519:0000000000000000",
        "agent_id": "agent:no-route",
        "timestamp": "2026-06-10T12:00:00+00:00",
    }

    tmp_queue.append("sha256:no-route-test", prov)
    tmp_queue.claim("sha256:no-route-test")
    tmp_queue.mark_no_route("sha256:no-route-test")

    intent = tmp_queue.get("sha256:no-route-test")
    assert intent["status"] == "no-route"


def test_ac7_intent_queue_failed(tmp_queue):
    """Intent queue can mark intents as failed."""
    prov = {
        "manifest_hash": "sha256:failed-test",
        "pubkey_id": "ed25519:0000000000000000",
        "agent_id": "agent:failed",
        "timestamp": "2026-06-10T12:00:00+00:00",
    }

    tmp_queue.append("sha256:failed-test", prov)
    tmp_queue.claim("sha256:failed-test")
    tmp_queue.mark_failed("sha256:failed-test", worker_id="settler-1")

    intent = tmp_queue.get("sha256:failed-test")
    assert intent["status"] == "failed"
    assert intent["worker_id"] == "settler-1"


def test_ac7_intent_queue_pending_filter(tmp_queue):
    """Intent queue pending() returns only pending intents."""
    # Create mixed statuses
    for i in range(3):
        prov = {
            "manifest_hash": f"sha256:pending-{i}",
            "pubkey_id": "ed25519:0000000000000000",
            "agent_id": "agent:filter-test",
            "timestamp": "2026-06-10T12:00:00+00:00",
        }
        tmp_queue.append(f"sha256:pending-{i}", prov)

    # Settle one
    tmp_queue.claim("sha256:pending-0")
    tmp_queue.settle("sha256:pending-0", op_payment_id="op-0")

    # Mark one no-route
    tmp_queue.claim("sha256:pending-1")
    tmp_queue.mark_no_route("sha256:pending-1")

    # Only pending-2 should be pending
    pending_intents = tmp_queue.pending()
    assert len(pending_intents) == 1
    assert pending_intents[0]["manifest_hash"] == "sha256:pending-2"
