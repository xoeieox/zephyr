"""Acceptance tests for decision/zephyr-stops-minting-payment-claims-2026-08-11.

Zephyr does not mint payment claims (R1). record() no longer calls
_emit_settlement_intent on any path (Leg 1). These tests never touch
/data/zephyr/intent_queue.db — the autouse fixture in tests/conftest.py
points ZEPHYR_INTENT_QUEUE_DB at a scratch tmp_path for every test in this
package and fails outright if anything resolves to production anyway.

Coverage map (spec "Definition of done"):
  DoD2  -- a signed deposit through record() adds ZERO rows to the intent queue
  DoD3  -- the deposit itself is unaffected: same manifest_hash, signature,
           verification_status still computes to verified on read
  DoD8  -- both settler-facing readers (pending(), claim()) return
           empty/False against a relabelled DB — proves the fix is
           structural, not cosmetic
  DoD10 -- ZEPHYR_DEPOSIT_EVENT_EMITTER still loads and fires a configured
           emitter (the retained general hook, exercised directly since
           record() no longer calls it)
"""

from __future__ import annotations

import sys
import types

import pytest

from zephyr.attribution import (
    AttributionLog,
    _emit_settlement_intent,
    get_emitter,
    record_signed,
    set_emitter,
)
from zephyr.intent_queue import SettlementIntentQueue, get_queue
from zephyr.registry import PubkeyRegistry
from zephyr.signing import AgentSigner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_log(tmp_path):
    return AttributionLog(tmp_path / "attr.db")


@pytest.fixture()
def tmp_signer(tmp_path):
    return AgentSigner(tmp_path / "agent-keys" / "test.key")


@pytest.fixture()
def tmp_registry(tmp_path):
    return PubkeyRegistry(tmp_path / "keys")


@pytest.fixture(autouse=True)
def reset_emitter_singleton():
    """Reset the zephyr.attribution emitter singleton before and after each test."""
    old_emitter = get_emitter()
    set_emitter(None)
    yield
    set_emitter(old_emitter)


# ---------------------------------------------------------------------------
# DoD2 -- signed deposit through record() adds zero rows to the intent queue
# ---------------------------------------------------------------------------


def test_dod2_signed_deposit_adds_zero_rows_to_intent_queue(
    tmp_log, tmp_signer, tmp_registry
):
    result = record_signed(
        {"payload": "dod2"},
        agent_id="agent:dod2-test",
        tool="test",
        signer=tmp_signer,
        registry=tmp_registry,
        recorder=tmp_log,
        summary="DoD2 test",
    )
    assert result["newly_recorded"] is True

    # get_queue() resolves against the scratch ZEPHYR_INTENT_QUEUE_DB the
    # conftest.py autouse fixture points at for this test — never production.
    queue = get_queue()
    assert queue.count() == 0
    assert queue.get(result["manifest_hash"]) is None


def test_dod2_unsigned_deposit_also_adds_zero_rows(tmp_path, tmp_log):
    """Belt-and-braces: unsigned deposits never emitted even before this fix;
    confirm removing the call site didn't somehow change that."""
    import os

    prov = {
        "manifest_hash": "sha256:dod2-unsigned",
        "agent_id": "agent:dod2-unsigned-test",
        "tool": "test",
        "schema_version": "lapis-provenance-v0",
    }
    old = os.environ.get("ZEPHYR_SIGNING_MODE")
    try:
        os.environ["ZEPHYR_SIGNING_MODE"] = "observe"
        assert tmp_log.record(prov) is True
    finally:
        if old is None:
            os.environ.pop("ZEPHYR_SIGNING_MODE", None)
        else:
            os.environ["ZEPHYR_SIGNING_MODE"] = old

    assert get_queue().count() == 0


# ---------------------------------------------------------------------------
# DoD3 -- the deposit itself is unaffected
# ---------------------------------------------------------------------------


def test_dod3_deposit_unaffected_same_hash_signature_verified(
    tmp_log, tmp_signer, tmp_registry
):
    result = record_signed(
        {"payload": "dod3"},
        agent_id="agent:dod3-test",
        tool="test",
        signer=tmp_signer,
        registry=tmp_registry,
        recorder=tmp_log,
        summary="DoD3 test",
    )

    row = tmp_log.get(result["manifest_hash"], registry=tmp_registry)
    assert row is not None
    assert row["manifest_hash"] == result["manifest_hash"]
    assert row["signature"] == result["signature"]
    assert row["pubkey_id"] == result["pubkey_id"]
    assert row["verified"] is True
    assert row["verification_status"] == "verified"


# ---------------------------------------------------------------------------
# DoD8 -- both settler-facing readers return empty against a relabelled DB
# ---------------------------------------------------------------------------


def test_dod8_pending_and_claim_empty_against_relabelled_db(tmp_path):
    """Scratch copy of the production shape: append pending rows the old
    default emit path would have created, relabel them, then prove the two
    settler-facing readers (pending()/claim()) see nothing."""
    queue = SettlementIntentQueue(tmp_path / "prod_shape_intent_queue.db")

    manifest_hash = "sha256:dod8-relabelled"
    prov = {
        "manifest_hash": manifest_hash,
        "pubkey_id": "ed25519:0000000000000000",
        "agent_id": "agent:dod8-test",
        "timestamp": "2026-06-10T12:00:00+00:00",
    }
    assert queue.append(manifest_hash, prov) is True
    assert queue.get(manifest_hash)["status"] == "pending"

    affected = queue.relabel_pending_to_simulation(
        "defect-residue: dod8 test row", execute=True
    )
    assert affected == 1
    assert queue.get(manifest_hash)["status"] == "simulation"

    # pending() must not list it
    assert queue.pending() == []

    # claim() must not be able to transition it
    assert queue.claim(manifest_hash) is False
    assert queue.get(manifest_hash)["status"] == "simulation"


# ---------------------------------------------------------------------------
# DoD10 -- ZEPHYR_DEPOSIT_EVENT_EMITTER still loads and fires
# ---------------------------------------------------------------------------


def test_dod10_env_var_emitter_loads_and_fires(monkeypatch):
    """The pluggable ZEPHYR_DEPOSIT_EVENT_EMITTER hook is retained (Leg 1) —
    it is a general deposit-event hook, not the defect. get_emitter() must
    still parse '<module>:<callable>' and load a stub emitter, and calling
    _emit_settlement_intent (the retained module, no longer wired into
    record()) must still fire it."""
    calls = []

    def stub_emit(provenance):
        calls.append(provenance)

    stub_module_name = "tests._dod10_stub_emitter_module"
    stub_module = types.ModuleType(stub_module_name)
    stub_module.stub_emit = stub_emit
    monkeypatch.setitem(sys.modules, stub_module_name, stub_module)
    monkeypatch.setenv(
        "ZEPHYR_DEPOSIT_EVENT_EMITTER", f"{stub_module_name}:stub_emit"
    )

    loaded = get_emitter()
    assert loaded is stub_emit

    _emit_settlement_intent({"manifest_hash": "sha256:dod10", "agent_id": "agent:dod10"})

    assert len(calls) == 1
    assert calls[0]["manifest_hash"] == "sha256:dod10"
