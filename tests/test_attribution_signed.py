"""Acceptance criteria tests for zephyr signed-attribution (Unit 1).

All identities are SYNTHETIC.  No real human identities (Erah is tested
only as the target of a rejection, never as a passing depositor).
No writes to /data/zephyr/*.  All tests use tmp_path fixtures.

Coverage map:
  AC1  -- reference path: record_signed stores verified row
  AC2  -- forgery rejected at write (tampered sig / tampered manifest)
  AC3  -- Tier-0 incident regression: Erah + human:test rejected in both modes
  AC4  -- key/agent mismatch rejected
  AC5  -- auto-registration refuses human namespace
  AC6  -- observe vs enforce on unsigned
  AC7  -- backward read compat: NULL sig reads as unsigned
  AC8  -- idempotency preserved
  AC9  -- no live calls (all tmp db + tmp keys; verified by fixture design)
"""

from __future__ import annotations

import os
import pytest

from zephyr.attribution import (
    AttributionLog,
    VerificationResult,
    record_signed,
    verify_row,
)
from zephyr.registry import PubkeyRegistry, _reset_registry
from zephyr.signing import AgentSigner, _reset_signer


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


# ---------------------------------------------------------------------------
# AC1 — reference path: record_signed stores verified row
# ---------------------------------------------------------------------------


def test_ac1_record_signed_stores_verified_row(tmp_path, tmp_log, tmp_signer, tmp_registry):
    result = record_signed(
        {"hello": "world"},
        agent_id="agent:zephyr-selftest",
        tool="unit-test",
        store_kind="mem",
        key="pm/ac1",
        signer=tmp_signer,
        registry=tmp_registry,
        recorder=tmp_log,
        summary="AC1 test deposit",
    )

    assert result["manifest_hash"].startswith("sha256:")
    assert result["pubkey_id"] == tmp_signer.pubkey_id_str
    assert len(result["signature"]) == 128
    assert result["newly_recorded"] is True

    # get() returns verified=True
    row = tmp_log.get(result["manifest_hash"], registry=tmp_registry)
    assert row is not None
    assert row["verified"] is True
    assert row["verification_status"] == "verified"
    assert row["signature"] == result["signature"]
    assert row["pubkey_id"] == result["pubkey_id"]

    # recent() also returns verified=True
    recent = tmp_log.recent(limit=1, registry=tmp_registry)
    assert recent[0]["verified"] is True
    assert recent[0]["verification_status"] == "verified"


# ---------------------------------------------------------------------------
# AC2 — forgery rejected at write
# ---------------------------------------------------------------------------


def test_ac2_tampered_signature_rejected(tmp_path, tmp_log, tmp_signer, tmp_registry):
    """A deposit with a signature that doesn't verify is rejected."""
    # First register the key
    tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:zephyr-selftest",
        "agent",
    )

    prov = {
        "manifest_hash": "sha256:ac2test",
        "agent_id": "agent:zephyr-selftest",
        "tool": "test",
        "signature": "ff" * 64,  # invalid signature
        "pubkey_id": tmp_signer.pubkey_id_str,
        "schema_version": "lapis-provenance-v0.1",
    }
    with pytest.raises(ValueError, match="[Ss]ignature verification failed"):
        tmp_log.record(prov, registry=tmp_registry)
    # Row must NOT be stored
    assert tmp_log.already_recorded("sha256:ac2test") is False


def test_ac2_tampered_manifest_rejected(tmp_path, tmp_log, tmp_signer, tmp_registry):
    """A deposit where the manifest_hash was changed after signing is rejected."""
    # Register key
    tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:zephyr-selftest",
        "agent",
    )

    real_mh = "sha256:real"
    sig = tmp_signer.sign(real_mh)

    prov = {
        "manifest_hash": "sha256:tampered",  # not what was signed
        "agent_id": "agent:zephyr-selftest",
        "tool": "test",
        "signature": sig,
        "pubkey_id": tmp_signer.pubkey_id_str,
        "schema_version": "lapis-provenance-v0.1",
    }
    with pytest.raises(ValueError, match="[Ss]ignature verification failed"):
        tmp_log.record(prov, registry=tmp_registry)
    assert tmp_log.already_recorded("sha256:tampered") is False


# ---------------------------------------------------------------------------
# AC3 — Tier-0 incident regression
# ---------------------------------------------------------------------------


def _human_rejected(log, agent_id, mode_env):
    """Helper: assert that a human-namespace deposit without a valid sig is rejected."""
    prov = {
        "manifest_hash": f"sha256:human-attempt-{agent_id.replace(':', '-')}",
        "agent_id": agent_id,
        "tool": "test",
        "schema_version": "lapis-provenance-v0",
    }
    old = os.environ.get("ZEPHYR_SIGNING_MODE")
    try:
        os.environ["ZEPHYR_SIGNING_MODE"] = mode_env
        with pytest.raises(PermissionError, match="Tier-0 guard"):
            log.record(prov)
    finally:
        if old is None:
            os.environ.pop("ZEPHYR_SIGNING_MODE", None)
        else:
            os.environ["ZEPHYR_SIGNING_MODE"] = old


def test_ac3_Erah_rejected_observe(tmp_log):
    _human_rejected(tmp_log, "Erah", "observe")


def test_ac3_Erah_rejected_enforce(tmp_log):
    _human_rejected(tmp_log, "Erah", "enforce")


def test_ac3_human_test_rejected_observe(tmp_log):
    _human_rejected(tmp_log, "human:test", "observe")


def test_ac3_human_test_rejected_enforce(tmp_log):
    _human_rejected(tmp_log, "human:test", "enforce")


# ---------------------------------------------------------------------------
# AC4 — key/agent mismatch rejected
# ---------------------------------------------------------------------------


def test_ac4_key_agent_mismatch_rejected(tmp_path, tmp_log, tmp_signer, tmp_registry):
    """A signature from a key registered to agent:A but claiming agent:B is rejected."""
    # Register the key under agent:A
    tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:A",
        "agent",
    )

    mh = "sha256:mismatch-test"
    sig = tmp_signer.sign(mh)

    prov = {
        "manifest_hash": mh,
        "agent_id": "agent:B",  # not A!
        "tool": "test",
        "signature": sig,
        "pubkey_id": tmp_signer.pubkey_id_str,
        "schema_version": "lapis-provenance-v0.1",
    }
    with pytest.raises(ValueError, match="[Kk]ey.*mismatch|agent_id.*registered|mismatch"):
        tmp_log.record(prov, registry=tmp_registry)
    assert tmp_log.already_recorded(mh) is False


# ---------------------------------------------------------------------------
# AC5 — auto-registration refuses human namespace
# ---------------------------------------------------------------------------


def test_ac5_record_signed_refuses_human_namespace_agent_id(
    tmp_log, tmp_signer, tmp_registry
):
    with pytest.raises(ValueError, match="human namespace"):
        record_signed(
            {},
            agent_id="Erah",
            tool="test",
            signer=tmp_signer,
            registry=tmp_registry,
            recorder=tmp_log,
        )


def test_ac5_record_signed_refuses_human_prefix(tmp_log, tmp_signer, tmp_registry):
    with pytest.raises(ValueError, match="human namespace"):
        record_signed(
            {},
            agent_id="human:test",
            tool="test",
            signer=tmp_signer,
            registry=tmp_registry,
            recorder=tmp_log,
        )


def test_ac5_registry_refuses_agent_context_human_namespace(tmp_registry, tmp_signer):
    with pytest.raises(ValueError, match="human-namespace"):
        tmp_registry.register(
            tmp_signer.pubkey_id_str,
            tmp_signer.public_key_bytes.hex(),
            "Erah",
            role="agent",
        )
    with pytest.raises(ValueError, match="human-namespace"):
        tmp_registry.register(
            tmp_signer.pubkey_id_str,
            tmp_signer.public_key_bytes.hex(),
            "human:ada",
            role="agent",
        )


# ---------------------------------------------------------------------------
# AC6 — observe vs enforce on unsigned
# ---------------------------------------------------------------------------


def test_ac6_observe_accepts_unsigned(tmp_path):
    log = AttributionLog(tmp_path / "attr.db")
    prov = {
        "manifest_hash": "sha256:unsigned-observe",
        "agent_id": "agent:legacy-producer",
        "tool": "weaver",
        "schema_version": "lapis-provenance-v0",
    }
    old = os.environ.get("ZEPHYR_SIGNING_MODE")
    try:
        os.environ["ZEPHYR_SIGNING_MODE"] = "observe"
        result = log.record(prov, store_kind="weaver")
    finally:
        if old is None:
            os.environ.pop("ZEPHYR_SIGNING_MODE", None)
        else:
            os.environ["ZEPHYR_SIGNING_MODE"] = old

    assert result is True
    row = log.get("sha256:unsigned-observe")
    assert row is not None
    assert row["signature"] is None
    assert row["pubkey_id"] is None
    assert row["verified"] is False
    assert row["verification_status"] == "unsigned"


def test_ac6_enforce_rejects_unsigned(tmp_path):
    log = AttributionLog(tmp_path / "attr.db")
    prov = {
        "manifest_hash": "sha256:unsigned-enforce",
        "agent_id": "agent:legacy-producer",
        "tool": "weaver",
        "schema_version": "lapis-provenance-v0",
    }
    old = os.environ.get("ZEPHYR_SIGNING_MODE")
    try:
        os.environ["ZEPHYR_SIGNING_MODE"] = "enforce"
        with pytest.raises(ValueError, match="unsigned deposit rejected"):
            log.record(prov, store_kind="weaver")
    finally:
        if old is None:
            os.environ.pop("ZEPHYR_SIGNING_MODE", None)
        else:
            os.environ["ZEPHYR_SIGNING_MODE"] = old

    assert log.already_recorded("sha256:unsigned-enforce") is False


# ---------------------------------------------------------------------------
# AC7 — backward read compat: NULL sig reads as unsigned/verified=False
# ---------------------------------------------------------------------------


def test_ac7_backward_compat_null_sig(tmp_path):
    """Rows with NULL signature and pubkey_id read as unsigned/verified=False."""
    log = AttributionLog(tmp_path / "attr.db")

    # Insert a v0-style row directly (bypassing enforcement by using observe mode)
    prov = {
        "manifest_hash": "sha256:v0-legacy",
        "agent_id": "agent:weaver-server",
        "tool": "weaver-deposit",
        "schema_version": "lapis-provenance-v0",
        "timestamp": "2026-05-01T00:00:00+00:00",
    }
    old = os.environ.get("ZEPHYR_SIGNING_MODE")
    try:
        os.environ["ZEPHYR_SIGNING_MODE"] = "observe"
        log.record(prov, store_kind="weaver")
    finally:
        if old is None:
            os.environ.pop("ZEPHYR_SIGNING_MODE", None)
        else:
            os.environ["ZEPHYR_SIGNING_MODE"] = old

    row = log.get("sha256:v0-legacy")
    assert row is not None
    assert row["verified"] is False
    assert row["verification_status"] == "unsigned"
    assert row["agent_id"] == "agent:weaver-server"

    recent = log.recent(limit=5)
    assert any(r["verification_status"] == "unsigned" for r in recent)


def test_ac7_verify_row_null_sig():
    """verify_row on a dict with no signature returns unsigned."""
    row = {
        "manifest_hash": "sha256:abc",
        "agent_id": "agent:x",
        "signature": None,
        "pubkey_id": None,
    }
    vr = verify_row(row)
    assert vr.status == "unsigned"
    assert vr.verified is False


# ---------------------------------------------------------------------------
# AC8 — idempotency
# ---------------------------------------------------------------------------


def test_ac8_idempotency_signed(tmp_path, tmp_signer, tmp_registry):
    log = AttributionLog(tmp_path / "attr.db")

    fixed_ts = "2026-06-07T00:00:00+00:00"
    kwargs = dict(
        agent_id="agent:zephyr-selftest",
        tool="test",
        store_kind="mem",
        signer=tmp_signer,
        registry=tmp_registry,
        recorder=log,
        summary="idempotency test",
        timestamp=fixed_ts,
    )

    r1 = record_signed({"x": 1}, **kwargs)
    assert r1["newly_recorded"] is True

    # Identical call (same payload + same timestamp) → same manifest_hash → no-op
    r2 = record_signed({"x": 1}, **kwargs)
    assert r2["newly_recorded"] is False
    assert r2["manifest_hash"] == r1["manifest_hash"]
    assert log.count() == 1


# ---------------------------------------------------------------------------
# AC9 — verify-on-read: unknown_key status
# ---------------------------------------------------------------------------


def test_verify_row_unknown_key(tmp_path):
    """If the pubkey_id is not in the registry, verify_row returns unknown_key."""
    from zephyr.registry import PubkeyRegistry

    reg = PubkeyRegistry(tmp_path / "keys-isolated")  # empty registry

    row = {
        "manifest_hash": "sha256:unknown",
        "agent_id": "agent:x",
        "signature": "aa" * 64,
        "pubkey_id": "ed25519:0000000000000000",
    }

    vr = verify_row(row, registry=reg)
    assert vr.status == "unknown_key"
    assert vr.verified is False


# ---------------------------------------------------------------------------
# verify_row re-checks at read time
# ---------------------------------------------------------------------------


def test_verify_row_invalid_sig_at_read_time(tmp_path, tmp_signer, tmp_registry):
    """verify_row returns invalid when the stored sig is corrupted."""
    row = {
        "manifest_hash": "sha256:read-invalid",
        "agent_id": "agent:zephyr-selftest",
        "signature": "cc" * 64,  # bad sig
        "pubkey_id": tmp_signer.pubkey_id_str,
    }
    # Register the key so the lookup succeeds
    tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:zephyr-selftest",
        "agent",
    )

    vr = verify_row(row, registry=tmp_registry)

    assert vr.status == "invalid"
    assert vr.verified is False


# ---------------------------------------------------------------------------
# Existing test compat: unsigned deposits still work in observe mode
# ---------------------------------------------------------------------------


def test_existing_attribution_tests_compat(tmp_path):
    """record() with no signature accepted in observe mode (three live producers)."""
    log = AttributionLog(tmp_path / "attr.db")

    prov = {
        "manifest_hash": "sha256:compat-1",
        "agent_id": "agent:compat",
        "tool": "unit-test",
        "timestamp": "2026-05-29T20:00:00+00:00",
        "schema_version": "lapis-provenance-v0",
    }
    old = os.environ.get("ZEPHYR_SIGNING_MODE")
    try:
        os.environ["ZEPHYR_SIGNING_MODE"] = "observe"
        assert log.record(prov) is True
        assert log.record(prov) is False  # duplicate
    finally:
        if old is None:
            os.environ.pop("ZEPHYR_SIGNING_MODE", None)
        else:
            os.environ["ZEPHYR_SIGNING_MODE"] = old

    assert log.count() == 1
