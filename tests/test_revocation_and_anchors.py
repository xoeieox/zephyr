"""Tests for revocation, rotation, and human-key anchor-chain verification.

All identities are synthetic. Tests for the agent-key-management spec §1-5.
"""

from __future__ import annotations

import os
import pytest

from zephyr.attribution import (
    AttributionLog,
    verify_row,
)
from zephyr.registry import (
    PubkeyRegistry,
    ZEPHYR_HUMAN_ROOT_ANCHOR,
    verify_human_anchor_chain,
)
from zephyr.signing import AgentSigner, sign_manifest


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
def anchor_signer(tmp_path):
    """Fresh AgentSigner for the human root anchor."""
    return AgentSigner(tmp_path / "agent-keys" / "anchor.key")


# ---------------------------------------------------------------------------
# AC0a — register() accepts role="node"
# ---------------------------------------------------------------------------


def test_register_node_role_accepted(tmp_registry, tmp_signer):
    """role='node' is accepted with required node_binding."""
    node_binding = {
        "node": "brix",
        "hostname": "brix.local",
        "tailscale_ip": "203.0.113.1",
    }
    entry = tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:gardener",  # non-human agent_id
        role="node",
        note="gardener executor",
        node_binding=node_binding,
    )
    assert entry["role"] == "node"
    assert entry["node_binding"] == node_binding


def test_register_node_role_requires_node_binding(tmp_registry, tmp_signer):
    """role='node' without node_binding raises ValueError."""
    with pytest.raises(ValueError, match="node_binding"):
        tmp_registry.register(
            tmp_signer.pubkey_id_str,
            tmp_signer.public_key_bytes.hex(),
            "agent:gardener",
            role="node",
        )


def test_register_node_refuses_human_namespace(tmp_registry, tmp_signer):
    """role='node' + human-namespace agent_id is rejected."""
    with pytest.raises(ValueError, match="human-namespace"):
        tmp_registry.register(
            tmp_signer.pubkey_id_str,
            tmp_signer.public_key_bytes.hex(),
            "Erah",
            role="node",
            node_binding={"node": "test", "hostname": "test", "tailscale_ip": "1.2.3.4"},
        )


# ---------------------------------------------------------------------------
# AC1 — Schema additive & backward compatible
# ---------------------------------------------------------------------------


def test_schema_backward_compat_v0_entry(tmp_registry, tmp_signer):
    """A pre-v0.2 entry (no new fields) loads with defaults."""
    # Manually write a v0 entry (no new fields)
    import json
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    v0_entry = {
        "pubkey_id": tmp_signer.pubkey_id_str,
        "public_key_hex": tmp_signer.public_key_bytes.hex(),
        "agent_id": "agent:test-legacy",
        "role": "agent",
        "added_at": now,
        "note": "legacy entry",
    }
    path = tmp_registry._path(tmp_signer.pubkey_id_str)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(v0_entry))

    # Load and check defaults
    loaded = tmp_registry.lookup(tmp_signer.pubkey_id_str)
    assert loaded is not None
    assert loaded["status"] == "active"
    assert loaded["valid_from"] == now
    assert loaded["revoked_at"] is None
    assert loaded["revoked_reason"] is None
    assert loaded["compromise_suspected_at"] is None
    assert loaded["assurance_tier"] == "warm"  # default for role="agent"


def test_assurance_tier_defaults_by_role(tmp_registry, tmp_signer):
    """Assurance tier defaults are role-specific."""
    # Agent
    agent_entry = tmp_registry.register(
        tmp_signer.pubkey_id_str + "_agent",
        tmp_signer.public_key_bytes.hex(),
        "agent:test",
        role="agent",
    )
    assert agent_entry["assurance_tier"] == "warm"

    # Human (without anchor for now)
    human_entry = tmp_registry.register(
        tmp_signer.pubkey_id_str + "_human",
        tmp_signer.public_key_bytes.hex(),
        "human:test",
        role="human",
    )
    assert human_entry["assurance_tier"] == "hardware"

    # Node
    node_entry = tmp_registry.register(
        tmp_signer.pubkey_id_str + "_node",
        tmp_signer.public_key_bytes.hex(),
        "agent:test-node",
        role="node",
        node_binding={"node": "test", "hostname": "test", "tailscale_ip": "1.2.3.4"},
    )
    assert node_entry["assurance_tier"] == "node"


# ---------------------------------------------------------------------------
# AC2 — Revoke is monotonic
# ---------------------------------------------------------------------------


def test_revoke_sets_status_and_fields(tmp_registry, tmp_signer):
    """revoke() sets status, revoked_at, revoked_reason."""
    entry = tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:test",
        role="agent",
    )
    assert entry["status"] == "active"

    revoked = tmp_registry.revoke(
        tmp_signer.pubkey_id_str,
        reason="rotated",
        note="rotated to new key",
    )
    assert revoked["status"] == "revoked"
    assert revoked["revoked_reason"] == "rotated"
    assert revoked["revoked_at"] is not None


def test_revoke_idempotent(tmp_registry, tmp_signer):
    """Second revoke of an already-revoked key is idempotent."""
    tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:test",
        role="agent",
    )
    r1 = tmp_registry.revoke(tmp_signer.pubkey_id_str, reason="rotated")
    revoked_at_1 = r1["revoked_at"]

    # Wait a tiny bit, then revoke again
    r2 = tmp_registry.revoke(tmp_signer.pubkey_id_str, reason="retired")
    # Should be unchanged
    assert r2["revoked_at"] == revoked_at_1
    assert r2["revoked_reason"] == "rotated"  # original reason preserved


def test_revoke_compromised_with_suspected_at(tmp_registry, tmp_signer):
    """revoke with reason=compromised and suspected_at."""
    tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:test",
        role="agent",
    )
    revoked = tmp_registry.revoke(
        tmp_signer.pubkey_id_str,
        reason="compromised",
        suspected_at="2026-06-01T12:00:00+00:00",
    )
    assert revoked["revoked_reason"] == "compromised"
    assert revoked["compromise_suspected_at"] == "2026-06-01T12:00:00+00:00"


def test_revoke_compromised_fallback_to_revoked_at(tmp_registry, tmp_signer, caplog):
    """revoke with reason=compromised but no suspected_at defaults and warns."""
    tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:test",
        role="agent",
    )
    revoked = tmp_registry.revoke(
        tmp_signer.pubkey_id_str,
        reason="compromised",
    )
    assert revoked["compromise_suspected_at"] == revoked["revoked_at"]
    assert "window unknown" in caplog.text.lower()


def test_revoke_invalid_reason(tmp_registry, tmp_signer):
    """revoke with invalid reason raises ValueError."""
    tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:test",
        role="agent",
    )
    with pytest.raises(ValueError, match="rotated|retired|compromised"):
        tmp_registry.revoke(
            tmp_signer.pubkey_id_str,
            reason="invalidreason",
        )


# ---------------------------------------------------------------------------
# AC3 & AC4 — Verify before/after compromise (read-path)
# ---------------------------------------------------------------------------


def test_verify_row_revoked_rotated_is_verified(tmp_registry, tmp_signer):
    """A deposit via a key revoked with reason=rotated still verifies."""
    tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:test",
        role="agent",
    )
    tmp_registry.revoke(tmp_signer.pubkey_id_str, reason="rotated")

    mh = "sha256:rotation-test"
    sig = tmp_signer.sign(mh)
    row = {
        "manifest_hash": mh,
        "agent_id": "agent:test",
        "signature": sig,
        "pubkey_id": tmp_signer.pubkey_id_str,
        "timestamp": "2026-06-01T00:00:00+00:00",
    }
    vr = verify_row(row, registry=tmp_registry)
    assert vr.status == "verified"
    assert vr.verified is True
    assert "retirement" in vr.detail.lower() or "retired" in vr.detail.lower()


def test_verify_row_revoked_retired_is_verified(tmp_registry, tmp_signer):
    """A deposit via a key revoked with reason=retired still verifies."""
    tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:test",
        role="agent",
    )
    tmp_registry.revoke(tmp_signer.pubkey_id_str, reason="retired")

    mh = "sha256:retirement-test"
    sig = tmp_signer.sign(mh)
    row = {
        "manifest_hash": mh,
        "agent_id": "agent:test",
        "signature": sig,
        "pubkey_id": tmp_signer.pubkey_id_str,
        "timestamp": "2026-06-01T00:00:00+00:00",
    }
    vr = verify_row(row, registry=tmp_registry)
    assert vr.verified is True


def test_verify_row_compromise_before_window(tmp_registry, tmp_signer):
    """Deposit before compromise_suspected_at is verified."""
    tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:test",
        role="agent",
    )
    tmp_registry.revoke(
        tmp_signer.pubkey_id_str,
        reason="compromised",
        suspected_at="2026-06-05T00:00:00+00:00",
    )

    mh = "sha256:before-compromise"
    sig = tmp_signer.sign(mh)
    row = {
        "manifest_hash": mh,
        "agent_id": "agent:test",
        "signature": sig,
        "pubkey_id": tmp_signer.pubkey_id_str,
        "timestamp": "2026-06-01T00:00:00+00:00",  # before suspect window
    }
    vr = verify_row(row, registry=tmp_registry)
    assert vr.verified is True
    assert vr.status == "verified"


def test_verify_row_compromise_after_window(tmp_registry, tmp_signer):
    """Deposit after compromise_suspected_at is suspect."""
    tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:test",
        role="agent",
    )
    tmp_registry.revoke(
        tmp_signer.pubkey_id_str,
        reason="compromised",
        suspected_at="2026-06-05T00:00:00+00:00",
    )

    mh = "sha256:after-compromise"
    sig = tmp_signer.sign(mh)
    row = {
        "manifest_hash": mh,
        "agent_id": "agent:test",
        "signature": sig,
        "pubkey_id": tmp_signer.pubkey_id_str,
        "timestamp": "2026-06-06T00:00:00+00:00",  # after suspect window
    }
    vr = verify_row(row, registry=tmp_registry)
    assert vr.verified is False
    assert vr.status == "suspect"


def test_verify_row_compromise_advisory_marker_for_node(tmp_registry, tmp_signer):
    """Compromise after-window detail marks node keys as advisory."""
    node_binding = {"node": "brix", "hostname": "brix", "tailscale_ip": "1.2.3.4"}
    tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:test",
        role="node",
        node_binding=node_binding,
    )
    tmp_registry.revoke(
        tmp_signer.pubkey_id_str,
        reason="compromised",
        suspected_at="2026-06-05T00:00:00+00:00",
    )

    mh = "sha256:advisory-test"
    sig = tmp_signer.sign(mh)
    row = {
        "manifest_hash": mh,
        "agent_id": "agent:test",
        "signature": sig,
        "pubkey_id": tmp_signer.pubkey_id_str,
        "timestamp": "2026-06-06T00:00:00+00:00",
    }
    vr = verify_row(row, registry=tmp_registry)
    assert vr.verified is False
    assert "advisory" in vr.detail.lower()


# ---------------------------------------------------------------------------
# AC5 — Assurance tier in VerificationResult
# ---------------------------------------------------------------------------


def test_verify_row_includes_assurance_tier(tmp_registry, tmp_signer):
    """verify_row returns assurance_tier when verified."""
    entry = tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:test",
        role="agent",
        assurance_tier="hardware",  # override default
    )

    mh = "sha256:tier-test"
    sig = tmp_signer.sign(mh)
    row = {
        "manifest_hash": mh,
        "agent_id": "agent:test",
        "signature": sig,
        "pubkey_id": tmp_signer.pubkey_id_str,
    }
    vr = verify_row(row, registry=tmp_registry)
    assert vr.assurance_tier == "hardware"


# ---------------------------------------------------------------------------
# AC6 — Node-vouches: node key can sign for any non-human agent_id
# ---------------------------------------------------------------------------


def test_node_vouches_different_agent_id(tmp_log, tmp_registry, tmp_signer):
    """A node key can sign a deposit for a different non-human agent_id."""
    node_binding = {"node": "brix", "hostname": "brix", "tailscale_ip": "1.2.3.4"}
    tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:brix",  # node is registered as agent:brix
        role="node",
        node_binding=node_binding,
    )

    # Sign as gardener (different agent_id)
    mh = "sha256:node-vouches-test"
    sig = tmp_signer.sign(mh)
    prov = {
        "manifest_hash": mh,
        "agent_id": "agent:gardener",  # different from registered agent:brix
        "tool": "test",
        "signature": sig,
        "pubkey_id": tmp_signer.pubkey_id_str,
        "schema_version": "lapis-provenance-v0.1",
    }

    # Should succeed (no exact-match check for node keys)
    assert tmp_log.record(prov, registry=tmp_registry) is True


def test_node_cannot_vouch_for_human_namespace(tmp_log, tmp_registry, tmp_signer):
    """A node key cannot sign for human-namespace agent_id (Tier-0 guard)."""
    node_binding = {"node": "brix", "hostname": "brix", "tailscale_ip": "1.2.3.4"}
    tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:brix",
        role="node",
        node_binding=node_binding,
    )

    mh = "sha256:human-guard-test"
    sig = tmp_signer.sign(mh)
    prov = {
        "manifest_hash": mh,
        "agent_id": "Erah",  # human namespace
        "tool": "test",
        "signature": sig,
        "pubkey_id": tmp_signer.pubkey_id_str,
        "schema_version": "lapis-provenance-v0.1",
    }

    # Should fail (Tier-0 guard fire before node-vouches check)
    with pytest.raises(PermissionError, match="Tier-0"):
        tmp_log.record(prov, registry=tmp_registry)


def test_agent_key_still_requires_exact_match(tmp_log, tmp_registry, tmp_signer):
    """An agent key requires exact agent_id match (unchanged from Unit 1)."""
    tmp_registry.register(
        tmp_signer.pubkey_id_str,
        tmp_signer.public_key_bytes.hex(),
        "agent:expert-A",  # registered as expert-A
        role="agent",
    )

    mh = "sha256:agent-exact-match"
    sig = tmp_signer.sign(mh)
    prov = {
        "manifest_hash": mh,
        "agent_id": "agent:expert-B",  # different!
        "tool": "test",
        "signature": sig,
        "pubkey_id": tmp_signer.pubkey_id_str,
        "schema_version": "lapis-provenance-v0.1",
    }

    # Should fail (agent keys require exact match)
    with pytest.raises(ValueError, match="[Mm]ismatch"):
        tmp_log.record(prov, registry=tmp_registry)


# ---------------------------------------------------------------------------
# AC7-9 — Human anchor-chain verification
# ---------------------------------------------------------------------------


def test_anchor_chain_unset_anchor_rejects_human(tmp_log, tmp_registry, tmp_signer):
    """With ZEPHYR_HUMAN_ROOT_ANCHOR unset, all human deposits are rejected."""
    import zephyr.registry
    old = os.environ.get("ZEPHYR_HUMAN_ROOT_ANCHOR")
    old_mod = zephyr.registry.ZEPHYR_HUMAN_ROOT_ANCHOR
    try:
        os.environ.pop("ZEPHYR_HUMAN_ROOT_ANCHOR", None)
        zephyr.registry.ZEPHYR_HUMAN_ROOT_ANCHOR = None

        # Register a human key (without anchor constraint)
        tmp_registry.register(
            tmp_signer.pubkey_id_str,
            tmp_signer.public_key_bytes.hex(),
            "human:test-synthetic",
            role="human",
        )

        mh = "sha256:unset-anchor-test"
        sig = tmp_signer.sign(mh)
        prov = {
            "manifest_hash": mh,
            "agent_id": "human:test-synthetic",
            "tool": "test",
            "signature": sig,
            "pubkey_id": tmp_signer.pubkey_id_str,
            "schema_version": "lapis-provenance-v0.1",
        }

        # Should fail: no anchor configured
        with pytest.raises(PermissionError, match="[Nn]o.*anchor.*configured"):
            tmp_log.record(prov, registry=tmp_registry)
    finally:
        if old is not None:
            os.environ["ZEPHYR_HUMAN_ROOT_ANCHOR"] = old


def test_anchor_chain_verify_happy_path(tmp_registry, anchor_signer, tmp_signer):
    """A human entry with valid registered_by signature from anchor is trusted."""
    # Set anchor
    import zephyr.registry
    anchor_pkid = anchor_signer.pubkey_id_str
    os.environ["ZEPHYR_HUMAN_ROOT_ANCHOR"] = anchor_pkid
    zephyr.registry.ZEPHYR_HUMAN_ROOT_ANCHOR = anchor_pkid

    try:
        # Register anchor as the root
        tmp_registry.register(
            anchor_pkid,
            anchor_signer.public_key_bytes.hex(),
            "human:root",
            role="human",
        )

        # Create a second human key and sign it with the anchor
        human_pkid = tmp_signer.pubkey_id_str
        human_pub_hex = tmp_signer.public_key_bytes.hex()
        human_agent_id = "human:alice-synthetic"
        human_valid_from = "2026-06-08T00:00:00+00:00"

        # Canonical signing target
        import json
        signing_target = json.dumps(
            [human_pkid, human_pub_hex, human_agent_id, human_valid_from],
            separators=(",", ":"),
        )
        anchor_signature = anchor_signer.sign(signing_target)

        # Register the human key with registered_by
        human_entry = tmp_registry.register(
            human_pkid,
            human_pub_hex,
            human_agent_id,
            role="human",
            valid_from=human_valid_from,
            registered_by={
                "signer_pkid": anchor_pkid,
                "signature": anchor_signature,
            },
        )

        # Verify anchor chain
        trusted, detail = verify_human_anchor_chain(human_entry, registry=tmp_registry)
        assert trusted is True
        assert "signature verified" in detail.lower()

    finally:
        os.environ.pop("ZEPHYR_HUMAN_ROOT_ANCHOR", None)


def test_anchor_chain_attack_invalid_signature(tmp_registry, anchor_signer, tmp_signer):
    """A human entry with an invalid registered_by signature is not trusted."""
    import zephyr.registry
    anchor_pkid = anchor_signer.pubkey_id_str
    os.environ["ZEPHYR_HUMAN_ROOT_ANCHOR"] = anchor_pkid
    zephyr.registry.ZEPHYR_HUMAN_ROOT_ANCHOR = anchor_pkid

    try:
        tmp_registry.register(
            anchor_pkid,
            anchor_signer.public_key_bytes.hex(),
            "human:root",
            role="human",
        )

        # Create entry with invalid signature
        human_entry = {
            "pubkey_id": tmp_signer.pubkey_id_str,
            "public_key_hex": tmp_signer.public_key_bytes.hex(),
            "agent_id": "human:eve-attacker",
            "role": "human",
            "added_at": "2026-06-08T00:00:00+00:00",
            "valid_from": "2026-06-08T00:00:00+00:00",
            "registered_by": {
                "signer_pkid": anchor_pkid,
                "signature": "ff" * 64,  # invalid
            },
        }

        trusted, detail = verify_human_anchor_chain(human_entry, registry=tmp_registry)
        assert trusted is False
        assert "signature" in detail.lower()

    finally:
        os.environ.pop("ZEPHYR_HUMAN_ROOT_ANCHOR", None)


def test_anchor_chain_attack_wrong_signer(tmp_path, tmp_registry, tmp_signer):
    """A human entry signed by a non-anchor key is not trusted."""
    import json
    import zephyr.registry

    anchor_pkid = "ed25519:aaaaaaaaaaaaaaaa"  # fake anchor
    os.environ["ZEPHYR_HUMAN_ROOT_ANCHOR"] = anchor_pkid
    zephyr.registry.ZEPHYR_HUMAN_ROOT_ANCHOR = anchor_pkid

    try:
        # Create a different signer
        wrong_signer = AgentSigner(tmp_path / "wrong.key")

        signing_target = json.dumps(
            [tmp_signer.pubkey_id_str, tmp_signer.public_key_bytes.hex(), "human:eve", ""],
            separators=(",", ":"),
        )
        wrong_signature = wrong_signer.sign(signing_target)

        human_entry = {
            "pubkey_id": tmp_signer.pubkey_id_str,
            "public_key_hex": tmp_signer.public_key_bytes.hex(),
            "agent_id": "human:eve",
            "role": "human",
            "added_at": "2026-06-08T00:00:00+00:00",
            "valid_from": "2026-06-08T00:00:00+00:00",
            "registered_by": {
                "signer_pkid": wrong_signer.pubkey_id_str,  # not the anchor!
                "signature": wrong_signature,
            },
        }

        trusted, detail = verify_human_anchor_chain(human_entry, registry=tmp_registry)
        assert trusted is False
        assert "not the pinned anchor" in detail

    finally:
        os.environ.pop("ZEPHYR_HUMAN_ROOT_ANCHOR", None)


# ---------------------------------------------------------------------------
# Write-path human rejection
# ---------------------------------------------------------------------------


def test_revoked_human_key_rejected_at_write(tmp_log, tmp_registry, anchor_signer, tmp_signer):
    """A human key revoked cannot be used for new deposits."""
    import zephyr.registry
    from datetime import datetime, timezone
    anchor_pkid = anchor_signer.pubkey_id_str
    os.environ["ZEPHYR_HUMAN_ROOT_ANCHOR"] = anchor_pkid
    zephyr.registry.ZEPHYR_HUMAN_ROOT_ANCHOR = anchor_pkid

    try:
        # Register anchor
        tmp_registry.register(
            anchor_pkid,
            anchor_signer.public_key_bytes.hex(),
            "human:root",
            role="human",
        )

        # Register and anchor-chain a human key, then revoke it
        import json
        human_pkid = tmp_signer.pubkey_id_str
        human_pub_hex = tmp_signer.public_key_bytes.hex()
        human_agent_id = "human:alice"
        valid_from = datetime.now(timezone.utc).isoformat()

        signing_target = json.dumps(
            [human_pkid, human_pub_hex, human_agent_id, valid_from],
            separators=(",", ":"),
        )
        sig = anchor_signer.sign(signing_target)

        tmp_registry.register(
            human_pkid,
            human_pub_hex,
            human_agent_id,
            role="human",
            valid_from=valid_from,
            registered_by={"signer_pkid": anchor_pkid, "signature": sig},
        )

        # Revoke it
        tmp_registry.revoke(human_pkid, reason="retired")

        # Try to deposit with revoked key
        mh = "sha256:revoked-human-test"
        deposit_sig = tmp_signer.sign(mh)
        prov = {
            "manifest_hash": mh,
            "agent_id": "human:alice",
            "tool": "test",
            "signature": deposit_sig,
            "pubkey_id": human_pkid,
            "schema_version": "lapis-provenance-v0.1",
        }

        with pytest.raises(PermissionError, match="revoked"):
            tmp_log.record(prov, registry=tmp_registry)

    finally:
        os.environ.pop("ZEPHYR_HUMAN_ROOT_ANCHOR", None)


def test_non_revoked_human_deposits_with_anchor_chain(tmp_log, tmp_registry, anchor_signer, tmp_signer):
    """A human key that is anchor-trusted and active can deposit."""
    import zephyr.registry
    from datetime import datetime, timezone
    anchor_pkid = anchor_signer.pubkey_id_str
    os.environ["ZEPHYR_HUMAN_ROOT_ANCHOR"] = anchor_pkid
    zephyr.registry.ZEPHYR_HUMAN_ROOT_ANCHOR = anchor_pkid

    try:
        # Register anchor
        tmp_registry.register(
            anchor_pkid,
            anchor_signer.public_key_bytes.hex(),
            "human:root",
            role="human",
        )

        # Register human key with anchor-chain
        import json
        human_pkid = tmp_signer.pubkey_id_str
        human_pub_hex = tmp_signer.public_key_bytes.hex()
        human_agent_id = "human:alice-synthetic"
        valid_from = datetime.now(timezone.utc).isoformat()

        signing_target = json.dumps(
            [human_pkid, human_pub_hex, human_agent_id, valid_from],
            separators=(",", ":"),
        )
        chain_sig = anchor_signer.sign(signing_target)

        tmp_registry.register(
            human_pkid,
            human_pub_hex,
            human_agent_id,
            role="human",
            valid_from=valid_from,
            registered_by={"signer_pkid": anchor_pkid, "signature": chain_sig},
        )

        # Deposit should succeed
        mh = "sha256:human-deposit-success"
        deposit_sig = tmp_signer.sign(mh)
        prov = {
            "manifest_hash": mh,
            "agent_id": "human:alice-synthetic",
            "tool": "test",
            "signature": deposit_sig,
            "pubkey_id": human_pkid,
            "schema_version": "lapis-provenance-v0.1",
            "timestamp": "2026-06-08T00:00:00+00:00",
        }

        assert tmp_log.record(prov, registry=tmp_registry) is True

    finally:
        os.environ.pop("ZEPHYR_HUMAN_ROOT_ANCHOR", None)
