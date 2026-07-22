"""Tests for the node-subject anchor-chain verifier: verify_node_anchor_chain,
node_anchor_status, and the node canonical-target format.

All identities are synthetic. Every test runs against a scratch ZEPHYR_KEYS_DIR
under tmp_path — never the real /data/zephyr/keys.
"""

from __future__ import annotations

import json

import pytest

from zephyr.attribution import AttributionLog
from zephyr.registry import (
    PubkeyRegistry,
    node_anchor_status,
    node_canonical_target,
    verify_human_anchor_chain,
    verify_node_anchor_chain,
)
from zephyr.signing import AgentSigner


@pytest.fixture(autouse=True)
def _scratch_env(tmp_path, monkeypatch):
    """DoD-8: every test runs against a scratch keyring/db under tmp_path, even
    though most tests here use an explicit PubkeyRegistry(tmp_path) directly."""
    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("ZEPHYR_ATTRIBUTION_DB", str(tmp_path / "attribution.db"))


@pytest.fixture()
def tmp_registry(tmp_path):
    return PubkeyRegistry(tmp_path / "keys")


@pytest.fixture()
def anchor_signer(tmp_path):
    return AgentSigner(tmp_path / "agent-keys" / "anchor.key")


@pytest.fixture()
def node_signer(tmp_path):
    return AgentSigner(tmp_path / "agent-keys" / "node.key")


@pytest.fixture()
def pinned_anchor(monkeypatch, tmp_registry, anchor_signer):
    """Registers anchor_signer as the human root and pins it, restoring after."""
    import zephyr.registry

    anchor_pkid = anchor_signer.pubkey_id_str
    monkeypatch.setenv("ZEPHYR_HUMAN_ROOT_ANCHOR", anchor_pkid)
    monkeypatch.setattr(zephyr.registry, "ZEPHYR_HUMAN_ROOT_ANCHOR", anchor_pkid)

    tmp_registry.register(
        anchor_pkid,
        anchor_signer.public_key_bytes.hex(),
        "human:root-synthetic",
        role="human",
        assurance_tier="software",
    )
    return anchor_pkid


def _register_node(tmp_registry, node_signer, agent_id="agent:vouch-node-test"):
    node_binding = {"node": "macbook", "hostname": "macbook.local", "tailscale_ip": "100.100.1.9"}
    return tmp_registry.register(
        node_signer.pubkey_id_str,
        node_signer.public_key_bytes.hex(),
        agent_id,
        role="node",
        node_binding=node_binding,
    )


def _vouch(tmp_registry, anchor_signer, node_entry):
    target = node_canonical_target(
        node_entry["pubkey_id"],
        node_entry["public_key_hex"],
        node_entry["agent_id"],
        node_entry.get("valid_from", ""),
        node_entry["node_binding"],
    )
    sig = anchor_signer.sign(target)
    return tmp_registry.set_registered_by(
        node_entry["pubkey_id"], {"signer_pkid": anchor_signer.pubkey_id_str, "signature": sig}
    )


# ---------------------------------------------------------------------------
# DoD-9 — canonical target round-trips
# ---------------------------------------------------------------------------


def test_node_canonical_target_round_trips(tmp_registry, anchor_signer, node_signer, pinned_anchor):
    node_entry = _register_node(tmp_registry, node_signer)

    signed_target = node_canonical_target(
        node_entry["pubkey_id"],
        node_entry["public_key_hex"],
        node_entry["agent_id"],
        node_entry.get("valid_from", ""),
        node_entry["node_binding"],
    )
    vouched = _vouch(tmp_registry, anchor_signer, node_entry)

    # verify_node_anchor_chain reconstructs the target internally; assert it is
    # byte-for-byte identical to what vouch-node signed.
    reconstructed = node_canonical_target(
        vouched["pubkey_id"],
        vouched["public_key_hex"],
        vouched["agent_id"],
        vouched.get("valid_from", ""),
        vouched["node_binding"],
    )
    assert reconstructed == signed_target

    trusted, detail = verify_node_anchor_chain(vouched, registry=tmp_registry)
    assert trusted is True, detail


# ---------------------------------------------------------------------------
# DoD-4 — verify anchored
# ---------------------------------------------------------------------------


def test_verify_node_anchor_chain_true_for_vouched_node(tmp_registry, anchor_signer, node_signer, pinned_anchor):
    node_entry = _register_node(tmp_registry, node_signer)
    vouched = _vouch(tmp_registry, anchor_signer, node_entry)

    trusted, detail = verify_node_anchor_chain(vouched, registry=tmp_registry)
    assert trusted is True
    assert "verified" in detail.lower()


def test_verify_node_cli_exit_0_for_anchored(tmp_registry, anchor_signer, node_signer, pinned_anchor, monkeypatch, tmp_path):
    from zephyr import keymint

    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))
    node_entry = _register_node(tmp_registry, node_signer)
    _vouch(tmp_registry, anchor_signer, node_entry)

    rc = keymint.main(["verify-node", "--node-pkid", node_entry["pubkey_id"]])
    assert rc == 0


# ---------------------------------------------------------------------------
# DoD-5 — additive / non-breaking
# ---------------------------------------------------------------------------


def test_self_asserted_node_still_verifies_at_deposit_layer(tmp_path, tmp_registry, node_signer):
    """A node key with no registered_by still deposits exactly as today."""
    _register_node(tmp_registry, node_signer, agent_id="agent:brix-self-asserted")

    log = AttributionLog(tmp_path / "attr.db")
    mh = "sha256:self-asserted-deposit"
    sig = node_signer.sign(mh)
    prov = {
        "manifest_hash": mh,
        "agent_id": "agent:gardener",
        "tool": "test",
        "signature": sig,
        "pubkey_id": node_signer.pubkey_id_str,
        "schema_version": "lapis-provenance-v0.1",
    }
    assert log.record(prov, registry=tmp_registry) is True


def test_self_asserted_node_reports_self_asserted(tmp_registry, node_signer):
    node_entry = _register_node(tmp_registry, node_signer)
    status = node_anchor_status(node_entry["pubkey_id"], registry=tmp_registry)
    assert status == {"state": "self_asserted", "root_tier": None}


def test_verify_node_cli_exit_3_for_self_asserted(tmp_registry, node_signer, monkeypatch, tmp_path):
    from zephyr import keymint

    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))
    node_entry = _register_node(tmp_registry, node_signer)

    rc = keymint.main(["verify-node", "--node-pkid", node_entry["pubkey_id"]])
    assert rc == 3


# ---------------------------------------------------------------------------
# DoD-6 — reject forged vouch
# ---------------------------------------------------------------------------


def test_reject_vouch_wrong_signer(tmp_registry, anchor_signer, node_signer, pinned_anchor, tmp_path):
    """A node whose registered_by signer is not the anchor is invalid."""
    node_entry = _register_node(tmp_registry, node_signer)

    imposter = AgentSigner(tmp_path / "agent-keys" / "imposter.key")
    target = node_canonical_target(
        node_entry["pubkey_id"],
        node_entry["public_key_hex"],
        node_entry["agent_id"],
        node_entry.get("valid_from", ""),
        node_entry["node_binding"],
    )
    forged_sig = imposter.sign(target)
    forged = tmp_registry.set_registered_by(
        node_entry["pubkey_id"],
        {"signer_pkid": imposter.pubkey_id_str, "signature": forged_sig},
    )

    trusted, detail = verify_node_anchor_chain(forged, registry=tmp_registry)
    assert trusted is False
    assert "not the pinned anchor" in detail


def test_reject_vouch_bad_signature(tmp_registry, anchor_signer, node_signer, pinned_anchor):
    """A node whose registered_by signature doesn't verify is invalid."""
    node_entry = _register_node(tmp_registry, node_signer)
    forged = tmp_registry.set_registered_by(
        node_entry["pubkey_id"],
        {"signer_pkid": anchor_signer.pubkey_id_str, "signature": "ff" * 64},
    )

    trusted, detail = verify_node_anchor_chain(forged, registry=tmp_registry)
    assert trusted is False
    assert "signature" in detail.lower()


def test_verify_node_cli_exit_1_for_invalid(tmp_registry, anchor_signer, node_signer, pinned_anchor, monkeypatch, tmp_path):
    from zephyr import keymint

    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))
    node_entry = _register_node(tmp_registry, node_signer)
    tmp_registry.set_registered_by(
        node_entry["pubkey_id"],
        {"signer_pkid": anchor_signer.pubkey_id_str, "signature": "ff" * 64},
    )

    rc = keymint.main(["verify-node", "--node-pkid", node_entry["pubkey_id"]])
    assert rc == 1


# ---------------------------------------------------------------------------
# DoD-7 — human path untouched (refactor sanity; full coverage in
# tests/test_revocation_and_anchors.py, unmodified)
# ---------------------------------------------------------------------------


def test_human_anchor_chain_still_works_after_refactor(tmp_registry, anchor_signer, pinned_anchor, tmp_path):
    human_signer = AgentSigner(tmp_path / "agent-keys" / "human.key")
    human_pkid = human_signer.pubkey_id_str
    human_pub_hex = human_signer.public_key_bytes.hex()
    human_agent_id = "human:alice-synthetic"
    valid_from = "2026-07-22T00:00:00+00:00"

    signing_target = json.dumps(
        [human_pkid, human_pub_hex, human_agent_id, valid_from],
        separators=(",", ":"),
    )
    sig = anchor_signer.sign(signing_target)

    human_entry = tmp_registry.register(
        human_pkid,
        human_pub_hex,
        human_agent_id,
        role="human",
        valid_from=valid_from,
        registered_by={"signer_pkid": anchor_signer.pubkey_id_str, "signature": sig},
    )

    trusted, detail = verify_human_anchor_chain(human_entry, registry=tmp_registry)
    assert trusted is True
    assert "verified" in detail.lower()


# ---------------------------------------------------------------------------
# unverifiable (no anchor pinned) — exit 4
# ---------------------------------------------------------------------------


def test_node_anchor_status_unverifiable_when_anchor_unset(tmp_registry, anchor_signer, node_signer, monkeypatch, tmp_path):
    import zephyr.registry

    monkeypatch.delenv("ZEPHYR_HUMAN_ROOT_ANCHOR", raising=False)
    monkeypatch.setattr(zephyr.registry, "ZEPHYR_HUMAN_ROOT_ANCHOR", None)

    node_entry = _register_node(tmp_registry, node_signer)
    target = node_canonical_target(
        node_entry["pubkey_id"],
        node_entry["public_key_hex"],
        node_entry["agent_id"],
        node_entry.get("valid_from", ""),
        node_entry["node_binding"],
    )
    sig = anchor_signer.sign(target)
    tmp_registry.set_registered_by(
        node_entry["pubkey_id"],
        {"signer_pkid": anchor_signer.pubkey_id_str, "signature": sig},
    )

    status = node_anchor_status(node_entry["pubkey_id"], registry=tmp_registry)
    assert status == {"state": "unverifiable", "root_tier": None}


def test_verify_node_cli_exit_4_for_unset_anchor(tmp_registry, anchor_signer, node_signer, monkeypatch, tmp_path):
    import zephyr.registry
    from zephyr import keymint

    monkeypatch.delenv("ZEPHYR_HUMAN_ROOT_ANCHOR", raising=False)
    monkeypatch.setattr(zephyr.registry, "ZEPHYR_HUMAN_ROOT_ANCHOR", None)
    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))

    node_entry = _register_node(tmp_registry, node_signer)
    target = node_canonical_target(
        node_entry["pubkey_id"],
        node_entry["public_key_hex"],
        node_entry["agent_id"],
        node_entry.get("valid_from", ""),
        node_entry["node_binding"],
    )
    sig = anchor_signer.sign(target)
    tmp_registry.set_registered_by(
        node_entry["pubkey_id"],
        {"signer_pkid": anchor_signer.pubkey_id_str, "signature": sig},
    )

    rc = keymint.main(["verify-node", "--node-pkid", node_entry["pubkey_id"]])
    assert rc == 4


# ---------------------------------------------------------------------------
# DoD-11 — software-tier surfaced
# ---------------------------------------------------------------------------


def test_node_anchor_status_software_root_tier_surfaced(tmp_registry, anchor_signer, node_signer, pinned_anchor):
    """pinned_anchor registers the anchor with assurance_tier='software'."""
    node_entry = _register_node(tmp_registry, node_signer)
    vouched = _vouch(tmp_registry, anchor_signer, node_entry)

    status = node_anchor_status(vouched["pubkey_id"], registry=tmp_registry)
    assert status == {"state": "anchored", "root_tier": "software"}


def test_node_anchor_status_hardware_root_tier_surfaced(tmp_registry, node_signer, monkeypatch, tmp_path):
    import zephyr.registry

    hw_anchor_signer = AgentSigner(tmp_path / "agent-keys" / "hw-anchor.key")
    hw_anchor_pkid = hw_anchor_signer.pubkey_id_str
    monkeypatch.setenv("ZEPHYR_HUMAN_ROOT_ANCHOR", hw_anchor_pkid)
    monkeypatch.setattr(zephyr.registry, "ZEPHYR_HUMAN_ROOT_ANCHOR", hw_anchor_pkid)

    tmp_registry.register(
        hw_anchor_pkid,
        hw_anchor_signer.public_key_bytes.hex(),
        "human:hw-root-synthetic",
        role="human",
        assurance_tier="hardware",
    )

    node_entry = _register_node(tmp_registry, node_signer)
    target = node_canonical_target(
        node_entry["pubkey_id"],
        node_entry["public_key_hex"],
        node_entry["agent_id"],
        node_entry.get("valid_from", ""),
        node_entry["node_binding"],
    )
    sig = hw_anchor_signer.sign(target)
    vouched = tmp_registry.set_registered_by(
        node_entry["pubkey_id"],
        {"signer_pkid": hw_anchor_pkid, "signature": sig},
    )

    status = node_anchor_status(vouched["pubkey_id"], registry=tmp_registry)
    assert status == {"state": "anchored", "root_tier": "hardware"}


def test_verify_node_cli_emits_software_warning_on_stderr(tmp_registry, anchor_signer, node_signer, pinned_anchor, monkeypatch, tmp_path, capsys):
    from zephyr import keymint

    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))
    node_entry = _register_node(tmp_registry, node_signer)
    _vouch(tmp_registry, anchor_signer, node_entry)

    rc = keymint.main(["verify-node", "--node-pkid", node_entry["pubkey_id"]])
    assert rc == 0
    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert "software" in captured.err.lower()
    assert captured.out == ""


def test_verify_node_cli_no_warning_for_hardware_root(tmp_registry, node_signer, monkeypatch, tmp_path, capsys):
    import zephyr.registry
    from zephyr import keymint

    hw_anchor_signer = AgentSigner(tmp_path / "agent-keys" / "hw-anchor2.key")
    hw_anchor_pkid = hw_anchor_signer.pubkey_id_str
    monkeypatch.setenv("ZEPHYR_HUMAN_ROOT_ANCHOR", hw_anchor_pkid)
    monkeypatch.setattr(zephyr.registry, "ZEPHYR_HUMAN_ROOT_ANCHOR", hw_anchor_pkid)
    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))

    tmp_registry.register(
        hw_anchor_pkid,
        hw_anchor_signer.public_key_bytes.hex(),
        "human:hw-root-synthetic2",
        role="human",
        assurance_tier="hardware",
    )
    node_entry = _register_node(tmp_registry, node_signer)
    target = node_canonical_target(
        node_entry["pubkey_id"],
        node_entry["public_key_hex"],
        node_entry["agent_id"],
        node_entry.get("valid_from", ""),
        node_entry["node_binding"],
    )
    sig = hw_anchor_signer.sign(target)
    tmp_registry.set_registered_by(
        node_entry["pubkey_id"], {"signer_pkid": hw_anchor_pkid, "signature": sig}
    )

    rc = keymint.main(["verify-node", "--node-pkid", node_entry["pubkey_id"]])
    assert rc == 0
    captured = capsys.readouterr()
    assert "WARNING" not in captured.err
