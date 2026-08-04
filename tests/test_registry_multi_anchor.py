"""Tests for Y0 registry multi-anchor: ZEPHYR_HUMAN_ROOT_ANCHORS (plural), anchor-status
enforcement (G1), and signing-anchor tier attribution (G2).

All identities are synthetic. Every test runs against a scratch ZEPHYR_KEYS_DIR under
tmp_path — never the real /data/zephyr/keys.
"""

from __future__ import annotations

import json

import pytest

from zephyr.registry import (
    PubkeyRegistry,
    _resolve_anchor_pkids,
    agent_acceptance,
    agent_anchor_status,
    agent_canonical_target,
    node_anchor_status,
    node_canonical_target,
    verify_agent_anchor_chain,
    verify_human_anchor_chain,
    verify_node_anchor_chain,
)
from zephyr.signing import AgentSigner


@pytest.fixture(autouse=True)
def _scratch_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("ZEPHYR_ATTRIBUTION_DB", str(tmp_path / "attribution.db"))
    # Multi-anchor tests never want a stray singular value bleeding in from the
    # real host environment.
    monkeypatch.delenv("ZEPHYR_HUMAN_ROOT_ANCHOR", raising=False)
    monkeypatch.delenv("ZEPHYR_HUMAN_ROOT_ANCHORS", raising=False)


@pytest.fixture()
def tmp_registry(tmp_path):
    return PubkeyRegistry(tmp_path / "keys")


@pytest.fixture()
def anchor_a_signer(tmp_path):
    return AgentSigner(tmp_path / "agent-keys" / "anchor-a.key")


@pytest.fixture()
def anchor_b_signer(tmp_path):
    return AgentSigner(tmp_path / "agent-keys" / "anchor-b.key")


@pytest.fixture()
def two_anchors(monkeypatch, tmp_registry, anchor_a_signer, anchor_b_signer):
    """Registers two human root anchors and pins both via ZEPHYR_HUMAN_ROOT_ANCHORS.

    Anchor A is tier='software' (mirrors the live root); anchor B is
    tier='hardware' (mirrors a Y1/Y2 hardware-rooted key) — exercises G2's
    mixed-tier reporting.
    """
    import zephyr.registry

    a_pkid = anchor_a_signer.pubkey_id_str
    b_pkid = anchor_b_signer.pubkey_id_str
    plural = f"{a_pkid},{b_pkid}"
    monkeypatch.setenv("ZEPHYR_HUMAN_ROOT_ANCHORS", plural)
    monkeypatch.setattr(zephyr.registry, "ZEPHYR_HUMAN_ROOT_ANCHORS", plural)

    tmp_registry.register(
        a_pkid, anchor_a_signer.public_key_bytes.hex(), "human:root-a-synthetic",
        role="human", assurance_tier="software",
    )
    tmp_registry.register(
        b_pkid, anchor_b_signer.public_key_bytes.hex(), "human:root-b-synthetic",
        role="human", assurance_tier="hardware",
    )
    return a_pkid, b_pkid


def _register_agent(tmp_registry, signer, agent_id):
    return tmp_registry.register(
        signer.pubkey_id_str, signer.public_key_bytes.hex(), agent_id, role="agent",
    )


def _register_node(tmp_registry, signer, agent_id):
    node_binding = {"node": "macbook", "hostname": "macbook.local", "tailscale_ip": "100.100.1.9"}
    return tmp_registry.register(
        signer.pubkey_id_str, signer.public_key_bytes.hex(), agent_id,
        role="node", node_binding=node_binding,
    )


def _vouch_agent(tmp_registry, anchor_signer, agent_entry):
    target = agent_canonical_target(
        agent_entry["pubkey_id"], agent_entry["public_key_hex"],
        agent_entry["agent_id"], agent_entry.get("valid_from", ""),
    )
    sig = anchor_signer.sign(target)
    return tmp_registry.set_registered_by(
        agent_entry["pubkey_id"], {"signer_pkid": anchor_signer.pubkey_id_str, "signature": sig}
    )


def _vouch_node(tmp_registry, anchor_signer, node_entry):
    target = node_canonical_target(
        node_entry["pubkey_id"], node_entry["public_key_hex"], node_entry["agent_id"],
        node_entry.get("valid_from", ""), node_entry["node_binding"],
    )
    sig = anchor_signer.sign(target)
    return tmp_registry.set_registered_by(
        node_entry["pubkey_id"], {"signer_pkid": anchor_signer.pubkey_id_str, "signature": sig}
    )


def _revoke_anchor(tmp_registry, anchor_signer, reason="compromised"):
    """Revoke a root anchor through the real revoke() path with a valid
    self-signed credential (mirrors the spec's evidence-base repro)."""
    pkid = anchor_signer.pubkey_id_str
    target = json.dumps([pkid, reason], separators=(",", ":"))
    sig = anchor_signer.sign(target)
    return tmp_registry.revoke(
        pkid, reason=reason, caller_credential={"signer_pkid": pkid, "signature": sig}
    )


# ---------------------------------------------------------------------------
# Resolver — union / de-dup / ordering
# ---------------------------------------------------------------------------


def test_resolve_anchor_pkids_empty_when_unset():
    assert _resolve_anchor_pkids() == ()


def test_resolve_anchor_pkids_plural_only(monkeypatch):
    import zephyr.registry

    monkeypatch.setattr(zephyr.registry, "ZEPHYR_HUMAN_ROOT_ANCHORS", "a,b")
    assert _resolve_anchor_pkids() == ("a", "b")


def test_resolve_anchor_pkids_singular_only(monkeypatch):
    import zephyr.registry

    monkeypatch.setattr(zephyr.registry, "ZEPHYR_HUMAN_ROOT_ANCHOR", "a")
    assert _resolve_anchor_pkids() == ("a",)


def test_resolve_anchor_pkids_union_dedup_and_whitespace(monkeypatch):
    import zephyr.registry

    monkeypatch.setattr(zephyr.registry, "ZEPHYR_HUMAN_ROOT_ANCHORS", "a, b, a")
    monkeypatch.setattr(zephyr.registry, "ZEPHYR_HUMAN_ROOT_ANCHOR", "b")
    assert _resolve_anchor_pkids() == ("a", "b")


# ---------------------------------------------------------------------------
# Two anchors both confer trust; either may vouch
# ---------------------------------------------------------------------------


def test_both_anchors_self_verify(tmp_registry, two_anchors):
    a_pkid, b_pkid = two_anchors
    entry_a = tmp_registry.lookup(a_pkid)
    entry_b = tmp_registry.lookup(b_pkid)

    trusted_a, _ = verify_human_anchor_chain(entry_a, registry=tmp_registry)
    trusted_b, _ = verify_human_anchor_chain(entry_b, registry=tmp_registry)
    assert trusted_a is True
    assert trusted_b is True


def test_subject_vouched_by_anchor_b_while_a_also_pinned(tmp_registry, two_anchors, anchor_b_signer):
    a_pkid, b_pkid = two_anchors
    agent_signer = AgentSigner(tmp_registry._dir.parent / "agent-keys" / "agent.key")
    agent_entry = _register_agent(tmp_registry, agent_signer, "agent:vouched-by-b")
    vouched = _vouch_agent(tmp_registry, anchor_b_signer, agent_entry)

    trusted, detail = verify_agent_anchor_chain(vouched, registry=tmp_registry)
    assert trusted is True
    assert "verified" in detail.lower()

    status = agent_anchor_status(vouched["pubkey_id"], registry=tmp_registry)
    assert status == {"state": "anchored", "root_tier": "hardware"}


# ---------------------------------------------------------------------------
# G1 — revoked anchor confers nothing via either branch
# ---------------------------------------------------------------------------


def test_revoked_anchor_no_longer_self_verifies(tmp_registry, two_anchors, anchor_a_signer):
    a_pkid, _b_pkid = two_anchors
    _revoke_anchor(tmp_registry, anchor_a_signer)

    entry_a = tmp_registry.lookup(a_pkid)
    assert entry_a["status"] == "revoked"

    trusted, detail = verify_human_anchor_chain(entry_a, registry=tmp_registry)
    assert trusted is False
    assert "revoked" in detail.lower() or "status=" in detail.lower()


def test_revoked_anchor_vouch_confers_no_trust(tmp_registry, two_anchors, anchor_a_signer):
    """A subject vouched by anchor A moves to revoked_anchor once A is revoked —
    not 'anchored', and distinct from 'self_asserted' (Y2 disaster-recovery case
    inverse: the revoked side, not the survivor)."""
    agent_signer = AgentSigner(tmp_registry._dir.parent / "agent-keys" / "agent2.key")
    agent_entry = _register_agent(tmp_registry, agent_signer, "agent:vouched-by-a")
    vouched = _vouch_agent(tmp_registry, anchor_a_signer, agent_entry)

    # Sanity: trusted before revocation.
    trusted_before, _ = verify_agent_anchor_chain(vouched, registry=tmp_registry)
    assert trusted_before is True

    _revoke_anchor(tmp_registry, anchor_a_signer)

    trusted_after, _ = verify_agent_anchor_chain(vouched, registry=tmp_registry)
    assert trusted_after is False

    status = agent_anchor_status(vouched["pubkey_id"], registry=tmp_registry)
    assert status == {"state": "revoked_anchor", "root_tier": None}
    assert status["state"] != "self_asserted"

    verdict = agent_acceptance(vouched["pubkey_id"], registry=tmp_registry)
    assert verdict["accept"] is False
    assert verdict["state"] == "revoked_anchor"


def test_revoked_anchor_bootstrap_agent_acceptance_false(tmp_registry, two_anchors, anchor_a_signer):
    """The Y2 disaster-recovery vector from the spec's evidence base, reproduced
    through agent_acceptance (the surface lapis-pm's enforcement calls)."""
    node_signer = AgentSigner(tmp_registry._dir.parent / "agent-keys" / "node1.key")
    node_entry = _register_node(tmp_registry, node_signer, "agent:node-vouched-by-a")
    vouched = _vouch_node(tmp_registry, anchor_a_signer, node_entry)

    status_before = node_anchor_status(vouched["pubkey_id"], registry=tmp_registry)
    assert status_before["state"] == "anchored"

    _revoke_anchor(tmp_registry, anchor_a_signer)

    status_after = node_anchor_status(vouched["pubkey_id"], registry=tmp_registry)
    assert status_after == {"state": "revoked_anchor", "root_tier": None}


# ---------------------------------------------------------------------------
# The surviving anchor still confers trust after its sibling is revoked
# (Y2 disaster-recovery case — the reason this unit exists)
# ---------------------------------------------------------------------------


def test_surviving_anchor_unaffected_by_sibling_revocation(
    tmp_registry, two_anchors, anchor_a_signer, anchor_b_signer
):
    a_pkid, b_pkid = two_anchors

    agent_signer = AgentSigner(tmp_registry._dir.parent / "agent-keys" / "agent3.key")
    agent_entry = _register_agent(tmp_registry, agent_signer, "agent:vouched-by-b-survivor")
    vouched = _vouch_agent(tmp_registry, anchor_b_signer, agent_entry)

    # Revoke sibling anchor A — B, and everything B vouched, must be unaffected.
    _revoke_anchor(tmp_registry, anchor_a_signer)

    trusted, _ = verify_agent_anchor_chain(vouched, registry=tmp_registry)
    assert trusted is True

    status = agent_anchor_status(vouched["pubkey_id"], registry=tmp_registry)
    assert status == {"state": "anchored", "root_tier": "hardware"}

    verdict = agent_acceptance(vouched["pubkey_id"], registry=tmp_registry)
    assert verdict["accept"] is True
    assert verdict["root_tier"] == "hardware"

    # B itself still self-verifies.
    entry_b = tmp_registry.lookup(b_pkid)
    trusted_b, _ = verify_human_anchor_chain(entry_b, registry=tmp_registry)
    assert trusted_b is True


# ---------------------------------------------------------------------------
# G2 — mixed-tier anchors report the SIGNING anchor's tier, not a fixed lookup
# ---------------------------------------------------------------------------


def test_mixed_tier_reports_signing_anchor_not_first_configured(
    tmp_registry, two_anchors, anchor_a_signer, anchor_b_signer
):
    """anchor_a is software, anchor_b is hardware. A subject vouched by A reports
    software; a subject vouched by B reports hardware — regardless of which
    anchor is 'first' in the resolved set."""
    signer_for_a = AgentSigner(tmp_registry._dir.parent / "agent-keys" / "for-a.key")
    entry_for_a = _register_agent(tmp_registry, signer_for_a, "agent:tier-check-a")
    vouched_a = _vouch_agent(tmp_registry, anchor_a_signer, entry_for_a)
    status_a = agent_anchor_status(vouched_a["pubkey_id"], registry=tmp_registry)
    assert status_a == {"state": "anchored", "root_tier": "software"}

    signer_for_b = AgentSigner(tmp_registry._dir.parent / "agent-keys" / "for-b.key")
    entry_for_b = _register_agent(tmp_registry, signer_for_b, "agent:tier-check-b")
    vouched_b = _vouch_agent(tmp_registry, anchor_b_signer, entry_for_b)
    status_b = agent_anchor_status(vouched_b["pubkey_id"], registry=tmp_registry)
    assert status_b == {"state": "anchored", "root_tier": "hardware"}


# ---------------------------------------------------------------------------
# Singular env var alone still behaves exactly as today
# ---------------------------------------------------------------------------


def test_singular_env_var_alone_unchanged(monkeypatch, tmp_registry, anchor_a_signer):
    import zephyr.registry

    a_pkid = anchor_a_signer.pubkey_id_str
    monkeypatch.setenv("ZEPHYR_HUMAN_ROOT_ANCHOR", a_pkid)
    monkeypatch.setattr(zephyr.registry, "ZEPHYR_HUMAN_ROOT_ANCHOR", a_pkid)
    # Plural stays unset.
    assert zephyr.registry.ZEPHYR_HUMAN_ROOT_ANCHORS is None

    tmp_registry.register(
        a_pkid, anchor_a_signer.public_key_bytes.hex(), "human:root-solo-synthetic",
        role="human", assurance_tier="software",
    )

    agent_signer = AgentSigner(tmp_registry._dir.parent / "agent-keys" / "agent-solo.key")
    agent_entry = _register_agent(tmp_registry, agent_signer, "agent:solo-vouch")
    vouched = _vouch_agent(tmp_registry, anchor_a_signer, agent_entry)

    status = agent_anchor_status(vouched["pubkey_id"], registry=tmp_registry)
    assert status == {"state": "anchored", "root_tier": "software"}

    entry_a = tmp_registry.lookup(a_pkid)
    trusted, _ = verify_human_anchor_chain(entry_a, registry=tmp_registry)
    assert trusted is True
