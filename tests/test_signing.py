"""Tests for zephyr.signing and zephyr.registry.

All identities are synthetic (agent:zephyr-selftest, human:test).
No real human identities. No writes to /data/zephyr/*.
"""

import pytest

from zephyr.signing import (
    load_or_create_agent_key,
    pubkey_id,
    sign_manifest,
    verify_manifest,
    AgentSigner,
    _reset_signer,
)
from zephyr.registry import (
    PubkeyRegistry,
    is_human_namespace,
    _reset_registry,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_signer(tmp_path):
    key_path = tmp_path / "agent-keys" / "test.key"
    return AgentSigner(key_path)


# ---------------------------------------------------------------------------
# pubkey_id
# ---------------------------------------------------------------------------


def test_pubkey_id_format(tmp_path):
    s = make_signer(tmp_path)
    pid = s.pubkey_id_str
    assert pid.startswith("ed25519:")
    hex_part = pid[len("ed25519:"):]
    assert len(hex_part) == 16
    assert all(c in "0123456789abcdef" for c in hex_part)


def test_pubkey_id_deterministic(tmp_path):
    key_path = tmp_path / "agent-keys" / "test.key"
    s1 = AgentSigner(key_path)
    s2 = AgentSigner(key_path)  # same file
    assert s1.pubkey_id_str == s2.pubkey_id_str


def test_pubkey_id_different_keys(tmp_path):
    s1 = AgentSigner(tmp_path / "a.key")
    s2 = AgentSigner(tmp_path / "b.key")
    assert s1.pubkey_id_str != s2.pubkey_id_str


# ---------------------------------------------------------------------------
# sign / verify
# ---------------------------------------------------------------------------


def test_sign_verify_roundtrip(tmp_path):
    s = make_signer(tmp_path)
    mh = "sha256:abc123def456"
    sig = s.sign(mh)
    assert isinstance(sig, str)
    assert len(sig) == 128  # 64 bytes hex
    assert verify_manifest(mh, sig, s.public_key_bytes)


def test_verify_tampered_manifest(tmp_path):
    s = make_signer(tmp_path)
    mh = "sha256:abc123def456"
    sig = s.sign(mh)
    assert not verify_manifest("sha256:tampered", sig, s.public_key_bytes)


def test_verify_tampered_sig(tmp_path):
    s = make_signer(tmp_path)
    mh = "sha256:abc123def456"
    sig = s.sign(mh)
    bad_sig = "ff" * 64
    assert not verify_manifest(mh, bad_sig, s.public_key_bytes)


def test_verify_wrong_key(tmp_path):
    s1 = AgentSigner(tmp_path / "a.key")
    s2 = AgentSigner(tmp_path / "b.key")
    mh = "sha256:abc123def456"
    sig = s1.sign(mh)
    # signed by s1, verified against s2's key — must fail
    assert not verify_manifest(mh, sig, s2.public_key_bytes)


# ---------------------------------------------------------------------------
# load_or_create_agent_key — O_EXCL idempotency
# ---------------------------------------------------------------------------


def test_key_persists_across_loads(tmp_path):
    key_path = tmp_path / "test.key"
    k1 = load_or_create_agent_key(key_path)
    k2 = load_or_create_agent_key(key_path)
    # Same key file -> same public key bytes
    from cryptography.hazmat.primitives import serialization

    pub1 = k1.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    pub2 = k2.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert pub1 == pub2


# ---------------------------------------------------------------------------
# is_human_namespace
# ---------------------------------------------------------------------------


def test_human_namespace_exact():
    assert is_human_namespace("Erah")


def test_human_namespace_prefix():
    assert is_human_namespace("human:test")
    assert is_human_namespace("human:ada")
    assert is_human_namespace("human:")


def test_not_human_namespace():
    assert not is_human_namespace("agent:zephyr-selftest")
    assert not is_human_namespace("agent:brix")
    assert not is_human_namespace("conductor")
    assert not is_human_namespace("")


# ---------------------------------------------------------------------------
# PubkeyRegistry
# ---------------------------------------------------------------------------


def test_registry_register_and_lookup(tmp_path):
    reg = PubkeyRegistry(tmp_path / "keys")
    s = make_signer(tmp_path)
    pkid = s.pubkey_id_str
    pub_hex = s.public_key_bytes.hex()

    entry = reg.register(pkid, pub_hex, "agent:zephyr-selftest", role="agent")
    assert entry["pubkey_id"] == pkid
    assert entry["role"] == "agent"
    assert entry["agent_id"] == "agent:zephyr-selftest"

    found = reg.lookup(pkid)
    assert found is not None
    assert found["pubkey_id"] == pkid


def test_registry_lookup_absent(tmp_path):
    reg = PubkeyRegistry(tmp_path / "keys")
    assert reg.lookup("ed25519:doesnotexist") is None


def test_registry_register_idempotent(tmp_path):
    reg = PubkeyRegistry(tmp_path / "keys")
    s = make_signer(tmp_path)
    pkid = s.pubkey_id_str
    pub_hex = s.public_key_bytes.hex()

    e1 = reg.register(pkid, pub_hex, "agent:zephyr-selftest", "agent")
    e2 = reg.register(pkid, pub_hex, "agent:zephyr-selftest", "agent")
    assert e1["pubkey_id"] == e2["pubkey_id"]
    assert reg.count_files(tmp_path / "keys") == 1


def test_registry_load_all(tmp_path):
    reg = PubkeyRegistry(tmp_path / "keys")
    s1 = AgentSigner(tmp_path / "k1.key")
    s2 = AgentSigner(tmp_path / "k2.key")
    reg.register(s1.pubkey_id_str, s1.public_key_bytes.hex(), "agent:a", "agent")
    reg.register(s2.pubkey_id_str, s2.public_key_bytes.hex(), "agent:b", "agent")
    all_entries = reg.load_all()
    assert len(all_entries) == 2


def test_registry_refuses_human_namespace_as_agent(tmp_path):
    reg = PubkeyRegistry(tmp_path / "keys")
    s = make_signer(tmp_path)
    with pytest.raises(ValueError, match="human-namespace"):
        reg.register(s.pubkey_id_str, s.public_key_bytes.hex(), "Erah", role="agent")
    with pytest.raises(ValueError, match="human-namespace"):
        reg.register(s.pubkey_id_str, s.public_key_bytes.hex(), "human:test", role="agent")


def test_registry_human_role_allowed_with_human_id(tmp_path):
    """Human-role registration is permitted (done out-of-band, not via agent TOFU)."""
    reg = PubkeyRegistry(tmp_path / "keys")
    s = make_signer(tmp_path)
    # role="human" with human-namespace agent_id is allowed
    entry = reg.register(s.pubkey_id_str, s.public_key_bytes.hex(), "human:test", role="human")
    assert entry["role"] == "human"
    assert entry["agent_id"] == "human:test"


def test_registry_invalid_role(tmp_path):
    reg = PubkeyRegistry(tmp_path / "keys")
    s = make_signer(tmp_path)
    with pytest.raises(ValueError, match="role must be"):
        reg.register(s.pubkey_id_str, s.public_key_bytes.hex(), "agent:x", role="unknown")


# Helper to count files (not part of the public API, kept test-local)
PubkeyRegistry.count_files = staticmethod(
    lambda d: len(list(d.glob("*.json"))) if d.exists() else 0
)
