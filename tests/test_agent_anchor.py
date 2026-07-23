"""Tests for the agent-subject anchor-chain verifier: verify_agent_anchor_chain,
agent_anchor_status, agent_acceptance, and the agent canonical-target format.

All identities are synthetic. Every test runs against a scratch ZEPHYR_KEYS_DIR
under tmp_path — never the real /data/zephyr/keys.
"""

from __future__ import annotations

import json

import pytest

from zephyr.attribution import AttributionLog, record_signed
from zephyr.registry import (
    PubkeyRegistry,
    agent_acceptance,
    agent_anchor_status,
    agent_canonical_target,
    verify_agent_anchor_chain,
)
from zephyr.signing import AgentSigner


@pytest.fixture(autouse=True)
def _scratch_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("ZEPHYR_ATTRIBUTION_DB", str(tmp_path / "attribution.db"))


@pytest.fixture()
def tmp_registry(tmp_path):
    return PubkeyRegistry(tmp_path / "keys")


@pytest.fixture()
def anchor_signer(tmp_path):
    return AgentSigner(tmp_path / "agent-keys" / "anchor.key")


@pytest.fixture()
def agent_signer(tmp_path):
    return AgentSigner(tmp_path / "agent-keys" / "agent.key")


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


def _register_agent(tmp_registry, agent_signer, agent_id="agent:vouch-agent-test"):
    return tmp_registry.register(
        agent_signer.pubkey_id_str,
        agent_signer.public_key_bytes.hex(),
        agent_id,
        role="agent",
    )


def _vouch(tmp_registry, anchor_signer, agent_entry):
    target = agent_canonical_target(
        agent_entry["pubkey_id"],
        agent_entry["public_key_hex"],
        agent_entry["agent_id"],
        agent_entry.get("valid_from", ""),
    )
    sig = anchor_signer.sign(target)
    return tmp_registry.set_registered_by(
        agent_entry["pubkey_id"], {"signer_pkid": anchor_signer.pubkey_id_str, "signature": sig}
    )


# ---------------------------------------------------------------------------
# AC1 — canonical target byte-identity + round-trip
# ---------------------------------------------------------------------------


def test_agent_canonical_target_byte_identical_to_human_inline_shape():
    pkid = "ed25519:deadbeef"
    pub_hex = "aa" * 32
    agent_id = "agent:test"
    valid_from = "2026-07-22T00:00:00+00:00"

    expected = json.dumps([pkid, pub_hex, agent_id, valid_from], separators=(",", ":"))
    assert agent_canonical_target(pkid, pub_hex, agent_id, valid_from) == expected


def test_agent_canonical_target_round_trips_through_registry_json(tmp_registry, agent_signer):
    agent_entry = _register_agent(tmp_registry, agent_signer)
    target_before = agent_canonical_target(
        agent_entry["pubkey_id"],
        agent_entry["public_key_hex"],
        agent_entry["agent_id"],
        agent_entry.get("valid_from", ""),
    )

    reloaded = tmp_registry.lookup(agent_entry["pubkey_id"])
    target_after = agent_canonical_target(
        reloaded["pubkey_id"],
        reloaded["public_key_hex"],
        reloaded["agent_id"],
        reloaded.get("valid_from", ""),
    )
    assert target_after == target_before


# ---------------------------------------------------------------------------
# AC2 — anchored
# ---------------------------------------------------------------------------


def test_verify_agent_anchor_chain_true_for_vouched_agent(tmp_registry, anchor_signer, agent_signer, pinned_anchor):
    agent_entry = _register_agent(tmp_registry, agent_signer)
    vouched = _vouch(tmp_registry, anchor_signer, agent_entry)

    trusted, detail = verify_agent_anchor_chain(vouched, registry=tmp_registry)
    assert trusted is True
    assert "verified" in detail.lower()


def test_agent_anchor_status_anchored_software_tier(tmp_registry, anchor_signer, agent_signer, pinned_anchor):
    agent_entry = _register_agent(tmp_registry, agent_signer)
    vouched = _vouch(tmp_registry, anchor_signer, agent_entry)

    status = agent_anchor_status(vouched["pubkey_id"], registry=tmp_registry)
    assert status == {"state": "anchored", "root_tier": "software"}


def test_agent_acceptance_true_for_anchored(tmp_registry, anchor_signer, agent_signer, pinned_anchor):
    agent_entry = _register_agent(tmp_registry, agent_signer)
    vouched = _vouch(tmp_registry, anchor_signer, agent_entry)

    verdict = agent_acceptance(vouched["pubkey_id"], registry=tmp_registry)
    assert verdict["accept"] is True
    assert verdict["state"] == "anchored"
    assert verdict["root_tier"] == "software"


# ---------------------------------------------------------------------------
# AC3 — self-asserted (no registered_by)
# ---------------------------------------------------------------------------


def test_agent_anchor_status_self_asserted(tmp_registry, agent_signer):
    agent_entry = _register_agent(tmp_registry, agent_signer)
    status = agent_anchor_status(agent_entry["pubkey_id"], registry=tmp_registry)
    assert status == {"state": "self_asserted", "root_tier": None}


def test_agent_acceptance_false_for_self_asserted(tmp_registry, agent_signer):
    agent_entry = _register_agent(tmp_registry, agent_signer)
    verdict = agent_acceptance(agent_entry["pubkey_id"], registry=tmp_registry)
    assert verdict["accept"] is False
    assert verdict["state"] == "self_asserted"
    assert verdict["reason"] == "self_asserted"


# ---------------------------------------------------------------------------
# AC4 — invalid (tampered signature / wrong signer)
# ---------------------------------------------------------------------------


def test_reject_vouch_bad_signature(tmp_registry, anchor_signer, agent_signer, pinned_anchor):
    agent_entry = _register_agent(tmp_registry, agent_signer)
    forged = tmp_registry.set_registered_by(
        agent_entry["pubkey_id"],
        {"signer_pkid": anchor_signer.pubkey_id_str, "signature": "ff" * 64},
    )

    trusted, detail = verify_agent_anchor_chain(forged, registry=tmp_registry)
    assert trusted is False
    assert "signature" in detail.lower()

    status = agent_anchor_status(forged["pubkey_id"], registry=tmp_registry)
    assert status["state"] == "invalid"
    assert agent_acceptance(forged["pubkey_id"], registry=tmp_registry)["accept"] is False


def test_reject_vouch_wrong_signer(tmp_registry, anchor_signer, agent_signer, pinned_anchor, tmp_path):
    agent_entry = _register_agent(tmp_registry, agent_signer)

    imposter = AgentSigner(tmp_path / "agent-keys" / "imposter.key")
    target = agent_canonical_target(
        agent_entry["pubkey_id"],
        agent_entry["public_key_hex"],
        agent_entry["agent_id"],
        agent_entry.get("valid_from", ""),
    )
    forged_sig = imposter.sign(target)
    forged = tmp_registry.set_registered_by(
        agent_entry["pubkey_id"],
        {"signer_pkid": imposter.pubkey_id_str, "signature": forged_sig},
    )

    trusted, detail = verify_agent_anchor_chain(forged, registry=tmp_registry)
    assert trusted is False
    assert "not the pinned anchor" in detail


# ---------------------------------------------------------------------------
# AC5 — unverifiable (anchor unset)
# ---------------------------------------------------------------------------


def test_agent_anchor_status_unverifiable_when_anchor_unset(tmp_registry, anchor_signer, agent_signer, monkeypatch):
    import zephyr.registry

    monkeypatch.delenv("ZEPHYR_HUMAN_ROOT_ANCHOR", raising=False)
    monkeypatch.setattr(zephyr.registry, "ZEPHYR_HUMAN_ROOT_ANCHOR", None)

    agent_entry = _register_agent(tmp_registry, agent_signer)
    target = agent_canonical_target(
        agent_entry["pubkey_id"],
        agent_entry["public_key_hex"],
        agent_entry["agent_id"],
        agent_entry.get("valid_from", ""),
    )
    sig = anchor_signer.sign(target)
    vouched = tmp_registry.set_registered_by(
        agent_entry["pubkey_id"],
        {"signer_pkid": anchor_signer.pubkey_id_str, "signature": sig},
    )

    status = agent_anchor_status(vouched["pubkey_id"], registry=tmp_registry)
    assert status == {"state": "unverifiable", "root_tier": None}
    assert agent_acceptance(vouched["pubkey_id"], registry=tmp_registry)["accept"] is False


# ---------------------------------------------------------------------------
# AC6 — verify-agent CLI exit codes
# ---------------------------------------------------------------------------


def test_verify_agent_cli_exit_0_for_anchored(tmp_registry, anchor_signer, agent_signer, pinned_anchor, monkeypatch, tmp_path):
    from zephyr import keymint

    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))
    agent_entry = _register_agent(tmp_registry, agent_signer)
    _vouch(tmp_registry, anchor_signer, agent_entry)

    rc = keymint.main(["verify-agent", "--agent-pkid", agent_entry["pubkey_id"]])
    assert rc == 0


def test_verify_agent_cli_exit_1_for_invalid(tmp_registry, anchor_signer, agent_signer, pinned_anchor, monkeypatch, tmp_path):
    from zephyr import keymint

    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))
    agent_entry = _register_agent(tmp_registry, agent_signer)
    tmp_registry.set_registered_by(
        agent_entry["pubkey_id"],
        {"signer_pkid": anchor_signer.pubkey_id_str, "signature": "ff" * 64},
    )

    rc = keymint.main(["verify-agent", "--agent-pkid", agent_entry["pubkey_id"]])
    assert rc == 1


def test_verify_agent_cli_exit_3_for_self_asserted(tmp_registry, agent_signer, monkeypatch, tmp_path):
    from zephyr import keymint

    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))
    agent_entry = _register_agent(tmp_registry, agent_signer)

    rc = keymint.main(["verify-agent", "--agent-pkid", agent_entry["pubkey_id"]])
    assert rc == 3


def test_verify_agent_cli_exit_4_for_unset_anchor(tmp_registry, anchor_signer, agent_signer, monkeypatch, tmp_path):
    import zephyr.registry
    from zephyr import keymint

    monkeypatch.delenv("ZEPHYR_HUMAN_ROOT_ANCHOR", raising=False)
    monkeypatch.setattr(zephyr.registry, "ZEPHYR_HUMAN_ROOT_ANCHOR", None)
    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))

    agent_entry = _register_agent(tmp_registry, agent_signer)
    target = agent_canonical_target(
        agent_entry["pubkey_id"],
        agent_entry["public_key_hex"],
        agent_entry["agent_id"],
        agent_entry.get("valid_from", ""),
    )
    sig = anchor_signer.sign(target)
    tmp_registry.set_registered_by(
        agent_entry["pubkey_id"],
        {"signer_pkid": anchor_signer.pubkey_id_str, "signature": sig},
    )

    rc = keymint.main(["verify-agent", "--agent-pkid", agent_entry["pubkey_id"]])
    assert rc == 4


def test_verify_agent_cli_exit_2_for_not_a_registered_agent(tmp_registry, monkeypatch, tmp_path):
    from zephyr import keymint

    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))
    rc = keymint.main(["verify-agent", "--agent-pkid", "ed25519:0000000000000000"])
    assert rc == 2


def test_verify_agent_cli_exit_2_for_wrong_role(tmp_registry, anchor_signer, pinned_anchor, monkeypatch, tmp_path):
    """A pkid that IS registered but not role='agent' (e.g. the human root itself)
    is a usage/lookup error (exit 2), not an anchor-state code."""
    from zephyr import keymint

    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))
    rc = keymint.main(["verify-agent", "--agent-pkid", anchor_signer.pubkey_id_str])
    assert rc == 2


def test_verify_agent_cli_emits_software_warning_on_stderr(tmp_registry, anchor_signer, agent_signer, pinned_anchor, monkeypatch, tmp_path, capsys):
    from zephyr import keymint

    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))
    agent_entry = _register_agent(tmp_registry, agent_signer)
    _vouch(tmp_registry, anchor_signer, agent_entry)

    rc = keymint.main(["verify-agent", "--agent-pkid", agent_entry["pubkey_id"]])
    assert rc == 0
    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert "software" in captured.err.lower()
    assert captured.out == ""


# ---------------------------------------------------------------------------
# AC9 — capture untouched: record_signed for an unvouched agent is unchanged
# ---------------------------------------------------------------------------


def test_capture_path_unchanged_for_self_asserted_agent(tmp_path, tmp_registry, agent_signer):
    log = AttributionLog(tmp_path / "attr.db")
    ts = "2026-07-22T00:00:00+00:00"
    result = record_signed(
        {"detail": "synthetic work"},
        agent_id="agent:capture-untouched",
        tool="test",
        signer=agent_signer,
        registry=tmp_registry,
        recorder=log,
        timestamp=ts,
    )
    assert result["newly_recorded"] is True

    entry = tmp_registry.lookup(agent_signer.pubkey_id_str)
    assert entry["role"] == "agent"
    assert entry.get("registered_by") is None

    status = agent_anchor_status(agent_signer.pubkey_id_str, registry=tmp_registry)
    assert status["state"] == "self_asserted"

    # Re-depositing identical bytes is still idempotent/no-op — capture untouched.
    result2 = record_signed(
        {"detail": "synthetic work"},
        agent_id="agent:capture-untouched",
        tool="test",
        signer=agent_signer,
        registry=tmp_registry,
        recorder=log,
        timestamp=ts,
    )
    assert result2["newly_recorded"] is False
    assert result2["manifest_hash"] == result["manifest_hash"]


# ---------------------------------------------------------------------------
# AC11 — agent_acceptance never raises, never mutates
# ---------------------------------------------------------------------------


def test_agent_acceptance_never_raises_for_missing_pkid(tmp_registry):
    verdict = agent_acceptance("ed25519:does-not-exist", registry=tmp_registry)
    assert verdict == {"accept": False, "state": "invalid", "root_tier": None, "reason": "invalid"}


def test_agent_acceptance_never_mutates_registry(tmp_registry, agent_signer, tmp_path):
    agent_entry = _register_agent(tmp_registry, agent_signer)
    before = (tmp_path / "keys" / f"{agent_entry['pubkey_id']}.json").read_text()

    agent_acceptance(agent_entry["pubkey_id"], registry=tmp_registry)

    after = (tmp_path / "keys" / f"{agent_entry['pubkey_id']}.json").read_text()
    assert before == after


def test_agent_acceptance_never_raises_for_malformed_entry(tmp_registry, tmp_path):
    # Hand-write a malformed entry (missing public_key_hex).
    bogus_pkid = "ed25519:malformed"
    (tmp_path / "keys").mkdir(parents=True, exist_ok=True)
    (tmp_path / "keys" / f"{bogus_pkid}.json").write_text(
        json.dumps({"pubkey_id": bogus_pkid, "role": "agent", "agent_id": "agent:bogus"})
    )
    verdict = agent_acceptance(bogus_pkid, registry=tmp_registry)
    assert verdict["accept"] is False


# ---------------------------------------------------------------------------
# AC12 — revoked agent reads as invalid, not self_asserted
# ---------------------------------------------------------------------------


def test_revoked_vouched_agent_reads_invalid_not_anchored(tmp_registry, anchor_signer, agent_signer, pinned_anchor):
    agent_entry = _register_agent(tmp_registry, agent_signer)
    vouched = _vouch(tmp_registry, anchor_signer, agent_entry)

    # Sanity: signature still verifies before revocation strips acceptance.
    trusted, _ = verify_agent_anchor_chain(vouched, registry=tmp_registry)
    assert trusted is True

    tmp_registry.revoke(vouched["pubkey_id"], reason="compromised")

    status = agent_anchor_status(vouched["pubkey_id"], registry=tmp_registry)
    assert status == {"state": "invalid", "root_tier": None}

    verdict = agent_acceptance(vouched["pubkey_id"], registry=tmp_registry)
    assert verdict["accept"] is False
    assert verdict["state"] == "invalid"
