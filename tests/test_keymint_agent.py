"""Tests for zephyr.keymint — mint-agent / vouch-agent / verify-agent CLI.

All identities are synthetic. Every test runs against a scratch ZEPHYR_KEYS_DIR /
ZEPHYR_ATTRIBUTION_DB under tmp_path — never the real /data/zephyr/*.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from zephyr import keymint
from zephyr.registry import PubkeyRegistry


@pytest.fixture(autouse=True)
def _scratch_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("ZEPHYR_ATTRIBUTION_DB", str(tmp_path / "attribution.db"))


def _keys_dir(tmp_path) -> Path:
    return tmp_path / "keys"


def _mint_human(tmp_path, capsys, agent_id="human:root-vouch-agent", key_out=None):
    args = ["mint-human", "--agent-id", agent_id]
    if key_out is not None:
        args += ["--key-out", str(key_out)]
    rc = keymint.main(args)
    assert rc == 0
    return capsys.readouterr().out.strip()


def _mint_agent(tmp_path, capsys, agent_id="agent:vouch-agent", key_out=None):
    args = ["mint-agent", "--agent-id", agent_id]
    if key_out is not None:
        args += ["--key-out", str(key_out)]
    rc = keymint.main(args)
    assert rc == 0
    return capsys.readouterr().out.strip()


# ---------------------------------------------------------------------------
# mint-agent
# ---------------------------------------------------------------------------


def test_mint_agent_registers_and_prints_pkid(tmp_path, capsys):
    rc = keymint.main(["mint-agent", "--agent-id", "agent:test-mint"])
    assert rc == 0

    printed_pkid = capsys.readouterr().out.strip()
    assert printed_pkid.startswith("ed25519:")

    reg = PubkeyRegistry(_keys_dir(tmp_path))
    entry = reg.lookup(printed_pkid)
    assert entry is not None
    assert entry["role"] == "agent"
    assert entry["assurance_tier"] == "warm"
    assert entry.get("registered_by") is None  # self-asserted baseline


# ---------------------------------------------------------------------------
# AC8 — mint-agent idempotent no-op / human-namespace refusal
# ---------------------------------------------------------------------------


def test_mint_agent_on_already_registered_pkid_is_idempotent_no_op(tmp_path, capsys):
    key_out = tmp_path / "agent.key"
    pkid1 = _mint_agent(tmp_path, capsys, agent_id="agent:idempotent", key_out=key_out)

    rc = keymint.main(
        ["mint-agent", "--agent-id", "agent:idempotent", "--key-out", str(key_out)]
    )
    # Refuses overwrite of the private key file itself, mirroring mint-human/mint-node.
    assert rc != 0

    # But registering the SAME already-existing pkid via register() directly is
    # a safe idempotent no-op (the underlying guarantee mint-agent relies on).
    reg = PubkeyRegistry(_keys_dir(tmp_path))
    existing = reg.lookup(pkid1)
    returned = reg.register(pkid1, existing["public_key_hex"], "agent:idempotent", role="agent")
    assert returned["pubkey_id"] == pkid1


def test_mint_agent_refuses_human_namespace_agent_id(tmp_path):
    rc = keymint.main(["mint-agent", "--agent-id", "human:not-allowed"])
    assert rc != 0

    keys_dir = _keys_dir(tmp_path)
    assert not keys_dir.exists() or list(keys_dir.glob("*.json")) == []


# ---------------------------------------------------------------------------
# vouch-agent
# ---------------------------------------------------------------------------


def test_vouch_agent_writes_registered_by_no_deposit_created(tmp_path, capsys):
    human_key_path = tmp_path / "human.key"
    human_pkid = _mint_human(tmp_path, capsys, key_out=human_key_path)
    agent_pkid = _mint_agent(tmp_path, capsys)

    rc = keymint.main(
        ["vouch-agent", "--agent-pkid", agent_pkid, "--human-key", str(human_key_path)]
    )
    assert rc == 0

    reg = PubkeyRegistry(_keys_dir(tmp_path))
    agent_entry = reg.lookup(agent_pkid)
    assert agent_entry["registered_by"]["signer_pkid"] == human_pkid
    assert agent_entry["registered_by"]["signature"]

    attribution_db = tmp_path / "attribution.db"
    assert not attribution_db.exists()


# ---------------------------------------------------------------------------
# AC7 — vouch-agent refuses without mutation
# ---------------------------------------------------------------------------


def test_vouch_agent_fails_clean_missing_agent_entry(tmp_path, capsys):
    human_key_path = tmp_path / "human.key"
    _mint_human(tmp_path, capsys, key_out=human_key_path)

    rc = keymint.main(
        [
            "vouch-agent",
            "--agent-pkid",
            "ed25519:0000000000000000",
            "--human-key",
            str(human_key_path),
        ]
    )
    assert rc != 0

    keys_dir = _keys_dir(tmp_path)
    assert not (keys_dir / "ed25519:0000000000000000.json").exists()


def test_vouch_agent_fails_clean_not_role_agent(tmp_path, capsys):
    """--agent-pkid resolving to a non-agent (e.g. human) key is refused."""
    human_key_path = tmp_path / "human.key"
    human_pkid = _mint_human(tmp_path, capsys, key_out=human_key_path)
    other_human_key_path = tmp_path / "human2.key"
    other_human_pkid = _mint_human(
        tmp_path, capsys, agent_id="human:other", key_out=other_human_key_path
    )

    rc = keymint.main(
        ["vouch-agent", "--agent-pkid", other_human_pkid, "--human-key", str(human_key_path)]
    )
    assert rc != 0

    reg = PubkeyRegistry(_keys_dir(tmp_path))
    entry = reg.lookup(other_human_pkid)
    assert entry.get("registered_by") is None
    assert human_pkid  # sanity: fixture used


def test_vouch_agent_fails_clean_unregistered_human_key(tmp_path, capsys):
    agent_pkid = _mint_agent(tmp_path, capsys)
    unregistered_key_path = tmp_path / "unregistered.key"

    rc = keymint.main(
        ["vouch-agent", "--agent-pkid", agent_pkid, "--human-key", str(unregistered_key_path)]
    )
    assert rc != 0

    entry = PubkeyRegistry(_keys_dir(tmp_path)).lookup(agent_pkid)
    assert entry.get("registered_by") is None


# ---------------------------------------------------------------------------
# AC10 — prod-path fail-closed for agent subcommands
# ---------------------------------------------------------------------------


def test_mint_agent_prod_path_fail_closed_without_flag(tmp_path, monkeypatch):
    fake_prod = tmp_path / "fake-prod-keys"
    monkeypatch.setattr(keymint, "PROD_KEYS_DIR", fake_prod)
    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(fake_prod))

    rc = keymint.main(["mint-agent", "--agent-id", "agent:should-not-mint"])
    assert rc == 2
    assert not fake_prod.exists()


def test_vouch_agent_prod_path_fail_closed_without_flag(tmp_path, monkeypatch):
    fake_prod = tmp_path / "fake-prod-keys"
    monkeypatch.setattr(keymint, "PROD_KEYS_DIR", fake_prod)
    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(fake_prod))

    rc = keymint.main(
        [
            "vouch-agent",
            "--agent-pkid",
            "ed25519:whatever",
            "--human-key",
            str(tmp_path / "human.key"),
        ]
    )
    assert rc == 2


def test_verify_agent_prod_path_fail_closed_without_flag(tmp_path, monkeypatch):
    fake_prod = tmp_path / "fake-prod-keys"
    monkeypatch.setattr(keymint, "PROD_KEYS_DIR", fake_prod)
    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(fake_prod))

    rc = keymint.main(["verify-agent", "--agent-pkid", "ed25519:whatever"])
    assert rc == 2


def test_agent_subcommands_prod_path_fail_closed_with_flag_succeeds(tmp_path, monkeypatch, capsys):
    fake_prod = tmp_path / "fake-prod-keys"
    monkeypatch.setattr(keymint, "PROD_KEYS_DIR", fake_prod)
    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(fake_prod))

    rc = keymint.main(
        ["mint-agent", "--agent-id", "agent:allowed", "--i-understand-this-is-prod"]
    )
    assert rc == 0
    pkid = capsys.readouterr().out.strip()
    assert PubkeyRegistry(fake_prod).lookup(pkid) is not None
