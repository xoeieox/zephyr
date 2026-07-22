"""Tests for zephyr.keymint — mint-human / mint-node / vouch-node CLI.

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
    """DoD-8: every test runs against a scratch keyring/db under tmp_path."""
    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("ZEPHYR_ATTRIBUTION_DB", str(tmp_path / "attribution.db"))


def _keys_dir(tmp_path) -> Path:
    return tmp_path / "keys"


# ---------------------------------------------------------------------------
# DoD-1 — mint-human
# ---------------------------------------------------------------------------


def test_mint_human_registers_candidate_and_prints_pkid(tmp_path, capsys):
    rc = keymint.main(["mint-human", "--agent-id", "human:test-root"])
    assert rc == 0

    printed_pkid = capsys.readouterr().out.strip()
    assert printed_pkid.startswith("ed25519:")

    reg = PubkeyRegistry(_keys_dir(tmp_path))
    entry = reg.lookup(printed_pkid)
    assert entry is not None
    assert entry["role"] == "human"
    assert entry["assurance_tier"] == "software"


def test_mint_human_never_self_pins_anchor(tmp_path, monkeypatch, capsys):
    """The CLI never writes ZEPHYR_HUMAN_ROOT_ANCHOR — pinning is a deliberate
    separate operator act."""
    import zephyr.registry

    monkeypatch.delenv("ZEPHYR_HUMAN_ROOT_ANCHOR", raising=False)
    monkeypatch.setattr(zephyr.registry, "ZEPHYR_HUMAN_ROOT_ANCHOR", None)

    rc = keymint.main(["mint-human", "--agent-id", "human:test-root2"])
    assert rc == 0

    assert zephyr.registry.ZEPHYR_HUMAN_ROOT_ANCHOR is None
    pkid = capsys.readouterr().out.strip()
    entry = PubkeyRegistry(_keys_dir(tmp_path)).lookup(pkid)
    assert entry.get("registered_by") is None


def test_mint_human_refuses_overwrite(tmp_path):
    rc1 = keymint.main(["mint-human", "--agent-id", "human:dup", "--key-out", str(tmp_path / "dup.key")])
    assert rc1 == 0

    rc2 = keymint.main(["mint-human", "--agent-id", "human:dup", "--key-out", str(tmp_path / "dup.key")])
    assert rc2 != 0


# ---------------------------------------------------------------------------
# DoD-2 — mint-node
# ---------------------------------------------------------------------------


def test_mint_node_registers_with_binding(tmp_path, capsys):
    rc = keymint.main(
        [
            "mint-node",
            "--agent-id",
            "agent:test-node",
            "--node",
            "macbook",
            "--hostname",
            "macbook.local",
            "--tailscale-ip",
            "100.100.1.2",
        ]
    )
    assert rc == 0
    pkid = capsys.readouterr().out.strip()

    reg = PubkeyRegistry(_keys_dir(tmp_path))
    entry = reg.lookup(pkid)
    assert entry["role"] == "node"
    assert entry["node_binding"] == {
        "node": "macbook",
        "hostname": "macbook.local",
        "tailscale_ip": "100.100.1.2",
    }
    assert entry.get("registered_by") is None  # self-asserted baseline


# ---------------------------------------------------------------------------
# DoD-3 — vouch-node
# ---------------------------------------------------------------------------


def _mint_human(tmp_path, capsys, agent_id="human:root-vouch", key_out=None):
    args = ["mint-human", "--agent-id", agent_id]
    if key_out is not None:
        args += ["--key-out", str(key_out)]
    rc = keymint.main(args)
    assert rc == 0
    return capsys.readouterr().out.strip()


def _mint_node(tmp_path, capsys, agent_id="agent:vouch-node"):
    rc = keymint.main(
        [
            "mint-node",
            "--agent-id",
            agent_id,
            "--node",
            "macbook",
            "--hostname",
            "macbook.local",
            "--tailscale-ip",
            "100.100.1.5",
        ]
    )
    assert rc == 0
    return capsys.readouterr().out.strip()


def test_vouch_node_writes_registered_by_no_deposit_created(tmp_path, capsys):
    human_key_path = tmp_path / "human.key"
    human_pkid = _mint_human(tmp_path, capsys, key_out=human_key_path)
    node_pkid = _mint_node(tmp_path, capsys)

    rc = keymint.main(
        ["vouch-node", "--node-pkid", node_pkid, "--human-key", str(human_key_path)]
    )
    assert rc == 0

    reg = PubkeyRegistry(_keys_dir(tmp_path))
    node_entry = reg.lookup(node_pkid)
    assert node_entry["registered_by"]["signer_pkid"] == human_pkid
    assert node_entry["registered_by"]["signature"]

    attribution_db = tmp_path / "attribution.db"
    assert not attribution_db.exists()


def test_vouch_node_fails_clean_missing_node_entry(tmp_path, capsys):
    human_key_path = tmp_path / "human.key"
    _mint_human(tmp_path, capsys, key_out=human_key_path)

    rc = keymint.main(
        [
            "vouch-node",
            "--node-pkid",
            "ed25519:0000000000000000",
            "--human-key",
            str(human_key_path),
        ]
    )
    assert rc != 0

    # writes nothing
    keys_dir = _keys_dir(tmp_path)
    assert not (keys_dir / "ed25519:0000000000000000.json").exists()


def test_vouch_node_fails_clean_malformed_node_binding(tmp_path, capsys):
    human_key_path = tmp_path / "human.key"
    _mint_human(tmp_path, capsys, key_out=human_key_path)

    # Hand-write a malformed node entry (node_binding missing a field)
    reg = PubkeyRegistry(_keys_dir(tmp_path))
    from zephyr.signing import AgentSigner

    node_signer = AgentSigner(tmp_path / "node.key")
    node_pkid = node_signer.pubkey_id_str
    reg.register(
        node_pkid,
        node_signer.public_key_bytes.hex(),
        "agent:malformed-node",
        role="node",
        node_binding={"node": "x", "hostname": "", "tailscale_ip": "1.2.3.4"},
    )

    rc = keymint.main(
        ["vouch-node", "--node-pkid", node_pkid, "--human-key", str(human_key_path)]
    )
    assert rc != 0

    entry = reg.lookup(node_pkid)
    assert entry.get("registered_by") is None


def test_vouch_node_fails_clean_unregistered_human_key(tmp_path, capsys):
    node_pkid = _mint_node(tmp_path, capsys)
    unregistered_key_path = tmp_path / "unregistered.key"

    rc = keymint.main(
        ["vouch-node", "--node-pkid", node_pkid, "--human-key", str(unregistered_key_path)]
    )
    assert rc != 0

    entry = PubkeyRegistry(_keys_dir(tmp_path)).lookup(node_pkid)
    assert entry.get("registered_by") is None


# ---------------------------------------------------------------------------
# DoD-10 — prod-path fail-closed
# ---------------------------------------------------------------------------


def test_prod_path_fail_closed_without_flag(tmp_path, monkeypatch):
    fake_prod = tmp_path / "fake-prod-keys"
    monkeypatch.setattr(keymint, "PROD_KEYS_DIR", fake_prod)
    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(fake_prod))

    rc = keymint.main(["mint-human", "--agent-id", "human:should-not-mint"])
    assert rc != 0
    assert not fake_prod.exists()


def test_prod_path_fail_closed_with_flag_succeeds(tmp_path, monkeypatch, capsys):
    fake_prod = tmp_path / "fake-prod-keys"
    monkeypatch.setattr(keymint, "PROD_KEYS_DIR", fake_prod)
    monkeypatch.setenv("ZEPHYR_KEYS_DIR", str(fake_prod))

    rc = keymint.main(
        ["mint-human", "--agent-id", "human:allowed", "--i-understand-this-is-prod"]
    )
    assert rc == 0
    pkid = capsys.readouterr().out.strip()
    assert PubkeyRegistry(fake_prod).lookup(pkid) is not None


# ---------------------------------------------------------------------------
# DoD-8 — no real prod path is ever opened for write
# ---------------------------------------------------------------------------


def test_no_prod_touch_guard(tmp_path, monkeypatch, capsys):
    """A full mint-human/mint-node/vouch-node/verify-node run never opens a
    real production path for write."""
    import os as os_module

    prod_prefixes = (
        str(keymint.PROD_KEYS_DIR),
        str(keymint.PROD_ATTRIBUTION_DB),
        str(keymint.PROD_AGENT_KEYS_DIR),
    )

    real_write_text = Path.write_text
    real_os_open = os_module.open

    def guarded_write_text(self, *a, **kw):
        assert not str(self).startswith(prod_prefixes), f"attempted prod write: {self}"
        return real_write_text(self, *a, **kw)

    def guarded_os_open(path, *a, **kw):
        assert not str(path).startswith(prod_prefixes), f"attempted prod open: {path}"
        return real_os_open(path, *a, **kw)

    monkeypatch.setattr(Path, "write_text", guarded_write_text)
    monkeypatch.setattr(os_module, "open", guarded_os_open)

    human_key_path = tmp_path / "human.key"
    human_pkid = _mint_human(tmp_path, capsys, key_out=human_key_path)
    node_pkid = _mint_node(tmp_path, capsys)
    rc = keymint.main(
        ["vouch-node", "--node-pkid", node_pkid, "--human-key", str(human_key_path)]
    )
    assert rc == 0
    keymint.main(["verify-node", "--node-pkid", node_pkid])
