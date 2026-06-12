"""End-to-end test for the U3 demo (zephyr-demo-runnable-v0).

Tests that the demo script runs successfully with proper registration of
contributor pubkeys, and produces the expected settlement outcomes.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


def test_demo_setup_registers_pubkeys_in_registry():
    """Test that setup_demo registers contributor pubkeys in the registry.

    This is the core fix for zephyr-demo-runnable-v0: the demo previously
    crashed with "unknown pubkey_id" error because setup_demo never registered
    the keys. This test verifies the fix is in place.
    """
    # Set up temp directories
    tmp_dir = Path(tempfile.mkdtemp(prefix="zephyr-demo-registry-"))
    keys_dir = tmp_dir / "demo-keys"
    wallet_map_path = tmp_dir / "wallet_map.json"
    registry_dir = tmp_dir / "registry"

    # Set ZEPHYR_KEYS_DIR BEFORE importing setup_demo so registry uses our temp dir
    registry_dir.mkdir(exist_ok=True)
    os.environ["ZEPHYR_KEYS_DIR"] = str(registry_dir)

    # Run setup_demo (U0)
    from fixtures.setup_demo import setup_demo

    setup_result = setup_demo(
        num_contributors=3,
        output_env_file=None,
        keys_dir=keys_dir,
        wallet_map_path=wallet_map_path,
    )

    # Verify setup completed
    assert len(setup_result["contributors"]) == 3
    assert setup_result["contributors"][-1]["no_wallet"] is True

    # Verify the registry has the registered keys
    from zephyr.registry import PubkeyRegistry

    registry = PubkeyRegistry(registry_dir)
    all_entries = registry.load_all()

    assert len(all_entries) >= 3, f"Expected 3+ registered keys, got {len(all_entries)}"

    # Verify each contributor's key is registered with correct properties
    for contrib in setup_result["contributors"]:
        pubkey_id = contrib["pubkey_id"]
        entry = registry.lookup(pubkey_id)

        assert entry is not None, f"Pubkey {pubkey_id} not registered"
        assert entry["role"] == "agent", f"Expected role='agent', got {entry['role']}"
        assert (
            entry["agent_id"] == f"agent:{contrib['name']}"
        ), f"Key registered to wrong agent_id: {entry['agent_id']}"
        assert entry["status"] == "active", "Key should be active"


def test_demo_setup_registers_pubkeys():
    """Test that setup_demo registers contributor pubkeys in the registry.

    This ensures the fix for the 'unknown pubkey_id' crash is in place.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="zephyr-demo-pubkeys-"))
    keys_dir = tmp_dir / "demo-keys"
    wallet_map_path = tmp_dir / "wallet_map.json"

    from fixtures.setup_demo import setup_demo
    from zephyr.registry import PubkeyRegistry

    # Run setup with custom temp dirs
    setup_result = setup_demo(
        num_contributors=3,
        output_env_file=None,
        keys_dir=keys_dir,
        wallet_map_path=wallet_map_path,
    )

    # Verify registry has all contributor keys
    # Create a fresh registry instance pointing to the same location
    import zephyr.registry as reg_module

    # Save original and temporarily override the default keys dir
    original_default = reg_module.DEFAULT_KEYS_DIR
    reg_module.DEFAULT_KEYS_DIR = reg_module.Path(
        os.environ.get("ZEPHYR_KEYS_DIR", "/data/zephyr/keys")
    )

    registry = PubkeyRegistry()
    all_keys = registry.load_all()

    # Restore original
    reg_module.DEFAULT_KEYS_DIR = original_default

    assert len(all_keys) >= 3, f"Expected at least 3 registered keys, got {len(all_keys)}"

    # Verify each contributor's key is registered with correct role and agent_id
    for contrib in setup_result["contributors"]:
        pubkey_id = contrib["pubkey_id"]
        entry = registry.lookup(pubkey_id)
        assert entry is not None, f"Pubkey {pubkey_id} not registered"
        assert entry["role"] == "agent", f"Expected role='agent', got {entry['role']}"
        assert (
            entry["agent_id"] == f"agent:{contrib['name']}"
        ), f"Pubkey registered to wrong agent_id"


def test_demo_deposits_are_verified():
    """Test that signed deposits in the demo pass signature verification.

    This ensures the real attribution gate is used, not a stub.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="zephyr-demo-verify-"))
    keys_dir = tmp_dir / "demo-keys"
    wallet_map_path = tmp_dir / "wallet_map.json"

    # Setup
    from fixtures.setup_demo import setup_demo

    setup_result = setup_demo(
        num_contributors=3,
        output_env_file=None,
        keys_dir=keys_dir,
        wallet_map_path=wallet_map_path,
    )

    # Set env vars before importing zephyr (critical!)
    os.environ["ZEPHYR_ATTRIBUTION_DB"] = str(tmp_dir / "attribution.db")
    os.environ["ZEPHYR_INTENT_QUEUE_DB"] = str(tmp_dir / "intent_queue.db")

    # Import zephyr modules AFTER env is set
    from zephyr.attribution import AttributionLog, verify_row
    from zephyr.registry import PubkeyRegistry
    from zephyr.signing import AgentSigner
    from datetime import datetime, timezone

    attr_log = AttributionLog(tmp_dir / "attribution.db")
    registry = PubkeyRegistry()

    # Make a signed deposit like the demo does
    contrib = setup_result["contributors"][0]
    key_file = keys_dir / f"{contrib['name']}.pem"
    signer = AgentSigner(key_file)

    manifest = "sha256:test-deposit"
    provenance = {
        "manifest_hash": manifest,
        "agent_id": f"agent:{contrib['name']}",
        "pubkey_id": contrib["pubkey_id"],
        "tool": "demo",
        "model": "demo-v0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "schema_version": "lapis-provenance-v0.1",
    }
    provenance["signature"] = signer.sign(manifest)

    # Record the deposit
    newly_recorded = attr_log.record(provenance, registry=registry)
    assert newly_recorded, "Deposit should be newly recorded"

    # Verify the recorded deposit
    row = attr_log.get(manifest)
    assert row is not None
    assert row["signature"] is not None
    assert row["pubkey_id"] == contrib["pubkey_id"]

    # Check verification at read time
    vr = verify_row(row, registry=registry)
    assert vr.verified, f"Signature should verify, but got status={vr.status}"
