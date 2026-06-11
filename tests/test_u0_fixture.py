"""Tests for U0 demo fixture setup.

DoD:
- Fixture script idempotent; produces valid WalletMap (one key intentionally absent)
- Source wallet funded (or configured)
- Env matrix emitted
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# Add fixtures to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from fixtures.setup_demo import (
    setup_demo,
    create_or_load_contributor_key,
    compute_pubkey_id,
)


class TestU0FixtureSetup:
    """U0 fixture setup tests."""

    def test_idempotent_key_generation(self, tmp_path):
        """Keys generated are deterministic when re-run."""
        keys_dir = tmp_path / "keys"

        # First run
        pubkey_id_1, _ = create_or_load_contributor_key("test_user", keys_dir)

        # Second run (should load, not regenerate)
        pubkey_id_2, _ = create_or_load_contributor_key("test_user", keys_dir)

        assert pubkey_id_1 == pubkey_id_2, "Idempotency failed: keys differ"
        assert keys_dir.exists(), "Keys directory not created"
        assert (keys_dir / "test_user.pem").exists(), "Key file not created"

    def test_wallet_map_generation(self, tmp_path):
        """WalletMap JSON is valid and contains correct entries."""
        keys_dir = tmp_path / "keys"
        wallet_map_path = tmp_path / "wallet_map.json"

        # Create fixture
        result = setup_demo(
            num_contributors=3,
            keys_dir=keys_dir,
            wallet_map_path=wallet_map_path,
        )

        # Verify wallet map file exists and is valid JSON
        assert wallet_map_path.exists(), "Wallet map file not created"
        with open(wallet_map_path) as f:
            wallet_map = json.load(f)

        # Verify contents
        contributors = result["contributors"]
        assert len(wallet_map) == 2, "WalletMap should have 2 entries (3rd excluded)"

        # First two contributors should be in wallet map
        for i in range(2):
            pubkey_id = contributors[i]["pubkey_id"]
            assert pubkey_id in wallet_map, f"Contributor {i} not in wallet map"
            assert wallet_map[pubkey_id].startswith(
                "https://wallet.interledger-test.dev/"
            ), "Wallet address format incorrect"

        # Third contributor (no_wallet=True) should NOT be in wallet map
        pubkey_id_3 = contributors[2]["pubkey_id"]
        assert (
            pubkey_id_3 not in wallet_map
        ), "Contributor 3 should not be in wallet map (no-route demo)"

    def test_one_contributor_without_wallet(self, tmp_path):
        """Last contributor deliberately has no wallet (no-route demo)."""
        keys_dir = tmp_path / "keys"
        wallet_map_path = tmp_path / "wallet_map.json"

        result = setup_demo(
            num_contributors=3,
            keys_dir=keys_dir,
            wallet_map_path=wallet_map_path,
        )

        contributors = result["contributors"]

        # Last contributor should have no_wallet=True
        assert contributors[-1]["no_wallet"] is True, "Last contributor should have no_wallet=True"

        # First two should have no_wallet=False
        for i in range(2):
            assert (
                contributors[i]["no_wallet"] is False
            ), f"Contributor {i} should have no_wallet=False"

    def test_env_matrix_emitted(self, tmp_path):
        """Environment matrix is emitted for demo script consumption."""
        keys_dir = tmp_path / "keys"
        wallet_map_path = tmp_path / "wallet_map.json"
        env_file = tmp_path / "demo.env"

        result = setup_demo(
            num_contributors=3,
            keys_dir=keys_dir,
            wallet_map_path=wallet_map_path,
            output_env_file=env_file,
        )

        # Verify env file was created
        assert env_file.exists(), "Env file not created"

        # Verify env file contains required variables
        env_content = env_file.read_text()
        required_vars = [
            "ZEPHYR_SETTLER_WALLET_MAP",
            "ZEPHYR_SETTLER_SOURCE_WALLET",
            "ZEPHYR_GNAP_ENDPOINT",
            "ZEPHYR_DEMO_KEYS_DIR",
            "ZEPHYR_DEMO_NUM_CONTRIBUTORS",
            "ZEPHYR_DEMO_CONTRIBUTORS",
            "ZEPHYR_DEMO_WALLET_MAP",
        ]
        for var in required_vars:
            assert var in env_content, f"Missing env var: {var}"

        # Verify env_vars dict in result
        env_vars = result["env_vars"]
        for var in required_vars:
            assert var in env_vars, f"Missing in result['env_vars']: {var}"

    def test_source_wallet_in_env(self, tmp_path):
        """Source wallet is configured in environment."""
        result = setup_demo(
            num_contributors=2,
            keys_dir=tmp_path / "keys",
            wallet_map_path=tmp_path / "wallet_map.json",
        )

        env_vars = result["env_vars"]

        # Source wallet should be set
        assert "ZEPHYR_SETTLER_SOURCE_WALLET" in env_vars
        source_wallet = env_vars["ZEPHYR_SETTLER_SOURCE_WALLET"]
        assert source_wallet.startswith("https://"), "Source wallet should be HTTPS URL"

    def test_pubkey_id_format(self, tmp_path):
        """PubKey IDs follow content-addressed format (ed25519:<16hex>)."""
        result = setup_demo(
            num_contributors=2,
            keys_dir=tmp_path / "keys",
            wallet_map_path=tmp_path / "wallet_map.json",
        )

        for contrib in result["contributors"]:
            pubkey_id = contrib["pubkey_id"]

            # Format check: ed25519:<16 hex chars>
            assert pubkey_id.startswith("ed25519:"), f"Invalid format: {pubkey_id}"
            hex_part = pubkey_id.split(":")[1]
            assert len(hex_part) == 16, f"Hex part should be 16 chars: {pubkey_id}"
            int(hex_part, 16)  # Verify it's valid hex

    def test_multiple_contributors(self, tmp_path):
        """Can generate multiple contributors."""
        result = setup_demo(num_contributors=5, keys_dir=tmp_path / "keys")

        contributors = result["contributors"]
        assert len(contributors) == 5, "Should create 5 contributors"

        # Last one has no wallet
        assert contributors[-1]["no_wallet"] is True

        # Others have wallets
        for i in range(4):
            assert contributors[i]["no_wallet"] is False

    def test_idempotent_full_setup(self, tmp_path):
        """Full setup is idempotent - same result on re-run."""
        keys_dir = tmp_path / "keys"
        wallet_map_path = tmp_path / "wallet_map.json"

        # First run
        result1 = setup_demo(
            num_contributors=3,
            keys_dir=keys_dir,
            wallet_map_path=wallet_map_path,
        )
        pubkey_ids_1 = [c["pubkey_id"] for c in result1["contributors"]]

        # Second run (should be identical)
        result2 = setup_demo(
            num_contributors=3,
            keys_dir=keys_dir,
            wallet_map_path=wallet_map_path,
        )
        pubkey_ids_2 = [c["pubkey_id"] for c in result2["contributors"]]

        assert pubkey_ids_1 == pubkey_ids_2, "Pubkey IDs should match on re-run"
        assert (
            result1["wallet_map"] == result2["wallet_map"]
        ), "Wallet maps should match"
