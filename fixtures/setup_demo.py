#!/usr/bin/env python3
"""U0 Demo Fixture Setup - idempotent contributor key and wallet setup.

Creates N synthetic contributor keys and wallet routing hints for the
zephyr-openpayments-settle-v0 demo. One contributor deliberately has no
wallet to demonstrate the no-route case + undiminished attribution.

Output: writes WalletMap JSON and emits environment variables for demo script.

Usage:
  python fixtures/setup_demo.py [--num-contributors N] [--output-env FILE]

Idempotency: safe to re-run; skips existing keys and wallet maps.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shlex
import sys
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Add parent dir to path for zephyr imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from zephyr.signing import pubkey_id as compute_pubkey_id
from zephyr.registry import PubkeyRegistry

log = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


# ============================================================================
# Paths and Defaults
# ============================================================================

DEMO_KEYS_DIR = Path(__file__).parent.parent / ".demo-keys"
WALLET_MAP_PATH = Path(
    os.environ.get("ZEPHYR_SETTLER_WALLET_MAP", "/data/zephyr/wallet_map.json")
)

# Interledger testnet wallets (format: https://wallet.interledger-test.dev/<account>)
# Source wallet (funded settlement-pool account)
DEFAULT_SOURCE_WALLET = "https://wallet.interledger-test.dev/zephyr-settler-source"

# Interledger testnet GNAP endpoint
DEFAULT_GNAP_ENDPOINT = "https://auth.interledger-test.dev"


# ============================================================================
# Key Generation and Content-Addressing
# ============================================================================


def generate_ed25519_key() -> tuple[Ed25519PrivateKey, bytes]:
    """Generate a new Ed25519 key pair.

    Returns (private_key, public_key_bytes).
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_bytes


def serialize_private_key(private_key: Ed25519PrivateKey) -> bytes:
    """Serialize a private key to PEM/PKCS8 format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ============================================================================
# Contributor Setup
# ============================================================================


def create_or_load_contributor_key(
    contributor_name: str, keys_dir: Path = DEMO_KEYS_DIR
) -> tuple[str, bytes]:
    """Create or load a contributor's Ed25519 key.

    Returns (pubkey_id, public_key_bytes).
    Idempotent: re-running returns the same key.
    """
    keys_dir.mkdir(parents=True, exist_ok=True)
    key_path = keys_dir / f"{contributor_name}.pem"

    if key_path.exists():
        # Load existing key
        pem_bytes = key_path.read_bytes()
        key = serialization.load_pem_private_key(pem_bytes, password=None)
        public_key = key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        log.info("Loaded existing key for %s", contributor_name)
    else:
        # Generate new key
        private_key, public_bytes = generate_ed25519_key()
        pem = serialize_private_key(private_key)
        key_path.write_bytes(pem)
        key_path.chmod(0o600)
        log.info("Generated new key for %s at %s", contributor_name, key_path)

    pubkey_id = compute_pubkey_id(public_bytes)
    return pubkey_id, public_bytes


# ============================================================================
# Wallet Map Setup
# ============================================================================


def create_wallet_map(
    contributors: list[dict], wallet_map_path: Path = WALLET_MAP_PATH
) -> dict:
    """Create wallet map JSON (idempotent).

    Includes entries for all contributors except those with 'no_wallet=True',
    demonstrating the no-route case.

    Args:
        contributors: List of {name, pubkey_id, no_wallet (optional)}.
        wallet_map_path: Output path for wallet_map.json.

    Returns the wallet map dict.
    """
    wallet_map_path.parent.mkdir(parents=True, exist_ok=True)

    wallet_map = {}
    for contrib in contributors:
        if contrib.get("no_wallet", False):
            log.info(
                "Skipping wallet for %s (intentionally has no route)",
                contrib["name"],
            )
            continue

        pubkey_id = contrib["pubkey_id"]
        # Use Interledger testnet wallet URL format
        wallet_address = f"https://wallet.interledger-test.dev/{contrib['name'].lower()}"
        wallet_map[pubkey_id] = wallet_address
        log.info(
            "Mapped %s → %s",
            pubkey_id,
            wallet_address,
        )

    # Write wallet map (idempotent)
    wallet_map_path.write_text(json.dumps(wallet_map, indent=2))
    log.info("Wrote wallet map to %s", wallet_map_path)

    return wallet_map


# ============================================================================
# Pubkey Registry Setup
# ============================================================================


def register_contributor_keys(
    contributors: list[dict],
    keys_dir: Path = DEMO_KEYS_DIR,
    registry_dir: Path | None = None,
) -> None:
    """Register each contributor's public key in the registry.

    Each contributor key is registered as role="agent" with the matching
    agent_id from the contributors list. This allows signed deposits to pass
    the registry check in AttributionLog.record().

    Args:
        contributors: List of contributor dicts with name, pubkey_id, etc.
        keys_dir: Directory where PEM files are stored.
        registry_dir: Directory for the pubkey registry. If None, uses the
            environment variable ZEPHYR_KEYS_DIR or the default.
    """
    if registry_dir is None:
        registry = PubkeyRegistry()
    else:
        registry = PubkeyRegistry(registry_dir)

    for contrib in contributors:
        pubkey_id = contrib["pubkey_id"]
        name = contrib["name"]
        agent_id = f"agent:{name}"

        # Load the public key bytes from the private key
        key_file = keys_dir / f"{name}.pem"
        if not key_file.exists():
            log.warning("Cannot register %s: key file not found at %s", name, key_file)
            continue

        pem_bytes = key_file.read_bytes()
        key = serialization.load_pem_private_key(pem_bytes, password=None)
        public_key = key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        public_hex = public_bytes.hex()

        # Register the key
        registry.register(
            pubkey_id,
            public_hex,
            agent_id,
            role="agent",
            note=f"Demo contributor {name}",
        )
        log.info("Registered %s (agent_id=%s)", pubkey_id, agent_id)


# ============================================================================
# Demo Setup Orchestration
# ============================================================================


def setup_demo(
    num_contributors: int = 3,
    output_env_file: Optional[Path] = None,
    keys_dir: Path = DEMO_KEYS_DIR,
    wallet_map_path: Path = WALLET_MAP_PATH,
    registry_dir: Optional[Path] = None,
) -> dict:
    """Orchestrate U0 demo setup.

    Creates N contributor keys (idempotent), one without wallet (no-route demo).
    Writes wallet map and returns environment matrix.

    Args:
        num_contributors: Number of synthetic contributors to create.
        output_env_file: Optional path to write environment variables.
        keys_dir: Directory for PEM key files.
        wallet_map_path: Path for wallet_map.json output.
        registry_dir: Optional directory for pubkey registry. If None, uses
            environment variable ZEPHYR_KEYS_DIR or the default.

    Returns:
        Dict with keys: contributors, wallet_map, env_vars.
    """
    log.info("=== U0 Demo Setup ===")
    log.info("Creating %d contributor keys", num_contributors)

    # Create contributor keys
    contributors = []
    for i in range(num_contributors):
        name = f"contributor_{i+1:02d}"
        pubkey_id, public_bytes = create_or_load_contributor_key(name, keys_dir)
        # Last contributor has no wallet (demonstrates no-route)
        no_wallet = i == num_contributors - 1
        contrib = {"name": name, "pubkey_id": pubkey_id, "no_wallet": no_wallet}
        contributors.append(contrib)
        log.info(
            "  %s: %s (no_wallet=%s)",
            name,
            pubkey_id,
            no_wallet,
        )

    # Create wallet map
    wallet_map = create_wallet_map(contributors, wallet_map_path)

    # Register contributor keys in the pubkey registry
    register_contributor_keys(contributors, keys_dir, registry_dir)

    # Construct environment matrix for demo script
    env_vars = {
        "ZEPHYR_SETTLER_WALLET_MAP": str(wallet_map_path),
        "ZEPHYR_SETTLER_SOURCE_WALLET": DEFAULT_SOURCE_WALLET,
        "ZEPHYR_GNAP_ENDPOINT": DEFAULT_GNAP_ENDPOINT,
        "ZEPHYR_DEMO_KEYS_DIR": str(keys_dir),
        "ZEPHYR_DEMO_NUM_CONTRIBUTORS": str(num_contributors),
        # JSON-encoded lists for demo script to consume
        "ZEPHYR_DEMO_CONTRIBUTORS": json.dumps(contributors),
        "ZEPHYR_DEMO_WALLET_MAP": json.dumps(wallet_map),
    }

    # Write env file if requested
    if output_env_file:
        output_env_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_env_file, "w") as f:
            for key, value in env_vars.items():
                f.write(f"export {key}={shlex.quote(value)}\n")
        log.info("Wrote environment matrix to %s", output_env_file)

    return {
        "contributors": contributors,
        "wallet_map": wallet_map,
        "env_vars": env_vars,
    }


# ============================================================================
# CLI
# ============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="U0 demo fixture setup: create contributor keys and wallet map"
    )
    parser.add_argument(
        "--num-contributors",
        type=int,
        default=3,
        help="Number of synthetic contributors to create (default: 3)",
    )
    parser.add_argument(
        "--output-env",
        type=Path,
        default=None,
        help="Write environment variables to this file (optional)",
    )
    parser.add_argument(
        "--keys-dir",
        type=Path,
        default=DEMO_KEYS_DIR,
        help=f"Directory for demo keys (default: {DEMO_KEYS_DIR})",
    )
    parser.add_argument(
        "--wallet-map",
        type=Path,
        default=WALLET_MAP_PATH,
        help=f"Wallet map output path (default: {WALLET_MAP_PATH})",
    )
    parser.add_argument(
        "--json-output",
        action="store_true",
        help="Output result as JSON to stdout (for programmatic use)",
    )

    args = parser.parse_args()

    result = setup_demo(
        num_contributors=args.num_contributors,
        output_env_file=args.output_env,
        keys_dir=args.keys_dir,
        wallet_map_path=args.wallet_map,
    )

    if args.json_output:
        # Output structured result as JSON
        print(json.dumps(result, indent=2))
    else:
        # Print summary
        print(f"\n✓ U0 Demo Setup Complete")
        print(f"  Contributors: {args.num_contributors}")
        print(f"    - Last contributor ({result['contributors'][-1]['name']}) has no wallet (no-route demo)")
        print(f"  Wallet map: {args.wallet_map}")
        print(f"  Keys dir: {args.keys_dir}")
        if args.output_env:
            print(f"  Env file: {args.output_env}")
        print(f"\nEnvironment variables:")
        for key in [
            "ZEPHYR_SETTLER_WALLET_MAP",
            "ZEPHYR_SETTLER_SOURCE_WALLET",
            "ZEPHYR_GNAP_ENDPOINT",
            "ZEPHYR_DEMO_KEYS_DIR",
        ]:
            print(f"  {key}={result['env_vars'][key]}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
