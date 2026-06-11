"""WalletMap - optional routing hints from pubkey_id to wallet address.

Format: JSON file with {pubkey_id → wallet address} mapping.
Location: $ZEPHYR_SETTLER_WALLET_MAP (default: /data/zephyr/wallet_map.json)

Example:
  {
    "ed25519:4b69c53929af009a": "https://wallet.interledger-test.dev/alice",
    "ed25519:2f3e8c1d7a9b5c02": "https://wallet.interledger-test.dev/bob"
  }

Missing/broken entries: contributor still fully credited; settlement marked no-route.
Missing routing never diminishes attribution.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

DEFAULT_WALLET_MAP = Path(
    os.environ.get("ZEPHYR_SETTLER_WALLET_MAP", "/data/zephyr/wallet_map.json")
)

log = logging.getLogger(__name__)


class WalletMap:
    """Resolver for pubkey_id → wallet address mappings."""

    def __init__(self, map_file: Path | str = DEFAULT_WALLET_MAP):
        self.map_file = Path(map_file)
        self._data = {}
        self._load()

    def _load(self) -> None:
        """Load wallet map from JSON file."""
        if not self.map_file.exists():
            log.info("WalletMap file not found: %s (optional, OK)", self.map_file)
            return
        try:
            with open(self.map_file) as f:
                self._data = json.load(f)
            log.debug("WalletMap loaded: %d entries", len(self._data))
        except Exception as e:
            log.error("Failed to load WalletMap from %s: %s", self.map_file, e)

    def resolve(self, pubkey_id: str) -> str | None:
        """Return the wallet address for a pubkey_id, or None if not found."""
        return self._data.get(pubkey_id)

    def has_route(self, pubkey_id: str) -> bool:
        """Return True if this pubkey_id has a wallet mapping."""
        return pubkey_id in self._data


def get_wallet_map() -> WalletMap:
    """Return a WalletMap instance (loaded from default path)."""
    return WalletMap()
