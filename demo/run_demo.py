#!/usr/bin/env python3
"""U3 End-to-End Demo: settlement intent → settler → ledger with void line.

Demonstrates the complete flow:
1. Contributor A (has wallet) makes a signed deposit
2. Settler drains and settles A's intent (Open Payments to testnet wallet)
3. Ledger shows A's settlement
4. Contributor C (no wallet) makes a signed deposit
5. Settler marks C's intent as no-route (no settlement)
6. Ledger shows C as no-route, still fully credited (void principle)

Usage:
  python demo/run_demo.py [--dry-run]

Environment setup (from U0):
  python fixtures/setup_demo.py --output-env /tmp/demo.env
  source /tmp/demo.env
  python demo/run_demo.py
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add parent dir to path for zephyr imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from zephyr.attribution import AttributionLog
from zephyr.intent_queue import SettlementIntentQueue
from zephyr.registry import PubkeyRegistry
from zephyr.signing import AgentSigner
from settler.ledger import SettlementLedger
from settler.wallet_map import WalletMap
from settler.run import Settler

log = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


def load_demo_env() -> dict:
    """Load environment variables from U0 setup."""
    env = {}
    required_keys = [
        "ZEPHYR_DEMO_KEYS_DIR",
        "ZEPHYR_DEMO_CONTRIBUTORS",
        "ZEPHYR_SETTLER_WALLET_MAP",
        "ZEPHYR_SETTLER_SOURCE_WALLET",
    ]

    for key in required_keys:
        if key not in os.environ:
            raise ValueError(
                f"Environment variable {key} not set. "
                f"Run: python fixtures/setup_demo.py --output-env <file> && source <file>"
            )
        env[key] = os.environ[key]

    # Parse JSON fields
    env["contributors"] = json.loads(env["ZEPHYR_DEMO_CONTRIBUTORS"])

    return env


def make_signed_deposit(
    attr_log: AttributionLog,
    signer: AgentSigner,
    contributor_name: str,
    manifest_hash: str,
    pubkey_id: str,
) -> dict:
    """Make a signed deposit to the attribution log.

    Returns the provenance dict.
    """
    now = datetime.now(timezone.utc).isoformat()
    provenance = {
        "manifest_hash": manifest_hash,
        "agent_id": f"agent:{contributor_name}",
        "pubkey_id": pubkey_id,
        "tool": "demo",
        "model": "demo-v0",
        "timestamp": now,
        "schema_version": "lapis-provenance-v0.1",
    }

    # Sign the manifest_hash
    signature = signer.sign(manifest_hash)
    provenance["signature"] = signature

    # Record (emits settlement intent if signed)
    newly_recorded = attr_log.record(provenance)

    if newly_recorded:
        log.info("Recorded signed deposit for %s (manifest_hash=%s)", contributor_name, manifest_hash)
    else:
        log.warning("Deposit already recorded: %s", manifest_hash)

    return provenance


def run_demo(
    demo_env: dict,
    dry_run: bool = False,
    attr_db: Path | None = None,
    queue_db: Path | None = None,
    ledger_db: Path | None = None,
) -> dict:
    """Run the end-to-end demo.

    Args:
        demo_env: Environment dict from load_demo_env()
        dry_run: If True, skip actual OP calls (mock them)
        attr_db: Override attribution DB path (for testing)
        queue_db: Override intent queue DB path (for testing)
        ledger_db: Override ledger DB path (for testing)

    Returns dict with demo results.
    """
    log.info("=== U3 End-to-End Demo ===")

    # Set up temporary DBs if not provided
    tmp_dir = None
    if not attr_db:
        tmp_dir = tempfile.mkdtemp(prefix="zephyr-demo-")
        attr_db = Path(tmp_dir) / "attribution.db"
        queue_db = Path(tmp_dir) / "intent_queue.db"
        ledger_db = Path(tmp_dir) / "ledger.db"
        log.info("Using temporary DBs in %s", tmp_dir)

    # Initialize components
    attr_log = AttributionLog(attr_db)
    intent_queue = SettlementIntentQueue(queue_db)
    ledger = SettlementLedger(ledger_db)
    wallet_map = WalletMap(demo_env["ZEPHYR_SETTLER_WALLET_MAP"])

    # Load contributor keys
    keys_dir = Path(demo_env["ZEPHYR_DEMO_KEYS_DIR"])
    # Parse contributors from demo_env (may be pre-parsed or as JSON string)
    contributors = demo_env.get("contributors")
    if contributors is None:
        contributors = json.loads(demo_env["ZEPHYR_DEMO_CONTRIBUTORS"])

    results = {
        "contributors": [],
        "settled": [],
        "no_route": [],
    }

    # Contributor A (has wallet) - make signed deposit
    log.info("\n--- Phase 1: Contributor A (with wallet) ---")
    contrib_a = contributors[0]
    key_file_a = keys_dir / f"{contrib_a['name']}.pem"

    if not key_file_a.exists():
        raise FileNotFoundError(f"Key file not found: {key_file_a}")

    signer_a = AgentSigner(key_file_a)
    manifest_a = f"sha256:demo-deposit-{contrib_a['name']}"
    pubkey_id_a = contrib_a["pubkey_id"]

    prov_a = make_signed_deposit(attr_log, signer_a, contrib_a["name"], manifest_a, pubkey_id_a)
    results["contributors"].append(
        {"name": contrib_a["name"], "manifest_hash": manifest_a, "has_wallet": True}
    )

    # Run settler for A (dry-run or actual OP flow)
    log.info("\n--- Phase 2: Settler drains A's intent ---")
    settler = Settler(
        source_wallet=demo_env["ZEPHYR_SETTLER_SOURCE_WALLET"],
        intent_queue=intent_queue,
        ledger=ledger,
        wallet_map=wallet_map,
        attr_log=attr_log,
    )

    if dry_run:
        log.info("DRY RUN: Mocking OP flow")
        with patch.object(settler, "_execute_op_flow") as mock_op:
            mock_op.return_value = "op-payment-demo-a-1234"
            settler.drain(limit=10)
    else:
        log.info("Running actual settler (may fail if testnet unreachable)")
        settler.drain(limit=10)

    # Check settlement status for A
    ledger_a = ledger.get(manifest_a)
    if ledger_a and ledger_a["status"] == "settled":
        log.info("✓ A's intent settled: %s", ledger_a["op_payment_id"])
        results["settled"].append(contrib_a["name"])
    elif ledger_a and ledger_a["status"] == "no-route":
        log.warning("! A's intent marked no-route (unexpected)")
        results["no_route"].append(contrib_a["name"])
    else:
        log.warning("! A's intent not in ledger (settlement may have failed)")

    # Contributor C (no wallet) - make signed deposit
    log.info("\n--- Phase 3: Contributor C (WITHOUT wallet) ---")
    contrib_c = contributors[-1]  # Last contributor has no wallet
    key_file_c = keys_dir / f"{contrib_c['name']}.pem"

    if not key_file_c.exists():
        raise FileNotFoundError(f"Key file not found: {key_file_c}")

    signer_c = AgentSigner(key_file_c)
    manifest_c = f"sha256:demo-deposit-{contrib_c['name']}"
    pubkey_id_c = contrib_c["pubkey_id"]

    prov_c = make_signed_deposit(attr_log, signer_c, contrib_c["name"], manifest_c, pubkey_id_c)
    results["contributors"].append(
        {"name": contrib_c["name"], "manifest_hash": manifest_c, "has_wallet": False}
    )

    # Run settler for C (should mark no-route because no wallet)
    log.info("\n--- Phase 4: Settler drains C's intent (expects no-route) ---")
    if dry_run:
        log.info("DRY RUN: Running settler in dry-run mode")
        settler.drain(limit=10)
    else:
        settler.drain(limit=10)

    # Check settlement status for C
    ledger_c = ledger.get(manifest_c)
    if ledger_c and ledger_c["status"] == "no-route":
        log.info("✓ C's intent marked no-route (as expected)")
        log.info("  ✓ C still fully credited despite no settlement")
        results["no_route"].append(contrib_c["name"])
    elif ledger_c and ledger_c["status"] == "settled":
        log.warning("! C's intent settled (unexpected; C has no wallet)")
        results["settled"].append(contrib_c["name"])
    else:
        log.warning("! C's intent not in ledger")

    # Display ledger with void line
    log.info("\n--- Phase 5: Display Settlement Ledger ---")
    print("\n")
    print("=" * 80)
    print("SETTLEMENT LEDGER — VOID PRINCIPLE")
    print("=" * 80)
    print()
    print("⚠️  VOID LINE")
    print("SplitPolicy: VOID — this system makes no claim about the correct share.")
    print("The livelihood gap is the unsolved problem.")
    print()
    print("All contributors below are fully credited, regardless of settlement status.")
    print("=" * 80)
    print()

    # Display ledger entries
    rows = ledger.all()

    print(f"{'Contributor':<20} {'Status':<12} {'Amount':<10} {'Attribution':<20}")
    print("-" * 65)

    for row in rows:
        pubkey_id = row["pubkey_id"][:18]
        status = row["status"]
        amount_str = f"${row['amount'] / 100:.2f}" if row["amount"] else "—"
        # Find contributor name
        contrib_name = "unknown"
        for c in contributors:
            if c["pubkey_id"] == row["pubkey_id"]:
                contrib_name = c["name"]
                break
        print(f"{contrib_name:<20} {status:<12} {amount_str:<10} fully credited")

    print()
    print(f"Total: {len(rows)} contributors (all credited)")
    print(f"  Settled: {sum(1 for r in rows if r['status'] == 'settled')}")
    print(f"  No-route (undiminished): {sum(1 for r in rows if r['status'] == 'no-route')}")
    print()

    log.info("\n=== U3 Demo Complete ===")
    return results


def main():
    parser = argparse.ArgumentParser(
        description="U3 end-to-end demo: settlement intent → settler → ledger"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip actual Open Payments calls (mock them)",
    )

    args = parser.parse_args()

    try:
        demo_env = load_demo_env()
        results = run_demo(demo_env, dry_run=args.dry_run)

        # Summary
        log.info("\n✓ Demo completed successfully")
        log.info("  Contributors recorded: %d", len(results["contributors"]))
        log.info("  Settled: %d", len(results["settled"]))
        log.info("  No-route (fully credited): %d", len(results["no_route"]))

        return 0

    except Exception as e:
        log.error("Demo failed: %s", e, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
