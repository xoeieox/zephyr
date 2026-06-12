#!/usr/bin/env python3
"""U3 End-to-End Demo: settlement intent → settler → ledger with event-log emission.

Demonstrates the complete flow with optional event-log capture for HTML replay.

Usage:
  # Dry-run with mock images:
  python demo/run_demo.py --dry-run --emit-json /tmp/capture.json

  # Live capture against testnet (requires real images and wallets):
  python demo/run_demo.py --images original.png remix.png --wallets wallets.json --emit-json /tmp/capture.json

Environment setup (from U0):
  python fixtures/setup_demo.py --output-env /tmp/demo.env
  source /tmp/demo.env
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from settler.event_log import CapturedRun

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

    env["contributors"] = json.loads(env["ZEPHYR_DEMO_CONTRIBUTORS"])
    return env


def compute_manifest_hash(image_path: str | Path) -> str:
    """Compute real sha256 of an image file."""
    path = Path(image_path)
    if not path.exists():
        raise FileNotFoundError(f"Image not found: {path}")
    content = path.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    return f"sha256:{digest}"


def load_wallets_config(wallets_file: Path) -> dict:
    """Load wallet configuration from JSON file.

    Expected schema:
    {
      "source_wallet": "https://wallet.interledger-test.dev/zephyr-settler-source",
      "wallets": {
        "contributor_01": "https://wallet.interledger-test.dev/contributor_01",
        ...
      }
    }
    """
    config = json.loads(wallets_file.read_text())
    return config


def make_signed_deposit(
    attr_log,
    signer,
    contributor_name: str,
    manifest_hash: str,
    pubkey_id: str,
    derived_from: str | None = None,
    registry=None,
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
    if derived_from:
        provenance["derived_from"] = derived_from

    signature = signer.sign(manifest_hash)
    provenance["signature"] = signature

    newly_recorded = attr_log.record(provenance, registry=registry)

    if newly_recorded:
        log.info("Recorded signed deposit for %s (manifest_hash=%s)", contributor_name, manifest_hash)
    else:
        log.warning("Deposit already recorded: %s", manifest_hash)

    return provenance


def run_demo(
    demo_env: dict,
    dry_run: bool = False,
    image_paths: list[str] | None = None,
    wallets_config: dict | None = None,
    emit_json_path: Path | None = None,
    attr_db: Path | None = None,
    queue_db: Path | None = None,
    ledger_db: Path | None = None,
) -> dict:
    """Run the end-to-end demo.

    Args:
        demo_env: Environment dict from load_demo_env()
        dry_run: If True, skip actual OP calls (mock them)
        image_paths: List of image file paths [original, remix] for real sha256
        wallets_config: Wallet configuration dict (loaded from --wallets)
        emit_json_path: Path to write event-log JSON
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
        os.environ["ZEPHYR_ATTRIBUTION_DB"] = str(attr_db)
        os.environ["ZEPHYR_INTENT_QUEUE_DB"] = str(queue_db)

    from zephyr.attribution import AttributionLog
    from zephyr.intent_queue import SettlementIntentQueue
    from zephyr.registry import PubkeyRegistry
    from zephyr.signing import AgentSigner
    from settler.ledger import SettlementLedger
    from settler.wallet_map import WalletMap
    from settler.run import Settler

    attr_log = AttributionLog(attr_db)
    intent_queue = SettlementIntentQueue(queue_db)
    ledger = SettlementLedger(ledger_db)
    wallet_map = WalletMap(demo_env["ZEPHYR_SETTLER_WALLET_MAP"])
    registry = PubkeyRegistry()

    keys_dir = Path(demo_env["ZEPHYR_DEMO_KEYS_DIR"])
    contributors = demo_env.get("contributors") or json.loads(demo_env["ZEPHYR_DEMO_CONTRIBUTORS"])

    # Compute manifest hashes (real or mock)
    if image_paths and len(image_paths) >= 2:
        manifest_original = compute_manifest_hash(image_paths[0])
        manifest_remix = compute_manifest_hash(image_paths[1])
        capture_mode = "live-testnet-a1"
    else:
        # Dry-run with deterministic placeholder hashes
        manifest_original = "sha256:demo-original-smiley-placeholder"
        manifest_remix = "sha256:demo-remix-smiley-hat-placeholder"
        capture_mode = "captured-mock"

    # Initialize event-log if requested
    captured_run = None
    if emit_json_path:
        source_wallet = wallets_config.get("source_wallet") if wallets_config else demo_env["ZEPHYR_SETTLER_SOURCE_WALLET"]
        captured_run = CapturedRun(
            run_id="run-demo",
            mode=capture_mode,
            network="interledger-test.dev",
            settler_source_wallet=source_wallet,
        )
        captured_run.add_actor("contributor", "Contributor", "entity", "the human/agent who made the work")
        captured_run.add_actor("settler", "Settler", "entity", "Zephyr")
        captured_run.add_actor("rafiki", "Rafiki", "responder", "Open Payments · interledger-test.dev")
        captured_run.add_artifact("original", "smiley.png", "image/png", manifest_original, "original — a smiley face")
        captured_run.add_artifact("remix", "smiley-hat.png", "image/png", manifest_remix, "remix — smiley with hat", derived_from=manifest_original)

    results = {
        "contributors": [],
        "settled": [],
        "no_route": [],
    }

    # Scene 1: Original creator (no wallet, no-route)
    log.info("\n--- Scene 1: Original Creator (NO WALLET) ---")
    contrib_original = contributors[0]
    key_file_orig = keys_dir / f"{contrib_original['name']}.pem"

    if not key_file_orig.exists():
        raise FileNotFoundError(f"Key file not found: {key_file_orig}")

    signer_orig = AgentSigner(key_file_orig)
    pubkey_id_orig = contrib_original["pubkey_id"]
    prov_orig = make_signed_deposit(attr_log, signer_orig, contrib_original["name"], manifest_original, pubkey_id_orig, registry=registry)
    results["contributors"].append({
        "name": contrib_original["name"],
        "manifest_hash": manifest_original,
        "has_wallet": False,
    })

    if captured_run:
        scene_log = captured_run.start_scene("scene-1-original-no-wallet")
        scene_log.set_title("An original, with no wallet")
        scene_log.set_contributor(
            f"agent:{contrib_original['name']}",
            contrib_original["name"],
            has_wallet=False,
        )
        scene_log.emit("contributor", "settler", "deposit", "signs the original", {
            "artifact": "original",
            "manifest_hash": manifest_original,
            "signature": prov_orig["signature"][:20] + "…",
            "pubkey_id": pubkey_id_orig,
        }, t=0)
        scene_log.emit("settler", "settler", "route", "resolve wallet ✗", {
            "resolved": False,
            "reason": "no wallet linked for this pubkey",
        }, t=500)
        scene_log.emit("settler", "settler", "ledger", "record no-route", {
            "status": "no-route",
            "amount": None,
            "asset_code": "USD",
            "attribution": "fully credited",
            "record": "permanent, portable, undiminished — the record stands",
        }, t=1000)

    # Settler processes scene 1
    log.info("\n--- Scene 1 Settlement ---")
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
            mock_op.return_value = "op-demo-orig-1234"
            settler.drain(limit=10)
    else:
        log.info("Running settler (may fail if testnet unreachable)")
        settler.drain(limit=10)

    ledger_orig = ledger.get(manifest_original)
    if ledger_orig and ledger_orig["status"] == "no-route":
        log.info("✓ Original marked no-route (as expected)")
        results["no_route"].append(contrib_original["name"])
        if captured_run:
            captured_run.add_ledger_row(
                contrib_original["name"],
                "original",
                "no-route",
                None,
                "USD",
                None,
                "fully credited",
                record="the record stands",
            )
    elif ledger_orig and ledger_orig["status"] == "settled":
        log.warning("! Original settled (unexpected; has no wallet)")
        results["settled"].append(contrib_original["name"])
    else:
        log.warning("! Original not in ledger")

    # Scene 2: Remixer (has wallet, settles)
    log.info("\n--- Scene 2: Remixer (WITH WALLET) ---")
    contrib_remix = contributors[1] if len(contributors) > 1 else contributors[-1]
    key_file_remix = keys_dir / f"{contrib_remix['name']}.pem"

    if not key_file_remix.exists():
        raise FileNotFoundError(f"Key file not found: {key_file_remix}")

    signer_remix = AgentSigner(key_file_remix)
    pubkey_id_remix = contrib_remix["pubkey_id"]
    prov_remix = make_signed_deposit(attr_log, signer_remix, contrib_remix["name"], manifest_remix, pubkey_id_remix, derived_from=manifest_original, registry=registry)
    results["contributors"].append({
        "name": contrib_remix["name"],
        "manifest_hash": manifest_remix,
        "has_wallet": True,
    })

    if captured_run:
        scene_log = captured_run.start_scene("scene-2-remix-settles")
        scene_log.set_title("A remix that builds on it, with a wallet")
        scene_log.set_contributor(
            f"agent:{contrib_remix['name']}",
            contrib_remix["name"],
            has_wallet=True,
        )
        scene_log.emit("contributor", "settler", "deposit", "signs the remix", {
            "artifact": "remix",
            "manifest_hash": manifest_remix,
            "derived_from": manifest_original,
            "signature": prov_remix["signature"][:20] + "…",
            "pubkey_id": pubkey_id_remix,
        }, t=0)
        scene_log.emit("settler", "settler", "lineage", "attribution travels", {
            "derived_from": manifest_original,
            "from_contributor": contrib_original["name"],
        }, t=500)
        scene_log.emit("settler", "settler", "policy", "void SplitPolicy", {
            "policy": "VOID",
            "asserts": "no claim on the correct share between original and remix",
        }, t=1000)
        scene_log.emit("settler", "settler", "route", "resolve wallet ✓", {
            "resolved": True,
            "wallet": wallet_map.resolve(pubkey_id_remix) or f"https://wallet.interledger-test.dev/{contrib_remix['name'].lower()}",
        }, t=1500)

    # Settler processes scene 2
    log.info("\n--- Scene 2 Settlement ---")
    if dry_run:
        log.info("DRY RUN: Mocking OP flow")
        with patch.object(settler, "_execute_op_flow") as mock_op:
            mock_op.return_value = "op-demo-remix-5678"
            settler.drain(limit=10)
    else:
        log.info("Running settler for remix (may require approval)")
        settler.drain(limit=10)

    ledger_remix = ledger.get(manifest_remix)
    if captured_run:
        scene_log = captured_run.scene_logs[-1]  # Get scene 2's log
    if ledger_remix and ledger_remix["status"] == "settled":
        log.info("✓ Remix settled: %s", ledger_remix["op_payment_id"])
        results["settled"].append(contrib_remix["name"])
        if captured_run:
            scene_log.emit("settler", "settler", "ledger", "record settled ✓", {
                "status": "settled",
                "amount": 1,
                "asset_code": "USD",
                "op_payment_id": ledger_remix["op_payment_id"],
                "attribution": "fully credited",
            }, t=6100)
            captured_run.add_ledger_row(
                contrib_remix["name"],
                "remix",
                "settled",
                1,
                "USD",
                ledger_remix["op_payment_id"],
                "fully credited",
                derived_from=contrib_original["name"],
            )
    elif ledger_remix and ledger_remix["status"] == "no-route":
        log.warning("! Remix marked no-route (unexpected; has wallet)")
        results["no_route"].append(contrib_remix["name"])
        if captured_run:
            scene_log.emit("settler", "settler", "ledger", "record no-route", {
                "status": "no-route",
                "amount": None,
                "asset_code": "USD",
                "attribution": "fully credited",
            }, t=6100)
    else:
        log.warning("! Remix not in ledger (settlement may have failed)")

    # Display ledger
    log.info("\n--- Settlement Ledger ---")
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

    rows = ledger.all()
    print(f"{'Contributor':<20} {'Status':<12} {'Amount':<10} {'Attribution':<20}")
    print("-" * 65)

    for row in rows:
        pubkey_id = row["pubkey_id"][:18]
        status = row["status"]
        amount_str = f"${row['amount'] / 100:.2f}" if row["amount"] else "—"
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

    # Finalize event-log
    if captured_run:
        captured_run.void_principle = {
            "policy": "VOID",
            "statement": "SplitPolicy VOID — this system makes no claim about the correct share between the original and the remix.",
            "record_not_money": "No wallet, no payment — and no retroactive backfill. Zephyr guarantees the RECORD — permanent, portable, undiminished — never deferred money.",
            "coda": "The livelihood gap is the unsolved problem.",
        }
        captured_run.write_json(emit_json_path)

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
    parser.add_argument(
        "--images",
        nargs=2,
        metavar=("ORIGINAL", "REMIX"),
        help="Image file paths [original remix] for real sha256 computation",
    )
    parser.add_argument(
        "--wallets",
        type=Path,
        help="Wallet configuration JSON file",
    )
    parser.add_argument(
        "--emit-json",
        type=Path,
        help="Write event-log JSON to this path",
    )

    args = parser.parse_args()

    try:
        demo_env = load_demo_env()
        wallets_config = load_wallets_config(args.wallets) if args.wallets else None
        results = run_demo(
            demo_env,
            dry_run=args.dry_run,
            image_paths=args.images,
            wallets_config=wallets_config,
            emit_json_path=args.emit_json,
        )

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
