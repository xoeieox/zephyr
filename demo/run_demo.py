#!/usr/bin/env python3
"""U3 End-to-End Demo: 3-act purchase model with settlement via Open Payments.

Three-act narrative:
- Act 1: User A deposits the original (no wallet → no-route, fully credited)
- Act 2: User B remixes it (has wallet, but no settlement yet)
- Act 3: User C purchases the remix → triggers settlement flow for B via Open Payments

Event-log emission (schema 1.2) captures the entire flow.

Usage:
  # Dry-run with synthetic events:
  python demo/run_demo.py --dry-run --emit-json /tmp/capture.json

  # Live capture against testnet (requires real images, wallets config):
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
      "source_wallet": "https://ilp.interledger-test.dev/user_c",
      "wallets": {
        "user_a": null,  // no wallet
        "user_b": "https://ilp.interledger-test.dev/user_b",
        "user_c": "https://ilp.interledger-test.dev/user_c",
        ...
      }
    }
    """
    if not wallets_file.exists():
        return None
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
    consent_declaration: dict | None = None,
) -> dict:
    """Run the end-to-end 3-act demo.

    Args:
        demo_env: Environment dict from load_demo_env()
        dry_run: If True, skip actual OP calls (mock them with synthetic events)
        image_paths: List of image file paths [original, remix] for real sha256
        wallets_config: Wallet configuration dict (loaded from --wallets)
        emit_json_path: Path to write event-log JSON
        attr_db: Override attribution DB path (for testing)
        queue_db: Override intent queue DB path (for testing)
        ledger_db: Override ledger DB path (for testing)
        consent_declaration: Optional override for the act-1b use declaration -
            keys "declare" (bool), "allowed_uses", "denied_uses",
            "revoke_declarator_key" (bool). Default: User A declares
            allowed=["remix"], denied=["training"] on the original. The remix
            (and the training bot) consult check_use and a non-"permitted"
            report makes the consumer skip - the machine only reports.

    Returns dict with demo results.
    """
    log.info("=== U3 End-to-End Demo (3-Act Model) ===")

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

    # Ensure we have at least 3 contributors for the 3-act model
    if len(contributors) < 3:
        log.warning("Expected 3+ contributors for 3-act model, got %d", len(contributors))

    # Compute manifest hashes (real or mock)
    if image_paths and len(image_paths) >= 2:
        manifest_original = compute_manifest_hash(image_paths[0])
        manifest_remix = compute_manifest_hash(image_paths[1])
        capture_mode = "live-testnet"
    else:
        # Dry-run with deterministic placeholder hashes
        manifest_original = "sha256:90071b6020ba2c70fb3c97d4e19bb655d836537ad9ac2f133ce4768fa3ef2ef7"
        manifest_remix = "sha256:9ebd0fd52e5cf445a66805cd97fe6bfd59cb34eb4a57c0f19f42e831aef59598"
        capture_mode = "captured-mock"

    # Initialize event-log if requested
    captured_run = None
    if emit_json_path:
        source_wallet = wallets_config.get("source_wallet") if wallets_config else demo_env["ZEPHYR_SETTLER_SOURCE_WALLET"]
        captured_run = CapturedRun(
            run_id="run-3act-demo",
            mode=capture_mode,
            network="interledger-test.dev",
            settler_source_wallet=source_wallet,
            inter_scene_gap_ms=2200,
        )
        captured_run.add_actor("user", "User", "entity", "the human/agent acting")
        captured_run.add_actor("settler", "Settler", "entity", "Zephyr")
        captured_run.add_actor("rafiki", "Rafiki", "responder", "Open Payments · interledger-test.dev")
        captured_run.add_actor("crawler", "Training bot", "entity", "third-party consumer (synthetic)")
        captured_run.add_artifact("smiley", "smiley.png", "image/png", manifest_original, "original")
        # hat-remix is registered ONLY when the remix actually proceeds (Act 2's
        # consent gate): a capture-doc that names an artifact that was never
        # deposited documents a thing that does not exist.

    results = {
        "contributors": [],
        "settled": [],
        "no_route": [],
    }

    # Get contributors for each role
    contrib_a = contributors[0]  # Original (no wallet)
    contrib_b = contributors[1] if len(contributors) > 1 else contributors[0]  # Remixer (has wallet)
    contrib_c = contributors[2] if len(contributors) > 2 else contributors[-1]  # Purchaser (has wallet)

    # ========================================================================
    # ACT 1: Original Creator deposits (no wallet → no-route)
    # ========================================================================
    log.info("\n--- Act 1: Original Creator (NO WALLET) ---")

    key_file_a = keys_dir / f"{contrib_a['name']}.pem"
    if not key_file_a.exists():
        raise FileNotFoundError(f"Key file not found: {key_file_a}")

    signer_a = AgentSigner(key_file_a)
    pubkey_id_a = contrib_a["pubkey_id"]
    prov_a = make_signed_deposit(attr_log, signer_a, contrib_a["name"], manifest_original, pubkey_id_a, registry=registry)
    results["contributors"].append({
        "name": contrib_a["name"],
        "manifest_hash": manifest_original,
        "has_wallet": False,
        "role": "depositor",
    })

    if captured_run:
        scene_log = captured_run.start_scene("act-1-deposit")
        scene_log.set_title("User A deposits the original")
        scene_log.set_outcome("attributed")
        scene_log.set_contributor(
            f"agent:{contrib_a['name']}",
            "User A",
            has_wallet=False,
            role="depositor",
        )
        scene_log.emit("user", "settler", "deposit", "A signs & deposits the original", {
            "artifact": "smiley",
            "manifest_hash": manifest_original[:20] + "…",
            "signature": prov_a["signature"][:20] + "…",
            "note": "Zephyr records the hash, never the image bytes",
        }, t=0)
        scene_log.emit("settler", "settler", "attribution", "attribution established", {
            "attributed_to": "User A",
            "manifest_hash": manifest_original[:20] + "…",
            "note": "the record stands - no money moves on a deposit",
        }, t=550)

    # ========================================================================
    # ACT 1b: Consent of use - User A signs a use declaration on the original
    # ========================================================================
    log.info("\n--- Act 1b: Consent of use (signed, revocable declaration) ---")

    from zephyr import claims as zephyr_claims

    # Hermetic claims.db: the demo never touches a real claims store.
    os.environ.setdefault("ZEPHYR_ATTRIBUTION_DB", str(attr_db))
    os.environ["ZEPHYR_CLAIMS_DB"] = str(Path(attr_db).parent / "claims.db")
    zephyr_claims._reset_claims_store()
    claims_store = zephyr_claims.get_claims_store()

    consent_cfg = {
        "declare": True,
        "allowed_uses": ["remix"],
        "denied_uses": ["training"],
        "revoke_declarator_key": False,
    }
    if consent_declaration:
        consent_cfg.update(consent_declaration)

    consent_record = None
    if consent_cfg["declare"]:
        consent_record = zephyr_claims.record_use_terms(
            subject=manifest_original,
            allowed_uses=list(consent_cfg["allowed_uses"]),
            denied_uses=list(consent_cfg["denied_uses"]),
            scope="standing",
            agent_id=f"agent:{contrib_a['name']}",
            signer=signer_a,
            registry=registry,
            recorder=attr_log,
        )
        log.info(
            "User A declared use terms on %s (consent manifest_hash=%s)",
            manifest_original[:20] + "…", consent_record["manifest_hash"][:20] + "…",
        )

    if consent_cfg["revoke_declarator_key"]:
        # A revoked declarator key makes the declaration unverifiable, so the
        # machine reports "undeclared" - never "denied", and never MORE
        # permissive than what was denied while the key stood. Treating
        # "undeclared" conservatively is the consumer's law, not ours.
        registry.revoke(
            pubkey_id_a, reason="compromised", suspected_at="2000-01-01T00:00:00+00:00"
        )

    remix_use = zephyr_claims.check_use(
        manifest_original, "remix", store=claims_store, log=attr_log, registry=registry
    )
    training_use = zephyr_claims.check_use(
        manifest_original, "training", store=claims_store, log=attr_log, registry=registry
    )
    log.info("check_use(remix)=%s check_use(training)=%s", remix_use, training_use)

    results["consent"] = {
        "declared": consent_record is not None,
        "consent_manifest_hash": (consent_record or {}).get("manifest_hash"),
        "remix_use": remix_use,
        "training_use": training_use,
        "declarator_key_revoked": bool(consent_cfg["revoke_declarator_key"]),
    }

    if captured_run:
        scene_log = captured_run.start_scene("act-1b-consent")
        scene_log.set_title("User A declares use terms on the original")
        scene_log.set_outcome("attributed")
        scene_log.set_contributor(
            f"agent:{contrib_a['name']}",
            "User A",
            has_wallet=False,
            role="declarator",
        )
        scene_log.emit("user", "settler", "consent_declaration", "A signs what may be done with the work", {
            "artifact": "smiley",
            "subject": manifest_original[:20] + "…",
            "declared_by": (consent_record or {}).get("pubkey_id", signer_a.pubkey_id_str)[:20] + "…",
            "allowed_uses": list(consent_cfg["allowed_uses"]),
            "denied_uses": list(consent_cfg["denied_uses"]),
            "note": "self-declared only - declared_by is attribution of the declaration, never proof of entitlement",
        }, t=0)
        scene_log.emit("settler", "settler", "consent_report", "the machine reports what was declared, nothing more", {
            "remix": remix_use,
            "training": training_use,
            "vocabulary": list(zephyr_claims.USE_VOCAB),
            "note": "permitted | denied | undeclared - undeclared is the permission-void, never permission",
        }, t=550)
        scene_log.emit("crawler", "settler", "consent_check", "third-party training bot consults the use report", {
            "use": "training",
            "report": training_use,
            "action": "proceed" if training_use == "permitted" else "skip",
            "note": "the consumer decides what undeclared means - Zephyr never does",
        }, t=1100)

    # ========================================================================
    # ACT 2: Remixer deposits derived_from original (has wallet, but no settlement yet)
    # ========================================================================
    log.info("\n--- Act 2: Remixer (WITH WALLET, NO SETTLEMENT YET) ---")

    key_file_b = keys_dir / f"{contrib_b['name']}.pem"
    if not key_file_b.exists():
        raise FileNotFoundError(f"Key file not found: {key_file_b}")

    signer_b = AgentSigner(key_file_b)
    pubkey_id_b = contrib_b["pubkey_id"]

    # The consent consult is anchored HERE, immediately BEFORE the functional
    # remix (this signed deposit) - not at the scene gap below. Anchoring after
    # the deposit would let an unpermitted remix land in the log first.
    remix_proceeds = remix_use == "permitted"
    prov_b = None
    if remix_proceeds:
        prov_b = make_signed_deposit(attr_log, signer_b, contrib_b["name"], manifest_remix, pubkey_id_b, derived_from=manifest_original, registry=registry)
        if captured_run:
            captured_run.add_artifact("hat-remix", "smiley-hat.png", "image/png", manifest_remix, "remix - original + hat", derived_from=manifest_original)
        results["contributors"].append({
            "name": contrib_b["name"],
            "manifest_hash": manifest_remix,
            "has_wallet": True,
            "role": "remixer",
        })
    else:
        # Consumer law, decided by the consumer (never by Zephyr): a remix not
        # reported "permitted" is skipped. "denied" and "undeclared" are both
        # conservative here - undeclared is never permission.
        log.info(
            "Remix skipped: the use report for the remix was %r (this consumer's default is conservative)",
            remix_use,
        )
        results["consent"]["remix_skipped"] = True

    if captured_run:
        scene_log = captured_run.start_scene("act-2-remix")
        scene_log.set_title("User B remixes it" if remix_proceeds else "User B's remix is not made - the use report is not permitted")
        scene_log.set_outcome("attributed")
        scene_log.set_contributor(
            f"agent:{contrib_b['name']}",
            "User B",
            has_wallet=True,
            role="remixer",
        )
        if remix_proceeds:
            scene_log.emit("user", "settler", "deposit", "B signs & deposits the remix", {
                "artifact": "hat-remix",
                "manifest_hash": manifest_remix[:20] + "…",
                "derived_from": manifest_original[:20] + "…",
                "signature": prov_b["signature"][:20] + "…",
                "note": "signed derived_from claim",
            }, t=0)
            scene_log.emit("settler", "settler", "lineage", "attribution travels", {
                "derived_from": manifest_original[:20] + "…",
                "from_user": "User A",
                "note": "B's remix links back to A's original - and gets its own hash",
            }, t=550)
            scene_log.emit("settler", "settler", "attribution", "attribution established", {
                "attributed_to": "User B",
                "manifest_hash": manifest_remix[:20] + "…",
                "note": "still no money - attribution only",
            }, t=1100)
        else:
            scene_log.emit("settler", "settler", "consent_skip", "remix not deposited", {
                "artifact": "hat-remix",
                "report": remix_use,
                "note": "the machine only proved what was declared; skipping is this consumer's own rule",
            }, t=0)

    # ========================================================================
    # ACT 3: Purchaser triggers settlement (real OP flow)
    # ========================================================================
    log.info("\n--- Act 3: Purchaser (triggers settlement) ---")

    key_file_c = keys_dir / f"{contrib_c['name']}.pem"
    if not key_file_c.exists():
        # If there are only 2 contributors, reuse B as the purchaser
        key_file_c = key_file_b
        contrib_c = contrib_b

    # Act 3 doesn't create a new deposit; it's a purchase event that triggers settlement
    # of the remix (manifest_remix) that was created in Act 2

    if captured_run:
        scene_log = captured_run.start_scene("act-3-purchase")
        scene_log.set_title("User C buys the remix - money moves")
        scene_log.set_outcome("settled")  # Act 3 is the settlement act
        scene_log.set_contributor(
            f"agent:{contrib_c['name']}",
            "User C",
            has_wallet=True,
            role="purchaser",
        )
        # The hat-remix references below are gated emit-time on prov_b: when
        # Act 2's consent gate skipped the remix, nothing was deposited, so the
        # capture-doc must not name an artifact that was never made.
        if prov_b is not None:
            scene_log.emit("user", "settler", "purchase", "C purchases the hat product", {
                "artifact": "hat-remix",
                "manifest_hash": manifest_remix[:20] + "…",
                "note": "a real purchase is the occasion for value to move",
            }, t=0)
        else:
            scene_log.emit("user", "settler", "purchase", "C goes to buy the hat product - there is none", {
                "manifest_hash": manifest_remix[:20] + "…",
                "note": "the remix was never deposited (the use report was not permitted) - a purchase needs an artifact that exists",
            }, t=0)
        if prov_b is not None:
            scene_log.emit("settler", "settler", "chain", "walk the attribution chain", {
                "chain": ["User B - hat-remix", "User A - original (derived_from)"],
                "note": "both are attributed",
            }, t=550)
        else:
            scene_log.emit("settler", "settler", "chain", "walk the attribution chain", {
                "chain": ["User A - original"],
                "note": "only the original is attributed - the remix was never made",
            }, t=550)
        scene_log.emit("settler", "settler", "policy", "void SplitPolicy", {
            "policy": "VOID",
            "asserts": "no claim on the correct share between User A and User B",
        }, t=1100)
        scene_log.emit("settler", "settler", "route", "who has a wallet at transaction time?", {
            "User B": "wallet ✓ - will receive",
            "User A": "no wallet ✗ - credited, unpaid",
        }, t=1650)

    # Zephyr does not mint payment claims (decision/zephyr-stops-minting-
    # payment-claims-2026-08-11) - record() no longer auto-enqueues a
    # settlement intent for every signed deposit. Act 3's purchase is
    # exactly the explicit, declared dry run R3 of that decision asks for:
    # a real purchase event just occurred, so the demo declares the intent
    # itself, here, rather than it falling out of a deposit as a side effect.
    log.info("\n--- Settlement Phase ---")
    log.info("Act 3 purchase explicitly declares a settlement intent for the remix")
    if prov_b is not None:
        intent_queue.append(manifest_remix, prov_b)
    else:
        log.info("No remix deposit exists (the consent report was not 'permitted') - nothing to settle")

    # Run settler
    settler = Settler(
        source_wallet=demo_env["ZEPHYR_SETTLER_SOURCE_WALLET"],
        intent_queue=intent_queue,
        ledger=ledger,
        wallet_map=wallet_map,
        attr_log=attr_log,
    )

    if dry_run:
        log.info("DRY RUN: Mocking OP flow with synthetic events")
        with patch.object(settler, "_execute_op_flow") as mock_op:
            mock_op.return_value = "op-demo-remix-5678"

            # Emit synthetic OP/GNAP handshake for Act 3 if capturing
            if captured_run:
                scene_log = captured_run.scene_logs[-1]  # Get Act 3's log

                # Incoming payment request/response
                scene_log.emit("settler", "rafiki", "op_request", "POST /incoming-payments", {
                    "method": "POST",
                    "url": f"https://ilp.interledger-test.dev/zephyr_userb/incoming-payments",
                    "body": {"incomingAmount": {"value": "1", "assetCode": "USD", "assetScale": 2}},
                }, t=2200)

                scene_log.emit("rafiki", "settler", "op_response", "201 incoming payment", {
                    "status": 201,
                    "body": {"id": "ip_9f3a2b", "walletAddress": "https://ilp.interledger-test.dev/zephyr_userb"},
                }, t=2650)

                # Quote request/response
                scene_log.emit("settler", "rafiki", "op_request", "POST /quotes", {
                    "method": "POST",
                    "url": "https://ilp.interledger-test.dev/zephyr_userc/quotes",
                    "body": {"receiver": "ip_9f3a2b", "method": "ilp"},
                }, t=3100)

                scene_log.emit("rafiki", "settler", "op_response", "201 quote - $0.01", {
                    "status": 201,
                    "body": {"id": "qt_4c7e", "receiveAmount": {"value": "1", "assetCode": "USD", "assetScale": 2}},
                }, t=3550)

                # GNAP grant request/response
                scene_log.emit("settler", "rafiki", "grant_request", "POST /grant (GNAP)", {
                    "method": "POST",
                    "url": "https://auth.interledger-test.dev/",
                    "body": {"access_token": {"access": [{"type": "outgoing-payment", "actions": ["create", "read"]}]}},
                }, t=4000)

                scene_log.emit("rafiki", "settler", "grant_interaction", "interact required", {
                    "status": 200,
                    "interact": {"redirect": "https://wallet.interledger-test.dev/interact/gr_a1b2/approve"},
                    "human_note": "the purchaser (User C) approves the outgoing payment once",
                }, t=4450)

                scene_log.emit("user", "rafiki", "grant_approval", "C approves the payment", {
                    "approved": True,
                    "note": "captured once - the Open Payments consent moment",
                }, t=5000)

                scene_log.emit("rafiki", "settler", "grant_response", "access_token granted", {
                    "status": 200,
                    "body": {"access_token": {"value": "gr_a1b2…"}},
                }, t=5550)

                # Outgoing payment request/response
                scene_log.emit("settler", "rafiki", "op_request", "POST /outgoing-payments", {
                    "method": "POST",
                    "url": "https://ilp.interledger-test.dev/zephyr_userc/outgoing-payments",
                    "body": {"quoteId": "qt_4c7e"},
                }, t=6000)

                scene_log.emit("rafiki", "settler", "op_response", "201 state: COMPLETED", {
                    "status": 201,
                    "body": {"id": "op_7e1d", "state": "COMPLETED", "sentAmount": {"value": "1", "assetCode": "USD", "assetScale": 2}},
                }, t=6450)

                # Ledger records
                scene_log.emit("settler", "settler", "ledger", "record settled - User B", {
                    "user": "User B",
                    "status": "settled",
                    "amount": 1,
                    "asset_code": "USD",
                    "op_payment_id": "op_7e1d",
                    "attribution": "fully credited",
                }, t=7000)

                scene_log.emit("settler", "settler", "ledger", "record no-route - User A", {
                    "user": "User A",
                    "status": "no-route",
                    "amount": None,
                    "asset_code": "USD",
                    "attribution": "fully credited",
                    "record": "the record stands",
                }, t=7550)

            settler.drain(limit=10)
    else:
        log.info("Running settler (may require approval)")
        settler.drain(limit=10)

    # Check results
    ledger_remix = ledger.get(manifest_remix)
    if ledger_remix and ledger_remix["status"] == "settled":
        log.info("✓ Remix settled: %s", ledger_remix["op_payment_id"])
        results["settled"].append(contrib_b["name"])
        if captured_run:
            scene_log = captured_run.scene_logs[-1]  # Get Act 3's log
            captured_run.add_ledger_row(
                "User B",
                "hat-remix",
                "settled",
                1,
                "USD",
                ledger_remix["op_payment_id"],
                "fully credited",
                derived_from="User A",
            )
    else:
        log.warning("! Remix not settled (may have failed)")

    # Record no-route for original
    results["no_route"].append(contrib_a["name"])
    if captured_run:
        captured_run.add_ledger_row(
            "User A",
            "smiley",
            "no-route",
            None,
            "USD",
            None,
            "fully credited",
            record="the record stands",
        )

    # Display ledger
    log.info("\n--- Settlement Ledger ---")
    print("\n")
    print("=" * 80)
    print("SETTLEMENT LEDGER - VOID PRINCIPLE")
    print("=" * 80)
    print()
    print("⚠️  VOID LINE")
    print("SplitPolicy: VOID - this system makes no claim about the correct share.")
    print("The livelihood gap is the unsolved problem.")
    print()
    print("All contributors below are fully credited, regardless of settlement status.")
    print("=" * 80)
    print()

    # Build mapping from pubkey_id to contributor display names
    contrib_map = {contrib["pubkey_id"]: contrib["name"] for contrib in contributors}

    rows = ledger.all()
    print(f"{'User':<20} {'Status':<12} {'Amount':<10} {'Attribution':<20}")
    print("-" * 65)

    for row in rows:
        pubkey_id = row["pubkey_id"]
        status = row["status"]
        amount_str = "-" if status == "no-route" or not row["amount"] else f"${row['amount'] / 100:.2f}"
        user_name = contrib_map.get(pubkey_id, f"Unknown ({pubkey_id[:18]})")
        print(f"{user_name:<20} {status:<12} {amount_str:<10} fully credited")

    print()
    print(f"Total: {len(rows)} users")
    print(f"  Settled: {sum(1 for r in rows if r['status'] == 'settled')}")
    print(f"  No-route (undiminished): {sum(1 for r in rows if r['status'] == 'no-route')}")
    print()

    # Finalize event-log
    if captured_run:
        captured_run.void_principle = {
            "policy": "VOID",
            "statement": "SplitPolicy VOID - Zephyr makes no claim about the correct share between User A and User B.",
            "record_not_money": "Money routes only to attributed creators who have a wallet linked at transaction time. User A has none, so User A is credited but unpaid - and there is no retroactive backfill. Zephyr guarantees the RECORD, never deferred money.",
            "coda": "The livelihood gap is the unsolved problem.",
        }
        captured_run.write_json(emit_json_path)

    log.info("\n=== U3 Demo Complete ===")
    return results


def main():
    parser = argparse.ArgumentParser(
        description="U3 3-act demo: original → remix → purchase → settlement"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip actual Open Payments calls (mock them with synthetic events)",
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
