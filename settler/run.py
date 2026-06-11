"""Settler main process - drains intents and settles via Open Payments.

Entry point: python -m settler.run

Orchestrates:
1. Load intent queue (pending intents)
2. For each intent:
   a. Atomic claim (pending → in_flight)
   b. Resolve wallet hint from WalletMap; cross-check pubkey_id in attribution DB
   c. Apply void SplitPolicy
   d. Execute OP flow (incoming/quote/grant/outgoing)
   e. Record in settlement ledger
3. Mark intents as settled/no-route/failed
"""

from __future__ import annotations

import logging
import os
from typing import Optional

import httpx

from zephyr.attribution import AttributionLog
from zephyr.intent_queue import get_queue
from settler.ledger import get_ledger
from settler.split import get_split_policy
from settler.wallet_map import get_wallet_map
from settler.gnap import GNAPClient
from settler.op_flow import OPClient

log = logging.getLogger(__name__)


class Settler:
    """Main settler process."""

    def __init__(
        self,
        source_wallet: str,
        gnap_endpoint: str = "https://auth.interledger-test.dev",
        max_retries: int = 3,
        intent_queue=None,
        ledger=None,
        wallet_map=None,
        attr_log=None,
    ):
        """Initialize settler.

        Args:
            source_wallet: Funded settlement-pool source wallet URL
            gnap_endpoint: Rafiki GNAP endpoint
            max_retries: Max attempts per intent before marking failed
            intent_queue: Optional IntentQueue instance (for testing)
            ledger: Optional SettlementLedger instance (for testing)
            wallet_map: Optional WalletMap instance (for testing)
            attr_log: Optional AttributionLog instance (for testing)
        """
        self.source_wallet = source_wallet
        self.gnap_endpoint = gnap_endpoint
        self.max_retries = max_retries
        self.intent_queue = intent_queue if intent_queue is not None else get_queue()
        self.ledger = ledger if ledger is not None else get_ledger()
        self.wallet_map = wallet_map if wallet_map is not None else get_wallet_map()
        self.split_policy = get_split_policy()
        self.attr_log = attr_log if attr_log is not None else AttributionLog()

    def settle_one(self, intent: dict) -> bool:
        """Attempt to settle a single intent, with retry logic.

        Returns True if settled/no-route, False if failed (can retry).
        """
        manifest_hash = intent["manifest_hash"]
        pubkey_id = intent["pubkey_id"]
        amount = intent["amount"]
        asset_code = intent["asset_code"]

        log.info("Settling intent: manifest_hash=%s pubkey_id=%s", manifest_hash, pubkey_id)

        # 1. Atomic claim (pending → in_flight)
        if not self.intent_queue.claim(manifest_hash):
            log.warning("Intent already claimed or processed: %s", manifest_hash)
            return True

        # 2. Resolve wallet hint and cross-check pubkey_id in attribution
        recipient_wallet = self.wallet_map.resolve(pubkey_id)
        if not recipient_wallet:
            log.info("No wallet routing for pubkey_id=%s, marking no-route", pubkey_id)
            self.intent_queue.mark_no_route(manifest_hash)
            self.ledger.record_no_route(manifest_hash, pubkey_id, amount, asset_code)
            return True

        # Cross-check pubkey_id exists in attribution DB
        attr_entry = self.attr_log.get_by_pubkey(pubkey_id)
        if attr_entry is None:
            log.warning("pubkey_id=%s not found in attribution DB, marking no-route", pubkey_id)
            self.intent_queue.mark_no_route(manifest_hash)
            self.ledger.record_no_route(manifest_hash, pubkey_id, amount, asset_code)
            return True

        # 3. Apply void SplitPolicy
        intent = self.split_policy.compute(intent)

        # 4. Execute OP flow with retry logic
        last_error = None
        for attempt in range(1, self.max_retries + 1):
            try:
                op_payment_id = self._execute_op_flow(
                    recipient_wallet,
                    amount,
                    asset_code,
                )
                log.info("Settlement succeeded: manifest_hash=%s op_payment_id=%s",
                         manifest_hash, op_payment_id)

                # 5. Record in ledger and mark settled
                self.intent_queue.settle(
                    manifest_hash,
                    op_payment_id=op_payment_id,
                    worker_id="settler-v0",
                )
                self.ledger.record_settled(
                    manifest_hash,
                    pubkey_id,
                    op_payment_id,
                    amount,
                    asset_code,
                )

                # 6. Write settlement info back to provenance (best-effort)
                self.attr_log.write_settlement_info(manifest_hash, op_payment_id)

                return True

            except Exception as e:
                last_error = e
                log.warning("Settlement attempt %d/%d failed for %s: %s",
                           attempt, self.max_retries, manifest_hash, e)
                if attempt < self.max_retries:
                    log.info("Retrying settlement for %s", manifest_hash)
                    continue

        log.error("Settlement failed after %d attempts for %s: %s",
                 self.max_retries, manifest_hash, last_error, exc_info=True)
        self.intent_queue.mark_failed(manifest_hash, worker_id="settler-v0")
        self.ledger.record_failed(
            manifest_hash,
            pubkey_id,
            amount,
            asset_code,
            str(last_error),
        )
        return False

    def _execute_op_flow(self, recipient_wallet: str, amount: int, asset_code: str) -> str:
        """Execute the full OP flow and return the outgoing payment ID."""
        # Create OP client
        op_client = OPClient(timeout_seconds=10.0)

        # GNAP grant request (pre-authorized)
        gnap = GNAPClient(self.gnap_endpoint, timeout_seconds=10.0)

        try:
            # Request a pre-authorized grant
            grant_resp = gnap.request_grant(
                interact_finish="redirect",
                access_token={
                    "flags": ["bearer"],
                    "access": [
                        {
                            "type": "outgoing-payment",
                            "actions": ["create", "read", "complete"],
                        },
                    ],
                },
            )

            if "access_token" not in grant_resp:
                raise RuntimeError(f"No access_token in grant response: {grant_resp}")

            token = grant_resp["access_token"]["value"]

            # Create incoming payment at recipient
            incoming = op_client.create_incoming_payment(recipient_wallet, token)
            incoming_payment_id = incoming["id"]

            # Request quote
            send_amount = {
                "value": str(amount),
                "assetCode": asset_code,
                "assetScale": 2,
            }
            quote = op_client.request_quote(
                recipient_wallet,
                incoming_payment_id,
                token,
                send_amount,
            )

            # Create outgoing payment from source
            outgoing = op_client.create_outgoing_payment(
                self.source_wallet,
                token,
                receive_amount=quote.get("receiveAmount", send_amount),
                ilp_address=quote.get("ilpAddress", ""),
                ilp_packet=quote.get("ilpPacket", ""),
            )

            return outgoing["id"]

        finally:
            op_client.close()
            gnap.close()

    def drain(self, limit: int = 100) -> int:
        """Drain up to *limit* pending intents.

        Returns the count of intents processed.
        """
        pending = self.intent_queue.pending(limit=limit)
        if not pending:
            log.info("No pending intents to settle")
            return 0

        log.info("Processing %d pending intents", len(pending))

        settled = 0
        for intent in pending:
            if self.settle_one(intent):
                settled += 1

        log.info("Settled %d/%d intents", settled, len(pending))
        return settled

    def run(self) -> None:
        """Run the settler (once)."""
        log.info("Starting settler")
        try:
            self.drain()
            log.info("Settler finished")
        except Exception as e:
            log.error("Settler crashed: %s", e, exc_info=True)
            raise


def main():
    """Entry point for python -m settler.run"""
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    source_wallet = os.environ.get("ZEPHYR_SETTLER_SOURCE_WALLET")
    if not source_wallet:
        raise ValueError("ZEPHYR_SETTLER_SOURCE_WALLET not set")

    gnap_endpoint = os.environ.get(
        "ZEPHYR_SETTLER_GNAP_ENDPOINT",
        "https://auth.interledger-test.dev",
    )

    settler = Settler(
        source_wallet=source_wallet,
        gnap_endpoint=gnap_endpoint,
    )
    settler.run()


if __name__ == "__main__":
    main()
