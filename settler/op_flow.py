"""Open Payments flow - incoming/quote/grant/outgoing settlement.

The settler executes this flow to move value from a source wallet to a recipient
wallet via Open Payments (Rafiki testnet).

Flow:
1. POST /incoming-payments to recipient wallet → receive payment ID
2. POST /quotes to recipient wallet → get send amount + ILP packet info
3. POST /grant to AS with access request → get access token
4. POST /outgoing-payments to source wallet → initiate transfer

All calls use raw httpx with hard 10s timeouts.
Partial failure: retry all steps from scratch; orphaned testnet objects acceptable.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

try:
    import httpx
except ImportError:
    httpx = None

log = logging.getLogger(__name__)


class OPClient:
    """Open Payments client for settlement."""

    def __init__(self, timeout_seconds: float = 10.0):
        if httpx is None:
            raise ImportError("httpx is required for OPClient")
        self.timeout = timeout_seconds
        self.client = httpx.Client(timeout=self.timeout)

    def create_incoming_payment(
        self, wallet_url: str, token: str
    ) -> dict:
        """Create an incoming payment at the recipient's wallet.

        Args:
            wallet_url: Recipient's wallet URL (e.g., https://wallet.interledger-test.dev/alice)
            token: Bearer token from GNAP grant

        Returns:
            Incoming payment dict with:
                - id: payment ID
                - walletAddress: wallet URL
                - ... (other fields)
        """
        url = f"{wallet_url.rstrip('/')}/incoming-payments"
        headers = {"Authorization": f"Bearer {token}"}
        req = {
            "walletAddress": wallet_url,
            "incomingAmount": {
                "value": "1",
                "assetCode": "USD",
                "assetScale": 2,
            },
        }

        log.debug("POST %s (create incoming payment)", url)

        try:
            resp = self.client.post(url, json=req, headers=headers)
            resp.raise_for_status()
            result = resp.json()
            log.debug("Incoming payment created: %s", result.get("id"))
            return result
        except httpx.HTTPError as e:
            log.error("Failed to create incoming payment: %s", e)
            raise

    def request_quote(
        self,
        wallet_url: str,
        incoming_payment_id: str,
        token: str,
        send_amount: dict,
    ) -> dict:
        """Request a quote from the destination wallet.

        Args:
            wallet_url: Recipient's wallet URL
            incoming_payment_id: ID of the incoming payment
            token: Bearer token
            send_amount: Amount to send (e.g., {"value": "1", "assetCode": "USD", "assetScale": 2})

        Returns:
            Quote dict with:
                - lowEstimatedExchangeRate
                - highEstimatedExchangeRate
                - sendAmount
                - receiveAmount
        """
        url = f"{wallet_url.rstrip('/')}/quotes"
        headers = {"Authorization": f"Bearer {token}"}
        req = {
            "walletAddress": wallet_url,
            "incomingPaymentId": incoming_payment_id,
            "sendAmount": send_amount,
        }

        log.debug("POST %s (request quote)", url)

        try:
            resp = self.client.post(url, json=req, headers=headers)
            resp.raise_for_status()
            result = resp.json()
            log.debug("Quote received: sendAmount=%s receiveAmount=%s",
                     result.get("sendAmount"), result.get("receiveAmount"))
            return result
        except httpx.HTTPError as e:
            log.error("Failed to request quote: %s", e)
            raise

    def create_outgoing_payment(
        self,
        wallet_url: str,
        token: str,
        receive_amount: dict,
        ilp_address: str,
        ilp_packet: str,
    ) -> dict:
        """Create an outgoing payment from the source wallet.

        Args:
            wallet_url: Source wallet URL (settler's wallet)
            token: Bearer token
            receive_amount: Amount recipient will receive
            ilp_address: ILP address from quote
            ilp_packet: ILP packet from quote

        Returns:
            Outgoing payment dict with:
                - id: payment ID
                - state: payment state (pending, completed, etc.)
        """
        url = f"{wallet_url.rstrip('/')}/outgoing-payments"
        headers = {"Authorization": f"Bearer {token}"}
        req = {
            "walletAddress": wallet_url,
            "receiveAmount": receive_amount,
            "ilpAddress": ilp_address,
            "ilpPacket": ilp_packet,
        }

        log.debug("POST %s (create outgoing payment)", url)

        try:
            resp = self.client.post(url, json=req, headers=headers)
            resp.raise_for_status()
            result = resp.json()
            log.debug("Outgoing payment created: %s (state=%s)", result.get("id"), result.get("state"))
            return result
        except httpx.HTTPError as e:
            log.error("Failed to create outgoing payment: %s", e)
            raise

    def get_outgoing_payment(
        self, wallet_url: str, token: str, payment_id: str
    ) -> dict:
        """Poll an outgoing payment for its status."""
        url = f"{wallet_url.rstrip('/')}/outgoing-payments/{payment_id}"
        headers = {"Authorization": f"Bearer {token}"}

        log.debug("GET %s (check payment status)", url)

        try:
            resp = self.client.get(url, headers=headers)
            resp.raise_for_status()
            result = resp.json()
            log.debug("Payment status: %s (state=%s)", result.get("id"), result.get("state"))
            return result
        except httpx.HTTPError as e:
            log.error("Failed to get payment status: %s", e)
            raise

    def close(self) -> None:
        """Close the HTTP client."""
        if self.client:
            self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
