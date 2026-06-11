"""GNAP (Grant Negotiation and Authorization Protocol) testnet client.

Rafiki v2.4-beta supports pre-authorized grants: no interactive redirect,
just a grant request against the AS endpoint.

This module provides low-level GNAP operations for testnet (interledger-test.dev).
JWK-based directed-identity is a future upgrade; v0 uses pre-auth (captured mode).

Reference: https://interledger.org/specifications/rafikirfc/
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


class GNAPClient:
    """Low-level GNAP pre-auth grant client for Rafiki testnet."""

    def __init__(
        self,
        as_endpoint: str,
        timeout_seconds: float = 10.0,
    ):
        """Initialize GNAP client.

        Args:
            as_endpoint: Authorization Server endpoint (e.g., "https://auth.interledger-test.dev")
            timeout_seconds: HTTP request timeout (default 10s).
        """
        if httpx is None:
            raise ImportError("httpx is required for GNAPClient")
        self.as_endpoint = as_endpoint.rstrip("/")
        self.timeout = timeout_seconds
        self.client = httpx.Client(timeout=self.timeout)

    def request_grant(
        self,
        interact_finish: str,
        access_token: dict,
        client_info: dict | None = None,
    ) -> dict:
        """Request a pre-authorized grant.

        Args:
            interact_finish: interaction finish method (e.g., "redirect")
            access_token: token request dict with:
                - flags: list of token flags (e.g., ["bearer"])
                - access: list of access items
            client_info: optional client identification (name, uri, etc.)

        Returns:
            Grant response dict with:
                - access_token: granted token dict
                - continue: optional continuation token
        """
        req = {
            "access_token": access_token,
            "client": client_info or {"name": "zephyr-settler"},
            "interact": {
                "finish": interact_finish,
                "start": ["redirect"],
            },
        }

        log.debug("GNAP request_grant: %s", json.dumps(req, indent=2))

        try:
            resp = self.client.post(f"{self.as_endpoint}/grant", json=req)
            resp.raise_for_status()
            result = resp.json()
            log.debug("GNAP grant response: %s", json.dumps(result, indent=2))
            return result
        except httpx.HTTPError as e:
            log.error("GNAP grant request failed: %s", e)
            raise

    def continue_grant(self, continue_token: str) -> dict:
        """Continue a grant interaction using a continuation token."""
        req = {"continue": {"access_token": continue_token}}

        log.debug("GNAP continue_grant: %s", json.dumps(req, indent=2))

        try:
            resp = self.client.post(f"{self.as_endpoint}/grant", json=req)
            resp.raise_for_status()
            result = resp.json()
            log.debug("GNAP continue response: %s", json.dumps(result, indent=2))
            return result
        except httpx.HTTPError as e:
            log.error("GNAP continue request failed: %s", e)
            raise

    def close(self) -> None:
        """Close the HTTP client."""
        if self.client:
            self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
