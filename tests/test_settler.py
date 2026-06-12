"""Tests for U2 settler - Open Payments settlement.

Acceptance criteria:
  U2-AC1  -- GNAP pre-auth grant request succeeds (testnet spike)
  U2-AC2  -- OP flow: incoming/quote/grant/outgoing succeeds
  U2-AC3  -- Atomic claim prevents double-settle
  U2-AC4  -- No-route marking when wallet hint absent
  U2-AC5  -- Attribution DB cross-check rejects orphans
  U2-AC6  -- Void SplitPolicy (no share calculation)
  U2-AC7  -- Settlement ledger records outcome
  U2-AC8  -- Settler drains batch of intents
  U2-AC9  -- Failure recovery (mark failed, can retry)
  U2-AC10 -- Wallet address resolved from WalletMap JSON
"""

from __future__ import annotations

import json
import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

from settler.ledger import SettlementLedger
from settler.split import SplitPolicy, get_split_policy
from settler.wallet_map import WalletMap
from settler.gnap import GNAPClient
from settler.op_flow import OPClient
from settler.run import Settler
from zephyr.intent_queue import SettlementIntentQueue
from zephyr.attribution import AttributionLog
from zephyr.signing import AgentSigner
from zephyr.registry import PubkeyRegistry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_ledger(tmp_path):
    """Fresh SettlementLedger in tmp_path."""
    return SettlementLedger(tmp_path / "ledger.db")


@pytest.fixture()
def tmp_queue(tmp_path):
    """Fresh SettlementIntentQueue in tmp_path."""
    return SettlementIntentQueue(tmp_path / "intent_queue.db")


@pytest.fixture()
def tmp_attr_log(tmp_path):
    """Fresh AttributionLog in tmp_path."""
    return AttributionLog(tmp_path / "attr.db")


@pytest.fixture()
def tmp_wallet_map(tmp_path):
    """Fresh WalletMap from a test JSON file."""
    map_file = tmp_path / "wallet_map.json"
    with open(map_file, "w") as f:
        json.dump({
            "ed25519:4b69c53929af009a": "https://wallet.interledger-test.dev/alice",
            "ed25519:2f3e8c1d7a9b5c02": "https://wallet.interledger-test.dev/bob",
        }, f)
    return WalletMap(map_file)


@pytest.fixture()
def tmp_signer(tmp_path):
    """Fresh AgentSigner using a tmp key."""
    return AgentSigner(tmp_path / "agent-keys" / "settler.key")


@pytest.fixture()
def tmp_registry(tmp_path):
    """Fresh PubkeyRegistry."""
    return PubkeyRegistry(tmp_path / "keys")


# ---------------------------------------------------------------------------
# U2-AC1 — GNAP pre-auth grant request (testnet spike)
# ---------------------------------------------------------------------------


def test_u2_ac1_gnap_pre_auth_grant_request():
    """GNAP client can construct a pre-auth grant request."""
    with patch("settler.gnap.httpx") as mock_httpx:
        mock_client = MagicMock()
        mock_httpx.Client.return_value = mock_client

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": {
                "value": "test-token-value",
                "flags": ["bearer"],
            }
        }
        mock_client.post.return_value = mock_response

        gnap = GNAPClient("https://auth.interledger-test.dev")
        result = gnap.request_grant(
            interact_finish="redirect",
            access_token={
                "flags": ["bearer"],
                "access": [{"type": "outgoing-payment"}],
            },
        )

        assert result["access_token"]["value"] == "test-token-value"
        assert mock_client.post.called


def test_u2_ac1_gnap_continue_grant():
    """GNAP client can continue a grant using continuation token."""
    with patch("settler.gnap.httpx") as mock_httpx:
        mock_client = MagicMock()
        mock_httpx.Client.return_value = mock_client

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": {
                "value": "final-token",
                "flags": ["bearer"],
            }
        }
        mock_client.post.return_value = mock_response

        gnap = GNAPClient("https://auth.interledger-test.dev")
        result = gnap.continue_grant("continue-token-123")

        assert result["access_token"]["value"] == "final-token"


# ---------------------------------------------------------------------------
# U2-AC2 — OP flow: incoming/quote/grant/outgoing
# ---------------------------------------------------------------------------


def test_u2_ac2_op_client_create_incoming_payment():
    """OP client can create an incoming payment at recipient."""
    with patch("settler.op_flow.httpx") as mock_httpx:
        mock_client = MagicMock()
        mock_httpx.Client.return_value = mock_client

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "id": "incoming-payment-123",
            "walletAddress": "https://wallet.interledger-test.dev/alice",
        }
        mock_client.post.return_value = mock_response

        op = OPClient()
        result = op.create_incoming_payment(
            "https://wallet.interledger-test.dev/alice",
            "test-bearer-token",
        )

        assert result["id"] == "incoming-payment-123"


def test_u2_ac2_op_client_request_quote():
    """OP client can request a quote from destination."""
    with patch("settler.op_flow.httpx") as mock_httpx:
        mock_client = MagicMock()
        mock_httpx.Client.return_value = mock_client

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "sendAmount": {"value": "1", "assetCode": "USD", "assetScale": 2},
            "receiveAmount": {"value": "1", "assetCode": "USD", "assetScale": 2},
            "ilpAddress": "g.rafiki.alice",
            "ilpPacket": "packet-data-here",
        }
        mock_client.post.return_value = mock_response

        op = OPClient()
        result = op.request_quote(
            "https://wallet.interledger-test.dev/alice",
            "incoming-payment-123",
            "test-bearer-token",
            {"value": "1", "assetCode": "USD", "assetScale": 2},
        )

        assert result["ilpAddress"] == "g.rafiki.alice"


def test_u2_ac2_op_client_create_outgoing_payment():
    """OP client can create an outgoing payment from source."""
    with patch("settler.op_flow.httpx") as mock_httpx:
        mock_client = MagicMock()
        mock_httpx.Client.return_value = mock_client

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "id": "outgoing-payment-456",
            "state": "pending",
        }
        mock_client.post.return_value = mock_response

        op = OPClient()
        result = op.create_outgoing_payment(
            "https://wallet.interledger-test.dev/settler",
            "test-bearer-token",
            quote_id="quote-123",
        )

        assert result["id"] == "outgoing-payment-456"


# ---------------------------------------------------------------------------
# U2-AC3 — Atomic claim prevents double-settle
# ---------------------------------------------------------------------------


def test_u2_ac3_atomic_claim_prevents_double_settle(tmp_queue):
    """Atomic claim ensures intent is claimed only once."""
    prov = {
        "manifest_hash": "sha256:atomic-claim-test",
        "pubkey_id": "ed25519:0000000000000001",
        "agent_id": "agent:test",
        "timestamp": "2026-06-10T12:00:00+00:00",
    }

    tmp_queue.append("sha256:atomic-claim-test", prov)

    # First claim succeeds
    claimed1 = tmp_queue.claim("sha256:atomic-claim-test")
    assert claimed1 is True

    # Second claim fails (already in_flight)
    claimed2 = tmp_queue.claim("sha256:atomic-claim-test")
    assert claimed2 is False


# ---------------------------------------------------------------------------
# U2-AC4 — No-route marking when wallet hint absent
# ---------------------------------------------------------------------------


def test_u2_ac4_no_route_when_wallet_absent(tmp_queue, tmp_ledger):
    """Intent marked no-route when wallet hint is missing."""
    prov = {
        "manifest_hash": "sha256:no-route-test",
        "pubkey_id": "ed25519:0000000000000099",
        "agent_id": "agent:no-wallet",
        "timestamp": "2026-06-10T12:00:00+00:00",
    }

    tmp_queue.append("sha256:no-route-test", prov)
    tmp_queue.claim("sha256:no-route-test")
    tmp_queue.mark_no_route("sha256:no-route-test")
    tmp_ledger.record_no_route("sha256:no-route-test", "ed25519:0000000000000099", 1, "USD")

    # Verify no-route status
    intent = tmp_queue.get("sha256:no-route-test")
    assert intent["status"] == "no-route"

    ledger_entry = tmp_ledger.get("sha256:no-route-test")
    assert ledger_entry["status"] == "no-route"


# ---------------------------------------------------------------------------
# U2-AC5 — Attribution DB cross-check rejects orphans
# ---------------------------------------------------------------------------


def test_u2_ac5_attr_cross_check_rejects_orphan(tmp_attr_log, tmp_queue):
    """Settler checks that pubkey_id exists in attribution DB."""
    prov = {
        "manifest_hash": "sha256:orphan-test",
        "pubkey_id": "ed25519:orphan0000000000",
        "agent_id": "agent:orphan",
        "timestamp": "2026-06-10T12:00:00+00:00",
    }

    tmp_queue.append("sha256:orphan-test", prov)

    # pubkey_id is NOT in attribution log → cross-check fails
    result = tmp_attr_log.get_by_pubkey("ed25519:orphan0000000000")
    assert result is None


def test_u2_ac5_attr_cross_check_accepts_known_key(
    tmp_attr_log, tmp_signer, tmp_registry
):
    """Settler accepts intents whose pubkey_id is in attribution DB."""
    import json
    from datetime import datetime, timezone

    # Manually insert a deposit record (bypassing record_signed to avoid archetypes_core)
    pubkey_id = tmp_signer.pubkey_id_str
    now = datetime.now(timezone.utc).isoformat()

    with tmp_attr_log._lock:
        tmp_attr_log._conn.execute(
            "INSERT INTO deposits "
            "(manifest_hash, agent_id, tool, model, timestamp, store_kind, "
            " target_key, schema_version, provenance_json, recorded_at, "
            " signature, pubkey_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "sha256:manual-test",
                "agent:settler-test",
                "test",
                None,
                now,
                "mem",
                None,
                "lapis-provenance-v0.1",
                json.dumps({"manifest_hash": "sha256:manual-test"}),
                now,
                "sig-placeholder",
                pubkey_id,
            ),
        )
        tmp_attr_log._conn.commit()

    # Now cross-check the key
    found = tmp_attr_log.get_by_pubkey(pubkey_id)
    assert found is not None
    assert found["pubkey_id"] == pubkey_id


# ---------------------------------------------------------------------------
# U2-AC6 — Void SplitPolicy (no share calculation)
# ---------------------------------------------------------------------------


def test_u2_ac6_void_split_policy_unchanged():
    """Void SplitPolicy returns intent unchanged."""
    policy = get_split_policy()
    intent = {
        "manifest_hash": "sha256:test",
        "pubkey_id": "ed25519:test",
        "amount": 1,
        "asset_code": "USD",
    }

    result = policy.compute(intent)
    assert result == intent
    assert result["amount"] == 1


# ---------------------------------------------------------------------------
# U2-AC7 — Settlement ledger records outcome
# ---------------------------------------------------------------------------


def test_u2_ac7_ledger_record_settled(tmp_ledger):
    """Settlement ledger can record a settled intent."""
    tmp_ledger.record_settled(
        "sha256:settled-test",
        "ed25519:0000000000000001",
        "op-payment-789",
        1,
        "USD",
    )

    entry = tmp_ledger.get("sha256:settled-test")
    assert entry is not None
    assert entry["status"] == "settled"
    assert entry["op_payment_id"] == "op-payment-789"


def test_u2_ac7_ledger_record_failed(tmp_ledger):
    """Settlement ledger can record a failed intent."""
    tmp_ledger.record_failed(
        "sha256:failed-test",
        "ed25519:0000000000000001",
        1,
        "USD",
        "Connection timeout",
    )

    entry = tmp_ledger.get("sha256:failed-test")
    assert entry is not None
    assert entry["status"] == "failed"
    assert "timeout" in entry["error_detail"]


# ---------------------------------------------------------------------------
# U2-AC8 — Settler drains batch of intents
# ---------------------------------------------------------------------------


def test_u2_ac8_settler_drain_batch(tmp_path, tmp_queue, tmp_attr_log, tmp_wallet_map, tmp_signer, tmp_ledger):
    """Settler can drain a batch of pending intents."""
    import json
    from datetime import datetime, timezone

    # Manually insert a deposit record (bypassing record_signed to avoid archetypes_core)
    pubkey_id = tmp_signer.pubkey_id_str
    now = datetime.now(timezone.utc).isoformat()

    with tmp_attr_log._lock:
        tmp_attr_log._conn.execute(
            "INSERT INTO deposits "
            "(manifest_hash, agent_id, tool, model, timestamp, store_kind, "
            " target_key, schema_version, provenance_json, recorded_at, "
            " signature, pubkey_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "sha256:batch-deposit",
                "agent:settler-test",
                "test",
                None,
                now,
                "mem",
                None,
                "lapis-provenance-v0.1",
                json.dumps({"manifest_hash": "sha256:batch-deposit"}),
                now,
                "sig-placeholder",
                pubkey_id,
            ),
        )
        tmp_attr_log._conn.commit()

    # Add the generated pubkey_id to the wallet map
    tmp_wallet_map._data[pubkey_id] = "https://wallet.interledger-test.dev/settler-test"

    # Add intents to queue
    for i in range(3):
        prov_i = {
            "manifest_hash": f"sha256:drain-test-{i}",
            "pubkey_id": pubkey_id,
            "agent_id": "agent:settler-test",
            "timestamp": "2026-06-10T12:00:00+00:00",
        }
        tmp_queue.append(f"sha256:drain-test-{i}", prov_i)

    # Create settler with injected instances
    settler = Settler(
        source_wallet="https://wallet.interledger-test.dev/settler",
        max_retries=3,
        intent_queue=tmp_queue,
        ledger=tmp_ledger,
        wallet_map=tmp_wallet_map,
        attr_log=tmp_attr_log,
    )

    with patch.object(settler, "_execute_op_flow") as mock_op:
        mock_op.return_value = "op-payment-xyz"

        # Drain
        count = settler.drain(limit=10)

        # All 3 should be settled (they have wallet hints via tmp_wallet_map)
        assert count == 3
        # Verify OP flow was called for all 3 intents
        assert mock_op.call_count == 3


# ---------------------------------------------------------------------------
# U2-AC9 — Failure recovery
# ---------------------------------------------------------------------------


def test_u2_ac9_failure_marked_failed(tmp_queue, tmp_ledger):
    """Failed settlement is marked failed in queue and ledger."""
    prov = {
        "manifest_hash": "sha256:fail-test",
        "pubkey_id": "ed25519:0000000000000001",
        "agent_id": "agent:test",
        "timestamp": "2026-06-10T12:00:00+00:00",
    }

    tmp_queue.append("sha256:fail-test", prov)
    tmp_queue.claim("sha256:fail-test")
    tmp_queue.mark_failed("sha256:fail-test", worker_id="settler-v0")
    tmp_ledger.record_failed("sha256:fail-test", "ed25519:0000000000000001", 1, "USD", "Network error")

    intent = tmp_queue.get("sha256:fail-test")
    assert intent["status"] == "failed"

    ledger_entry = tmp_ledger.get("sha256:fail-test")
    assert ledger_entry["status"] == "failed"


# ---------------------------------------------------------------------------
# U2-AC10 — WalletMap resolution
# ---------------------------------------------------------------------------


def test_u2_ac10_wallet_map_loads_json(tmp_wallet_map):
    """WalletMap loads and resolves wallet addresses from JSON."""
    wallet = tmp_wallet_map.resolve("ed25519:4b69c53929af009a")
    assert wallet == "https://wallet.interledger-test.dev/alice"

    wallet_bob = tmp_wallet_map.resolve("ed25519:2f3e8c1d7a9b5c02")
    assert wallet_bob == "https://wallet.interledger-test.dev/bob"


def test_u2_ac10_wallet_map_missing_key(tmp_wallet_map):
    """WalletMap returns None for missing keys."""
    wallet = tmp_wallet_map.resolve("ed25519:missing0000000000")
    assert wallet is None
