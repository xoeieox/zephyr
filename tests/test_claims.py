"""Acceptance criteria tests for zephyr claims domain store (rail U0).

All identities are SYNTHETIC (agent:claims-test / agent:route-test).  No
writes outside tmp dirs: ZEPHYR_CLAIMS_DB is monkeypatched to a tmp_path
location and the claims-store singleton is reset around every test, mirroring
the AttributionLog/PubkeyRegistry/AgentSigner tmp_path pattern used across
this repo (test_attribution_signed.py:39-54).

Coverage map:
  AC1  -- self wallet_binding: record + resolve_wallet round-trip, verified
  AC2  -- binding is self-only: signer.pubkey_id != subject raises; no
          method/declared_by/subject_kind parameter exists to route around it
  AC3  -- routing_terms bounds at record time: share_bps out of range raises;
          unregistered beneficiary_pubkey_id raises
  AC10 -- human-namespace agent_id raises (inherited from record_signed)
"""

from __future__ import annotations

import inspect

import pytest

from zephyr import claims
from zephyr.attribution import AttributionLog
from zephyr.registry import PubkeyRegistry
from zephyr.signing import AgentSigner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_log(tmp_path):
    return AttributionLog(tmp_path / "attr.db")


@pytest.fixture()
def tmp_registry(tmp_path):
    return PubkeyRegistry(tmp_path / "keys")


@pytest.fixture()
def tmp_claims_store(tmp_path, monkeypatch):
    monkeypatch.setenv("ZEPHYR_CLAIMS_DB", str(tmp_path / "claims.db"))
    claims._reset_claims_store()
    yield claims.get_claims_store()
    claims._reset_claims_store()


def _signer(tmp_path, name):
    return AgentSigner(tmp_path / "agent-keys" / f"{name}.key")


# ---------------------------------------------------------------------------
# AC1 -- self wallet_binding round-trip
# ---------------------------------------------------------------------------


def test_ac1_self_wallet_binding_round_trip(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac1")

    result = claims.record_wallet_binding(
        subject=s.pubkey_id_str,
        wallet_address="https://wallet.example/alice",
        agent_id="agent:claims-test",
        signer=s,
        registry=tmp_registry,
        recorder=tmp_log,
    )

    assert result["manifest_hash"].startswith("sha256:")
    assert result["newly_recorded"] is True

    row = tmp_log.get(result["manifest_hash"], registry=tmp_registry)
    assert row is not None
    assert row["verification_status"] == "verified"

    resolved = claims.resolve_wallet(s.pubkey_id_str, store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert resolved == "https://wallet.example/alice"


def test_ac1_revocation_tombstones_binding(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac1-revoke")

    claims.record_wallet_binding(
        subject=s.pubkey_id_str,
        wallet_address="https://wallet.example/bob",
        agent_id="agent:claims-test",
        signer=s,
        registry=tmp_registry,
        recorder=tmp_log,
        timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_wallet_binding(
        subject=s.pubkey_id_str,
        wallet_address="https://wallet.example/bob",
        agent_id="agent:claims-test",
        revokes=True,
        signer=s,
        registry=tmp_registry,
        recorder=tmp_log,
        timestamp="2026-07-20T00:00:01+00:00",
    )

    resolved = claims.resolve_wallet(s.pubkey_id_str, store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert resolved is None


def test_ac1_resolve_wallet_absent_returns_none(tmp_log, tmp_registry, tmp_claims_store):
    assert claims.resolve_wallet("ed25519:0000000000000000", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) is None


# ---------------------------------------------------------------------------
# AC2 -- binding is self-only
# ---------------------------------------------------------------------------


def test_ac2_binding_rejects_non_self_subject(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac2-signer")

    with pytest.raises(ValueError, match="self-signed only"):
        claims.record_wallet_binding(
            subject="ed25519:not-the-signer-key",
            wallet_address="https://wallet.example/mallory",
            agent_id="agent:claims-test",
            signer=s,
            registry=tmp_registry,
            recorder=tmp_log,
        )


def test_ac2_no_proxy_binding_parameter_exists():
    """There is no parameter with which to record a binding for another party:
    no method / declared_by / subject_kind kwarg is accepted."""
    sig = inspect.signature(claims.record_wallet_binding)
    forbidden = {"method", "declared_by", "subject_kind", "on_behalf_of", "proxy"}
    assert forbidden.isdisjoint(sig.parameters.keys())


# ---------------------------------------------------------------------------
# AC3 -- routing_terms bounds at record time
# ---------------------------------------------------------------------------


def test_ac3_share_bps_below_zero_raises(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac3-below")
    tmp_registry.register(s.pubkey_id_str, s.public_key_bytes.hex(), "agent:beneficiary", "agent")

    with pytest.raises(ValueError, match="share_bps"):
        claims.record_routing_terms(
            subject="sha256:some-subject",
            beneficiary_pubkey_id=s.pubkey_id_str,
            share_bps=-1,
            scope="standing",
            declared_by="agent:claims-test",
            agent_id="agent:claims-test",
            registry=tmp_registry,
            recorder=tmp_log,
        )


def test_ac3_share_bps_above_10000_raises(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac3-above")
    tmp_registry.register(s.pubkey_id_str, s.public_key_bytes.hex(), "agent:beneficiary", "agent")

    with pytest.raises(ValueError, match="share_bps"):
        claims.record_routing_terms(
            subject="sha256:some-subject",
            beneficiary_pubkey_id=s.pubkey_id_str,
            share_bps=10001,
            scope="standing",
            declared_by="agent:claims-test",
            agent_id="agent:claims-test",
            registry=tmp_registry,
            recorder=tmp_log,
        )


def test_ac3_unregistered_beneficiary_raises(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    with pytest.raises(ValueError, match="not registered"):
        claims.record_routing_terms(
            subject="sha256:some-subject",
            beneficiary_pubkey_id="ed25519:not-registered-000",
            share_bps=1000,
            scope="standing",
            declared_by="agent:claims-test",
            agent_id="agent:claims-test",
            registry=tmp_registry,
            recorder=tmp_log,
        )


def test_ac3_registered_beneficiary_records_successfully(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac3-ok")
    tmp_registry.register(s.pubkey_id_str, s.public_key_bytes.hex(), "agent:beneficiary", "agent")

    result = claims.record_routing_terms(
        subject="sha256:some-subject",
        beneficiary_pubkey_id=s.pubkey_id_str,
        share_bps=4000,
        scope="standing",
        declared_by="agent:claims-test",
        agent_id="agent:claims-test",
        registry=tmp_registry,
        recorder=tmp_log,
    )
    assert result["newly_recorded"] is True

    rows = tmp_claims_store.list_routing_terms_for_subject("sha256:some-subject")
    assert len(rows) == 1
    assert rows[0]["beneficiary_pubkey_id"] == s.pubkey_id_str
    assert rows[0]["share_bps"] == 4000
    assert rows[0]["basis"] == "declared-contract"


# ---------------------------------------------------------------------------
# AC10 -- human-namespace agent_id raises (inherited from record_signed)
# ---------------------------------------------------------------------------


def test_ac10_wallet_binding_refuses_human_namespace(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac10-wallet")

    with pytest.raises(ValueError, match="human namespace"):
        claims.record_wallet_binding(
            subject=s.pubkey_id_str,
            wallet_address="https://wallet.example/Erah",
            agent_id="Erah",
            signer=s,
            registry=tmp_registry,
            recorder=tmp_log,
        )


def test_ac10_routing_terms_refuses_human_namespace(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac10-terms")
    tmp_registry.register(s.pubkey_id_str, s.public_key_bytes.hex(), "agent:beneficiary", "agent")

    with pytest.raises(ValueError, match="human namespace"):
        claims.record_routing_terms(
            subject="sha256:some-subject",
            beneficiary_pubkey_id=s.pubkey_id_str,
            share_bps=1000,
            scope="standing",
            declared_by="human:test",
            agent_id="human:test",
            registry=tmp_registry,
            recorder=tmp_log,
        )
