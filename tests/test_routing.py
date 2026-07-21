"""Acceptance criteria tests for the zephyr RouteManifest compiler (rail U1).

All identities are SYNTHETIC (agent:route-test, agent:claims-test, and
per-contributor agent:route-test-<name> ids).  No writes outside tmp dirs:
ZEPHYR_CLAIMS_DB is monkeypatched to a tmp_path location and the claims-store
singleton is reset around every test, mirroring the AttributionLog /
PubkeyRegistry / AgentSigner tmp_path pattern used across this repo
(test_attribution_signed.py:39-54).

Coverage map:
  AC3  -- compile-time bounds: direct terms summing > 10000 raises; duplicate
          (subject, beneficiary) raises
  AC4  -- conservation grid + brute-force reference + exact-tie ordering
  AC5  -- normative worked example verbatim; 3-hop chain raises
          RouteDepthExceeded; two standing terms on parent raise
          RouteCompileError
  AC6  -- missing wallet binding -> credited-unpaid, other legs unaffected
  AC7  -- determinism + idempotency
  AC8  -- fail closed: unsigned routing_terms -> RouteTamperError
  AC9  -- CLI happy path (subprocess, tmp env vars)
  AC11 -- replay binding: a term for subject X is never consumed compiling Y
  AC12 -- replay guard: identical recompile idempotent; changed amount ->
          RouteReplayConflict, no new row
  AC13 -- tamper detection: hash_mismatch / missing_envelope / unsigned
  AC14 -- resolution supersession: revoke -> new manifest with supersedes,
          allocation layer byte-identical, third recompile idempotent
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from fractions import Fraction
from pathlib import Path

import pytest

from zephyr import claims, routing
from zephyr.attribution import AttributionLog
from zephyr.registry import PubkeyRegistry
from zephyr.routing import (
    RouteCompileError,
    RouteDepthExceeded,
    RouteReplayConflict,
    RouteTamperError,
    compile_route_manifest,
)
from zephyr.signing import AgentSigner

REPO_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Fixtures + helpers
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


def _contributor(tmp_path, registry, name):
    s = _signer(tmp_path, name)
    registry.register(s.pubkey_id_str, s.public_key_bytes.hex(), f"agent:{name}", "agent")
    return s


def _make_content_deposit(log, signer, registry, *, agent_id, payload, summary, timestamp, derived_from=None):
    """Reference-path content deposit, mirroring demo/run_demo.py's make_signed_deposit:
    derived_from is a recorder-side column, not part of manifest_hash, so it is
    attached to the provenance dict after to_lapis_return computes the hash."""
    from archetypes_core.provenance import SCHEMA_VERSION_V01, to_lapis_return

    ltr = to_lapis_return(
        payload, agent_id=agent_id, tool="demo", summary=summary,
        schema_version=SCHEMA_VERSION_V01, timestamp=timestamp,
    )
    mh = ltr.provenance.manifest_hash
    pkid = signer.pubkey_id_str
    if registry.lookup(pkid) is None:
        registry.register(pkid, signer.public_key_bytes.hex(), agent_id, role="agent")
    prov = ltr.provenance.to_dict()
    prov["signature"] = signer.sign(mh)
    prov["pubkey_id"] = pkid
    if derived_from:
        prov["derived_from"] = derived_from
    log.record(prov, store_kind="content", registry=registry)
    return mh


def _record_unsigned_routing_terms(log, store, *, subject, beneficiary_pubkey_id, share_bps, scope, declared_by, agent_id, timestamp):
    """Bypasses record_routing_terms's signing path entirely (observe-mode deposit)."""
    from archetypes_core.provenance import SCHEMA_VERSION_V01, to_lapis_return

    payload = {
        "routing_terms": {
            "subject": subject,
            "beneficiary_pubkey_id": beneficiary_pubkey_id,
            "share_bps": share_bps,
            "basis": "declared-contract",
            "scope": scope,
            "declared_by": declared_by,
            "note": "",
        }
    }
    summary = f"unsigned routing term: {subject}"
    ltr = to_lapis_return(
        payload, agent_id=agent_id, tool="zephyr:routing-terms", summary=summary,
        schema_version=SCHEMA_VERSION_V01, timestamp=timestamp,
    )
    mh = ltr.provenance.manifest_hash
    prov = ltr.provenance.to_dict()

    old_mode = os.environ.get("ZEPHYR_SIGNING_MODE")
    os.environ["ZEPHYR_SIGNING_MODE"] = "observe"
    try:
        log.record(prov, store_kind="routing_terms", key=subject)
    finally:
        if old_mode is None:
            os.environ.pop("ZEPHYR_SIGNING_MODE", None)
        else:
            os.environ["ZEPHYR_SIGNING_MODE"] = old_mode

    store.insert_routing_terms(
        manifest_hash=mh, subject=subject, beneficiary_pubkey_id=beneficiary_pubkey_id,
        share_bps=share_bps, basis="declared-contract", scope=scope, declared_by=declared_by,
        note="", summary=summary, recorded_at=timestamp,
    )
    return mh


# ---------------------------------------------------------------------------
# AC3 -- compile-time bounds
# ---------------------------------------------------------------------------


def test_ac3_direct_terms_sum_exceeds_10000_raises(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "ac3-d")
    m = _contributor(tmp_path, tmp_registry, "ac3-m")
    compiler = _signer(tmp_path, "ac3-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:ac3-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=6000,
        scope="standing", declared_by="agent:ac3-d", agent_id="agent:ac3-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=m.pubkey_id_str, share_bps=6000,
        scope="standing", declared_by="agent:ac3-m", agent_id="agent:ac3-m",
        signer=m, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:02+00:00",
    )

    with pytest.raises(RouteCompileError, match="10000"):
        compile_route_manifest(
            event_kind="demo-sale", event_ref="evt-ac3-sum", subject=subject_mh,
            amount_value=500, asset_code="USD", asset_scale=2,
            agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
            timestamp="2026-07-20T00:01:00+00:00",
        )


def test_ac3_duplicate_beneficiary_raises(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "ac3dup-d")
    compiler = _signer(tmp_path, "ac3dup-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:ac3dup-d", payload={"work": "y"},
        summary="work y", timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=1000,
        scope="standing", declared_by="agent:ac3dup-d", agent_id="agent:ac3dup-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=2000,
        scope=f"event:evt-ac3-dup", declared_by="agent:ac3dup-d", agent_id="agent:ac3dup-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:02+00:00",
    )

    with pytest.raises(RouteCompileError, match="duplicate"):
        compile_route_manifest(
            event_kind="demo-sale", event_ref="evt-ac3-dup", subject=subject_mh,
            amount_value=500, asset_code="USD", asset_scale=2,
            agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
            timestamp="2026-07-20T00:01:00+00:00",
        )


# ---------------------------------------------------------------------------
# AC4 -- conservation grid
# ---------------------------------------------------------------------------

GRID_AMOUNTS = [1, 2, 3, 499, 500, 501, 999999, 1000003]
GRID_BPS_SETS = [
    [3333, 3333, 3334],
    [1, 1, 1],
    [9999],
    [5000, 5000],
]


def _brute_force_allocate(amount, bucket_specs):
    """Independent reference: exact-rational largest remainder via Fraction."""
    scored = []
    for bid, bps, is_payer in bucket_specs:
        frac = Fraction(amount * bps, 10000)
        floor = frac.numerator // frac.denominator
        remainder = frac - floor
        scored.append((bid, is_payer, floor, remainder))
    leftover = amount - sum(s[2] for s in scored)
    order = sorted(scored, key=lambda s: (-s[3], 1 if s[1] else 0, s[0] or ""))
    bump = {id(s) for s in order[:leftover]}
    return {s[0]: s[2] + (1 if id(s) in bump else 0) for s in scored}


@pytest.mark.parametrize("bps_set", GRID_BPS_SETS, ids=lambda b: "-".join(map(str, b)))
@pytest.mark.parametrize("amount", GRID_AMOUNTS)
def test_ac4_conservation_grid(amount, bps_set):
    ids = [f"b{i}" for i in range(len(bps_set))]
    buckets = [{"id": bid, "bps": bps, "is_payer": False} for bid, bps in zip(ids, bps_set)]
    payer_bps = 10000 - sum(bps_set)
    buckets.append({"id": None, "bps": payer_bps, "is_payer": True})

    result = routing._largest_remainder(amount, buckets)

    assert sum(b["amount"] for b in result) == amount
    assert all(b["amount"] >= 0 for b in result)

    ref = _brute_force_allocate(amount, [(b["id"], b["bps"], b["is_payer"]) for b in buckets])
    for b in result:
        assert b["amount"] == ref[b["id"]]


@pytest.mark.parametrize("amount", [3, 7])
def test_ac4_exact_tie_order(amount):
    buckets = [
        {"id": "b0", "bps": 2500, "is_payer": False},
        {"id": "b1", "bps": 2500, "is_payer": False},
        {"id": "b2", "bps": 2500, "is_payer": False},
        {"id": None, "bps": 2500, "is_payer": True},
    ]
    result = routing._largest_remainder(amount, buckets)
    by_id = {b["id"]: b["amount"] for b in result}

    if amount == 3:
        assert by_id == {"b0": 1, "b1": 1, "b2": 1, None: 0}
    else:  # amount == 7
        assert by_id == {"b0": 2, "b1": 2, "b2": 2, None: 1}


# ---------------------------------------------------------------------------
# AC5 -- normative worked example + depth cap
# ---------------------------------------------------------------------------


def test_ac5_worked_example_verbatim(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "ac5-d")
    m = _contributor(tmp_path, tmp_registry, "ac5-m")
    p = _contributor(tmp_path, tmp_registry, "ac5-p")
    compiler = _signer(tmp_path, "ac5-compiler")

    parent_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:ac5-d", payload={"work": "original"},
        summary="D's original work", timestamp="2026-07-19T00:00:00+00:00",
    )
    subject_mh = _make_content_deposit(
        tmp_log, m, tmp_registry, agent_id="agent:ac5-m", payload={"work": "derivative"},
        summary="derivative work", timestamp="2026-07-19T01:00:00+00:00", derived_from=parent_mh,
    )

    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by="agent:ac5-d", agent_id="agent:ac5-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-19T02:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=m.pubkey_id_str, share_bps=2500,
        scope="standing", declared_by="agent:ac5-m", agent_id="agent:ac5-m",
        signer=m, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-19T02:00:01+00:00",
    )
    claims.record_routing_terms(
        subject=parent_mh, beneficiary_pubkey_id=p.pubkey_id_str, share_bps=1000,
        scope="standing", declared_by="agent:ac5-d", agent_id="agent:ac5-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-19T02:00:02+00:00",
    )

    result = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-ac5-worked", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:00:00+00:00",
    )

    rm = result["manifest"]["route_manifest"]
    assert rm["payer_retained"] == 175
    by_beneficiary = {leg["beneficiary_pubkey_id"]: leg["amount"] for leg in rm["legs"]}
    assert by_beneficiary[d.pubkey_id_str] == 180
    assert by_beneficiary[m.pubkey_id_str] == 125
    assert by_beneficiary[p.pubkey_id_str] == 20
    assert rm["payer_retained"] + sum(leg["amount"] for leg in rm["legs"]) == 500


def test_ac5_three_hop_chain_raises_depth_exceeded(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    g = _contributor(tmp_path, tmp_registry, "ac5depth-g")
    d = _contributor(tmp_path, tmp_registry, "ac5depth-d")
    q = _contributor(tmp_path, tmp_registry, "ac5depth-q")
    compiler = _signer(tmp_path, "ac5depth-compiler")

    grandparent_mh = _make_content_deposit(
        tmp_log, g, tmp_registry, agent_id="agent:ac5depth-g", payload={"work": "root"},
        summary="root work", timestamp="2026-07-19T00:00:00+00:00",
    )
    parent_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:ac5depth-d", payload={"work": "mid"},
        summary="mid work", timestamp="2026-07-19T01:00:00+00:00", derived_from=grandparent_mh,
    )
    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:ac5depth-d", payload={"work": "leaf"},
        summary="leaf work", timestamp="2026-07-19T02:00:00+00:00", derived_from=parent_mh,
    )

    claims.record_routing_terms(
        subject=grandparent_mh, beneficiary_pubkey_id=q.pubkey_id_str, share_bps=500,
        scope="standing", declared_by="agent:ac5depth-g", agent_id="agent:ac5depth-g",
        signer=g, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-19T03:00:00+00:00",
    )

    with pytest.raises(RouteDepthExceeded):
        compile_route_manifest(
            event_kind="demo-sale", event_ref="evt-ac5-depth", subject=subject_mh,
            amount_value=500, asset_code="USD", asset_scale=2,
            agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
            timestamp="2026-07-20T00:00:00+00:00",
        )


def test_ac5_two_standing_terms_on_parent_raises(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "ac5two-d")
    p1 = _contributor(tmp_path, tmp_registry, "ac5two-p1")
    p2 = _contributor(tmp_path, tmp_registry, "ac5two-p2")
    compiler = _signer(tmp_path, "ac5two-compiler")

    parent_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:ac5two-d", payload={"work": "original"},
        summary="original", timestamp="2026-07-19T00:00:00+00:00",
    )
    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:ac5two-d", payload={"work": "derivative"},
        summary="derivative", timestamp="2026-07-19T01:00:00+00:00", derived_from=parent_mh,
    )

    claims.record_routing_terms(
        subject=parent_mh, beneficiary_pubkey_id=p1.pubkey_id_str, share_bps=500,
        scope="standing", declared_by="agent:ac5two-d", agent_id="agent:ac5two-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-19T02:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=parent_mh, beneficiary_pubkey_id=p2.pubkey_id_str, share_bps=500,
        scope="standing", declared_by="agent:ac5two-d", agent_id="agent:ac5two-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-19T02:00:01+00:00",
    )

    with pytest.raises(RouteCompileError) as excinfo:
        compile_route_manifest(
            event_kind="demo-sale", event_ref="evt-ac5-two-standing", subject=subject_mh,
            amount_value=500, asset_code="USD", asset_scale=2,
            agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
            timestamp="2026-07-20T00:00:00+00:00",
        )
    assert not isinstance(excinfo.value, RouteDepthExceeded)


# ---------------------------------------------------------------------------
# AC6 -- missing wallet binding
# ---------------------------------------------------------------------------


def test_ac6_missing_wallet_binding_credited_unpaid(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "ac6-d")
    m = _contributor(tmp_path, tmp_registry, "ac6-m")
    compiler = _signer(tmp_path, "ac6-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:ac6-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by="agent:ac6-d", agent_id="agent:ac6-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=m.pubkey_id_str, share_bps=2500,
        scope="standing", declared_by="agent:ac6-m", agent_id="agent:ac6-m",
        signer=m, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:02+00:00",
    )
    # Only M's wallet is bound.
    claims.record_wallet_binding(
        subject=m.pubkey_id_str, wallet_address="https://wallet.example/m",
        agent_id="agent:ac6-m", signer=m, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:00:03+00:00",
    )

    unbound = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-ac6-unbound", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:01:00+00:00",
    )
    rm = unbound["manifest"]["route_manifest"]
    legs_by_id = {leg["beneficiary_pubkey_id"]: leg for leg in rm["legs"]}
    assert legs_by_id[d.pubkey_id_str]["leg_status"] == "credited-unpaid"
    assert legs_by_id[d.pubkey_id_str]["wallet_address"] is None
    assert legs_by_id[d.pubkey_id_str]["amount"] == 200
    assert legs_by_id[m.pubkey_id_str]["leg_status"] == "routable"
    assert legs_by_id[m.pubkey_id_str]["wallet_address"] == "https://wallet.example/m"

    # Now bind D's wallet too and compile a fresh event with identical inputs.
    claims.record_wallet_binding(
        subject=d.pubkey_id_str, wallet_address="https://wallet.example/d",
        agent_id="agent:ac6-d", signer=d, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:01:01+00:00",
    )
    bound = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-ac6-bound", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:02:00+00:00",
    )
    rm_bound = bound["manifest"]["route_manifest"]
    assert rm_bound["payer_retained"] == rm["payer_retained"]
    bound_by_id = {leg["beneficiary_pubkey_id"]: leg["amount"] for leg in rm_bound["legs"]}
    assert bound_by_id[d.pubkey_id_str] == legs_by_id[d.pubkey_id_str]["amount"]
    assert bound_by_id[m.pubkey_id_str] == legs_by_id[m.pubkey_id_str]["amount"]


# ---------------------------------------------------------------------------
# AC7 -- determinism + idempotency
# ---------------------------------------------------------------------------


def test_ac7_determinism_and_idempotency(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "ac7-d")
    compiler = _signer(tmp_path, "ac7-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:ac7-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by="agent:ac7-d", agent_id="agent:ac7-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )

    kwargs = dict(
        event_kind="demo-sale", event_ref="evt-ac7", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:01:00+00:00",
    )

    r1 = compile_route_manifest(**kwargs)
    assert r1["newly_recorded"] is True

    r2 = compile_route_manifest(**kwargs)
    assert r2["newly_recorded"] is False
    assert r2["manifest_hash"] == r1["manifest_hash"]


# ---------------------------------------------------------------------------
# AC8 -- fail closed: unsigned routing_terms
# ---------------------------------------------------------------------------


def test_ac8_unsigned_routing_terms_raises_tamper_error(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "ac8-d")
    compiler = _signer(tmp_path, "ac8-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:ac8-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    unsigned_mh = _record_unsigned_routing_terms(
        tmp_log, tmp_claims_store, subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str,
        share_bps=1000, scope="standing", declared_by="agent:ac8-d", agent_id="agent:ac8-d",
        timestamp="2026-07-20T00:00:01+00:00",
    )

    with pytest.raises(RouteTamperError) as excinfo:
        compile_route_manifest(
            event_kind="demo-sale", event_ref="evt-ac8", subject=subject_mh,
            amount_value=500, asset_code="USD", asset_scale=2,
            agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
            timestamp="2026-07-20T00:01:00+00:00",
        )
    assert excinfo.value.failure_mode == "unsigned"
    assert unsigned_mh in str(excinfo.value)


# ---------------------------------------------------------------------------
# AC9 -- CLI happy path
# ---------------------------------------------------------------------------


def test_ac9_cli_happy_path(tmp_path, monkeypatch):
    attr_db = tmp_path / "attr.db"
    keys_dir = tmp_path / "keys"
    claims_db = tmp_path / "claims.db"
    agent_key = tmp_path / "agent-keys" / "cli.key"

    log = AttributionLog(attr_db)
    registry = PubkeyRegistry(keys_dir)

    monkeypatch.setenv("ZEPHYR_CLAIMS_DB", str(claims_db))
    claims._reset_claims_store()

    d = _contributor(tmp_path, registry, "cli-d")

    subject_mh = _make_content_deposit(
        log, d, registry, agent_id="agent:cli-d", payload={"work": "cli-test"},
        summary="cli test work", timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=5000,
        scope="standing", declared_by="agent:cli-d", agent_id="agent:cli-d",
        signer=d, registry=registry, recorder=log, timestamp="2026-07-20T00:00:01+00:00",
    )

    env = dict(os.environ)
    env.update(
        {
            "ZEPHYR_ATTRIBUTION_DB": str(attr_db),
            "ZEPHYR_KEYS_DIR": str(keys_dir),
            "ZEPHYR_AGENT_KEY_PATH": str(agent_key),
            "ZEPHYR_CLAIMS_DB": str(claims_db),
        }
    )

    result = subprocess.run(
        [
            sys.executable, "-m", "zephyr.route",
            "--event-kind", "demo-sale",
            "--event-ref", "evt-cli-ac9",
            "--subject", subject_mh,
            "--amount", "500",
            "--asset-code", "USD",
            "--asset-scale", "2",
            "--agent-id", "agent:route-cli-test",
        ],
        cwd=str(REPO_ROOT), env=env, capture_output=True, text=True, timeout=30,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["manifest_hash"].startswith("sha256:")
    assert payload["newly_recorded"] is True


# ---------------------------------------------------------------------------
# AC11 -- replay binding
# ---------------------------------------------------------------------------


def test_ac11_term_for_x_not_consumed_compiling_y(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "ac11-d")
    compiler = _signer(tmp_path, "ac11-compiler")

    subject_x = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:ac11-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    subject_y = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:ac11-d", payload={"work": "y"},
        summary="work y", timestamp="2026-07-20T00:00:01+00:00",
    )
    claims.record_routing_terms(
        subject=subject_x, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by="agent:ac11-d", agent_id="agent:ac11-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:02+00:00",
    )

    result = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-ac11-y", subject=subject_y,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:01:00+00:00",
    )
    rm = result["manifest"]["route_manifest"]
    assert rm["legs"] == []
    assert rm["payer_retained"] == 500


# ---------------------------------------------------------------------------
# AC12 -- replay guard
# ---------------------------------------------------------------------------


def test_ac12_identical_recompile_idempotent_no_second_row(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "ac12-d")
    compiler = _signer(tmp_path, "ac12-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:ac12-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )

    r1 = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-ac12", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
    )
    r2 = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-ac12", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
    )
    assert r2["newly_recorded"] is False
    assert r2["manifest_hash"] == r1["manifest_hash"]

    rows = [
        r for r in tmp_log.recent(limit=50, store_kind="route_manifest")
        if r["target_key"] == "evt-ac12"
    ]
    assert len(rows) == 1


def test_ac12_changed_amount_raises_replay_conflict_no_new_row(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "ac12b-d")
    compiler = _signer(tmp_path, "ac12b-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:ac12b-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )

    r1 = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-ac12b", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
    )

    with pytest.raises(RouteReplayConflict) as excinfo:
        compile_route_manifest(
            event_kind="demo-sale", event_ref="evt-ac12b", subject=subject_mh,
            amount_value=600, asset_code="USD", asset_scale=2,
            agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        )
    assert r1["manifest_hash"] in str(excinfo.value)

    rows = [
        r for r in tmp_log.recent(limit=50, store_kind="route_manifest")
        if r["target_key"] == "evt-ac12b"
    ]
    assert len(rows) == 1
    assert rows[0]["manifest_hash"] == r1["manifest_hash"]


# ---------------------------------------------------------------------------
# AC13 -- tamper detection
# ---------------------------------------------------------------------------


def test_ac13_hash_mismatch_on_edited_domain_row(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "ac13-d")
    compiler = _signer(tmp_path, "ac13-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:ac13-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    result = claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=1000,
        scope="standing", declared_by="agent:ac13-d", agent_id="agent:ac13-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )
    mh = result["manifest_hash"]

    # Bypass the helper: edit the domain row's share_bps directly.
    tmp_claims_store._conn.execute(
        "UPDATE routing_terms SET share_bps = 9999 WHERE manifest_hash = ?", (mh,)
    )
    tmp_claims_store._conn.commit()

    with pytest.raises(RouteTamperError) as excinfo:
        compile_route_manifest(
            event_kind="demo-sale", event_ref="evt-ac13-hash", subject=subject_mh,
            amount_value=500, asset_code="USD", asset_scale=2,
            agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
            timestamp="2026-07-20T00:01:00+00:00",
        )
    assert excinfo.value.failure_mode == "hash_mismatch"
    assert mh in str(excinfo.value)


def test_ac13_missing_envelope(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "ac13b-d")
    compiler = _signer(tmp_path, "ac13b-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:ac13b-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    fake_mh = "sha256:" + "0" * 64
    tmp_claims_store.insert_routing_terms(
        manifest_hash=fake_mh, subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str,
        share_bps=1000, basis="declared-contract", scope="standing", declared_by="agent:ac13b-d",
        note="", summary="ghost row", recorded_at="2026-07-20T00:00:01+00:00",
    )

    with pytest.raises(RouteTamperError) as excinfo:
        compile_route_manifest(
            event_kind="demo-sale", event_ref="evt-ac13-missing", subject=subject_mh,
            amount_value=500, asset_code="USD", asset_scale=2,
            agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
            timestamp="2026-07-20T00:01:00+00:00",
        )
    assert excinfo.value.failure_mode == "missing_envelope"


def test_ac13_unsigned_is_covered_by_ac8():
    """AC13 explicitly asserts this specific mode too; see test_ac8_unsigned_routing_terms_raises_tamper_error."""


# ---------------------------------------------------------------------------
# AC14 -- resolution supersession
# ---------------------------------------------------------------------------


def test_ac14_revocation_supersedes_with_allocation_byte_identical(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "ac14-d")
    compiler = _signer(tmp_path, "ac14-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:ac14-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by="agent:ac14-d", agent_id="agent:ac14-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )
    claims.record_wallet_binding(
        subject=d.pubkey_id_str, wallet_address="https://wallet.example/ac14-d",
        agent_id="agent:ac14-d", signer=d, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:00:02+00:00",
    )

    first = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-ac14", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:01:00+00:00",
    )
    first_rm = first["manifest"]["route_manifest"]
    first_leg = next(leg for leg in first_rm["legs"] if leg["beneficiary_pubkey_id"] == d.pubkey_id_str)
    assert first_leg["leg_status"] == "routable"

    claims.record_wallet_binding(
        subject=d.pubkey_id_str, wallet_address="https://wallet.example/ac14-d",
        agent_id="agent:ac14-d", revokes=True, signer=d, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:02:00+00:00",
    )

    second = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-ac14", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:03:00+00:00",
    )
    assert second["newly_recorded"] is True
    assert second["manifest_hash"] != first["manifest_hash"]
    second_rm = second["manifest"]["route_manifest"]
    assert second_rm["supersedes"] == first["manifest_hash"]
    assert second_rm["payer_retained"] == first_rm["payer_retained"]

    second_leg = next(leg for leg in second_rm["legs"] if leg["beneficiary_pubkey_id"] == d.pubkey_id_str)
    assert second_leg["amount"] == first_leg["amount"]
    assert second_leg["leg_status"] == "credited-unpaid"
    assert second_leg["wallet_address"] is None

    third = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-ac14", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:04:00+00:00",
    )
    assert third["newly_recorded"] is False
    assert third["manifest_hash"] == second["manifest_hash"]

    # The first manifest remains untouched in both stores.
    first_row = tmp_log.get(first["manifest_hash"], registry=tmp_registry)
    assert first_row is not None
    assert first_row["verification_status"] == "verified"
