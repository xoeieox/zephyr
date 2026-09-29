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

Rail U2a additions (zephyr-route-manifest-hardening-v0) -- prefixed
test_u2a_ac<N> to avoid colliding with the U0/U1 AC numbers above (the two
specs independently number their own acceptance criteria from 1):
  AC5   -- missing_domain_row is tamper (D2): deleted routing_terms /
           wallet_binding domain row with the deposit still present
  AC6   -- unregistered beneficiary_pubkey_id is tamper (D3): unknown_key
  AC7   -- revoked beneficiary is NOT tamper (D3): credited-unpaid,
           Void Principle preserved (other legs byte-identical)
  AC8   -- reverify_leg refuses a stale routable: binding_revoked /
           address_changed, never raises
  AC9   -- is_current_head catches mid-run supersession
  AC10  -- no behavioural drift: golden payload, hash is a pure function of
           payload, same-tree determinism
  AC11  -- conservation end-to-end on compiled manifest payloads (extends
           the AC4 grid to the compiler, including the pass-through split)
  AC12  -- the brute-force oracle is independent (Fraction arithmetic, no
           id(), no reference to _largest_remainder's internals)
  AC13  -- public surface pinned (__all__)
  AC13b -- malformed chain is never reported as absence
  AC13c -- describe_manifest_chain never raises
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
from fractions import Fraction
from pathlib import Path

import pytest

from zephyr import claims, routing
from zephyr.attribution import AttributionLog
from zephyr.registry import PubkeyRegistry
from zephyr.routing import (
    RouteChainError,
    RouteCompileError,
    RouteDepthExceeded,
    RouteReplayConflict,
    RouteTamperError,
    compile_route_manifest,
    describe_manifest_chain,
    get_manifest_for_event,
    is_current_head,
    reverify_leg,
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
    """Independent reference oracle: exact-rational largest remainder.

    Rewritten for rail U2a / AC12 - the prior version replicated
    _largest_remainder's own sort key and used id()-based bump-set
    construction, so it structurally could not catch a tie-ordering
    deviation in the implementation it was meant to check. This version:
      - computes remainders via exact Fraction arithmetic (not the
        implementation's floor-division/modulo), an independent
        arithmetic path;
      - derives the SAME total order the spec mandates - larger remainder
        first, beneficiaries before the payer bucket on an exact tie,
        lexicographic pubkey_id as the final tiebreak - from scratch, with
        no reference to routing._largest_remainder's code or sort key;
      - identifies bumped buckets by (business id, is_payer), never by
        Python's id() (a memory address, not a stable identity).
    pubkey_id is a real identity (no two beneficiary buckets can share one)
    and the payer bucket is disjoint and always sorts last on ties, so this
    key is total - there is no residual tie for the oracle to break
    arbitrarily.
    """
    scored = []
    for bid, bps, is_payer in bucket_specs:
        frac = Fraction(amount * bps, 10000)
        floor = frac.numerator // frac.denominator
        remainder = frac - floor
        scored.append({"id": bid, "is_payer": is_payer, "floor": floor, "remainder": remainder})

    leftover = amount - sum(s["floor"] for s in scored)
    order = sorted(scored, key=lambda s: (-s["remainder"], s["is_payer"], s["id"] or ""))
    bumped = {(s["id"], s["is_payer"]) for s in order[:leftover]}

    return {
        s["id"]: s["floor"] + (1 if (s["id"], s["is_payer"]) in bumped else 0)
        for s in scored
    }


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
    """Unit-level, not compile-level (rail U2a / D2 changed this test's shape):
    a ghost domain row with no backing deposit is no longer reachable via
    compile_route_manifest at all - the gather stage is now deposit-
    authoritative (D2), so a domain row nothing ever deposited is simply
    never gathered, not tamper (see test_u2a_ac5_missing_domain_row_is_tamper
    for the attack D2 actually closes: a deposit whose domain row was
    deleted). verify_routing_terms_row's missing_envelope path is still real
    and still tested, just no longer reachable through the compiler for this
    exact construction."""
    d = _contributor(tmp_path, tmp_registry, "ac13b-d")

    fake_mh = "sha256:" + "0" * 64
    tmp_claims_store.insert_routing_terms(
        manifest_hash=fake_mh, subject="sha256:unrelated-subject", beneficiary_pubkey_id=d.pubkey_id_str,
        share_bps=1000, basis="declared-contract", scope="standing", declared_by="agent:ac13b-d",
        note="", summary="ghost row", recorded_at="2026-07-20T00:00:01+00:00",
    )
    row = tmp_claims_store.list_routing_terms_for_subject("sha256:unrelated-subject")[0]

    result = claims.verify_routing_terms_row(row, log=tmp_log, registry=tmp_registry)
    assert result.ok is False
    assert result.failure_mode == "missing_envelope"


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


# ===========================================================================
# Rail U2a (zephyr-route-manifest-hardening-v0) additions
# ===========================================================================

# ---------------------------------------------------------------------------
# AC5 -- missing_domain_row is tamper (D2)
# ---------------------------------------------------------------------------


def test_u2a_ac5_missing_domain_row_routing_terms_is_tamper(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "u2aac5-d")
    compiler = _signer(tmp_path, "u2aac5-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:u2aac5-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    result = claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by="agent:u2aac5-d", agent_id="agent:u2aac5-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )
    mh = result["manifest_hash"]

    # Delete the domain row directly - the signed deposit remains in attribution.db.
    tmp_claims_store._conn.execute("DELETE FROM routing_terms WHERE manifest_hash = ?", (mh,))
    tmp_claims_store._conn.commit()

    with pytest.raises(RouteTamperError) as excinfo:
        compile_route_manifest(
            event_kind="demo-sale", event_ref="evt-u2aac5-terms", subject=subject_mh,
            amount_value=500, asset_code="USD", asset_scale=2,
            agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
            timestamp="2026-07-20T00:01:00+00:00",
        )
    assert excinfo.value.failure_mode == "missing_domain_row"
    assert mh in str(excinfo.value)

    # The compile does NOT instead succeed with a smaller leg set.
    assert tmp_claims_store.latest_route_manifest_for_event("evt-u2aac5-terms") is None


def test_u2a_ac5_missing_domain_row_wallet_binding_is_tamper(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "u2aac5wb-d")
    compiler = _signer(tmp_path, "u2aac5wb-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:u2aac5wb-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by="agent:u2aac5wb-d", agent_id="agent:u2aac5wb-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )
    binding_result = claims.record_wallet_binding(
        subject=d.pubkey_id_str, wallet_address="https://wallet.example/u2aac5wb-d",
        agent_id="agent:u2aac5wb-d", signer=d, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:00:02+00:00",
    )
    binding_mh = binding_result["manifest_hash"]

    tmp_claims_store._conn.execute("DELETE FROM wallet_bindings WHERE manifest_hash = ?", (binding_mh,))
    tmp_claims_store._conn.commit()

    with pytest.raises(RouteTamperError) as excinfo:
        compile_route_manifest(
            event_kind="demo-sale", event_ref="evt-u2aac5-wallet", subject=subject_mh,
            amount_value=500, asset_code="USD", asset_scale=2,
            agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
            timestamp="2026-07-20T00:01:00+00:00",
        )
    assert excinfo.value.failure_mode == "missing_domain_row"
    assert binding_mh in str(excinfo.value)
    assert tmp_claims_store.latest_route_manifest_for_event("evt-u2aac5-wallet") is None


# ---------------------------------------------------------------------------
# AC6 -- unregistered beneficiary is tamper (D3)
# ---------------------------------------------------------------------------


def test_u2a_ac6_unregistered_beneficiary_is_tamper(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "u2aac6-d")
    compiler = _signer(tmp_path, "u2aac6-compiler")
    ghost = _signer(tmp_path, "u2aac6-ghost")  # never registered

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:u2aac6-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )

    # Bypass record_routing_terms's own registry check: sign+deposit directly
    # (as D, a registered signer), then insert the domain row, naming an
    # unregistered beneficiary_pubkey_id.
    from zephyr.attribution import record_signed

    payload = {
        "routing_terms": {
            "subject": subject_mh, "beneficiary_pubkey_id": ghost.pubkey_id_str,
            "share_bps": 4000, "basis": "declared-contract", "scope": "standing",
            "declared_by": "agent:u2aac6-d", "note": "",
        }
    }
    summary = f"routing term: {subject_mh} -> {ghost.pubkey_id_str} 4000bps (standing)"
    result = record_signed(
        payload, agent_id="agent:u2aac6-d", tool="zephyr:routing-terms",
        store_kind="routing_terms", key=subject_mh, signer=d, registry=tmp_registry,
        recorder=tmp_log, summary=summary, timestamp="2026-07-20T00:00:01+00:00",
    )
    mh = result["manifest_hash"]
    tmp_claims_store.insert_routing_terms(
        manifest_hash=mh, subject=subject_mh, beneficiary_pubkey_id=ghost.pubkey_id_str,
        share_bps=4000, basis="declared-contract", scope="standing", declared_by="agent:u2aac6-d",
        note="", summary=summary, recorded_at="2026-07-20T00:00:01+00:00",
    )

    with pytest.raises(RouteTamperError) as excinfo:
        compile_route_manifest(
            event_kind="demo-sale", event_ref="evt-u2aac6", subject=subject_mh,
            amount_value=500, asset_code="USD", asset_scale=2,
            agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
            timestamp="2026-07-20T00:01:00+00:00",
        )
    assert excinfo.value.failure_mode == "unknown_key"
    assert ghost.pubkey_id_str in str(excinfo.value)
    assert tmp_claims_store.latest_route_manifest_for_event("evt-u2aac6") is None


# ---------------------------------------------------------------------------
# AC7 -- revoked beneficiary is NOT tamper (D3, Void Principle)
# ---------------------------------------------------------------------------


def test_u2a_ac7_revoked_beneficiary_is_not_tamper(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "u2aac7-d")
    m = _contributor(tmp_path, tmp_registry, "u2aac7-m")
    compiler = _signer(tmp_path, "u2aac7-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:u2aac7-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by="agent:u2aac7-d", agent_id="agent:u2aac7-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=m.pubkey_id_str, share_bps=2500,
        scope="standing", declared_by="agent:u2aac7-m", agent_id="agent:u2aac7-m",
        signer=m, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:02+00:00",
    )
    # M has a valid, currently-bound wallet - proving revocation forces
    # credited-unpaid even when a routable wallet would otherwise resolve.
    claims.record_wallet_binding(
        subject=m.pubkey_id_str, wallet_address="https://wallet.example/u2aac7-m",
        agent_id="agent:u2aac7-m", signer=m, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:00:03+00:00",
    )

    before = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-u2aac7-before", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:01:00+00:00",
    )
    before_rm = before["manifest"]["route_manifest"]
    before_by_id = {leg["beneficiary_pubkey_id"]: leg for leg in before_rm["legs"]}
    assert before_by_id[m.pubkey_id_str]["leg_status"] == "routable"

    tmp_registry.revoke(m.pubkey_id_str, reason="rotated")

    after = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-u2aac7-after", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:02:00+00:00",
    )
    after_rm = after["manifest"]["route_manifest"]
    after_by_id = {leg["beneficiary_pubkey_id"]: leg for leg in after_rm["legs"]}

    assert after_by_id[m.pubkey_id_str]["leg_status"] == "credited-unpaid"
    assert after_by_id[m.pubkey_id_str]["wallet_address"] is None
    assert after_by_id[m.pubkey_id_str]["amount"] == before_by_id[m.pubkey_id_str]["amount"]
    assert after_by_id[d.pubkey_id_str]["amount"] == before_by_id[d.pubkey_id_str]["amount"]
    assert after_rm["payer_retained"] == before_rm["payer_retained"]


# ---------------------------------------------------------------------------
# AC8 -- reverify_leg refuses a stale routable (D4)
# ---------------------------------------------------------------------------


def test_u2a_ac8_reverify_leg_refuses_stale_routable(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "u2aac8-d")
    compiler = _signer(tmp_path, "u2aac8-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:u2aac8-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by="agent:u2aac8-d", agent_id="agent:u2aac8-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )
    claims.record_wallet_binding(
        subject=d.pubkey_id_str, wallet_address="https://wallet.example/u2aac8-d",
        agent_id="agent:u2aac8-d", signer=d, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:00:02+00:00",
    )

    result = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-u2aac8", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:01:00+00:00",
    )
    manifest = result["manifest"]["route_manifest"]
    leg = next(l for l in manifest["legs"] if l["beneficiary_pubkey_id"] == d.pubkey_id_str)
    assert leg["leg_status"] == "routable"

    claims.record_wallet_binding(
        subject=d.pubkey_id_str, wallet_address="https://wallet.example/u2aac8-d",
        agent_id="agent:u2aac8-d", revokes=True, signer=d, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:02:00+00:00",
    )

    outcome = reverify_leg(manifest, leg, store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert outcome == {"payable": False, "wallet_address": None, "reason": "binding_revoked"}

    # Rebind D to a DIFFERENT wallet address.
    claims.record_wallet_binding(
        subject=d.pubkey_id_str, wallet_address="https://wallet.example/u2aac8-d-NEW",
        agent_id="agent:u2aac8-d", signer=d, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:03:00+00:00",
    )
    outcome2 = reverify_leg(manifest, leg, store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert outcome2["payable"] is False
    assert outcome2["reason"] == "address_changed"
    assert outcome2["wallet_address"] == "https://wallet.example/u2aac8-d-NEW"


def test_u2a_ac8_reverify_leg_unverified_row_gets_no_named_verdict(
    tmp_path, tmp_log, tmp_registry, tmp_claims_store
):
    # H2 coverage (a): binding rows ARE present but the integrity bind FAILS
    # and the raw revokes cell is False - the verdict must be the generic
    # "binding_unverified", never a named verdict derived from unverified data.
    d = _contributor(tmp_path, tmp_registry, "u2aac8u-d")
    compiler = _signer(tmp_path, "u2aac8u-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:u2aac8u-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by="agent:u2aac8u-d", agent_id="agent:u2aac8u-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )
    claims.record_wallet_binding(
        subject=d.pubkey_id_str, wallet_address="https://wallet.example/u2aac8u-d",
        agent_id="agent:u2aac8u-d", signer=d, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:00:02+00:00",
    )

    result = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-u2aac8u", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:01:00+00:00",
    )
    manifest = result["manifest"]["route_manifest"]
    leg = next(l for l in manifest["legs"] if l["beneficiary_pubkey_id"] == d.pubkey_id_str)
    assert leg["leg_status"] == "routable"

    rows = tmp_claims_store.list_wallet_bindings_for_subject(d.pubkey_id_str)
    assert rows and all(r["revokes"] == 0 for r in rows)

    # Break the integrity bind WITHOUT touching the revokes cell: the stored
    # columns no longer reproduce the committed manifest_hash.
    tmp_claims_store._conn.execute(
        "UPDATE wallet_bindings SET note = 'flipped' WHERE manifest_hash = ?",
        (max(rows, key=lambda r: r["seq"])["manifest_hash"],),
    )
    tmp_claims_store._conn.commit()

    outcome = reverify_leg(manifest, leg, store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert outcome == {"payable": False, "wallet_address": None, "reason": "binding_unverified"}


def test_u2a_ac8_reverify_leg_tampered_revokes_cell_is_unverified_not_revoked(
    tmp_path, tmp_log, tmp_registry, tmp_claims_store
):
    # H2 coverage (b), the pinned behavior delta: a row whose RAW revokes cell
    # is set but which FAILS the integrity bind must report
    # "binding_unverified", NOT "binding_revoked". Unverified data produces no
    # named verdict - the fail-closed direction.
    d = _contributor(tmp_path, tmp_registry, "u2aac8t-d")
    compiler = _signer(tmp_path, "u2aac8t-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:u2aac8t-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by="agent:u2aac8t-d", agent_id="agent:u2aac8t-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )
    claims.record_wallet_binding(
        subject=d.pubkey_id_str, wallet_address="https://wallet.example/u2aac8t-d",
        agent_id="agent:u2aac8t-d", signer=d, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:00:02+00:00",
    )

    result = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-u2aac8t", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:01:00+00:00",
    )
    manifest = result["manifest"]["route_manifest"]
    leg = next(l for l in manifest["legs"] if l["beneficiary_pubkey_id"] == d.pubkey_id_str)
    assert leg["leg_status"] == "routable"

    latest = max(
        tmp_claims_store.list_wallet_bindings_for_subject(d.pubkey_id_str),
        key=lambda r: r["seq"],
    )
    # Flip the revokes cell directly in the domain table: the raw cell now says
    # "revoked", but the committed manifest_hash no longer covers it, so the
    # integrity bind fails.
    tmp_claims_store._conn.execute(
        "UPDATE wallet_bindings SET revokes = 1 WHERE manifest_hash = ?",
        (latest["manifest_hash"],),
    )
    tmp_claims_store._conn.commit()

    outcome = reverify_leg(manifest, leg, store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert outcome["payable"] is False
    assert outcome["reason"] == "binding_unverified"
    assert outcome["reason"] != "binding_revoked"
    assert outcome["wallet_address"] is None


# ---------------------------------------------------------------------------
# AC9 -- is_current_head catches mid-run supersession (D4)
# ---------------------------------------------------------------------------


def test_u2a_ac9_is_current_head_catches_mid_run_supersession(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "u2aac9-d")
    compiler = _signer(tmp_path, "u2aac9-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:u2aac9-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by="agent:u2aac9-d", agent_id="agent:u2aac9-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )
    claims.record_wallet_binding(
        subject=d.pubkey_id_str, wallet_address="https://wallet.example/u2aac9-d",
        agent_id="agent:u2aac9-d", signer=d, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:00:02+00:00",
    )

    first = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-u2aac9", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:01:00+00:00",
    )
    captured_hash = first["manifest_hash"]
    assert is_current_head("evt-u2aac9", captured_hash, store=tmp_claims_store) is True

    claims.record_wallet_binding(
        subject=d.pubkey_id_str, wallet_address="https://wallet.example/u2aac9-d",
        agent_id="agent:u2aac9-d", revokes=True, signer=d, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:02:00+00:00",
    )
    second = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-u2aac9", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:03:00+00:00",
    )
    assert second["manifest_hash"] != captured_hash

    assert is_current_head("evt-u2aac9", captured_hash, store=tmp_claims_store) is False
    assert is_current_head("evt-u2aac9", second["manifest_hash"], store=tmp_claims_store) is True


# ---------------------------------------------------------------------------
# AC10 -- no behavioural drift
# ---------------------------------------------------------------------------

# Pinned golden literal for the worked example (amount 500, direct terms
# {D: 4000bps, M: 2500bps}, parent standing term on D's work {P: 1000bps} ->
# payer_retained 175, legs D=180 M=125 P=20, total 500 exact - the same
# worked example as test_ac5_worked_example_verbatim). Every ed25519:...
# pubkey_id-shaped and sha256:... manifest_hash-shaped string is replaced by
# a stable placeholder (documented substitution: legs sorted by amount first
# - a business-stable, non-random property in this specific example, since
# 20/125/180 are distinct - then placeholders assigned by first-appearance
# order walking dict keys in sorted order). This is what actually varies
# run-to-run: pubkey_ids come from freshly generated Ed25519 keys, and any
# manifest_hash that embeds one (routing_terms term_refs) varies with it.
_AC10_GOLDEN_PAYLOAD = {
    "amount_in": {"asset_code": "USD", "asset_scale": 2, "value": 500},
    "depth": 1,
    "event": {"kind": "demo-sale", "ref": "evt-u2aac10-worked", "subject": "HASH#0"},
    "legs": [
        {
            "amount": 20,
            "beneficiary_pubkey_id": "PUBKEY#0",
            "derivation": {
                "algorithm": "declared-split+single-passthrough-v0",
                "edge_refs": ["HASH#0", "HASH#1"],
                "term_refs": ["HASH#2", "HASH#3"],
            },
            "leg_status": "credited-unpaid",
            "wallet_address": None,
        },
        {
            "amount": 125,
            "beneficiary_pubkey_id": "PUBKEY#1",
            "derivation": {
                "algorithm": "declared-split+single-passthrough-v0",
                "edge_refs": ["HASH#0"],
                "term_refs": ["HASH#4"],
            },
            "leg_status": "credited-unpaid",
            "wallet_address": None,
        },
        {
            "amount": 180,
            "beneficiary_pubkey_id": "PUBKEY#2",
            "derivation": {
                "algorithm": "declared-split+single-passthrough-v0",
                "edge_refs": ["HASH#0", "HASH#1"],
                "term_refs": ["HASH#2", "HASH#3"],
            },
            "leg_status": "credited-unpaid",
            "wallet_address": None,
        },
    ],
    "payer_retained": 175,
    "schema": "zephyr-route-manifest-v0",
}


def _normalize_run_varying(route_manifest):
    """Documented substitution for AC10 - see _AC10_GOLDEN_PAYLOAD's comment."""
    rm = dict(route_manifest)
    rm["legs"] = sorted(route_manifest["legs"], key=lambda leg: leg["amount"])

    pubkey_map, hash_map = {}, {}

    def _sub(v):
        if isinstance(v, str):
            if v.startswith("ed25519:"):
                return pubkey_map.setdefault(v, f"PUBKEY#{len(pubkey_map)}")
            if v.startswith("sha256:"):
                return hash_map.setdefault(v, f"HASH#{len(hash_map)}")
            return v
        if isinstance(v, dict):
            return {k: _sub(v[k]) for k in sorted(v.keys())}
        if isinstance(v, list):
            return [_sub(x) for x in v]
        return v

    return _sub(rm)


def test_u2a_ac10_golden_payload_shape(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    """Manual cross-commit check (per AC10's closing paragraph, reported in
    the PR body, not asserted here): the worked example was run on clean
    1f67ce6 before any code change and its normalized payload matched this
    same golden literal - D1/D1b/D2/D3 change no behaviour on an
    already-well-formed, already-registered, already-non-deleted input."""
    d = _contributor(tmp_path, tmp_registry, "u2aac10-d")
    m = _contributor(tmp_path, tmp_registry, "u2aac10-m")
    p = _contributor(tmp_path, tmp_registry, "u2aac10-p")
    compiler = _signer(tmp_path, "u2aac10-compiler")

    parent_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:u2aac10-d", payload={"work": "original"},
        summary="D's original work", timestamp="2026-07-19T00:00:00+00:00",
    )
    subject_mh = _make_content_deposit(
        tmp_log, m, tmp_registry, agent_id="agent:u2aac10-m", payload={"work": "derivative"},
        summary="derivative work", timestamp="2026-07-19T01:00:00+00:00", derived_from=parent_mh,
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by="agent:u2aac10-d", agent_id="agent:u2aac10-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-19T02:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=m.pubkey_id_str, share_bps=2500,
        scope="standing", declared_by="agent:u2aac10-m", agent_id="agent:u2aac10-m",
        signer=m, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-19T02:00:01+00:00",
    )
    claims.record_routing_terms(
        subject=parent_mh, beneficiary_pubkey_id=p.pubkey_id_str, share_bps=1000,
        scope="standing", declared_by="agent:u2aac10-d", agent_id="agent:u2aac10-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-19T02:00:02+00:00",
    )

    result = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-u2aac10-worked", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:00:00+00:00",
    )
    normalized = _normalize_run_varying(result["manifest"]["route_manifest"])
    assert normalized == _AC10_GOLDEN_PAYLOAD


def test_u2a_ac10_hash_is_pure_function_of_payload(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    """The canonical hash algorithm, written out here (sorted keys,
    separators (",", ":"), UTF-8, sha256) rather than by calling
    archetypes_core.provenance._canonical_json or
    zephyr.claims._compute_manifest_hash."""
    d = _contributor(tmp_path, tmp_registry, "u2aac10hash-d")
    compiler = _signer(tmp_path, "u2aac10hash-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:u2aac10hash-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by="agent:u2aac10hash-d", agent_id="agent:u2aac10hash-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )

    result = compile_route_manifest(
        event_kind="demo-sale", event_ref="evt-u2aac10hash", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:01:00+00:00",
    )

    envelope = tmp_log.get(result["manifest_hash"], registry=tmp_registry, verify=False)
    prov_dict = json.loads(envelope["provenance_json"])
    for k in ("manifest_hash", "signature", "pubkey_id"):
        prov_dict.pop(k, None)

    route_row = tmp_claims_store.raw_route_manifest_rows("evt-u2aac10hash")[0]
    summary = route_row["summary"]
    payload = result["manifest"]

    hashable = json.dumps(
        {"payload": payload, "provenance": prov_dict, "summary": summary},
        sort_keys=True, separators=(",", ":"),
    )
    expected_hash = "sha256:" + hashlib.sha256(hashable.encode("utf-8")).hexdigest()

    assert expected_hash == result["manifest_hash"]


def test_u2a_ac10_same_tree_determinism(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "u2aac10det-d")
    compiler = _signer(tmp_path, "u2aac10det-compiler")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:u2aac10det-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by="agent:u2aac10det-d", agent_id="agent:u2aac10det-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )

    kwargs = dict(
        event_kind="demo-sale", event_ref="evt-u2aac10det", subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:01:00+00:00",
    )
    r1 = compile_route_manifest(**kwargs)
    r2 = compile_route_manifest(**kwargs)
    assert r1["manifest_hash"] == r2["manifest_hash"]
    assert r2["newly_recorded"] is False


# ---------------------------------------------------------------------------
# AC11 -- conservation end-to-end on compiled manifest payloads (D5)
# ---------------------------------------------------------------------------


def _compile_direct_grid_case(tmp_path, tmp_log, tmp_registry, event_ref, amount, bps_set):
    d = _contributor(tmp_path, tmp_registry, f"{event_ref}-subj")
    compiler = _signer(tmp_path, f"{event_ref}-compiler")
    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id=f"agent:{event_ref}-subj", payload={"work": event_ref},
        summary=f"work {event_ref}", timestamp="2026-07-20T00:00:00+00:00",
    )
    for i, bps in enumerate(bps_set):
        b = _contributor(tmp_path, tmp_registry, f"{event_ref}-b{i}")
        claims.record_routing_terms(
            subject=subject_mh, beneficiary_pubkey_id=b.pubkey_id_str, share_bps=bps,
            scope="standing", declared_by=f"agent:{event_ref}-b{i}", agent_id=f"agent:{event_ref}-b{i}",
            signer=b, registry=tmp_registry, recorder=tmp_log,
            timestamp=f"2026-07-20T00:00:{i + 1:02d}+00:00",
        )
    result = compile_route_manifest(
        event_kind="demo-sale", event_ref=event_ref, subject=subject_mh,
        amount_value=amount, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:01:00+00:00",
    )
    return result["manifest"]["route_manifest"]


@pytest.mark.parametrize("bps_set", GRID_BPS_SETS, ids=lambda b: "-".join(map(str, b)))
@pytest.mark.parametrize("amount", GRID_AMOUNTS)
def test_u2a_ac11_conservation_end_to_end(tmp_path, tmp_log, tmp_registry, tmp_claims_store, amount, bps_set):
    event_ref = f"evt-u2aac11-{amount}-{'-'.join(map(str, bps_set))}"
    rm = _compile_direct_grid_case(tmp_path, tmp_log, tmp_registry, event_ref, amount, bps_set)
    assert rm["payer_retained"] + sum(leg["amount"] for leg in rm["legs"]) == amount
    assert rm["payer_retained"] >= 0
    assert all(leg["amount"] >= 0 for leg in rm["legs"])


@pytest.mark.parametrize("amount", [1, 2, 3, 500, 999999, 1000003])
def test_u2a_ac11_conservation_with_passthrough_split(tmp_path, tmp_log, tmp_registry, tmp_claims_store, amount):
    """The AC4 grid never exercised the pass-through split (routing.py:305-317)
    - a second allocation absent from the grid entirely. Closes that gap."""
    event_ref = f"evt-u2aac11-pt-{amount}"
    d = _contributor(tmp_path, tmp_registry, f"{event_ref}-d")
    m = _contributor(tmp_path, tmp_registry, f"{event_ref}-m")
    p = _contributor(tmp_path, tmp_registry, f"{event_ref}-p")
    compiler = _signer(tmp_path, f"{event_ref}-compiler")

    parent_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id=f"agent:{event_ref}-d", payload={"work": "original"},
        summary="original", timestamp="2026-07-19T00:00:00+00:00",
    )
    subject_mh = _make_content_deposit(
        tmp_log, m, tmp_registry, agent_id=f"agent:{event_ref}-m", payload={"work": "derivative"},
        summary="derivative", timestamp="2026-07-19T01:00:00+00:00", derived_from=parent_mh,
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by=f"agent:{event_ref}-d", agent_id=f"agent:{event_ref}-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-19T02:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=m.pubkey_id_str, share_bps=2500,
        scope="standing", declared_by=f"agent:{event_ref}-m", agent_id=f"agent:{event_ref}-m",
        signer=m, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-19T02:00:01+00:00",
    )
    claims.record_routing_terms(
        subject=parent_mh, beneficiary_pubkey_id=p.pubkey_id_str, share_bps=1000,
        scope="standing", declared_by=f"agent:{event_ref}-d", agent_id=f"agent:{event_ref}-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-19T02:00:02+00:00",
    )

    result = compile_route_manifest(
        event_kind="demo-sale", event_ref=event_ref, subject=subject_mh,
        amount_value=amount, asset_code="USD", asset_scale=2,
        agent_id="agent:route-test", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:00:00+00:00",
    )
    rm = result["manifest"]["route_manifest"]
    assert rm["depth"] == 1
    assert rm["payer_retained"] + sum(leg["amount"] for leg in rm["legs"]) == amount
    assert all(leg["amount"] >= 0 for leg in rm["legs"])
    assert rm["payer_retained"] >= 0


# ---------------------------------------------------------------------------
# AC12 -- the brute-force oracle is independent (D5)
# ---------------------------------------------------------------------------


def test_u2a_ac12_oracle_is_independent():
    """No id() use, no reference to _largest_remainder's own code/sort key
    (asserted by inspection), and the oracle must actually discriminate a
    wrong tie order rather than always agreeing with the real implementation
    by construction."""
    import inspect

    # co_names catches actual references to the id() builtin, unlike a naive
    # substring search over source text (which also matches "id()" appearing
    # in comments/docstrings).
    assert "id" not in _brute_force_allocate.__code__.co_names
    src = inspect.getsource(_brute_force_allocate)
    assert "_largest_remainder(" not in src
    assert "Fraction" in src

    amount = 3
    buckets = [
        {"id": "b0", "bps": 2500, "is_payer": False},
        {"id": "b1", "bps": 2500, "is_payer": False},
        {"id": "b2", "bps": 2500, "is_payer": False},
        {"id": None, "bps": 2500, "is_payer": True},
    ]
    ref = _brute_force_allocate(amount, [(b["id"], b["bps"], b["is_payer"]) for b in buckets])
    real = routing._largest_remainder(amount, buckets)
    real_by_id = {b["id"]: b["amount"] for b in real}
    assert ref == real_by_id

    wrong_tie_order = {"b0": 0, "b1": 1, "b2": 1, None: 1}  # payer bumped ahead of a beneficiary
    assert wrong_tie_order != ref


# ---------------------------------------------------------------------------
# AC13 / AC13b / AC13c -- executor contract surface
# ---------------------------------------------------------------------------


def test_u2a_ac13_public_surface_pinned():
    assert set(routing.__all__) >= {
        "compile_route_manifest", "get_manifest_for_event", "is_current_head",
        "reverify_leg", "describe_manifest_chain", "RouteTamperError", "RouteChainError",
    }
    assert set(claims.__all__) >= {"resolve_wallet", "RouteChainError"}


def test_u2a_ac13b_malformed_chain_never_reported_as_absence(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    event_ref = "evt-u2aac13b-fork"
    tmp_claims_store._conn.execute("DROP INDEX IF EXISTS route_manifests_chain_unique")
    tmp_claims_store._conn.commit()

    root = "sha256:" + "1" * 64
    tmp_claims_store._conn.execute(
        "INSERT INTO route_manifests (manifest_hash, event_ref, payload_json, summary, recorded_at, supersedes) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (root, event_ref, "{}", "root", "2026-07-20T00:00:00+00:00", None),
    )
    tmp_claims_store._conn.execute(
        "INSERT INTO route_manifests (manifest_hash, event_ref, payload_json, summary, recorded_at, supersedes) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("sha256:" + "2" * 64, event_ref, "{}", "child-a", "2026-07-20T00:00:01+00:00", root),
    )
    tmp_claims_store._conn.execute(
        "INSERT INTO route_manifests (manifest_hash, event_ref, payload_json, summary, recorded_at, supersedes) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("sha256:" + "3" * 64, event_ref, "{}", "child-b", "2026-07-20T00:00:02+00:00", root),
    )
    tmp_claims_store._conn.commit()

    with pytest.raises(RouteChainError) as excinfo:
        get_manifest_for_event(event_ref, store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert excinfo.value.failure_mode == "forked_chain"


def test_u2a_ac13c_describe_manifest_chain_never_raises(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    tmp_claims_store._conn.execute("DROP INDEX IF EXISTS route_manifests_chain_unique")
    tmp_claims_store._conn.commit()

    def _insert(event_ref, mh, supersedes):
        tmp_claims_store._conn.execute(
            "INSERT INTO route_manifests (manifest_hash, event_ref, payload_json, summary, recorded_at, supersedes) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (mh, event_ref, "{}", "x", "2026-07-20T00:00:00+00:00", supersedes),
        )
        tmp_claims_store._conn.commit()

    # fork
    fork_ref = "evt-u2aac13c-fork"
    root = "sha256:" + "a" * 64
    child_a, child_b = "sha256:" + "b" * 64, "sha256:" + "c" * 64
    _insert(fork_ref, root, None)
    _insert(fork_ref, child_a, root)
    _insert(fork_ref, child_b, root)
    diag = describe_manifest_chain(fork_ref, store=tmp_claims_store)
    assert diag["well_formed"] is False
    assert diag["failure_mode"] == "forked_chain"
    assert set(diag["heads"]) == {child_a, child_b}
    assert len(diag["rows"]) == 3

    # cycle
    cycle_ref = "evt-u2aac13c-cycle"
    x, y = "sha256:" + "d" * 64, "sha256:" + "e" * 64
    _insert(cycle_ref, x, y)
    _insert(cycle_ref, y, x)
    diag2 = describe_manifest_chain(cycle_ref, store=tmp_claims_store)
    assert diag2["well_formed"] is False
    assert diag2["failure_mode"] == "cycle"

    # orphaned: a proper 2-row chain plus a disconnected 2-cycle
    orphan_ref = "evt-u2aac13c-orphan"
    r1 = "sha256:" + "f0" + "0" * 62
    h = "sha256:" + "f1" + "0" * 62
    sx, sy = "sha256:" + "f2" + "0" * 62, "sha256:" + "f3" + "0" * 62
    _insert(orphan_ref, r1, None)
    _insert(orphan_ref, h, r1)
    _insert(orphan_ref, sx, sy)
    _insert(orphan_ref, sy, sx)
    diag3 = describe_manifest_chain(orphan_ref, store=tmp_claims_store)
    assert diag3["well_formed"] is False
    assert diag3["failure_mode"] == "orphaned"

    # multiple_roots
    roots_ref = "evt-u2aac13c-roots"
    _insert(roots_ref, "sha256:" + "9" * 64, None)
    _insert(roots_ref, "sha256:" + "8" * 64, None)
    diag4 = describe_manifest_chain(roots_ref, store=tmp_claims_store)
    assert diag4["well_formed"] is False
    assert diag4["failure_mode"] == "multiple_roots"

    # well-formed
    ok_ref = "evt-u2aac13c-ok"
    ok_root = "sha256:" + "5" * 64
    ok_head = "sha256:" + "6" * 64
    _insert(ok_ref, ok_root, None)
    _insert(ok_ref, ok_head, ok_root)
    diag5 = describe_manifest_chain(ok_ref, store=tmp_claims_store)
    assert diag5["well_formed"] is True
    assert diag5["failure_mode"] is None
    assert diag5["heads"] == [ok_head]
