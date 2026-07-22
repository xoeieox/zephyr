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

Rail U2a additions (zephyr-route-manifest-hardening-v0) -- prefixed
test_u2a_ac<N> to avoid colliding with the U0 AC numbers above (the two
specs independently number their own acceptance criteria from 1):
  AC1   -- chain walk beats timestamps (D1 regression proof)
  AC2   -- fork rejected at write: RouteChainError("supersedes_not_head"),
           no row inserted
  AC3   -- malformed chains fail closed, never guess: forked_chain / cycle /
           orphaned / multiple_roots, each naming .event_ref
  AC4   -- idempotent insert of an identical manifest_hash is a no-op
  AC4b  -- fork guard is atomic under concurrency (threads + processes)
  AC4c  -- wallet-binding resolution ignores caller timestamps (D1b
           regression proof); revoking the latest fails closed, no fallback
  AC4d  -- seq is not caller-settable; strictly increasing
  AC4e  -- the schema backstop (COALESCE unique index) holds independently
           of the application guard
  AC13d -- the seq migration is idempotent and preserves every guarantee

Rail U2b additions (zephyr-route-executor-foundation-v0) -- prefixed
test_u2b_ac<N> to avoid colliding with the U0/U2a AC numbers above:
  AC1  -- receipt dual-write round-trips through route_receipts_for_manifest
  AC2  -- settled requires non-null op_payment_id + all three amount fields
  AC3  -- settled against a credited-unpaid leg raises not_routable
  AC4  -- settled with sent_value != leg amount raises amount_mismatch
  AC5  -- terminal idempotency: exact-repeat writes nothing, newly_recorded=False
  AC6  -- terminal conflict raises outcome_conflict
  AC7  -- failed then settled supersedes; partial unique index still holds
  AC8  -- receipt against a superseded/stale manifest_hash raises not_head
  AC9  -- receipt for a beneficiary_pubkey_id absent from the head raises no_such_leg
  AC10 -- RouteChainError from a wedged chain propagates unchanged
  AC11 -- route_receipts_for_manifest skips an integrity-failed (orphan) receipt
  AC12 -- two concurrent terminal writes for one leg: exactly one wins
  AC13 -- conservation end-to-end (the spec's global AC12): payer_retained +
          settled + skipped leg amounts == amount_in, joined on the manifest
"""

from __future__ import annotations

import inspect
import os
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from zephyr import claims
from zephyr.attribution import AttributionLog
from zephyr.registry import PubkeyRegistry
from zephyr.routing import RouteChainError, compile_route_manifest
from zephyr.signing import AgentSigner

REPO_ROOT = Path(__file__).resolve().parents[1]


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


# ===========================================================================
# Rail U2a (zephyr-route-manifest-hardening-v0) additions
# ===========================================================================


def _raw_insert_route_manifest(store, event_ref, mh, supersedes):
    """Bypasses insert_route_manifest's application guard entirely - for
    hand-constructing malformed chains (AC3) that route_manifest_chain_for_event
    must detect independently of the write-time guard."""
    store._conn.execute(
        "INSERT INTO route_manifests (manifest_hash, event_ref, payload_json, summary, recorded_at, supersedes) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (mh, event_ref, "{}", "x", "2026-07-20T00:00:00+00:00", supersedes),
    )
    store._conn.commit()


# ---------------------------------------------------------------------------
# AC1 -- chain walk beats timestamps (D1 regression proof)
# ---------------------------------------------------------------------------


def test_u2a_ac1_chain_walk_beats_timestamps(tmp_claims_store):
    event_ref = "evt-u2aac1"
    first_hash = "sha256:" + "1" * 64
    second_hash = "sha256:" + "0" * 64  # sorts lexicographically BELOW first_hash

    tmp_claims_store.insert_route_manifest(
        manifest_hash=first_hash, event_ref=event_ref, payload_json="{}",
        summary="first", recorded_at="2026-07-20T00:00:00+00:00", supersedes=None,
    )
    # Second manifest supersedes the first, with an IDENTICAL injected
    # recorded_at and a hash that sorts BELOW the first - old (recorded_at,
    # manifest_hash)-max selection would pick first_hash back up here.
    tmp_claims_store.insert_route_manifest(
        manifest_hash=second_hash, event_ref=event_ref, payload_json="{}",
        summary="second", recorded_at="2026-07-20T00:00:00+00:00", supersedes=first_hash,
    )

    head = tmp_claims_store.latest_route_manifest_for_event(event_ref)
    assert head["manifest_hash"] == second_hash


# ---------------------------------------------------------------------------
# AC2 -- fork rejected at write
# ---------------------------------------------------------------------------


def test_u2a_ac2_fork_rejected_null_supersedes_when_head_exists(tmp_claims_store):
    event_ref = "evt-u2aac2-null"
    tmp_claims_store.insert_route_manifest(
        manifest_hash="sha256:" + "1" * 64, event_ref=event_ref, payload_json="{}",
        summary="first", recorded_at="2026-07-20T00:00:00+00:00", supersedes=None,
    )
    with pytest.raises(claims.RouteChainError) as excinfo:
        tmp_claims_store.insert_route_manifest(
            manifest_hash="sha256:" + "2" * 64, event_ref=event_ref, payload_json="{}",
            summary="second", recorded_at="2026-07-20T00:00:01+00:00", supersedes=None,
        )
    assert excinfo.value.failure_mode == "supersedes_not_head"

    n = tmp_claims_store._conn.execute(
        "SELECT COUNT(*) AS n FROM route_manifests WHERE event_ref = ?", (event_ref,)
    ).fetchone()["n"]
    assert n == 1


def test_u2a_ac2_fork_rejected_supersedes_names_non_head(tmp_claims_store):
    event_ref = "evt-u2aac2-nonhead"
    tmp_claims_store.insert_route_manifest(
        manifest_hash="sha256:" + "1" * 64, event_ref=event_ref, payload_json="{}",
        summary="first", recorded_at="2026-07-20T00:00:00+00:00", supersedes=None,
    )
    with pytest.raises(claims.RouteChainError) as excinfo:
        tmp_claims_store.insert_route_manifest(
            manifest_hash="sha256:" + "2" * 64, event_ref=event_ref, payload_json="{}",
            summary="second", recorded_at="2026-07-20T00:00:01+00:00",
            supersedes="sha256:" + "9" * 64,  # names a hash that is not the current head
        )
    assert excinfo.value.failure_mode == "supersedes_not_head"

    n = tmp_claims_store._conn.execute(
        "SELECT COUNT(*) AS n FROM route_manifests WHERE event_ref = ?", (event_ref,)
    ).fetchone()["n"]
    assert n == 1


# ---------------------------------------------------------------------------
# AC3 -- malformed chains fail closed, never guess
# ---------------------------------------------------------------------------


def test_u2a_ac3_forked_chain(tmp_claims_store):
    tmp_claims_store._conn.execute("DROP INDEX IF EXISTS route_manifests_chain_unique")
    tmp_claims_store._conn.commit()

    event_ref = "evt-u2aac3-fork"
    root = "sha256:" + "1" * 64
    a, b = "sha256:" + "2" * 64, "sha256:" + "3" * 64
    _raw_insert_route_manifest(tmp_claims_store, event_ref, root, None)
    _raw_insert_route_manifest(tmp_claims_store, event_ref, a, root)
    _raw_insert_route_manifest(tmp_claims_store, event_ref, b, root)

    with pytest.raises(claims.RouteChainError) as excinfo:
        tmp_claims_store.route_manifest_chain_for_event(event_ref)
    assert excinfo.value.failure_mode == "forked_chain"
    assert excinfo.value.event_ref == event_ref
    assert a in str(excinfo.value) and b in str(excinfo.value)


def test_u2a_ac3_cycle(tmp_claims_store):
    tmp_claims_store._conn.execute("DROP INDEX IF EXISTS route_manifests_chain_unique")
    tmp_claims_store._conn.commit()

    event_ref = "evt-u2aac3-cycle"
    x, y = "sha256:" + "4" * 64, "sha256:" + "5" * 64
    _raw_insert_route_manifest(tmp_claims_store, event_ref, x, y)
    _raw_insert_route_manifest(tmp_claims_store, event_ref, y, x)

    with pytest.raises(claims.RouteChainError) as excinfo:
        tmp_claims_store.route_manifest_chain_for_event(event_ref)
    assert excinfo.value.failure_mode == "cycle"
    assert excinfo.value.event_ref == event_ref


def test_u2a_ac3_orphaned(tmp_claims_store):
    tmp_claims_store._conn.execute("DROP INDEX IF EXISTS route_manifests_chain_unique")
    tmp_claims_store._conn.commit()

    event_ref = "evt-u2aac3-orphan"
    root, head = "sha256:" + "6" * 64, "sha256:" + "7" * 64
    sx, sy = "sha256:" + "8" * 64, "sha256:" + "9" * 64
    _raw_insert_route_manifest(tmp_claims_store, event_ref, root, None)
    _raw_insert_route_manifest(tmp_claims_store, event_ref, head, root)
    _raw_insert_route_manifest(tmp_claims_store, event_ref, sx, sy)
    _raw_insert_route_manifest(tmp_claims_store, event_ref, sy, sx)

    with pytest.raises(claims.RouteChainError) as excinfo:
        tmp_claims_store.route_manifest_chain_for_event(event_ref)
    assert excinfo.value.failure_mode == "orphaned"
    assert excinfo.value.event_ref == event_ref


def test_u2a_ac3_multiple_roots(tmp_claims_store):
    tmp_claims_store._conn.execute("DROP INDEX IF EXISTS route_manifests_chain_unique")
    tmp_claims_store._conn.commit()

    event_ref = "evt-u2aac3-roots"
    r1, r2 = "sha256:" + "a" * 64, "sha256:" + "b" * 64
    _raw_insert_route_manifest(tmp_claims_store, event_ref, r1, None)
    _raw_insert_route_manifest(tmp_claims_store, event_ref, r2, None)

    with pytest.raises(claims.RouteChainError) as excinfo:
        tmp_claims_store.route_manifest_chain_for_event(event_ref)
    assert excinfo.value.failure_mode == "multiple_roots"
    assert excinfo.value.event_ref == event_ref


# ---------------------------------------------------------------------------
# AC4 -- idempotent recompile still works
# ---------------------------------------------------------------------------


def test_u2a_ac4_idempotent_insert_is_a_noop(tmp_claims_store):
    event_ref = "evt-u2aac4"
    mh = "sha256:" + "1" * 64
    tmp_claims_store.insert_route_manifest(
        manifest_hash=mh, event_ref=event_ref, payload_json="{}",
        summary="first", recorded_at="2026-07-20T00:00:00+00:00", supersedes=None,
    )
    # Re-inserting the identical manifest_hash must be a silent no-op, never
    # raising - this is what makes routing.py:375-384's idempotent-recompile
    # path work even though it recomputes supersedes/recorded_at each time.
    tmp_claims_store.insert_route_manifest(
        manifest_hash=mh, event_ref=event_ref, payload_json="{}",
        summary="first", recorded_at="2026-07-20T00:00:01+00:00", supersedes=None,
    )
    n = tmp_claims_store._conn.execute(
        "SELECT COUNT(*) AS n FROM route_manifests WHERE event_ref = ?", (event_ref,)
    ).fetchone()["n"]
    assert n == 1


# ---------------------------------------------------------------------------
# AC4b -- fork guard is atomic under concurrency
# ---------------------------------------------------------------------------


def test_u2a_ac4b_fork_guard_atomic_threads(tmp_path):
    """Threads prove per-connection isolation: a SEPARATE ClaimsStore instance
    per thread against the same file, each with its own connection and its
    own self._lock. Sharing one instance would let the in-process mutex
    serialize the threads and this test would pass against buggy code."""
    db_path = tmp_path / "claims-threads.db"
    root_hash = "sha256:" + "1" * 64
    root_store = claims.ClaimsStore(db_path)
    root_store.insert_route_manifest(
        manifest_hash=root_hash, event_ref="evt-threads", payload_json="{}",
        summary="root", recorded_at="2026-07-20T00:00:00+00:00", supersedes=None,
    )

    results = {}

    def _attempt(name, mh):
        store = claims.ClaimsStore(db_path)
        try:
            store.insert_route_manifest(
                manifest_hash=mh, event_ref="evt-threads", payload_json="{}",
                summary=name, recorded_at="2026-07-20T00:00:01+00:00", supersedes=root_hash,
            )
            results[name] = "ok"
        except claims.RouteChainError as exc:
            results[name] = exc.failure_mode

    t1 = threading.Thread(target=_attempt, args=("t1", "sha256:" + "2" * 64))
    t2 = threading.Thread(target=_attempt, args=("t2", "sha256:" + "3" * 64))
    t1.start()
    t2.start()
    t1.join(timeout=30)
    t2.join(timeout=30)

    outcomes = list(results.values())
    assert outcomes.count("ok") == 1
    assert outcomes.count("supersedes_not_head") == 1

    final_store = claims.ClaimsStore(db_path)
    head = final_store.latest_route_manifest_for_event("evt-threads")
    assert head is not None
    assert final_store.route_manifest_chain_for_event("evt-threads")  # does not raise


def test_u2a_ac4b_fork_guard_atomic_processes(tmp_path):
    """Processes prove the SQLite write lock itself - the case the in-process
    self._lock cannot cover at all, since each process has its own Python
    interpreter and its own lock object."""
    db_path = tmp_path / "claims-procs.db"
    root_hash = "sha256:" + "1" * 64
    root_store = claims.ClaimsStore(db_path)
    root_store.insert_route_manifest(
        manifest_hash=root_hash, event_ref="evt-procs", payload_json="{}",
        summary="root", recorded_at="2026-07-20T00:00:00+00:00", supersedes=None,
    )

    script = (
        "import os, sys\n"
        "from zephyr import claims\n"
        "store = claims.ClaimsStore(os.environ['ZEPHYR_CLAIMS_DB'])\n"
        "try:\n"
        "    store.insert_route_manifest(\n"
        "        manifest_hash=sys.argv[1], event_ref='evt-procs', payload_json='{}',\n"
        "        summary=sys.argv[1], recorded_at='2026-07-20T00:00:01+00:00',\n"
        "        supersedes=os.environ['ZEPHYR_ROOT_HASH'],\n"
        "    )\n"
        "    print('ok')\n"
        "except claims.RouteChainError as exc:\n"
        "    print(exc.failure_mode)\n"
    )

    env = dict(os.environ)
    env["ZEPHYR_CLAIMS_DB"] = str(db_path)
    env["ZEPHYR_ROOT_HASH"] = root_hash

    p1 = subprocess.Popen(
        [sys.executable, "-c", script, "sha256:" + "2" * 64],
        cwd=str(REPO_ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    p2 = subprocess.Popen(
        [sys.executable, "-c", script, "sha256:" + "3" * 64],
        cwd=str(REPO_ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    out1, err1 = p1.communicate(timeout=30)
    out2, err2 = p2.communicate(timeout=30)

    outcomes = [out1.strip(), out2.strip()]
    assert outcomes.count("ok") == 1, (outcomes, err1, err2)
    assert outcomes.count("supersedes_not_head") == 1, (outcomes, err1, err2)

    final_store = claims.ClaimsStore(db_path)
    head = final_store.latest_route_manifest_for_event("evt-procs")
    assert head is not None
    assert final_store.route_manifest_chain_for_event("evt-procs")  # does not raise


# ---------------------------------------------------------------------------
# AC4c -- wallet-binding resolution ignores caller timestamps (D1b)
# ---------------------------------------------------------------------------


def test_u2a_ac4c_resolution_ignores_equal_caller_timestamp(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "u2aac4c-equal")
    claims.record_wallet_binding(
        subject=s.pubkey_id_str, wallet_address="https://wallet.example/a",
        agent_id="agent:claims-test", signer=s, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_wallet_binding(
        subject=s.pubkey_id_str, wallet_address="https://wallet.example/b",
        agent_id="agent:claims-test", signer=s, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:00:00+00:00",  # IDENTICAL to A's
    )
    resolved = claims.resolve_wallet(s.pubkey_id_str, store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert resolved == "https://wallet.example/b"


def test_u2a_ac4c_resolution_ignores_earlier_caller_timestamp(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "u2aac4c-earlier")
    claims.record_wallet_binding(
        subject=s.pubkey_id_str, wallet_address="https://wallet.example/a",
        agent_id="agent:claims-test", signer=s, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_wallet_binding(
        subject=s.pubkey_id_str, wallet_address="https://wallet.example/b",
        agent_id="agent:claims-test", signer=s, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-19T00:00:00+00:00",  # EARLIER than A's, injected
    )
    resolved = claims.resolve_wallet(s.pubkey_id_str, store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert resolved == "https://wallet.example/b"

    # Revoke B (the later-inserted binding, by seq) - resolve_wallet returns
    # None, NOT a fallback to A - fail closed, latest-only, no walking back
    # down the stack.
    claims.record_wallet_binding(
        subject=s.pubkey_id_str, wallet_address="https://wallet.example/b",
        agent_id="agent:claims-test", revokes=True, signer=s, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-18T00:00:00+00:00",
    )
    resolved2 = claims.resolve_wallet(s.pubkey_id_str, store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert resolved2 is None


# ---------------------------------------------------------------------------
# AC4d -- seq is not caller-settable
# ---------------------------------------------------------------------------


def test_u2a_ac4d_seq_not_caller_settable(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    sig_binding = inspect.signature(claims.ClaimsStore.insert_wallet_binding)
    assert "seq" not in sig_binding.parameters
    sig_terms = inspect.signature(claims.ClaimsStore.insert_routing_terms)
    assert "seq" not in sig_terms.parameters

    payload = dict(
        manifest_hash="sha256:" + "1" * 64, subject="sha256:some-subject",
        wallet_address="https://wallet.example/x", revokes=False, note="", summary="x",
        recorded_at="2026-07-20T00:00:00+00:00", seq=999,
    )
    with pytest.raises(TypeError):
        tmp_claims_store.insert_wallet_binding(**payload)


def test_u2a_ac4d_seq_strictly_increasing(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "u2aac4d-seq")
    seqs = []
    for i in range(3):
        claims.record_wallet_binding(
            subject=s.pubkey_id_str, wallet_address=f"https://wallet.example/{i}",
            agent_id="agent:claims-test", signer=s, registry=tmp_registry, recorder=tmp_log,
            timestamp=f"2026-07-20T00:00:0{i}+00:00",
        )
        rows = tmp_claims_store.list_wallet_bindings_for_subject(s.pubkey_id_str)
        seqs.append(max(r["seq"] for r in rows))
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == 3


# ---------------------------------------------------------------------------
# AC4e -- the schema backstop holds independently of the application guard
# ---------------------------------------------------------------------------


def test_u2a_ac4e_schema_backstop_holds_independently(tmp_claims_store):
    row = tmp_claims_store._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='route_manifests_chain_unique'"
    ).fetchone()
    assert row is not None

    event_ref = "evt-u2aac4e"
    root = "sha256:" + "1" * 64
    tmp_claims_store._conn.execute(
        "INSERT INTO route_manifests (manifest_hash, event_ref, payload_json, summary, recorded_at, supersedes) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (root, event_ref, "{}", "root", "2026-07-20T00:00:00+00:00", None),
    )
    child = "sha256:" + "2" * 64
    tmp_claims_store._conn.execute(
        "INSERT INTO route_manifests (manifest_hash, event_ref, payload_json, summary, recorded_at, supersedes) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (child, event_ref, "{}", "child", "2026-07-20T00:00:01+00:00", root),
    )
    tmp_claims_store._conn.commit()

    # A direct insert of a second manifest carrying an already-used
    # supersedes value (root, already named by `child`) - IntegrityError.
    with pytest.raises(sqlite3.IntegrityError):
        tmp_claims_store._conn.execute(
            "INSERT INTO route_manifests (manifest_hash, event_ref, payload_json, summary, recorded_at, supersedes) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("sha256:" + "3" * 64, event_ref, "{}", "dup-fork", "2026-07-20T00:00:02+00:00", root),
        )
    tmp_claims_store._conn.rollback()

    # A second NULL-supersedes root for the same event_ref - the case a bare
    # UNIQUE(event_ref, supersedes) would silently admit (SQLite treats NULLs
    # as distinct), and the reason for the COALESCE form.
    with pytest.raises(sqlite3.IntegrityError):
        tmp_claims_store._conn.execute(
            "INSERT INTO route_manifests (manifest_hash, event_ref, payload_json, summary, recorded_at, supersedes) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("sha256:" + "4" * 64, event_ref, "{}", "dup-root", "2026-07-20T00:00:03+00:00", None),
        )
    tmp_claims_store._conn.rollback()


# ---------------------------------------------------------------------------
# AC13d -- the seq migration is idempotent and preserves every guarantee
# ---------------------------------------------------------------------------

_OLD_WALLET_BINDINGS_SCHEMA = """
    CREATE TABLE wallet_bindings (
        manifest_hash   TEXT PRIMARY KEY,
        subject         TEXT,
        wallet_address  TEXT,
        revokes         INTEGER,
        note            TEXT,
        summary         TEXT,
        recorded_at     TEXT
    )
"""


def test_u2a_ac13d_migration_idempotent_and_preserves_guarantees(tmp_path):
    db_path = tmp_path / "old-schema-claims.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(_OLD_WALLET_BINDINGS_SCHEMA)
    conn.execute("CREATE INDEX wallet_bindings_subject ON wallet_bindings(subject)")
    rows = [
        ("sha256:" + "3" * 64, "subj", "https://wallet.example/c", 0, "", "c", "2026-07-20T00:00:02+00:00"),
        ("sha256:" + "1" * 64, "subj", "https://wallet.example/a", 0, "", "a", "2026-07-20T00:00:00+00:00"),
        ("sha256:" + "2" * 64, "subj", "https://wallet.example/b", 0, "", "b", "2026-07-20T00:00:01+00:00"),
    ]
    conn.executemany(
        "INSERT INTO wallet_bindings (manifest_hash, subject, wallet_address, revokes, note, summary, recorded_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    conn.close()

    store = claims.ClaimsStore(db_path)
    migrated = store._conn.execute(
        "SELECT manifest_hash, seq FROM wallet_bindings ORDER BY seq"
    ).fetchall()
    # Backfilled seq follows recorded_at order (the migration's INSERT...SELECT
    # ORDER BY), not insertion order into the OLD table (which was c, a, b).
    assert [r["manifest_hash"] for r in migrated] == [
        "sha256:" + "1" * 64, "sha256:" + "2" * 64, "sha256:" + "3" * 64,
    ]
    assert [r["seq"] for r in migrated] == sorted(r["seq"] for r in migrated)
    assert len(set(r["seq"] for r in migrated)) == 3
    max_seq_before = max(r["seq"] for r in migrated)
    store._conn.close()

    # Re-opening is a no-op: no error, no re-backfill, no row lost or duplicated.
    store2 = claims.ClaimsStore(db_path)
    migrated2 = store2._conn.execute(
        "SELECT manifest_hash, seq FROM wallet_bindings ORDER BY seq"
    ).fetchall()
    assert [r["manifest_hash"] for r in migrated2] == [r["manifest_hash"] for r in migrated]
    assert [r["seq"] for r in migrated2] == [r["seq"] for r in migrated]

    # Post-migration inserts continue monotonically from the backfilled
    # maximum WITHOUT any application-side MAX(seq)+1 computation - SQLite
    # assigns it via AUTOINCREMENT.
    store2.insert_wallet_binding(
        manifest_hash="sha256:" + "4" * 64, subject="subj", wallet_address="https://wallet.example/d",
        revokes=False, note="", summary="d", recorded_at="2026-07-20T00:00:03+00:00",
    )
    new_row = store2._conn.execute(
        "SELECT seq FROM wallet_bindings WHERE manifest_hash = ?", ("sha256:" + "4" * 64,)
    ).fetchone()
    assert new_row["seq"] > max_seq_before

    # INSERT OR IGNORE on a duplicate manifest_hash is still a silent no-op
    # now that manifest_hash is UNIQUE rather than PRIMARY KEY.
    store2.insert_wallet_binding(
        manifest_hash="sha256:" + "1" * 64, subject="subj", wallet_address="https://SHOULD-NOT-APPEAR",
        revokes=False, note="", summary="dup", recorded_at="2026-07-20T00:00:04+00:00",
    )
    count = store2._conn.execute("SELECT COUNT(*) AS n FROM wallet_bindings").fetchone()["n"]
    assert count == 4
    unchanged = store2._conn.execute(
        "SELECT wallet_address FROM wallet_bindings WHERE manifest_hash = ?", ("sha256:" + "1" * 64,)
    ).fetchone()
    assert unchanged["wallet_address"] == "https://wallet.example/a"


def test_u2a_ac13d_migration_lock_exhaustion_leaves_store_unmodified(tmp_path):
    """A competing write lock held across a migration attempt: BEGIN IMMEDIATE
    fails at the START, before any DDL runs. On exhausting the bounded
    backoff (5 attempts, 50ms doubling), _migrate_add_seq raises and the
    store is left byte-identical - never a half-upgraded schema."""
    db_path = tmp_path / "old-schema-locked.db"
    conn = sqlite3.connect(str(db_path), timeout=0.1)
    conn.row_factory = sqlite3.Row
    conn.execute(_OLD_WALLET_BINDINGS_SCHEMA)
    conn.execute(
        "INSERT INTO wallet_bindings (manifest_hash, subject, wallet_address, revokes, note, summary, recorded_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("sha256:" + "5" * 64, "subj", "https://wallet.example/e", 0, "", "e", "2026-07-20T00:00:00+00:00"),
    )
    conn.commit()
    before_bytes = db_path.read_bytes()

    holder = sqlite3.connect(str(db_path), timeout=0.1)
    holder.execute("BEGIN IMMEDIATE")
    holder.execute("CREATE TABLE _holder_marker (x INTEGER)")

    try:
        with pytest.raises(sqlite3.OperationalError):
            claims._migrate_add_seq(conn)
    finally:
        holder.rollback()
        holder.close()
        conn.close()

    after_bytes = db_path.read_bytes()
    assert after_bytes == before_bytes


# ===========================================================================
# Rail U2b (zephyr-route-executor-foundation-v0) additions
# ===========================================================================


def _contributor(tmp_path, registry, name):
    s = _signer(tmp_path, name)
    registry.register(s.pubkey_id_str, s.public_key_bytes.hex(), f"agent:{name}", "agent")
    return s


def _make_content_deposit(log, signer, registry, *, agent_id, payload, summary, timestamp):
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
    log.record(prov, store_kind="content", registry=registry)
    return mh


def _build_routable_manifest(tmp_path, tmp_log, tmp_registry, tmp_claims_store, *, name, amount=500, bps=4000):
    """A single-beneficiary manifest with a bound wallet - the leg resolves
    "routable". Returns (manifest_hash, event_ref, leg, node_signer)."""
    d = _contributor(tmp_path, tmp_registry, f"{name}-d")
    compiler = _signer(tmp_path, f"{name}-compiler")
    node_signer = _signer(tmp_path, f"{name}-node")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id=f"agent:{name}-d", payload={"work": name},
        summary=f"work {name}", timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=bps,
        scope="standing", declared_by=f"agent:{name}-d", agent_id=f"agent:{name}-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )
    claims.record_wallet_binding(
        subject=d.pubkey_id_str, wallet_address=f"https://wallet.example/{name}-d",
        agent_id=f"agent:{name}-d", signer=d, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:00:02+00:00",
    )

    event_ref = f"evt-{name}"
    result = compile_route_manifest(
        event_kind="demo-sale", event_ref=event_ref, subject=subject_mh,
        amount_value=amount, asset_code="USD", asset_scale=2,
        agent_id=f"agent:{name}-route", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:01:00+00:00",
    )
    manifest_hash = result["manifest_hash"]
    rm = result["manifest"]["route_manifest"]
    leg = next(l for l in rm["legs"] if l["beneficiary_pubkey_id"] == d.pubkey_id_str)
    assert leg["leg_status"] == "routable"
    return manifest_hash, event_ref, leg, node_signer


def _record(tmp_log, tmp_registry, tmp_claims_store, node_signer, *, event_ref, manifest_hash,
            beneficiary_pubkey_id, outcome, timestamp, **kwargs):
    return claims.record_route_receipt(
        event_ref=event_ref, manifest_hash=manifest_hash,
        beneficiary_pubkey_id=beneficiary_pubkey_id, outcome=outcome,
        agent_id="agent:node-test", signer=node_signer, recorder=tmp_log, log=tmp_log,
        registry=tmp_registry, store=tmp_claims_store, timestamp=timestamp, **kwargs,
    )


# ---------------------------------------------------------------------------
# AC1 -- receipt dual-write round-trips through route_receipts_for_manifest
# ---------------------------------------------------------------------------


def test_u2b_ac1_settled_receipt_round_trips(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    mh, event_ref, leg, node_signer = _build_routable_manifest(
        tmp_path, tmp_log, tmp_registry, tmp_claims_store, name="u2bac1"
    )

    result = _record(
        tmp_log, tmp_registry, tmp_claims_store, node_signer,
        event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id=leg["beneficiary_pubkey_id"],
        outcome="settled", op_payment_id="https://ilp.example/pay/1",
        sent_value=leg["amount"], sent_asset_code="USD", sent_asset_scale=2,
        timestamp="2026-07-20T00:02:00+00:00",
    )
    assert result["newly_recorded"] is True
    assert result["receipt_hash"].startswith("sha256:")

    envelope = tmp_log.get(result["receipt_hash"], registry=tmp_registry)
    assert envelope is not None
    assert envelope["verification_status"] == "verified"

    receipts = claims.route_receipts_for_manifest(mh, store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert len(receipts) == 1
    r = receipts[0]
    assert r["beneficiary_pubkey_id"] == leg["beneficiary_pubkey_id"]
    assert r["outcome"] == "settled"
    assert r["op_payment_id"] == "https://ilp.example/pay/1"
    assert r["sent_amount"] == {"value": leg["amount"], "asset_code": "USD", "asset_scale": 2}
    assert r["leg_status"] == "routable"
    assert r["receipt_hash"] == result["receipt_hash"]


def test_u2b_ac1_skipped_receipt_round_trips(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    """A skipped (credited-unpaid) leg is a routable leg the executor chose not
    to pay for another reason - the Void Principle means a receipt is still
    written for the skip, never silently dropped."""
    mh, event_ref, leg, node_signer = _build_routable_manifest(
        tmp_path, tmp_log, tmp_registry, tmp_claims_store, name="u2bac1skip"
    )

    result = _record(
        tmp_log, tmp_registry, tmp_claims_store, node_signer,
        event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id=leg["beneficiary_pubkey_id"],
        outcome="skipped", reason="not_routable",
        timestamp="2026-07-20T00:02:00+00:00",
    )
    assert result["newly_recorded"] is True

    receipts = claims.route_receipts_for_manifest(mh, store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert len(receipts) == 1
    assert receipts[0]["outcome"] == "skipped"
    assert receipts[0]["sent_amount"] is None
    assert receipts[0]["reason"] == "not_routable"


# ---------------------------------------------------------------------------
# AC2 -- settled requires non-null op_payment_id + all three amount fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(op_payment_id=None, sent_value=200, sent_asset_code="USD", sent_asset_scale=2),
        dict(op_payment_id="https://ilp.example/pay/1", sent_value=None, sent_asset_code="USD", sent_asset_scale=2),
        dict(op_payment_id="https://ilp.example/pay/1", sent_value=200, sent_asset_code=None, sent_asset_scale=2),
        dict(op_payment_id="https://ilp.example/pay/1", sent_value=200, sent_asset_code="USD", sent_asset_scale=None),
    ],
)
def test_u2b_ac2_settled_requires_all_amount_fields(tmp_path, tmp_log, tmp_registry, tmp_claims_store, kwargs):
    mh, event_ref, leg, node_signer = _build_routable_manifest(
        tmp_path, tmp_log, tmp_registry, tmp_claims_store, name="u2bac2"
    )
    with pytest.raises(ValueError):
        _record(
            tmp_log, tmp_registry, tmp_claims_store, node_signer,
            event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id=leg["beneficiary_pubkey_id"],
            outcome="settled", timestamp="2026-07-20T00:02:00+00:00", **kwargs,
        )


# ---------------------------------------------------------------------------
# AC3 -- settled against a credited-unpaid leg raises not_routable
# ---------------------------------------------------------------------------


def test_u2b_ac3_settled_against_credited_unpaid_raises_not_routable(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "u2bac3-d")
    compiler = _signer(tmp_path, "u2bac3-compiler")
    node_signer = _signer(tmp_path, "u2bac3-node")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:u2bac3-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by="agent:u2bac3-d", agent_id="agent:u2bac3-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )
    # No wallet_binding -> the leg resolves credited-unpaid.
    event_ref = "evt-u2bac3"
    result = compile_route_manifest(
        event_kind="demo-sale", event_ref=event_ref, subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:u2bac3-route", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:01:00+00:00",
    )
    mh = result["manifest_hash"]
    rm = result["manifest"]["route_manifest"]
    leg = next(l for l in rm["legs"] if l["beneficiary_pubkey_id"] == d.pubkey_id_str)
    assert leg["leg_status"] == "credited-unpaid"

    with pytest.raises(claims.RouteReceiptError) as excinfo:
        _record(
            tmp_log, tmp_registry, tmp_claims_store, node_signer,
            event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id=leg["beneficiary_pubkey_id"],
            outcome="settled", op_payment_id="https://ilp.example/pay/1",
            sent_value=leg["amount"], sent_asset_code="USD", sent_asset_scale=2,
            timestamp="2026-07-20T00:02:00+00:00",
        )
    assert excinfo.value.failure_mode == "not_routable"


# ---------------------------------------------------------------------------
# AC4 -- settled with sent_value != leg amount raises amount_mismatch
# ---------------------------------------------------------------------------


def test_u2b_ac4_amount_mismatch_raises(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    mh, event_ref, leg, node_signer = _build_routable_manifest(
        tmp_path, tmp_log, tmp_registry, tmp_claims_store, name="u2bac4"
    )
    with pytest.raises(claims.RouteReceiptError) as excinfo:
        _record(
            tmp_log, tmp_registry, tmp_claims_store, node_signer,
            event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id=leg["beneficiary_pubkey_id"],
            outcome="settled", op_payment_id="https://ilp.example/pay/1",
            sent_value=leg["amount"] + 1, sent_asset_code="USD", sent_asset_scale=2,
            timestamp="2026-07-20T00:02:00+00:00",
        )
    assert excinfo.value.failure_mode == "amount_mismatch"


def test_u2b_ac4_asset_code_mismatch_raises(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    mh, event_ref, leg, node_signer = _build_routable_manifest(
        tmp_path, tmp_log, tmp_registry, tmp_claims_store, name="u2bac4b"
    )
    with pytest.raises(claims.RouteReceiptError) as excinfo:
        _record(
            tmp_log, tmp_registry, tmp_claims_store, node_signer,
            event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id=leg["beneficiary_pubkey_id"],
            outcome="settled", op_payment_id="https://ilp.example/pay/1",
            sent_value=leg["amount"], sent_asset_code="EUR", sent_asset_scale=2,
            timestamp="2026-07-20T00:02:00+00:00",
        )
    assert excinfo.value.failure_mode == "amount_mismatch"


# ---------------------------------------------------------------------------
# AC5 -- terminal idempotency: exact repeat is a no-op
# ---------------------------------------------------------------------------


def test_u2b_ac5_exact_repeat_terminal_is_idempotent(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    mh, event_ref, leg, node_signer = _build_routable_manifest(
        tmp_path, tmp_log, tmp_registry, tmp_claims_store, name="u2bac5"
    )
    kwargs = dict(
        event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id=leg["beneficiary_pubkey_id"],
        outcome="settled", op_payment_id="https://ilp.example/pay/1",
        sent_value=leg["amount"], sent_asset_code="USD", sent_asset_scale=2,
    )
    r1 = _record(tmp_log, tmp_registry, tmp_claims_store, node_signer, timestamp="2026-07-20T00:02:00+00:00", **kwargs)
    assert r1["newly_recorded"] is True

    r2 = _record(tmp_log, tmp_registry, tmp_claims_store, node_signer, timestamp="2026-07-20T00:03:00+00:00", **kwargs)
    assert r2["newly_recorded"] is False
    assert r2["receipt_hash"] == r1["receipt_hash"]

    rows = tmp_claims_store.list_route_receipts_for_manifest(mh)
    assert len(rows) == 1


def test_u2b_ac5_exact_repeat_skipped_is_idempotent(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    mh, event_ref, leg, node_signer = _build_routable_manifest(
        tmp_path, tmp_log, tmp_registry, tmp_claims_store, name="u2bac5skip"
    )
    kwargs = dict(
        event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id=leg["beneficiary_pubkey_id"],
        outcome="skipped", reason="binding_revoked",
    )
    r1 = _record(tmp_log, tmp_registry, tmp_claims_store, node_signer, timestamp="2026-07-20T00:02:00+00:00", **kwargs)
    assert r1["newly_recorded"] is True
    r2 = _record(tmp_log, tmp_registry, tmp_claims_store, node_signer, timestamp="2026-07-20T00:03:00+00:00", **kwargs)
    assert r2["newly_recorded"] is False

    rows = tmp_claims_store.list_route_receipts_for_manifest(mh)
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# AC6 -- terminal conflict raises outcome_conflict
# ---------------------------------------------------------------------------


def test_u2b_ac6_conflicting_terminal_raises_outcome_conflict(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    mh, event_ref, leg, node_signer = _build_routable_manifest(
        tmp_path, tmp_log, tmp_registry, tmp_claims_store, name="u2bac6"
    )
    _record(
        tmp_log, tmp_registry, tmp_claims_store, node_signer,
        event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id=leg["beneficiary_pubkey_id"],
        outcome="skipped", reason="not_routable", timestamp="2026-07-20T00:02:00+00:00",
    )
    with pytest.raises(claims.RouteReceiptError) as excinfo:
        _record(
            tmp_log, tmp_registry, tmp_claims_store, node_signer,
            event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id=leg["beneficiary_pubkey_id"],
            outcome="settled", op_payment_id="https://ilp.example/pay/1",
            sent_value=leg["amount"], sent_asset_code="USD", sent_asset_scale=2,
            timestamp="2026-07-20T00:03:00+00:00",
        )
    assert excinfo.value.failure_mode == "outcome_conflict"

    rows = tmp_claims_store.list_route_receipts_for_manifest(mh)
    assert len(rows) == 1
    assert rows[0]["outcome"] == "skipped"


# ---------------------------------------------------------------------------
# AC7 -- failed then settled supersedes; partial unique index still holds
# ---------------------------------------------------------------------------


def test_u2b_ac7_failed_then_settled_supersedes(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    mh, event_ref, leg, node_signer = _build_routable_manifest(
        tmp_path, tmp_log, tmp_registry, tmp_claims_store, name="u2bac7"
    )
    r_failed = _record(
        tmp_log, tmp_registry, tmp_claims_store, node_signer,
        event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id=leg["beneficiary_pubkey_id"],
        outcome="failed", reason="ILPQuoteError", timestamp="2026-07-20T00:02:00+00:00",
    )
    assert r_failed["newly_recorded"] is True

    r_settled = _record(
        tmp_log, tmp_registry, tmp_claims_store, node_signer,
        event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id=leg["beneficiary_pubkey_id"],
        outcome="settled", op_payment_id="https://ilp.example/pay/1",
        sent_value=leg["amount"], sent_asset_code="USD", sent_asset_scale=2,
        timestamp="2026-07-20T00:03:00+00:00",
    )
    assert r_settled["newly_recorded"] is True

    rows = tmp_claims_store.list_route_receipts_for_manifest(mh)
    assert len(rows) == 2
    assert {r["outcome"] for r in rows} == {"failed", "settled"}

    receipts = claims.route_receipts_for_manifest(mh, store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert len(receipts) == 1
    assert receipts[0]["outcome"] == "settled"

    # A second failed row is free to accrue too - failed is never terminal.
    r_failed2 = _record(
        tmp_log, tmp_registry, tmp_claims_store, node_signer,
        event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id=leg["beneficiary_pubkey_id"],
        outcome="failed", reason="ILPTimeoutError", timestamp="2026-07-20T00:01:00+00:00",
    )
    assert r_failed2["newly_recorded"] is True
    assert len(tmp_claims_store.list_route_receipts_for_manifest(mh)) == 3


# ---------------------------------------------------------------------------
# AC8 -- receipt against a superseded/stale manifest_hash raises not_head
# ---------------------------------------------------------------------------


def test_u2b_ac8_stale_manifest_hash_raises_not_head(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    d = _contributor(tmp_path, tmp_registry, "u2bac8-d")
    compiler = _signer(tmp_path, "u2bac8-compiler")
    node_signer = _signer(tmp_path, "u2bac8-node")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:u2bac8-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
        scope="standing", declared_by="agent:u2bac8-d", agent_id="agent:u2bac8-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )
    claims.record_wallet_binding(
        subject=d.pubkey_id_str, wallet_address="https://wallet.example/u2bac8-d",
        agent_id="agent:u2bac8-d", signer=d, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:00:02+00:00",
    )

    event_ref = "evt-u2bac8"
    first = compile_route_manifest(
        event_kind="demo-sale", event_ref=event_ref, subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:u2bac8-route", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:01:00+00:00",
    )
    stale_hash = first["manifest_hash"]

    # Revoke + rebind to force a supersession (a new head for the same event_ref).
    claims.record_wallet_binding(
        subject=d.pubkey_id_str, wallet_address="https://wallet.example/u2bac8-d",
        agent_id="agent:u2bac8-d", revokes=True, signer=d, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:02:00+00:00",
    )
    claims.record_wallet_binding(
        subject=d.pubkey_id_str, wallet_address="https://wallet.example/u2bac8-d-new",
        agent_id="agent:u2bac8-d", signer=d, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:02:01+00:00",
    )
    second = compile_route_manifest(
        event_kind="demo-sale", event_ref=event_ref, subject=subject_mh,
        amount_value=500, asset_code="USD", asset_scale=2,
        agent_id="agent:u2bac8-route", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:03:00+00:00",
    )
    assert second["manifest_hash"] != stale_hash

    with pytest.raises(claims.RouteReceiptError) as excinfo:
        _record(
            tmp_log, tmp_registry, tmp_claims_store, node_signer,
            event_ref=event_ref, manifest_hash=stale_hash, beneficiary_pubkey_id=d.pubkey_id_str,
            outcome="skipped", reason="stale-attempt", timestamp="2026-07-20T00:04:00+00:00",
        )
    assert excinfo.value.failure_mode == "not_head"


def test_u2b_ac8_unknown_event_ref_raises_unknown_manifest(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    node_signer = _signer(tmp_path, "u2bac8u-node")
    with pytest.raises(claims.RouteReceiptError) as excinfo:
        _record(
            tmp_log, tmp_registry, tmp_claims_store, node_signer,
            event_ref="evt-does-not-exist", manifest_hash="sha256:" + "0" * 64,
            beneficiary_pubkey_id="ed25519:whoever", outcome="skipped", reason="x",
            timestamp="2026-07-20T00:00:00+00:00",
        )
    assert excinfo.value.failure_mode == "unknown_manifest"


# ---------------------------------------------------------------------------
# AC9 -- receipt for an absent beneficiary raises no_such_leg
# ---------------------------------------------------------------------------


def test_u2b_ac9_absent_beneficiary_raises_no_such_leg(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    mh, event_ref, leg, node_signer = _build_routable_manifest(
        tmp_path, tmp_log, tmp_registry, tmp_claims_store, name="u2bac9"
    )
    with pytest.raises(claims.RouteReceiptError) as excinfo:
        _record(
            tmp_log, tmp_registry, tmp_claims_store, node_signer,
            event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id="ed25519:not-a-leg",
            outcome="skipped", reason="x", timestamp="2026-07-20T00:02:00+00:00",
        )
    assert excinfo.value.failure_mode == "no_such_leg"


# ---------------------------------------------------------------------------
# AC10 -- RouteChainError from a wedged chain propagates unchanged
# ---------------------------------------------------------------------------


def test_u2b_ac10_wedged_chain_propagates(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    tmp_claims_store._conn.execute("DROP INDEX IF EXISTS route_manifests_chain_unique")
    tmp_claims_store._conn.commit()

    event_ref = "evt-u2bac10-fork"
    root = "sha256:" + "1" * 64
    a, b = "sha256:" + "2" * 64, "sha256:" + "3" * 64
    _raw_insert_route_manifest(tmp_claims_store, event_ref, root, None)
    _raw_insert_route_manifest(tmp_claims_store, event_ref, a, root)
    _raw_insert_route_manifest(tmp_claims_store, event_ref, b, root)

    node_signer = _signer(tmp_path, "u2bac10-node")
    with pytest.raises(RouteChainError) as excinfo:
        _record(
            tmp_log, tmp_registry, tmp_claims_store, node_signer,
            event_ref=event_ref, manifest_hash=a, beneficiary_pubkey_id="ed25519:whoever",
            outcome="skipped", reason="x", timestamp="2026-07-20T00:00:00+00:00",
        )
    assert excinfo.value.failure_mode == "forked_chain"


# ---------------------------------------------------------------------------
# AC11 -- route_receipts_for_manifest skips an integrity-failed receipt
# ---------------------------------------------------------------------------


def test_u2b_ac11_skips_orphan_receipt_missing_envelope(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    mh, event_ref, leg, node_signer = _build_routable_manifest(
        tmp_path, tmp_log, tmp_registry, tmp_claims_store, name="u2bac11"
    )
    result = _record(
        tmp_log, tmp_registry, tmp_claims_store, node_signer,
        event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id=leg["beneficiary_pubkey_id"],
        outcome="settled", op_payment_id="https://ilp.example/pay/1",
        sent_value=leg["amount"], sent_asset_code="USD", sent_asset_scale=2,
        timestamp="2026-07-20T00:02:00+00:00",
    )
    assert result["newly_recorded"] is True

    # Simulate the documented residual failure: the domain row committed but
    # its deposit envelope never landed (crash between D1's two writes).
    tmp_log._conn.execute("DELETE FROM deposits WHERE manifest_hash = ?", (result["receipt_hash"],))
    tmp_log._conn.commit()

    rows = tmp_claims_store.list_route_receipts_for_manifest(mh)
    assert len(rows) == 1
    vr = claims.verify_route_receipt_row(rows[0], log=tmp_log, registry=tmp_registry)
    assert vr.ok is False
    assert vr.failure_mode == "missing_envelope"

    receipts = claims.route_receipts_for_manifest(mh, store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert receipts == []


# ---------------------------------------------------------------------------
# AC12 -- two concurrent terminal writes for one leg: exactly one wins
# ---------------------------------------------------------------------------


def test_u2b_ac12_concurrent_terminal_writes_exactly_one_wins(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    mh, event_ref, leg, node_signer = _build_routable_manifest(
        tmp_path, tmp_log, tmp_registry, tmp_claims_store, name="u2bac12"
    )
    claims_db_path = tmp_claims_store.db_path

    outcomes = {}

    def _attempt(name, op_payment_id):
        store = claims.ClaimsStore(claims_db_path)
        try:
            r = claims.record_route_receipt(
                event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id=leg["beneficiary_pubkey_id"],
                outcome="settled", op_payment_id=op_payment_id,
                sent_value=leg["amount"], sent_asset_code="USD", sent_asset_scale=2,
                agent_id="agent:node-test", signer=node_signer, recorder=tmp_log, log=tmp_log,
                registry=tmp_registry, store=store, timestamp="2026-07-20T00:02:00+00:00",
            )
            outcomes[name] = ("ok", r["newly_recorded"])
        except claims.RouteReceiptError as exc:
            outcomes[name] = ("conflict", exc.failure_mode)

    t1 = threading.Thread(target=_attempt, args=("t1", "https://ilp.example/pay/A"))
    t2 = threading.Thread(target=_attempt, args=("t2", "https://ilp.example/pay/B"))
    t1.start()
    t2.start()
    t1.join(timeout=30)
    t2.join(timeout=30)

    results = list(outcomes.values())
    assert ("ok", True) in results
    assert results.count(("ok", True)) == 1
    other = [r for r in results if r != ("ok", True)][0]
    assert other == ("conflict", "outcome_conflict")

    final_store = claims.ClaimsStore(claims_db_path)
    rows = final_store.list_route_receipts_for_manifest(mh)
    terminal_rows = [r for r in rows if r["outcome"] in ("settled", "skipped")]
    assert len(terminal_rows) == 1


# ---------------------------------------------------------------------------
# AC13 -- conservation end-to-end (spec's global AC12)
# ---------------------------------------------------------------------------


def test_u2b_ac13_conservation_end_to_end(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    """payer_retained > 0 (declared share_bps sum < 10000) AND one settled leg
    AND one skipped (credited-unpaid) leg. After receipting both:
      payer_retained + sum(settled leg.amount) + sum(skipped leg.amount) == amount_in.value
    joined leg-by-leg on the MANIFEST's own amounts (a skipped receipt's own
    sent_amount is null by design), plus each settled receipt's sent_value
    equals that leg's manifest amount exactly. A whole-manifest join, not an
    aggregate a compensating over/under-pay could slip through.
    """
    d = _contributor(tmp_path, tmp_registry, "u2bac13-d")  # will be settled (routable)
    m = _contributor(tmp_path, tmp_registry, "u2bac13-m")  # will be skipped (credited-unpaid)
    compiler = _signer(tmp_path, "u2bac13-compiler")
    node_signer = _signer(tmp_path, "u2bac13-node")

    subject_mh = _make_content_deposit(
        tmp_log, d, tmp_registry, agent_id="agent:u2bac13-d", payload={"work": "x"},
        summary="work x", timestamp="2026-07-20T00:00:00+00:00",
    )
    # share_bps sum (3000 + 2000 = 5000) < 10000 -> payer_retained > 0.
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=3000,
        scope="standing", declared_by="agent:u2bac13-d", agent_id="agent:u2bac13-d",
        signer=d, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:01+00:00",
    )
    claims.record_routing_terms(
        subject=subject_mh, beneficiary_pubkey_id=m.pubkey_id_str, share_bps=2000,
        scope="standing", declared_by="agent:u2bac13-m", agent_id="agent:u2bac13-m",
        signer=m, registry=tmp_registry, recorder=tmp_log, timestamp="2026-07-20T00:00:02+00:00",
    )
    # Only D's wallet is bound - M stays credited-unpaid (Void Principle).
    claims.record_wallet_binding(
        subject=d.pubkey_id_str, wallet_address="https://wallet.example/u2bac13-d",
        agent_id="agent:u2bac13-d", signer=d, registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-07-20T00:00:03+00:00",
    )

    event_ref = "evt-u2bac13"
    amount_value = 733  # non-trivial, not evenly divisible by the bps split
    result = compile_route_manifest(
        event_kind="demo-sale", event_ref=event_ref, subject=subject_mh,
        amount_value=amount_value, asset_code="USD", asset_scale=2,
        agent_id="agent:u2bac13-route", log=tmp_log, registry=tmp_registry, signer=compiler,
        timestamp="2026-07-20T00:01:00+00:00",
    )
    mh = result["manifest_hash"]
    rm = result["manifest"]["route_manifest"]
    assert rm["payer_retained"] > 0

    legs_by_id = {leg["beneficiary_pubkey_id"]: leg for leg in rm["legs"]}
    d_leg = legs_by_id[d.pubkey_id_str]
    m_leg = legs_by_id[m.pubkey_id_str]
    assert d_leg["leg_status"] == "routable"
    assert m_leg["leg_status"] == "credited-unpaid"

    _record(
        tmp_log, tmp_registry, tmp_claims_store, node_signer,
        event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id=d.pubkey_id_str,
        outcome="settled", op_payment_id="https://ilp.example/pay/1",
        sent_value=d_leg["amount"], sent_asset_code="USD", sent_asset_scale=2,
        timestamp="2026-07-20T00:02:00+00:00",
    )
    _record(
        tmp_log, tmp_registry, tmp_claims_store, node_signer,
        event_ref=event_ref, manifest_hash=mh, beneficiary_pubkey_id=m.pubkey_id_str,
        outcome="skipped", reason="not_routable", timestamp="2026-07-20T00:02:01+00:00",
    )

    receipts = claims.route_receipts_for_manifest(mh, store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    receipts_by_id = {r["beneficiary_pubkey_id"]: r for r in receipts}

    settled_total = sum(
        legs_by_id[bpid]["amount"] for bpid, r in receipts_by_id.items() if r["outcome"] == "settled"
    )
    skipped_total = sum(
        legs_by_id[bpid]["amount"] for bpid, r in receipts_by_id.items() if r["outcome"] == "skipped"
    )
    assert rm["payer_retained"] + settled_total + skipped_total == amount_value

    for bpid, r in receipts_by_id.items():
        if r["outcome"] == "settled":
            assert r["sent_amount"]["value"] == legs_by_id[bpid]["amount"]
        else:
            assert r["sent_amount"] is None
