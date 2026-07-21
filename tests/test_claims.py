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
