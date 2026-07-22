"""Acceptance criteria tests for zephyr per-leg execution-state store (rail U2b, D2).

All against scratch DBs (tmp_path, env-injected ZEPHYR_ROUTE_EXEC_DB) - never
/data/zephyr/route_exec.db. No signing/attribution involved here at all;
manifest_hash/beneficiary_pubkey_id are opaque strings for this module's
purposes.

Coverage map:
  AC1 -- every legal edge in the state table succeeds
  AC2 -- every illegal edge raises LegStateError (incl. the pending ->
         submitted shortcut, any transition out of a terminal state)
  AC3 -- claim_leg is idempotent while pending; re-claim after failed
         increments attempt and clears last_error
  AC4 -- record_submitted persists outgoing_payment_id before any terminal
         transition (recoverable by GET, never re-created)
  AC5 -- own DB file, never claims.db; singleton re-reads env on creation
  AC6 -- concurrent-writer TOCTOU (BEGIN IMMEDIATE) - two writers, one
         deterministic winner
  AC7 -- injectable timestamp threads through every setter (no datetime.now()
         in a spot a test cannot pin)
"""

from __future__ import annotations

import threading

import pytest

from zephyr import route_exec
from zephyr.route_exec import LegExecutionStore, LegStateError

MH = "sha256:" + "1" * 64
BPID = "ed25519:deadbeefcafef00d"


@pytest.fixture()
def store(tmp_path):
    return LegExecutionStore(tmp_path / "route_exec.db")


@pytest.fixture()
def tmp_store_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ZEPHYR_ROUTE_EXEC_DB", str(tmp_path / "route_exec.db"))
    route_exec._reset_route_exec_store()
    yield
    route_exec._reset_route_exec_store()


# ---------------------------------------------------------------------------
# AC1 -- every legal edge succeeds
# ---------------------------------------------------------------------------


def test_ac1_full_happy_path(store):
    row = store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:00+00:00")
    assert row["state"] == "pending"
    assert row["attempt"] == 0

    row = store.record_quote(MH, BPID, "quote-1", timestamp="2026-07-22T00:00:01+00:00")
    assert row["state"] == "quoted"
    assert row["quote_id"] == "quote-1"

    row = store.record_submitted(MH, BPID, "https://ilp.example/pay/1", timestamp="2026-07-22T00:00:02+00:00")
    assert row["state"] == "submitted"
    assert row["outgoing_payment_id"] == "https://ilp.example/pay/1"

    row = store.record_settled(MH, BPID, timestamp="2026-07-22T00:00:03+00:00")
    assert row["state"] == "settled"


def test_ac1_skip_from_pending(store):
    store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:00+00:00")
    row = store.record_skipped(MH, BPID, "not_routable", timestamp="2026-07-22T00:00:01+00:00")
    assert row["state"] == "skipped"
    assert row["last_error"] == "not_routable"


def test_ac1_skip_from_quoted(store):
    store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:00+00:00")
    store.record_quote(MH, BPID, "quote-1", timestamp="2026-07-22T00:00:01+00:00")
    row = store.record_skipped(MH, BPID, "address_changed", timestamp="2026-07-22T00:00:02+00:00")
    assert row["state"] == "skipped"


@pytest.mark.parametrize("from_state_setup", ["pending", "quoted", "submitted"])
def test_ac1_fail_from_any_in_flight_state(store, from_state_setup):
    store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:00+00:00")
    if from_state_setup in ("quoted", "submitted"):
        store.record_quote(MH, BPID, "quote-1", timestamp="2026-07-22T00:00:01+00:00")
    if from_state_setup == "submitted":
        store.record_submitted(MH, BPID, "https://ilp.example/pay/1", timestamp="2026-07-22T00:00:02+00:00")

    row = store.record_failed(MH, BPID, "ILPTimeoutError", timestamp="2026-07-22T00:00:03+00:00")
    assert row["state"] == "failed"
    assert row["last_error"] == "ILPTimeoutError"


def test_ac1_reclaim_after_failed(store):
    store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:00+00:00")
    store.record_failed(MH, BPID, "ILPTimeoutError", timestamp="2026-07-22T00:00:01+00:00")

    row = store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:02+00:00")
    assert row["state"] == "pending"
    assert row["attempt"] == 1
    assert row["last_error"] is None

    # Must traverse the full path again - no pending -> submitted shortcut,
    # even though outgoing_payment_id was never set this time around.
    row = store.record_quote(MH, BPID, "quote-2", timestamp="2026-07-22T00:00:03+00:00")
    assert row["state"] == "quoted"


# ---------------------------------------------------------------------------
# AC2 -- every illegal edge raises LegStateError
# ---------------------------------------------------------------------------


def test_ac2_pending_to_submitted_shortcut_raises(store):
    store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:00+00:00")
    with pytest.raises(LegStateError) as excinfo:
        store.record_submitted(MH, BPID, "https://ilp.example/pay/1", timestamp="2026-07-22T00:00:01+00:00")
    assert excinfo.value.from_state == "pending"
    assert excinfo.value.to_state == "submitted"


def test_ac2_reclaim_with_persisted_payment_id_still_requires_full_path(store):
    """A re-claimed leg that already carries an outgoing_payment_id from a
    prior attempt still cannot jump straight to submitted - reconcile-by-read
    of that payment is U2c's job; U2b just refuses the illegal edge."""
    store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:00+00:00")
    store.record_quote(MH, BPID, "quote-1", timestamp="2026-07-22T00:00:01+00:00")
    store.record_submitted(MH, BPID, "https://ilp.example/pay/1", timestamp="2026-07-22T00:00:02+00:00")
    store.record_failed(MH, BPID, "ILPTimeoutError", timestamp="2026-07-22T00:00:03+00:00")

    row = store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:04+00:00")
    assert row["state"] == "pending"
    assert row["outgoing_payment_id"] == "https://ilp.example/pay/1"  # still persisted, but inert

    with pytest.raises(LegStateError) as excinfo:
        store.record_submitted(MH, BPID, "https://ilp.example/pay/2", timestamp="2026-07-22T00:00:05+00:00")
    assert excinfo.value.from_state == "pending"
    assert excinfo.value.to_state == "submitted"


@pytest.mark.parametrize(
    "terminal_setup,edge_call",
    [
        ("settled", lambda s: s.record_quote(MH, BPID, "q", timestamp="2026-07-22T00:01:00+00:00")),
        ("settled", lambda s: s.claim_leg(MH, BPID, timestamp="2026-07-22T00:01:00+00:00")),
        ("skipped", lambda s: s.record_quote(MH, BPID, "q", timestamp="2026-07-22T00:01:00+00:00")),
        ("skipped", lambda s: s.claim_leg(MH, BPID, timestamp="2026-07-22T00:01:00+00:00")),
    ],
)
def test_ac2_no_transition_out_of_terminal_state(store, terminal_setup, edge_call):
    store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:00+00:00")
    if terminal_setup == "settled":
        store.record_quote(MH, BPID, "quote-1", timestamp="2026-07-22T00:00:01+00:00")
        store.record_submitted(MH, BPID, "https://ilp.example/pay/1", timestamp="2026-07-22T00:00:02+00:00")
        store.record_settled(MH, BPID, timestamp="2026-07-22T00:00:03+00:00")
    else:
        store.record_skipped(MH, BPID, "not_routable", timestamp="2026-07-22T00:00:01+00:00")

    with pytest.raises(LegStateError):
        edge_call(store)


def test_ac2_quote_without_claim_raises(store):
    with pytest.raises(LegStateError) as excinfo:
        store.record_quote(MH, BPID, "quote-1", timestamp="2026-07-22T00:00:00+00:00")
    assert excinfo.value.from_state is None
    assert excinfo.value.to_state == "quoted"


def test_ac2_settle_without_submit_raises(store):
    store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:00+00:00")
    store.record_quote(MH, BPID, "quote-1", timestamp="2026-07-22T00:00:01+00:00")
    with pytest.raises(LegStateError) as excinfo:
        store.record_settled(MH, BPID, timestamp="2026-07-22T00:00:02+00:00")
    assert excinfo.value.from_state == "quoted"
    assert excinfo.value.to_state == "settled"


def test_ac2_skip_from_submitted_raises(store):
    store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:00+00:00")
    store.record_quote(MH, BPID, "quote-1", timestamp="2026-07-22T00:00:01+00:00")
    store.record_submitted(MH, BPID, "https://ilp.example/pay/1", timestamp="2026-07-22T00:00:02+00:00")
    with pytest.raises(LegStateError) as excinfo:
        store.record_skipped(MH, BPID, "not_routable", timestamp="2026-07-22T00:00:03+00:00")
    assert excinfo.value.from_state == "submitted"
    assert excinfo.value.to_state == "skipped"


# ---------------------------------------------------------------------------
# AC3 -- claim_leg idempotent; re-claim increments attempt
# ---------------------------------------------------------------------------


def test_ac3_claim_leg_idempotent_while_pending(store):
    row1 = store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:00+00:00")
    row2 = store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:01+00:00")
    assert row1["state"] == row2["state"] == "pending"
    assert row2["attempt"] == 0


def test_ac3_claim_leg_illegal_from_quoted(store):
    store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:00+00:00")
    store.record_quote(MH, BPID, "quote-1", timestamp="2026-07-22T00:00:01+00:00")
    with pytest.raises(LegStateError) as excinfo:
        store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:02+00:00")
    assert excinfo.value.from_state == "quoted"


# ---------------------------------------------------------------------------
# AC4 -- record_submitted persists outgoing_payment_id before any terminal transition
# ---------------------------------------------------------------------------


def test_ac4_outgoing_payment_id_persisted_before_settle(store):
    store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:00+00:00")
    store.record_quote(MH, BPID, "quote-1", timestamp="2026-07-22T00:00:01+00:00")
    row = store.record_submitted(MH, BPID, "https://ilp.example/pay/1", timestamp="2026-07-22T00:00:02+00:00")
    assert row["state"] == "submitted"
    assert row["outgoing_payment_id"] == "https://ilp.example/pay/1"

    # Simulated crash here - re-read reflects the persisted payment id even
    # though settle never ran.
    fetched = store.get_leg_state(MH, BPID)
    assert fetched["outgoing_payment_id"] == "https://ilp.example/pay/1"
    assert fetched["state"] == "submitted"


# ---------------------------------------------------------------------------
# AC5 -- own DB file, singleton re-reads env
# ---------------------------------------------------------------------------


def test_ac5_singleton_reads_env_on_creation(tmp_store_env, tmp_path):
    st = route_exec.get_route_exec_store()
    assert st.db_path == tmp_path / "route_exec.db"
    assert (tmp_path / "route_exec.db").exists()


def test_ac5_module_functions_use_singleton(tmp_store_env):
    row = route_exec.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:00+00:00")
    assert row["state"] == "pending"
    fetched = route_exec.get_leg_state(MH, BPID)
    assert fetched["state"] == "pending"

    legs = route_exec.legs_for_manifest(MH)
    assert len(legs) == 1
    assert legs[0]["beneficiary_pubkey_id"] == BPID


def test_ac5_legs_for_manifest_scopes_by_manifest_hash(store):
    store.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:00+00:00")
    store.claim_leg(MH, "ed25519:another", timestamp="2026-07-22T00:00:01+00:00")
    other_mh = "sha256:" + "2" * 64
    store.claim_leg(other_mh, BPID, timestamp="2026-07-22T00:00:02+00:00")

    legs = store.legs_for_manifest(MH)
    assert len(legs) == 2
    assert {l["beneficiary_pubkey_id"] for l in legs} == {BPID, "ed25519:another"}


# ---------------------------------------------------------------------------
# AC6 -- concurrent-writer TOCTOU
# ---------------------------------------------------------------------------


def test_ac6_concurrent_claim_exactly_one_creates(tmp_path):
    """Two separate LegExecutionStore instances (own connection, own lock)
    against the same file - proves the SQLite-level BEGIN IMMEDIATE guard,
    not just the in-process mutex."""
    db_path = tmp_path / "route_exec_concurrent.db"
    LegExecutionStore(db_path)  # create schema up front

    results = {}

    def _attempt(name):
        st = LegExecutionStore(db_path)
        row = st.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:00+00:00")
        results[name] = row["state"]

    t1 = threading.Thread(target=_attempt, args=("t1",))
    t2 = threading.Thread(target=_attempt, args=("t2",))
    t1.start()
    t2.start()
    t1.join(timeout=30)
    t2.join(timeout=30)

    assert results["t1"] == "pending"
    assert results["t2"] == "pending"

    final = LegExecutionStore(db_path)
    legs = final.legs_for_manifest(MH)
    assert len(legs) == 1  # not two rows


def test_ac6_concurrent_settle_one_wins_one_raises(tmp_path):
    db_path = tmp_path / "route_exec_concurrent2.db"
    setup = LegExecutionStore(db_path)
    setup.claim_leg(MH, BPID, timestamp="2026-07-22T00:00:00+00:00")
    setup.record_quote(MH, BPID, "quote-1", timestamp="2026-07-22T00:00:01+00:00")
    setup.record_submitted(MH, BPID, "https://ilp.example/pay/1", timestamp="2026-07-22T00:00:02+00:00")

    outcomes = {}

    def _attempt(name):
        st = LegExecutionStore(db_path)
        try:
            st.record_settled(MH, BPID, timestamp="2026-07-22T00:00:03+00:00")
            outcomes[name] = "ok"
        except LegStateError as exc:
            outcomes[name] = exc.from_state

    t1 = threading.Thread(target=_attempt, args=("t1",))
    t2 = threading.Thread(target=_attempt, args=("t2",))
    t1.start()
    t2.start()
    t1.join(timeout=30)
    t2.join(timeout=30)

    results = list(outcomes.values())
    assert results.count("ok") == 1
    assert results.count("settled") == 1  # the loser saw state already settled


# ---------------------------------------------------------------------------
# AC7 -- injectable timestamp, no datetime.now() a test cannot pin
# ---------------------------------------------------------------------------


def test_ac7_updated_at_reflects_injected_timestamp(store):
    row = store.claim_leg(MH, BPID, timestamp="2020-01-01T00:00:00+00:00")
    assert row["updated_at"] == "2020-01-01T00:00:00+00:00"

    row = store.record_quote(MH, BPID, "quote-1", timestamp="2020-01-01T00:00:01+00:00")
    assert row["updated_at"] == "2020-01-01T00:00:01+00:00"
