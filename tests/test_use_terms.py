"""Acceptance criteria tests for use_terms declarations (rail zephyr-use-terms-consent-v0).

All identities are SYNTHETIC (agent:use-terms-test / contributor-style names).
No writes outside tmp dirs: ZEPHYR_CLAIMS_DB is monkeypatched to a tmp_path
location and the claims-store singleton is reset around every test, mirroring
the fixtures in tests/test_claims.py:79-89 (tmp_log / tmp_registry /
tmp_claims_store).

Coverage map (spec AC list):
  AC1  -- declare -> resolve -> verify round-trip; identical re-record is a
          no-op; a differing row at the same manifest_hash raises loudly
  AC2  -- self-declared only, STRUCTURALLY: no declared_by (nor
          method/subject_kind/on_behalf_of/proxy) parameter exists
  AC3  -- closed vocabulary + disjoint/union-non-empty validator; tombstone
          exemption
  AC3b -- scope grammar (mirrors routing_terms) + empty event ref rejected +
          an event-scoped declaration is still consulted (v0 ruling)
  AC4  -- tri-state: permitted / denied / undeclared distinct; unknown use raises
  AC5  -- revocation: additive tombstone, no resurfacing, re-declaration works
  AC6  -- selection law: recorded_at never load-bearing; seq not caller-settable
  AC7  -- tamper: missing_domain_row / orphan_domain_row / fail-closed with no
          fallback / malformed uses JSON never raises
  AC8  -- revoked declared-by key, BOTH polarities (rotated/retired stands;
          compromised/reason-missing -> undeclared) + the README consumer law
"""

from __future__ import annotations

import inspect
import json
import sqlite3

import pytest

from zephyr import claims
from zephyr.attribution import AttributionLog
from zephyr.registry import PubkeyRegistry
from zephyr.routing import RouteTamperError
from zephyr.signing import AgentSigner

REPO_ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]

# A real-shaped work hash (sha256: + 64 lowercase hex) - what the ecosystem
# actually produces, not a bare digest.
WORK = "sha256:" + "ab" * 32
WORK_2 = "sha256:" + "cd" * 32


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


def _declare(tmp_path, tmp_log, tmp_registry, store, *, name="ac", subject=WORK,
             allowed=("remix",), denied=("training",), scope="standing", revokes=False,
             note="", timestamp=None, signer=None):
    s = signer or _signer(tmp_path, name)
    result = claims.record_use_terms(
        subject=subject,
        allowed_uses=list(allowed),
        denied_uses=list(denied),
        scope=scope,
        agent_id="agent:use-terms-test",
        revokes=revokes,
        note=note,
        signer=s,
        registry=tmp_registry,
        recorder=tmp_log,
        timestamp=timestamp,
    )
    return s, result


# ---------------------------------------------------------------------------
# AC1 -- round-trip + loud insert
# ---------------------------------------------------------------------------


def test_ac1_declare_resolve_verify_round_trip(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s, result = _declare(tmp_path, tmp_log, tmp_registry, tmp_claims_store)

    assert result["manifest_hash"].startswith("sha256:")
    assert result["newly_recorded"] is True

    # The consent's OWN envelope hash is the domain row's manifest_hash - never
    # the work hash (the work hash is subject).
    assert result["manifest_hash"] != WORK

    row = tmp_log.get(result["manifest_hash"], registry=tmp_registry)
    assert row is not None
    assert row["verification_status"] == "verified"
    assert row["store_kind"] == "use_terms"
    assert row["target_key"] == WORK

    resolved = claims.resolve_use_terms(
        WORK, store=tmp_claims_store, log=tmp_log, registry=tmp_registry
    )
    assert resolved is not None
    assert resolved["subject"] == WORK
    assert resolved["declared_by"] == s.pubkey_id_str
    assert resolved["allowed_uses"] == ["remix"]
    assert resolved["denied_uses"] == ["training"]
    assert resolved["scope"] == "standing"
    assert resolved["revokes"] is False
    assert resolved["manifest_hash"] == result["manifest_hash"]
    assert resolved["verification"] == "verified"
    assert isinstance(resolved["seq"], int)

    rows = tmp_claims_store.list_use_terms_for_subject(WORK)
    assert len(rows) == 1
    vr = claims.verify_use_terms_row(rows[0], log=tmp_log, registry=tmp_registry)
    assert vr.ok is True
    assert vr.failure_mode is None


def test_ac1_resolve_return_shape_is_pinned(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    _declare(tmp_path, tmp_log, tmp_registry, tmp_claims_store)
    resolved = claims.resolve_use_terms(
        WORK, store=tmp_claims_store, log=tmp_log, registry=tmp_registry
    )
    assert set(resolved.keys()) == {
        "subject", "declared_by", "allowed_uses", "denied_uses", "scope",
        "revokes", "seq", "manifest_hash", "verification",
    }


def test_ac1_identical_re_record_is_a_noop(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    """The no-op branch (not an INSERT-OR-IGNORE swallow) fires: identical
    content at the same envelope hash inserts nothing."""
    s = _signer(tmp_path, "ac1-idem")
    kwargs = dict(
        subject=WORK, allowed_uses=["remix"], denied_uses=["training"],
        scope="standing", agent_id="agent:use-terms-test", signer=s,
        registry=tmp_registry, recorder=tmp_log,
        timestamp="2026-09-28T00:00:00+00:00",
    )
    claims.record_use_terms(**kwargs)
    claims.record_use_terms(**kwargs)  # byte-identical re-record
    rows = tmp_claims_store.list_use_terms_for_subject(WORK)
    assert len(rows) == 1


def test_ac1_differing_row_at_same_hash_raises_integrity_error(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    """DD9's loud insert: a pre-seeded row at the same envelope hash with ANY
    differing column raises - never absorbed by OR IGNORE."""
    s = _signer(tmp_path, "ac1-loud")
    result = claims.record_use_terms(
        subject=WORK, allowed_uses=["remix"], denied_uses=["training"],
        scope="standing", agent_id="agent:use-terms-test", signer=s,
        registry=tmp_registry, recorder=tmp_log,
    )
    mh = result["manifest_hash"]

    with pytest.raises(sqlite3.IntegrityError):
        tmp_claims_store.insert_use_terms(
            manifest_hash=mh, subject=WORK, declared_by=s.pubkey_id_str,
            allowed_uses=["remix", "training"], denied_uses=[],  # DIFFERS
            scope="standing", revokes=False, note="", summary="different",
            recorded_at="2026-09-28T00:00:00+00:00",
        )


def test_ac1_multiple_declarations_for_one_work_coexist(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    """Distinct declarations for the same work are distinct rows (the row key
    is the consent's own envelope hash, not the work hash)."""
    s = _signer(tmp_path, "ac1-multi")
    claims.record_use_terms(
        subject=WORK, allowed_uses=["remix"], denied_uses=[],
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:00+00:00",
    )
    claims.record_use_terms(
        subject=WORK, allowed_uses=["training"], denied_uses=[],
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:01+00:00",
    )
    rows = tmp_claims_store.list_use_terms_for_subject(WORK)
    assert len(rows) == 2
    assert len({r["manifest_hash"] for r in rows}) == 2


# ---------------------------------------------------------------------------
# AC2 -- self-declared only, structurally
# ---------------------------------------------------------------------------


def test_ac2_no_proxy_declaration_parameter_exists():
    """There is no parameter with which to declare use terms for another
    party: the forbidden set is verbatim from test_claims.py:182, declared_by
    included - the test passes precisely because the parameter does not exist."""
    sig = inspect.signature(claims.record_use_terms)
    forbidden = {"method", "declared_by", "subject_kind", "on_behalf_of", "proxy"}
    assert forbidden.isdisjoint(sig.parameters.keys())


def test_ac2_insert_has_no_declarant_override_beyond_stored_value():
    sig = inspect.signature(claims.ClaimsStore.insert_use_terms)
    assert "seq" not in sig.parameters
    assert "declared_by" in sig.parameters  # store-side column only; the record_* rail derives it


def test_ac2_stored_declared_by_is_the_signer(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s, result = _declare(tmp_path, tmp_log, tmp_registry, tmp_claims_store, name="ac2")
    rows = tmp_claims_store.list_use_terms_for_subject(WORK)
    assert rows[0]["declared_by"] == s.pubkey_id_str == result["pubkey_id"]

    resolved = claims.resolve_use_terms(
        WORK, store=tmp_claims_store, log=tmp_log, registry=tmp_registry
    )
    # declared_by ships in the return: the entitlement cross-check is the
    # consumer's job (consent squatting is structural, not a defect).
    assert resolved["declared_by"] == s.pubkey_id_str


# ---------------------------------------------------------------------------
# AC3 -- closed vocabulary
# ---------------------------------------------------------------------------


def test_ac3_unknown_allowed_token_raises_naming_vocab(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac3-unknown")
    with pytest.raises(ValueError) as exc:
        claims.record_use_terms(
            subject=WORK, allowed_uses=["something-weird"], denied_uses=[],
            agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
            recorder=tmp_log,
        )
    assert "training" in str(exc.value) and "remix" in str(exc.value) and "redistribution" in str(exc.value)
    assert tmp_claims_store.list_use_terms_for_subject(WORK) == []


def test_ac3_unknown_denied_token_raises(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac3-denied-bad")
    with pytest.raises(ValueError, match="vocabulary"):
        claims.record_use_terms(
            subject=WORK, allowed_uses=["remix"], denied_uses=["vendetta"],
            agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
            recorder=tmp_log,
        )


def test_ac3_overlap_raises(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac3-overlap")
    with pytest.raises(ValueError, match="overlap"):
        claims.record_use_terms(
            subject=WORK, allowed_uses=["remix"], denied_uses=["remix"],
            agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
            recorder=tmp_log,
        )


def test_ac3_empty_union_raises_on_a_declaration(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac3-empty")
    with pytest.raises(ValueError, match="must not both be empty"):
        claims.record_use_terms(
            subject=WORK, allowed_uses=[], denied_uses=[],
            agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
            recorder=tmp_log,
        )


def test_ac3_tombstone_is_exempt_from_the_validator(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    """DD5: a tombstone declares nothing - both lists empty is REQUIRED, and
    DD4's validator must not reject it."""
    s = _signer(tmp_path, "ac3-tomb")
    result = claims.record_use_terms(
        subject=WORK, allowed_uses=[], denied_uses=[], revokes=True,
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log,
    )
    assert result["newly_recorded"] is True
    rows = tmp_claims_store.list_use_terms_for_subject(WORK)
    assert rows[0]["revokes"] == 1
    assert json.loads(rows[0]["allowed_uses"]) == []
    assert json.loads(rows[0]["denied_uses"]) == []


def test_ac3_tombstone_with_content_raises(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac3-tomb-bad")
    with pytest.raises(ValueError, match="must both be empty"):
        claims.record_use_terms(
            subject=WORK, allowed_uses=["remix"], denied_uses=[], revokes=True,
            agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
            recorder=tmp_log,
        )


def test_ac3_all_three_vocab_tokens_are_writable(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac3-full")
    claims.record_use_terms(
        subject=WORK, allowed_uses=list(claims.USE_VOCAB), denied_uses=[],
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log,
    )
    assert claims.USE_VOCAB == ("training", "remix", "redistribution")
    assert claims.check_use(WORK, "redistribution", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "permitted"


# ---------------------------------------------------------------------------
# AC3b -- scope grammar (v0: stored + hashed, never consulted)
# ---------------------------------------------------------------------------


def test_ac3b_bad_scope_raises(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac3b-bad")
    with pytest.raises(ValueError, match="scope"):
        claims.record_use_terms(
            subject=WORK, allowed_uses=["remix"], denied_uses=[], scope="global",
            agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
            recorder=tmp_log,
        )


def test_ac3b_bare_event_prefix_raises(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac3b-empty-ref")
    with pytest.raises(ValueError, match="scope"):
        claims.record_use_terms(
            subject=WORK, allowed_uses=["remix"], denied_uses=[], scope="event:",
            agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
            recorder=tmp_log,
        )


def test_ac3b_event_scoped_declaration_is_still_consulted(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    """DD3's v0 ruling: scope is stored and hashed but NEVER consulted - an
    event-scoped declaration governs the standing tri-state."""
    s, _ = _declare(tmp_path, tmp_log, tmp_registry, tmp_claims_store,
                    name="ac3b-event", allowed=("remix",), denied=("training",),
                    scope="event:evt-42")
    assert claims.check_use(WORK, "remix", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "permitted"
    assert claims.check_use(WORK, "training", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "denied"
    resolved = claims.resolve_use_terms(WORK, store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert resolved["scope"] == "event:evt-42"


def test_ac3b_scope_is_inside_the_signed_envelope(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s, _ = _declare(tmp_path, tmp_log, tmp_registry, tmp_claims_store,
                    name="ac3b-hash", scope="event:evt-99")
    row = tmp_claims_store.list_use_terms_for_subject(WORK)[0]
    # Flip the scope cell only: the envelope no longer re-hashes (the field is
    # bound), so verify fails rather than silently reporting the tampered value.
    tmp_claims_store._conn.execute("UPDATE use_terms SET scope = 'standing' WHERE manifest_hash = ?", (row["manifest_hash"],))
    tmp_claims_store._conn.commit()
    tampered = tmp_claims_store.list_use_terms_for_subject(WORK)[0]
    assert tampered["scope"] == "standing"  # the raw cell DID change
    vr = claims.verify_use_terms_row(tampered, log=tmp_log, registry=tmp_registry)
    assert vr.ok is False
    assert vr.failure_mode == "hash_mismatch"
    assert claims.resolve_use_terms(WORK, store=tmp_claims_store, log=tmp_log, registry=tmp_registry) is None


# ---------------------------------------------------------------------------
# AC4 -- tri-state
# ---------------------------------------------------------------------------


def test_ac4_permitted_denied_undeclared_are_distinct(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    _declare(tmp_path, tmp_log, tmp_registry, tmp_claims_store,
             name="ac4", allowed=("remix",), denied=("training",))

    permitted = claims.check_use(WORK, "remix", store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    denied = claims.check_use(WORK, "training", store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    undeclared = claims.check_use(WORK, "redistribution", store=tmp_claims_store, log=tmp_log, registry=tmp_registry)

    assert (permitted, denied, undeclared) == ("permitted", "denied", "undeclared")
    assert len({permitted, denied, undeclared}) == 3


def test_ac4_absent_subject_is_undeclared_not_denied(tmp_log, tmp_registry, tmp_claims_store):
    assert claims.check_use(WORK_2, "remix", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "undeclared"
    assert claims.resolve_use_terms(WORK_2, store=tmp_claims_store, log=tmp_log, registry=tmp_registry) is None


def test_ac4_unknown_use_argument_raises(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    _declare(tmp_path, tmp_log, tmp_registry, tmp_claims_store, name="ac4-unknown")
    with pytest.raises(ValueError) as exc:
        claims.check_use(WORK, "vendetta", store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert "training" in str(exc.value) and "remix" in str(exc.value) and "redistribution" in str(exc.value)


def test_ac4_bad_subject_shape_raises_before_any_write(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    """DD1: the gate is 'sha256:' + 64 lowercase hex - the shape real work
    hashes actually carry. A bare digest is rejected; so is uppercase."""
    s = _signer(tmp_path, "ac4-shape")
    for bad in ["ab" * 32, "sha256:" + "AB" * 32, "sha256:" + "ab" * 31, "sha512:" + "ab" * 32, ""]:
        with pytest.raises(ValueError, match="subject"):
            claims.record_use_terms(
                subject=bad, allowed_uses=["remix"], denied_uses=[],
                agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
                recorder=tmp_log,
            )
    assert tmp_claims_store.list_use_terms_for_subject(WORK) == []


# ---------------------------------------------------------------------------
# AC5 -- revocation is additive, history-preserving, never skipped over
# ---------------------------------------------------------------------------


def test_ac5_tombstone_makes_check_undeclared_not_denied(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac5")
    claims.record_use_terms(
        subject=WORK, allowed_uses=["remix"], denied_uses=["training"],
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:00+00:00",
    )
    claims.record_use_terms(
        subject=WORK, allowed_uses=[], denied_uses=[], revokes=True,
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:01+00:00",
    )

    # consent withdrawn is not consent to refuse
    assert claims.check_use(WORK, "training", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "undeclared"
    assert claims.check_use(WORK, "remix", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "undeclared"
    assert claims.resolve_use_terms(WORK, store=tmp_claims_store, log=tmp_log, registry=tmp_registry) is None


def test_ac5_tombstone_itself_verifies_and_history_stands(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac5-history")
    first = claims.record_use_terms(
        subject=WORK, allowed_uses=["remix"], denied_uses=["training"],
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:00+00:00",
    )
    tomb = claims.record_use_terms(
        subject=WORK, allowed_uses=[], denied_uses=[], revokes=True,
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:01+00:00",
    )

    rows = {r["manifest_hash"]: r for r in tmp_claims_store.list_use_terms_for_subject(WORK)}
    assert set(rows) == {first["manifest_hash"], tomb["manifest_hash"]}
    for mh, row in rows.items():
        vr = claims.verify_use_terms_row(row, log=tmp_log, registry=tmp_registry)
        assert vr.ok is True, (mh, vr.failure_mode)

    # append-only: nothing updated or deleted
    n = tmp_claims_store._conn.execute("SELECT COUNT(*) AS n FROM use_terms").fetchone()["n"]
    assert n == 2


def test_ac5_redeclaring_after_a_tombstone_reactivates(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac5-reactivate")
    claims.record_use_terms(
        subject=WORK, allowed_uses=["remix"], denied_uses=[],
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:00+00:00",
    )
    claims.record_use_terms(
        subject=WORK, allowed_uses=[], denied_uses=[], revokes=True,
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:01+00:00",
    )
    assert claims.check_use(WORK, "remix", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "undeclared"

    claims.record_use_terms(
        subject=WORK, allowed_uses=["remix", "training"], denied_uses=[],
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:02+00:00",
    )
    assert claims.check_use(WORK, "remix", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "permitted"
    assert claims.check_use(WORK, "training", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "permitted"


def test_ac5_old_permitted_never_resurfaces_behind_a_tombstone(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    """H1's fail-open attack, pinned: with the tombstone as seq-max, NO query
    path consults the older permitted row."""
    s = _signer(tmp_path, "ac5-noresurface")
    first = claims.record_use_terms(
        subject=WORK, allowed_uses=["remix", "training", "redistribution"], denied_uses=[],
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:00+00:00",
    )
    claims.record_use_terms(
        subject=WORK, allowed_uses=[], denied_uses=[], revokes=True,
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:01+00:00",
    )

    for use in claims.USE_VOCAB:
        assert claims.check_use(WORK, use, store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "undeclared"
    assert claims.resolve_use_terms(WORK, store=tmp_claims_store, log=tmp_log, registry=tmp_registry) is None

    # The tombstone is genuinely the seq-max row over ALL rows (tombstones
    # included) - selection did not filter it out and fall back.
    rows = tmp_claims_store.list_use_terms_for_subject(WORK)
    top = max(rows, key=lambda r: r["seq"])
    assert top["revokes"] == 1
    assert top["manifest_hash"] != first["manifest_hash"]


# ---------------------------------------------------------------------------
# AC6 -- selection law: seq, never recorded_at
# ---------------------------------------------------------------------------


def test_ac6_backdated_recorded_at_does_not_change_selection(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac6-backdate")
    claims.record_use_terms(
        subject=WORK, allowed_uses=["remix"], denied_uses=[],
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:00+00:00",
    )
    claims.record_use_terms(
        subject=WORK, allowed_uses=["training"], denied_uses=[],
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-27T00:00:00+00:00",  # BACKDATED
    )
    # seq-max wins: the later-INSERTED (training) declaration is active.
    assert claims.check_use(WORK, "training", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "permitted"
    assert claims.check_use(WORK, "remix", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "undeclared"


def test_ac6_equal_timestamps_still_select_by_seq(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac6-equal")
    claims.record_use_terms(
        subject=WORK, allowed_uses=["remix"], denied_uses=[],
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:00+00:00",
    )
    claims.record_use_terms(
        subject=WORK, allowed_uses=["redistribution"], denied_uses=[],
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:00+00:00",  # IDENTICAL
    )
    assert claims.check_use(WORK, "redistribution", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "permitted"
    assert claims.check_use(WORK, "remix", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "undeclared"


def test_ac6_backdated_tombstone_still_revokes(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac6-tomb-backdate")
    claims.record_use_terms(
        subject=WORK, allowed_uses=["remix"], denied_uses=[],
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:00+00:00",
    )
    claims.record_use_terms(
        subject=WORK, allowed_uses=[], denied_uses=[], revokes=True,
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-01T00:00:00+00:00",  # backdated tombstone
    )
    assert claims.check_use(WORK, "remix", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "undeclared"


def test_ac6_seq_not_caller_settable_and_strictly_increasing(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    sig = inspect.signature(claims.ClaimsStore.insert_use_terms)
    assert "seq" not in sig.parameters
    with pytest.raises(TypeError):
        tmp_claims_store.insert_use_terms(
            manifest_hash="sha256:" + "1" * 64, subject=WORK, declared_by="ed25519:x",
            allowed_uses=["remix"], denied_uses=[], scope="standing", revokes=False,
            note="", summary="x", recorded_at="2026-09-28T00:00:00+00:00", seq=999,
        )

    s = _signer(tmp_path, "ac6-seq")
    seqs = []
    for i, use in enumerate(claims.USE_VOCAB):
        claims.record_use_terms(
            subject=WORK, allowed_uses=[use], denied_uses=[],
            agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
            recorder=tmp_log, timestamp=f"2026-09-28T00:00:0{i}+00:00",
        )
        seqs.append(max(r["seq"] for r in tmp_claims_store.list_use_terms_for_subject(WORK)))
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == 3


def test_ac6_schema_is_purely_additive(tmp_claims_store):
    """Opening the store creates use_terms and leaves every pre-existing claim
    table/column untouched (DD9)."""
    tables = {
        r[0] for r in tmp_claims_store._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    for t in ("wallet_bindings", "routing_terms", "route_manifests", "route_receipts", "use_terms"):
        assert t in tables
    idx = tmp_claims_store._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='use_terms_subject'"
    ).fetchone()
    assert idx is not None
    cols = [r[1] for r in tmp_claims_store._conn.execute("PRAGMA table_info(use_terms)").fetchall()]
    assert cols == [
        "seq", "manifest_hash", "subject", "declared_by", "allowed_uses",
        "denied_uses", "scope", "revokes", "note", "summary", "recorded_at",
    ]


# ---------------------------------------------------------------------------
# AC7 -- tamper
# ---------------------------------------------------------------------------


def test_ac7_deposit_without_domain_row_raises_missing_domain_row(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s, result = _declare(tmp_path, tmp_log, tmp_registry, tmp_claims_store, name="ac7-md")
    tmp_claims_store._conn.execute("DELETE FROM use_terms WHERE manifest_hash = ?", (result["manifest_hash"],))
    tmp_claims_store._conn.commit()

    with pytest.raises(RouteTamperError) as exc:
        claims.check_use(WORK, "remix", store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert exc.value.failure_mode == "missing_domain_row"
    assert result["manifest_hash"] in str(exc.value)
    assert WORK in str(exc.value)


def test_ac7_retagged_deposit_raises_orphan_domain_row(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    """H6: the reverse check. Re-tagging the deposit (store_kind outside
    Merkle coverage) must NOT degrade into a benign 'undeclared'."""
    s, result = _declare(tmp_path, tmp_log, tmp_registry, tmp_claims_store, name="ac7-orphan")
    tmp_log._conn.execute(
        "UPDATE deposits SET store_kind = 'mem', target_key = 'nobody' WHERE manifest_hash = ?",
        (result["manifest_hash"],),
    )
    tmp_log._conn.commit()

    with pytest.raises(RouteTamperError) as exc:
        claims.check_use(WORK, "remix", store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert exc.value.failure_mode == "orphan_domain_row"
    assert result["manifest_hash"] in str(exc.value)

    with pytest.raises(RouteTamperError):
        claims.resolve_use_terms(WORK, store=tmp_claims_store, log=tmp_log, registry=tmp_registry)


def test_ac7_revocation_erasure_attempts_are_loud(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    """The H6 attack, both single-sided halves: re-tagging the tombstone's
    deposit OR deleting its domain row raises loudly - never a silent
    'undeclared'. The both-sides-removed case is the spec's stated residual
    (a raw-write adversary on both dbs; see the parity helper's docstring)."""
    s = _signer(tmp_path, "ac7-erase")
    claims.record_use_terms(
        subject=WORK, allowed_uses=["remix"], denied_uses=[],
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:00+00:00",
    )
    tomb = claims.record_use_terms(
        subject=WORK, allowed_uses=[], denied_uses=[], revokes=True,
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:01+00:00",
    )

    # (a) delete only the tombstone's domain row - deposit-authoritative side.
    tmp_claims_store._conn.execute("DELETE FROM use_terms WHERE manifest_hash = ?", (tomb["manifest_hash"],))
    tmp_claims_store._conn.commit()
    with pytest.raises(RouteTamperError) as exc:
        claims.check_use(WORK, "remix", store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert exc.value.failure_mode == "missing_domain_row"

    # (b) restore the domain row, then re-tag only the deposit - reverse side.
    tmp_claims_store.insert_use_terms(
        manifest_hash=tomb["manifest_hash"], subject=WORK, declared_by=s.pubkey_id_str,
        allowed_uses=[], denied_uses=[], scope="standing", revokes=True, note="",
        summary="use terms revocation for " + WORK,
        recorded_at="2026-09-28T00:00:01+00:00",
    )
    tmp_log._conn.execute(
        "UPDATE deposits SET store_kind = 'mem', target_key = 'nobody' WHERE manifest_hash = ?",
        (tomb["manifest_hash"],),
    )
    tmp_log._conn.commit()
    with pytest.raises(RouteTamperError) as exc:
        claims.check_use(WORK, "remix", store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert exc.value.failure_mode == "orphan_domain_row"

    # The residual is stated honestly in the code, not promised away.
    assert "re-tags" in claims._assert_use_terms_deposit_parity.__doc__


def test_ac7_integrity_failure_fails_closed_with_no_fallback(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s = _signer(tmp_path, "ac7-nofallback")
    claims.record_use_terms(
        subject=WORK, allowed_uses=["remix", "training", "redistribution"], denied_uses=[],
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:00+00:00",
    )
    latest = claims.record_use_terms(
        subject=WORK, allowed_uses=["remix"], denied_uses=[],
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:01+00:00",
    )
    # Break the LATEST row's envelope binding only (flip a bound cell).
    tmp_claims_store._conn.execute(
        "UPDATE use_terms SET scope = 'event:tampered' WHERE manifest_hash = ?", (latest["manifest_hash"],)
    )
    tmp_claims_store._conn.commit()

    assert claims.resolve_use_terms(WORK, store=tmp_claims_store, log=tmp_log, registry=tmp_registry) is None
    # No fallback to the older, still-verifiable all-permitted row.
    for use in claims.USE_VOCAB:
        assert claims.check_use(WORK, use, store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "undeclared"


def test_ac7_malformed_denied_json_never_raises_and_warns(tmp_path, tmp_log, tmp_registry, tmp_claims_store, caplog):
    """DD8's never-raise: a tampered uses cell is an integrity FAIL named
    malformed_uses_json, not a crash and not a silent undeclared."""
    s, result = _declare(tmp_path, tmp_log, tmp_registry, tmp_claims_store,
                         name="ac7-json", allowed=("remix",), denied=("training",))
    tmp_claims_store._conn.execute(
        "UPDATE use_terms SET denied_uses = '{{{not json' WHERE manifest_hash = ?",
        (result["manifest_hash"],),
    )
    tmp_claims_store._conn.commit()

    row = tmp_claims_store.list_use_terms_for_subject(WORK)[0]
    vr = claims.verify_use_terms_row(row, log=tmp_log, registry=tmp_registry)
    assert vr.ok is False
    assert vr.failure_mode == "malformed_uses_json"

    with caplog.at_level("WARNING"):
        verdict = claims.check_use(WORK, "remix", store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    assert verdict == "undeclared"
    assert any("malformed_uses_json" in r.getMessage() for r in caplog.records), [
        r.getMessage() for r in caplog.records
    ]


def test_ac7_key_missing_row_never_raises_and_is_named(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    """Hygiene MINOR (KeyError in verify except): the try body performs seven
    bare row[...] subscripts, so a key-missing row dict must land on the same
    named malformed_uses_json failure as malformed JSON - never escape the
    never-raises guarantee as a crash."""
    s, result = _declare(tmp_path, tmp_log, tmp_registry, tmp_claims_store,
                        name="ac7-keyerror", allowed=("remix",), denied=("training",))
    good = tmp_claims_store.list_use_terms_for_subject(WORK)[0]
    assert claims.verify_use_terms_row(good, log=tmp_log, registry=tmp_registry).ok is True

    for key in ("subject", "declared_by", "allowed_uses", "denied_uses", "scope", "revokes", "note"):
        row = dict(good)
        del row[key]
        vr = claims.verify_use_terms_row(row, log=tmp_log, registry=tmp_registry)
        assert vr.ok is False, f"a row missing {key!r} must not verify ok"
        assert vr.failure_mode == "malformed_uses_json", (
            f"a row missing {key!r} must name the failure, got {vr.failure_mode!r}"
        )
        assert vr.payload is None and vr.envelope is None


def test_ac7_hash_mismatch_is_named_not_silent(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s, result = _declare(tmp_path, tmp_log, tmp_registry, tmp_claims_store, name="ac7-hm")
    row = tmp_claims_store.list_use_terms_for_subject(WORK)[0]
    tmp_claims_store._conn.execute(
        "UPDATE use_terms SET note = 'flipped' WHERE manifest_hash = ?", (result["manifest_hash"],)
    )
    tmp_claims_store._conn.commit()
    fresh = tmp_claims_store.list_use_terms_for_subject(WORK)[0]
    vr = claims.verify_use_terms_row(fresh, log=tmp_log, registry=tmp_registry)
    assert vr.ok is False
    assert vr.failure_mode == "hash_mismatch"
    assert claims.resolve_use_terms(WORK, store=tmp_claims_store, log=tmp_log, registry=tmp_registry) is None


def test_ac7_verdicts_come_from_the_verified_payload_not_raw_columns(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    """DD8: the verdict reads ClaimIntegrityResult.payload, never raw columns.
    A raw-column rewrite that keeps the envelope consistent is impossible, so
    the tampered row must fail the bind rather than be trusted."""
    s, result = _declare(tmp_path, tmp_log, tmp_registry, tmp_claims_store,
                         name="ac7-payload", allowed=("remix",), denied=("training",))
    assert claims.check_use(WORK, "training", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "denied"
    tmp_claims_store._conn.execute(
        "UPDATE use_terms SET denied_uses = '[]' WHERE manifest_hash = ?", (result["manifest_hash"],)
    )
    tmp_claims_store._conn.commit()
    # The raw cell now says "nothing denied", but the envelope still binds the
    # original list -> hash_mismatch -> fail closed, never a relaxed verdict.
    assert claims.check_use(WORK, "training", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "undeclared"


# ---------------------------------------------------------------------------
# AC8 -- revoked declared-by key, BOTH polarities
# ---------------------------------------------------------------------------


def _declared(tmp_path, tmp_log, tmp_registry, store, name):
    s = _signer(tmp_path, name)
    result = claims.record_use_terms(
        subject=WORK, allowed_uses=["remix"], denied_uses=["training"],
        agent_id="agent:use-terms-test", signer=s, registry=tmp_registry,
        recorder=tmp_log, timestamp="2026-09-28T00:00:00+00:00",
    )
    return s, result


def test_ac8_compromised_key_in_window_reports_undeclared(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s, result = _declared(tmp_path, tmp_log, tmp_registry, tmp_claims_store, "ac8-comp")
    tmp_registry.revoke(s.pubkey_id_str, reason="compromised", suspected_at="2000-01-01T00:00:00+00:00")

    row = tmp_claims_store.list_use_terms_for_subject(WORK)[0]
    vr = claims.verify_use_terms_row(row, log=tmp_log, registry=tmp_registry)
    assert vr.ok is False
    assert vr.failure_mode == "suspect"
    assert claims.check_use(WORK, "remix", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "undeclared"


def test_ac8_missing_revocation_reason_reports_undeclared(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    s, result = _declared(tmp_path, tmp_log, tmp_registry, tmp_claims_store, "ac8-reason")
    entry = tmp_registry.lookup(s.pubkey_id_str)
    entry["status"] = "revoked"
    entry["revoked_reason"] = None
    tmp_registry._path(s.pubkey_id_str).write_text(json.dumps(entry, indent=2, sort_keys=True))

    row = tmp_claims_store.list_use_terms_for_subject(WORK)[0]
    vr = claims.verify_use_terms_row(row, log=tmp_log, registry=tmp_registry)
    assert vr.ok is False
    assert vr.failure_mode == "revoked_key"
    assert claims.check_use(WORK, "remix", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "undeclared"


@pytest.mark.parametrize("reason", ["rotated", "retired"])
def test_ac8_clean_retirement_leaves_the_tri_state_standing(tmp_path, tmp_log, tmp_registry, tmp_claims_store, reason):
    """DD5: what was true while consent stood stays verifiable forever - the
    same polarity as verify_row's rotated/retired handling."""
    s, result = _declared(tmp_path, tmp_log, tmp_registry, tmp_claims_store, f"ac8-{reason}")
    tmp_registry.revoke(s.pubkey_id_str, reason=reason)

    row = tmp_claims_store.list_use_terms_for_subject(WORK)[0]
    vr = claims.verify_use_terms_row(row, log=tmp_log, registry=tmp_registry)
    assert vr.ok is True

    assert claims.check_use(WORK, "remix", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "permitted"
    assert claims.check_use(WORK, "training", store=tmp_claims_store, log=tmp_log, registry=tmp_registry) == "denied"


def test_ac8_readme_consumer_law_sentence_ships():
    """DoD-4(a): the README must carry the consumer law - undeclared is never
    permission and never more permissive than a prior denied declaration."""
    readme = (REPO_ROOT / "README.md").read_text()
    flat = " ".join(readme.split())
    assert "never permission" in flat
    assert "never treated more permissively than a prior `denied` declaration" in flat
    assert "`declared_by` is attribution of the declaration, never proof of entitlement" in flat
    assert "never populate `note` with personal data" in flat.lower() or "do not populate `note` with personal data" in flat.lower()
    # DoD-4(b): the anti-overclaim gate. The banned stems are assembled from
    # fragments so this file itself never carries them as contiguous prose.
    import re
    banned = "|".join(["con" + "sent regist" + "ry", "verify who cons" + "ented",
                       "en" + "force", "ad" + "judicat"])
    assert re.search(banned, readme, re.I) is None
    # DoD-4(c): the vocabulary in the README is exactly the shipped one.
    assert "{training, remix, redistribution}" in flat


def test_ac8_compromised_key_never_honored_above_denied_by_the_demo_consumer(tmp_path, tmp_log, tmp_registry, tmp_claims_store):
    """The consumer-law shape at the library level: a revoked declarator flips
    'denied' to 'undeclared', and an honest consumer treats BOTH as 'skip'."""
    s, result = _declared(tmp_path, tmp_log, tmp_registry, tmp_claims_store, "ac8-consumer")
    before = claims.check_use(WORK, "training", store=tmp_claims_store, log=tmp_log, registry=tmp_registry)
    tmp_registry.revoke(s.pubkey_id_str, reason="compromised", suspected_at="2000-01-01T00:00:00+00:00")
    after = claims.check_use(WORK, "training", store=tmp_claims_store, log=tmp_log, registry=tmp_registry)

    assert (before, after) == ("denied", "undeclared")
    # The consumer's own rule: proceed ONLY on an affirmative 'permitted'.
    proceeds = lambda v: v == "permitted"
    assert proceeds(before) is False and proceeds(after) is False
