"""Zephyr RouteManifest compiler (rail U1) + executor contract surface (rail U2a).

Compiles a payment event (amount EXOGENOUS - never derived here) into a
RouteManifest: a signed, deposited claim naming exactly who gets paid what,
by walking declared routing_terms + the 2-hop derived_from lineage cap.

Route-not-compute (decision/zephyr-attribution-not-valuation-route-not-compute):
attribution sets the PATH, declared terms set the RATIO, the amount is
EXOGENOUS. Nothing in this module derives a share from any property of a
contribution - every bps figure comes from a routing_terms deposit someone
signed, taken as given.

Void Principle: a beneficiary without a wallet is credited-but-unpaid, never
dropped, never redistributed - the leg stays in the manifest at full amount
with leg_status="credited-unpaid" and wallet_address=null. A beneficiary
whose registered key is later revoked keeps the same allocation and also
resolves to credited-unpaid (D3) - revocation never redistributes either.

Compile stages (see compile_route_manifest docstring for the strict order).
This function never moves money - it only ever produces and deposits a
signed manifest; execution (U2b) is a separate, later unit.

Executor contract surface (D4): get_manifest_for_event(), is_current_head(),
reverify_leg() are the three pure-read helpers U2b builds on - they exist so
the executor never reimplements head selection, envelope parsing, or per-leg
re-verification. describe_manifest_chain() is a non-raising human diagnostic
for a wedged store; wedged-state *recovery* is deliberately out of scope (a
chain-repair tool is a chain-rewrite tool - see AGENTS.md).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from zephyr.claims import RouteChainError

__all__ = [
    "RouteCompileError",
    "RouteDepthExceeded",
    "RouteReplayConflict",
    "RouteTamperError",
    "RouteChainError",
    "compile_route_manifest",
    "get_manifest_for_event",
    "is_current_head",
    "reverify_leg",
    "describe_manifest_chain",
]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class RouteCompileError(ValueError):
    """Compile refused. Message format: '<reason>: <offending manifest_hash or field>'."""


class RouteDepthExceeded(RouteCompileError):
    """Lineage deeper than the ratified 2-hop cap.

    Raised when the parent deposit itself carries derived_from AND any
    standing routing_terms exists for that grandparent subject - legs may
    derive from the subject's direct terms plus one parent pass-through,
    nothing deeper.
    """


class RouteReplayConflict(RouteCompileError):
    """A route_manifest already exists for this event_ref with DIFFERENT content.

    Message names both manifest_hashes. Recompiling identical inputs is NOT
    a conflict (idempotent return); same event with changed amount/terms is.
    """


class RouteTamperError(RouteCompileError):
    """Integrity-bind failure on a consumed claim.

    Carries ``failure_mode``, one of the verify_row statuses ('unsigned',
    'invalid', 'unknown_key', 'revoked_key', 'suspect'), or 'hash_mismatch'
    (domain payload does not re-hash to its deposit), 'missing_envelope'
    (domain row with no attribution.db deposit), 'missing_domain_row'
    (deposit with no claims-store row when one is required), or 'unknown_key'
    (a routing_terms beneficiary_pubkey_id absent from the registry - D3).
    Message names the manifest_hash and the failure_mode.
    """

    def __init__(self, message: str, *, failure_mode: str):
        super().__init__(message)
        self.failure_mode = failure_mode


# ---------------------------------------------------------------------------
# Largest-remainder integer allocation
# ---------------------------------------------------------------------------


def _largest_remainder(amount_value: int, buckets: list[dict]) -> list[dict]:
    """Allocate amount_value across buckets by largest-remainder, integer-exact.

    Each bucket is a dict with "id" (str | None, None for the payer bucket),
    "bps" (int), "is_payer" (bool). Returns the same dicts with an "amount"
    key added; sum(amount) == amount_value exactly.

    Tie order (larger exact remainder first; among exact ties, beneficiary
    buckets before the payer bucket, then lexicographically ascending id):
    sort key (-remainder, is_payer, id).
    """
    scored = []
    total_floor = 0
    for b in buckets:
        floor = (amount_value * b["bps"]) // 10000
        remainder = (amount_value * b["bps"]) % 10000
        scored.append({**b, "floor": floor, "remainder": remainder})
        total_floor += floor

    leftover = amount_value - total_floor
    order = sorted(
        scored,
        key=lambda b: (-b["remainder"], 1 if b["is_payer"] else 0, b["id"] or ""),
    )
    bump = {id(b) for b in order[:leftover]}

    result = []
    for b in scored:
        amount = b["floor"] + (1 if id(b) in bump else 0)
        result.append({**b, "amount": amount})
    return result


# ---------------------------------------------------------------------------
# Payload layer helpers (allocation vs resolution, for the stage-0 replay guard)
# ---------------------------------------------------------------------------


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _allocation_layer(route_manifest: dict) -> dict:
    return {
        "schema": route_manifest["schema"],
        "event": route_manifest["event"],
        "amount_in": route_manifest["amount_in"],
        "payer_retained": route_manifest["payer_retained"],
        "depth": route_manifest["depth"],
        "legs": [
            {
                "beneficiary_pubkey_id": leg["beneficiary_pubkey_id"],
                "amount": leg["amount"],
                "derivation": leg["derivation"],
            }
            for leg in route_manifest["legs"]
        ],
    }


# ---------------------------------------------------------------------------
# Deposit-authoritative gather (D2 - "missing_domain_row" tamper detection)
# ---------------------------------------------------------------------------


def _gathered_routing_terms(key: str, *, store, lg) -> list[dict]:
    """Every routing_terms domain row for target_key=key, with the attribution
    log's deposit set as authority.

    Iterating from claims-store domain rows made a deleted domain row
    silently invisible (the deletion attack D2 exists to close): the compile
    would just drop the leg with no tamper signal, a silent allocation
    change. Inverted: for every routing_terms DEPOSIT naming this key, a
    claims-store domain row keyed by that deposit's manifest_hash MUST exist,
    or RouteTamperError("missing_domain_row") naming the manifest_hash and
    the key. Revoked-then-superseded deposits still have a domain row (claims
    are append-only tombstones) and are filtered by scope/integrity bind
    downstream, not by absence here - absence is always tamper.
    """
    deposits = lg.list_by_store_kind_and_key("routing_terms", key)
    domain_by_hash = {r["manifest_hash"]: r for r in store.list_routing_terms_for_subject(key)}
    rows = []
    for dep in deposits:
        mh = dep["manifest_hash"]
        domain_row = domain_by_hash.get(mh)
        if domain_row is None:
            raise RouteTamperError(
                f"missing_domain_row: {mh} (subject={key})", failure_mode="missing_domain_row"
            )
        rows.append(domain_row)
    return rows


# ---------------------------------------------------------------------------
# compile_route_manifest
# ---------------------------------------------------------------------------


def compile_route_manifest(
    *,
    event_kind: str,
    event_ref: str,
    subject: str,
    amount_value: int,
    asset_code: str,
    asset_scale: int,
    agent_id: str,
    log=None,
    registry=None,
    signer=None,
    timestamp: str | None = None,
) -> dict:
    """Compile + deposit a RouteManifest for one payment event.

    Stages, strictly in order (validation fully precedes the deposit):
      0. Replay guard - recompute allocation + resolution layers, compare
         against the latest route_manifest for this event_ref (none -> new;
         byte-identical -> idempotent return; allocation same/resolution
         changed -> new manifest with supersedes; allocation differs ->
         RouteReplayConflict).
      1. Gather - subject + parent (derived_from) envelopes, direct + parent
         standing routing_terms from the claims store (deposit-authoritative,
         D2: a deposit with no domain row is missing_domain_row tamper).
      2. Verify consumed claims - every routing_terms row is integrity-bound
         (RouteTamperError on failure); subject/parent envelopes must be
         verified (RouteCompileError otherwise).
      2b. Registry enforcement (D3) - every consumed term's
          beneficiary_pubkey_id must be registered (unknown_key tamper,
          fails the whole compile) or revoked (not tamper - the leg keeps
          its allocation but resolves credited-unpaid in stage 5).
      3. Validate terms - bounds, duplicates, single pass-through hop, 2-hop
         depth cap.
      4. Allocate - exact integer conservation via largest-remainder.
      5. Resolve wallets - Void Principle: unresolved -> credited-unpaid.
      6. Emit + deposit - record via record_signed.
    """
    from zephyr.attribution import get_recorder, record_signed
    from zephyr.claims import get_claims_store, verify_routing_terms_row
    from zephyr.claims import resolve_wallet as _resolve_wallet
    from zephyr.registry import get_registry
    from zephyr.signing import get_signer

    lg = log if log is not None else get_recorder()
    reg = registry if registry is not None else get_registry()
    sig = signer if signer is not None else get_signer()
    store = get_claims_store()

    # ---- Stage 1: Gather --------------------------------------------------

    subject_row = lg.get(subject, registry=reg)
    if subject_row is None or subject_row.get("verification_status") != "verified":
        status = subject_row.get("verification_status") if subject_row else "missing_envelope"
        raise RouteCompileError(f"subject deposit not verified ({status}): {subject}")

    parent_mh = subject_row.get("derived_from")
    parent_row = None
    if parent_mh:
        parent_row = lg.get(parent_mh, registry=reg)
        if parent_row is None or parent_row.get("verification_status") != "verified":
            status = parent_row.get("verification_status") if parent_row else "missing_envelope"
            raise RouteCompileError(f"parent deposit not verified ({status}): {parent_mh}")

    event_scope = f"event:{event_ref}"
    direct_all_rows = _gathered_routing_terms(subject, store=store, lg=lg)
    direct_candidate_rows = [r for r in direct_all_rows if r["scope"] in ("standing", event_scope)]
    parent_all_rows = _gathered_routing_terms(parent_mh, store=store, lg=lg) if parent_mh else []
    parent_standing_candidate_rows = [r for r in parent_all_rows if r["scope"] == "standing"]

    # ---- Stage 2: Verify consumed claims -----------------------------------

    def _verified(rows):
        out = []
        for row in rows:
            vr = verify_routing_terms_row(row, log=lg, registry=reg)
            if not vr.ok:
                raise RouteTamperError(
                    f"{vr.failure_mode}: {row['manifest_hash']}", failure_mode=vr.failure_mode
                )
            out.append(row)
        return out

    direct_term_rows = _verified(direct_candidate_rows)
    parent_standing_rows = _verified(parent_standing_candidate_rows)

    # ---- Stage 2b: Registry enforcement (D3) -------------------------------

    revoked_beneficiaries = set()
    for row in direct_term_rows + parent_standing_rows:
        bpid = row["beneficiary_pubkey_id"]
        entry = reg.lookup(bpid)
        if entry is None:
            raise RouteTamperError(
                f"unknown_key: {bpid} ({row['manifest_hash']})", failure_mode="unknown_key"
            )
        if entry.get("status") == "revoked":
            revoked_beneficiaries.add(bpid)

    # ---- Stage 3: Validate terms --------------------------------------

    seen_beneficiaries = set()
    total_bps = 0
    for row in direct_term_rows:
        b = row["beneficiary_pubkey_id"]
        if b in seen_beneficiaries:
            raise RouteCompileError(f"duplicate (subject, beneficiary) term: {row['manifest_hash']}")
        seen_beneficiaries.add(b)
        total_bps += row["share_bps"]
    if total_bps > 10000:
        raise RouteCompileError(
            f"direct terms share_bps sum {total_bps} exceeds 10000: event_ref={event_ref}"
        )

    if len(parent_standing_rows) > 1:
        raise RouteCompileError(
            f"multiple standing terms on parent: {parent_mh}"
        )

    if parent_row is not None:
        grandparent_mh = parent_row.get("derived_from")
        if grandparent_mh:
            grandparent_standing = [
                r
                for r in store.list_routing_terms_for_subject(grandparent_mh)
                if r["scope"] == "standing"
            ]
            if grandparent_standing:
                raise RouteDepthExceeded(
                    f"lineage depth exceeds 2-hop cap: {subject} -> {parent_mh} -> {grandparent_mh}"
                )

    # ---- Stage 4: Allocate - exact integer conservation --------------------

    buckets = [
        {"id": row["beneficiary_pubkey_id"], "bps": row["share_bps"], "is_payer": False, "term_row": row}
        for row in direct_term_rows
    ]
    payer_bps = 10000 - total_bps
    buckets.append({"id": None, "bps": payer_bps, "is_payer": True, "term_row": None})

    allocated = _largest_remainder(amount_value, buckets)
    payer_retained = next(b["amount"] for b in allocated if b["is_payer"])

    direct_legs = []
    for b in allocated:
        if b["is_payer"]:
            continue
        term_row = b["term_row"]
        direct_legs.append(
            {
                "beneficiary_pubkey_id": b["id"],
                "amount": b["amount"],
                "term_refs": [term_row["manifest_hash"]],
                "edge_refs": [subject],
            }
        )
    direct_legs.sort(key=lambda leg: leg["beneficiary_pubkey_id"])

    depth = 0
    passthrough_leg = None
    if parent_standing_rows:
        parent_term_row = parent_standing_rows[0]
        contributor_pubkey_id = parent_row.get("pubkey_id") if parent_row else None
        source_idx = next(
            (
                i
                for i, leg in enumerate(direct_legs)
                if leg["beneficiary_pubkey_id"] == contributor_pubkey_id
            ),
            None,
        )
        if source_idx is not None:
            source_leg = direct_legs[source_idx]
            split = _largest_remainder(
                source_leg["amount"],
                [
                    {"id": parent_term_row["beneficiary_pubkey_id"], "bps": parent_term_row["share_bps"], "is_payer": False},
                    {"id": source_leg["beneficiary_pubkey_id"], "bps": 10000 - parent_term_row["share_bps"], "is_payer": True},
                ],
            )
            passthrough_amount = next(b["amount"] for b in split if not b["is_payer"])
            retained_amount = next(b["amount"] for b in split if b["is_payer"])

            combined_term_refs = [source_leg["term_refs"][0], parent_term_row["manifest_hash"]]
            combined_edge_refs = [subject, parent_mh]

            source_leg["amount"] = retained_amount
            source_leg["term_refs"] = combined_term_refs
            source_leg["edge_refs"] = combined_edge_refs

            passthrough_leg = {
                "beneficiary_pubkey_id": parent_term_row["beneficiary_pubkey_id"],
                "amount": passthrough_amount,
                "term_refs": combined_term_refs,
                "edge_refs": combined_edge_refs,
            }
            depth = 1

    legs = list(direct_legs)
    if passthrough_leg is not None:
        insert_at = source_idx + 1
        legs.insert(insert_at, passthrough_leg)

    # ---- Stage 5: Resolve wallets -------------------------------------

    final_legs = []
    for leg in legs:
        if leg["beneficiary_pubkey_id"] in revoked_beneficiaries:
            wallet_address = None
        else:
            wallet_address = _resolve_wallet(leg["beneficiary_pubkey_id"], store=store, log=lg, registry=reg)
        leg_status = "routable" if wallet_address is not None else "credited-unpaid"
        final_legs.append(
            {
                "beneficiary_pubkey_id": leg["beneficiary_pubkey_id"],
                "amount": leg["amount"],
                "wallet_address": wallet_address,
                "leg_status": leg_status,
                "derivation": {
                    "term_refs": leg["term_refs"],
                    "edge_refs": leg["edge_refs"],
                    "algorithm": "declared-split+single-passthrough-v0",
                },
            }
        )

    route_manifest = {
        "schema": "zephyr-route-manifest-v0",
        "event": {"kind": event_kind, "ref": event_ref, "subject": subject},
        "amount_in": {"value": amount_value, "asset_code": asset_code, "asset_scale": asset_scale},
        "payer_retained": payer_retained,
        "legs": final_legs,
        "depth": depth,
    }

    # ---- Stage 0: Replay guard --------------------------------------------

    prior = store.latest_route_manifest_for_event(event_ref)
    summary = f"route manifest: {event_kind} {event_ref} subject={subject}"

    if prior is not None:
        prior_payload = json.loads(prior["payload_json"])
        prior_rm = dict(prior_payload["route_manifest"])
        prior_rm.pop("supersedes", None)

        if _canonical(route_manifest) == _canonical(prior_rm):
            prior_envelope = lg.get(prior["manifest_hash"], registry=reg)
            return {
                "manifest_hash": prior["manifest_hash"],
                "pubkey_id": prior_envelope.get("pubkey_id") if prior_envelope else None,
                "signature": prior_envelope.get("signature") if prior_envelope else None,
                "newly_recorded": False,
                "manifest": prior_payload,
            }

        if _canonical(_allocation_layer(route_manifest)) != _canonical(_allocation_layer(prior_rm)):
            from archetypes_core.provenance import SCHEMA_VERSION_V01, to_lapis_return

            preview = to_lapis_return(
                {"route_manifest": route_manifest},
                agent_id=agent_id,
                tool="zephyr:route-compile",
                summary=summary,
                schema_version=SCHEMA_VERSION_V01,
                timestamp=timestamp,
            )
            raise RouteReplayConflict(
                f"allocation differs from prior manifest for event_ref={event_ref}: "
                f"{prior['manifest_hash']} vs {preview.provenance.manifest_hash}"
            )

        route_manifest["supersedes"] = prior["manifest_hash"]

    # ---- Stage 6: Emit + deposit -----------------------------------------

    payload = {"route_manifest": route_manifest}

    result = record_signed(
        payload,
        agent_id=agent_id,
        tool="zephyr:route-compile",
        store_kind="route_manifest",
        key=event_ref,
        signer=sig,
        registry=reg,
        recorder=lg,
        summary=summary,
        timestamp=timestamp,
    )

    store.insert_route_manifest(
        manifest_hash=result["manifest_hash"],
        event_ref=event_ref,
        payload_json=_canonical(payload),
        summary=summary,
        recorded_at=timestamp or datetime.now(timezone.utc).isoformat(),
        supersedes=route_manifest.get("supersedes"),
    )

    return {**result, "manifest": payload}


# ---------------------------------------------------------------------------
# Executor contract surface (D4) - pure reads, no writes
# ---------------------------------------------------------------------------


def get_manifest_for_event(event_ref, *, store=None, log=None, registry=None) -> dict | None:
    """The head manifest for event_ref, envelope-verified and parsed.

    Returns None if no manifest exists. Returns a dict with keys:
      manifest_hash, manifest (parsed payload), pubkey_id, signature, supersedes.
    Raises RouteTamperError if the head's own envelope fails the integrity bind,
    RouteChainError if the chain is malformed. Never returns an unverified
    manifest, and a malformed chain is NEVER reported as absence (None means
    exactly one thing: no manifest exists for this event_ref) - silently
    reading a corrupt store as "nothing to pay" is the failure mode this
    unit exists to prevent.
    """
    from zephyr.attribution import get_recorder
    from zephyr.claims import get_claims_store, verify_route_manifest_row
    from zephyr.registry import get_registry

    st = store if store is not None else get_claims_store()
    lg = log if log is not None else get_recorder()
    reg = registry if registry is not None else get_registry()

    head = st.latest_route_manifest_for_event(event_ref)  # raises RouteChainError, never guesses
    if head is None:
        return None

    vr = verify_route_manifest_row(head, log=lg, registry=reg)
    if not vr.ok:
        raise RouteTamperError(f"{vr.failure_mode}: {head['manifest_hash']}", failure_mode=vr.failure_mode)

    return {
        "manifest_hash": head["manifest_hash"],
        "manifest": json.loads(head["payload_json"]),
        "pubkey_id": (vr.envelope or {}).get("pubkey_id"),
        "signature": (vr.envelope or {}).get("signature"),
        "supersedes": head["supersedes"],
    }


def is_current_head(event_ref, manifest_hash, *, store=None) -> bool:
    """True iff manifest_hash is the chain head for event_ref right now.

    The executor calls this immediately before moving value. A manifest that
    was the head when the run started may have been superseded by a
    revocation since. Raises RouteChainError if the chain is malformed - a
    wedged store is never silently reported as "not the head".
    """
    from zephyr.claims import get_claims_store

    st = store if store is not None else get_claims_store()
    head = st.latest_route_manifest_for_event(event_ref)
    if head is None:
        return False
    return head["manifest_hash"] == manifest_hash


def reverify_leg(manifest, leg, *, store=None, log=None, registry=None) -> dict:
    """Re-run the full resolution check for one leg at execution time.

    Returns {"payable": bool, "wallet_address": str | None, "reason": str}.
    payable=True requires ALL of: leg_status=="routable" in the manifest, a
    currently verified non-revoked self-signed wallet_binding for the
    beneficiary, and the freshly resolved address EQUAL to the leg's recorded
    wallet_address. Any mismatch returns payable=False with reason in
    {"not_routable", "binding_revoked", "binding_unverified", "address_changed",
    "unknown_key"} - it does not raise. A stale routable never pays.

    Returning rather than raising is deliberate: partial completion must be
    honest in the ledger, so the executor needs to skip one leg and continue,
    not abort the run. Tamper (as opposed to an unpayable-but-legitimate leg)
    still raises RouteTamperError from the underlying bind - e.g. a deleted
    wallet_binding domain row surfaces as missing_domain_row, unchanged.
    """
    from zephyr.attribution import get_recorder
    from zephyr.claims import get_claims_store, verify_wallet_binding_row
    from zephyr.claims import resolve_wallet as _resolve_wallet
    from zephyr.registry import get_registry

    st = store if store is not None else get_claims_store()
    lg = log if log is not None else get_recorder()
    reg = registry if registry is not None else get_registry()

    if leg.get("leg_status") != "routable":
        return {"payable": False, "wallet_address": None, "reason": "not_routable"}

    bpid = leg["beneficiary_pubkey_id"]

    if reg.lookup(bpid) is None:
        return {"payable": False, "wallet_address": None, "reason": "unknown_key"}

    fresh_address = _resolve_wallet(bpid, store=st, log=lg, registry=reg)

    if fresh_address is None:
        rows = st.list_wallet_bindings_for_subject(bpid)
        if rows:
            latest = max(rows, key=lambda r: r["seq"])
            # Verify first, then read the revocation verdict off the VERIFIED
            # payload: an unverifiable row must never be classified
            # "binding_revoked" on unverified data.
            vr = verify_wallet_binding_row(latest, log=lg, registry=reg)
            if not vr.ok:
                return {"payable": False, "wallet_address": None, "reason": "binding_unverified"}
            if vr.payload["wallet_binding"]["revokes"]:
                return {"payable": False, "wallet_address": None, "reason": "binding_revoked"}
        return {"payable": False, "wallet_address": None, "reason": "binding_unverified"}

    if fresh_address != leg.get("wallet_address"):
        return {"payable": False, "wallet_address": fresh_address, "reason": "address_changed"}

    return {"payable": True, "wallet_address": fresh_address, "reason": "ok"}


def describe_manifest_chain(event_ref, *, store=None) -> dict:
    """Human-readable chain diagnostic. NEVER raises on a malformed chain.

    Returns {"event_ref", "rows": [...], "heads": [...], "roots": [...],
             "well_formed": bool, "failure_mode": str | None}.

    `rows` carries the RAW manifest_hash/supersedes/recorded_at/seq values
    exactly as stored - unreconstructed, unsorted-by-inference. The
    reconstructed interpretation lives in `heads`/`roots`; the raw edges live
    in `rows`, so a human debugging a wedged store can see where the
    application's reading of the chain and the literal table contents
    disagree. This is the surface a human reads when RouteChainError fires -
    the fork must be visible, not merely fatal. Wedged-state *recovery* is
    deliberately out of scope: a repair tool for a forked chain IS a
    chain-rewrite tool, the capability this unit exists to deny.
    """
    from zephyr.claims import get_claims_store

    st = store if store is not None else get_claims_store()

    raw_rows = st.raw_route_manifest_rows(event_ref)
    superseded = {r["supersedes"] for r in raw_rows if r["supersedes"]}
    heads = [r["manifest_hash"] for r in raw_rows if r["manifest_hash"] not in superseded]
    roots = [r["manifest_hash"] for r in raw_rows if r["supersedes"] is None]

    try:
        st.route_manifest_chain_for_event(event_ref)
    except RouteChainError as exc:
        well_formed = False
        failure_mode = exc.failure_mode
    else:
        well_formed = True
        failure_mode = None

    return {
        "event_ref": event_ref,
        "rows": raw_rows,
        "heads": heads,
        "roots": roots,
        "well_formed": well_formed,
        "failure_mode": failure_mode,
    }
