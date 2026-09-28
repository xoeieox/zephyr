"""python -m zephyr.route  — the Node read/write seam (rail U2b, D3).

All signing and all chain/integrity logic stays in Python behind this CLI;
a Node executor calls these subcommands and never touches keys, canonical
JSON, or SQLite directly. Every subcommand emits exactly one JSON document
on stdout; human-readable logs (none, currently) would go to stderr, never
stdout. Signing happens only inside `record-receipt`, under the node key -
there is no `--signer`/`--key` override on that subcommand, so a production
caller structurally cannot sign a route_receipt as anything but the node key.

Subcommands:
  compile         - byte-identical to the historic bare-flag invocation
                     (also the DEFAULT subcommand when none is given, so
                     existing callers of the old flat CLI are unaffected).
  get-manifest    - the verified chain head for --event-ref, or null.
  is-head         - {"is_current_head": bool}.
  reverify-legs   - re-run reverify_leg for every leg of the named head.
                     Refuses (exit 12, failure_mode="not_head") if
                     --manifest-hash is not the current head - the executor
                     must re-fetch get-manifest before acting.
  leg-claim / leg-quote / leg-submit / leg-settle / leg-fail / leg-skip
                  - thin wrappers over zephyr.route_exec's per-leg state
                     machine (rail U2b, D2).
  record-receipt  - write a signed route_receipt via zephyr.claims (D1).

Exit-code contract (also documented in AGENTS.md):
  0  ok
  10 RouteChainError   - wedged store; caller STOPS, does not pay
  11 RouteTamperError
  12 RouteReceiptError / LegStateError - bad caller request, incl. not_head
  2  usage error (argparse's own; EXEMPT from the JSON-envelope rule below -
     argparse's native usage message on stderr is acceptable, no custom
     ArgumentParser.error() override)
  1  any other unexpected exception (OSError, an unclassified ValueError,
     etc.) - human-readable stderr message, no JSON envelope

On exit 10/11/12, stdout carries exactly one JSON document:
  {"error": "<class>", "failure_mode": "<mode|null>", "detail": "<msg>"}

No key material or token ever reaches stdout or stderr on any path.
"""

from __future__ import annotations

import argparse
import json
import sys

_SUBCOMMANDS = frozenset(
    {
        "compile",
        "get-manifest",
        "is-head",
        "reverify-legs",
        "leg-claim",
        "leg-quote",
        "leg-submit",
        "leg-settle",
        "leg-fail",
        "leg-skip",
        "record-receipt",
    }
)


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def _cmd_compile(args) -> None:
    """Compile + deposit a RouteManifest. Python signs here (or via --key);
    Node never touches the signer - it only ever calls this subcommand."""
    from zephyr.routing import compile_route_manifest

    signer = None
    if args.key:
        from pathlib import Path

        from zephyr.signing import AgentSigner

        signer = AgentSigner(Path(args.key))

    result = compile_route_manifest(
        event_kind=args.event_kind,
        event_ref=args.event_ref,
        subject=args.subject,
        amount_value=args.amount,
        asset_code=args.asset_code,
        asset_scale=args.asset_scale,
        agent_id=args.agent_id,
        signer=signer,
    )
    print(json.dumps(result))


def _cmd_get_manifest(args) -> None:
    """Read-only: the verified chain head for --event-ref, or null. Node calls
    this instead of reimplementing chain-walk head selection + envelope verify."""
    from zephyr.routing import get_manifest_for_event

    result = get_manifest_for_event(args.event_ref)
    print(json.dumps(result))


def _cmd_is_head(args) -> None:
    """Read-only: is --manifest-hash still the chain head for --event-ref right now."""
    from zephyr.routing import is_current_head

    result = is_current_head(args.event_ref, args.manifest_hash)
    print(json.dumps({"is_current_head": result}))


def _cmd_reverify_legs(args) -> None:
    """Read-only: re-run reverify_leg for every leg of the named head. Refuses
    (not_head) if --manifest-hash is stale - the executor must re-fetch
    get-manifest before acting, never reverify against a superseded manifest."""
    from zephyr.claims import RouteReceiptError
    from zephyr.routing import get_manifest_for_event, is_current_head, reverify_leg

    if not is_current_head(args.event_ref, args.manifest_hash):
        raise RouteReceiptError(
            f"not_head: manifest_hash={args.manifest_hash!r} is not the current head for "
            f"event_ref={args.event_ref!r} - re-fetch get-manifest before acting",
            failure_mode="not_head",
        )

    head = get_manifest_for_event(args.event_ref)
    manifest = head["manifest"]["route_manifest"]

    results = []
    for leg in manifest["legs"]:
        r = reverify_leg(manifest, leg)
        results.append({"beneficiary_pubkey_id": leg["beneficiary_pubkey_id"], **r})
    print(json.dumps(results))


def _cmd_leg_claim(args) -> None:
    """Thin wrapper over zephyr.route_exec's D2 state machine: (absent)/failed -> pending."""
    from zephyr.route_exec import claim_leg

    print(json.dumps(claim_leg(args.manifest_hash, args.beneficiary)))


def _cmd_leg_quote(args) -> None:
    """Thin wrapper over zephyr.route_exec's D2 state machine: pending -> quoted."""
    from zephyr.route_exec import record_quote

    print(json.dumps(record_quote(args.manifest_hash, args.beneficiary, args.quote_id)))


def _cmd_leg_submit(args) -> None:
    """Thin wrapper over zephyr.route_exec's D2 state machine: quoted -> submitted."""
    from zephyr.route_exec import record_submitted

    print(json.dumps(record_submitted(args.manifest_hash, args.beneficiary, args.outgoing_payment_id)))


def _cmd_leg_settle(args) -> None:
    """Thin wrapper over zephyr.route_exec's D2 state machine: submitted -> settled (terminal)."""
    from zephyr.route_exec import record_settled

    print(json.dumps(record_settled(args.manifest_hash, args.beneficiary)))


def _cmd_leg_fail(args) -> None:
    """Thin wrapper over zephyr.route_exec's D2 state machine: in-flight -> failed (non-terminal)."""
    from zephyr.route_exec import record_failed

    print(json.dumps(record_failed(args.manifest_hash, args.beneficiary, args.error)))


def _cmd_leg_skip(args) -> None:
    """Thin wrapper over zephyr.route_exec's D2 state machine: pending/quoted -> skipped (terminal)."""
    from zephyr.route_exec import record_skipped

    print(json.dumps(record_skipped(args.manifest_hash, args.beneficiary, args.reason)))


def _cmd_record_receipt(args) -> None:
    """Sign + deposit a route_receipt via zephyr.claims (D1). Signing happens
    HERE, in Python, under the node key - this subcommand exposes no
    --signer/--key override, so Node structurally cannot sign as anything else."""
    from zephyr.claims import record_route_receipt

    result = record_route_receipt(
        event_ref=args.event_ref,
        manifest_hash=args.manifest_hash,
        beneficiary_pubkey_id=args.beneficiary,
        outcome=args.outcome,
        op_payment_id=args.op_payment_id,
        sent_value=args.sent_value,
        sent_asset_code=args.sent_asset_code,
        sent_asset_scale=args.sent_asset_scale,
        reason=args.reason,
        agent_id=args.agent_id,
    )
    print(json.dumps(result))


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m zephyr.route",
        description="Zephyr RouteManifest compiler + executor Node seam (rail U2b).",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_compile = sub.add_parser("compile", help="Compile a RouteManifest (default subcommand)")
    p_compile.add_argument("--event-kind", required=True, help="Event kind, e.g. demo-sale")
    p_compile.add_argument("--event-ref", required=True, help="Opaque event id")
    p_compile.add_argument("--subject", required=True, help="manifest_hash of the paid work's deposit")
    p_compile.add_argument("--amount", required=True, type=int, help="Amount, integer smallest units")
    p_compile.add_argument("--asset-code", required=True, help="Asset code, e.g. USD")
    p_compile.add_argument("--asset-scale", required=True, type=int, help="Asset scale, e.g. 2")
    p_compile.add_argument("--agent-id", required=True, help="Recording identity")
    p_compile.add_argument("--key", default=None, help="Optional signer key path")
    p_compile.set_defaults(func=_cmd_compile)

    p_get = sub.add_parser("get-manifest", help="Fetch the verified chain head for an event_ref")
    p_get.add_argument("--event-ref", required=True)
    p_get.set_defaults(func=_cmd_get_manifest)

    p_ishead = sub.add_parser("is-head", help="Check whether a manifest_hash is the current chain head")
    p_ishead.add_argument("--event-ref", required=True)
    p_ishead.add_argument("--manifest-hash", required=True)
    p_ishead.set_defaults(func=_cmd_is_head)

    p_reverify = sub.add_parser("reverify-legs", help="Re-run reverify_leg for every leg of a head manifest")
    p_reverify.add_argument("--event-ref", required=True)
    p_reverify.add_argument("--manifest-hash", required=True)
    p_reverify.set_defaults(func=_cmd_reverify_legs)

    p_claim = sub.add_parser("leg-claim", help="Claim a leg for execution (rail U2b, D2)")
    p_claim.add_argument("--manifest-hash", required=True)
    p_claim.add_argument("--beneficiary", required=True)
    p_claim.set_defaults(func=_cmd_leg_claim)

    p_quote = sub.add_parser("leg-quote", help="Record a quote for a claimed leg")
    p_quote.add_argument("--manifest-hash", required=True)
    p_quote.add_argument("--beneficiary", required=True)
    p_quote.add_argument("--quote-id", required=True)
    p_quote.set_defaults(func=_cmd_leg_quote)

    p_submit = sub.add_parser("leg-submit", help="Record a leg's outgoing payment submission")
    p_submit.add_argument("--manifest-hash", required=True)
    p_submit.add_argument("--beneficiary", required=True)
    p_submit.add_argument("--outgoing-payment-id", required=True)
    p_submit.set_defaults(func=_cmd_leg_submit)

    p_settle = sub.add_parser("leg-settle", help="Mark a submitted leg settled (terminal)")
    p_settle.add_argument("--manifest-hash", required=True)
    p_settle.add_argument("--beneficiary", required=True)
    p_settle.set_defaults(func=_cmd_leg_settle)

    p_fail = sub.add_parser("leg-fail", help="Mark a leg failed (non-terminal, re-claimable)")
    p_fail.add_argument("--manifest-hash", required=True)
    p_fail.add_argument("--beneficiary", required=True)
    p_fail.add_argument("--error", required=True)
    p_fail.set_defaults(func=_cmd_leg_fail)

    p_skip = sub.add_parser("leg-skip", help="Mark a leg skipped (terminal, unpayable before submit)")
    p_skip.add_argument("--manifest-hash", required=True)
    p_skip.add_argument("--beneficiary", required=True)
    p_skip.add_argument("--reason", required=True)
    p_skip.set_defaults(func=_cmd_leg_skip)

    p_receipt = sub.add_parser("record-receipt", help="Sign + deposit a route_receipt (rail U2b, D1)")
    p_receipt.add_argument("--event-ref", required=True)
    p_receipt.add_argument("--manifest-hash", required=True)
    p_receipt.add_argument("--beneficiary", required=True)
    p_receipt.add_argument("--outcome", required=True, choices=["settled", "failed", "skipped"])
    p_receipt.add_argument("--op-payment-id", default=None)
    p_receipt.add_argument("--sent-value", type=int, default=None)
    p_receipt.add_argument("--sent-asset-code", default=None)
    p_receipt.add_argument("--sent-asset-scale", type=int, default=None)
    p_receipt.add_argument("--reason", default=None)
    p_receipt.add_argument("--agent-id", required=True)
    p_receipt.set_defaults(func=_cmd_record_receipt)

    return parser


# ---------------------------------------------------------------------------
# Error envelope + main
# ---------------------------------------------------------------------------


def _print_error_and_exit(code: int, error_cls: str, failure_mode: str | None, detail: str) -> None:
    print(json.dumps({"error": error_cls, "failure_mode": failure_mode, "detail": detail}))
    sys.exit(code)


def main(argv: list[str] | None = None) -> None:
    argv = list(argv if argv is not None else sys.argv[1:])
    if not argv or argv[0] not in _SUBCOMMANDS:
        argv = ["compile", *argv]

    parser = _build_parser()
    args = parser.parse_args(argv)  # may sys.exit(2) - exempt from the JSON-envelope rule

    from zephyr.claims import RouteReceiptError
    from zephyr.route_exec import LegStateError
    from zephyr.routing import RouteChainError, RouteTamperError

    try:
        args.func(args)
    except RouteChainError as exc:
        _print_error_and_exit(10, "RouteChainError", exc.failure_mode, str(exc))
    except RouteTamperError as exc:
        _print_error_and_exit(11, "RouteTamperError", exc.failure_mode, str(exc))
    except RouteReceiptError as exc:
        _print_error_and_exit(12, "RouteReceiptError", exc.failure_mode, str(exc))
    except LegStateError as exc:
        _print_error_and_exit(12, "LegStateError", None, str(exc))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
