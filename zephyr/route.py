"""python -m zephyr.route  — thin CLI for the RouteManifest compiler.

Usage:
  python -m zephyr.route \\
      --event-kind demo-sale \\
      --event-ref evt-123 \\
      --subject sha256:... \\
      --amount 500 \\
      --asset-code USD \\
      --asset-scale 2 \\
      --agent-id agent:route-compiler \\
      [--key path/to/signer.key]

Exits 0 on success and prints the compile result (manifest, manifest_hash,
pubkey_id, signature, newly_recorded) to stdout as JSON. Exits 1 on error
with a one-line stderr message on RouteCompileError (and its subclasses
RouteDepthExceeded / RouteReplayConflict / RouteTamperError).

This module is the thin CLI surface; the compiler logic lives in
zephyr.routing.compile_route_manifest.
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Compile a Zephyr RouteManifest (reference path for Unit 2)."
    )
    parser.add_argument("--event-kind", required=True, help="Event kind, e.g. demo-sale")
    parser.add_argument("--event-ref", required=True, help="Opaque event id")
    parser.add_argument("--subject", required=True, help="manifest_hash of the paid work's deposit")
    parser.add_argument("--amount", required=True, type=int, help="Amount, integer smallest units")
    parser.add_argument("--asset-code", required=True, help="Asset code, e.g. USD")
    parser.add_argument("--asset-scale", required=True, type=int, help="Asset scale, e.g. 2")
    parser.add_argument("--agent-id", required=True, help="Recording identity")
    parser.add_argument("--key", default=None, help="Optional signer key path")

    args = parser.parse_args(argv)

    try:
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
        print(json.dumps(result, indent=2))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
