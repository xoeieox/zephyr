"""python -m zephyr.deposit  — thin CLI for the self-signing reference depositor.

Usage:
  python -m zephyr.deposit \\
      --agent-id agent:zephyr-selftest \\
      --tool my-tool \\
      --store-kind mem \\
      --payload '{"hello": "world"}' \\
      [--key target/key] \\
      [--summary "one-line description"]

Exits 0 on success and prints the manifest_hash, pubkey_id, and newly_recorded
flag to stdout as JSON.  Exits 1 on error with a human-readable message.

This module is the thin CLI surface; the signing logic lives in
zephyr.attribution.record_signed.
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Self-signing Zephyr deposit (reference path for Unit 2)."
    )
    parser.add_argument("--agent-id", required=True, help="Depositing agent's id")
    parser.add_argument("--tool", required=True, help="Tool name")
    parser.add_argument(
        "--store-kind",
        default="mem",
        help="Store kind label (mem, weaver, slot, wallet_binding, routing_terms, "
        "route_manifest, …). Default: mem",
    )
    parser.add_argument(
        "--payload",
        default="{}",
        help="JSON payload string. Default: {}",
    )
    parser.add_argument("--key", default=None, help="Optional target_key for the log")
    parser.add_argument("--summary", default="", help="One-line summary")

    args = parser.parse_args(argv)

    try:
        payload = json.loads(args.payload)
    except json.JSONDecodeError as exc:
        print(f"error: --payload is not valid JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        from zephyr.attribution import record_signed

        result = record_signed(
            payload,
            agent_id=args.agent_id,
            tool=args.tool,
            store_kind=args.store_kind,
            key=args.key,
            summary=args.summary,
        )
        print(json.dumps(result, indent=2))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
