#!/usr/bin/env python3
"""Display settlement ledger with void-policy header.

Entry point: python scripts/show_ledger.py

Renders the settlement ledger in a human-readable format with a prominent
void-policy disclaimer, ensuring no settlement-weighted ranking of contributors.
"""

import os
import sys
from pathlib import Path
from settler.ledger import get_ledger


def truncate_hash(h: str, length: int = 12) -> str:
    """Truncate hash to first N chars."""
    if not h:
        return "(none)"
    return h[:length]


def truncate_key(key: str, length: int = 20) -> str:
    """Truncate pubkey_id for display."""
    if not key:
        return "(none)"
    return key[:length]


def main():
    """Display the settlement ledger."""
    ledger = get_ledger()

    # Print void-policy header
    print()
    print("=" * 80)
    print("SETTLEMENT LEDGER")
    print("=" * 80)
    print()
    print("⚠️  VOID LINE")
    print("SplitPolicy: VOID — this system makes no claim about the correct share.")
    print("The livelihood gap is the unsolved problem.")
    print()
    print("Settlement status below is PROOF OF ATTESTATION COST, not compensation.")
    print("Contributors are fully credited regardless of settlement status.")
    print("=" * 80)
    print()

    # Read all rows in order of creation (not settlement status or amount)
    rows = ledger.all()

    if not rows:
        print("(No settlement records yet)")
        print()
        return

    # Print table header
    print(
        f"{'Contributor':<22} {'Status':<12} {'Amount':<10} {'Manifest':<14} {'Payment ID':<14} {'Settled At':<20}"
    )
    print("-" * 95)

    # Print rows
    for row in rows:
        manifest_hash = truncate_hash(row["manifest_hash"], 12)
        pubkey_id = truncate_key(row["pubkey_id"], 18)
        status = row["status"]
        amount_str = f"${row['amount'] / 100:.2f}" if row["amount"] is not None else "—"
        op_payment_id = truncate_hash(row["op_payment_id"], 12) if row["op_payment_id"] else "—"
        settled_at = row["settled_at"][:10] if row["settled_at"] else "—"

        print(
            f"{pubkey_id:<22} {status:<12} {amount_str:<10} {manifest_hash:<14} "
            f"{op_payment_id:<14} {settled_at:<20}"
        )

    print()
    print(f"Total records: {len(rows)}")
    settled_count = sum(1 for r in rows if r["status"] == "settled")
    no_route_count = sum(1 for r in rows if r["status"] == "no-route")
    failed_count = sum(1 for r in rows if r["status"] == "failed")

    if settled_count > 0:
        print(f"  Settled: {settled_count}")
    if no_route_count > 0:
        print(f"  No-route (attributed, undiminished): {no_route_count}")
    if failed_count > 0:
        print(f"  Failed: {failed_count}")

    print()


if __name__ == "__main__":
    main()
