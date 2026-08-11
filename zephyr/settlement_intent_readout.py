"""python -m zephyr.settlement_intent_readout — read-only readout of the
relabelled ('simulation') settlement-intent rows.

decision/zephyr-stops-minting-payment-claims-2026-08-11 (Leg 3): the label
on its own is not enough (a Mirror Council pass on 2026-08-11 flagged that
retaining rows under a 'simulation' label risks reading as a valid mode of
operation rather than a defect). This readout is what satisfies R3's
"declared as such" — it is the one step between the label and the defect
record, printed every time the label is looked at.

Read-only. No writes, no status transitions. Reads only rows with
status = 'simulation'.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from zephyr.intent_queue import SettlementIntentQueue, _default_queue_db

DECISION_KEY = "decision/zephyr-stops-minting-payment-claims-2026-08-11"

DISCLAIMER_LINES = (
    "THE AMOUNT IS A HARDCODED ONE-CENT PLACEHOLDER, NOT A VALUATION.",
    "NO CLAIM EXISTS AND NOTHING WILL SETTLE.",
    f"'simulation' was never an intended mode of operation — these rows are "
    f"the residue of a defect. Authoritative record: {DECISION_KEY}",
)


def gather(db_path: Path) -> dict:
    """Read-only: gather the simulation-row readout data from *db_path*.

    Opening a SettlementIntentQueue applies only the additive, idempotent
    `reason`-column migration (a no-op if already present) — no other write
    happens here.
    """
    queue = SettlementIntentQueue(db_path)
    summary = queue.simulation_summary()
    summary["db_path"] = str(db_path)
    return summary


def render(data: dict) -> str:
    lines = []
    lines.append("=" * 78)
    lines.append("SETTLEMENT INTENT QUEUE — SIMULATION ROWS (DEFECT RESIDUE)")
    lines.append("=" * 78)
    lines.append("")
    for line in DISCLAIMER_LINES:
        lines.append(f"⚠️  {line}")
    lines.append("")
    lines.append(f"DB: {data['db_path']}")
    lines.append(f"Simulation rows: {data['count']}")
    start, end = data["date_range"]
    if data["count"] > 0:
        lines.append(f"Date range (created_at): {start} .. {end}")
        lines.append(
            f"Summed amount: {data['total_amount_cents']} cents "
            f"(${data['total_amount_cents'] / 100:.2f}) — placeholder, not a valuation"
        )
        lines.append("")
        lines.append(f"By agent_id ({len(data['by_agent'])} distinct):")
        for agent_id, n in data["by_agent"]:
            lines.append(f"  {agent_id:<32} {n}")
    else:
        lines.append("(No simulation rows.)")
    lines.append("")
    lines.append("=" * 78)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Read-only readout of relabelled ('simulation') settlement "
        "intent rows (decision/zephyr-stops-minting-payment-claims-2026-08-11, Leg 3)."
    )
    parser.add_argument(
        "--db",
        default=None,
        help="Path to intent_queue.db. Default: $ZEPHYR_INTENT_QUEUE_DB or "
        "/data/zephyr/intent_queue.db.",
    )
    args = parser.parse_args(argv)

    db_path = Path(args.db) if args.db else _default_queue_db()

    try:
        data = gather(db_path)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(render(data))
    sys.exit(0)


if __name__ == "__main__":
    main()
