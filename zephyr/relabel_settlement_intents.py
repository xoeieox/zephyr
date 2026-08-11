"""python -m zephyr.relabel_settlement_intents — one-shot relabel migration.

Moves every ``settlement_intents`` row with ``status = 'pending'`` to
``status = 'simulation'`` and stamps a ``reason`` on each, per
decision/zephyr-stops-minting-payment-claims-2026-08-11 (Leg 2).

WHY THIS EXISTS — read before running.
Zephyr does not mint payment claims (R1 of that decision). Until the emit
call was removed from ``attribution.py``'s ``record()``, every signed
deposit appended a hardcoded one-cent (``amount=1``, ``asset_code='USD'``)
row here with ``status='pending'`` — a fabricated payment claim nobody owed
and nothing was ever going to settle. R2 chose to relabel the existing rows
rather than delete or freeze them: the data stays on disk as evidence of the
defect. **``simulation`` was never an intended mode of operation.** It is
defect residue, not a feature, not a dry-run economics model, and not a
statement that a cent is owed. The authoritative record of why is
``decision/zephyr-stops-minting-payment-claims-2026-08-11`` — every relabelled
row's ``reason`` column names it explicitly so a future reader who encounters
the label lands one step from the defect record, not a feature description.

WHAT THIS DOES
  UPDATE settlement_intents
  SET status = 'simulation', reason = '<defect-residue reason, see below>'
  WHERE status = 'pending';

Only ``pending`` rows are touched. Rows already in ``in_flight``, ``settled``,
``no-route``, ``failed``, or already ``simulation`` are left exactly as they
are. No row is ever deleted; no column but the additive ``reason`` (added by
SettlementIntentQueue._migrate(), guarded by PRAGMA table_info so it is a
no-op on an already-migrated DB) is touched.

DRY-RUN IS THE DEFAULT. Invoking this module with no flags performs no
write — it only counts and reports what WOULD be relabelled. Writing
requires the explicit ``--execute`` flag; ``--dry-run`` is also accepted
(and wins over ``--execute`` if both are given) purely for callers who want
to say the safe thing explicitly.

IDEMPOTENT. Running with ``--execute`` a second time relabels zero rows
(the WHERE clause only ever matches ``status = 'pending'``) and exits 0.

REVERSIBLE (documented, not automated — no code path in this repo performs
the reverse). The inverse operation, should it ever be needed, is:
  UPDATE settlement_intents
  SET status = 'pending', reason = NULL
  WHERE status = 'simulation' AND reason LIKE 'defect-residue:%';
This repo intentionally ships no CLI flag for the reverse — restoring
8,120 fabricated payment claims to 'pending' is exactly the defect this
migration exists to correct, so making it a flag would be handing back
the footgun. Anyone who genuinely needs to reverse this should run the SQL
above by hand against a specific DB, deliberately.

Usage:
  python -m zephyr.relabel_settlement_intents [--db PATH] [--execute]

Exits 0 on success (dry-run or executed). Exits 1 on error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from zephyr.intent_queue import SettlementIntentQueue, _default_queue_db

# Written verbatim into every relabelled row's `reason` column. Names the
# defect and the decision key — deliberately NOT phrased as a mode
# ("simulation mode enabled") so the label cannot be misread as a feature.
RELABEL_REASON = (
    "defect-residue: row was a fabricated one-cent payment claim minted by "
    "the since-removed default settlement-intent emit in attribution.py's "
    "record(); simulation was never an intended mode. See "
    "decision/zephyr-stops-minting-payment-claims-2026-08-11."
)


def relabel(db_path: Path, *, execute: bool) -> dict:
    """Run the relabel migration against *db_path*.

    Opening a SettlementIntentQueue against db_path applies the additive
    `reason` column migration (idempotent) before the relabel runs, so the
    column is guaranteed to exist either way.

    Returns {"affected": int, "executed": bool, "db_path": str}.
    *affected* is the count of rows with status='pending' — the count that
    would be (dry-run) or was (executed) relabelled.
    """
    queue = SettlementIntentQueue(db_path)
    pending_count = queue.relabel_pending_to_simulation(RELABEL_REASON, execute=execute)

    return {
        "affected": pending_count,
        "executed": bool(execute and pending_count > 0),
        "db_path": str(db_path),
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Relabel pending settlement_intents rows to 'simulation' "
        "(decision/zephyr-stops-minting-payment-claims-2026-08-11, Leg 2)."
    )
    parser.add_argument(
        "--db",
        default=None,
        help="Path to intent_queue.db. Default: $ZEPHYR_INTENT_QUEUE_DB or "
        "/data/zephyr/intent_queue.db.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually perform the relabel write. Without this flag the "
        "migration always dry-runs, regardless of any other flag.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Explicitly request a dry run. This is also the default with "
        "no flags at all, and wins over --execute if both are given.",
    )
    args = parser.parse_args(argv)

    db_path = Path(args.db) if args.db else _default_queue_db()
    do_write = args.execute and not args.dry_run

    try:
        result = relabel(db_path, execute=do_write)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Verb reflects the caller's intent (do_write), not just whether a write
    # actually happened — a real --execute run against an already-migrated
    # DB (0 pending rows) still ran in execute mode, it just had nothing to
    # do, and should not be reported as if it were a dry run.
    verb = "Relabelled" if do_write else "Would relabel"
    print(
        f"{verb} {result['affected']} row(s) pending -> simulation "
        f"in {result['db_path']}"
    )
    if not do_write:
        print(
            "Dry run — no changes were written. Pass --execute to apply.",
            file=sys.stderr,
        )
    sys.exit(0)


if __name__ == "__main__":
    main()
