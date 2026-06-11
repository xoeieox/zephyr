"""SplitPolicy - v0 void implementation (no share calculation).

Per spec: The machine makes NO claim about the correct share. Shares are the
*open problem* left to human negotiation outside the machine.

v0 SplitPolicy is a void: it emits the intent as-is with a flat $0.01 nominal
amount (purely attestation cost, never compensation).

Future upgrade: proportional multi-party splitting moves into an upgraded
SplitPolicy; the interface remains stable.
"""

from __future__ import annotations


class SplitPolicy:
    """Base interface for computing settlement splits (v0: void)."""

    def compute(self, intent: dict) -> dict:
        """Apply split policy to an intent.

        v0 void implementation: returns intent unchanged.
        Future: upgrades to proportional/multi-party splitting.

        Args:
            intent: Settlement intent from the queue.

        Returns:
            The intent, possibly modified (v0: no modification).
        """
        return intent


def get_split_policy() -> SplitPolicy:
    """Return the active SplitPolicy instance (v0: void by default)."""
    return SplitPolicy()
