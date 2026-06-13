"""Event-log emitter for captured settlement runs.

Structures all settlement activity as timestamped events conforming to the
shared contract (zephyr-demo-eventlog.example.json, schema 1.2 - 3-act model).

Event format: {t, from, to, kind, label, detail}
  t: milliseconds relative to scene start
  from/to: actor IDs from the actors list
  kind: event classification (deposit, lineage, policy, route, op_request, grant_interaction, etc.)
  label: human-readable description
  detail: event-specific data dict (includes raw request/response for OP calls)
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, asdict
from typing import Any, Optional
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass
class Event:
    """A single event in the settlement flow."""
    t: int  # milliseconds relative to scene start
    from_: str  # actor ID (use "from_" to avoid Python keyword)
    to: str  # actor ID
    kind: str  # event classification
    label: str  # human-readable description
    detail: dict  # event-specific data

    def to_dict(self) -> dict:
        """Convert to dict with 'from' key (not 'from_')."""
        d = asdict(self)
        d["from"] = d.pop("from_")
        return d


class EventLog:
    """Captures events during a settlement run."""

    def __init__(self, scene_id: str, start_time: float | None = None):
        """Initialize event log for a scene.

        Args:
            scene_id: Identifier for this scene (e.g., "act-1-deposit")
            start_time: Unix timestamp for scene start (default: now)
        """
        self.scene_id = scene_id
        self.start_time = start_time or time.time()
        self.events: list[Event] = []
        self.contributor_info: dict | None = None
        self.title: str = ""
        self.outcome: str | None = None  # Explicit outcome, can be set via set_outcome()

    def emit(
        self,
        from_: str,
        to: str,
        kind: str,
        label: str,
        detail: dict,
        t: int | None = None,
    ) -> None:
        """Record an event.

        Args:
            from_: Actor ID (source)
            to: Actor ID (destination)
            kind: Event classification
            label: Human-readable label
            detail: Event-specific data
            t: Time in ms since scene start (default: current elapsed time)
        """
        if t is None:
            elapsed = (time.time() - self.start_time) * 1000
            t = int(elapsed)

        event = Event(
            t=t,
            from_=from_,
            to=to,
            kind=kind,
            label=label,
            detail=detail,
        )
        self.events.append(event)
        log.debug("Event [%s] t=%d %s→%s: %s", self.scene_id, t, from_, to, label)

    def set_contributor(self, agent_id: str, display: str, has_wallet: bool, role: str = "depositor") -> None:
        """Set contributor metadata for this scene.

        Args:
            agent_id: Agent ID (e.g., "agent:contributor_01")
            display: Display name
            has_wallet: Whether contributor has a wallet
            role: Role in this act (depositor, remixer, purchaser)
        """
        self.contributor_info = {
            "id": agent_id.replace("agent:", "").lower(),
            "display": display,
            "role": role,
            "has_wallet": has_wallet,
        }

    def set_title(self, title: str) -> None:
        """Set the scene title."""
        self.title = title

    def set_outcome(self, outcome: str) -> None:
        """Set the scene outcome explicitly (e.g., 'settled', 'attributed', 'no-route')."""
        self.outcome = outcome

    def to_list(self) -> list[dict]:
        """Return events as list of dicts."""
        return [e.to_dict() for e in self.events]


class CapturedRun:
    """Complete captured settlement run with all scenes and metadata."""

    def __init__(
        self,
        run_id: str,
        mode: str,
        network: str,
        settler_source_wallet: str,
        inter_scene_gap_ms: int = 2000,
    ):
        """Initialize a captured run.

        Args:
            run_id: Unique identifier for this run
            mode: Capture mode (e.g., "live-testnet-a1", "captured-mock")
            network: Network identifier (e.g., "interledger-test.dev")
            settler_source_wallet: Source wallet URL
            inter_scene_gap_ms: Gap between scenes in event timeline
        """
        self.run_id = run_id
        self.mode = mode
        self.network = network
        self.settler_source_wallet = settler_source_wallet
        self.inter_scene_gap_ms = inter_scene_gap_ms
        self.captured_at = None  # Will be set at finalization
        self.actors: list[dict] = []
        self.artifacts: list[dict] = []
        self.scenes: list[dict] = []
        self.ledger: list[dict] = []
        self.void_principle: dict = {}
        self.scene_logs: list[EventLog] = []

    def add_actor(
        self,
        id: str,
        label: str,
        kind: str,
        sub: str,
    ) -> None:
        """Add an actor to the run."""
        self.actors.append({
            "id": id,
            "label": label,
            "kind": kind,
            "sub": sub,
        })

    def add_artifact(
        self,
        id: str,
        filename: str,
        media_type: str,
        manifest_hash: str,
        caption: str,
        derived_from: str | None = None,
    ) -> None:
        """Add an artifact to the run."""
        artifact = {
            "id": id,
            "filename": filename,
            "media_type": media_type,
            "manifest_hash": manifest_hash,
            "caption": caption,
        }
        if derived_from:
            artifact["derived_from"] = derived_from
        self.artifacts.append(artifact)

    def add_ledger_row(
        self,
        user: str,
        artifact: str,
        status: str,
        amount: int | None,
        asset_code: str,
        op_payment_id: str | None,
        attribution: str,
        record: str | None = None,
        derived_from: str | None = None,
    ) -> None:
        """Add a ledger row to the final summary."""
        row = {
            "user": user,
            "artifact": artifact,
            "status": status,
            "amount": amount,
            "asset_code": asset_code,
            "op_payment_id": op_payment_id,
            "attribution": attribution,
        }
        if record:
            row["record"] = record
        if derived_from:
            row["derived_from"] = derived_from
        self.ledger.append(row)

    def start_scene(self, scene_id: str, start_time: float | None = None) -> EventLog:
        """Start a new scene and return its event log."""
        scene_log = EventLog(scene_id, start_time)
        self.scene_logs.append(scene_log)
        return scene_log

    def finalize(self, captured_at: str | None = None) -> dict:
        """Finalize the run and return the complete event-log document (schema 1.2).

        Args:
            captured_at: ISO8601 timestamp (default: now)

        Returns:
            Complete document dict ready for JSON serialization
        """
        from datetime import datetime, timezone
        if captured_at is None:
            captured_at = datetime.now(timezone.utc).isoformat()
        self.captured_at = captured_at

        # Build scenes with events
        scenes_out = []
        for scene_log in self.scene_logs:
            # Use explicit outcome if set, otherwise infer from events
            outcome = scene_log.outcome
            artifact_id = None

            if not outcome:
                # Infer outcome from events (first deposit/settlement determines it)
                for event in scene_log.events:
                    if "artifact" in event.detail:
                        artifact_id = event.detail["artifact"]
                    # Use first event with a status as the outcome
                    if event.kind in ("ledger", "purchase", "deposit") and "status" in event.detail:
                        if outcome is None:  # Only set if not already set
                            outcome = event.detail["status"]
                            break

            # Extract artifact_id from events if not already found
            if not artifact_id:
                for event in scene_log.events:
                    if "artifact" in event.detail:
                        artifact_id = event.detail["artifact"]
                        break

            scene_obj = {
                "id": scene_log.scene_id,
                "title": scene_log.title,
                "user": scene_log.contributor_info,
                "artifact": artifact_id,
                "outcome": outcome or "attributed",
                "events": scene_log.to_list(),
            }
            scenes_out.append(scene_obj)

        return {
            "schema_version": "1.2",
            "run": {
                "id": self.run_id,
                "mode": self.mode,
                "network": self.network,
                "captured_at": self.captured_at,
                "settler_source_wallet": self.settler_source_wallet,
                "inter_scene_gap_ms": self.inter_scene_gap_ms,
            },
            "actors": self.actors,
            "artifacts": self.artifacts,
            "scenes": scenes_out,
            "ledger": self.ledger,
            "void_principle": self.void_principle,
        }

    def write_json(self, path: Path | str) -> None:
        """Write the finalized run to a JSON file."""
        path = Path(path)
        doc = self.finalize()
        path.write_text(json.dumps(doc, indent=2))
        log.info("Wrote event-log to %s", path)
