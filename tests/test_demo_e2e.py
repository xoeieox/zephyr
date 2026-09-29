"""End-to-end test for the U3 demo (zephyr-demo-runnable-v0).

Tests that the demo script runs successfully with proper registration of
contributor pubkeys, and produces the expected settlement outcomes.
"""

import os
import tempfile
from pathlib import Path


def test_demo_setup_registers_pubkeys_in_registry():
    """Test that setup_demo registers contributor pubkeys in the registry.

    This is the core fix for zephyr-demo-runnable-v0: the demo previously
    crashed with "unknown pubkey_id" error because setup_demo never registered
    the keys. This test verifies the fix is in place and checks that the
    registry dir is properly isolated from production.
    """
    # Set up isolated temp directories
    tmp_dir = Path(tempfile.mkdtemp(prefix="zephyr-demo-registry-"))
    keys_dir = tmp_dir / "demo-keys"
    wallet_map_path = tmp_dir / "wallet_map.json"
    registry_dir = tmp_dir / "registry"
    registry_dir.mkdir(exist_ok=True)

    # Run setup_demo with explicit registry_dir parameter (no env-var coupling)
    from fixtures.setup_demo import setup_demo

    setup_result = setup_demo(
        num_contributors=3,
        output_env_file=None,
        keys_dir=keys_dir,
        wallet_map_path=wallet_map_path,
        registry_dir=registry_dir,
    )

    # Verify setup completed
    assert len(setup_result["contributors"]) == 3
    assert setup_result["contributors"][0]["no_wallet"] is True

    # Verify the registry has the registered keys (create fresh instance pointing to registry_dir)
    from zephyr.registry import PubkeyRegistry

    registry = PubkeyRegistry(registry_dir)
    all_entries = registry.load_all()

    assert len(all_entries) >= 3, f"Expected 3+ registered keys, got {len(all_entries)}"

    # Verify each contributor's key is registered with correct properties
    for contrib in setup_result["contributors"]:
        pubkey_id = contrib["pubkey_id"]
        entry = registry.lookup(pubkey_id)

        assert entry is not None, f"Pubkey {pubkey_id} not registered"
        assert entry["role"] == "agent", f"Expected role='agent', got {entry['role']}"
        assert (
            entry["agent_id"] == f"agent:{contrib['name']}"
        ), f"Key registered to wrong agent_id: {entry['agent_id']}"
        assert entry["status"] == "active", "Key should be active"


def test_demo_deposits_are_verified():
    """Test that signed deposits in the demo pass signature verification.

    This ensures the real attribution gate is used, not a stub.
    Uses isolated temp directories for keys and registry to avoid contaminating
    production stores.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="zephyr-demo-verify-"))
    keys_dir = tmp_dir / "demo-keys"
    wallet_map_path = tmp_dir / "wallet_map.json"
    registry_dir = tmp_dir / "registry"
    registry_dir.mkdir(exist_ok=True)

    # Setup with isolated directories
    from fixtures.setup_demo import setup_demo

    setup_result = setup_demo(
        num_contributors=3,
        output_env_file=None,
        keys_dir=keys_dir,
        wallet_map_path=wallet_map_path,
        registry_dir=registry_dir,
    )

    # Import zephyr modules (attribution.py can use module-level registry)
    from zephyr.attribution import AttributionLog, verify_row
    from zephyr.registry import PubkeyRegistry
    from zephyr.signing import AgentSigner
    from datetime import datetime, timezone

    # Use isolated temp databases
    attr_log = AttributionLog(tmp_dir / "attribution.db")
    # Create a registry instance pointing to our isolated registry_dir
    registry = PubkeyRegistry(registry_dir)

    # Make a signed deposit like the demo does
    contrib = setup_result["contributors"][0]
    key_file = keys_dir / f"{contrib['name']}.pem"
    signer = AgentSigner(key_file)

    manifest = "sha256:test-deposit"
    provenance = {
        "manifest_hash": manifest,
        "agent_id": f"agent:{contrib['name']}",
        "pubkey_id": contrib["pubkey_id"],
        "tool": "demo",
        "model": "demo-v0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "schema_version": "lapis-provenance-v0.1",
    }
    provenance["signature"] = signer.sign(manifest)

    # Record the deposit
    newly_recorded = attr_log.record(provenance, registry=registry)
    assert newly_recorded, "Deposit should be newly recorded"

    # Verify the recorded deposit
    row = attr_log.get(manifest)
    assert row is not None
    assert row["signature"] is not None
    assert row["pubkey_id"] == contrib["pubkey_id"]

    # Check verification at read time
    vr = verify_row(row, registry=registry)
    assert vr.verified, f"Signature should verify, but got status={vr.status}"


def test_demo_emit_json_schema_valid():
    """Test that --dry-run --emit-json produces a schema-valid document.

    Asserts key-presence against the contract (zephyr-demo-eventlog.example.json,
    schema 1.1) for the dry-run path.
    """
    import json
    import tempfile
    import os
    import sys

    tmp_dir = Path(tempfile.mkdtemp(prefix="zephyr-demo-emit-json-"))
    keys_dir = tmp_dir / "demo-keys"
    wallet_map_path = tmp_dir / "wallet_map.json"
    registry_dir = tmp_dir / "registry"
    registry_dir.mkdir(exist_ok=True)
    attr_db = tmp_dir / "attribution.db"
    queue_db = tmp_dir / "intent_queue.db"
    ledger_db = tmp_dir / "ledger.db"
    emit_path = tmp_dir / "capture.json"

    # Set registry and queue dirs BEFORE any imports that use them
    old_keys_dir = os.environ.get("ZEPHYR_KEYS_DIR")
    old_queue_db = os.environ.get("ZEPHYR_INTENT_QUEUE_DB")
    old_attr_db = os.environ.get("ZEPHYR_ATTRIBUTION_DB")
    os.environ["ZEPHYR_KEYS_DIR"] = str(registry_dir)
    os.environ["ZEPHYR_INTENT_QUEUE_DB"] = str(queue_db)
    os.environ["ZEPHYR_ATTRIBUTION_DB"] = str(attr_db)

    # Clear any cached modules to force re-evaluation of DEFAULT_*_DIR
    deleted_modules = {}
    for mod in list(sys.modules.keys()):
        if 'zephyr' in mod or 'fixture' in mod or 'settler' in mod:
            deleted_modules[mod] = sys.modules[mod]
            del sys.modules[mod]

    try:
        # Setup demo environment
        from fixtures.setup_demo import setup_demo

        setup_result = setup_demo(
            num_contributors=3,
            output_env_file=None,
            keys_dir=keys_dir,
            wallet_map_path=wallet_map_path,
            registry_dir=registry_dir,
        )

        # Run demo with --dry-run --emit-json
        from demo.run_demo import run_demo, load_wallets_config

        demo_env = {
            "ZEPHYR_DEMO_KEYS_DIR": str(keys_dir),
            "ZEPHYR_DEMO_CONTRIBUTORS": json.dumps(setup_result["contributors"]),
            "ZEPHYR_SETTLER_WALLET_MAP": str(wallet_map_path),
            "ZEPHYR_SETTLER_SOURCE_WALLET": "https://wallet.interledger-test.dev/zephyr-settler-source",
        }

        results = run_demo(
            demo_env,
            dry_run=True,
            emit_json_path=emit_path,
            attr_db=attr_db,
            queue_db=queue_db,
            ledger_db=ledger_db,
        )

        # Verify the JSON file was written
        assert emit_path.exists(), f"Event-log not written to {emit_path}"

        # Parse and validate schema
        doc = json.loads(emit_path.read_text())

        # Check top-level keys (schema 1.2 - 3-act model)
        assert "schema_version" in doc, "Missing schema_version"
        assert doc["schema_version"] == "1.2", f"Expected schema_version 1.2, got {doc['schema_version']}"

        # Check run block
        assert "run" in doc, "Missing run block"
        run_block = doc["run"]
        assert "id" in run_block, "run block missing id"
        assert "mode" in run_block, "run block missing mode"
        assert "network" in run_block, "run block missing network"
        assert "captured_at" in run_block, "run block missing captured_at"
        assert "settler_source_wallet" in run_block, "run block missing settler_source_wallet"
        assert "inter_scene_gap_ms" in run_block, "run block missing inter_scene_gap_ms"
        assert run_block["mode"] == "captured-mock", "Dry-run should have mode=captured-mock"

        # Check actors
        assert "actors" in doc, "Missing actors"
        assert len(doc["actors"]) >= 3, "Expected at least 3 actors"
        actor_ids = {a["id"] for a in doc["actors"]}
        assert "user" in actor_ids, "Missing user actor"
        assert "settler" in actor_ids, "Missing settler actor"
        assert "rafiki" in actor_ids, "Missing rafiki actor"

        # Check artifacts
        assert "artifacts" in doc, "Missing artifacts"
        assert len(doc["artifacts"]) >= 2, "Expected at least 2 artifacts"
        artifact_ids = {a["id"] for a in doc["artifacts"]}
        assert "smiley" in artifact_ids, "Missing smiley artifact"
        assert "hat-remix" in artifact_ids, "Missing hat-remix artifact"

        # Check that remix has derived_from pointing to original's manifest_hash
        remix_artifact = next(a for a in doc["artifacts"] if a["id"] == "hat-remix")
        original_artifact = next(a for a in doc["artifacts"] if a["id"] == "smiley")
        assert "derived_from" in remix_artifact, "remix artifact missing derived_from"
        assert remix_artifact["derived_from"] == original_artifact["manifest_hash"], \
            "remix derived_from should point to original manifest_hash"

        # Check scenes (3-act model: act-1-deposit, act-2-remix, act-3-purchase)
        assert "scenes" in doc, "Missing scenes"
        assert len(doc["scenes"]) >= 3, "Expected at least 3 scenes (acts)"

        for scene in doc["scenes"]:
            assert "id" in scene, "scene missing id"
            assert "title" in scene, "scene missing title"
            assert scene["title"], "scene title should not be empty"
            assert "user" in scene, "scene missing user"
            assert scene["user"] is not None, "scene user should not be null"
            assert "id" in scene["user"], "user missing id"
            assert "display" in scene["user"], "user missing display"
            assert "has_wallet" in scene["user"], "user missing has_wallet"
            assert "artifact" in scene, "scene missing artifact"
            assert "outcome" in scene, "scene missing outcome"
            assert scene["outcome"] in ("no-route", "settled", "attributed"), f"unexpected outcome: {scene['outcome']}"
            assert "events" in scene, "scene missing events"
            assert len(scene["events"]) > 0, "scene should have at least one event"

            # Verify events have required fields
            for event in scene["events"]:
                assert "t" in event, "event missing t (timestamp)"
                assert "from" in event, "event missing from"
                assert "to" in event, "event missing to"
                assert "kind" in event, "event missing kind"
                assert "label" in event, "event missing label"
                assert "detail" in event, "event missing detail"

        # Check Act 1 (original, no-route)
        act_1 = next(s for s in doc["scenes"] if s["id"] == "act-1-deposit")
        assert act_1["outcome"] == "attributed", "Act 1 should have outcome=attributed"
        assert act_1["user"]["has_wallet"] is False, "Act 1 user should have has_wallet=false"
        # Verify no Rafiki events in act 1 (no OP calls for original deposit)
        rafiki_events = [e for e in act_1["events"] if e.get("to") == "rafiki"]
        assert len(rafiki_events) == 0, "Act 1 should have no Rafiki events (deposit only)"

        # Check Act 2 (remix, no settlement yet)
        act_2 = next(s for s in doc["scenes"] if s["id"] == "act-2-remix")
        assert act_2["outcome"] == "attributed", "Act 2 should have outcome=attributed"
        assert act_2["user"]["has_wallet"] is True, "Act 2 user should have has_wallet=true"

        # Check Act 3 (purchase, settlement)
        act_3 = next(s for s in doc["scenes"] if s["id"] == "act-3-purchase")
        assert act_3["outcome"] == "settled", "Act 3 should have outcome=settled"
        assert act_3["user"]["has_wallet"] is True, "Act 3 user should have has_wallet=true"

        # Check ledger
        assert "ledger" in doc, "Missing ledger"
        assert len(doc["ledger"]) >= 2, "Expected at least 2 ledger rows"
        ledger_statuses = {row["status"] for row in doc["ledger"]}
        assert "no-route" in ledger_statuses, "ledger should have a no-route row"
        assert "settled" in ledger_statuses, "ledger should have a settled row"

        # Verify Act 3 contains all required event kinds (OP request/response pairs and GNAP grant flow)
        act3_kinds = {e["kind"] for e in act_3["events"]}
        required_kinds = {"op_request", "op_response", "grant_request", "grant_interaction", "grant_approval", "grant_response"}
        assert required_kinds <= act3_kinds, f"Act 3 missing required event kinds. Expected {required_kinds}, got {act3_kinds}"

        # Check void_principle
        assert "void_principle" in doc, "Missing void_principle"
        void = doc["void_principle"]
        assert "policy" in void, "void_principle missing policy"
        assert "statement" in void, "void_principle missing statement"
        assert "record_not_money" in void, "void_principle missing record_not_money"
        assert "coda" in void, "void_principle missing coda"
    finally:
        # Restore deleted sys.modules
        for mod, obj in deleted_modules.items():
            sys.modules[mod] = obj

        # Restore original environment variables
        if old_keys_dir is not None:
            os.environ["ZEPHYR_KEYS_DIR"] = old_keys_dir
        else:
            os.environ.pop("ZEPHYR_KEYS_DIR", None)
        if old_queue_db is not None:
            os.environ["ZEPHYR_INTENT_QUEUE_DB"] = old_queue_db
        else:
            os.environ.pop("ZEPHYR_INTENT_QUEUE_DB", None)
        if old_attr_db is not None:
            os.environ["ZEPHYR_ATTRIBUTION_DB"] = old_attr_db
        else:
            os.environ.pop("ZEPHYR_ATTRIBUTION_DB", None)


# ---------------------------------------------------------------------------
# Consent of use (rail zephyr-use-terms-consent-v0, D2)
#
# The consent scene runs between act-1-deposit and act-2-remix, and the remix
# consult is anchored IMMEDIATELY BEFORE the functional remix deposit (the
# make_signed_deposit(... derived_from=manifest_original ...) call), so a
# non-"permitted" report means the remix never reaches the attribution log at
# all. All three consumer outcomes are asserted distinctly, and the
# third-party training bot (net-new actor "crawler") is asserted too.
# ---------------------------------------------------------------------------


def _run_consent_demo(tmp_root, consent_declaration):
    """Set up an isolated demo run and return (results, capture_doc, paths)."""
    import json as _json
    import sys as _sys

    tmp_dir = Path(tmp_root)
    keys_dir = tmp_dir / "demo-keys"
    wallet_map_path = tmp_dir / "wallet_map.json"
    registry_dir = tmp_dir / "registry"
    registry_dir.mkdir(exist_ok=True)
    attr_db = tmp_dir / "attribution.db"
    queue_db = tmp_dir / "intent_queue.db"
    ledger_db = tmp_dir / "ledger.db"
    emit_path = tmp_dir / "capture.json"

    old = {
        k: os.environ.get(k)
        for k in ("ZEPHYR_KEYS_DIR", "ZEPHYR_INTENT_QUEUE_DB", "ZEPHYR_ATTRIBUTION_DB", "ZEPHYR_CLAIMS_DB")
    }
    os.environ["ZEPHYR_KEYS_DIR"] = str(registry_dir)
    os.environ["ZEPHYR_INTENT_QUEUE_DB"] = str(queue_db)
    os.environ["ZEPHYR_ATTRIBUTION_DB"] = str(attr_db)
    os.environ["ZEPHYR_CLAIMS_DB"] = str(tmp_dir / "claims.db")

    deleted = {}
    for mod in list(_sys.modules.keys()):
        if "zephyr" in mod or "fixture" in mod or "settler" in mod:
            deleted[mod] = _sys.modules[mod]
            del _sys.modules[mod]

    try:
        from fixtures.setup_demo import setup_demo

        setup_result = setup_demo(
            num_contributors=3,
            output_env_file=None,
            keys_dir=keys_dir,
            wallet_map_path=wallet_map_path,
            registry_dir=registry_dir,
        )
        from demo.run_demo import run_demo

        demo_env = {
            "ZEPHYR_DEMO_KEYS_DIR": str(keys_dir),
            "ZEPHYR_DEMO_CONTRIBUTORS": _json.dumps(setup_result["contributors"]),
            "ZEPHYR_SETTLER_WALLET_MAP": str(wallet_map_path),
            "ZEPHYR_SETTLER_SOURCE_WALLET": "https://wallet.interledger-test.dev/zephyr-settler-source",
        }
        results = run_demo(
            demo_env,
            dry_run=True,
            emit_json_path=emit_path,
            attr_db=attr_db,
            queue_db=queue_db,
            ledger_db=ledger_db,
            consent_declaration=consent_declaration,
        )
        doc = _json.loads(emit_path.read_text()) if emit_path.exists() else None
        return results, doc, attr_db, registry_dir
    finally:
        for mod, obj in deleted.items():
            _sys.modules[mod] = obj
        for k, v in old.items():
            if v is not None:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)


def test_demo_consent_permitted_remix_proceeds():
    """permitted -> the remix is deposited, lineage recorded, act-1b ships."""
    with tempfile.TemporaryDirectory(prefix="zephyr-consent-permitted-") as td:
        results, doc, attr_db, registry_dir = _run_consent_demo(td, None)

        assert results["consent"]["remix_use"] == "permitted"
        assert results["consent"]["training_use"] == "denied"
        assert results["consent"]["declared"] is True
        assert "remix_skipped" not in results["consent"]
        # the remix really is in the log
        remix_mh = next(c["manifest_hash"] for c in results["contributors"] if c["role"] == "remixer")
        from zephyr.attribution import AttributionLog

        row = AttributionLog(attr_db).get(remix_mh)
        assert row is not None and row["derived_from"] is not None

        scenes = {s["id"]: s for s in doc["scenes"]}
        assert "act-1b-consent" in scenes, list(scenes)
        order = [s["id"] for s in doc["scenes"]]
        assert order.index("act-1b-consent") == order.index("act-1-deposit") + 1
        consent = scenes["act-1b-consent"]
        kinds = {e["kind"] for e in consent["events"]}
        assert {"consent_declaration", "consent_report", "consent_check"} <= kinds
        bot = next(e for e in consent["events"] if e["kind"] == "consent_check")
        assert bot["from"] == "crawler"
        assert bot["detail"]["report"] == "denied"
        assert bot["detail"]["action"] == "skip"
        # remix scene deposited normally
        assert any(e["kind"] == "deposit" for e in scenes["act-2-remix"]["events"])
        assert not any(e["kind"] == "consent_skip" for e in scenes["act-2-remix"]["events"])


def test_demo_consent_denied_remix_skips():
    """denied -> the remix is never deposited, and the skip is a logged beat."""
    with tempfile.TemporaryDirectory(prefix="zephyr-consent-denied-") as td:
        results, doc, attr_db, registry_dir = _run_consent_demo(
            td, {"allowed_uses": ["redistribution"], "denied_uses": ["remix", "training"]}
        )

        assert results["consent"]["remix_use"] == "denied"
        assert results["consent"]["remix_skipped"] is True
        assert not any(c["role"] == "remixer" for c in results["contributors"])
        assert results["settled"] == []

        from zephyr.attribution import AttributionLog

        log = AttributionLog(attr_db)
        remix_mh = "sha256:9ebd0fd52e5cf445a66805cd97fe6bfd59cb34eb4a57c0f19f42e831aef59598"
        assert log.get(remix_mh) is None, "a denied remix must never reach the log"

        scenes = {s["id"]: s for s in doc["scenes"]}
        assert any(e["kind"] == "consent_skip" for e in scenes["act-2-remix"]["events"])
        skip = next(e for e in scenes["act-2-remix"]["events"] if e["kind"] == "consent_skip")
        assert skip["detail"]["report"] == "denied"

        # Hygiene MINOR (capture-doc names skipped artifact): the skipped remix
        # was never deposited, so the doc's artifact registry must not name it.
        artifact_ids = {a["id"] for a in doc["artifacts"]}
        assert "hat-remix" not in artifact_ids, artifact_ids
        assert artifact_ids == {"smiley"}, artifact_ids
        # ...and the act-3 purchase beat must not name it either.
        purchase = next(e for e in scenes["act-3-purchase"]["events"] if e["kind"] == "purchase")
        assert "artifact" not in purchase["detail"], purchase["detail"]
        assert "hat-remix" not in str(purchase)
        chain = next(e for e in scenes["act-3-purchase"]["events"] if e["kind"] == "chain")
        assert "hat-remix" not in str(chain)


def test_demo_consent_skipped_remix_is_absent_from_capture_artifacts():
    """Hygiene MINOR (demo capture-doc names skipped artifact): hat-remix used
    to be registered unconditionally before the consent gate, so a skipped
    remix still showed up in doc["artifacts"] - the capture-doc named a thing
    that was never deposited. Registration is now gated on the remix actually
    proceeding, and the act-3 purchase emit guards its hat-remix reference."""
    with tempfile.TemporaryDirectory(prefix="zephyr-consent-artifacts-") as td:
        results, doc, attr_db, registry_dir = _run_consent_demo(td, {"declare": False})

        assert results["consent"]["remix_skipped"] is True
        ids = {a["id"] for a in doc["artifacts"]}
        assert "hat-remix" not in ids, f"skipped artifact named in capture-doc: {ids}"
        assert "smiley" in ids, ids
        # the surviving artifact is the original, and it stands alone
        assert len(doc["artifacts"]) == 1
        assert doc["artifacts"][0]["id"] == "smiley"
        assert "derived_from" not in doc["artifacts"][0]
        # no ledger row was minted for an artifact that does not exist
        assert not any(row["artifact"] == "hat-remix" for row in doc["ledger"])


def test_demo_consent_undeclared_remix_skips_conservatively():
    """undeclared (nothing declared) -> the v0 consumer skips: undeclared is
    never permission."""
    with tempfile.TemporaryDirectory(prefix="zephyr-consent-undeclared-") as td:
        results, doc, attr_db, registry_dir = _run_consent_demo(td, {"declare": False})

        assert results["consent"]["declared"] is False
        assert results["consent"]["remix_use"] == "undeclared"
        assert results["consent"]["training_use"] == "undeclared"
        assert results["consent"]["remix_skipped"] is True
        assert not any(c["role"] == "remixer" for c in results["contributors"])

        scenes = {s["id"]: s for s in doc["scenes"]}
        report = next(e for e in scenes["act-1b-consent"]["events"] if e["kind"] == "consent_report")
        assert report["detail"]["remix"] == "undeclared"
        assert report["detail"]["vocabulary"] == ["training", "remix", "redistribution"]
        bot = next(e for e in scenes["act-1b-consent"]["events"] if e["kind"] == "consent_check")
        assert bot["detail"]["report"] == "undeclared" and bot["detail"]["action"] == "skip"
        assert any(e["kind"] == "consent_skip" for e in scenes["act-2-remix"]["events"])


def test_demo_consent_revoked_declarator_never_honored_above_denied():
    """The training bot's own law: a revoked declarator key turns the report
    from 'denied' into 'undeclared', and the bot skips BOTH - it never treats
    undeclared as more permissive than the prior denied."""
    with tempfile.TemporaryDirectory(prefix="zephyr-consent-revoked-") as td:
        results, doc, attr_db, registry_dir = _run_consent_demo(
            td, {"allowed_uses": ["remix"], "denied_uses": ["training"], "revoke_declarator_key": True}
        )

        assert results["consent"]["declarator_key_revoked"] is True
        assert results["consent"]["training_use"] == "undeclared"
        assert results["consent"]["remix_use"] == "undeclared"
        assert results["consent"]["remix_skipped"] is True

        scenes = {s["id"]: s for s in doc["scenes"]}
        bot = next(e for e in scenes["act-1b-consent"]["events"] if e["kind"] == "consent_check")
        assert bot["detail"]["report"] == "undeclared"
        assert bot["detail"]["action"] == "skip", "undeclared must never be honored above denied"


def test_demo_consent_uses_only_the_closed_vocabulary():
    """The scene's declaration is written against the shipped vocabulary, and
    an out-of-vocabulary declaration is refused before anything is deposited."""
    with tempfile.TemporaryDirectory(prefix="zephyr-consent-vocab-") as td:
        results, doc, attr_db, registry_dir = _run_consent_demo(td, None)
        scenes = {s["id"]: s for s in doc["scenes"]}
        decl = next(e for e in scenes["act-1b-consent"]["events"] if e["kind"] == "consent_declaration")
        assert set(decl["detail"]["allowed_uses"]) | set(decl["detail"]["denied_uses"]) <= {
            "training", "remix", "redistribution"
        }
        # declared_by is reported (the consumer's entitlement cross-check needs it)
        assert decl["detail"]["declared_by"]
        assert "never proof of entitlement" in decl["detail"]["note"]
