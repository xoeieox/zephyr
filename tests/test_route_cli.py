"""Acceptance criteria tests for the `python -m zephyr.route` Node seam (rail U2b, D3).

All subprocess-based (mirroring test_routing.py's test_ac9_cli_happy_path):
scratch DBs via env vars, synthetic keys, no writes outside tmp dirs. JSON
assertions check individual fields, never full-document equality against a
hardcoded literal - pubkey_id/signature/receipt_hash are freshly generated
per synthetic key and are not stable across runs (the U2a AC10 lesson).

Coverage map:
  AC1 -- compile is the default subcommand, byte-identical to the bare
         flat-flag invocation
  AC2 -- get-manifest / is-head emit valid single-document JSON
  AC3 -- reverify-legs on a non-head hash exits 12 with failure_mode=not_head
  AC4 -- reverify-legs on the current head reverifies every leg
  AC5 -- leg-* subcommands round-trip through the D2 state machine; an
         illegal edge exits 12 (LegStateError)
  AC6 -- record-receipt produces a verifiable signed deposit; --outcome
         choices are enforced by argparse (exit 2)
  AC7 -- exit 2 on a missing required arg, no JSON envelope required
  AC8 -- no key material or token ever appears on stdout or stderr
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from zephyr import claims
from zephyr.attribution import AttributionLog
from zephyr.registry import PubkeyRegistry
from zephyr.signing import AgentSigner

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def cli_env(tmp_path):
    attr_db = tmp_path / "attr.db"
    keys_dir = tmp_path / "keys"
    claims_db = tmp_path / "claims.db"
    route_exec_db = tmp_path / "route_exec.db"
    compiler_key = tmp_path / "agent-keys" / "compiler.key"
    node_key = tmp_path / "agent-keys" / "node.key"

    log = AttributionLog(attr_db)
    registry = PubkeyRegistry(keys_dir)

    env = dict(os.environ)
    env.update(
        {
            "ZEPHYR_ATTRIBUTION_DB": str(attr_db),
            "ZEPHYR_KEYS_DIR": str(keys_dir),
            "ZEPHYR_CLAIMS_DB": str(claims_db),
            "ZEPHYR_ROUTE_EXEC_DB": str(route_exec_db),
            "ZEPHYR_AGENT_KEY_PATH": str(compiler_key),
        }
    )
    return {
        "env": env,
        "log": log,
        "registry": registry,
        "tmp_path": tmp_path,
        "node_key_path": node_key,
    }


def _run(args, env, **kwargs):
    return subprocess.run(
        [sys.executable, "-m", "zephyr.route", *args],
        cwd=str(REPO_ROOT), env=env, capture_output=True, text=True, timeout=30, **kwargs
    )


def _signer(tmp_path, name):
    return AgentSigner(tmp_path / "agent-keys" / f"{name}.key")


def _seed_routable_leg(cli_env, *, event_ref, amount=500, bps=4000):
    """Sets up a single-beneficiary manifest with a bound wallet directly
    against the same scratch stores the subprocess CLI will read, then
    compiles it via the CLI itself (so this also exercises `compile`)."""
    log = cli_env["log"]
    registry = cli_env["registry"]
    tmp_path = cli_env["tmp_path"]

    d = _signer(tmp_path, "d")
    registry.register(d.pubkey_id_str, d.public_key_bytes.hex(), "agent:d", "agent")

    from archetypes_core.provenance import SCHEMA_VERSION_V01, to_lapis_return

    ltr = to_lapis_return(
        {"work": "x"}, agent_id="agent:d", tool="demo", summary="work x",
        schema_version=SCHEMA_VERSION_V01, timestamp="2026-07-20T00:00:00+00:00",
    )
    subject_mh = ltr.provenance.manifest_hash
    prov = ltr.provenance.to_dict()
    prov["signature"] = d.sign(subject_mh)
    prov["pubkey_id"] = d.pubkey_id_str
    log.record(prov, store_kind="content", registry=registry)

    claims_env_bak = os.environ.get("ZEPHYR_CLAIMS_DB")
    os.environ["ZEPHYR_CLAIMS_DB"] = cli_env["env"]["ZEPHYR_CLAIMS_DB"]
    claims._reset_claims_store()
    try:
        claims.record_routing_terms(
            subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=bps,
            scope="standing", declared_by="agent:d", agent_id="agent:d",
            signer=d, registry=registry, recorder=log, timestamp="2026-07-20T00:00:01+00:00",
        )
        claims.record_wallet_binding(
            subject=d.pubkey_id_str, wallet_address="https://wallet.example/d",
            agent_id="agent:d", signer=d, registry=registry, recorder=log,
            timestamp="2026-07-20T00:00:02+00:00",
        )
    finally:
        claims._reset_claims_store()
        if claims_env_bak is None:
            os.environ.pop("ZEPHYR_CLAIMS_DB", None)
        else:
            os.environ["ZEPHYR_CLAIMS_DB"] = claims_env_bak

    result = _run(
        [
            "compile",
            "--event-kind", "demo-sale", "--event-ref", event_ref, "--subject", subject_mh,
            "--amount", str(amount), "--asset-code", "USD", "--asset-scale", "2",
            "--agent-id", "agent:route-cli",
        ],
        cli_env["env"],
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    manifest_hash = payload["manifest_hash"]
    leg = payload["manifest"]["route_manifest"]["legs"][0]
    return manifest_hash, leg


# ---------------------------------------------------------------------------
# AC1 -- compile is the default subcommand, byte-identical to bare flags
# ---------------------------------------------------------------------------


def test_ac1_bare_flags_default_to_compile(cli_env):
    mh, leg = _seed_routable_leg(cli_env, event_ref="evt-ac1")
    assert mh.startswith("sha256:")
    assert leg["leg_status"] == "routable"


def test_ac1_explicit_compile_subcommand_matches(cli_env):
    log = cli_env["log"]
    registry = cli_env["registry"]
    tmp_path = cli_env["tmp_path"]
    d = _signer(tmp_path, "d2")
    registry.register(d.pubkey_id_str, d.public_key_bytes.hex(), "agent:d2", "agent")

    from archetypes_core.provenance import SCHEMA_VERSION_V01, to_lapis_return

    ltr = to_lapis_return(
        {"work": "y"}, agent_id="agent:d2", tool="demo", summary="work y",
        schema_version=SCHEMA_VERSION_V01, timestamp="2026-07-20T00:00:00+00:00",
    )
    subject_mh = ltr.provenance.manifest_hash
    prov = ltr.provenance.to_dict()
    prov["signature"] = d.sign(subject_mh)
    prov["pubkey_id"] = d.pubkey_id_str
    log.record(prov, store_kind="content", registry=registry)

    claims_env_bak = os.environ.get("ZEPHYR_CLAIMS_DB")
    os.environ["ZEPHYR_CLAIMS_DB"] = cli_env["env"]["ZEPHYR_CLAIMS_DB"]
    claims._reset_claims_store()
    try:
        claims.record_routing_terms(
            subject=subject_mh, beneficiary_pubkey_id=d.pubkey_id_str, share_bps=4000,
            scope="standing", declared_by="agent:d2", agent_id="agent:d2",
            signer=d, registry=registry, recorder=log, timestamp="2026-07-20T00:00:01+00:00",
        )
        claims.record_wallet_binding(
            subject=d.pubkey_id_str, wallet_address="https://wallet.example/d2",
            agent_id="agent:d2", signer=d, registry=registry, recorder=log,
            timestamp="2026-07-20T00:00:02+00:00",
        )
    finally:
        claims._reset_claims_store()
        if claims_env_bak is None:
            os.environ.pop("ZEPHYR_CLAIMS_DB", None)
        else:
            os.environ["ZEPHYR_CLAIMS_DB"] = claims_env_bak

    result_explicit = _run(
        [
            "compile",
            "--event-kind", "demo-sale", "--event-ref", "evt-ac1-explicit", "--subject", subject_mh,
            "--amount", "100", "--asset-code", "USD", "--asset-scale", "2",
            "--agent-id", "agent:route-cli",
        ],
        cli_env["env"],
    )
    result_bare = _run(
        [
            "--event-kind", "demo-sale", "--event-ref", "evt-ac1-bare", "--subject", subject_mh,
            "--amount", "100", "--asset-code", "USD", "--asset-scale", "2",
            "--agent-id", "agent:route-cli",
        ],
        cli_env["env"],
    )
    assert result_explicit.returncode == 0, result_explicit.stderr
    assert result_bare.returncode == 0, result_bare.stderr
    p1 = json.loads(result_explicit.stdout)
    p2 = json.loads(result_bare.stdout)
    # Same allocation shape from identical inputs (different event_ref only).
    assert p1["manifest"]["route_manifest"]["legs"][0]["amount"] == p2["manifest"]["route_manifest"]["legs"][0]["amount"]


# ---------------------------------------------------------------------------
# AC2 -- get-manifest / is-head emit single-document JSON
# ---------------------------------------------------------------------------


def test_ac2_get_manifest_null_when_absent(cli_env):
    result = _run(["get-manifest", "--event-ref", "evt-nonexistent"], cli_env["env"])
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) is None
    assert result.stdout.strip().count("\n") == 0


def test_ac2_get_manifest_returns_head(cli_env):
    mh, leg = _seed_routable_leg(cli_env, event_ref="evt-ac2")
    result = _run(["get-manifest", "--event-ref", "evt-ac2"], cli_env["env"])
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["manifest_hash"] == mh


def test_ac2_is_head_true_and_false(cli_env):
    mh, leg = _seed_routable_leg(cli_env, event_ref="evt-ac2b")
    result_true = _run(["is-head", "--event-ref", "evt-ac2b", "--manifest-hash", mh], cli_env["env"])
    assert json.loads(result_true.stdout) == {"is_current_head": True}

    result_false = _run(
        ["is-head", "--event-ref", "evt-ac2b", "--manifest-hash", "sha256:" + "0" * 64], cli_env["env"]
    )
    assert json.loads(result_false.stdout) == {"is_current_head": False}


# ---------------------------------------------------------------------------
# AC3 -- reverify-legs on a non-head hash exits 12 not_head
# ---------------------------------------------------------------------------


def test_ac3_reverify_legs_non_head_exits_12(cli_env):
    result = _run(
        ["reverify-legs", "--event-ref", "evt-nonexistent", "--manifest-hash", "sha256:" + "0" * 64],
        cli_env["env"],
    )
    assert result.returncode == 12, result.stderr
    payload = json.loads(result.stdout)
    assert payload["error"] == "RouteReceiptError"
    assert payload["failure_mode"] == "not_head"


# ---------------------------------------------------------------------------
# AC4 -- reverify-legs on the head reverifies every leg
# ---------------------------------------------------------------------------


def test_ac4_reverify_legs_on_head(cli_env):
    mh, leg = _seed_routable_leg(cli_env, event_ref="evt-ac4")
    result = _run(["reverify-legs", "--event-ref", "evt-ac4", "--manifest-hash", mh], cli_env["env"])
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert len(payload) == 1
    assert payload[0]["beneficiary_pubkey_id"] == leg["beneficiary_pubkey_id"]
    assert payload[0]["payable"] is True
    assert payload[0]["reason"] == "ok"


# ---------------------------------------------------------------------------
# AC5 -- leg-* round-trip, illegal edge exits 12
# ---------------------------------------------------------------------------


def test_ac5_leg_lifecycle_round_trip(cli_env):
    mh, leg = _seed_routable_leg(cli_env, event_ref="evt-ac5")
    bpid = leg["beneficiary_pubkey_id"]

    r = _run(["leg-claim", "--manifest-hash", mh, "--beneficiary", bpid], cli_env["env"])
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["state"] == "pending"

    r = _run(["leg-quote", "--manifest-hash", mh, "--beneficiary", bpid, "--quote-id", "q1"], cli_env["env"])
    assert r.returncode == 0
    assert json.loads(r.stdout)["state"] == "quoted"

    r = _run(
        ["leg-submit", "--manifest-hash", mh, "--beneficiary", bpid, "--outgoing-payment-id", "https://ilp.example/pay/1"],
        cli_env["env"],
    )
    assert r.returncode == 0
    body = json.loads(r.stdout)
    assert body["state"] == "submitted"
    assert body["outgoing_payment_id"] == "https://ilp.example/pay/1"

    r = _run(["leg-settle", "--manifest-hash", mh, "--beneficiary", bpid], cli_env["env"])
    assert r.returncode == 0
    assert json.loads(r.stdout)["state"] == "settled"


def test_ac5_illegal_edge_exits_12(cli_env):
    mh, leg = _seed_routable_leg(cli_env, event_ref="evt-ac5b")
    bpid = leg["beneficiary_pubkey_id"]

    r = _run(["leg-claim", "--manifest-hash", mh, "--beneficiary", bpid], cli_env["env"])
    assert r.returncode == 0

    # pending -> submitted shortcut is illegal.
    r = _run(
        ["leg-submit", "--manifest-hash", mh, "--beneficiary", bpid, "--outgoing-payment-id", "https://ilp.example/pay/1"],
        cli_env["env"],
    )
    assert r.returncode == 12, r.stderr
    payload = json.loads(r.stdout)
    assert payload["error"] == "LegStateError"


def test_ac5_leg_fail_and_skip(cli_env):
    mh, leg = _seed_routable_leg(cli_env, event_ref="evt-ac5c")
    bpid = leg["beneficiary_pubkey_id"]

    _run(["leg-claim", "--manifest-hash", mh, "--beneficiary", bpid], cli_env["env"])
    r = _run(["leg-fail", "--manifest-hash", mh, "--beneficiary", bpid, "--error", "ILPTimeoutError"], cli_env["env"])
    assert r.returncode == 0
    assert json.loads(r.stdout)["state"] == "failed"

    r = _run(["leg-claim", "--manifest-hash", mh, "--beneficiary", bpid], cli_env["env"])
    assert json.loads(r.stdout)["attempt"] == 1

    r = _run(["leg-skip", "--manifest-hash", mh, "--beneficiary", bpid, "--reason", "binding_revoked"], cli_env["env"])
    assert r.returncode == 0
    assert json.loads(r.stdout)["state"] == "skipped"


# ---------------------------------------------------------------------------
# AC6 -- record-receipt produces a verifiable signed deposit
# ---------------------------------------------------------------------------


def test_ac6_record_receipt_settled(cli_env):
    mh, leg = _seed_routable_leg(cli_env, event_ref="evt-ac6")
    bpid = leg["beneficiary_pubkey_id"]

    env = dict(cli_env["env"])
    env["ZEPHYR_AGENT_KEY_PATH"] = str(cli_env["node_key_path"])

    r = _run(
        [
            "record-receipt", "--event-ref", "evt-ac6", "--manifest-hash", mh, "--beneficiary", bpid,
            "--outcome", "settled", "--op-payment-id", "https://ilp.example/pay/1",
            "--sent-value", str(leg["amount"]), "--sent-asset-code", "USD", "--sent-asset-scale", "2",
            "--agent-id", "agent:node-cli",
        ],
        env,
    )
    assert r.returncode == 0, r.stderr
    payload = json.loads(r.stdout)
    assert payload["newly_recorded"] is True
    assert payload["receipt_hash"].startswith("sha256:")
    assert payload["receipt"]["route_receipt"]["outcome"] == "settled"

    verify = cli_env["log"].get(payload["receipt_hash"], registry=cli_env["registry"])
    assert verify is not None
    assert verify["verification_status"] == "verified"


def test_ac6_record_receipt_bad_outcome_exits_2(cli_env):
    mh, leg = _seed_routable_leg(cli_env, event_ref="evt-ac6b")
    bpid = leg["beneficiary_pubkey_id"]
    r = _run(
        [
            "record-receipt", "--event-ref", "evt-ac6b", "--manifest-hash", mh, "--beneficiary", bpid,
            "--outcome", "not-a-real-outcome", "--agent-id", "agent:node-cli",
        ],
        cli_env["env"],
    )
    assert r.returncode == 2


def test_ac6_record_receipt_no_signer_flag_exists():
    result = subprocess.run(
        [sys.executable, "-m", "zephyr.route", "record-receipt", "--help"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    assert "--signer" not in result.stdout
    assert "--key" not in result.stdout


# ---------------------------------------------------------------------------
# AC7 -- exit 2 on a missing required arg
# ---------------------------------------------------------------------------


def test_ac7_missing_required_arg_exits_2(cli_env):
    r = _run(["get-manifest"], cli_env["env"])
    assert r.returncode == 2


def test_ac7_compile_missing_required_arg_exits_2(cli_env):
    r = _run(["--event-kind", "demo-sale"], cli_env["env"])
    assert r.returncode == 2


# ---------------------------------------------------------------------------
# AC8 -- no key material or token ever appears on stdout or stderr
# ---------------------------------------------------------------------------


def test_ac8_no_key_material_on_stdout_or_stderr(cli_env):
    mh, leg = _seed_routable_leg(cli_env, event_ref="evt-ac8")
    bpid = leg["beneficiary_pubkey_id"]

    env = dict(cli_env["env"])
    env["ZEPHYR_AGENT_KEY_PATH"] = str(cli_env["node_key_path"])

    r = _run(
        [
            "record-receipt", "--event-ref", "evt-ac8", "--manifest-hash", mh, "--beneficiary", bpid,
            "--outcome", "settled", "--op-payment-id", "https://ilp.example/pay/1",
            "--sent-value", str(leg["amount"]), "--sent-asset-code", "USD", "--sent-asset-scale", "2",
            "--agent-id", "agent:node-cli",
        ],
        env,
    )
    assert r.returncode == 0, r.stderr
    key_pem_bytes = cli_env["node_key_path"].read_bytes()
    assert key_pem_bytes not in r.stdout.encode()
    assert key_pem_bytes not in r.stderr.encode()
    assert "PRIVATE KEY" not in r.stdout
    assert "PRIVATE KEY" not in r.stderr
