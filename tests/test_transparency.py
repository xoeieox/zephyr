"""Acceptance tests for zephyr/transparency.py (rail
zephyr-witnessed-checkpoint-log-v0, D2/D3).

All identities SYNTHETIC. No writes outside tmp_path — every fixture points
ZEPHYR_ATTRIBUTION_DB / ZEPHYR_TRANSPARENCY_DB / ZEPHYR_KEYS_DIR /
ZEPHYR_AGENT_KEY_PATH at a tmp_path location, mirroring the AttributionLog /
PubkeyRegistry / AgentSigner tmp_path pattern used across this repo
(test_attribution_signed.py, test_route_cli.py). Checkpoint issuance never
mutates `deposits` — every test that builds a tree does so by reading an
AttributionLog that was populated with plain record() calls first.

Coverage map (numbers match the spec's Tests section):

  1  -- empty log, single-leaf, two-leaf root values match the RFC 6962
        formula directly (SHA-256 domain-separated leaf/node hashing) —
        not a hand-copied "known vector" hex string, but the literal
        normative construction, re-derived independently of the module
        under test using bare hashlib calls.
  2  -- inclusion proof verifies for every leaf across tree sizes 1..64,
        including non-power-of-two sizes.
  3  -- consistency proof verifies for every (old, new) pair in 1..32; a
        deleted deposit and a reordered pair each make it fail.
  4  -- a tampered deposit (different manifest_hash content) breaks
        inclusion against a checkpoint issued after the tamper.
  6  -- proof-index arithmetic rejects tree_size above 2^32.
  7  -- a hash of 63, 65, or uppercase hex characters is rejected before
        decode.
  8  -- absent `witnesses` -> diverged; empty `witnesses` ->
        consistent-unwitnessed.
  9  -- a checkpoint with a lower tree_size than the prior one is refused
        at issue.
  10 -- CLI exit codes: diverged=20, unanchored=21, never conflated.
  11 -- D4 (1F916 dossier conformance oracle) is explicitly SKIPPED — no
        real captured dossier exists in this repo (verified: no `1f916` or
        `dossier` string anywhere in the tree). Per the spec's amendment,
        a synthetic self-generated dossier must never be used as a stand-in
        oracle, so D4 is deferred rather than faked.

(Test 5 — the seq-migration idempotence acceptance criteria — lives in
test_attribution_seq_migration.py, since it is a D1 property of
zephyr/attribution.py, not of this module.)
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from zephyr.attribution import AttributionLog
from zephyr.registry import PubkeyRegistry
from zephyr.signing import AgentSigner
from zephyr.transparency import (
    CheckpointStore,
    consistency_proof,
    inclusion_proof,
    issue_checkpoint,
    leaf_hash,
    merkle_tree_hash,
    node_hash,
    verify_consistency,
    verify_inclusion,
    witness_countersignature_payload,
    _consistency_proof_hashes,
    _verify_checkpoint_envelope,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_log(tmp_path):
    return AttributionLog(tmp_path / "attr.db")


@pytest.fixture()
def tmp_signer(tmp_path):
    return AgentSigner(tmp_path / "agent-keys" / "node.key")


@pytest.fixture()
def tmp_registry(tmp_path):
    return PubkeyRegistry(tmp_path / "keys")


@pytest.fixture()
def tmp_store(tmp_path):
    return CheckpointStore(tmp_path / "transparency.db")


def _seed_deposits(log, n, prefix="leaf"):
    """Record n synthetic unsigned deposits (observe mode) and return their
    manifest_hash strings in insertion (== seq) order. manifest_hash is
    derived from (prefix, i) so distinct calls (e.g. growing a log across
    two seed batches) never collide under dedup."""
    hashes = []
    for i in range(n):
        mh = "sha256:" + hashlib.sha256(f"{prefix}-{i}".encode()).hexdigest()
        log.record(
            {
                "manifest_hash": mh,
                "agent_id": f"agent:synthetic-{prefix}-{i}",
                "tool": "test",
                "schema_version": "v0.1",
            },
            store_kind="content",
        )
        hashes.append(mh)
    return hashes


# ---------------------------------------------------------------------------
# Test 1 -- RFC 6962 root formula, n=0, 1, 2
# ---------------------------------------------------------------------------


def test_1_empty_tree_root_is_sha256_of_empty_string():
    assert merkle_tree_hash([]) == hashlib.sha256(b"").digest()


def test_1_single_leaf_root_is_domain_separated_leaf_hash():
    data = b"hello-leaf"
    expected = hashlib.sha256(b"\x00" + data).digest()
    assert leaf_hash(data) == expected
    assert merkle_tree_hash([leaf_hash(data)]) == expected


def test_1_two_leaf_root_matches_rfc6962_node_formula():
    d0, d1 = b"leaf-zero", b"leaf-one"
    h0, h1 = leaf_hash(d0), leaf_hash(d1)
    # Independently re-derive via bare hashlib, not by calling node_hash().
    expected = hashlib.sha256(b"\x01" + h0 + h1).digest()
    assert merkle_tree_hash([h0, h1]) == expected
    assert node_hash(h0, h1) == expected


# ---------------------------------------------------------------------------
# Test 2 -- inclusion proof verifies for every leaf, tree sizes 1..64
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("n", list(range(1, 65)))
def test_2_inclusion_proof_every_leaf_every_size(tmp_log, n):
    hashes = _seed_deposits(tmp_log, n)
    root_hex = merkle_tree_hash(
        [leaf_hash(mh.encode("utf-8")) for mh in hashes]
    ).hex()
    for m in range(n):
        leaf_index, tree_size, audit_path = inclusion_proof(hashes[m], recorder=tmp_log)
        assert leaf_index == m
        assert tree_size == n
        assert verify_inclusion(hashes[m], leaf_index, tree_size, audit_path, root_hex)


def test_2_inclusion_proof_unknown_manifest_hash_raises(tmp_log):
    _seed_deposits(tmp_log, 3)
    with pytest.raises(KeyError):
        inclusion_proof("sha256:" + "f" * 64, recorder=tmp_log)


def test_2_inclusion_proof_wrong_leaf_data_fails(tmp_log):
    hashes = _seed_deposits(tmp_log, 5)
    root_hex = merkle_tree_hash(
        [leaf_hash(mh.encode("utf-8")) for mh in hashes]
    ).hex()
    leaf_index, tree_size, audit_path = inclusion_proof(hashes[2], recorder=tmp_log)
    assert verify_inclusion(hashes[3], leaf_index, tree_size, audit_path, root_hex) is False


# ---------------------------------------------------------------------------
# Test 3 -- consistency proof for every (old, new) in 1..32; deletion and
# reordering each break it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("new_n", list(range(1, 33)))
def test_3_consistency_proof_every_pair(tmp_log, new_n):
    hashes = _seed_deposits(tmp_log, new_n)
    all_leaf_hashes = [leaf_hash(mh.encode("utf-8")) for mh in hashes]
    new_root = merkle_tree_hash(all_leaf_hashes).hex()
    for old_m in range(1, new_n + 1):
        old_root = merkle_tree_hash(all_leaf_hashes[:old_m]).hex()
        proof = consistency_proof(old_m, new_n, recorder=tmp_log)
        assert verify_consistency(old_m, new_n, proof, old_root, new_root)


def test_3_deleted_deposit_breaks_consistency():
    n = 10
    hashes = [leaf_hash(f"sha256:{i:064x}".encode()) for i in range(n)]
    old_m = 6
    old_root = merkle_tree_hash(hashes[:old_m]).hex()
    proof = [h.hex() for h in _consistency_proof_hashes(old_m, hashes)]

    # Simulate a deletion: one leaf from within the old prefix is gone, and
    # everything after it shifts — this changes every subtree hash from
    # that point on, including the new root.
    tampered = hashes[: old_m - 2] + hashes[old_m - 1 :]
    tampered_root = merkle_tree_hash(tampered).hex()

    assert not verify_consistency(old_m, n - 1, proof, old_root, tampered_root)


def test_3_reordered_pair_breaks_consistency():
    n = 10
    hashes = [leaf_hash(f"sha256:{i:064x}".encode()) for i in range(n)]
    old_m = 6
    old_root = merkle_tree_hash(hashes[:old_m]).hex()
    proof = [h.hex() for h in _consistency_proof_hashes(old_m, hashes)]

    reordered = list(hashes)
    reordered[1], reordered[3] = reordered[3], reordered[1]  # both within the old prefix
    reordered_root = merkle_tree_hash(reordered).hex()

    assert not verify_consistency(old_m, n, proof, old_root, reordered_root)


def test_3_consistency_proof_new_size_exceeds_current_tree_raises(tmp_log):
    _seed_deposits(tmp_log, 3)
    with pytest.raises(ValueError):
        consistency_proof(1, 10, recorder=tmp_log)


# ---------------------------------------------------------------------------
# Test 4 -- a tampered deposit breaks inclusion against a post-tamper
# checkpoint (manifest_hash is a content hash: different content -> a
# different leaf identity, so tampering a row's content and re-recording it
# does not silently keep the same leaf position)
# ---------------------------------------------------------------------------


def test_4_tampered_row_changes_manifest_hash_and_breaks_inclusion(tmp_log, tmp_signer, tmp_registry, tmp_path):
    from archetypes_core.provenance import SCHEMA_VERSION_V01, to_lapis_return

    def _deposit(payload, i):
        ltr = to_lapis_return(
            payload, agent_id=f"agent:synthetic-{i}", tool="test", summary="s",
            schema_version=SCHEMA_VERSION_V01, timestamp=f"2026-08-14T00:00:{i:02d}+00:00",
        )
        mh = ltr.provenance.manifest_hash
        prov = ltr.provenance.to_dict()
        tmp_log.record(prov, store_kind="content", registry=tmp_registry)
        return mh

    original_hashes = [_deposit({"work": f"payload-{i}"}, i) for i in range(3)]
    root_v1 = merkle_tree_hash(
        [leaf_hash(mh.encode("utf-8")) for _, mh in tmp_log.leaves_by_seq()]
    ).hex()
    leaf_index, tree_size, audit_path = inclusion_proof(original_hashes[1], recorder=tmp_log)
    assert verify_inclusion(original_hashes[1], leaf_index, tree_size, audit_path, root_v1)

    # Attacker with DB write access replaces row 1's content in place —
    # tampered payload means a DIFFERENT canonical manifest_hash, so this
    # is necessarily a delete-and-reinsert-under-a-new-identity, changing
    # what leaf occupies that position.
    tampered_mh = _deposit({"work": "payload-1-TAMPERED"}, 1)
    tmp_log._conn.execute(
        "DELETE FROM deposits WHERE manifest_hash = ?", (original_hashes[1],)
    )
    tmp_log._conn.commit()
    assert tampered_mh != original_hashes[1]

    new_leaves = [mh for _, mh in tmp_log.leaves_by_seq()]
    root_v2 = merkle_tree_hash([leaf_hash(mh.encode("utf-8")) for mh in new_leaves]).hex()

    assert root_v2 != root_v1
    # The original inclusion proof (captured against root_v1) no longer
    # verifies against the post-tamper root — the tamper is detected.
    assert verify_inclusion(original_hashes[1], leaf_index, tree_size, audit_path, root_v2) is False
    # And the original manifest_hash simply no longer exists as a leaf at all.
    with pytest.raises(KeyError):
        inclusion_proof(original_hashes[1], recorder=tmp_log)


# ---------------------------------------------------------------------------
# Test 6 -- tree_size above 2^32 rejected without shift-based overflow
# ---------------------------------------------------------------------------


def test_6_tree_size_above_2_32_rejected():
    zero_root = hashlib.sha256(b"").hexdigest()
    with pytest.raises(ValueError):
        verify_inclusion("sha256:x", 0, 2**32 + 1, [], zero_root)
    with pytest.raises(ValueError):
        verify_consistency(0, 2**32 + 1, [], zero_root, zero_root)


def test_6_leaf_index_out_of_range_rejected():
    zero_root = hashlib.sha256(b"").hexdigest()
    with pytest.raises(ValueError):
        verify_inclusion("sha256:x", 5, 5, [], zero_root)  # index == tree_size
    with pytest.raises(ValueError):
        verify_inclusion("sha256:x", -1, 5, [], zero_root)
    with pytest.raises(ValueError):
        verify_inclusion("sha256:x", 1.5, 5, [], zero_root)  # non-integer


# ---------------------------------------------------------------------------
# Test 7 -- malformed hash rejected before decode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_hash",
    [
        "a" * 63,
        "a" * 65,
        "A" * 64,  # uppercase
        "g" * 64,  # non-hex char
    ],
)
def test_7_malformed_root_hash_rejected(bad_hash):
    with pytest.raises(ValueError):
        verify_inclusion("sha256:x", 0, 1, [], bad_hash)


@pytest.mark.parametrize(
    "bad_hash",
    [
        "a" * 63,
        "a" * 65,
        "A" * 64,
        "g" * 64,
    ],
)
def test_7_malformed_audit_path_entry_rejected(bad_hash):
    good_root = hashlib.sha256(b"").hexdigest()
    with pytest.raises(ValueError):
        verify_inclusion("sha256:x", 0, 2, [bad_hash], good_root)


def test_7_witness_payload_also_validates_root_hex():
    with pytest.raises(ValueError):
        witness_countersignature_payload("origin", "log", 3, "not-a-hash")


# ---------------------------------------------------------------------------
# Test 8 -- absent witnesses -> diverged; empty witnesses ->
# consistent-unwitnessed
# ---------------------------------------------------------------------------


def _issue_test_checkpoint(tmp_log, tmp_store, tmp_signer, n=4):
    _seed_deposits(tmp_log, n)
    return issue_checkpoint(recorder=tmp_log, store=tmp_store, signer=tmp_signer)


def test_8_absent_witnesses_key_is_diverged(tmp_log, tmp_store, tmp_signer):
    cp = _issue_test_checkpoint(tmp_log, tmp_store, tmp_signer)
    envelope = cp.to_envelope()
    del envelope["witnesses"]
    result = _verify_checkpoint_envelope(envelope, anchor_pubkey_hex=cp.public_key_hex)
    assert result["verdict"] == "diverged"


def test_8_empty_witnesses_array_is_consistent_unwitnessed(tmp_log, tmp_store, tmp_signer):
    cp = _issue_test_checkpoint(tmp_log, tmp_store, tmp_signer)
    envelope = cp.to_envelope()
    assert envelope["witnesses"] == []
    result = _verify_checkpoint_envelope(envelope, anchor_pubkey_hex=cp.public_key_hex)
    assert result["verdict"] == "consistent-unwitnessed"


def test_8_successful_verify_carries_historical_ordering_honesty_note(tmp_log, tmp_store, tmp_signer):
    """D1's historical-ordering caveat (pre-migration order is a
    reconstruction, not a record) must surface in the D3 verifier output,
    not just the module docstring — per the spec's amendment."""
    cp = _issue_test_checkpoint(tmp_log, tmp_store, tmp_signer)
    envelope = cp.to_envelope()
    result = _verify_checkpoint_envelope(envelope, anchor_pubkey_hex=cp.public_key_hex)
    assert "history_note" in result
    assert "reconstruction" in result["history_note"]


def test_8_non_list_witnesses_is_diverged(tmp_log, tmp_store, tmp_signer):
    cp = _issue_test_checkpoint(tmp_log, tmp_store, tmp_signer)
    envelope = cp.to_envelope()
    envelope["witnesses"] = "not-a-list"
    result = _verify_checkpoint_envelope(envelope, anchor_pubkey_hex=cp.public_key_hex)
    assert result["verdict"] == "diverged"


def test_8_no_anchor_no_registry_falls_back_to_embedded_key_unanchored(tmp_log, tmp_store, tmp_signer):
    cp = _issue_test_checkpoint(tmp_log, tmp_store, tmp_signer)
    envelope = cp.to_envelope()
    result = _verify_checkpoint_envelope(envelope)  # no anchor, no registry
    assert result["verdict"] == "unanchored"


def test_8_registry_match_is_anchored_without_explicit_flag(tmp_log, tmp_store, tmp_signer, tmp_registry):
    tmp_registry.register(
        tmp_signer.pubkey_id_str, tmp_signer.public_key_bytes.hex(), "node:test", "node",
        node_binding={"node": "test", "hostname": "test", "tailscale_ip": "0.0.0.0"},
    )
    cp = _issue_test_checkpoint(tmp_log, tmp_store, tmp_signer)
    envelope = cp.to_envelope()
    result = _verify_checkpoint_envelope(envelope, registry=tmp_registry)
    assert result["verdict"] == "consistent-unwitnessed"


def test_8_tampered_signature_is_diverged(tmp_log, tmp_store, tmp_signer):
    cp = _issue_test_checkpoint(tmp_log, tmp_store, tmp_signer)
    envelope = cp.to_envelope()
    envelope["signature"] = "00" * 64
    result = _verify_checkpoint_envelope(envelope, anchor_pubkey_hex=cp.public_key_hex)
    assert result["verdict"] == "diverged"


def test_8_tampered_payload_is_diverged(tmp_log, tmp_store, tmp_signer):
    cp = _issue_test_checkpoint(tmp_log, tmp_store, tmp_signer)
    envelope = cp.to_envelope()
    parts = envelope["payload"].split(":")
    parts[3] = "f" * 64  # tamper the root
    envelope["payload"] = ":".join(parts)
    result = _verify_checkpoint_envelope(envelope, anchor_pubkey_hex=cp.public_key_hex)
    assert result["verdict"] == "diverged"


# ---------------------------------------------------------------------------
# Test 9 -- monotonic tree_size refused at issue
# ---------------------------------------------------------------------------


def test_9_tree_size_regression_refused_at_issue(tmp_log, tmp_store, tmp_signer):
    _seed_deposits(tmp_log, 5)
    cp1 = issue_checkpoint(recorder=tmp_log, store=tmp_store, signer=tmp_signer)
    assert cp1.tree_size == 5

    class _ShrunkRecorder:
        def leaves_by_seq(self):
            return tmp_log.leaves_by_seq()[:2]

    with pytest.raises(ValueError):
        issue_checkpoint(recorder=_ShrunkRecorder(), store=tmp_store, signer=tmp_signer)


def test_9_equal_or_growing_tree_size_is_fine(tmp_log, tmp_store, tmp_signer):
    _seed_deposits(tmp_log, 3)
    cp1 = issue_checkpoint(recorder=tmp_log, store=tmp_store, signer=tmp_signer)
    assert cp1.tree_size == 3

    # Same size again — not a regression, must succeed.
    cp2 = issue_checkpoint(recorder=tmp_log, store=tmp_store, signer=tmp_signer)
    assert cp2.tree_size == 3

    _seed_deposits(tmp_log, 2, prefix="more")
    cp3 = issue_checkpoint(recorder=tmp_log, store=tmp_store, signer=tmp_signer)
    assert cp3.tree_size == 5


# ---------------------------------------------------------------------------
# Test 10 -- CLI exit codes, subprocess-based (mirrors test_route_cli.py)
# ---------------------------------------------------------------------------


@pytest.fixture()
def cli_env(tmp_path):
    attr_db = tmp_path / "attr.db"
    transparency_db = tmp_path / "transparency.db"
    keys_dir = tmp_path / "keys"
    node_key = tmp_path / "agent-keys" / "node.key"

    log = AttributionLog(attr_db)
    for i in range(4):
        mh = f"sha256:{i:064x}"
        log.record(
            {
                "manifest_hash": mh,
                "agent_id": f"agent:synthetic-cli-{i}",
                "tool": "test",
                "schema_version": "v0.1",
            },
            store_kind="content",
        )

    env = dict(os.environ)
    env.update(
        {
            "ZEPHYR_ATTRIBUTION_DB": str(attr_db),
            "ZEPHYR_TRANSPARENCY_DB": str(transparency_db),
            "ZEPHYR_KEYS_DIR": str(keys_dir),
            "ZEPHYR_AGENT_KEY_PATH": str(node_key),
        }
    )
    return {"env": env, "tmp_path": tmp_path, "log": log}


def _run(args, env):
    return subprocess.run(
        [sys.executable, "-m", "zephyr.transparency", *args],
        cwd=str(REPO_ROOT), env=env, capture_output=True, text=True, timeout=30,
    )


def test_10_checkpoint_and_verify_anchored_exits_0(cli_env):
    r = _run(["checkpoint"], cli_env["env"])
    assert r.returncode == 0, r.stderr
    cp = json.loads(r.stdout)
    cp_path = cli_env["tmp_path"] / "cp.json"
    cp_path.write_text(json.dumps(cp))

    r2 = _run(
        ["verify", "--checkpoint", str(cp_path), "--anchor-pubkey-hex", cp["public_key_hex"]],
        cli_env["env"],
    )
    assert r2.returncode == 0, r2.stderr
    assert json.loads(r2.stdout)["verdict"] == "consistent-unwitnessed"


def test_10_verify_no_anchor_exits_21_unanchored(cli_env):
    r = _run(["checkpoint"], cli_env["env"])
    cp = json.loads(r.stdout)
    cp_path = cli_env["tmp_path"] / "cp.json"
    cp_path.write_text(json.dumps(cp))

    r2 = _run(["verify", "--checkpoint", str(cp_path)], cli_env["env"])
    assert r2.returncode == 21, r2.stderr
    assert json.loads(r2.stdout)["verdict"] == "unanchored"


def test_10_verify_tampered_checkpoint_exits_20_diverged(cli_env):
    r = _run(["checkpoint"], cli_env["env"])
    cp = json.loads(r.stdout)
    cp["signature"] = "00" * 64
    cp_path = cli_env["tmp_path"] / "bad_cp.json"
    cp_path.write_text(json.dumps(cp))

    r2 = _run(
        ["verify", "--checkpoint", str(cp_path), "--anchor-pubkey-hex", cp["public_key_hex"]],
        cli_env["env"],
    )
    assert r2.returncode == 20, r2.stderr
    assert json.loads(r2.stdout)["verdict"] == "diverged"


def test_10_verify_missing_witnesses_exits_20_not_21(cli_env):
    r = _run(["checkpoint"], cli_env["env"])
    cp = json.loads(r.stdout)
    del cp["witnesses"]
    cp_path = cli_env["tmp_path"] / "no_witnesses_cp.json"
    cp_path.write_text(json.dumps(cp))

    r2 = _run(
        ["verify", "--checkpoint", str(cp_path), "--anchor-pubkey-hex", cp["public_key_hex"]],
        cli_env["env"],
    )
    # Confirms diverged (20) and unanchored (21) are never conflated: a
    # malformed envelope is 20 even when an anchor key IS supplied.
    assert r2.returncode == 20, r2.stderr


def test_10_inclusion_and_verify_round_trip(cli_env):
    r = _run(["checkpoint"], cli_env["env"])
    cp = json.loads(r.stdout)
    cp_path = cli_env["tmp_path"] / "cp.json"
    cp_path.write_text(json.dumps(cp))

    mh = f"sha256:{0:064x}"
    r2 = _run(["inclusion", "--manifest-hash", mh], cli_env["env"])
    assert r2.returncode == 0, r2.stderr
    incl = json.loads(r2.stdout)
    incl_path = cli_env["tmp_path"] / "incl.json"
    incl_path.write_text(json.dumps(incl))

    r3 = _run(
        [
            "verify", "--checkpoint", str(cp_path),
            "--anchor-pubkey-hex", cp["public_key_hex"],
            "--inclusion-proof", str(incl_path),
        ],
        cli_env["env"],
    )
    assert r3.returncode == 0, r3.stderr
    payload = json.loads(r3.stdout)
    assert payload["inclusion_verified"] is True


def test_10_consistency_and_verify_round_trip(cli_env):
    r1 = _run(["checkpoint"], cli_env["env"])
    old_cp = json.loads(r1.stdout)
    old_cp_path = cli_env["tmp_path"] / "old_cp.json"
    old_cp_path.write_text(json.dumps(old_cp))

    # Grow the log, then issue a new checkpoint.
    for i in range(4, 6):
        cli_env["log"].record(
            {
                "manifest_hash": f"sha256:{i:064x}",
                "agent_id": f"agent:synthetic-cli-{i}",
                "tool": "test",
                "schema_version": "v0.1",
            },
            store_kind="content",
        )
    r2 = _run(["checkpoint"], cli_env["env"])
    new_cp = json.loads(r2.stdout)
    new_cp_path = cli_env["tmp_path"] / "new_cp.json"
    new_cp_path.write_text(json.dumps(new_cp))

    # tree_size isn't a top-level envelope field — parse it from payload.
    old_size = int(old_cp["payload"].split(":")[2])
    new_size = int(new_cp["payload"].split(":")[2])
    r3 = _run(["consistency", "--old-size", str(old_size), "--new-size", str(new_size)], cli_env["env"])
    assert r3.returncode == 0, r3.stderr
    cons = json.loads(r3.stdout)
    cons_path = cli_env["tmp_path"] / "cons.json"
    cons_path.write_text(json.dumps(cons))

    r4 = _run(
        [
            "verify", "--checkpoint", str(new_cp_path),
            "--anchor-pubkey-hex", new_cp["public_key_hex"],
            "--consistency-proof", str(cons_path),
            "--consistency-old-checkpoint", str(old_cp_path),
        ],
        cli_env["env"],
    )
    assert r4.returncode == 0, r4.stderr
    assert json.loads(r4.stdout)["consistency_verified"] is True


def test_10_usage_error_exits_2(cli_env):
    r = _run(["verify"], cli_env["env"])
    assert r.returncode == 2


def test_10_unknown_subcommand_exits_2(cli_env):
    r = _run(["bogus-subcommand"], cli_env["env"])
    assert r.returncode == 2


# ---------------------------------------------------------------------------
# Test 11 -- D4 explicitly skipped: no real 1F916 dossier fixture exists
# ---------------------------------------------------------------------------


@pytest.mark.skip(
    reason=(
        "D4 (1F916 dossier conformance oracle) is non-blocking per spec and is "
        "deferred: no real captured dossier exists in this repo, and a "
        "self-generated synthetic dossier must never be used as a stand-in "
        "oracle (verifying our own output with our own verifier proves "
        "nothing). D1-D3 land complete with D4 absent."
    )
)
def test_11_d4_dossier_verification_deferred():
    pass


# ---------------------------------------------------------------------------
# Witness payload shape — defined now, never emitted by this unit
# ---------------------------------------------------------------------------


def test_witness_payload_shape_is_defined_and_distinct_from_checkpoint_payload():
    payload = witness_countersignature_payload(
        "https://witness.example", "zephyr.attribution", 5, "a" * 64
    )
    assert payload == f"zephyr.witness.v1:https://witness.example:zephyr.attribution:5:{'a' * 64}"
    assert payload.split(":")[0] != "zephyr.checkpoint.v1"


def test_checkpoint_payload_never_uses_1f916_namespace(tmp_log, tmp_store, tmp_signer):
    cp = _issue_test_checkpoint(tmp_log, tmp_store, tmp_signer)
    assert cp.payload.startswith("zephyr.checkpoint.v1:")
    assert "1f916" not in cp.payload
