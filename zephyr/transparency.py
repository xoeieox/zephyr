"""zephyr/transparency.py — RFC 6962 Merkle transparency log over deposits.

Rail ``zephyr-witnessed-checkpoint-log-v0``, D1-D3 (D4 deferred — no real
1F916 dossier fixture exists in this repo; see the module-level Test 11
skip in tests/test_transparency.py). Named consumers: ``verify_row()``
(zephyr/attribution.py:505), which is intended to gain a log-inclusion
verdict on top of the primitives this module exports — that wiring is not
part of D1-D3 and is left for the unit that does it; and the new
``python -m zephyr.transparency verify`` CLI, usable today by any relying
party — including a non-Lapis one — that must check a Zephyr deposit
without trusting the BRIX operator.

Why: the deposit log is append-only by convention and schema, not by
construction. Signed attribution (zephyr.signing / zephyr.registry) proves
WHO said something; it does not prove that the SET of things said has not
been edited. A holder of write access to attribution.db can delete a
deposit and every surviving row still verifies perfectly. This module closes
that gap for one specific threat: silent tampering by the party who already
holds write access to the log.

Pure-CPU: hashlib + the existing Ed25519 signer (zephyr.signing). No new
dependencies, no network calls at build or verify time.

--------------------------------------------------------------------------
Scope — read this before trusting a verdict
--------------------------------------------------------------------------
This unit reaches, in the draft's four-valued verdict vocabulary,
**consistent-unwitnessed** and no further:

  Buys:      a deletion, edit, or reordering of the deposit log becomes
             detectable by anyone holding a prior checkpoint. Operator
             deniability is removed.
  Does NOT   detection of a registry that shows two different consistent
  buy:       histories to two different parties (equivocation / split-view).
             Only witness diversity bounds that, and witnesses are a
             separate, later unit (a witness needs a host and a publication
             surface outside this registry's control). Nothing here emits
             a ``witnessed`` verdict, ever — its absence is deliberate.

--------------------------------------------------------------------------
RFC 6962 construction
--------------------------------------------------------------------------
Leaf hash:      SHA-256(0x00 || leaf_data)
Internal node:  SHA-256(0x01 || left || right)
The 0x00/0x01 domain-separation prefixes prevent second-preimage attacks
between leaves and internal nodes, and are what makes this tree agree with
every other RFC 6962 implementation (including the draft's reference impl
and any future witness). They are never simplified away.

Leaf data is the deposit's ``manifest_hash`` (UTF-8 bytes of the string,
e.g. ``"sha256:<64hex>"``), ordered by ``deposits.seq`` ascending (D1,
zephyr/attribution.py). manifest_hash is already the canonical signing
target with signature zeroed, so a leaf commits to a deposit's content
without re-canonicalizing anything.

--------------------------------------------------------------------------
Checkpoint envelope
--------------------------------------------------------------------------
Signed payload (versioned, in-band, colon-separated, own namespace — never
``1f916.*``; interoperability lives in the tree construction, which is what
a verifier checks, not in the label):

    zephyr.checkpoint.v1:<log>:<tree_size>:<root_hex>:<created_at_ms>

The JSON envelope wrapping that payload MUST carry a ``witnesses`` array
that is EMPTY, never ABSENT:

    {"payload": "...", "signature": "<hex>", "pubkey_id": "...",
     "public_key_hex": "<hex>", "witnesses": []}

An absent ``witnesses`` key is a malformed artifact -> verifies ``diverged``.
An empty array is a well-formed unwitnessed checkpoint ->
``consistent-unwitnessed``. This is the forward-compatibility distinction
the witness unit needs to exist; see ``_verify_checkpoint_envelope`` and
test_transparency.py's AC8.

A witness countersignature is never embedded in the signed payload string
(signing bytes that contain their own countersignature would be circular).
Its payload shape is defined here, now, for the next unit — NO code in
this unit ever constructs or emits one:

    zephyr.witness.v1:<registry_origin>:<log>:<tree_size>:<root_hex>

The checkpoint is always signed with the NODE identity
(``zephyr.signing.get_signer()``'s default, no caller override) — mirroring
the ``record-receipt`` precedent in zephyr/route.py. Human private keys
never live on BRIX/StarHouse (AGENTS.md); this module never accepts a
``--signer``/``--key`` override for checkpoint issuance.

``tree_size`` is monotonic per ``log``: issuing a checkpoint whose
``tree_size`` is lower than a previously issued one for the same log is
refused at issue time (``issue_checkpoint`` raises ``ValueError``), not
merely flagged at verify time.

--------------------------------------------------------------------------
Verdict vocabulary (closed) and CLI exit codes
--------------------------------------------------------------------------
``consistent-unwitnessed``  -- every check that ran, passed; no witness
                                countersignature was checked (none exist).
``unanchored``               -- every key used in verification came from the
                                artifact itself; proves internal consistency
                                only. A CALLER/CONFIGURATION outcome, never
                                a tamper signal — never log or report it as
                                one.
``diverged``                  -- a proof, signature, or envelope check
                                actually failed: the log contradicts itself.
                                Caller must stop.
``witnessed``                  -- NOT emittable by this unit. Its absence is
                                deliberate, not an oversight.

``python -m zephyr.transparency`` subcommands: ``checkpoint``, ``inclusion``,
``consistency``, ``verify``. Exactly one JSON document on stdout per
invocation. Exit codes (disjoint from zephyr.route's 10/11/12):
    0   verified consistent-unwitnessed
    20  diverged
    21  unanchored
    2   usage error (argparse; exempt from the JSON-envelope rule)
    1   unexpected exception, no JSON envelope

--------------------------------------------------------------------------
Invariants
--------------------------------------------------------------------------
- No LLM calls, no network at verify time. Fully offline.
- Checkpoint issuance never mutates ``deposits`` — reading the log to build
  a tree is a read (see ``AttributionLog.leaves_by_seq``).
- Nothing in this module can delete or rewrite a deposit. A tool that could
  adjust the log to make a checkpoint validate is exactly the capability
  this unit exists to deny.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "DEFAULT_LOG_ID",
    "Checkpoint",
    "CheckpointStore",
    "get_checkpoint_store",
    "issue_checkpoint",
    "leaf_hash",
    "node_hash",
    "merkle_tree_hash",
    "inclusion_proof",
    "consistency_proof",
    "verify_inclusion",
    "verify_consistency",
    "witness_countersignature_payload",
]

DEFAULT_LOG_ID = "zephyr.attribution"

_CHECKPOINT_PREFIX = "zephyr.checkpoint.v1"
_WITNESS_PREFIX = "zephyr.witness.v1"

_MAX_TREE_SIZE = 2**32
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Input validation — adopted from the draft's own hard-won defect list.
# Validate BEFORE decode, never after; no bitwise shifts in index math
# (shift-based index math forges proofs above 2^32); reject non-integer or
# out-of-range leaf_index/tree_size before any tree walk.
# ---------------------------------------------------------------------------


def _validate_hex_hash(value, *, name: str) -> str:
    if not isinstance(value, str) or not _HEX64_RE.match(value):
        raise ValueError(
            f"{name} must be exactly 64 lowercase hex characters, got {value!r}"
        )
    return value


def _validate_int(value, name: str, *, minimum: int = 0, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer, got {value!r}")
    if value < minimum:
        raise ValueError(f"{name} out of range: {value} < {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} out of range: {value} > {maximum}")
    return value


def _validate_tree_size(n) -> int:
    return _validate_int(n, "tree_size", minimum=0, maximum=_MAX_TREE_SIZE)


def _validate_leaf_index(m, tree_size: int) -> int:
    m = _validate_int(m, "leaf_index", minimum=0)
    if m >= tree_size:
        raise ValueError(f"leaf_index out of range: {m} >= tree_size {tree_size}")
    return m


# ---------------------------------------------------------------------------
# RFC 6962 leaf/node hashing and Merkle Tree Hash (MTH)
# ---------------------------------------------------------------------------


def leaf_hash(leaf_data: bytes) -> bytes:
    """RFC 6962 leaf hash: SHA-256(0x00 || leaf_data)."""
    return hashlib.sha256(b"\x00" + leaf_data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 internal-node hash: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_pow2_lt(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2). k < n <= 2k.

    Multiplication only — no bitwise shifts, per the draft's index-arithmetic
    defect (shift-based index math forges proofs above 2^32).
    """
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_tree_hash(leaf_hashes: list[bytes]) -> bytes:
    """RFC 6962 MTH over a list of already leaf-hashed values.

    MTH({}) = SHA-256() (n=0). MTH({d0}) = d0 already carries the leaf-hash
    formula (n=1, base case). For n>1: split at k = largest power of two
    < n; MTH(D[0:n]) = node_hash(MTH(D[0:k]), MTH(D[k:n])).
    """
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hashes[0]
    k = _largest_pow2_lt(n)
    left = merkle_tree_hash(leaf_hashes[:k])
    right = merkle_tree_hash(leaf_hashes[k:])
    return node_hash(left, right)


# ---------------------------------------------------------------------------
# Merkle audit path (RFC 6962 §2.1.1) — generation (needs leaf data) and
# reconstruction (pure — needs only the path + leaf hash + tree shape).
# ---------------------------------------------------------------------------


def _audit_path_hashes(m: int, leaf_hashes: list[bytes]) -> list[bytes]:
    """PATH(m, D[0:n]) for leaf index m in the tree over leaf_hashes."""
    n = len(leaf_hashes)
    if n == 1:
        return []
    k = _largest_pow2_lt(n)
    if m < k:
        return _audit_path_hashes(m, leaf_hashes[:k]) + [merkle_tree_hash(leaf_hashes[k:])]
    return _audit_path_hashes(m - k, leaf_hashes[k:]) + [merkle_tree_hash(leaf_hashes[:k])]


def _reconstruct_root_for_inclusion(
    m: int, n: int, path: list[bytes], leaf_h: bytes
) -> bytes:
    """Recompute MTH(D[0:n]) from an audit path for leaf index m, mirroring
    _audit_path_hashes's exact recursive split — no leaf data required, only
    the claimed leaf hash, so this is safe for a third party with no
    database access."""

    def rec(m: int, n: int, idx: int) -> tuple[bytes, int]:
        if n == 1:
            return leaf_h, idx
        k = _largest_pow2_lt(n)
        if m < k:
            sub_hash, idx = rec(m, k, idx)
            sibling = path[idx]
            return node_hash(sub_hash, sibling), idx + 1
        sub_hash, idx = rec(m - k, n - k, idx)
        sibling = path[idx]
        return node_hash(sibling, sub_hash), idx + 1

    result, idx = rec(m, n, 0)
    if idx != len(path):
        raise ValueError("audit path has extra, unused entries")
    return result


# ---------------------------------------------------------------------------
# Merkle consistency proof (RFC 6962 §2.1.2) — generation and pure
# reconstruction. The `b` flag ("complete") is true only along the pure-left
# recursion spine matching the ORIGINAL m unchanged; it flips to false
# (permanently, for the rest of that recursion branch) the moment the
# right-hand branch (m > k) is taken, because from that point on a subtree
# boundary equal to the tracked size is no longer directly known to the
# verifier as "the old root" and must be committed explicitly.
# ---------------------------------------------------------------------------


def _gen_subproof(m: int, n: int, leaf_hashes: list[bytes], b: bool) -> list[bytes]:
    if m == n:
        if b:
            return []
        return [merkle_tree_hash(leaf_hashes)]
    k = _largest_pow2_lt(n)
    if m <= k:
        return _gen_subproof(m, k, leaf_hashes[:k], b) + [merkle_tree_hash(leaf_hashes[k:])]
    return _gen_subproof(m - k, n - k, leaf_hashes[k:], False) + [merkle_tree_hash(leaf_hashes[:k])]


def _consistency_proof_hashes(m: int, leaf_hashes: list[bytes]) -> list[bytes]:
    """PROOF(m, D[0:n]) where n = len(leaf_hashes), 0 <= m <= n."""
    n = len(leaf_hashes)
    if m == 0 or m == n:
        return []
    return _gen_subproof(m, n, leaf_hashes, True)


def _verify_subproof(
    m: int, n: int, proof: list[bytes], idx: int, b: bool, old_root: bytes
) -> tuple[bytes, bytes, int]:
    """Returns (old_hash, new_hash, next_idx) for this (m, n) subtree,
    mirroring _gen_subproof exactly. old_root is the externally-supplied,
    already-trusted root for the full m-sized (old) tree, substituted
    whenever the b=True base case is hit (mirrors the "m is a power of two"
    proof-generation optimization, where the old root is never re-included
    in the proof because the verifier already has it)."""
    if m == n:
        if b:
            return old_root, old_root, idx
        h = proof[idx]
        return h, h, idx + 1
    k = _largest_pow2_lt(n)
    if m <= k:
        left_old, left_new, idx = _verify_subproof(m, k, proof, idx, b, old_root)
        right_new = proof[idx]
        idx += 1
        return left_old, node_hash(left_new, right_new), idx
    # m > k: mirror _gen_subproof's append order exactly — the recursive
    # (right-subtree) entries were appended FIRST during generation, and
    # THIS level's left-sibling commitment MTH(D[0:k]) was appended LAST,
    # so it must be consumed last here too (consume the recursion's
    # entries before reading this level's own proof entry).
    right_old, right_new, idx = _verify_subproof(m - k, n - k, proof, idx, False, old_root)
    left_hash = proof[idx]
    idx += 1
    return node_hash(left_hash, right_old), node_hash(left_hash, right_new), idx


# ---------------------------------------------------------------------------
# D3 — pure-function proof verifiers (no database access; a third party can
# run these against nothing but the proof, the root, and the public key).
# ---------------------------------------------------------------------------


def verify_inclusion(
    manifest_hash: str,
    leaf_index: int,
    tree_size: int,
    audit_path_hex: list[str],
    root_hex: str,
) -> bool:
    """Verify an RFC 6962 inclusion proof. Pure function, no DB access.

    Raises ValueError for malformed input (bad hash shape, non-integer or
    out-of-range index/size) BEFORE any tree walk. Returns False (never
    raises) for well-formed-but-wrong proof material.
    """
    root_hex = _validate_hex_hash(root_hex, name="root_hex")
    for i, h in enumerate(audit_path_hex):
        _validate_hex_hash(h, name=f"audit_path[{i}]")
    tree_size = _validate_tree_size(tree_size)
    leaf_index = _validate_leaf_index(leaf_index, tree_size)
    if not isinstance(manifest_hash, str) or not manifest_hash:
        raise ValueError(f"manifest_hash must be a non-empty string, got {manifest_hash!r}")

    path = [bytes.fromhex(h) for h in audit_path_hex]
    root = bytes.fromhex(root_hex)
    leaf_h = leaf_hash(manifest_hash.encode("utf-8"))
    try:
        computed = _reconstruct_root_for_inclusion(leaf_index, tree_size, path, leaf_h)
    except IndexError:
        raise ValueError("audit path is too short for the claimed tree_size/leaf_index") from None
    return computed == root


def verify_consistency(
    old_size: int,
    new_size: int,
    proof_hex: list[str],
    old_root_hex: str,
    new_root_hex: str,
) -> bool:
    """Verify an RFC 6962 consistency proof between two tree sizes. Pure
    function, no DB access.

    Raises ValueError for malformed input BEFORE any tree walk. Returns
    False (never raises) for well-formed-but-wrong proof material.
    """
    old_root_hex = _validate_hex_hash(old_root_hex, name="old_root_hex")
    new_root_hex = _validate_hex_hash(new_root_hex, name="new_root_hex")
    for i, h in enumerate(proof_hex):
        _validate_hex_hash(h, name=f"proof[{i}]")
    new_size = _validate_tree_size(new_size)
    old_size = _validate_int(old_size, "old_size", minimum=0, maximum=new_size)

    proof = [bytes.fromhex(h) for h in proof_hex]
    old_root = bytes.fromhex(old_root_hex)
    new_root = bytes.fromhex(new_root_hex)

    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size == 0:
        # Any tree is trivially a consistent extension of the empty tree.
        return not proof

    try:
        recon_old, recon_new, idx = _verify_subproof(
            old_size, new_size, proof, 0, True, old_root
        )
    except IndexError:
        return False
    if idx != len(proof):
        return False
    return recon_old == old_root and recon_new == new_root


# ---------------------------------------------------------------------------
# Witness countersignature payload shape — DEFINED now, EMITTED by no code
# in this unit. See module docstring.
# ---------------------------------------------------------------------------


def witness_countersignature_payload(
    registry_origin: str, log: str, tree_size: int, root_hex: str
) -> str:
    """The payload shape a future witness unit will countersign over a
    checkpoint's tree head. Defined here so the checkpoint envelope's
    reserved ``witnesses`` slot has a documented target shape. NOT called by
    any code in this unit — no witness countersignature is ever produced
    here."""
    tree_size = _validate_tree_size(tree_size)
    root_hex = _validate_hex_hash(root_hex, name="root_hex")
    return f"{_WITNESS_PREFIX}:{registry_origin}:{log}:{tree_size}:{root_hex}"


def _parse_checkpoint_payload(payload: str) -> tuple[str, int, str, int]:
    """Parse + validate a zephyr.checkpoint.v1 payload string. Raises
    ValueError on any malformation (wrong prefix, wrong field count,
    malformed hash/ints) — validated before any hex decode."""
    if not isinstance(payload, str):
        raise ValueError(f"checkpoint payload must be a string, got {payload!r}")
    parts = payload.split(":")
    if len(parts) != 5 or parts[0] != _CHECKPOINT_PREFIX:
        raise ValueError(f"malformed checkpoint payload: {payload!r}")
    _, log_name, tree_size_s, root_hex, created_at_ms_s = parts
    if not log_name:
        raise ValueError(f"malformed checkpoint payload (empty log): {payload!r}")
    if not re.fullmatch(r"[0-9]+", tree_size_s):
        raise ValueError(f"malformed tree_size in checkpoint payload: {tree_size_s!r}")
    tree_size = _validate_tree_size(int(tree_size_s))
    root_hex = _validate_hex_hash(root_hex, name="root_hex")
    if not re.fullmatch(r"[0-9]+", created_at_ms_s):
        raise ValueError(f"malformed created_at_ms in checkpoint payload: {created_at_ms_s!r}")
    created_at_ms = int(created_at_ms_s)
    return log_name, tree_size, root_hex, created_at_ms


# ---------------------------------------------------------------------------
# D2 — Checkpoint dataclass + append-only CheckpointStore
# ---------------------------------------------------------------------------


@dataclass
class Checkpoint:
    """A signed RFC 6962 tree head. The envelope's `witnesses` array is
    empty (never absent) — this unit issues no witness countersignatures."""

    log: str
    tree_size: int
    root_hex: str
    created_at_ms: int
    pubkey_id: str
    signature: str
    public_key_hex: str
    witnesses: list = field(default_factory=list)

    @property
    def payload(self) -> str:
        return f"{_CHECKPOINT_PREFIX}:{self.log}:{self.tree_size}:{self.root_hex}:{self.created_at_ms}"

    def to_envelope(self) -> dict:
        return {
            "payload": self.payload,
            "signature": self.signature,
            "pubkey_id": self.pubkey_id,
            "public_key_hex": self.public_key_hex,
            "witnesses": list(self.witnesses),
        }


DEFAULT_TRANSPARENCY_DB = Path(
    os.environ.get("ZEPHYR_TRANSPARENCY_DB", "/data/zephyr/transparency.db")
)

_CHECKPOINT_SCHEMA = """
CREATE TABLE IF NOT EXISTS checkpoints (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    log             TEXT NOT NULL,
    tree_size       INTEGER NOT NULL,
    root_hex        TEXT NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    payload         TEXT NOT NULL,
    signature       TEXT NOT NULL,
    pubkey_id       TEXT NOT NULL,
    public_key_hex  TEXT,
    witnesses_json  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS checkpoints_log ON checkpoints(log, tree_size);
"""


class CheckpointStore:
    """SQLite-backed append-only history of issued checkpoints.

    Own file (default ``/data/zephyr/transparency.db``, override with
    ``ZEPHYR_TRANSPARENCY_DB``) — separate from attribution.db. Only ever
    appended to by ``issue_checkpoint``; never mutates ``deposits``.
    """

    def __init__(self, db_path: Path | str = DEFAULT_TRANSPARENCY_DB):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_CHECKPOINT_SCHEMA)
        self._conn.commit()

    def latest(self, log: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM checkpoints WHERE log = ? "
                "ORDER BY tree_size DESC, seq DESC LIMIT 1",
                (log,),
            ).fetchone()
        return dict(row) if row is not None else None

    def latest_tree_size(self, log: str) -> int | None:
        latest = self.latest(log)
        return latest["tree_size"] if latest is not None else None

    def append(self, checkpoint: Checkpoint) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO checkpoints "
                "(log, tree_size, root_hex, created_at_ms, payload, signature, "
                " pubkey_id, public_key_hex, witnesses_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    checkpoint.log,
                    checkpoint.tree_size,
                    checkpoint.root_hex,
                    checkpoint.created_at_ms,
                    checkpoint.payload,
                    checkpoint.signature,
                    checkpoint.pubkey_id,
                    checkpoint.public_key_hex,
                    json.dumps(checkpoint.witnesses),
                ),
            )
            self._conn.commit()


_CHECKPOINT_STORE: CheckpointStore | None = None
_CHECKPOINT_STORE_LOCK = threading.Lock()


def get_checkpoint_store() -> CheckpointStore:
    """Return the process-wide CheckpointStore singleton (parallel to
    zephyr.attribution.get_recorder())."""
    global _CHECKPOINT_STORE
    if _CHECKPOINT_STORE is None:
        with _CHECKPOINT_STORE_LOCK:
            if _CHECKPOINT_STORE is None:
                _CHECKPOINT_STORE = CheckpointStore()
    return _CHECKPOINT_STORE


def _reset_checkpoint_store() -> None:
    """For tests — force reload of the checkpoint store on next use."""
    global _CHECKPOINT_STORE
    _CHECKPOINT_STORE = None


def issue_checkpoint(
    *,
    log: str = DEFAULT_LOG_ID,
    recorder=None,
    store: CheckpointStore | None = None,
    signer=None,
) -> Checkpoint:
    """Build the RFC 6962 tree over the deposit log's seq-ordered leaves and
    issue a signed checkpoint.

    Read-only against `deposits` (invariant) — only
    AttributionLog.leaves_by_seq() is called; nothing here writes to
    attribution.db. Signs with the node identity via
    zephyr.signing.get_signer()'s default — no caller override, mirroring
    the record-receipt precedent (human private keys never live on
    BRIX/StarHouse).

    Refuses (ValueError) if tree_size would regress relative to the last
    checkpoint issued for *log* — a checkpoint is monotonic proof of
    append-only growth, never a rollback. Refused at issue time, not merely
    flagged at verify time.
    """
    from zephyr.attribution import get_recorder
    from zephyr.signing import get_signer

    rec = recorder if recorder is not None else get_recorder()
    st = store if store is not None else get_checkpoint_store()
    s = signer if signer is not None else get_signer()

    leaves = rec.leaves_by_seq()
    tree_size = len(leaves)
    leaf_hashes = [leaf_hash(mh.encode("utf-8")) for _, mh in leaves]
    root_hex = merkle_tree_hash(leaf_hashes).hex()

    prior_size = st.latest_tree_size(log)
    if prior_size is not None and tree_size < prior_size:
        raise ValueError(
            f"issue_checkpoint: tree_size regression refused for log={log!r}: "
            f"new tree_size={tree_size} < previously issued tree_size={prior_size}"
        )

    created_at_ms = int(time.time() * 1000)
    cp = Checkpoint(
        log=log,
        tree_size=tree_size,
        root_hex=root_hex,
        created_at_ms=created_at_ms,
        pubkey_id=s.pubkey_id_str,
        signature="",
        public_key_hex=s.public_key_bytes.hex(),
        witnesses=[],
    )
    cp.signature = s.sign(cp.payload)
    st.append(cp)
    return cp


# ---------------------------------------------------------------------------
# D3 — inclusion_proof / consistency_proof (DB-touching; read-only)
# ---------------------------------------------------------------------------


def inclusion_proof(manifest_hash: str, *, recorder=None) -> tuple[int, int, list[str]]:
    """(leaf_index, tree_size, audit_path) for *manifest_hash* against the
    CURRENT full deposit log. audit_path entries are hex-encoded.

    Raises KeyError if manifest_hash has no deposit row.
    """
    from zephyr.attribution import get_recorder

    rec = recorder if recorder is not None else get_recorder()
    leaves = rec.leaves_by_seq()
    index = next((i for i, (_, mh) in enumerate(leaves) if mh == manifest_hash), None)
    if index is None:
        raise KeyError(f"inclusion_proof: manifest_hash={manifest_hash!r} not found in deposit log")

    leaf_hashes = [leaf_hash(mh.encode("utf-8")) for _, mh in leaves]
    path = _audit_path_hashes(index, leaf_hashes)
    return index, len(leaves), [h.hex() for h in path]


def consistency_proof(old_size: int, new_size: int, *, recorder=None) -> list[str]:
    """PROOF(old_size, new_size) — a holder of an old checkpoint of size
    *old_size* can use this to prove the tree at *new_size* is an
    append-only extension of it. Hex-encoded entries.

    Raises ValueError if new_size exceeds the current tree_size.
    """
    from zephyr.attribution import get_recorder

    old_size = _validate_int(old_size, "old_size", minimum=0)
    new_size = _validate_tree_size(new_size)
    if old_size > new_size:
        raise ValueError(f"consistency_proof: old_size={old_size} > new_size={new_size}")

    rec = recorder if recorder is not None else get_recorder()
    leaves = rec.leaves_by_seq()
    if new_size > len(leaves):
        raise ValueError(
            f"consistency_proof: new_size={new_size} exceeds current tree_size={len(leaves)}"
        )

    leaf_hashes = [leaf_hash(mh.encode("utf-8")) for _, mh in leaves[:new_size]]
    path = _consistency_proof_hashes(old_size, leaf_hashes)
    return [h.hex() for h in path]


# ---------------------------------------------------------------------------
# Checkpoint envelope verification — signature + witnesses-key + anchor
# resolution. NOT one of D3's pure proof verifiers (may consult a local
# registry as an anchor source); verify_inclusion/verify_consistency above
# remain pure with no DB access.
# ---------------------------------------------------------------------------


def _verify_checkpoint_envelope(
    envelope: dict, *, anchor_pubkey_hex: str | None = None, registry=None
) -> dict:
    """Verify a checkpoint envelope's shape + signature.

    Returns a dict with at least ``verdict`` in {"diverged", "unanchored",
    "consistent-unwitnessed"}. On success also carries ``log``,
    ``tree_size``, ``root_hex``, ``created_at_ms``, ``witness_count``.

    Anchor resolution order: --anchor-pubkey-hex (external, always anchored)
    -> local PubkeyRegistry lookup by pubkey_id (anchored — external to the
    artifact) -> the envelope's own embedded public_key_hex (unanchored —
    "every key used in verification came from the artifact itself").
    """
    from zephyr.signing import pubkey_id as compute_pubkey_id
    from zephyr.signing import verify_manifest

    if not isinstance(envelope, dict):
        return {"verdict": "diverged", "detail": "checkpoint envelope must be a JSON object"}

    if "witnesses" not in envelope:
        return {
            "verdict": "diverged",
            "detail": "envelope missing required 'witnesses' key — an absent "
            "witnesses key is a malformed artifact, distinct from a "
            "well-formed empty array",
        }
    witnesses = envelope["witnesses"]
    if not isinstance(witnesses, list):
        return {"verdict": "diverged", "detail": "'witnesses' must be an array"}

    payload = envelope.get("payload")
    signature = envelope.get("signature")
    pubkey_id_claimed = envelope.get("pubkey_id")
    if not payload or not signature or not pubkey_id_claimed:
        return {"verdict": "diverged", "detail": "envelope missing payload/signature/pubkey_id"}

    try:
        log_name, tree_size, root_hex, created_at_ms = _parse_checkpoint_payload(payload)
    except ValueError as exc:
        return {"verdict": "diverged", "detail": f"malformed checkpoint payload: {exc}"}

    anchored = False
    pub_bytes = None

    if anchor_pubkey_hex:
        try:
            pub_bytes = bytes.fromhex(anchor_pubkey_hex)
        except ValueError:
            return {"verdict": "diverged", "detail": "malformed --anchor-pubkey-hex"}
        if compute_pubkey_id(pub_bytes) != pubkey_id_claimed:
            return {
                "verdict": "diverged",
                "detail": "anchor key does not match envelope pubkey_id",
            }
        anchored = True
    else:
        entry = None
        if registry is not None:
            try:
                entry = registry.lookup(pubkey_id_claimed)
            except Exception:
                entry = None
        if entry is not None:
            pub_bytes = bytes.fromhex(entry["public_key_hex"])
            anchored = True
        else:
            embedded = envelope.get("public_key_hex")
            if not embedded:
                return {
                    "verdict": "diverged",
                    "detail": "no verification key available: no anchor supplied, no "
                    "registry match, and the envelope carries no embedded key",
                }
            try:
                pub_bytes = bytes.fromhex(embedded)
            except ValueError:
                return {"verdict": "diverged", "detail": "malformed embedded public_key_hex"}
            if compute_pubkey_id(pub_bytes) != pubkey_id_claimed:
                return {
                    "verdict": "diverged",
                    "detail": "embedded public_key_hex does not match envelope pubkey_id",
                }
            anchored = False

    if not verify_manifest(payload, signature, pub_bytes):
        return {"verdict": "diverged", "detail": "checkpoint signature does not verify"}

    return {
        "verdict": "consistent-unwitnessed" if anchored else "unanchored",
        "log": log_name,
        "tree_size": tree_size,
        "root_hex": root_hex,
        "created_at_ms": created_at_ms,
        "witness_count": len(witnesses),
        "history_note": _HISTORY_HONESTY_NOTE,
    }


# Historical-ordering honesty (D1 amendment) — surfaced in every successful
# verify result, not just the module docstring, so a relying party never
# reads a verdict as attesting more than it does. The pre-migration copy
# order (zephyr/attribution.py's ORDER BY recorded_at, manifest_hash) is a
# reconstruction, not a record: recorded_at is caller-supplied and was
# never trustworthy. This tree attests the log from the D1 migration
# checkpoint forward; it cannot attest that pre-migration history was
# itself un-reordered.
_HISTORY_HONESTY_NOTE = (
    "seq is store-assigned and tamper-evident from the D1 migration "
    "checkpoint forward. Ordering of any deposit that existed before that "
    "migration ran is a best-effort reconstruction (ORDER BY recorded_at, "
    "manifest_hash), not an attested record — this tree cannot prove "
    "pre-migration history was itself un-reordered."
)


# ---------------------------------------------------------------------------
# python -m zephyr.transparency — checkpoint / inclusion / consistency / verify
# ---------------------------------------------------------------------------


def _cmd_checkpoint(args) -> None:
    cp = issue_checkpoint(log=args.log)
    print(json.dumps(cp.to_envelope()))


def _cmd_inclusion(args) -> None:
    leaf_index, tree_size, audit_path = inclusion_proof(args.manifest_hash)
    print(
        json.dumps(
            {
                "manifest_hash": args.manifest_hash,
                "leaf_index": leaf_index,
                "tree_size": tree_size,
                "audit_path": audit_path,
            }
        )
    )


def _cmd_consistency(args) -> None:
    proof = consistency_proof(args.old_size, args.new_size)
    print(json.dumps({"old_size": args.old_size, "new_size": args.new_size, "proof": proof}))


def _cmd_verify(args) -> None:
    envelope = json.loads(Path(args.checkpoint).read_text())

    registry = None
    try:
        from zephyr.registry import get_registry

        registry = get_registry()
    except Exception:
        registry = None

    result = _verify_checkpoint_envelope(
        envelope, anchor_pubkey_hex=args.anchor_pubkey_hex, registry=registry
    )
    verdict = result["verdict"]
    extra: dict = {}

    if verdict != "diverged" and args.inclusion_proof:
        incl = json.loads(Path(args.inclusion_proof).read_text())
        try:
            ok = verify_inclusion(
                incl["manifest_hash"],
                incl["leaf_index"],
                incl["tree_size"],
                incl["audit_path"],
                result["root_hex"],
            )
        except (ValueError, KeyError) as exc:
            ok = False
            extra["inclusion_error"] = str(exc)
        if not ok or incl.get("tree_size") != result["tree_size"]:
            verdict = "diverged"
            extra.setdefault("inclusion_error", "inclusion proof failed or tree_size mismatch")
        extra["inclusion_verified"] = ok

    if verdict != "diverged" and args.consistency_proof and args.consistency_old_checkpoint:
        old_envelope = json.loads(Path(args.consistency_old_checkpoint).read_text())
        old_result = _verify_checkpoint_envelope(
            old_envelope, anchor_pubkey_hex=args.anchor_pubkey_hex, registry=registry
        )
        if old_result["verdict"] == "diverged":
            verdict = "diverged"
            extra["consistency_error"] = "old checkpoint envelope invalid"
        else:
            cons = json.loads(Path(args.consistency_proof).read_text())
            try:
                ok = verify_consistency(
                    cons["old_size"],
                    cons["new_size"],
                    cons["proof"],
                    old_result["root_hex"],
                    result["root_hex"],
                )
            except (ValueError, KeyError) as exc:
                ok = False
                extra["consistency_error"] = str(exc)
            if not ok:
                verdict = "diverged"
                extra.setdefault("consistency_error", "consistency proof failed")
            extra["consistency_verified"] = ok

    output = {**result, **extra, "verdict": verdict}
    print(json.dumps(output))

    if verdict == "diverged":
        sys.exit(20)
    elif verdict == "unanchored":
        sys.exit(21)
    else:
        sys.exit(0)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m zephyr.transparency",
        description="Zephyr RFC 6962 transparency log over the deposit log "
        "(rail zephyr-witnessed-checkpoint-log-v0, D2/D3).",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_checkpoint = sub.add_parser("checkpoint", help="Issue a signed checkpoint over the current deposit log")
    p_checkpoint.add_argument("--log", default=DEFAULT_LOG_ID)
    p_checkpoint.set_defaults(func=_cmd_checkpoint)

    p_inclusion = sub.add_parser("inclusion", help="Produce an inclusion proof for one deposit")
    p_inclusion.add_argument("--manifest-hash", required=True)
    p_inclusion.set_defaults(func=_cmd_inclusion)

    p_consistency = sub.add_parser("consistency", help="Produce a consistency proof between two tree sizes")
    p_consistency.add_argument("--old-size", required=True, type=int)
    p_consistency.add_argument("--new-size", required=True, type=int)
    p_consistency.set_defaults(func=_cmd_consistency)

    p_verify = sub.add_parser(
        "verify", help="Offline-verify a checkpoint envelope, optionally with an inclusion/consistency proof"
    )
    p_verify.add_argument("--checkpoint", required=True, help="Path to a checkpoint envelope JSON file")
    p_verify.add_argument(
        "--anchor-pubkey-hex",
        default=None,
        help="External trust anchor: raw Ed25519 public key, 64 hex chars",
    )
    p_verify.add_argument(
        "--inclusion-proof",
        default=None,
        help="Path to an inclusion-proof JSON file (manifest_hash, leaf_index, tree_size, audit_path)",
    )
    p_verify.add_argument(
        "--consistency-proof",
        default=None,
        help="Path to a consistency-proof JSON file (old_size, new_size, proof)",
    )
    p_verify.add_argument(
        "--consistency-old-checkpoint",
        default=None,
        help="Path to the prior checkpoint envelope the consistency proof is against",
    )
    p_verify.set_defaults(func=_cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> None:
    argv = list(argv if argv is not None else sys.argv[1:])
    parser = _build_parser()
    args = parser.parse_args(argv)  # may sys.exit(2) - exempt from the JSON-envelope rule

    try:
        args.func(args)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
