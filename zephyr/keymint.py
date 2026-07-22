"""python -m zephyr.keymint — the human-vouch keyring CLI (mint-human / mint-node /
vouch-node / verify-node).

Additive, capture-only tooling for the human-vouches-for-node trust chain: a node
key keeps working self-asserted exactly as today (no change to record()'s
deposit-acceptance logic); a vouch is a *verifiable stronger layer* added on top,
never enforced at deposit time.

Fail-closed on production paths: every subcommand refuses to operate against
``/data/zephyr/keys``, ``/data/zephyr/attribution.db``, or ``/data/zephyr/agent-keys``
(or their real, symlink-resolved dirs) unless ``--i-understand-this-is-prod`` is
passed explicitly. Tests run against a scratch ZEPHYR_KEYS_DIR (tmp_path) only.

No key material is minted against production by this tool as a side effect of
normal (non-flagged) use — pinning a minted human root as
ZEPHYR_HUMAN_ROOT_ANCHOR is a deliberate operator act, never something this CLI
writes into a key entry.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Production paths this CLI refuses to touch without an explicit override.
# Referenced as module globals (not bound at def-time) so tests can monkeypatch
# them to a fake prod-like path under tmp without ever touching the real dirs.
PROD_KEYS_DIR = Path("/data/zephyr/keys")
PROD_ATTRIBUTION_DB = Path("/data/zephyr/attribution.db")
PROD_AGENT_KEYS_DIR = Path("/data/zephyr/agent-keys")


def _resolve(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path


def _dir_hits_prod(path: Path, prod_dir: Path) -> bool:
    rp, rprod = _resolve(path), _resolve(prod_dir)
    return rp == rprod or rprod in rp.parents


def _file_hits_prod(path: Path, prod_file: Path) -> bool:
    return _resolve(path) == _resolve(prod_file)


def _prod_guard_blocks(i_understand_this_is_prod: bool, *, keys_dir: Path, key_out: Path | None = None) -> bool:
    """Fail-closed prod guard. Returns True (and prints a stderr diagnostic) if
    *keys_dir*, ZEPHYR_ATTRIBUTION_DB, or *key_out*'s directory resolve to a
    production path and the deliberate override flag was not passed — the
    caller must then abort (return non-zero) before any keygen/registration.

    A plain function returning a bool, not sys.exit(): keymint.main() is called
    directly (not just via __main__), including from tests, so a guard deep in
    the call stack must never call sys.exit itself.
    """
    attribution_db = Path(os.environ.get("ZEPHYR_ATTRIBUTION_DB", "/data/zephyr/attribution.db"))
    hits_prod = _dir_hits_prod(keys_dir, PROD_KEYS_DIR) or _file_hits_prod(
        attribution_db, PROD_ATTRIBUTION_DB
    )
    if key_out is not None:
        hits_prod = hits_prod or _dir_hits_prod(key_out.parent, PROD_AGENT_KEYS_DIR)

    if hits_prod and not i_understand_this_is_prod:
        print(
            "error: refusing to operate against a production path "
            f"(keys_dir={keys_dir}, attribution_db={attribution_db}) "
            "without --i-understand-this-is-prod",
            file=sys.stderr,
        )
        return True
    return False


def _sanitize_agent_id(agent_id: str) -> str:
    return agent_id.replace(":", "_").replace("/", "_")


def _default_key_path(keys_dir: Path, agent_id: str) -> Path:
    return keys_dir.parent / "agent-keys" / f"{_sanitize_agent_id(agent_id)}.key"


def _keys_dir() -> Path:
    return Path(os.environ.get("ZEPHYR_KEYS_DIR", "/data/zephyr/keys"))


def _mint(args, *, role: str, node_binding: dict | None) -> int:
    from cryptography.hazmat.primitives import serialization

    from zephyr.registry import PubkeyRegistry
    from zephyr.signing import load_or_create_agent_key, pubkey_id as compute_pubkey_id

    keys_dir = _keys_dir()
    key_out = Path(args.key_out) if args.key_out else _default_key_path(keys_dir, args.agent_id)

    if _prod_guard_blocks(args.i_understand_this_is_prod, keys_dir=keys_dir, key_out=key_out):
        return 2

    if key_out.exists():
        print(f"error: key already exists at {key_out}, refusing to overwrite", file=sys.stderr)
        return 1

    key = load_or_create_agent_key(key_out)
    pub_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    pkid = compute_pubkey_id(pub_bytes)

    reg = PubkeyRegistry(keys_dir)
    kwargs = dict(note=args.note or "")
    if role == "human":
        kwargs["assurance_tier"] = "software"
    if node_binding is not None:
        kwargs["node_binding"] = node_binding
    reg.register(pkid, pub_bytes.hex(), args.agent_id, role=role, **kwargs)

    print(pkid)
    return 0


def cmd_mint_human(args) -> int:
    return _mint(args, role="human", node_binding=None)


def cmd_mint_node(args) -> int:
    node_binding = {
        "node": args.node,
        "hostname": args.hostname,
        "tailscale_ip": args.tailscale_ip,
    }
    return _mint(args, role="node", node_binding=node_binding)


def cmd_vouch_node(args) -> int:
    from zephyr.registry import PubkeyRegistry, node_canonical_target
    from zephyr.signing import (
        load_or_create_agent_key,
        pubkey_id as compute_pubkey_id,
        sign_manifest,
    )
    from cryptography.hazmat.primitives import serialization

    keys_dir = _keys_dir()
    if _prod_guard_blocks(args.i_understand_this_is_prod, keys_dir=keys_dir):
        return 2

    reg = PubkeyRegistry(keys_dir)

    node_entry = reg.lookup(args.node_pkid)
    if node_entry is None:
        print(f"error: node pubkey_id {args.node_pkid!r} not found in registry", file=sys.stderr)
        return 1
    if node_entry.get("role") != "node":
        print(
            f"error: {args.node_pkid!r} is not role='node' (role={node_entry.get('role')!r})",
            file=sys.stderr,
        )
        return 1

    node_binding = node_entry.get("node_binding")
    required = ("node", "hostname", "tailscale_ip")
    if not node_binding or not all(
        isinstance(node_binding.get(k), str) and node_binding.get(k) for k in required
    ):
        print(
            f"error: node entry {args.node_pkid!r} has a missing/malformed node_binding "
            f"(requires non-empty {required})",
            file=sys.stderr,
        )
        return 1

    human_key_path = Path(args.human_key)
    if not human_key_path.exists():
        print(f"error: --human-key path {human_key_path} does not exist", file=sys.stderr)
        return 1

    try:
        human_key = load_or_create_agent_key(human_key_path)
    except Exception as exc:
        print(f"error: --human-key path {human_key_path} is not a valid key: {exc}", file=sys.stderr)
        return 1

    human_pub_bytes = human_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    human_pkid = compute_pubkey_id(human_pub_bytes)
    human_entry = reg.lookup(human_pkid)
    if human_entry is None or human_entry.get("role") != "human":
        print(
            f"error: --human-key (pubkey_id={human_pkid!r}) does not resolve to a "
            "registered role='human' key",
            file=sys.stderr,
        )
        return 1

    target = node_canonical_target(
        node_entry["pubkey_id"],
        node_entry["public_key_hex"],
        node_entry["agent_id"],
        node_entry.get("valid_from", ""),
        node_binding,
    )
    signature = sign_manifest(target, human_key)

    reg.set_registered_by(
        args.node_pkid, {"signer_pkid": human_pkid, "signature": signature}
    )
    print(args.node_pkid)
    return 0


_EXIT_BY_STATE = {
    "anchored": 0,
    "invalid": 1,
    "self_asserted": 3,
    "unverifiable": 4,
}


def cmd_verify_node(args) -> int:
    from zephyr.registry import PubkeyRegistry, node_anchor_status

    keys_dir = _keys_dir()
    if _prod_guard_blocks(args.i_understand_this_is_prod, keys_dir=keys_dir):
        return 2

    reg = PubkeyRegistry(keys_dir)

    entry = reg.lookup(args.node_pkid)
    if entry is None or entry.get("role") != "node":
        print(f"error: {args.node_pkid!r} is not a registered role='node' key", file=sys.stderr)
        return 2

    status = node_anchor_status(args.node_pkid, registry=reg)
    state = status["state"]

    if state == "self_asserted":
        print("self_asserted: no registered_by present (additive baseline, no vouch)", file=sys.stderr)
    elif state == "unverifiable":
        print("unverifiable: ZEPHYR_HUMAN_ROOT_ANCHOR is not configured", file=sys.stderr)
    elif state == "invalid":
        print(
            "invalid: registered_by is present but does not chain to the pinned anchor",
            file=sys.stderr,
        )
    else:
        if status.get("root_tier") == "software":
            print(
                "WARNING: anchoring root is assurance_tier=software — transitional, "
                "YubiKey hardening owed",
                file=sys.stderr,
            )
        print("anchored", file=sys.stderr)

    return _EXIT_BY_STATE[state]


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--i-understand-this-is-prod",
        action="store_true",
        help="Deliberate override: allow operating against a production path.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keymint", description="Zephyr human-vouches-for-node keyring CLI."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_mh = sub.add_parser("mint-human", help="Mint + register a role='human' key.")
    p_mh.add_argument("--agent-id", required=True)
    p_mh.add_argument("--key-out", default=None, help="Private-key output path (default derived).")
    p_mh.add_argument("--note", default="")
    _add_common_args(p_mh)
    p_mh.set_defaults(func=cmd_mint_human)

    p_mn = sub.add_parser("mint-node", help="Mint + register a role='node' key.")
    p_mn.add_argument("--agent-id", required=True)
    p_mn.add_argument("--node", required=True)
    p_mn.add_argument("--hostname", required=True)
    p_mn.add_argument("--tailscale-ip", required=True)
    p_mn.add_argument("--key-out", default=None, help="Private-key output path (default derived).")
    p_mn.add_argument("--note", default="")
    _add_common_args(p_mn)
    p_mn.set_defaults(func=cmd_mint_node)

    p_vn = sub.add_parser("vouch-node", help="Human key vouches for a registered node key.")
    p_vn.add_argument("--node-pkid", required=True)
    p_vn.add_argument("--human-key", required=True, help="Path to the human private key.")
    _add_common_args(p_vn)
    p_vn.set_defaults(func=cmd_vouch_node)

    p_ver = sub.add_parser("verify-node", help="Report a node's anchor state via exit code.")
    p_ver.add_argument("--node-pkid", required=True)
    _add_common_args(p_ver)
    p_ver.set_defaults(func=cmd_verify_node)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
