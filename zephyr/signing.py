"""Zephyr signing primitives — Ed25519 agent-key load/create, sign, verify.

Mirrors the librarian (agents-core) idiom: PEM/PKCS8, O_EXCL, mode 0o600.
No LLM calls, no network, no zephyr imports (pure crypto).

Default key path: ZEPHYR_AGENT_KEY_PATH env, or
/data/zephyr/agent-keys/<hostname>.key.
"""

from __future__ import annotations

import hashlib
import logging
import os
import socket
import threading
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

log = logging.getLogger(__name__)

_DEFAULT_KEY_PATH = Path(
    os.environ.get(
        "ZEPHYR_AGENT_KEY_PATH",
        f"/data/zephyr/agent-keys/{socket.gethostname()}.key",
    )
)


# ---------------------------------------------------------------------------
# Key load / create
# ---------------------------------------------------------------------------


def _read_key(key_path: Path) -> Ed25519PrivateKey:
    pem_bytes = key_path.read_bytes()
    key = serialization.load_pem_private_key(pem_bytes, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"Key at {key_path} is not Ed25519")
    return key


def load_or_create_agent_key(path: Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from *path*, or generate and persist one.

    Uses O_EXCL so a concurrent generator can't overwrite an existing key.
    The key file is created with mode 0o600 (owner-read-write only).

    Raises OSError with a clear message if the parent directory is
    unwritable (actionable: `mkdir -p <dir> && chown user`).
    """
    if path.exists():
        return _read_key(path)

    new_key = Ed25519PrivateKey.generate()
    pem = new_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OSError(
            f"Cannot create agent-key directory {path.parent} — "
            f"run: mkdir -p {path.parent} && chown user {path.parent}\n"
            f"Original error: {exc}"
        ) from exc

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(str(path), flags, 0o600)
    except FileExistsError:
        # Lost the race — another process generated first. Load theirs.
        return _read_key(path)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)
    log.info("zephyr.signing: generated new Ed25519 agent key at %s", path)
    return new_key


# ---------------------------------------------------------------------------
# Content-addressed pubkey identity
# ---------------------------------------------------------------------------


def pubkey_id(public_key_bytes: bytes) -> str:
    """Return the content-addressed identity for a raw Ed25519 public key.

    Format: ``"ed25519:" + sha256(raw_pubkey_bytes).hexdigest()[:16]``

    Self-certifying: the identity is derived from the key, never asserted
    by a string, so forging a pubkey_id requires forging the key itself.
    """
    return "ed25519:" + hashlib.sha256(public_key_bytes).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Sign / verify over manifest_hash
# ---------------------------------------------------------------------------


def sign_manifest(manifest_hash: str, key: Ed25519PrivateKey) -> str:
    """Ed25519-sign *manifest_hash* (UTF-8 encoded) and return hex signature."""
    return key.sign(manifest_hash.encode("utf-8")).hex()


def verify_manifest(manifest_hash: str, sig_hex: str, public_key_bytes: bytes) -> bool:
    """Verify an Ed25519 signature over *manifest_hash*.

    Returns True on success, False on bad or unverifiable signatures (including
    malformed hex). Never raises for bad signatures - only raises for programming
    errors such as a malformed public key.
    """
    pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        return False
    try:
        pub.verify(sig_bytes, manifest_hash.encode("utf-8"))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# AgentSigner — thin wrapper around a loaded key
# ---------------------------------------------------------------------------


class AgentSigner:
    """Wraps a loaded Ed25519PrivateKey with helper accessors for sign/verify."""

    def __init__(self, key_path: Path = _DEFAULT_KEY_PATH):
        self._key = load_or_create_agent_key(key_path)
        pub = self._key.public_key()
        self._pub_bytes: bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._pubkey_id: str = pubkey_id(self._pub_bytes)

    @property
    def public_key_bytes(self) -> bytes:
        return self._pub_bytes

    @property
    def pubkey_id_str(self) -> str:
        return self._pubkey_id

    def sign(self, manifest_hash: str) -> str:
        return sign_manifest(manifest_hash, self._key)


# ---------------------------------------------------------------------------
# Singleton factory (parallel to get_recorder())
# ---------------------------------------------------------------------------

_SIGNER: AgentSigner | None = None
_SIGNER_LOCK = threading.Lock()


def get_signer() -> AgentSigner:
    """Return the process-wide AgentSigner singleton.

    Parallel to get_recorder(): usable as a callable target for a future
    *_DEPOSIT_SIGNER env spec (dynamic import) so substrate servers need
    not statically import zephyr.
    """
    global _SIGNER
    if _SIGNER is None:
        with _SIGNER_LOCK:
            if _SIGNER is None:
                _SIGNER = AgentSigner()
    return _SIGNER


def _reset_signer() -> None:
    """For tests — force reload of signer on next use."""
    global _SIGNER
    _SIGNER = None
