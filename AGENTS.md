# AGENTS.md - working notes for AI agents in this repo

Zephyr is the **node-collaboration work-record substrate** - a federated
attribution protocol. It owns the canonical, queryable record of cross-node
work deposits (`zephyr.attribution`), keyed by `provenance.manifest_hash`.
The protocol's job is **trustworthy attribution**: a deposit's claim "X
contributed Y" must be verifiable, not asserted.

## Hard rules

- **No LLM calls. Ever.** Zephyr is a pure-CPU integrity substrate
  (crypto + SQLite). No model invocation, no network LLM dependency.
- **Decoupling is structural.** Substrate servers and downstream daemons do
  NOT statically import zephyr; they resolve the recorder/signer via a
  config-driven `*_DEPOSIT_RECORDER` / `*_DEPOSIT_SIGNER` env spec
  (`<module>:<callable>`, dynamic import). Zephyr is injected, never
  hard-wired.
- **`manifest_hash` is the integrity + dedup anchor.** `record()` is
  INSERT-OR-IGNORE on it; re-depositing identical bytes is a no-op. It is
  computed with `signature` zeroed, so it is the canonical signing target.
- **Invalid signatures are never stored as valid.** Verification is
  enforced at the recorder chokepoint and re-checked on read.
- **Human private keys never live on remote hosts.** The recorder holds only
  *public* keys for human-role identities. Agents sign their own deposits
  with host-local keys.
- **Synthetic identities in all tests/demos.** Never use a real human
  identity in a test, fixture, docstring, or example; write only to tmp DBs.
- **DB migrations are additive.** New columns are nullable; historical rows
  must keep reading. The log is append-only.
- **Head selection is a chain walk over `supersedes` edges, never a sort.**
  `recorded_at` is audit-only and never load-bearing for selection.
- **Wallet bindings are self-signed only.** A key binds only itself; paying
  a contributor means provisioning them a key, never a claim recorded on
  their behalf. A credited-but-unpaid leg is never dropped or redistributed.

## Dev loop

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
pytest
```

Tests live in `tests/`; use a tmp claims/attribution DB, never the host DB.
