"""Zephyr - node-collaboration work-record substrate (in-vitro).

v0 surface: the attribution log (`zephyr.attribution`) - the canonical, queryable
record of cross-node work deposits, keyed by `provenance.manifest_hash`. It rides
the existing `archetypes_core.provenance.LapisToolReturn` envelope; this repo owns
only the deposit-log / attribution domain abstraction (per
decision/zephyrium-substrate-repo-is-zephyrium-2026-05-20).

Layering: substrate servers (agents-core mem-server, weaver-server) declare a
`DepositRecorder` Protocol and inject `zephyr.attribution.get_recorder()` at boot.
agents-core/weaver do NOT import zephyr; the wiring is config-driven (env path).
"""

__version__ = "0.1.0"
