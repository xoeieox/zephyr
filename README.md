# zephyr

Zephyr protocol, previously known as Zephyrium

Zephyr is a node-collaboration work-record substrate: an attribution log
plus deposit envelope. This repo is the in-vitro instance of the Zephyr
envelope and rides `archetypes_core.provenance` for provenance primitives.

## Layout

- `zephyr/` - core package: attribution log, claims, deposit, intent
  queue, registry, key minting, signing, routing.
- `settler/` - settlement leg: event log, ledger, GNAP flow helpers,
  operation flow, wallet map.
- `scripts/show_ledger.py` - inspect a local ledger.
- `fixtures/`, `demo/` - demo setup and key fixtures.
- `tests/` - test suite.

## Run / inspect

Python >= 3.10; runtime deps: `cryptography`, `httpx`.

```bash
pip install -e .
pytest
```

## License

Apache License 2.0 - see `LICENSE` and `NOTICE`.
