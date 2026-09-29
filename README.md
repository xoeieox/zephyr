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

## Consent of use

A rights holder's registered key can sign a **use declaration** on a work,
identified by the work's `manifest_hash` (`sha256:` + 64 lowercase hex).
What shipped in v0:

- **Signed self-declarations over a closed vocabulary** `{training, remix,
  redistribution}`: `record_use_terms(subject=..., allowed_uses=[...],
  denied_uses=[...])` - a key declares only for itself (the declarant is
  derived from the signer; there is no parameter with which to declare on
  another party's behalf), and every verdict-affecting field lives inside the
  signed envelope.
- **Tri-state reporting**: `check_use(subject, use)` answers exactly one of
  `permitted`, `denied`, or `undeclared`. A use not covered by the active
  declaration is `undeclared` - never silently permitted, never silently
  denied. The machine makes no claim about what you may do; it proves what was
  declared, and the absence of a declaration is itself visible. What
  `undeclared` means for your activity is your call as the consumer - Zephyr
  never decides it for you, and `undeclared` is never permission and is never
  treated more permissively than a prior `denied` declaration on the same
  work.
- **Revocation without erasure**: a later declaration with `revokes=True`
  withdraws the active one (it declares nothing itself); rows are never
  updated or deleted, so what was true while consent stood stays verifiable
  forever. After revocation the report is `undeclared`, not `denied` -
  consent withdrawn is not consent to refuse.
- **Merkle-auditable**: every declaration rides the transparency log as a
  signed deposit; a domain row whose deposit was tampered with surfaces as a
  loud named failure, never a silent absence.

`declared_by` is attribution of the declaration, never proof of entitlement -
disputes go to the social layer. Any registered key can sign a declaration
over any work hash, so consumers must cross-check `declared_by` against the
work's creator before honoring `permitted`: the machine reports WHO declared,
never who was entitled.

Do not confuse this with the Open-Payments payment-grant "consent" beats in
`demo/README.md` (the GNAP approval moment in act 3) - that word-sense is a
payment grant; the consent described here is a signed use declaration, and
the two are decoupled by design (a use declaration never gates a payment
leg).

Never populate `note` with personal data - it is signed into the public
envelope, and the privacy guarantee rests on synthetic-identity discipline,
not on this rail.

Next units (not shipped, stated honestly): character/scene/environment
creative-use consent (a social-layer question), witness countersignature, and
event-scoped terms (`scope` is stored and hashed today but is not consulted
by `check_use` in v0).
