# Zephyr Demo: 3-Act Purchase Model with Settlement

This demo captures a complete attribution and settlement flow using a 3-act narrative:
1. **Act 1** — User A deposits the original image (no wallet → no-route, fully credited)
2. **Act 2** — User B remixes it, declaring `derived_from` the original (has wallet, no settlement yet)
3. **Act 3** — User C purchases the remix → settlement flow executes, routing value to User B via Open Payments

## Quick Start (Deterministic Dry-Run)

The deterministic path requires no external setup and produces a valid event-log with synthetic OP/GNAP handshake events:

```bash
# Set up the demo environment (one-time)
python fixtures/setup_demo.py --output-env /tmp/demo.env
source /tmp/demo.env

# Run dry-run capture (no network calls, deterministic output)
python demo/run_demo.py --dry-run --emit-json /tmp/capture-mock.json
```

Output: `/tmp/capture-mock.json` — a schema-1.2 event-log in `captured-mock` mode, suitable for playback and offline testing. No real wallets or network calls.

## Live Capture (Best-Effort, Requires Setup)

A real settlement against `wallet.interledger-test.dev` (the public Interledger test network).

### Prerequisites

1. **Image files** — two real PNG files:
   ```
   original.png       # Act 1 & Act 2 reference
   remix.png          # Act 2 artifact + Act 3 purchase target
   ```
   The system computes real SHA256 hashes and records them in the event-log.

2. **Wallets configuration** — a JSON file defining source wallet and per-user recipient addresses:
   ```json
   {
     "source_wallet": "https://wallet.interledger-test.dev/zephyr-settler",
     "wallets": {
       "agent:contributor_01": null,
       "agent:contributor_02": "https://wallet.interledger-test.dev/userb",
       "agent:contributor_03": "https://wallet.interledger-test.dev/userc"
     }
   }
   ```
   - **`source_wallet`** — the outgoing payment originator (must have testnet funds).
   - **`wallets`** — mapping of agent IDs to wallet addresses; `null` = no wallet (no-route path).
   - For Act 3 to succeed, the purchaser (User C) must have testnet wallet access and approve the outgoing payment once.

3. **Testnet wallet provisioning** — operator manually creates + funds wallets at `wallet.interledger-test.dev`:
   - Create three test wallets (User A, User B, User C).
   - Fund User B and User C with nominal testnet currency (e.g., $1 USD equivalent).
   - Export wallet addresses and create the `wallets.json` config file.
   - Save the file to a secure location (e.g., `/home/user/.zephyr-secrets/wallets.json`).

### Live-Capture Invocation

```bash
# Set up environment (same as dry-run)
python fixtures/setup_demo.py --output-env /tmp/demo.env
source /tmp/demo.env

# Run live capture
python demo/run_demo.py \
  --images original.png remix.png \
  --wallets /home/user/.zephyr-secrets/wallets.json \
  --emit-json /tmp/capture-live.json
```

The demo will:
1. Compute real SHA256 hashes from image files.
2. Register both images as artifacts with `derived_from` lineage.
3. Execute the real Open Payments flow against `wallet.interledger-test.dev`.
4. **Pause and display the approval URL** when User C's outgoing-payment grant requires interactive approval.
5. Continue after operator approval and complete settlement.
6. Emit `/tmp/capture-live.json` with mode `live-testnet` and real payment IDs.

### Important: Interactive Grant Approval

The live-capture flow requires **one interactive approval** from User C (the purchaser). When the settler reaches the GNAP grant step, it will surface the approval URL:

```
⚠️  Approval required
URL: https://wallet.interledger-test.dev/interact/gr_xxxx/approve
Please open the link in a browser, approve the payment, and confirm here [press Enter]
```

This approval is **expected and captures the Open Payments consent moment** — a key part of the video narrative.

## Known Limitation: Unsigned HTTP Calls

The current `settler/op_flow.py` uses unsigned `httpx` calls to the Open Payments API. The public testnet requires:
- **HTTP Message Signatures** (HTTPS + signature headers per Open Payments spec)
- **GNAP grant signing**

**Impact:** The live-capture path will fail with HTTP 401 on real `wallet.interledger-test.dev` API calls.

**Workaround for deterministic reliability (Saturday lock):** Use `--dry-run --emit-json`, which produces a valid schema-1.2 event-log with synthetic OP/GNAP events. This is the **guaranteed-shippable tier** for the video.

**TODO (best-effort, Sunday deadline):** 
- Integrate a maintained Open Payments client (e.g., `@interledger/open-payments` via Node.js helper, or a Python OP SDK).
- Add HTTP Message Signature support.
- Re-test live capture and update this README with success confirmation.

## Event-Log Format (Schema 1.2)

Both dry-run and live captures emit a JSON event-log conforming to `schema_version: "1.2"`. The document structure:

```json
{
  "schema_version": "1.2",
  "run": {
    "id": "run-3act-demo",
    "mode": "captured-mock" | "live-testnet",
    "network": "interledger-test.dev",
    "captured_at": "2026-06-12T...",
    "settler_source_wallet": "https://...",
    "inter_scene_gap_ms": 2200
  },
  "actors": [
    { "id": "user", "display": "User", "role": "entity", ... },
    { "id": "settler", "display": "Settler", "role": "entity", ... },
    { "id": "rafiki", "display": "Rafiki", "role": "responder", ... }
  ],
  "artifacts": [
    { "id": "smiley", "filename": "smiley.png", "manifest_hash": "sha256:...", "role": "original" },
    { "id": "hat-remix", "filename": "...", "manifest_hash": "sha256:...", "derived_from": "sha256:...", "role": "remix" }
  ],
  "scenes": [
    {
      "id": "act-1-deposit",
      "title": "User A deposits the original",
      "outcome": "attributed",
      "user": { "id": "agent:contributor_01", "display": "User A", "has_wallet": false },
      "events": [
        { "t": 0, "from": "user", "to": "settler", "kind": "deposit", "label": "...", "detail": {...} },
        ...
      ]
    },
    {
      "id": "act-2-remix",
      "title": "User B remixes it",
      "outcome": "attributed",
      "user": { "id": "agent:contributor_02", "display": "User B", "has_wallet": true },
      "events": [ ... ]
    },
    {
      "id": "act-3-purchase",
      "title": "User C buys the remix",
      "outcome": "settled",
      "user": { "id": "agent:contributor_03", "display": "User C", "has_wallet": true },
      "events": [
        { "kind": "purchase", ... },
        { "kind": "op_request", ... },
        { "kind": "op_response", ... },
        { "kind": "grant_request", ... },
        { "kind": "grant_interaction", ... },
        { "kind": "grant_approval", ... },
        { "kind": "grant_response", ... },
        ...
      ]
    }
  ],
  "ledger": [
    { "user": "User A", "artifact": "smiley", "status": "no-route", "record": "the record stands", ... },
    { "user": "User B", "artifact": "hat-remix", "status": "settled", "amount": 1, "op_payment_id": "op_...", ... }
  ],
  "void_principle": {
    "policy": "VOID",
    "statement": "...",
    "record_not_money": "...",
    "coda": "..."
  }
}
```

## Testing the Output

Validate the emitted JSON against the schema:

```bash
python -c "
import json
doc = json.load(open('/tmp/capture-mock.json'))
assert doc['schema_version'] == '1.2', 'Wrong schema'
assert 'run' in doc and 'actors' in doc and 'artifacts' in doc, 'Missing top-level keys'
assert len(doc['scenes']) == 3, f'Expected 3 acts, got {len(doc[\"scenes\"])}'
act3 = next(s for s in doc['scenes'] if s['id'] == 'act-3-purchase')
act3_kinds = {e['kind'] for e in act3['events']}
assert 'op_request' in act3_kinds, 'Missing op_request events'
print('✓ Schema valid')
"
```

## Attribution Semantics

- **`derived_from`** is a signed, self-asserted provenance claim (User B declares "I built on User A's hash").
- Zephyr does NOT verify the derivation forensically; it **notarizes** the claim as signed (consent-based posture).
- Attribution is **not** split or shared — both User A and User B are **fully credited** for their respective artifacts.
- Settlement is **separate** from attribution. User A (no wallet) is credited but unpaid; User B (has wallet) receives payment.
- The record is permanent and portable — undiminished regardless of settlement outcome.

## Troubleshooting

### Dry-run produces missing event kinds
Ensure `settler/event_log.py` emits synthetic OP/GNAP events for Act 3. The events must match the contract fixture kinds.

### Live capture times out on grant approval
The approval URL was not confirmed in time. The settler will block indefinitely waiting for stdin. Press Ctrl+C to abort.

### Unsigned httpx 401 errors
See the **Known Limitation** section above. The live-capture path requires HTTP Message Signatures (TODO). For now, use deterministic dry-run.

### Image hashes mismatch
Verify that:
1. Image files exist at the specified paths.
2. The SHA256 is computed correctly: `sha256sum <file>`.
3. The manifest_hash in the event-log matches.

---

**Contact:** Zephyr protocol; attribution + settlement flow  
**Last updated:** 2026-06-12  
**Schema:** 1.2
