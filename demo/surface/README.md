# Zephyr Demo — Protocol Theater Surface

A self-contained HTML replay surface for visualizing the Zephyr protocol flow as a three-pane protocol theater with autoplay timeline.

## Two Load Paths

### 1. No-Server (Recommended for demo / `file://`)

Open `index.html` directly in a browser:

```bash
open demo/surface/index.html
# or
firefox demo/surface/index.html
```

This plays the inlined fixture with **zero network requests** and **zero setup**. Perfect for screen recording a 60–90s video of the two-scene flow.

### 2. Served (for custom event-logs)

If you have a custom event-log JSON file, serve the directory and pass the path via `?run=`:

```bash
cd demo/surface
python -m http.server 8000

# Then open:
# http://localhost:8000/?run=../eventlog.json
# or with a full path relative to index.html:
# http://localhost:8000/?run=runs/capture.json
```

**Important:** Browser CORS policy prevents `fetch()` over `file://` URLs. Use the Python server for custom runs.

## Interface

- **Three panes:** Contributor | Settler (Zephyr) | Rafiki (Open Payments)
- **Per-pane terminal logs:** Each pane shows events where that actor was the sender
- **Artifact display:** Contributor pane shows the image with real hash; missing files render as hash-stamped placeholder SVGs
- **Lineage tree (Scene 2):** SVG node-tree linking remix → original, labelled as signed `derived_from` claim (Loupe Landscape style)
- **Void banner (Scene 2):** VOID SplitPolicy announcement
- **Ledger footer:** Running ledger + void principle statement + coda
- **Packet animation:** Events between panes animate as visible packets in transit
- **Autoplay:** Timeline with play/pause/restart + speed control (0.5× / 1× / 2×), respects `prefers-reduced-motion`

## Event-Log Contract

Drives entirely off the event-log JSON fixture (schema v1.1). The surface renders whatever is in the log faithfully:

- **Fixture location:** `/home/user/zephyr-demo-eventlog.example.json` (contract for both capture and surface units)
- **Inlined:** fixture is baked into `index.html` as a fallback for the no-server path
- **Custom:** pass `?run=<path>` (relative to `index.html`) to load a different run

Fields:
- `run.mode`: surfaced as provenance badge
- `artifacts[].filename`: rendered from this path; missing files fallback to placeholder SVGs
- `artifacts[].manifest_hash`: displayed with image; used as visual anchor
- `artifacts[].derived_from`: triggers lineage tree rendering (scene 2)
- `scenes[].events[]`: ordered chronologically by `t` (ms); `kind` determines rendering; unknown kinds degrade to generic log line
- `inter_scene_gap_ms`: pause between scenes

## Scene Narrative

**Scene 1 (original-no-wallet):**
- Contributor deposits the smiley (no wallet)
- Settler resolves wallet → no route
- Ledger records "fully credited" (no-route, no payment, no deferred-payment promise)
- Rafiki pane stays dark (never called)

**Scene 2 (remix-settles):**
- Contributor deposits hat-smiley with signed `derived_from` claim
- Settler renders lineage tree (visual proof of borrowing)
- Void SplitPolicy banner fires
- Settler resolves wallet → found
- Full Open Payments flow (incoming-payment, quote, grant-approval consent beat, outgoing-payment)
- Ledger records "settled ✓" with real `op_payment_id`

**Ledger + Void Principle (footer):**
- Accumulates rows as scenes resolve
- `record_not_money` statement: "No wallet, no payment — and no retroactive backfill…"
- Coda: "The livelihood gap is the unsolved problem."

## Styling & Accessibility

- **Palette:** dark theme (OLED-friendly), color-coded per actor, high contrast
- **Typography:** monospace terminal logs, sans-serif labels, generous spacing
- **Video-friendly:** 16:9, large type, 1080p+ tested
- **Motion:** respects `prefers-reduced-motion`; all animations degrade gracefully
- **CSS variables:** palette and type hooks for future aesthetic tweaks

## Failure Modes

- **Missing image:** renders hash-stamped placeholder SVG (never breaks timeline)
- **Unknown event kind:** degrades to generic monospace log line
- **Failed fetch:** (served mode) shows error message; (no-server) uses inlined fixture
- **No schema validation:** fixture is the only contract; malformed JSON throws; unknown fields are ignored

## Development

- No build step, no framework, no CDN dependencies
- Pure vanilla JS + inline CSS
- All logic in a single HTML file for easy deployment
- Fixture loading is async; UI updates follow event-log ordering

Edit CSS variables at the top of the `<style>` block to customize palette/type.
