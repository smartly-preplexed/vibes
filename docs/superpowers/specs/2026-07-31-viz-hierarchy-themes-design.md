# Viz Refinement: Traffic Hierarchy, Group Promotion, Themes — Design

**Date:** 2026-07-31
**Status:** Approved direction, spec for implementation planning
**Goal:** Make the 1000-node view answer "who's talking the most" at a glance, support glance-then-drill inspection, promote long-lived conversation groups to open screen space, and introduce a theme system with **retro blue** as the new default.

User requirements (from brainstorm):
- Primary question the screen answers: **who's talking the most** (traffic volume is signal).
- Interaction: **glance, then drill in** (hover/click for detail).
- Density: **keep every node visible**, restyle for hierarchy (no semantic-zoom collapse).
- Color: **subnet hue + traffic brightness**; protocol color stays on edges.
- **Long-lived groups (3+ nodes) migrate to clear screen space.**
- **Themes**, retro blue default, nodes match theme.
- Future (explicitly out of scope now): time scrubber / stream replay.

## 1. Traffic-scaled nodes

- Each `LayoutNode` gets `trafficScore`: sum of its displayed connections' weights (the existing decayed packet/byte EWMA), updated in `deltaSync`.
- Radius: log-scaled from `trafficScore`, 4 px (whisperer) → 18 px (heavy talker), multiplied by the existing density scale so 1000-node mode stays packed. `effectiveRadius` follows — big talkers occupy real space in the physics.
- Top-K talkers (K=10) get the glow ring; everyone else loses it (today every connected node glows, which flattens hierarchy).

## 2. Theme system + node color

- New `themeStore` (zustand, persisted, versioned like physicsStore). A theme defines:
  - `background`, `uiAccent`, `uiText`, `panelBorder` (applied as CSS variables on `:root`; index.css and panel styles reference the variables instead of hardcoded greens),
  - `subnetHueRange` (hue band nodes draw from), `nodeSaturation`, `brightnessRange` (traffic maps to lightness),
  - `edgeProtocolColors` (tcp/udp/icmp/http map),
  - `groupHalo`, `labelColor`, `dimAlpha`.
- Node fill = hue from `hash(clusterKey)` mapped **into the theme's hue band**, lightness from traffic percentile. Same subnet ⇒ same hue in every theme.
- Two themes ship: `classic` (current green CRT, preserved) and `retro-blue` (**default**): deep navy background, node hues in the cyan→blue→violet band (~180-270°), amber/magenta reserved as accents for promoted groups and alerts so they pop against the blue field.
- Theme picker in SettingsPanel. Canvas renderer reads the active palette per frame from a ref (no re-render).

## 3. Edge de-noise at overview

- At zoom < 1.0, edge alpha is additionally scaled by weight percentile: bottom half of flows fade to ~0.15 alpha, top decile full strength. Zooming in or focusing restores everything. No edges are removed — only de-emphasized.

## 4. Glance-then-drill (hover/click focus)

- Hit-testing on mousemove (throttled ~60 ms, linear scan over layout nodes is fine at 1000).
- **Hover:** node + its edges + direct peers render at full alpha; everything else dims to the theme's `dimAlpha` (~0.15). Cursor: pointer.
- **Click:** pins the focus (persists after mouse leaves). Click empty background or press Esc to release.
- **Readout:** canvas-drawn panel anchored near the focused node: IP, subnet key, traffic rate (from trafficScore), top 5 peers by connection weight, active ports/protocols. Stays inside the pure-drawing renderer — no new React surface.

## 5. Long-lived conversation-group promotion

- `LayoutEdge` gains `firstSeen` (persisted across syncs via the sticky-edge identity).
- Every ~2 s, compute connected components over edges continuously alive ≥ 20 s (`GROUP_PROMOTE_AGE`, tunable in PhysicsPanel). Components with ≥ 3 nodes qualify.
- A qualifying group registers as a **placement cluster** (same spiral-slot registry as subnet blobs) with stable identity = lowest member id. Members' effective cluster becomes the group id → the existing membrane/target machinery moves them to open space automatically. Promoted groups place **before** subnet blobs in the spiral, so persistent conversations claim prime real estate.
- Visual: theme `groupHalo` ring around the group's membrane circle.
- Hysteresis: join requires the joining edge itself to be ≥ promote-age; demotion only after all group edges have been dead > connectionLifetime; on demotion, members revert to subnet cluster (glide home — no teleport, positions persist).

## Order of implementation

Capture rewrite lands first (separate spec), then this, as: themes (2) → hierarchy (1) → de-noise (3) → drill-in (4) → group promotion (5). Each stage independently shippable and verifiable.

## Testing (testing/ harness)

- `stability.js` must still PASS at 150 and 1000 nodes after each stage.
- New `hierarchy.js` check: with a skewed synthetic load (one pair at 10× rate), the top-talker's rendered radius must exceed median radius by ≥ 1.8×; screenshot for eyeball confirmation.
- Group promotion: synthetic persistent 4-node conversation (genpcap or sim tweak) must acquire its own placement slot within 30 s (assert via `__VIBES_LAYOUT` cluster targets) and appear visually separated in screenshots.
- Theme: screenshots in both themes at both densities; no console errors; contrast eyeballed (labels readable on navy).

## Non-goals

- Semantic zoom / node collapsing (explicitly declined).
- Inter-blob tether bundling (revisit only if cross-blob spaghetti still bothers after de-noise).
- Time scrubber / replay (future feature, noted on roadmap; depends on capture rewrite's pcap ring).
