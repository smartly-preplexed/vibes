# VIBES Game Loop Architecture — `useGraphLayout` Refactor

**Date:** 2026-05-05  
**Status:** Approved  
**Branch:** feature/fix-sampling

---

## Problem Statement

The current `CanvasNetworkRenderer.tsx` (987 lines) runs three independent timers that fight each other:

- **50 ms** — packet flush from `usePacketProcessor`
- **200 ms** — full teardown and rebuild of all connection objects in the renderer
- **16 ms** — RAF physics that runs on whatever connection data happens to be present

The 200 ms rebuild destroys every spring every 5 frames. Springs can never converge because they restart before they settle. The result: jittery, oscillating nodes that never find a stable layout, and the "massive ball" problem caused by the gravity force being applied per-connection instead of per-node.

The renderer also does four unrelated jobs — store sync, physics, drawing, and input — making individual bugs nearly impossible to isolate.

---

## Goals

1. **Smooth 60 fps rendering** at any network throughput, including 10 Gbps with simulated input
2. **Stable force-directed layout** — connected nodes converge and stay put; quiet nodes drift away gracefully
3. **Single game-loop clock** — one RAF drives everything; no competing intervals for physics
4. **Clean separation of concerns** — layout logic isolated from drawing logic
5. **All existing physics rules preserved** — physicsStore params, pin rules, node expiry, connection lifetime unchanged
6. **Security signal readiness** — architecture supports anomaly visual hooks (scan bloom, beaconing) as a follow-on without structural changes

---

## What Changes vs What Stays

### Unchanged
- Go backend (capture modes: interface, PCAP replay, dumpcap, Zeek, simulated; 90% sampling; WebSocket broadcast)
- `useWebSocket` — connection management
- `usePacketProcessor` — 50 ms flow window, `addFlowBatch()` atomic store write
- `physicsStore` — all physics parameters (spring, damping, repulsion, nodeSpacing, drift, centerPull, lifetime)
- `pinStore` — pinned node rules (exact, CIDR, range)
- `settingsStore` — maxNodes, maxConnectionsPerNode
- `sizeStore` — canvas dimensions

### Minor cleanup
- `networkStore` — remove dead `x` and `y` fields on the `Node` type; positions belong in the layout engine, not the graph store. All other node and connection fields unchanged.

### New
- `useGraphLayout` hook — owns all node positions and velocities; runs the fixed-timestep game loop inside the RAF

### Replaced
- `CanvasNetworkRenderer.tsx` physics block + 200 ms sync interval → `useGraphLayout`
- `CanvasNetworkRenderer.tsx` shrinks from 987 lines to ~250 lines of pure drawing code

---

## Architecture

```
Backend (any capture mode)
    ↓ WebSocket JSON
useWebSocket
    ↓
usePacketProcessor  [50 ms flow window]
    ↓ addFlowBatch()
networkStore        [source of truth: who talks to whom]
    ↓ getState() delta-sync on each layout tick
useGraphLayout      [game loop: fixed 30 Hz layout inside RAF]
    ↓ layoutNodes ref
CanvasRenderer      [pure drawing: reads ref, draws, handles input]
    ↓
Canvas 2D
```

---

## `useGraphLayout` — The Game Loop

### Responsibilities
- Own all `LayoutNode` positions and velocities in a `Map<string, LayoutNode>` ref
- Run a fixed 30 Hz layout tick via accumulator pattern inside `requestAnimationFrame`
- Delta-sync from `networkStore` on each tick: add newly appeared nodes, remove expired nodes — **never full rebuild**
- Expose a stable `layoutNodes` ref that `CanvasRenderer` reads each frame
- Apply all force-directed physics: springs, repulsion, gravity, drift, soft boundaries

### `LayoutNode` type

```typescript
interface LayoutNode {
  id: string
  x: number
  y: number
  vx: number
  vy: number
  radius: number        // 10 active, 6 fading
  color: string         // protocol color
  highlightColor: string
  alpha: number         // 0..1, decays as node goes quiet
  lastActive: number    // ms timestamp from store
  isDriftingAway: boolean
}
```

Positions and velocities never touch Zustand. They live only in the hook's local ref.

### Fixed-timestep loop

```
PHYSICS_HZ   = 30
PHYSICS_STEP = 1000 / 30  // 33.3 ms

On each RAF frame:
  accumulator += clamp(now - lastTime, 0, 100)

  while accumulator >= PHYSICS_STEP:
    deltaSync()
    tickLayout(PHYSICS_STEP)
    accumulator -= PHYSICS_STEP

  draw(accumulator / PHYSICS_STEP)   // interpolation alpha for renderer
```

`clamp(..., 0, 100)` prevents physics explosion if the tab was hidden.  
The renderer receives an interpolation alpha (0..1) so it can smoothly blend between the previous and current tick positions — this is what makes motion silky at 120 Hz monitors even though physics only ticks at 30 Hz.

### `deltaSync()` — never a full rebuild

On each physics tick, compare `networkStore.getState()` against the current `layoutNodes` map:

1. **Add** any node in the store not yet in `layoutNodes` — spawn at center 50% of viewport, zero velocity
2. **Update** `lastActive`, `radius`, `color` on existing nodes from store data
3. **Remove** any node in `layoutNodes` not present in the store (already pruned by store)
4. **Build edge list** — read connections from store, filter to only pairs where both endpoints exist in `layoutNodes`, apply `maxConnectionsPerNode` budget

The edge list is rebuilt each tick from the store, but that is cheap (just filtering an array) — it does not destroy any physics state, because physics state (positions, velocities) lives in `layoutNodes`, not in the edge list.

### `tickLayout(dt: number)` — force model

`dt` is passed as raw milliseconds (PHYSICS_STEP = 33.3 ms). Normalize at the top of the function so all forces use a consistent dimensionless frame unit (1.0 = one 60 fps frame):

```
dtNorm = dt / 16.67   // 2.0 at 30 Hz, 1.0 at 60 Hz, 0.5 at 120 Hz
```

All force constants are read from `physicsRef.current` (subscribed via `physicsStore.subscribe()`; no re-renders).

**1. Per-node: expiry and fade**
```
age = now - node.lastActive
if age > connectionLifetime: mark for removal
alpha = node has live connection ? 1 : max(0, 1 - age / connectionLifetime)
```

**2. Repulsion — all node pairs** (soft zone + hard zone, bbox early-out)
```
minDist = nodeA.radius + nodeB.radius + nodeSpacing
softDist = minDist * 1.5

if |dx| > softDist OR |dy| > softDist: skip  // cheap bbox reject, avoids sqrt

dist = sqrt(dx² + dy²)
if dist < softDist:
  strength = dist < minDist
    ? collisionRepulsion * 0.5 * (minDist - dist) / dist   // hard zone
    : collisionRepulsion * 0.05 * (softDist - dist) / dist // soft spread zone
  apply ±strength * dtNorm to velocities
```

The soft zone is what spreads non-connected nodes apart naturally. Without it, nodes only get pushed when already overlapping.

**3. Springs — connected pairs only**
```
displacement = dist - springRestLength
springK = connectionPullStrength * 0.006
force = springK * displacement * dtNorm
apply ±(dx/dist * force) to velocities
```

**4. Centre gravity — once per connected node** (NOT once per connection)
```
gravK = centerPullStrength
node.vx += (centerX - node.x) * gravK * dtNorm
node.vy += (centerY - node.y) * gravK * dtNorm
```

Applying per-connection caused hub nodes with 50 connections to receive 50× gravity, instantly slamming everything to center. Applied once per node it is a gentle cluster anchor.

**5. Drift — disconnected nodes**
```
if node has no live connection:
  node.vx += (node.x - centerX) * driftAwayStrength * 0.000002 * dtNorm
  node.vy += (node.y - centerY) * driftAwayStrength * 0.000002 * dtNorm
```

Quiet nodes drift outward and fade. The graph never freezes; there is always motion.

**6. Pinned nodes** — read from `usePinStore.getState().isPined(id)`; position locked to right-edge column layout, velocity zeroed.

**7. Integration**
```
retain = pow(1 - damping, dtNorm)  // frame-rate independent, overdamped
node.vx *= retain
node.vy *= retain
node.vx = clamp(node.vx, -15, 15) // prevent teleportation
node.vy = clamp(node.vy, -15, 15)
node.x += node.vx * dtNorm
node.y += node.vy * dtNorm
```

`damping = 0.20` is above the critical damping threshold (~0.17) for `springK = 0.0078`, so nodes settle without oscillating.

**8. Soft boundary walls**
```
edge = 40px
if node.x < edge:           node.vx += (edge - node.x) * 0.2 * dtNorm
if node.x > width - edge:   node.vx -= (node.x - (width - edge)) * 0.2 * dtNorm
// same for y
```

---

## `CanvasRenderer` — Pure Drawing

### Responsibilities
- Read `layoutNodes` ref on each RAF frame
- Draw connections (lines, protocol colors, alpha)
- Draw nodes (circles, glow, IP labels)
- Handle pan, zoom, keyboard reset
- Subscribe only to `sizeStore` (resize is rare and expected to re-render)

### No physics, no store subscriptions beyond sizeStore

All game-loop state is in refs passed down from `useGraphLayout`. The renderer never calls `useNetworkStore()`, `usePhysicsStore()`, `usePinStore()`, or `usePacketStore()` as hooks — these were causing 20+ re-renders/second that destabilized the RAF loop.

### Rendering passes (each frame)
1. Clear canvas (black fill)
2. Save context, apply viewport transform (pan + zoom)
3. Draw connections — protocol-colored lines, alpha from `layoutNode.alpha`, port/protocol labels only at zoom > 1.5
4. Draw nodes — circle fill (protocol color), glow ring (highlight color) when active, IP label below
5. Restore context
6. HUD overlay — "Waiting for network activity..." when no nodes; FPS counter in debug mode

### Connection color by protocol
- TCP: green `rgba(0,255,0,α)`
- UDP: magenta `rgba(255,0,255,α)`
- ICMP: yellow `rgba(255,255,0,α)`
- HTTP/HTTPS: orange `rgba(255,165,0,α)`
- Other: cyan `rgba(0,255,255,α)`

### Node highlight color by IP range
- 192.168.x.x — blue
- 10.x.x.x — magenta
- 172.x.x.x — orange
- 8.x.x.x / 1.x.x.x — yellow (public DNS)
- Everything else — hash-derived hue

---

## Node Lifecycle

```
SPAWN     → position: center 50% of viewport, random, zero velocity
ACTIVE    → alpha 1.0, radius 10, pulled by springs toward connected nodes
FADING    → last connection expired, alpha decays, drift force applied outward
REMOVED   → age > connectionLifetime OR drifted off-screen → removed from layoutNodes
           → networkStore.removeNode() called to keep stores in sync
```

---

## Security Signal Architecture (follow-on, not this build)

The layout node type and renderer are intentionally designed to support future signal properties without structural changes:

- **Scan bloom**: `layoutNode.uniqueDestinations: number` derived in `deltaSync()` from store connection data. Renderer scales node radius logarithmically. No new stores needed.
- **Beaconing**: `connection.beatPhase: number` computed in `tickLayout()` from inter-arrival timing. Renderer pulses line alpha on phase. Stored in the edge list ref, not Zustand.

These are addable as deltas to `deltaSync()` and `tickLayout()` without touching any other layer.

---

## Files Changed

| File | Change |
|------|--------|
| `src/hooks/useGraphLayout.ts` | **New** — ~350 lines |
| `src/components/CanvasNetworkRenderer.tsx` | **Rewrite** — ~250 lines (pure drawing) |
| `src/stores/networkStore.ts` | Remove `x`, `y` from `Node` interface |
| `src/stores/physicsStore.ts` | No change |
| `src/stores/pinStore.ts` | No change |
| `src/stores/settingsStore.ts` | No change |
| `src/hooks/usePacketProcessor.ts` | No change |

---

## Out of Scope

- Animated packet particles along connection lines (future option)
- NetFlow / sFlow ingest (future capture mode)
- Security signal visual implementation (scan bloom, beaconing)
- Mobile / responsive layout
- Export / recording
- L2 / MAC address support
- Port display UI improvements beyond what already exists
