# Game Loop Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 3-timer chaos in CanvasNetworkRenderer with a clean game loop — `useGraphLayout` hook owns all physics state and runs a fixed 30 Hz tick inside a single RAF, and CanvasNetworkRenderer becomes ~250 lines of pure drawing code.

**Architecture:** `useGraphLayout` exposes a `tick(now)` function and two stable refs (`layoutNodes`, `layoutEdges`). `CanvasNetworkRenderer` calls `tick` at the start of its RAF callback, then draws from the refs. Physics and drawing share one RAF loop with zero competing timers.

**Tech Stack:** React 18, TypeScript, Zustand 4, Canvas 2D API, `requestAnimationFrame`

**Spec:** `docs/superpowers/specs/2026-05-05-game-loop-architecture-design.md`

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `src/hooks/useGraphLayout.ts` | **Create** | Game loop: fixed-step physics, delta-sync, exposes `tick` + layout refs |
| `src/components/CanvasNetworkRenderer.tsx` | **Rewrite** | Pure drawing: reads layout refs, handles pan/zoom, ~250 lines |
| `src/stores/networkStore.ts` | **Edit** | Remove dead `x?` and `y?` fields from `Node` interface |

Everything else is unchanged: `usePacketProcessor`, `networkStore` logic, `physicsStore`, `pinStore`, `settingsStore`, Go backend, `useWebSocket`.

---

## Task 1: Remove dead position fields from networkStore

**Files:**
- Modify: `src/stores/networkStore.ts:9-22`

The `Node` interface has `x?` and `y?` fields that the renderer never reads. Positions belong in `useGraphLayout`. Removing them prevents future confusion.

- [ ] **Step 1: Edit Node interface**

In `src/stores/networkStore.ts`, change:

```typescript
export interface Node {
  id: string;
  label?: string;
  x?: number;
  y?: number;
  size?: number;
  color?: number;
  highlighted?: boolean;
  lastActive: number;
  type?: string;
  packetSource?: 'real' | 'simulated' | string
  packetColor?: string;
  ports: Set<number>;
}
```

To:

```typescript
export interface Node {
  id: string;
  label?: string;
  size?: number;
  color?: number;
  highlighted?: boolean;
  lastActive: number;
  type?: string;
  packetSource?: 'real' | 'simulated' | string;
  packetColor?: string;
  ports: Set<number>;
}
```

- [ ] **Step 2: Verify TypeScript compiles**

```bash
cd /Users/ebg/Documents/Code/vibes/frontend && npx tsc --noEmit 2>&1 | grep -v "App.tsx\|PhysicsPanel\|SettingsPanel\|pinStore\|websocketUtils" | head -20
```

Expected: no errors referencing `networkStore` or `Node.x` / `Node.y`.

- [ ] **Step 3: Commit**

```bash
git add src/stores/networkStore.ts
git commit -m "refactor: remove dead x/y position fields from Node interface"
```

---

## Task 2: Create useGraphLayout hook

**Files:**
- Create: `src/hooks/useGraphLayout.ts`

This hook owns all layout state. It never touches Zustand for positions. It delta-syncs from `networkStore` on each physics tick (33 ms) rather than doing a full rebuild. It exposes a stable `tick(now)` function and two stable refs.

- [ ] **Step 1: Create the file**

Create `src/hooks/useGraphLayout.ts` with this content:

```typescript
import { useEffect, useRef, useCallback, MutableRefObject } from 'react';
import { useNetworkStore } from '../stores/networkStore';
import { usePhysicsStore } from '../stores/physicsStore';
import { useSettingsStore } from '../stores/settingsStore';
import { usePinStore } from '../stores/pinStore';
import { useSizeStore } from '../stores/sizeStore';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface LayoutNode {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  color: string;
  highlightColor: string;
  alpha: number;
  lastActive: number;
}

export interface LayoutEdge {
  sourceId: string;
  targetId: string;
  color: string;
  protocol?: string;
  dstPort?: number;
  alpha: number;
  lastActive: number;
}

export interface GraphLayoutResult {
  layoutNodes: MutableRefObject<Map<string, LayoutNode>>;
  layoutEdges: MutableRefObject<LayoutEdge[]>;
  tick: (now: number) => void;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const PHYSICS_HZ = 30;
const PHYSICS_STEP = 1000 / PHYSICS_HZ; // 33.3 ms

// ─── Color helpers ────────────────────────────────────────────────────────────

function getProtocolColor(protocol?: string): string {
  switch (protocol?.toLowerCase()) {
    case 'tcp':   return '#00FF00';
    case 'udp':   return '#FF00FF';
    case 'icmp':  return '#FFFF00';
    case 'http':
    case 'https': return '#FFA500';
    default:      return '#CCCCCC';
  }
}

function hslToHex(h: number, s: number, l: number): string {
  h /= 360; s /= 100; l /= 100;
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const x = c * (1 - Math.abs((h * 6) % 2 - 1));
  const m = l - c / 2;
  let r = 0, g = 0, b = 0;
  if (h < 1 / 6)      { r = c; g = x; b = 0; }
  else if (h < 2 / 6) { r = x; g = c; b = 0; }
  else if (h < 3 / 6) { r = 0; g = c; b = x; }
  else if (h < 4 / 6) { r = 0; g = x; b = c; }
  else if (h < 5 / 6) { r = x; g = 0; b = c; }
  else                 { r = c; g = 0; b = x; }
  const toHex = (v: number) => Math.round((v + m) * 255).toString(16).padStart(2, '0');
  return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
}

function getHighlightColor(id: string): string {
  if (id.includes('.')) {
    const parts = id.split('.').map(Number);
    if (parts.length === 4 && parts.every(p => !isNaN(p) && p >= 0 && p <= 255)) {
      const [a] = parts;
      if (a === 192) return '#0080ff';
      if (a === 10)  return '#ff00ff';
      if (a === 172) return '#ff4500';
      if (a === 8 || a === 1) return '#ffff00';
    }
  }
  let hash = 0;
  for (let i = 0; i < id.length; i++) {
    hash = ((hash << 5) - hash) + id.charCodeAt(i);
    hash = hash & hash;
  }
  return hslToHex(Math.abs(hash) % 360, 90, 60);
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

export function useGraphLayout(): GraphLayoutResult {
  const layoutNodes = useRef<Map<string, LayoutNode>>(new Map());
  const layoutEdges = useRef<LayoutEdge[]>([]);
  const lastTickTime = useRef<number>(0);
  const accumulator  = useRef<number>(0);
  const physicsRef   = useRef(usePhysicsStore.getState());
  const viewportRef  = useRef({ width: 0, height: 0 });

  // Subscribe to store changes via refs — zero re-renders
  useEffect(() => {
    const { width, height } = useSizeStore.getState();
    viewportRef.current = { width, height };
    const unsubPhysics = usePhysicsStore.subscribe(s => { physicsRef.current = s; });
    const unsubSize    = useSizeStore.subscribe(s => { viewportRef.current = { width: s.width, height: s.height }; });
    return () => { unsubPhysics(); unsubSize(); };
  }, []);

  // ── deltaSync: add/update/remove nodes and rebuild edge list ────────────────
  // Called each physics tick. Never does a full rebuild — only touches changed nodes.
  const deltaSync = useCallback(() => {
    const { nodes: storeNodes, connections: storeConns } = useNetworkStore.getState();
    const { maxNodes, maxConnectionsPerNode } = useSettingsStore.getState();
    const { connectionLifetime } = physicsRef.current;
    const now = Date.now();
    const vp  = viewportRef.current;
    const W   = vp.width  || 1280;
    const H   = vp.height || 800;

    // Most-active slice up to maxNodes
    const activeNodes = storeNodes
      .slice()
      .sort((a, b) => b.lastActive - a.lastActive)
      .slice(0, maxNodes);
    const activeIds = new Set(activeNodes.map(n => n.id));

    // Remove nodes that dropped out of the active set
    for (const id of layoutNodes.current.keys()) {
      if (!activeIds.has(id)) layoutNodes.current.delete(id);
    }

    // Add new nodes; update lastActive + color on existing ones
    for (const sn of activeNodes) {
      const existing = layoutNodes.current.get(sn.id);
      const latestConn = storeConns.find(c => c.source === sn.id || c.target === sn.id);
      if (existing) {
        existing.lastActive = sn.lastActive;
        existing.radius = (now - sn.lastActive) < 30000 ? 10 : 6;
        if (latestConn) existing.color = getProtocolColor(latestConn.protocol);
      } else {
        layoutNodes.current.set(sn.id, {
          id: sn.id,
          x:  W * 0.25 + Math.random() * W * 0.5,
          y:  H * 0.25 + Math.random() * H * 0.5,
          vx: 0, vy: 0,
          radius: 10,
          color:          getProtocolColor(latestConn?.protocol),
          highlightColor: getHighlightColor(sn.id),
          alpha:      1,
          lastActive: sn.lastActive,
        });
      }
    }

    // Build edge list — filter to active pairs, apply per-node budget
    // This rebuilds the array each tick but does NOT destroy physics state
    // (positions/velocities live in layoutNodes, not in edges).
    const nodeBudget = new Map<string, number>();
    layoutEdges.current = storeConns
      .filter(c => activeIds.has(c.source) && activeIds.has(c.target))
      .sort((a, b) => b.lastActive - a.lastActive)
      .filter(c => {
        const s = nodeBudget.get(c.source) ?? 0;
        const d = nodeBudget.get(c.target) ?? 0;
        if (s >= maxConnectionsPerNode || d >= maxConnectionsPerNode) return false;
        nodeBudget.set(c.source, s + 1);
        nodeBudget.set(c.target, d + 1);
        return true;
      })
      .map(c => ({
        sourceId:  c.source,
        targetId:  c.target,
        color:     c.packetColor ?? getProtocolColor(c.protocol),
        protocol:  c.protocol,
        dstPort:   c.dstPort,
        alpha:     Math.max(0, 1 - (now - c.lastActive) / connectionLifetime),
        lastActive: c.lastActive,
      }));
  }, []);

  // ── tickLayout: apply forces and integrate ──────────────────────────────────
  const tickLayout = useCallback((dt: number) => {
    const dtNorm = dt / 16.67; // normalise to 60-fps frame units

    const {
      nodeSpacing: ns, connectionPullStrength: cps, collisionRepulsion: cr,
      damping: dmp, connectionLifetime: clt, driftAwayStrength: das,
      centerPullStrength: cps2, springRestLength: srl,
    } = physicsRef.current;

    const { isPined } = usePinStore.getState();
    const vp      = viewportRef.current;
    const centerX = vp.width  / 2;
    const centerY = vp.height / 2;
    const now     = Date.now();
    const retain  = Math.pow(1 - dmp, dtNorm);
    const MAX_V   = 15;

    // Which nodes have live connections right now?
    const connectedIds = new Set<string>();
    layoutEdges.current.forEach(e => {
      if (now - e.lastActive < clt) {
        connectedIds.add(e.sourceId);
        connectedIds.add(e.targetId);
      }
    });

    // ── Pinned nodes: lock position to right-edge column ──
    const pinnedList = Array.from(layoutNodes.current.values())
      .filter(n => isPined(n.id))
      .sort((a, b) => a.id.localeCompare(b.id));
    pinnedList.forEach((n, i) => {
      const col = Math.floor(i / 18);
      n.x = vp.width - 100 - col * 200;
      n.y = 100 + (i % 18) * 50;
      n.vx = 0; n.vy = 0;
    });

    // ── Per-node: expiry, fade, drift ──
    const toRemove: string[] = [];
    layoutNodes.current.forEach(node => {
      if (isPined(node.id)) return;
      const age = now - node.lastActive;
      if (age > clt) { toRemove.push(node.id); return; }
      const offscreen = node.x < -200 || node.x > vp.width  + 200 ||
                        node.y < -200 || node.y > vp.height + 200;
      if (offscreen) { toRemove.push(node.id); return; }

      node.alpha = connectedIds.has(node.id) ? 1 : Math.max(0, 1 - age / clt);

      // Disconnected nodes drift outward
      if (!connectedIds.has(node.id)) {
        node.vx += (node.x - centerX) * das * 0.000002 * dtNorm;
        node.vy += (node.y - centerY) * das * 0.000002 * dtNorm;
      }
    });
    toRemove.forEach(id => {
      layoutNodes.current.delete(id);
      useNetworkStore.getState().removeNode(id);
    });

    // ── Repulsion: all pairs, soft zone + hard zone, bbox early-out ──
    const arr = Array.from(layoutNodes.current.values());
    for (let i = 0; i < arr.length; i++) {
      for (let j = i + 1; j < arr.length; j++) {
        const a = arr[i], b = arr[j];
        if (isPined(a.id) && isPined(b.id)) continue;
        const dx = b.x - a.x, dy = b.y - a.y;
        const minDist  = a.radius + b.radius + ns;
        const softDist = minDist * 1.5;
        if (Math.abs(dx) > softDist || Math.abs(dy) > softDist) continue;
        const dist = Math.sqrt(dx * dx + dy * dy) || 0.001;
        if (dist < softDist) {
          const strength = dist < minDist
            ? cr * 0.5  * (minDist  - dist) / dist
            : cr * 0.05 * (softDist - dist) / dist;
          const push = strength * dtNorm;
          if (!isPined(a.id)) { a.vx -= dx * push; a.vy -= dy * push; }
          if (!isPined(b.id)) { b.vx += dx * push; b.vy += dy * push; }
        }
      }
    }

    // ── Springs: connected pairs only ──
    layoutEdges.current.forEach(edge => {
      if (now - edge.lastActive > clt) return;
      const src = layoutNodes.current.get(edge.sourceId);
      const tgt = layoutNodes.current.get(edge.targetId);
      if (!src || !tgt) return;
      const srcPin = isPined(src.id), tgtPin = isPined(tgt.id);
      const dx   = tgt.x - src.x, dy = tgt.y - src.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 0.001;
      const sf   = cps * 0.006 * (dist - srl) * dtNorm;
      if (!srcPin) { src.vx += (dx / dist) * sf; src.vy += (dy / dist) * sf; }
      if (!tgtPin) { tgt.vx -= (dx / dist) * sf; tgt.vy -= (dy / dist) * sf; }
    });

    // ── Centre gravity: once per connected node ──
    layoutNodes.current.forEach(node => {
      if (isPined(node.id) || !connectedIds.has(node.id)) return;
      node.vx += (centerX - node.x) * cps2 * dtNorm;
      node.vy += (centerY - node.y) * cps2 * dtNorm;
    });

    // ── Integrate: damp → cap → move → soft walls ──
    const edge = 40;
    layoutNodes.current.forEach(node => {
      if (isPined(node.id)) return;
      node.vx *= retain; node.vy *= retain;
      node.vx = Math.max(-MAX_V, Math.min(MAX_V, node.vx));
      node.vy = Math.max(-MAX_V, Math.min(MAX_V, node.vy));
      node.x += node.vx * dtNorm;
      node.y += node.vy * dtNorm;
      if (node.x < edge)             node.vx += (edge - node.x)              * 0.2 * dtNorm;
      if (node.x > vp.width  - edge) node.vx -= (node.x - (vp.width  - edge)) * 0.2 * dtNorm;
      if (node.y < edge)             node.vy += (edge - node.y)              * 0.2 * dtNorm;
      if (node.y > vp.height - edge) node.vy -= (node.y - (vp.height - edge)) * 0.2 * dtNorm;
    });
  }, []);

  // ── tick: called by renderer's RAF each frame ────────────────────────────────
  // Advances the accumulator and runs as many 33 ms physics steps as needed.
  const tick = useCallback((now: number) => {
    const rawDelta = lastTickTime.current > 0 ? now - lastTickTime.current : 16;
    lastTickTime.current = now;
    accumulator.current += Math.min(rawDelta, 100); // cap: don't spiral after hidden tab

    while (accumulator.current >= PHYSICS_STEP) {
      deltaSync();
      tickLayout(PHYSICS_STEP);
      accumulator.current -= PHYSICS_STEP;
    }
  }, [deltaSync, tickLayout]);

  return { layoutNodes, layoutEdges, tick };
}
```

- [ ] **Step 2: Verify TypeScript compiles**

```bash
cd /Users/ebg/Documents/Code/vibes/frontend && npx tsc --noEmit 2>&1 | grep "useGraphLayout" | head -20
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/hooks/useGraphLayout.ts
git commit -m "feat: add useGraphLayout hook with fixed-step game loop"
```

---

## Task 3: Rewrite CanvasNetworkRenderer as pure drawing

**Files:**
- Rewrite: `src/components/CanvasNetworkRenderer.tsx`

The existing 987-line file is replaced wholesale. All physics, store subscriptions (except `useSizeStore`), object pools, and the 200 ms interval are removed. The component calls `tick` at the start of its RAF, reads the layout refs, and draws.

- [ ] **Step 1: Replace CanvasNetworkRenderer.tsx**

Replace the entire file with:

```typescript
import React, { useEffect, useRef, useCallback } from 'react';
import { useSizeStore } from '../stores/sizeStore';
import { useGraphLayout } from '../hooks/useGraphLayout';

export const CanvasNetworkRenderer: React.FC = React.memo(() => {
  const canvasRef     = useRef<HTMLCanvasElement>(null);
  const animationRef  = useRef<number>();
  const viewportRef   = useRef({ x: 0, y: 0, zoom: 1.0, width: 0, height: 0 });
  const frameCount    = useRef(0);
  const lastFpsTime   = useRef(0);
  const fpsRef        = useRef(0);

  const { width, height } = useSizeStore();
  const { layoutNodes, layoutEdges, tick } = useGraphLayout();

  // ── Canvas resize ───────────────────────────────────────────────────────────
  useEffect(() => {
    if (!canvasRef.current || !width || !height) return;
    const canvas = canvasRef.current;
    const dpr = window.devicePixelRatio || 1;
    canvas.width  = width  * dpr;
    canvas.height = height * dpr;
    canvas.style.width  = `${width}px`;
    canvas.style.height = `${height}px`;
    viewportRef.current.width  = width;
    viewportRef.current.height = height;
    const ctx = canvas.getContext('2d');
    if (ctx) ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }, [width, height]);

  // ── Render loop ─────────────────────────────────────────────────────────────
  const render = useCallback((now: number) => {
    // Advance physics first — one RAF drives everything
    tick(now);

    const canvas = canvasRef.current;
    const vp     = viewportRef.current;
    if (!canvas || !vp.width || !vp.height) {
      animationRef.current = requestAnimationFrame(render);
      return;
    }
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // FPS counter
    frameCount.current++;
    if (now - lastFpsTime.current >= 1000) {
      fpsRef.current    = frameCount.current;
      frameCount.current = 0;
      lastFpsTime.current = now;
    }

    // Clear
    ctx.fillStyle = 'black';
    ctx.fillRect(0, 0, vp.width, vp.height);

    ctx.save();
    ctx.translate(-vp.x * vp.zoom, -vp.y * vp.zoom);
    ctx.scale(vp.zoom, vp.zoom);

    const nodes = layoutNodes.current;
    const edges = layoutEdges.current;

    // ── Draw edges ──────────────────────────────────────────────────────────
    edges.forEach(edge => {
      const src = nodes.get(edge.sourceId);
      const tgt = nodes.get(edge.targetId);
      if (!src || !tgt || edge.alpha <= 0) return;

      const proto = edge.protocol?.toLowerCase() ?? '';
      let strokeColor = `rgba(0,255,255,${edge.alpha})`;
      let lineWidth = 1;
      if      (proto === 'tcp')                  { strokeColor = `rgba(0,255,0,${edge.alpha})`;   lineWidth = 2; }
      else if (proto === 'udp')                  { strokeColor = `rgba(255,0,255,${edge.alpha})`; lineWidth = 2; }
      else if (proto === 'icmp')                 { strokeColor = `rgba(255,255,0,${edge.alpha})`; lineWidth = 1; }
      else if (proto === 'http' || proto === 'https') { strokeColor = `rgba(255,165,0,${edge.alpha})`; lineWidth = 2; }

      ctx.strokeStyle = strokeColor;
      ctx.lineWidth   = lineWidth;
      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);
      ctx.stroke();

      // Port/protocol label — only when zoomed in
      if (vp.zoom > 1.5 && (edge.dstPort ?? 0) > 0) {
        const label = `${edge.protocol?.toUpperCase() ?? ''}:${edge.dstPort}`;
        const mx    = (src.x + tgt.x) / 2;
        const my    = (src.y + tgt.y) / 2;
        ctx.font      = '9px monospace';
        ctx.textAlign = 'center';
        ctx.fillStyle = `rgba(0,255,255,${edge.alpha})`;
        ctx.fillText(label, mx, my);
      }
    });

    // ── Draw nodes ──────────────────────────────────────────────────────────
    nodes.forEach(node => {
      if (node.alpha <= 0) return;

      // Parse highlight color once
      const hr = parseInt(node.highlightColor.slice(1, 3), 16);
      const hg = parseInt(node.highlightColor.slice(3, 5), 16);
      const hb = parseInt(node.highlightColor.slice(5, 7), 16);

      // Glow ring for active nodes
      if (node.radius > 7) {
        ctx.fillStyle = `rgba(${hr},${hg},${hb},${node.alpha * 0.3})`;
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius * 1.5, 0, Math.PI * 2);
        ctx.fill();
      }

      // Node body
      ctx.globalAlpha = node.alpha;
      ctx.fillStyle   = node.color;
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      ctx.fill();
      ctx.globalAlpha = 1;

      // IP label
      if (node.id.includes('.')) {
        const fontSize = Math.max(11, 13 * vp.zoom);
        ctx.font      = `${fontSize}px monospace`;
        ctx.textAlign = 'center';
        const textY = node.y + node.radius + fontSize + 2;
        const tw    = ctx.measureText(node.id).width;
        ctx.fillStyle = 'rgba(0,0,0,0.75)';
        ctx.fillRect(node.x - tw / 2 - 3, textY - fontSize, tw + 6, fontSize + 2);
        ctx.fillStyle = `rgba(${hr},${hg},${hb},${node.alpha})`;
        ctx.fillText(node.id, node.x, textY);
      }
    });

    ctx.textAlign = 'left';
    ctx.restore();

    // No-data overlay
    if (nodes.size === 0) {
      ctx.fillStyle = '#444';
      ctx.font      = '16px monospace';
      ctx.textAlign = 'center';
      ctx.fillText('Waiting for network activity...', vp.width / 2, vp.height / 2);
      ctx.textAlign = 'left';
    }

    animationRef.current = requestAnimationFrame(render);
  }, [tick, layoutNodes, layoutEdges]);

  // Start/stop render loop
  useEffect(() => {
    if (canvasRef.current) animationRef.current = requestAnimationFrame(render);
    return () => { if (animationRef.current) cancelAnimationFrame(animationRef.current); };
  }, [render]);

  // ── Pan / zoom / keyboard ───────────────────────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    let dragging = false, lastX = 0, lastY = 0;

    const onDown  = (e: MouseEvent) => { dragging = true; lastX = e.clientX; lastY = e.clientY; canvas.style.cursor = 'grabbing'; };
    const onMove  = (e: MouseEvent) => {
      if (!dragging) return;
      viewportRef.current.x -= (e.clientX - lastX) / viewportRef.current.zoom;
      viewportRef.current.y -= (e.clientY - lastY) / viewportRef.current.zoom;
      lastX = e.clientX; lastY = e.clientY;
    };
    const onUp    = () => { dragging = false; canvas.style.cursor = 'grab'; };
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const newZoom = Math.max(0.1, Math.min(5, viewportRef.current.zoom * (e.deltaY > 0 ? 0.9 : 1.1)));
      const rect    = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left, my = e.clientY - rect.top;
      const wx = mx / viewportRef.current.zoom + viewportRef.current.x;
      const wy = my / viewportRef.current.zoom + viewportRef.current.y;
      viewportRef.current.zoom = newZoom;
      viewportRef.current.x    = wx - mx / newZoom;
      viewportRef.current.y    = wy - my / newZoom;
    };
    const onKey   = (e: KeyboardEvent) => {
      if (e.key === 'r' || e.key === 'R') { viewportRef.current.x = 0; viewportRef.current.y = 0; viewportRef.current.zoom = 1; }
    };

    canvas.addEventListener('mousedown', onDown);
    canvas.addEventListener('mousemove', onMove);
    canvas.addEventListener('mouseup',   onUp);
    canvas.addEventListener('mouseleave', onUp);
    canvas.addEventListener('wheel', onWheel, { passive: false });
    document.addEventListener('keydown', onKey);
    canvas.style.cursor = 'grab';
    canvas.tabIndex = 0;

    return () => {
      canvas.removeEventListener('mousedown', onDown);
      canvas.removeEventListener('mousemove', onMove);
      canvas.removeEventListener('mouseup',   onUp);
      canvas.removeEventListener('mouseleave', onUp);
      canvas.removeEventListener('wheel',     onWheel);
      document.removeEventListener('keydown', onKey);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{ width: '100%', height: '100%', display: 'block', background: 'black' }}
    />
  );
});

CanvasNetworkRenderer.displayName = 'CanvasNetworkRenderer';
```

- [ ] **Step 2: Verify TypeScript compiles clean**

```bash
cd /Users/ebg/Documents/Code/vibes/frontend && npx tsc --noEmit 2>&1 | grep -v "App.tsx\|PhysicsPanel\|SettingsPanel\|pinStore\|websocketUtils" | head -20
```

Expected: no errors in `CanvasNetworkRenderer.tsx` or `useGraphLayout.ts`.

- [ ] **Step 3: Commit**

```bash
git add src/components/CanvasNetworkRenderer.tsx
git commit -m "feat: rewrite CanvasNetworkRenderer as pure drawing, wire useGraphLayout"
```

---

## Task 4: Visual verification

**Files:** none — this is a run-and-check task.

- [ ] **Step 1: Start the dev server**

```bash
cd /Users/ebg/Documents/Code/vibes/frontend && npm run dev
```

Expected: server starts on `http://localhost:5174` with no console errors.

- [ ] **Step 2: Open browser and verify with simulated traffic**

Open `http://localhost:5174`. The backend should be running in simulated mode (default).

Check for:
1. Nodes appear and spread out — no immediate ball collapse
2. Connected nodes drift toward each other over ~2-3 seconds
3. No jitter or oscillation — nodes settle into stable positions
4. IP labels visible below nodes
5. Connection lines colored by protocol (green=TCP, magenta=UDP, yellow=ICMP, orange=HTTP)
6. Quiet nodes fade and drift toward edges over ~30 seconds
7. Pan (drag) and zoom (scroll wheel) work
8. Press `r` resets viewport to origin

- [ ] **Step 3: Open browser console — confirm no errors**

Expected: no React errors, no `undefined` ref errors, no RAF loop exceptions.

- [ ] **Step 4: Commit if all checks pass**

```bash
git add -A
git commit -m "feat: game loop architecture complete — useGraphLayout + pure canvas renderer"
```
