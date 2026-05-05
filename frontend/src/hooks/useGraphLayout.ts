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

    // Build edge list — filter to active pairs, apply per-node budget.
    // Rebuilds the array each tick but does NOT destroy physics state
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
        sourceId:   c.source,
        targetId:   c.target,
        color:      c.packetColor ?? getProtocolColor(c.protocol),
        protocol:   c.protocol,
        dstPort:    c.dstPort,
        alpha:      Math.max(0, 1 - (now - c.lastActive) / connectionLifetime),
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

      // Disconnected nodes drift outward — always in motion even with zero traffic
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

    // ── Centre gravity: once per connected node (not per connection!) ──
    layoutNodes.current.forEach(node => {
      if (isPined(node.id) || !connectedIds.has(node.id)) return;
      node.vx += (centerX - node.x) * cps2 * dtNorm;
      node.vy += (centerY - node.y) * cps2 * dtNorm;
    });

    // ── Integrate: damp → cap → move → soft walls ──
    const edgeMargin = 40;
    layoutNodes.current.forEach(node => {
      if (isPined(node.id)) return;
      node.vx *= retain; node.vy *= retain;
      node.vx = Math.max(-MAX_V, Math.min(MAX_V, node.vx));
      node.vy = Math.max(-MAX_V, Math.min(MAX_V, node.vy));
      node.x += node.vx * dtNorm;
      node.y += node.vy * dtNorm;
      if (node.x < edgeMargin)              node.vx += (edgeMargin - node.x)               * 0.2 * dtNorm;
      if (node.x > vp.width  - edgeMargin)  node.vx -= (node.x - (vp.width  - edgeMargin)) * 0.2 * dtNorm;
      if (node.y < edgeMargin)              node.vy += (edgeMargin - node.y)               * 0.2 * dtNorm;
      if (node.y > vp.height - edgeMargin)  node.vy -= (node.y - (vp.height - edgeMargin)) * 0.2 * dtNorm;
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
