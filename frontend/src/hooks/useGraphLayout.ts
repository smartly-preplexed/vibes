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
  effectiveRadius: number; // collision zone including text label footprint
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
  isBridge?: boolean;
  clusterPair: string;
  rank: number;
}

export interface GraphLayoutResult {
  layoutNodes: MutableRefObject<Map<string, LayoutNode>>;
  layoutEdges: MutableRefObject<LayoutEdge[]>;
  tick: (now: number) => void;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const PHYSICS_HZ = 30;
const PHYSICS_STEP = 1000 / PHYSICS_HZ; // 33.3 ms
const MAX_TOPOLOGY_DEGREE = 150;
const DEFAULT_TOPOLOGY_DEGREE = 10;
const ACTIVE_CORE_RADIUS = 260;
const CLUSTER_ANCHOR_RADIUS = 260;
const QUIET_NODE_OVERFLOW = 25;
const PHYSICS_EDGE_RANK_LIMIT = 12;
const QUIET_EDGE_TARGET_PADDING = 80;
const GROUP_GRID_SPACING = 245;
const NODE_GRID_SPACING = 64;

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

function getClusterKey(id: string): string {
  const parts = id.split('.').map(Number);
  if (parts.length === 4 && parts.every(p => !Number.isNaN(p))) {
    const [a, b, c] = parts;
    if (a === 10) return `10.${b}`;
    if (a === 172) return `172.${b}`;
    if (a === 192 && b === 168) return `192.168.${c}`;
    return `${a}`;
  }
  return id.slice(0, 3);
}

function getHexSlot(index: number, spacing: number): { x: number; y: number } {
  if (index === 0) return { x: 0, y: 0 };

  let ring = 1;
  let firstIndexInRing = 1;
  while (index >= firstIndexInRing + ring * 6) {
    firstIndexInRing += ring * 6;
    ring++;
  }

  let offset = index - firstIndexInRing;
  let q = ring;
  let r = 0;
  const dirs = [
    { q: -1, r: 1 },
    { q: -1, r: 0 },
    { q: 0, r: -1 },
    { q: 1, r: -1 },
    { q: 1, r: 0 },
    { q: 0, r: 1 },
  ];

  for (const dir of dirs) {
    const steps = Math.min(ring, offset);
    q += dir.q * steps;
    r += dir.r * steps;
    offset -= steps;
    if (offset === 0) break;
  }

  return {
    x: spacing * (q + r / 2),
    y: spacing * Math.sqrt(3) * r / 2,
  };
}

function getRingSlot(index: number, count: number, radius: number, seed: string): { x: number; y: number } {
  let hash = 0;
  for (let i = 0; i < seed.length; i++) hash = ((hash << 5) - hash) + seed.charCodeAt(i);
  const offset = (Math.abs(hash) % 360) * Math.PI / 180;
  const angle = offset + (index / Math.max(1, count)) * Math.PI * 2;
  return {
    x: Math.cos(angle) * radius,
    y: Math.sin(angle) * radius,
  };
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

export function useGraphLayout(): GraphLayoutResult {
  const layoutNodes = useRef<Map<string, LayoutNode>>(new Map());
  const layoutEdges = useRef<LayoutEdge[]>([]);
  const lastTickTime = useRef<number>(0);
  const accumulator  = useRef<number>(0);
  const physicsRef   = useRef(usePhysicsStore.getState());
  const viewportRef  = useRef({ width: 0, height: 0 });
  const componentRef  = useRef<Map<string, { x: number; y: number; size: number }>>(new Map());

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

    // Most-active slice up to maxNodes — limits which NEW nodes we add, not which we keep
    const activeNodes = storeNodes
      .slice()
      .sort((a, b) => b.lastActive - a.lastActive)
      .slice(0, maxNodes);
    const activeIds = new Set(activeNodes.map(n => n.id));

    // Remove layout nodes that are completely gone from the store.
    // Do NOT remove based on maxNodes rank — tickLayout owns expiry via connectionLifetime.
    // Removing here by rank causes nodes to flash out early when new bursts push them off the top-N list.
    const storeIds = new Set(storeNodes.map(n => n.id));
    for (const id of layoutNodes.current.keys()) {
      if (!storeIds.has(id)) layoutNodes.current.delete(id);
    }

    const degreeLimit = Math.max(1, Math.min(maxConnectionsPerNode || DEFAULT_TOPOLOGY_DEGREE, MAX_TOPOLOGY_DEGREE));
    const nodeBudget = new Map<string, number>();
    const edgeRank = new Map<string, number>();
    const visibleStoreConns = storeConns
      .filter(c =>
        storeIds.has(c.source) &&
        storeIds.has(c.target) &&
        now - c.lastActive <= connectionLifetime
      )
      .sort((a, b) => b.lastActive - a.lastActive)
      .filter(c => {
        const s = nodeBudget.get(c.source) ?? 0;
        const d = nodeBudget.get(c.target) ?? 0;
        if (s >= degreeLimit || d >= degreeLimit) return false;
        edgeRank.set(c.id, Math.max(s, d) + 1);
        nodeBudget.set(c.source, s + 1);
        nodeBudget.set(c.target, d + 1);
        return true;
      });
    const visibleEndpointIds = new Set<string>();
    visibleStoreConns.forEach(c => {
      visibleEndpointIds.add(c.source);
      visibleEndpointIds.add(c.target);
    });

    // Add new nodes only when they participate in the visible topology; update
    // existing nodes even after their edge expires so they can fade/drift out.
    for (const sn of activeNodes) {
      if (!visibleEndpointIds.has(sn.id) && !layoutNodes.current.has(sn.id)) continue;
      const existing = layoutNodes.current.get(sn.id);
      const latestConn = storeConns.find(c => c.source === sn.id || c.target === sn.id);
      // Use the circle radius for physics collision only.
      // Label text is allowed to visually overlap at overview zoom — the topology is what matters.
      // User zooms in to read individual IPs.
      const r = 10;
      const effectiveRadius = r;
      if (existing) {
        existing.lastActive = sn.lastActive;
        existing.radius = r;
        existing.effectiveRadius = effectiveRadius;
        if (latestConn) existing.color = getProtocolColor(latestConn.protocol);
      } else {
        // Spawn near an already-laid-out neighbor so the spring doesn't have to
        // drag the node across the canvas before the graph looks right.
        const neighborConn = storeConns.find(c =>
          (c.source === sn.id && layoutNodes.current.has(c.target)) ||
          (c.target === sn.id && layoutNodes.current.has(c.source))
        );
        const anchor = neighborConn
          ? layoutNodes.current.get(neighborConn.source === sn.id ? neighborConn.target : neighborConn.source)
          : null;
        const playCenterX = W * 0.46;
        const playCenterY = H * 0.46;
        const spawnX = anchor ? anchor.x + (Math.random() - 0.5) * 60 : playCenterX + (Math.random() - 0.5) * 120;
        const spawnY = anchor ? anchor.y + (Math.random() - 0.5) * 60 : playCenterY + (Math.random() - 0.5) * 120;
        layoutNodes.current.set(sn.id, {
          id: sn.id,
          x:  spawnX,
          y:  spawnY,
          vx: 0, vy: 0,
          radius: r,
          effectiveRadius,
          color:          getProtocolColor(latestConn?.protocol),
          highlightColor: getHighlightColor(sn.id),
          alpha:          1,
          lastActive:     sn.lastActive,
        });
      }
    }

    const layoutLimit = maxNodes + QUIET_NODE_OVERFLOW;
    if (layoutNodes.current.size > layoutLimit) {
      const removable = Array.from(layoutNodes.current.values())
        .filter(n => !activeIds.has(n.id))
        .sort((a, b) => a.lastActive - b.lastActive);
      let overflow = layoutNodes.current.size - layoutLimit;
      for (const node of removable) {
        if (overflow <= 0) break;
        layoutNodes.current.delete(node.id);
        overflow--;
      }
    }

    // Build edge list — filter to pairs where both endpoints are alive in the layout.
    // Use layoutNodes (not activeIds) so connections stay visible for their full connectionLifetime
    // even when a burst of new nodes pushes an endpoint out of the top-maxNodes rank.
    layoutEdges.current = visibleStoreConns
      .filter(c => layoutNodes.current.has(c.source) && layoutNodes.current.has(c.target))
      .map(c => ({
        sourceId:   c.source,
        targetId:   c.target,
        color:      c.packetColor ?? getProtocolColor(c.protocol),
        protocol:   c.protocol,
        dstPort:    c.dstPort,
        alpha:      Math.max(0, 1 - (now - c.lastActive) / connectionLifetime),
        lastActive: c.lastActive,
        isBridge:   getClusterKey(c.source) !== getClusterKey(c.target),
        clusterPair: [getClusterKey(c.source), getClusterKey(c.target)].sort().join('|'),
        rank:       edgeRank.get(c.id) ?? 1,
      }));
  }, []);

  const updateComponents = useCallback((now: number, connectionLifetime: number, centerX: number, centerY: number) => {
    const adjacency = new Map<string, Set<string>>();
    layoutNodes.current.forEach((_, id) => adjacency.set(id, new Set()));

    layoutEdges.current.forEach(edge => {
      if (now - edge.lastActive > connectionLifetime) return;
      const src = adjacency.get(edge.sourceId);
      const tgt = adjacency.get(edge.targetId);
      if (!src || !tgt) return;
      src.add(edge.targetId);
      tgt.add(edge.sourceId);
    });

    const components: string[][] = [];
    const degree = new Map<string, number>();
    const visited = new Set<string>();
    adjacency.forEach((neighbors, id) => degree.set(id, neighbors.size));
    adjacency.forEach((neighbors, id) => {
      if (visited.has(id) || neighbors.size === 0) return;
      const stack = [id];
      const ids: string[] = [];
      visited.add(id);
      while (stack.length > 0) {
        const next = stack.pop()!;
        ids.push(next);
        adjacency.get(next)?.forEach(peer => {
          if (!visited.has(peer)) {
            visited.add(peer);
            stack.push(peer);
          }
        });
      }
      components.push(ids);
    });

    const anchors = new Map<string, { x: number; y: number; size: number }>();
    const groups = components.sort((a, b) => b.length - a.length);
    const viewportLimitX = Math.max(140, centerX - 140);
    const viewportLimitY = Math.max(120, centerY - 120);
    groups.forEach((ids, index) => {
      const cell = getHexSlot(index, GROUP_GRID_SPACING);
      const anchor = {
        x: centerX + Math.max(-viewportLimitX, Math.min(viewportLimitX, cell.x)),
        y: centerY + Math.max(-viewportLimitY, Math.min(viewportLimitY, cell.y)),
        size: ids.length,
      };

      const sorted = ids
        .slice()
        .sort((a, b) => (degree.get(b) ?? 0) - (degree.get(a) ?? 0) || b.localeCompare(a));
      const root = sorted[0];
      const distance = new Map<string, number>([[root, 0]]);
      const queue = [root];
      while (queue.length > 0) {
        const id = queue.shift()!;
        const nextDistance = (distance.get(id) ?? 0) + 1;
        adjacency.get(id)?.forEach(peer => {
          if (!distance.has(peer)) {
            distance.set(peer, nextDistance);
            queue.push(peer);
          }
        });
      }

      const shells = new Map<number, string[]>();
      sorted.forEach(id => {
        const shell = Math.min(4, distance.get(id) ?? 4);
        const peers = shells.get(shell) ?? [];
        peers.push(id);
        shells.set(shell, peers);
      });

      shells.forEach((shellIds, shell) => {
        shellIds
          .sort((a, b) => (degree.get(b) ?? 0) - (degree.get(a) ?? 0) || a.localeCompare(b))
          .forEach((id, shellIndex) => {
            const shellRadius = shell === 0 ? 0 : 32 + shell * NODE_GRID_SPACING + Math.max(0, shellIds.length - 8) * 2;
            const slot = shell === 0
              ? { x: 0, y: 0 }
              : getRingSlot(shellIndex, shellIds.length, shellRadius, `${root}:${shell}`);
            anchors.set(id, {
              x: anchor.x + slot.x,
              y: anchor.y + slot.y,
              size: ids.length,
            });
          });
      });
    });
    componentRef.current = anchors;
  }, []);

  // ── tickLayout: apply forces and integrate ──────────────────────────────────
  const tickLayout = useCallback((dt: number) => {
    const dtNorm = dt / 16.67; // normalise to 60-fps frame units

    const {
      nodeSpacing: ns, connectionPullStrength: cps, collisionRepulsion: cr,
      damping: dmp, connectionLifetime: clt, nodeLifetime: nlt, driftAwayStrength: das,
      centerPullStrength: cps2, springRestLength: srl,
    } = physicsRef.current;

    const { isPined } = usePinStore.getState();
    const vp      = viewportRef.current;
    const centerX = vp.width  * 0.46;
    const centerY = vp.height * 0.46;
    const now     = Date.now();
    const damping = Math.max(0, Math.min(0.95, dmp));
    const retain  = Math.pow(1 - damping, dtNorm);
    const forceResponse = Math.max(0.12, 1 - damping * 0.7);
    const MAX_V   = 28;

    // Which nodes have live connections right now?
    const connectedIds = new Set<string>();
    layoutEdges.current.forEach(e => {
      if (now - e.lastActive < clt) {
        connectedIds.add(e.sourceId);
        connectedIds.add(e.targetId);
      }
    });
    updateComponents(now, clt, centerX, centerY);

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
    // connectionLifetime governs edge alpha and connectedIds.
    // nodeLifetime governs how long a node stays on screen after its last packet.
    const toRemove: string[] = [];
    layoutNodes.current.forEach(node => {
      if (isPined(node.id)) return;
      const age = now - node.lastActive;
      if (age > nlt) { toRemove.push(node.id); return; }
      const offscreen = node.x < -200 || node.x > vp.width  + 200 ||
                        node.y < -200 || node.y > vp.height + 200;
      if (offscreen) { toRemove.push(node.id); return; }

      // Full opacity while connected; fade out over nodeLifetime once quiet
      node.alpha = connectedIds.has(node.id) ? 1 : Math.max(0, 1 - age / nlt);

      // Disconnected nodes drift outward — always in motion even with zero traffic
      if (!connectedIds.has(node.id)) {
        const dx = node.x - centerX;
        const dy = node.y - centerY;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const targetDist = Math.max(vp.width, vp.height) * 0.5 + QUIET_EDGE_TARGET_PADDING;
        const remaining = Math.max(250, nlt - age);
        const desiredSpeed = Math.max(1.2, (targetDist - dist) / (remaining / PHYSICS_STEP));
        const outward = das * desiredSpeed * 0.16 * dtNorm;
        node.vx += (dx / dist) * outward;
        node.vy += (dy / dist) * outward;
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
        const minDist  = a.effectiveRadius + b.effectiveRadius + ns;
        const softDist = minDist * 1.5;
        if (Math.abs(dx) > softDist || Math.abs(dy) > softDist) continue;
        const dist = Math.sqrt(dx * dx + dy * dy) || 0.001;
        if (dist < softDist) {
          const strength = dist < minDist
            ? cr * 0.5  * (minDist  - dist) / dist
            : cr * 0.05 * (softDist - dist) / dist;
          const push = strength * forceResponse * dtNorm;
          if (!isPined(a.id)) { a.vx -= dx * push; a.vy -= dy * push; }
          if (!isPined(b.id)) { b.vx += dx * push; b.vy += dy * push; }

          if (dist < minDist) {
            const overlap = minDist - dist;
            const nx = dx / dist;
            const ny = dy / dist;
            const correction = Math.min(overlap * 0.55, 12);
            const aPinned = isPined(a.id);
            const bPinned = isPined(b.id);
            if (!aPinned && !bPinned) {
              a.x -= nx * correction * 0.5;
              a.y -= ny * correction * 0.5;
              b.x += nx * correction * 0.5;
              b.y += ny * correction * 0.5;
            } else if (!aPinned) {
              a.x -= nx * correction;
              a.y -= ny * correction;
            } else if (!bPinned) {
              b.x += nx * correction;
              b.y += ny * correction;
            }
          }
        }
      }
    }

    // ── Springs: connected pairs only ──
    const liveDegree = new Map<string, number>();
    layoutEdges.current.forEach(edge => {
      if (now - edge.lastActive > clt) return;
      if (edge.rank > PHYSICS_EDGE_RANK_LIMIT) return;
      liveDegree.set(edge.sourceId, (liveDegree.get(edge.sourceId) ?? 0) + 1);
      liveDegree.set(edge.targetId, (liveDegree.get(edge.targetId) ?? 0) + 1);
    });

    layoutEdges.current.forEach(edge => {
      if (now - edge.lastActive > clt) return;
      if (edge.rank > PHYSICS_EDGE_RANK_LIMIT) return;
      const src = layoutNodes.current.get(edge.sourceId);
      const tgt = layoutNodes.current.get(edge.targetId);
      if (!src || !tgt) return;
      const srcPin = isPined(src.id), tgtPin = isPined(tgt.id);
      const dx   = tgt.x - src.x, dy = tgt.y - src.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 0.001;
      const sameCluster = getClusterKey(src.id) === getClusterKey(tgt.id);
      const restLength = Math.max(85, srl);
      const springScale = sameCluster ? 0.14 : 0.08;
      const edgeDegree = Math.max(liveDegree.get(src.id) ?? 1, liveDegree.get(tgt.id) ?? 1);
      const degreeResponse = Math.min(1, Math.sqrt(8 / edgeDegree));
      const sf   = cps * springScale * degreeResponse * (dist - restLength) * forceResponse * dtNorm;
      if (!srcPin) { src.vx += (dx / dist) * sf; src.vy += (dy / dist) * sf; }
      if (!tgtPin) { tgt.vx -= (dx / dist) * sf; tgt.vy -= (dy / dist) * sf; }
    });

    // ── Component gravity: active components cluster around stable center anchors ──
    layoutNodes.current.forEach(node => {
      if (isPined(node.id) || !connectedIds.has(node.id)) return;
      const anchor = componentRef.current.get(node.id) ?? { x: centerX, y: centerY, size: 1 };
      const dx = anchor.x - node.x;
      const dy = anchor.y - node.y;
      const anchorPull = Math.max(cps2, 0.018);
      node.vx += dx * anchorPull * forceResponse * dtNorm;
      node.vy += dy * anchorPull * forceResponse * dtNorm;

      const centerDx = centerX - node.x;
      const centerDy = centerY - node.y;
      const distFromCenter = Math.sqrt(centerDx * centerDx + centerDy * centerDy);
      if (distFromCenter > ACTIVE_CORE_RADIUS + anchor.size * 2) {
        node.vx += centerDx * cps2 * 0.35 * forceResponse * dtNorm;
        node.vy += centerDy * cps2 * 0.35 * forceResponse * dtNorm;
      }
      node.vx += centerDx * cps2 * 0.08 * forceResponse * dtNorm;
      node.vy += centerDy * cps2 * 0.08 * forceResponse * dtNorm;
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
