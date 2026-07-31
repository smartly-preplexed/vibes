import { useEffect, useRef, useCallback, MutableRefObject } from 'react';
import { useNetworkStore } from '../stores/networkStore';
import { usePhysicsStore } from '../stores/physicsStore';
import { useSettingsStore } from '../stores/settingsStore';
import { usePinStore } from '../stores/pinStore';
import { useSizeStore } from '../stores/sizeStore';

export interface LayoutNode {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  homeX: number;
  homeY: number;
  radius: number;
  effectiveRadius: number;
  color: string;
  highlightColor: string;
  alpha: number;
  lastActive: number;
}

export interface LayoutEdge {
  id: string;
  sourceId: string;
  targetId: string;
  color: string;
  protocol?: string;
  dstPort?: number;
  alpha: number;
  weight: number;
  lastActive: number;
}

export interface GraphLayoutResult {
  layoutNodes: MutableRefObject<Map<string, LayoutNode>>;
  layoutEdges: MutableRefObject<LayoutEdge[]>;
  tick: (now: number) => void;
}

const PHYSICS_HZ = 30;
const PHYSICS_STEP = 1000 / PHYSICS_HZ;
const NODE_RADIUS = 10;
const QUIET_EDGE_PADDING = 120;
const CLUSTER_RADIUS = 110;

function getProtocolColor(protocol?: string): string {
  switch (protocol?.toLowerCase()) {
    case 'tcp': return '#00FF00';
    case 'udp': return '#FF00FF';
    case 'icmp': return '#FFFF00';
    case 'http':
    case 'https': return '#FFA500';
    default: return '#CCCCCC';
  }
}

function hslToHex(h: number, s: number, l: number): string {
  h /= 360; s /= 100; l /= 100;
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const x = c * (1 - Math.abs((h * 6) % 2 - 1));
  const m = l - c / 2;
  let r = 0, g = 0, b = 0;
  if (h < 1 / 6) { r = c; g = x; b = 0; }
  else if (h < 2 / 6) { r = x; g = c; b = 0; }
  else if (h < 3 / 6) { r = 0; g = c; b = x; }
  else if (h < 4 / 6) { r = 0; g = x; b = c; }
  else if (h < 5 / 6) { r = x; g = 0; b = c; }
  else { r = c; g = 0; b = x; }
  const toHex = (v: number) => Math.round((v + m) * 255).toString(16).padStart(2, '0');
  return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
}

function getHighlightColor(id: string): string {
  if (id.includes('.')) {
    const parts = id.split('.').map(Number);
    if (parts.length === 4 && parts.every(p => !Number.isNaN(p) && p >= 0 && p <= 255)) {
      const [a] = parts;
      if (a === 192) return '#0080ff';
      if (a === 10) return '#ff00ff';
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

function hashStr(s: string): number {
  let hash = 0;
  for (let i = 0; i < s.length; i++) {
    hash = ((hash << 5) - hash) + s.charCodeAt(i);
    hash = hash & hash;
  }
  return Math.abs(hash);
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

// Deterministic home position: same IP always lands in the same spot, clustered
// by subnet. This is what keeps the layout stable — membership and physics can
// churn, but every node is anchored to a fixed home it returns to.
function getHomeAnchor(id: string, width: number, height: number): { x: number; y: number } {
  const key = getClusterKey(id);
  const h = hashStr(key);
  const clusterX = width * (0.14 + 0.72 * ((h % 997) / 997));
  const clusterY = height * (0.14 + 0.72 * (((h >> 10) % 991) / 991));
  const nh = hashStr(id);
  const angle = (nh % 360) * Math.PI / 180;
  const dist = ((nh >> 9) % 100) / 100 * CLUSTER_RADIUS;
  return {
    x: clusterX + Math.cos(angle) * dist,
    y: clusterY + Math.sin(angle) * dist,
  };
}

export function useGraphLayout(): GraphLayoutResult {
  const layoutNodes = useRef<Map<string, LayoutNode>>(new Map());
  const layoutEdges = useRef<LayoutEdge[]>([]);
  const lastTickTime = useRef<number>(0);
  const accumulator = useRef<number>(0);
  const syncCountdown = useRef<number>(0);
  const physicsRef = useRef(usePhysicsStore.getState());
  const viewportRef = useRef({ width: 0, height: 0 });

  useEffect(() => {
    if (import.meta.env.DEV) {
      (window as any).__VIBES_LAYOUT = { nodes: layoutNodes, edges: layoutEdges };
      (window as any).__VIBES_STORE = useNetworkStore;
    }
    const { width, height } = useSizeStore.getState();
    viewportRef.current = { width, height };
    const unsubPhysics = usePhysicsStore.subscribe(s => { physicsRef.current = s; });
    const unsubSize = useSizeStore.subscribe(s => {
      viewportRef.current = { width: s.width, height: s.height };
    });
    return () => {
      unsubPhysics();
      unsubSize();
    };
  }, []);

  const deltaSync = useCallback(() => {
    const { nodes: storeNodes, connections: storeConns } = useNetworkStore.getState();
    const { maxNodes, maxConnectionsPerNode } = useSettingsStore.getState();
    const { connectionLifetime } = physicsRef.current;
    const now = Date.now();
    const vp = viewportRef.current;
    const width = vp.width || 1280;
    const height = vp.height || 800;

    const storeById = new Map(storeNodes.map(n => [n.id, n]));

    // Membership hysteresis: a node leaves only when the store drops it or it
    // expires (tickLayout). Never evict by activity rank — rank churn is what
    // made the old layout teleport.
    for (const id of layoutNodes.current.keys()) {
      if (!storeById.has(id)) layoutNodes.current.delete(id);
    }

    // Refresh nodes already in the layout from their store counterparts.
    layoutNodes.current.forEach(node => {
      const sn = storeById.get(node.id);
      if (sn) node.lastActive = sn.lastActive;
    });

    // Live connections, heaviest first. Weight is a decayed packet/byte EWMA
    // from networkStore — priority only, never a hard visibility threshold.
    // Edges already on screen get a sticky bonus so near-equal-weight flows
    // don't swap budget slots every sync. Priority is computed once per conn
    // (decorate-sort) — doing it inside the comparator is a hot-loop killer at
    // firehose connection counts.
    const currentEdgeKeys = new Set(layoutEdges.current.map(e => e.id));
    const candidateConns = storeConns
      .filter(c =>
        storeById.has(c.source) &&
        storeById.has(c.target) &&
        now - c.lastActive <= connectionLifetime
      )
      .map(c => ({ c, p: (c.weight ?? 1) + (currentEdgeKeys.has(c.id) ? 2 : 0) }))
      .sort((a, b) => b.p - a.p || b.c.lastActive - a.c.lastActive)
      .map(({ c }) => c);

    const maxTopologyEdges = Math.max(40, Math.floor(maxNodes * 2.4));
    const nodeBudget = new Map<string, number>();
    const visibleConns: typeof candidateConns = [];
    for (const c of candidateConns) {
      if (visibleConns.length >= maxTopologyEdges) break;
      const s = nodeBudget.get(c.source) ?? 0;
      const t = nodeBudget.get(c.target) ?? 0;
      if (s >= maxConnectionsPerNode || t >= maxConnectionsPerNode) continue;
      nodeBudget.set(c.source, s + 1);
      nodeBudget.set(c.target, t + 1);
      visibleConns.push(c);
    }

    // Admit new nodes in edge-weight order while there is room. Spawn at the
    // node's deterministic home anchor so a returning IP reappears where it was.
    for (const c of visibleConns) {
      for (const id of [c.source, c.target]) {
        if (layoutNodes.current.has(id)) continue;
        if (layoutNodes.current.size >= maxNodes) break;
        const sn = storeById.get(id)!;
        const home = getHomeAnchor(id, width, height);
        layoutNodes.current.set(id, {
          id,
          x: home.x + (Math.random() - 0.5) * 30,
          y: home.y + (Math.random() - 0.5) * 30,
          vx: 0,
          vy: 0,
          homeX: home.x,
          homeY: home.y,
          radius: NODE_RADIUS,
          effectiveRadius: NODE_RADIUS,
          color: getProtocolColor(c.protocol),
          highlightColor: getHighlightColor(id),
          alpha: 1,
          lastActive: sn.lastActive,
        });
      }
    }

    layoutEdges.current = visibleConns
      .filter(c =>
        layoutNodes.current.has(c.source) &&
        layoutNodes.current.has(c.target)
      )
      .map(c => ({
        id: c.id,
        sourceId: c.source,
        targetId: c.target,
        color: c.packetColor ?? getProtocolColor(c.protocol),
        protocol: c.protocol,
        dstPort: c.dstPort,
        alpha: Math.max(0, 1 - (now - c.lastActive) / connectionLifetime),
        weight: c.weight ?? 1,
        lastActive: c.lastActive,
      }));
  }, []);

  const tickLayout = useCallback((dt: number) => {
    const dtNorm = dt / 16.67;
    const {
      nodeSpacing,
      connectionPullStrength,
      collisionRepulsion,
      damping,
      connectionLifetime,
      nodeLifetime,
      driftAwayStrength,
      centerPullStrength,
      springRestLength,
    } = physicsRef.current;

    const { isPined } = usePinStore.getState();
    const vp = viewportRef.current;
    const centerX = (vp.width || 1280) / 2;
    const centerY = (vp.height || 800) / 2;
    const now = Date.now();
    const retain = Math.pow(Math.max(0, 1 - damping), dtNorm);
    const maxVelocity = 18;

    const connectedIds = new Set<string>();
    layoutEdges.current.forEach(edge => {
      if (now - edge.lastActive <= connectionLifetime) {
        connectedIds.add(edge.sourceId);
        connectedIds.add(edge.targetId);
      }
    });

    const pinnedList = Array.from(layoutNodes.current.values())
      .filter(n => isPined(n.id))
      .sort((a, b) => a.id.localeCompare(b.id));
    pinnedList.forEach((node, i) => {
      const col = Math.floor(i / 18);
      node.x = (vp.width || 1280) - 100 - col * 200;
      node.y = 100 + (i % 18) * 50;
      node.vx = 0;
      node.vy = 0;
    });

    const toRemove: string[] = [];
    layoutNodes.current.forEach(node => {
      if (isPined(node.id)) return;

      const age = now - node.lastActive;
      if (age > nodeLifetime) {
        toRemove.push(node.id);
        return;
      }

      const offscreen = node.x < -250 || node.x > (vp.width || 1280) + 250 ||
        node.y < -250 || node.y > (vp.height || 800) + 250;
      if (offscreen) {
        toRemove.push(node.id);
        return;
      }

      if (connectedIds.has(node.id)) {
        node.alpha = 1;
      } else {
        const fadeAge = Math.max(0, age - connectionLifetime);
        const fadeWindow = Math.max(1, nodeLifetime - connectionLifetime);
        node.alpha = Math.max(0, 1 - fadeAge / fadeWindow);

        const dx = node.x - centerX;
        const dy = node.y - centerY;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const targetDist = Math.max(vp.width || 1280, vp.height || 800) * 0.5 + QUIET_EDGE_PADDING;
        const remaining = Math.max(250, nodeLifetime - age);
        const desiredStep = Math.max(0.8, (targetDist - dist) / (remaining / PHYSICS_STEP));
        node.vx += (dx / dist) * driftAwayStrength * desiredStep * 0.12 * dtNorm;
        node.vy += (dy / dist) * driftAwayStrength * desiredStep * 0.12 * dtNorm;
      }
    });

    toRemove.forEach(id => {
      layoutNodes.current.delete(id);
      useNetworkStore.getState().removeNode(id);
    });

    const nodes = Array.from(layoutNodes.current.values());
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];
        if (isPined(a.id) && isPined(b.id)) continue;

        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const minDist = a.effectiveRadius + b.effectiveRadius + nodeSpacing;
        const softDist = minDist * 1.6;
        if (Math.abs(dx) > softDist || Math.abs(dy) > softDist) continue;

        const dist = Math.sqrt(dx * dx + dy * dy) || 0.001;
        if (dist >= softDist) continue;

        const strength = dist < minDist
          ? collisionRepulsion * 0.65 * (minDist - dist) / dist
          : collisionRepulsion * 0.08 * (softDist - dist) / dist;
        const push = strength * dtNorm;

        if (!isPined(a.id)) {
          a.vx -= dx * push;
          a.vy -= dy * push;
        }
        if (!isPined(b.id)) {
          b.vx += dx * push;
          b.vy += dy * push;
        }

        if (dist < minDist) {
          const nx = dx / dist;
          const ny = dy / dist;
          const correction = Math.min((minDist - dist) * 0.5, 10);
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

    const liveDegree = new Map<string, number>();
    layoutEdges.current.forEach(edge => {
      if (now - edge.lastActive > connectionLifetime) return;
      liveDegree.set(edge.sourceId, (liveDegree.get(edge.sourceId) ?? 0) + 1);
      liveDegree.set(edge.targetId, (liveDegree.get(edge.targetId) ?? 0) + 1);
    });

    layoutEdges.current.forEach(edge => {
      if (now - edge.lastActive > connectionLifetime) return;

      const source = layoutNodes.current.get(edge.sourceId);
      const target = layoutNodes.current.get(edge.targetId);
      if (!source || !target) return;

      const dx = target.x - source.x;
      const dy = target.y - source.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 0.001;
      const edgeDegree = Math.max(liveDegree.get(source.id) ?? 1, liveDegree.get(target.id) ?? 1);
      const degreeResponse = Math.max(0.18, Math.min(1, Math.sqrt(8 / edgeDegree)));
      const weightResponse = Math.max(0.65, Math.min(1.6, Math.sqrt(edge.weight)));
      const restLength = Math.max(45, springRestLength - Math.min(35, edge.weight * 4));
      // Clamped so a cross-cluster edge tugs gently instead of dragging its
      // endpoints off their anchors — anchor gravity must stay the backbone.
      const displacement = Math.max(-80, Math.min(80, dist - restLength));
      const spring = connectionPullStrength * 0.002 * weightResponse * degreeResponse * displacement * dtNorm;
      const nx = dx / dist;
      const ny = dy / dist;

      if (!isPined(source.id)) {
        source.vx += nx * spring;
        source.vy += ny * spring;
      }
      if (!isPined(target.id)) {
        target.vx -= nx * spring;
        target.vy -= ny * spring;
      }
    });

    // Anchor gravity: every connected node is pulled toward its deterministic
    // subnet home, not the screen center — this is the layout's backbone.
    layoutNodes.current.forEach(node => {
      if (isPined(node.id) || !connectedIds.has(node.id)) return;
      const anchorPull = Math.max(centerPullStrength, 0.008);
      node.vx += (node.homeX - node.x) * anchorPull * dtNorm;
      node.vy += (node.homeY - node.y) * anchorPull * dtNorm;
    });

    const edgeMargin = 40;
    layoutNodes.current.forEach(node => {
      if (isPined(node.id)) return;
      node.vx *= retain;
      node.vy *= retain;
      node.vx = Math.max(-maxVelocity, Math.min(maxVelocity, node.vx));
      node.vy = Math.max(-maxVelocity, Math.min(maxVelocity, node.vy));
      node.x += node.vx * dtNorm;
      node.y += node.vy * dtNorm;

      const width = vp.width || 1280;
      const height = vp.height || 800;
      if (node.x < edgeMargin) node.vx += (edgeMargin - node.x) * 0.15 * dtNorm;
      if (node.x > width - edgeMargin) node.vx -= (node.x - (width - edgeMargin)) * 0.15 * dtNorm;
      if (node.y < edgeMargin) node.vy += (edgeMargin - node.y) * 0.15 * dtNorm;
      if (node.y > height - edgeMargin) node.vy -= (node.y - (height - edgeMargin)) * 0.15 * dtNorm;
    });
  }, []);

  const tick = useCallback((now: number) => {
    const rawDelta = lastTickTime.current > 0 ? now - lastTickTime.current : 16;
    lastTickTime.current = now;
    accumulator.current += Math.min(rawDelta, 100);

    while (accumulator.current >= PHYSICS_STEP) {
      // Membership/edge sync scans the whole connection store — ~10 Hz is
      // imperceptible (edge alpha fades over seconds) and keeps the 30 Hz
      // physics steps cheap at firehose connection counts.
      syncCountdown.current -= 1;
      if (syncCountdown.current <= 0) {
        deltaSync();
        syncCountdown.current = 3;
      }
      tickLayout(PHYSICS_STEP);
      accumulator.current -= PHYSICS_STEP;
    }
  }, [deltaSync, tickLayout]);

  return { layoutNodes, layoutEdges, tick };
}
