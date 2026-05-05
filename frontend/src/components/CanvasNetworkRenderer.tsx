import React, { useEffect, useRef, useCallback } from 'react';
import { useSizeStore } from '../stores/sizeStore';
import { useGraphLayout } from '../hooks/useGraphLayout';

export const CanvasNetworkRenderer: React.FC = React.memo(() => {
  const canvasRef    = useRef<HTMLCanvasElement>(null);
  const animationRef = useRef<number>();
  const viewportRef  = useRef({ x: 0, y: 0, zoom: 1.0, width: 0, height: 0 });
  const frameCount   = useRef(0);
  const lastFpsTime  = useRef(0);
  const fpsRef       = useRef(0);

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
      fpsRef.current     = frameCount.current;
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
    const bridgePairBudget = new Map<string, number>();
    const drawnEdges = edges.filter(edge => {
      if (edge.alpha <= 0) return false;
      if (vp.zoom < 1.2) {
        if (edge.rank > 12) return false;
        if (edge.isBridge) {
          const count = bridgePairBudget.get(edge.clusterPair) ?? 0;
          if (count >= 2) return false;
          bridgePairBudget.set(edge.clusterPair, count + 1);
        }
      }
      return true;
    });

    const edgeDegree = new Map<string, number>();
    const connectedIds = new Set<string>();
    edges.forEach(edge => {
      if (edge.alpha <= 0) return;
      connectedIds.add(edge.sourceId);
      connectedIds.add(edge.targetId);
    });
    drawnEdges.forEach(edge => {
      edgeDegree.set(edge.sourceId, (edgeDegree.get(edge.sourceId) ?? 0) + 1);
      edgeDegree.set(edge.targetId, (edgeDegree.get(edge.targetId) ?? 0) + 1);
    });

    // ── Draw edges ──────────────────────────────────────────────────────────
    drawnEdges.forEach(edge => {
      const src = nodes.get(edge.sourceId);
      const tgt = nodes.get(edge.targetId);
      if (!src || !tgt || edge.alpha <= 0) return;

      const proto = edge.protocol?.toLowerCase() ?? '';
      const degree = Math.max(edgeDegree.get(edge.sourceId) ?? 1, edgeDegree.get(edge.targetId) ?? 1);
      const degreeAlpha = Math.max(0.45, Math.min(1, Math.sqrt(18 / degree)));
      const edgeAlpha = edge.alpha * degreeAlpha * (edge.isBridge ? 0.7 : 1);
      let strokeColor = `rgba(0,255,255,${edgeAlpha})`;
      let lineWidth = 1;
      if      (proto === 'tcp')                       { strokeColor = `rgba(0,255,0,${edgeAlpha})`;   lineWidth = edge.isBridge ? 1 : 2; }
      else if (proto === 'udp')                       { strokeColor = `rgba(255,0,255,${edgeAlpha})`; lineWidth = edge.isBridge ? 1 : 2; }
      else if (proto === 'icmp')                      { strokeColor = `rgba(255,255,0,${edgeAlpha})`; lineWidth = 1; }
      else if (proto === 'http' || proto === 'https') { strokeColor = `rgba(255,165,0,${edgeAlpha})`; lineWidth = edge.isBridge ? 1 : 2; }

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
    const labelBoxes: Array<{ x1: number; y1: number; x2: number; y2: number }> = [];
    nodes.forEach(node => {
      if (node.alpha <= 0) return;

      const hr = parseInt(node.highlightColor.slice(1, 3), 16);
      const hg = parseInt(node.highlightColor.slice(3, 5), 16);
      const hb = parseInt(node.highlightColor.slice(5, 7), 16);
      const isConnected = connectedIds.has(node.id);
      const visualAlpha = isConnected ? node.alpha : node.alpha * 0.35;

      // Glow ring for active nodes
      if (node.radius > 7 && isConnected) {
        ctx.fillStyle = `rgba(${hr},${hg},${hb},${visualAlpha * 0.3})`;
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius * 1.5, 0, Math.PI * 2);
        ctx.fill();
      }

      // Node body
      ctx.globalAlpha = visualAlpha;
      ctx.fillStyle   = node.color;
      ctx.beginPath();
      ctx.arc(node.x, node.y, isConnected ? node.radius : node.radius * 0.7, 0, Math.PI * 2);
      ctx.fill();
      ctx.globalAlpha = 1;

      // IP labels are a zoomed-in detail. Drawing every label at overview scale
      // turns dense traffic into text noise and hides the topology.
      if (isConnected && node.id.includes('.') && vp.zoom >= 0.95) {
        const fontSize = Math.max(11, 13 * vp.zoom);
        ctx.font      = `${fontSize}px monospace`;
        ctx.textAlign = 'center';
        const textY = node.y + node.radius + fontSize + 2;
        const tw    = ctx.measureText(node.id).width;
        const labelBox = {
          x1: node.x - tw / 2 - 4,
          y1: textY - fontSize - 2,
          x2: node.x + tw / 2 + 4,
          y2: textY + 4,
        };
        const overlapsLabel = labelBoxes.some(box =>
          labelBox.x1 < box.x2 &&
          labelBox.x2 > box.x1 &&
          labelBox.y1 < box.y2 &&
          labelBox.y2 > box.y1
        );
        if (overlapsLabel && vp.zoom < 1.4) return;
        labelBoxes.push(labelBox);
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
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'r' || e.key === 'R') { viewportRef.current.x = 0; viewportRef.current.y = 0; viewportRef.current.zoom = 1; }
    };

    canvas.addEventListener('mousedown',  onDown);
    canvas.addEventListener('mousemove',  onMove);
    canvas.addEventListener('mouseup',    onUp);
    canvas.addEventListener('mouseleave', onUp);
    canvas.addEventListener('wheel',      onWheel, { passive: false });
    document.addEventListener('keydown',  onKey);
    canvas.style.cursor = 'grab';
    canvas.tabIndex = 0;

    return () => {
      canvas.removeEventListener('mousedown',  onDown);
      canvas.removeEventListener('mousemove',  onMove);
      canvas.removeEventListener('mouseup',    onUp);
      canvas.removeEventListener('mouseleave', onUp);
      canvas.removeEventListener('wheel',      onWheel);
      document.removeEventListener('keydown',  onKey);
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
