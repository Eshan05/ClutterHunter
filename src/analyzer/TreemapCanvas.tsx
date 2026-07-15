import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { ZoomIn, ZoomOut, RotateCcw } from "lucide-react";
import type { TreemapNode } from "../bindings/TreemapNode";
import { layoutTreemap, treemapColor, type TreemapRect } from "./treemap";

interface TreemapCanvasProps {
  nodes: TreemapNode[];
  selectedId: string | null;
  onSelect: (node: TreemapNode) => void;
  onOpen: (node: TreemapNode) => void;
  onHoverItem?: (node: TreemapNode | null, rect: DOMRect | null) => void;
  formatBytes: (value: string) => string;
}

export function TreemapCanvas({
  nodes,
  selectedId,
  onSelect,
  onOpen,
  onHoverItem,
  formatBytes,
}: TreemapCanvasProps) {
  const hostRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });
  const [hovered, setHovered] = useState<TreemapRect | null>(null);

  // Zoom and Pan Viewport State
  const [zoom, setZoom] = useState<number>(1.0);
  const [offset, setOffset] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState<boolean>(false);
  const panStartRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const touchDistanceRef = useRef<number | null>(null);

  const rects = useMemo(
    () => layoutTreemap(nodes, size.width, size.height),
    [nodes, size],
  );

  // Reset zoom & pan when nodes change
  useEffect(() => {
    setZoom(1.0);
    setOffset({ x: 0, y: 0 });
  }, [nodes]);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const measure = () => setSize({ width: host.clientWidth, height: host.clientHeight });
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(host);
    return () => observer.disconnect();
  }, []);

  // Zoom center calculation helper
  const handleZoomAtPoint = useCallback((factor: number, clientX: number, clientY: number) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const bounds = canvas.getBoundingClientRect();
    const cursorX = clientX - bounds.left;
    const cursorY = clientY - bounds.top;

    setZoom((prevZoom) => {
      const nextZoom = Math.min(10.0, Math.max(1.0, prevZoom * factor));
      if (nextZoom === 1.0) {
        setOffset({ x: 0, y: 0 });
        return 1.0;
      }
      setOffset((prevOffset) => ({
        x: cursorX - ((cursorX - prevOffset.x) * nextZoom) / prevZoom,
        y: cursorY - ((cursorY - prevOffset.y) * nextZoom) / prevZoom,
      }));
      return nextZoom;
    });
  }, []);

  // Native wheel listener for smooth pinch & trackpad zoom
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.15 : 0.87;
      handleZoomAtPoint(zoomFactor, e.clientX, e.clientY);
    };

    canvas.addEventListener("wheel", onWheel, { passive: false });
    return () => canvas.removeEventListener("wheel", onWheel);
  }, [handleZoomAtPoint]);

  // Touch handlers for multi-touch pinch zoom
  const handleTouchStart = (e: React.TouchEvent<HTMLCanvasElement>) => {
    if (e.touches.length === 2) {
      const dist = Math.hypot(
        e.touches[0].clientX - e.touches[1].clientX,
        e.touches[0].clientY - e.touches[1].clientY,
      );
      touchDistanceRef.current = dist;
    }
  };

  const handleTouchMove = (e: React.TouchEvent<HTMLCanvasElement>) => {
    if (e.touches.length === 2 && touchDistanceRef.current !== null) {
      const newDist = Math.hypot(
        e.touches[0].clientX - e.touches[1].clientX,
        e.touches[0].clientY - e.touches[1].clientY,
      );
      const factor = newDist / touchDistanceRef.current;
      const centerX = (e.touches[0].clientX + e.touches[1].clientX) / 2;
      const centerY = (e.touches[0].clientY + e.touches[1].clientY) / 2;
      handleZoomAtPoint(factor, centerX, centerY);
      touchDistanceRef.current = newDist;
    }
  };

  const handleTouchEnd = () => {
    touchDistanceRef.current = null;
  };

  // Convert Screen Coordinates -> Local Untransformed Treemap Rect Space
  const hitTest = useCallback(
    (clientX: number, clientY: number, canvas: HTMLCanvasElement): TreemapRect | null => {
      const bounds = canvas.getBoundingClientRect();
      const screenX = clientX - bounds.left;
      const screenY = clientY - bounds.top;

      const localX = (screenX - offset.x) / zoom;
      const localY = (screenY - offset.y) / zoom;

      return (
        rects.find(
          (rect) =>
            localX >= rect.x &&
            localX <= rect.x + rect.width &&
            localY >= rect.y &&
            localY <= rect.y + rect.height,
        ) ?? null
      );
    },
    [offset, rects, zoom],
  );

  // Render Canvas with Viewport Transform and Adaptive Text Formatting
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || size.width <= 0 || size.height <= 0) return;
    const ratio = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, Math.floor(size.width * ratio));
    canvas.height = Math.max(1, Math.floor(size.height * ratio));
    canvas.style.width = `${size.width}px`;
    canvas.style.height = `${size.height}px`;

    const context = canvas.getContext("2d");
    if (!context) return;

    // Apply hardware transform (devicePixelRatio * zoom, plus offset panning)
    context.setTransform(ratio * zoom, 0, 0, ratio * zoom, offset.x * ratio, offset.y * ratio);
    context.clearRect(-offset.x / zoom, -offset.y / zoom, size.width / zoom, size.height / zoom);

    for (const rect of rects) {
      // Draw background box
      context.fillStyle = treemapColor(rect.node);
      context.fillRect(rect.x, rect.y, rect.width, rect.height);

      // Selection & Hover Highlights
      const isSelected = rect.node.id === selectedId;
      const isHovered = hovered?.node.id === rect.node.id;

      context.strokeStyle = isSelected ? "#8ce1cb" : isHovered ? "#60a5fa" : "#111512";
      context.lineWidth = (isSelected || isHovered ? 2 : 1) / zoom;
      context.strokeRect(rect.x + 0.5 / zoom, rect.y + 0.5 / zoom, Math.max(0, rect.width - 1 / zoom), Math.max(0, rect.height - 1 / zoom));

      // Effective size on screen
      const effectiveW = rect.width * zoom;
      const effectiveH = rect.height * zoom;

      // Adaptive text size rendering with zero clutter
      if (effectiveW > 45 && effectiveH > 22) {
        context.save();
        context.beginPath();
        context.rect(rect.x + 3 / zoom, rect.y + 3 / zoom, Math.max(0, rect.width - 6 / zoom), Math.max(0, rect.height - 6 / zoom));
        context.clip();

        // Node Title
        context.fillStyle = "#ffffff";
        context.font = `${Math.max(9, Math.min(13, 11))}px "Segoe UI", system-ui, sans-serif`;
        context.textBaseline = "top";
        context.fillText(rect.node.name, rect.x + 4 / zoom, rect.y + 4 / zoom, Math.max(0, rect.width - 8 / zoom));

        // Allocated Byte Size
        if (effectiveW > 60 && effectiveH > 36) {
          context.fillStyle = "#a8c0b5";
          context.font = `9px "Segoe UI", system-ui, sans-serif`;
          context.fillText(formatBytes(rect.node.allocated_bytes), rect.x + 4 / zoom, rect.y + 18 / zoom);
        }

        // Policy tier tag when zoomed in
        if (effectiveW > 110 && effectiveH > 52) {
          context.fillStyle = rect.node.policy_tier === "cleanup_candidate" ? "#f87171" : "#60a5fa";
          context.font = `8px monospace`;
          context.fillText(`[${rect.node.policy_tier.toUpperCase()}]`, rect.x + 4 / zoom, rect.y + 31 / zoom);
        }

        context.restore();
      }
    }
  }, [formatBytes, hovered, offset, rects, selectedId, size, zoom]);

  // Mouse Pan Handlers
  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (e.button === 0 && zoom > 1.0) {
      setIsPanning(true);
      panStartRef.current = { x: e.clientX - offset.x, y: e.clientY - offset.y };
    }
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (isPanning) {
      setOffset({
        x: e.clientX - panStartRef.current.x,
        y: e.clientY - panStartRef.current.y,
      });
      return;
    }

    const hit = hitTest(e.clientX, e.clientY, e.currentTarget);
    setHovered(hit);
    if (onHoverItem) {
      onHoverItem(hit ? hit.node : null, hit ? e.currentTarget.getBoundingClientRect() : null);
    }
  };

  const handleMouseUp = () => {
    setIsPanning(false);
  };

  return (
    <div ref={hostRef} className="treemap-canvas-host relative">
      {/* Dynamic Floating Zoom Bar Controls */}
      <div className="absolute top-2 right-2 z-30 flex items-center gap-1 bg-[#151d18]/90 backdrop-blur-md border border-[#2b3a32] p-1 rounded-md shadow-lg text-[10px]">
        <button
          type="button"
          onClick={() => {
            const canvas = canvasRef.current;
            if (!canvas) return;
            const b = canvas.getBoundingClientRect();
            handleZoomAtPoint(1.25, b.left + b.width / 2, b.top + b.height / 2);
          }}
          className="p-1 hover:bg-[#25332b] rounded text-[#8ce1cb] transition-colors"
          title="Zoom In (or double click / pinch)"
        >
          <ZoomIn size={13} />
        </button>
        <span className="font-mono font-bold text-[#b8dfd5] px-1 min-w-[34px] text-center select-none">
          {Math.round(zoom * 100)}%
        </span>
        <button
          type="button"
          onClick={() => {
            const canvas = canvasRef.current;
            if (!canvas) return;
            const b = canvas.getBoundingClientRect();
            handleZoomAtPoint(0.8, b.left + b.width / 2, b.top + b.height / 2);
          }}
          className="p-1 hover:bg-[#25332b] rounded text-[#8ce1cb] transition-colors"
          title="Zoom Out (or scroll down / pinch)"
        >
          <ZoomOut size={13} />
        </button>
        {zoom > 1.0 && (
          <button
            type="button"
            onClick={() => {
              setZoom(1.0);
              setOffset({ x: 0, y: 0 });
            }}
            className="p-1 hover:bg-[#25332b] rounded text-[#e0a899] transition-colors ml-1"
            title="Reset Zoom to 100%"
          >
            <RotateCcw size={12} />
          </button>
        )}
      </div>

      <canvas
        ref={canvasRef}
        aria-label="Storage treemap"
        className={isPanning ? "cursor-grabbing" : zoom > 1.0 ? "cursor-grab" : "cursor-pointer"}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={() => {
          setIsPanning(false);
          setHovered(null);
          if (onHoverItem) onHoverItem(null, null);
        }}
        onTouchStart={handleTouchStart}
        onTouchMove={handleTouchMove}
        onTouchEnd={handleTouchEnd}
        onClick={(event) => {
          if (isPanning) return;
          const hit = hitTest(event.clientX, event.clientY, event.currentTarget);
          if (hit && !hit.node.synthetic) onSelect(hit.node);
        }}
        onDoubleClick={(event) => {
          const hit = hitTest(event.clientX, event.clientY, event.currentTarget);
          if (hit && hit.node.kind === "directory" && !hit.node.synthetic) onOpen(hit.node);
        }}
      />
      {hovered && (
        <div className="treemap-tooltip">
          <strong>{hovered.node.name}</strong>
          <span>{formatBytes(hovered.node.allocated_bytes)}</span>
        </div>
      )}
    </div>
  );
}
