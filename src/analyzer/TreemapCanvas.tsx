import { useEffect, useMemo, useRef, useState } from "react";
import type { TreemapNode } from "../bindings/TreemapNode";
import { layoutTreemap, treemapColor, type TreemapRect } from "./treemap";

interface TreemapCanvasProps {
  nodes: TreemapNode[];
  selectedId: string | null;
  onSelect: (node: TreemapNode) => void;
  onOpen: (node: TreemapNode) => void;
  formatBytes: (value: string) => string;
}

export function TreemapCanvas({
  nodes,
  selectedId,
  onSelect,
  onOpen,
  formatBytes,
}: TreemapCanvasProps) {
  const hostRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });
  const [hovered, setHovered] = useState<TreemapRect | null>(null);
  const rects = useMemo(
    () => layoutTreemap(nodes, size.width, size.height),
    [nodes, size],
  );

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const measure = () => setSize({ width: host.clientWidth, height: host.clientHeight });
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(host);
    return () => observer.disconnect();
  }, []);

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
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    context.clearRect(0, 0, size.width, size.height);
    context.font = "11px Segoe UI";
    context.textBaseline = "top";
    for (const rect of rects) {
      context.fillStyle = treemapColor(rect.node);
      context.fillRect(rect.x, rect.y, rect.width, rect.height);
      context.strokeStyle = rect.node.id === selectedId ? "#bdf5e6" : "#111512";
      context.lineWidth = rect.node.id === selectedId ? 2 : 1;
      context.strokeRect(rect.x + 0.5, rect.y + 0.5, Math.max(0, rect.width - 1), Math.max(0, rect.height - 1));
      if (rect.width > 62 && rect.height > 32) {
        context.save();
        context.beginPath();
        context.rect(rect.x + 4, rect.y + 4, Math.max(0, rect.width - 8), Math.max(0, rect.height - 8));
        context.clip();
        context.fillStyle = "#f0f4f1";
        context.fillText(rect.node.name, rect.x + 5, rect.y + 5, Math.max(0, rect.width - 10));
        context.fillStyle = "#d3ddd7";
        context.font = "10px Segoe UI";
        context.fillText(formatBytes(rect.node.allocated_bytes), rect.x + 5, rect.y + 20);
        context.restore();
        context.font = "11px Segoe UI";
      }
    }
  }, [formatBytes, rects, selectedId, size]);

  const hitTest = (event: React.MouseEvent<HTMLCanvasElement>) => {
    const bounds = event.currentTarget.getBoundingClientRect();
    const x = event.clientX - bounds.left;
    const y = event.clientY - bounds.top;
    return rects.find((rect) =>
      x >= rect.x && x <= rect.x + rect.width && y >= rect.y && y <= rect.y + rect.height) ?? null;
  };

  return (
    <div ref={hostRef} className="treemap-canvas-host">
      <canvas
        ref={canvasRef}
        aria-label="Storage treemap"
        onPointerMove={(event) => setHovered(hitTest(event))}
        onPointerLeave={() => setHovered(null)}
        onClick={(event) => {
          const hit = hitTest(event);
          if (hit && !hit.node.synthetic) onSelect(hit.node);
        }}
        onDoubleClick={(event) => {
          const hit = hitTest(event);
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
