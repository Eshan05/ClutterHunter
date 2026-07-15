import { TreeMap, type NodeProps, type TooltipProps } from "@nivo/treemap";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { TreemapNode } from "../bindings/TreemapNode";
import { buildTreemapHierarchy, type StorageTreemapDatum } from "./treemap";

interface TreemapCanvasProps {
  nodes: TreemapNode[];
  omittedAllocatedBytes: string;
  scopeName: string;
  scopePath: string;
  selectedId: string | null;
  onSelect: (node: TreemapNode) => void;
  onOpen: (node: TreemapNode) => void;
  formatBytes: (value: string) => string;
}

export function TreemapCanvas({
  nodes,
  omittedAllocatedBytes,
  scopeName,
  scopePath,
  selectedId,
  onSelect,
  onOpen,
  formatBytes,
}: TreemapCanvasProps) {
  const hostRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });
  const [hovered, setHovered] = useState<StorageTreemapDatum | null>(null);
  const data = useMemo(
    () => buildTreemapHierarchy(nodes, omittedAllocatedBytes),
    [nodes, omittedAllocatedBytes],
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

  const hoveredAncestors = useMemo(() => new Set(hovered?.ancestorIds ?? []), [hovered]);
  const renderNode = useCallback(
    ({ node }: NodeProps<StorageTreemapDatum>) => {
      const item = node.data;
      const isRoot = node.treeDepth === 0;
      const isHovered = item.id === hovered?.id;
      const isHoveredAncestor = hoveredAncestors.has(item.id);
      const isSelected = item.node?.id === selectedId;
      const outline = isHovered
        ? "#ffffff"
        : isSelected
        ? "#d9fff4"
        : isHoveredAncestor
        ? "rgba(209, 255, 242, 0.72)"
        : node.isParent
        ? "rgba(7, 10, 8, 0.72)"
        : "none";
      const outlineWidth = isHovered ? 2.5 : isSelected ? 2 : isHoveredAncestor ? 1.5 : 0.75;
      const parentLabel = fitSvgText(
        `${item.name} (${formatBytes(item.allocatedBytes)})`,
        node.width - 10,
        10,
      );
      const leafLabel = fitSvgText(item.name, node.width - 8, 10);

      return (
        <g
          transform={`translate(${node.x},${node.y})`}
          onMouseEnter={node.onMouseEnter}
          onMouseMove={node.onMouseMove}
          onMouseLeave={node.onMouseLeave}
          onClick={node.onClick}
          onDoubleClick={() => {
            if (item.node?.kind === "directory") onOpen(item.node);
          }}
          style={{ cursor: isRoot ? "default" : "crosshair" }}
        >
          <rect
            width={Math.max(0, node.width)}
            height={Math.max(0, node.height)}
            fill={isRoot ? "#111512" : node.color}
            fillOpacity={isHovered && node.isLeaf ? 0.9 : 1}
            stroke={outline}
            strokeWidth={outlineWidth}
            vectorEffect="non-scaling-stroke"
            pointerEvents={isRoot ? "none" : "all"}
          />
          {node.isParent && !isRoot && node.width >= 72 && node.height >= 25 && (
            <g pointerEvents="none">
              <rect
                x={2}
                y={2}
                width={Math.max(0, node.width - 4)}
                height={15}
                fill={isHovered || isHoveredAncestor ? "rgba(24, 48, 40, .95)" : "rgba(17, 21, 18, .82)"}
              />
              <text x={6} y={13} fill="#f1f6f3" fontFamily="Segoe UI" fontSize={10} fontWeight={600}>
                {parentLabel}
              </text>
            </g>
          )}
          {node.isLeaf && !isRoot && node.width >= 34 && node.height >= 16 && (
            <g pointerEvents="none">
              <text x={4} y={13} fill="#f7faf8" fontFamily="Segoe UI" fontSize={10} fontWeight={600}>
                {leafLabel}
              </text>
              {node.height >= 31 && (
                <text x={4} y={26} fill="rgba(247, 250, 248, .82)" fontFamily="Segoe UI" fontSize={9}>
                  {fitSvgText(formatBytes(item.allocatedBytes), node.width - 8, 9)}
                </text>
              )}
            </g>
          )}
        </g>
      );
    },
    [formatBytes, hovered, hoveredAncestors, onOpen, selectedId],
  );
  const hoveredPath = hovered ? joinWindowsPath(scopePath, hovered.relativePath) : scopePath;
  const renderTooltip = useCallback(
    ({ node }: TooltipProps<StorageTreemapDatum>) => {
      const path = joinWindowsPath(scopePath, node.data.relativePath);
      return (
        <div className="treemap-tooltip">
          <strong>{node.data.name}</strong>
          <span>{formatBytes(node.data.allocatedBytes)}</span>
          <small>{path}</small>
        </div>
      );
    },
    [formatBytes, scopePath],
  );

  return (
    <div ref={hostRef} className="treemap-canvas-host" role="img" aria-label="Storage treemap">
      {size.width > 0 && size.height > 0 && (
        <TreeMap<StorageTreemapDatum>
          data={data}
          width={size.width}
          height={size.height}
          identity="id"
          value="value"
          tile="binary"
          leavesOnly={false}
          innerPadding={0.75}
          outerPadding={0}
          enableLabel={false}
          enableParentLabel
          parentLabelSize={17}
          parentLabelPadding={1}
          colors={(node) => node.data.color}
          colorBy="id"
          nodeOpacity={1}
          borderWidth={0}
          animate={false}
          isInteractive
          nodeComponent={renderNode}
          tooltip={renderTooltip}
          onMouseEnter={(node) => setHovered(node.data)}
          onMouseMove={(node) => setHovered((current) => current?.id === node.data.id ? current : node.data)}
          onMouseLeave={() => setHovered(null)}
          onClick={(node) => {
            if (node.data.node) onSelect(node.data.node);
          }}
        />
      )}
      <div className={`treemap-hover-readout${hovered ? " active" : ""}`}>
        <span className="treemap-hover-swatch" style={{ backgroundColor: hovered?.color ?? "#3d4541" }} />
        <strong>{hovered?.name ?? scopeName}</strong>
        <span>{hovered ? formatBytes(hovered.allocatedBytes) : "Current scope"}</span>
        <small title={hoveredPath}>{hoveredPath}</small>
      </div>
    </div>
  );
}

function fitSvgText(text: string, maxWidth: number, fontSize: number): string {
  const maximumCharacters = Math.max(0, Math.floor(maxWidth / (fontSize * 0.56)));
  if (text.length <= maximumCharacters) return text;
  if (maximumCharacters <= 3) return "";
  return `${text.slice(0, maximumCharacters - 3)}...`;
}

function joinWindowsPath(scopePath: string, relativePath: string): string {
  if (!relativePath) return scopePath;
  const separator = scopePath.endsWith("\\") ? "" : "\\";
  return `${scopePath}${separator}${relativePath}`;
}
