import { hierarchy, treemap, treemapBinary } from "d3-hierarchy";
import type { TreemapNode } from "../bindings/TreemapNode";

export interface TreemapRect {
  node: TreemapNode;
  x: number;
  y: number;
  width: number;
  height: number;
}

interface TreemapDatum {
  node?: TreemapNode;
  children?: TreemapDatum[];
}

export function layoutTreemap(
  nodes: TreemapNode[],
  width: number,
  height: number,
): TreemapRect[] {
  if (nodes.length === 0 || width <= 0 || height <= 0) return [];
  const root = hierarchy<TreemapDatum>({
    children: nodes.map((node) => ({ node })),
  }).sum((datum) => datum.node ? visualBytes(datum.node.allocated_bytes) : 0);
  const laidOutRoot = treemap<TreemapDatum>()
    .tile(treemapBinary)
    .size([width, height])
    .paddingInner(1)
    .round(true)(root);
  return laidOutRoot.leaves().flatMap((leaf) => {
    if (!leaf.data.node) return [];
    return [{
      node: leaf.data.node,
      x: leaf.x0,
      y: leaf.y0,
      width: Math.max(0, leaf.x1 - leaf.x0),
      height: Math.max(0, leaf.y1 - leaf.y0),
    }];
  });
}

export function treemapColor(node: TreemapNode): string {
  const palette = ["#317d70", "#b8734f", "#536f9f", "#a3873d", "#735f8d", "#4d8264", "#a45656"];
  const key = node.kind === "file"
    ? node.name.slice(node.name.lastIndexOf(".") + 1).toLocaleLowerCase()
    : node.name.toLocaleLowerCase();
  let hash = 0;
  for (const character of key) hash = ((hash << 5) - hash + character.charCodeAt(0)) | 0;
  return palette[Math.abs(hash) % palette.length] ?? palette[0]!;
}

function visualBytes(value: string): number {
  const bytes = Number(value);
  return Number.isFinite(bytes) && bytes > 0 ? bytes : 1;
}
