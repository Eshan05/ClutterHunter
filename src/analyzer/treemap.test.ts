import { describe, expect, it } from "vitest";
import type { TreemapNode } from "../bindings/TreemapNode";
import { layoutTreemap, treemapColor } from "./treemap";

const nodes: TreemapNode[] = [
  node("large", "900"),
  node("small", "100"),
];

describe("treemap layout", () => {
  it("keeps every bounded node inside the canvas", () => {
    const rectangles = layoutTreemap(nodes, 1000, 500);

    expect(rectangles).toHaveLength(2);
    expect(rectangles[0]!.width * rectangles[0]!.height).toBeGreaterThan(
      rectangles[1]!.width * rectangles[1]!.height,
    );
    for (const rectangle of rectangles) {
      expect(rectangle.x).toBeGreaterThanOrEqual(0);
      expect(rectangle.y).toBeGreaterThanOrEqual(0);
      expect(rectangle.x + rectangle.width).toBeLessThanOrEqual(1000);
      expect(rectangle.y + rectangle.height).toBeLessThanOrEqual(500);
    }
  });

  it("is empty for unusable bounds and colors equal extensions consistently", () => {
    expect(layoutTreemap(nodes, 0, 500)).toEqual([]);
    expect(treemapColor(node("one.log", "10"))).toBe(treemapColor(node("two.log", "20")));
  });
});

function node(name: string, allocatedBytes: string): TreemapNode {
  return {
    id: name,
    parent_id: null,
    name,
    allocated_bytes: allocatedBytes,
    kind: "file",
    policy_tier: "protected",
    owner_id: null,
    synthetic: false,
  };
}
