import { describe, expect, it } from "vitest";
import type { TreemapNode } from "../bindings/TreemapNode";
import { buildTreemapHierarchy, treemapColor } from "./treemap";

describe("treemap hierarchy", () => {
  it("restores bounded ancestors and accounts for omitted space at each level", () => {
    const folder = node("folder", "folder", "1000", "directory", null);
    const nested = node("nested", "nested", "700", "directory", folder.id);
    const file = node("large.bin", "large.bin", "500", "file", nested.id);

    const root = buildTreemapHierarchy([folder, nested, file], "500");

    expect(root.allocatedBytes).toBe("1000");
    expect(root.children?.map((child) => child.name)).toEqual(["folder"]);
    const folderDatum = root.children?.[0];
    expect(folderDatum?.relativePath).toBe("folder");
    expect(folderDatum?.children?.[0]?.relativePath).toBe("folder\\nested");
    expect(folderDatum?.children?.[0]?.ancestorIds).toEqual(["folder"]);
    expect(folderDatum?.children?.map((child) => [child.name, child.allocatedBytes])).toEqual([
      ["nested", "700"],
      ["Other", "300"],
    ]);
    expect(folderDatum?.children?.[0]?.children?.map((child) => [child.name, child.allocatedBytes])).toEqual([
      ["large.bin", "500"],
      ["Other", "200"],
    ]);
  });

  it("keeps same-extension file colors stable", () => {
    expect(treemapColor(node("one.log", "one", "10"))).toBe(
      treemapColor(node("two.log", "two", "20")),
    );
  });
});

function node(
  name: string,
  id: string,
  allocatedBytes: string,
  kind: TreemapNode["kind"] = "file",
  parentId: string | null = null,
): TreemapNode {
  return {
    id,
    parent_id: parentId,
    name,
    allocated_bytes: allocatedBytes,
    kind,
    policy_tier: "protected",
    owner_id: null,
    synthetic: false,
  };
}
