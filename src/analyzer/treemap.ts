import type { TreemapNode } from "../bindings/TreemapNode";

export interface StorageTreemapDatum {
  id: string;
  name: string;
  relativePath: string;
  ancestorIds: string[];
  allocatedBytes: string;
  allocatedValue: number;
  color: string;
  synthetic: boolean;
  node: TreemapNode | null;
  value?: number;
  children?: StorageTreemapDatum[];
}

const FILE_COLORS = [
  "#2aa876",
  "#f08c46",
  "#4f83cc",
  "#d34f8a",
  "#b8bd27",
  "#25a9b7",
  "#d45b52",
  "#8d69c4",
  "#4f9d55",
  "#d19a32",
  "#5376a8",
  "#b85b9b",
] as const;

export function buildTreemapHierarchy(
  nodes: TreemapNode[],
  omittedAllocatedBytes: string,
): StorageTreemapDatum {
  const representedLeafBytes = nodes.reduce(
    (total, node) => node.kind === "directory"
      ? total
      : total + parseByteCount(node.allocated_bytes),
    0n,
  );
  const totalBytes = representedLeafBytes + parseByteCount(omittedAllocatedBytes);
  const root = datum({
    id: "treemap-scope",
    name: "Current scope",
    allocated_bytes: totalBytes.toString(),
    kind: "directory",
    synthetic: true,
  });
  const byId = new Map(nodes.map((node) => [node.id, datum(node)]));

  for (const node of nodes) {
    const current = byId.get(node.id)!;
    const parent = node.parent_id ? byId.get(node.parent_id) : undefined;
    const container = parent ?? root;
    (container.children ??= []).push(current);
  }

  completeHierarchy(root);
  assignHierarchyContext(root, "", []);
  return root;
}

export function treemapColor(node: TreemapNode): string {
  if (node.synthetic) return "#3d4541";
  const key = node.kind === "file"
    ? fileExtension(node.name)
    : node.name.toLocaleLowerCase();
  let hash = 0;
  for (const character of key) {
    hash = ((hash << 5) - hash + character.charCodeAt(0)) | 0;
  }
  return FILE_COLORS[Math.abs(hash) % FILE_COLORS.length] ?? FILE_COLORS[0];
}

function completeHierarchy(parent: StorageTreemapDatum): void {
  const children = parent.children;
  if (!children?.length) {
    parent.value = Math.max(1, parent.allocatedValue);
    return;
  }

  const represented = children.reduce(
    (total, child) => total + parseByteCount(child.allocatedBytes),
    0n,
  );
  const remainder = parseByteCount(parent.allocatedBytes) - represented;
  if (remainder > 0n) {
    children.push(syntheticRemainder(parent, remainder));
  }
  children.sort((left, right) => right.allocatedValue - left.allocatedValue);
  for (const child of children) completeHierarchy(child);
  delete parent.value;
}

function datum(node: TreemapNode): StorageTreemapDatum;
function datum(node: Pick<TreemapNode, "id" | "name" | "allocated_bytes" | "kind" | "synthetic">): StorageTreemapDatum;
function datum(
  node: Pick<TreemapNode, "id" | "name" | "allocated_bytes" | "kind" | "synthetic">,
): StorageTreemapDatum {
  const source = "parent_id" in node ? node as TreemapNode : null;
  return {
    id: node.id,
    name: node.name,
    relativePath: "",
    ancestorIds: [],
    allocatedBytes: node.allocated_bytes,
    allocatedValue: visualBytes(node.allocated_bytes),
    color: source ? treemapColor(source) : "#252c28",
    synthetic: node.synthetic,
    node: source,
  };
}

function syntheticRemainder(
  parent: StorageTreemapDatum,
  bytes: bigint,
): StorageTreemapDatum {
  const allocatedBytes = bytes.toString();
  return {
    id: `${parent.id}:other`,
    name: "Other",
    relativePath: "",
    ancestorIds: [],
    allocatedBytes,
    allocatedValue: visualBytes(allocatedBytes),
    color: "#3d4541",
    synthetic: true,
    node: null,
    value: visualBytes(allocatedBytes),
  };
}

function assignHierarchyContext(
  parent: StorageTreemapDatum,
  parentPath: string,
  ancestorIds: string[],
): void {
  parent.relativePath = parentPath;
  parent.ancestorIds = ancestorIds;
  const childAncestors = parent.id === "treemap-scope"
    ? []
    : [...ancestorIds, parent.id];
  for (const child of parent.children ?? []) {
    const childPath = parentPath ? `${parentPath}\\${child.name}` : child.name;
    assignHierarchyContext(child, childPath, childAncestors);
  }
}

function fileExtension(name: string): string {
  const separator = name.lastIndexOf(".");
  return separator > 0 && separator < name.length - 1
    ? name.slice(separator + 1).toLocaleLowerCase()
    : "(none)";
}

function parseByteCount(value: string): bigint {
  try {
    const bytes = BigInt(value);
    return bytes > 0n ? bytes : 0n;
  } catch {
    return 0n;
  }
}

function visualBytes(value: string): number {
  const bytes = Number(value);
  return Number.isFinite(bytes) && bytes > 0 ? bytes : 1;
}
