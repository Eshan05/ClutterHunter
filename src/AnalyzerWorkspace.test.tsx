// @vitest-environment jsdom

import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ItemRow } from "./bindings/ItemRow";
import type { ScanSummary } from "./bindings/ScanSummary";

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  reveal: vi.fn(),
  selection: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: mocks.invoke }));
vi.mock("@tauri-apps/plugin-opener", () => ({ revealItemInDir: mocks.reveal }));
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({ count }: { count: number }) => ({
    getTotalSize: () => count * 30,
    getVirtualItems: () => Array.from({ length: count }, (_, index) => ({
      index,
      key: index,
      size: 30,
      start: index * 30,
    })),
  }),
}));

import { AnalyzerWorkspace } from "./AnalyzerWorkspace";

const summary: ScanSummary = {
  session_id: "scan-1",
  target: {
    id: "C:",
    kind: "volume",
    display_path: "C:\\",
    filesystem: "NTFS",
    volume_id: null,
    total_bytes: null,
    available_bytes: null,
    fast_scan_available: true,
  },
  backend: "raw_ntfs",
  coverage: "complete",
  entry_count: "4",
  logical_bytes: "1000",
  allocated_bytes: "1200",
  volume_used_bytes: null,
  unaccounted_bytes: null,
  started_at_ms: "1",
  completed_at_ms: "2",
  elapsed_ms: "1",
  warnings: [],
};

const users = item("scan-1:1", null, "Users", "C:\\Users", "directory", "700");
const windows = item("scan-1:2", null, "Windows", "C:\\Windows", "directory", "400");
const target = item("scan-1:3", users.id, "target", "C:\\Users\\target", "directory", "300");

describe("AnalyzerWorkspace", () => {
  beforeEach(() => {
    vi.stubGlobal("ResizeObserver", class {
      observe() {}
      disconnect() {}
    });
    mocks.invoke.mockReset();
    mocks.reveal.mockReset();
    mocks.reveal.mockResolvedValue(undefined);
    mocks.selection.mockReset();
    mocks.invoke.mockImplementation((command: string, args: Record<string, unknown>) => {
      if (command === "query_items") {
        const query = args.query as { parent_id: string | null; text?: string; cursor: string | null };
        if (query.text) return Promise.resolve({ items: [target], next_cursor: null, truncated: false });
        if (query.parent_id === users.id) return Promise.resolve({ items: [target], next_cursor: null, truncated: false });
        return Promise.resolve({ items: [users, windows], next_cursor: null, truncated: false });
      }
      if (command === "get_storage_aggregate") {
        return Promise.resolve({
          buckets: [{ key: "log", label: ".log", item_count: "2", logical_bytes: "200", allocated_bytes: "240" }],
          other_item_count: "0",
          other_logical_bytes: "0",
          other_allocated_bytes: "0",
        });
      }
      if (command === "get_treemap_slice") {
        return Promise.resolve({
          nodes: [{
            id: users.id,
            parent_id: null,
            name: users.name,
            allocated_bytes: users.allocated_bytes,
            kind: users.kind,
            policy_tier: users.policy.tier,
            owner_id: null,
            synthetic: false,
          }],
          truncated: false,
          other_allocated_bytes: "0",
        });
      }
      if (command === "cancel_item_query") return Promise.resolve(true);
      throw new Error(`Unexpected command: ${command}`);
    });
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("navigates bounded folders, searches recursively, and hands selection to the agent", async () => {
    const user = userEvent.setup();
    renderWorkspace();

    const hierarchy = screen.getByRole("region", { name: "Storage hierarchy" });
    expect(await within(hierarchy).findByText("Users")).toBeTruthy();
    expect(screen.getByText(".log")).toBeTruthy();
    expect(screen.getByLabelText("Storage treemap")).toBeTruthy();
    expect(queryCalls()[0]?.query).toMatchObject({
      parent_id: null,
      recursive: false,
      sort: "allocated",
      direction: "desc",
      cursor: null,
      limit: 100,
    });

    await user.click(within(hierarchy).getByText("Windows"));
    expect(mocks.selection).toHaveBeenLastCalledWith(windows);
    await user.click(screen.getByRole("button", { name: "Reveal selected item in Explorer" }));
    expect(mocks.reveal).toHaveBeenCalledWith("C:\\Windows");

    await user.dblClick(within(hierarchy).getByText("Users"));
    expect(await screen.findByRole("button", { name: "Users" })).toBeTruthy();
    await waitFor(() => expect(queryCalls().some((call) => call.query.parent_id === users.id)).toBe(true));

    await user.type(screen.getByRole("textbox", { name: "Search storage items" }), "target");
    await waitFor(() => expect(queryCalls().some((call) =>
      call.query.text === "target"
      && call.query.scope_id === users.id
      && call.query.recursive === true)).toBe(true));
    expect(await within(hierarchy).findByText("target")).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "Back" }));
    await waitFor(() => expect(screen.queryByRole("button", { name: "Users" })).toBeNull());
  });

  it("loads the next bounded page when virtual rows reach the cursor", async () => {
    mocks.invoke.mockImplementation((command: string, args: Record<string, unknown>) => {
      if (command === "query_items") {
        const query = args.query as { cursor: string | null };
        return Promise.resolve(query.cursor
          ? { items: [windows], next_cursor: null, truncated: false }
          : { items: [users], next_cursor: "cursor-2", truncated: true });
      }
      if (command === "get_storage_aggregate") {
        return Promise.resolve({ buckets: [], other_item_count: "0", other_logical_bytes: "0", other_allocated_bytes: "0" });
      }
      if (command === "get_treemap_slice") return Promise.resolve({ nodes: [], truncated: false, other_allocated_bytes: "0" });
      if (command === "cancel_item_query") return Promise.resolve(true);
      throw new Error(`Unexpected command: ${command}`);
    });

    renderWorkspace();

    expect(await screen.findByText("Users")).toBeTruthy();
    expect(await screen.findByText("Windows")).toBeTruthy();
    expect(queryCalls().some((call) => call.query.cursor === "cursor-2")).toBe(true);
  });
});

function renderWorkspace() {
  render(
    <AnalyzerWorkspace
      summary={summary}
      progress={null}
      scanStatus="complete"
      scanError={null}
      metric="allocated"
      onMetricChange={vi.fn()}
      onSelectionChange={mocks.selection}
    />,
  );
}

function queryCalls() {
  return mocks.invoke.mock.calls
    .filter(([command]) => command === "query_items")
    .map(([, args]) => args as { sessionId: string; query: Record<string, unknown> });
}

function item(
  id: string,
  parentId: string | null,
  name: string,
  displayPath: string,
  kind: ItemRow["kind"],
  allocatedBytes: string,
): ItemRow {
  return {
    id,
    parent_id: parentId,
    name,
    display_path: displayPath,
    kind,
    logical_bytes: allocatedBytes,
    allocated_bytes: allocatedBytes,
    modified_at_ms: null,
    extension: null,
    attributes: [],
    hard_link_count: null,
    child_count: kind === "directory" ? 1 : null,
    owner: null,
    policy: {
      tier: "protected",
      rule_id: "default",
      rule_version: "1",
      facts: [],
      inference: [],
      warnings: [],
    },
  };
}
