import { describe, expect, it } from "vitest";
import { MAX_TOOL_RESULT_BYTES, ToolResultBudget, createAnalyzerTools } from "./tools";

describe("agent analyzer tools", () => {
  it("truncates a result before crossing 12 KiB", () => {
    const budget = new ToolResultBudget();
    const result = budget.wrap("ItemListResult", {
      items: Array.from({ length: 100 }, (_, index) => ({
        id: String(index),
        name: "x".repeat(500),
      })),
      next_cursor: "next",
    });
    expect(result.truncated).toBe(true);
    expect(result.data.items.length).toBeLessThan(100);
    expect(new TextEncoder().encode(JSON.stringify(result)).byteLength).toBeLessThanOrEqual(MAX_TOOL_RESULT_BYTES);
  });

  it("keeps a bounded portion of a single approved log excerpt", () => {
    const budget = new ToolResultBudget();
    const result = budget.wrap("LogExcerptApproval", {
      excerpts: [{ item_id: "log-1", path: "C:\\logs\\app.log", content: "x".repeat(50_000) }],
      total_bytes_read: "50000",
      truncated: false,
    });

    expect(result.truncated).toBe(true);
    expect(result.data.excerpts).toHaveLength(1);
    expect(result.data.excerpts[0]?.content).toContain("[tool result truncated]");
    expect(new TextEncoder().encode(JSON.stringify(result)).byteLength).toBeLessThanOrEqual(MAX_TOOL_RESULT_BYTES);
  });

  it("inspects a folder through one composite tool result", async () => {
    const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
    const tools = createAnalyzerTools({
      sessionId: "session-1",
      invoke: async <T>(command: string, args?: Record<string, unknown>) => {
        calls.push({ command, args });
        const value = command === "get_scan_summary"
          ? {
              session_id: "session-1",
              target: { display_path: "C:\\" },
              coverage: "complete",
              logical_bytes: "900",
              allocated_bytes: "1000",
              warnings: [],
            }
          : command === "query_items"
            ? (args?.query as { top_only?: boolean })?.top_only
              ? {
                  items: [{ name: "disk.vhdx", display_path: "C:\\Users\\disk.vhdx", allocated_bytes: "600" }],
                  next_cursor: null,
                }
              : {
                  items: [{ name: "Users", display_path: "C:\\Users", allocated_bytes: "700" }],
                  next_cursor: null,
                }
            : {
                buckets: [{ label: "Directory", allocated_bytes: "700" }],
                other_item_count: "0",
                other_logical_bytes: "0",
                other_allocated_bytes: "0",
              };
        return value as T;
      },
    });
    if (!tools.inspect_folder.execute) throw new Error("Folder-inspection tool is not executable");

    const result = await tools.inspect_folder.execute(
      { limit: 10 },
      { toolCallId: "inspect-root", messages: [], context: {} },
    );

    expect(result).toMatchObject({
      component: "FolderInspectionResult",
      data: {
        scope: { display_path: "C:\\", allocated_bytes: "1000" },
        top_children: [{ name: "Users" }],
        top_files: [{ name: "disk.vhdx" }],
        coverage: "complete",
      },
    });
    expect(calls.filter((call) => call.command === "get_storage_aggregate")).toHaveLength(3);
    expect(calls.find((call) => call.command === "query_items" && !(call.args?.query as { top_only?: boolean }).top_only)?.args).toMatchObject({
      query: { parent_id: null, recursive: false, sort: "allocated" },
    });
    expect(calls.find((call) => (call.args?.query as { top_only?: boolean })?.top_only)?.args).toMatchObject({
      query: { recursive: true, top_only: true, kinds: ["file"], sort: "allocated" },
    });
  });

  it("lists cleanup opportunities without replacing the active plan", async () => {
    const calls: string[] = [];
    const tools = createAnalyzerTools({
      sessionId: "session-1",
      invoke: async <T>(command: string) => {
        calls.push(command);
        if (command === "get_item_details") {
          return {
            item: { display_path: "C:\\Temp\\Cache" },
            evidence: { tier: "cleanup_candidate", facts: ["Known cache root"] },
          } as T;
        }
        return {
          selected_candidate_bytes: "100",
          review_potential_bytes: "900",
          truncated: false,
          items: [
            {
              id: "safe",
              node_ids: ["session-1:2"],
              title: "Cache",
              category: "cache",
              tier: "cleanup_candidate",
              reclaimable_bytes: "100",
              evidence: [],
              warnings: [],
              action_kind: "none",
            },
            {
              id: "review",
              node_ids: ["session-1:3"],
              title: "Build output",
              category: "build",
              tier: "review_required",
              reclaimable_bytes: "900",
              evidence: [],
              warnings: [],
              action_kind: "inspect",
            },
          ],
        } as T;
      },
    });
    if (!tools.list_cleanup_opportunities.execute) throw new Error("Cleanup-opportunity tool is not executable");

    const result = await tools.list_cleanup_opportunities.execute(
      { include_review: false, limit: 25 },
      { toolCallId: "cleanup-opportunities", messages: [], context: {} },
    );

    expect(calls).toEqual(["get_cleanup_opportunities", "get_item_details"]);
    expect(result).toMatchObject({
      component: "CleanupOpportunitiesResult",
      data: {
        conservative_bytes: "100",
        review_potential_bytes: "900",
        items: [{ display_path: "C:\\Temp\\Cache", tier: "cleanup_candidate", reason: "Known cache root" }],
      },
    });
  });

  it("bounds cleanup opportunities to the locally resolved folder", async () => {
    const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
    const tools = createAnalyzerTools({
      sessionId: "session-1",
      invoke: async <T>(command: string, args?: Record<string, unknown>) => {
        calls.push({ command, args });
        if (command === "query_items") {
          return {
            items: [{
              id: "session-1:4",
              name: "AppData",
              display_path: "C:\\Users\\redma\\AppData",
              kind: "directory",
              allocated_bytes: "1000",
            }],
            next_cursor: null,
          } as T;
        }
        return {
          selected_candidate_bytes: "100",
          review_potential_bytes: "200",
          omitted_candidate_bytes: "25",
          omitted_review_bytes: "50",
          truncated: true,
          items: [],
        } as T;
      },
    });
    if (!tools.list_cleanup_opportunities.execute) throw new Error("Cleanup-opportunity tool is not executable");

    const result = await tools.list_cleanup_opportunities.execute(
      { scope: "C:\\Users\\redma\\AppData", include_review: true, limit: 25 },
      { toolCallId: "scoped-cleanup", messages: [], context: {} },
    );

    expect(calls[1]).toEqual({
      command: "get_cleanup_opportunities",
      args: { sessionId: "session-1", scopeId: "session-1:4" },
    });
    expect(result).toMatchObject({
      data: {
        conservative_bytes: "125",
        review_potential_bytes: "250",
        resolved_scope: { display_path: "C:\\Users\\redma\\AppData" },
      },
    });
  });

  it("maps a bounded item query to the existing Tauri command", async () => {
    const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
    const tools = createAnalyzerTools({
      sessionId: "session-1",
      invoke: async <T>(command: string, args?: Record<string, unknown>) => {
        calls.push({ command, args });
        return { items: [], next_cursor: null } as T;
      },
    });
    if (!tools.list_folder_children.execute) throw new Error("Folder-list tool is not executable");
    await tools.list_folder_children.execute(
      { sort: "allocated", direction: "desc", cursor: null, limit: 25 },
      { toolCallId: "call-1", messages: [], context: {} },
    );
    expect(calls[0]?.command).toBe("query_items");
    expect(calls[0]?.args).toMatchObject({
      sessionId: "session-1",
      query: { parent_id: null, recursive: false, sort: "allocated", direction: "desc", cursor: null, limit: 25 },
    });
    expect(tools.protect_path.needsApproval).toBe(true);
    expect(tools.inspect_log_excerpt.needsApproval).toBe(true);
  });

  it("ranks largest recursive items with bounded top-only analyzer work", async () => {
    const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
    const tools = createAnalyzerTools({
      sessionId: "session-1",
      invoke: async <T>(command: string, args?: Record<string, unknown>) => {
        calls.push({ command, args });
        return { items: [], next_cursor: null } as T;
      },
    });
    if (!tools.list_largest_items.execute) throw new Error("Largest-item tool is not executable");

    const result = await tools.list_largest_items.execute(
      { kinds: ["file"], metric: "logical", limit: 10 },
      { toolCallId: "largest-files", messages: [], context: {} },
    );

    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      command: "query_items",
      args: {
        query: {
          parent_id: null,
          recursive: true,
          top_only: true,
          kinds: ["file"],
          sort: "logical",
          direction: "desc",
          limit: 10,
        },
      },
    });
    expect(result).toMatchObject({ data: { query_context: { mode: "largest", sort: "logical" } } });
  });

  it("resolves a folder name and performs the scoped query in one tool execution", async () => {
    const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
    const tools = createAnalyzerTools({
      sessionId: "session-1",
      invoke: async <T>(command: string, args?: Record<string, unknown>) => {
        calls.push({ command, args });
        if (calls.length === 1) {
          return {
            items: [{
              id: "session-1:7",
              name: "Projects",
              display_path: "C:\\Users\\person\\Projects",
              allocated_bytes: "100",
              kind: "directory",
            }],
            next_cursor: null,
          } as T;
        }
        return { items: [], next_cursor: null } as T;
      },
    });
    if (!tools.list_folder_children.execute) throw new Error("Folder-list tool is not executable");

    const result = await tools.list_folder_children.execute(
      { scope: "Projects", sort: "allocated", direction: "desc", cursor: null, limit: 25 },
      { toolCallId: "call-2", messages: [], context: {} },
    );

    expect(calls[0]?.args).toMatchObject({
      sessionId: "session-1",
      query: { text: "Projects", kinds: ["directory"] },
    });
    expect(calls[1]?.args).toMatchObject({
      sessionId: "session-1",
      query: { parent_id: "session-1:7", recursive: false, scope_id: undefined, sort: "allocated" },
    });
    expect(result).toMatchObject({
      data: {
        resolved_scope: { display_path: "C:\\Users\\person\\Projects" },
        query_context: {
          scope: "C:\\Users\\person\\Projects",
          sort: "allocated",
          direction: "desc",
          limit: 25,
        },
      },
    });
  });

  it("lists direct children but keeps text searches bounded to the resolved subtree", async () => {
    const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
    const tools = createAnalyzerTools({
      sessionId: "session-1",
      invoke: async <T>(command: string, args?: Record<string, unknown>) => {
        calls.push({ command, args });
        return (calls.length === 1
          ? {
              items: [{
                id: "session-1:7",
                name: "Projects",
                display_path: "C:\\Users\\person\\Projects",
                allocated_bytes: "100",
                kind: "directory",
              }],
              next_cursor: null,
            }
          : { items: [], next_cursor: null }) as T;
      },
    });
    if (!tools.search_storage.execute) throw new Error("Search tool is not executable");

    await tools.search_storage.execute(
      {
        scope: "Projects",
        text: "bundle",
        sort: "allocated",
        direction: "desc",
        cursor: null,
        limit: 25,
      },
      { toolCallId: "call-subtree-search", messages: [], context: {} },
    );

    expect(calls[1]?.args).toMatchObject({
      query: {
        parent_id: null,
        recursive: true,
        scope_id: "session-1:7",
        text: "bundle",
      },
    });
  });

  it("uses the trusted attached directory for omitted and full-path scopes", async () => {
    const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
    const tools = createAnalyzerTools({
      sessionId: "session-1",
      attachment: {
        id: "session-1:42",
        name: "Users",
        displayPath: "C:\\Users",
        kind: "directory",
        allocatedBytes: "100",
        logicalBytes: "90",
        policyTier: "protected",
      },
      invoke: async <T>(command: string, args?: Record<string, unknown>) => {
        calls.push({ command, args });
        return { items: [], next_cursor: null } as T;
      },
    });
    if (!tools.list_folder_children.execute) throw new Error("Folder-list tool is not executable");

    await tools.list_folder_children.execute(
      { sort: "allocated", direction: "desc", cursor: null, limit: 25 },
      { toolCallId: "call-attached-default", messages: [], context: {} },
    );
    await tools.list_folder_children.execute(
      { scope: "C:\\Users", sort: "allocated", direction: "desc", cursor: null, limit: 25 },
      { toolCallId: "call-attached-path", messages: [], context: {} },
    );

    expect(calls).toHaveLength(2);
    expect(calls.every((call) =>
      (call.args?.query as { parent_id?: string }).parent_id === "session-1:42"
    )).toBe(true);
  });

  it("reuses the last resolved scope for an omitted follow-up scope", async () => {
    const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
    const tools = createAnalyzerTools({
      sessionId: "session-1",
      defaultScope: {
        id: "session-1:84",
        name: "redma",
        display_path: "C:\\Users\\redma",
      },
      attachment: {
        id: "session-1:42",
        name: "Users",
        displayPath: "C:\\Users",
        kind: "directory",
        allocatedBytes: "100",
        logicalBytes: "90",
        policyTier: "protected",
      },
      invoke: async <T>(command: string, args?: Record<string, unknown>) => {
        calls.push({ command, args });
        return { items: [], next_cursor: null } as T;
      },
    });
    if (!tools.list_folder_children.execute) throw new Error("Folder-list tool is not executable");

    const result = await tools.list_folder_children.execute(
      { kinds: ["directory"], sort: "allocated", direction: "desc", cursor: null, limit: 25 },
      { toolCallId: "call-follow-up", messages: [], context: {} },
    );

    expect(calls[0]?.args).toMatchObject({ query: { parent_id: "session-1:84", scope_id: undefined } });
    expect(result).toMatchObject({
      data: { query_context: { scope: "C:\\Users\\redma", kinds: ["directory"] } },
    });
  });

  it("resolves non-attached full paths by their final component", async () => {
    const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
    const tools = createAnalyzerTools({
      sessionId: "session-1",
      invoke: async <T>(command: string, args?: Record<string, unknown>) => {
        calls.push({ command, args });
        if (calls.length === 1) {
          return {
            items: [{
              id: "session-1:7",
              name: "Projects",
              display_path: "C:\\Users\\person\\Projects",
              allocated_bytes: "100",
              kind: "directory",
            }],
            next_cursor: null,
          } as T;
        }
        return { items: [], next_cursor: null } as T;
      },
    });
    if (!tools.list_folder_children.execute) throw new Error("Folder-list tool is not executable");

    await tools.list_folder_children.execute(
      {
        scope: "C:\\Users\\person\\Projects",
        sort: "allocated",
        direction: "desc",
        cursor: null,
        limit: 25,
      },
      { toolCallId: "call-full-path", messages: [], context: {} },
    );

    expect(calls[0]?.args).toMatchObject({ query: { text: "Projects", limit: 100 } });
    expect(calls[1]?.args).toMatchObject({ query: { parent_id: "session-1:7", scope_id: undefined } });
  });

  it("reads evidence for the trusted attachment without a model-visible node ID", async () => {
    const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
    const tools = createAnalyzerTools({
      sessionId: "session-1",
      attachment: {
        id: "session-1:42",
        name: "Users",
        displayPath: "C:\\Users",
        kind: "directory",
        allocatedBytes: "100",
        logicalBytes: "90",
        policyTier: "protected",
      },
      invoke: async <T>(command: string, args?: Record<string, unknown>) => {
        calls.push({ command, args });
        return { item: { id: "session-1:42" } } as T;
      },
    });
    if (!tools.inspect_item.execute) throw new Error("Item-inspection tool is not executable");

    await tools.inspect_item.execute(
      { use_attached_item: true },
      { toolCallId: "call-attached-evidence", messages: [], context: {} },
    );

    expect(calls).toEqual([{
      command: "get_item_details",
      args: { sessionId: "session-1", nodeId: "session-1:42" },
    }]);
  });

  it("inspects an exact item path without exposing its node id in the schema", async () => {
    const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
    const tools = createAnalyzerTools({
      sessionId: "session-1",
      invoke: async <T>(command: string, args?: Record<string, unknown>) => {
        calls.push({ command, args });
        if (command === "query_items") {
          return {
            items: [{
              id: "session-1:9",
              name: "pagefile.sys",
              display_path: "C:\\pagefile.sys",
              kind: "file",
              allocated_bytes: "100",
            }],
            next_cursor: null,
          } as T;
        }
        return {
          item: { id: "session-1:9", name: "pagefile.sys", display_path: "C:\\pagefile.sys" },
          evidence: { tier: "protected" },
        } as T;
      },
    });
    if (!tools.inspect_item.execute) throw new Error("Item-inspection tool is not executable");

    const result = await tools.inspect_item.execute(
      { scope: "C:\\pagefile.sys", use_attached_item: false },
      { toolCallId: "inspect-pagefile", messages: [], context: {} },
    );

    expect(calls[0]).toMatchObject({ command: "query_items", args: { query: { text: "pagefile.sys" } } });
    expect(calls[1]).toEqual({
      command: "get_item_details",
      args: { sessionId: "session-1", nodeId: "session-1:9" },
    });
    expect(result).toMatchObject({
      component: "OwnershipEvidenceResult",
      data: { resolved_item: { display_path: "C:\\pagefile.sys" } },
    });
  });

  it("treats slash as the explicit scan root even with an attachment", async () => {
    const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
    const tools = createAnalyzerTools({
      sessionId: "session-1",
      allowRootScope: true,
      attachment: {
        id: "session-1:42",
        name: "Users",
        displayPath: "C:\\Users",
        kind: "directory",
        allocatedBytes: "100",
        logicalBytes: "90",
        policyTier: "protected",
      },
      invoke: async <T>(command: string, args?: Record<string, unknown>) => {
        calls.push({ command, args });
        return { items: [], next_cursor: null } as T;
      },
    });
    if (!tools.list_folder_children.execute) throw new Error("Folder-list tool is not executable");

    await tools.list_folder_children.execute(
      { scope: "/", sort: "allocated", direction: "desc", cursor: null, limit: 25 },
      { toolCallId: "call-root", messages: [], context: {} },
    );

    expect(calls).toHaveLength(1);
    expect(calls[0]?.args).toMatchObject({ query: { parent_id: null, scope_id: undefined } });
  });

  it("rejects a model-invented root scope when the user selected a folder", async () => {
    const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
    const tools = createAnalyzerTools({
      sessionId: "session-1",
      attachment: {
        id: "session-1:42",
        name: "Users",
        displayPath: "C:\\Users",
        kind: "directory",
        allocatedBytes: "100",
        logicalBytes: "90",
        policyTier: "protected",
      },
      invoke: async <T>(command: string, args?: Record<string, unknown>) => {
        calls.push({ command, args });
        return { items: [], next_cursor: null } as T;
      },
    });
    if (!tools.list_folder_children.execute) throw new Error("Folder-list tool is not executable");

    await tools.list_folder_children.execute(
      { scope: "/", sort: "allocated", direction: "desc", cursor: null, limit: 25 },
      { toolCallId: "call-invented-root", messages: [], context: {} },
    );

    expect(calls[0]?.args).toMatchObject({ query: { parent_id: "session-1:42", scope_id: undefined } });
  });

  it("resolves named aggregate scopes without exposing scan-local IDs to the model", async () => {
    const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
    const tools = createAnalyzerTools({
      sessionId: "session-1",
      invoke: async <T>(command: string, args?: Record<string, unknown>) => {
        calls.push({ command, args });
        if (command === "query_items") {
          return {
            items: [{
              id: "session-1:7",
              name: "Projects",
              display_path: "C:\\Users\\person\\Projects",
              allocated_bytes: "100",
              kind: "directory",
            }],
            next_cursor: null,
          } as T;
        }
        return {
          buckets: [],
          other_item_count: "0",
          other_logical_bytes: "0",
          other_allocated_bytes: "0",
        } as T;
      },
    });
    if (!tools.summarize_storage.execute) throw new Error("Aggregate tool is not executable");

    const result = await tools.summarize_storage.execute(
      { scope: "Projects", group_by: "extension", limit: 20 },
      { toolCallId: "call-3", messages: [], context: {} },
    );

    expect(calls[1]).toMatchObject({
      command: "get_storage_aggregate",
      args: { sessionId: "session-1", query: { scope_id: "session-1:7", dimension: "extension" } },
    });
    expect(result).toMatchObject({
      data: { resolved_scope: { display_path: "C:\\Users\\person\\Projects" } },
    });
  });
});
