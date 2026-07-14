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

  it("maps a bounded item query to the existing Tauri command", async () => {
    const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
    const tools = createAnalyzerTools({
      sessionId: "session-1",
      invoke: async <T>(command: string, args?: Record<string, unknown>) => {
        calls.push({ command, args });
        return { items: [], next_cursor: null } as T;
      },
    });
    if (!tools.query_storage_items.execute) throw new Error("Query tool is not executable");
    await tools.query_storage_items.execute(
      { sort: "allocated", direction: "desc", cursor: null, limit: 25 },
      { toolCallId: "call-1", messages: [], context: {} },
    );
    expect(calls[0]?.command).toBe("query_items");
    expect(calls[0]?.args).toMatchObject({
      sessionId: "session-1",
      query: { parent_id: null, sort: "allocated", direction: "desc", cursor: null, limit: 25 },
    });
    expect(tools.protect_path.needsApproval).toBe(true);
    expect(tools.inspect_log_excerpt.needsApproval).toBe(true);
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
    if (!tools.query_storage_items.execute) throw new Error("Query tool is not executable");

    const result = await tools.query_storage_items.execute(
      { scope: "Projects", sort: "allocated", direction: "desc", cursor: null, limit: 25 },
      { toolCallId: "call-2", messages: [], context: {} },
    );

    expect(calls[0]?.args).toMatchObject({
      sessionId: "session-1",
      query: { text: "Projects", kinds: ["directory"] },
    });
    expect(calls[1]?.args).toMatchObject({
      sessionId: "session-1",
      query: { scope_id: "session-1:7", sort: "allocated" },
    });
    expect(result).toMatchObject({
      data: { resolved_scope: { display_path: "C:\\Users\\person\\Projects" } },
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
    if (!tools.query_storage_items.execute) throw new Error("Query tool is not executable");

    await tools.query_storage_items.execute(
      { sort: "allocated", direction: "desc", cursor: null, limit: 25 },
      { toolCallId: "call-attached-default", messages: [], context: {} },
    );
    await tools.query_storage_items.execute(
      { scope: "C:\\Users", sort: "allocated", direction: "desc", cursor: null, limit: 25 },
      { toolCallId: "call-attached-path", messages: [], context: {} },
    );

    expect(calls).toHaveLength(2);
    expect(calls.every((call) =>
      (call.args?.query as { scope_id?: string }).scope_id === "session-1:42"
    )).toBe(true);
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
    if (!tools.query_storage_items.execute) throw new Error("Query tool is not executable");

    await tools.query_storage_items.execute(
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
    expect(calls[1]?.args).toMatchObject({ query: { scope_id: "session-1:7" } });
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
    if (!tools.get_item_evidence.execute) throw new Error("Evidence tool is not executable");

    await tools.get_item_evidence.execute(
      { item_ids: [], use_attached_item: true },
      { toolCallId: "call-attached-evidence", messages: [], context: {} },
    );

    expect(calls).toEqual([{
      command: "get_item_details",
      args: { sessionId: "session-1", nodeId: "session-1:42" },
    }]);
  });

  it("treats slash as the explicit scan root even with an attachment", async () => {
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
    if (!tools.query_storage_items.execute) throw new Error("Query tool is not executable");

    await tools.query_storage_items.execute(
      { scope: "/", sort: "allocated", direction: "desc", cursor: null, limit: 25 },
      { toolCallId: "call-root", messages: [], context: {} },
    );

    expect(calls).toHaveLength(1);
    expect(calls[0]?.args).toMatchObject({ query: { scope_id: undefined } });
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
