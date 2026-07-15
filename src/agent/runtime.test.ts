import { describe, expect, it } from "vitest";
import {
  authoritativeToolText,
  compactSessionHistory,
  deterministicStorageQueryForPrompt,
  evidenceToolForPrompt,
  fallbackToolText,
  OllamaAgentRuntime,
  promptRequestsScanRoot,
  turnResult,
} from "./runtime";

describe("Ollama agent runtime discovery", () => {
  it("combines local Ollama discovery with the bounded Rust hardware profile", async () => {
    const runtime = new OllamaAgentRuntime({
      invoke: async <T>(command: string) => {
        expect(command).toBe("get_hardware_profile");
        return {
          total_memory_bytes: "8000000000",
          available_memory_bytes: "4000000000",
        } as T;
      },
      fetch: async (input) => {
        const path = new URL(typeof input === "string" ? input : input instanceof URL ? input : input.url).pathname;
        if (path === "/api/version") return Response.json({ version: "0.30.7" });
        if (path === "/api/ps") return Response.json({ models: [] });
        return Response.json({
          models: [{
            name: "qwen3.5:2b",
            model: "qwen3.5:2b",
            modified_at: "2026-07-14T00:00:00Z",
            size: 1_600_000_000,
            digest: "a".repeat(64),
            details: { format: "gguf", family: "qwen", parameter_size: "2B" },
          }],
        });
      },
    });
    const discovered = await runtime.discover();
    expect(discovered.ollamaVersion).toBe("0.30.7");
    expect(discovered.models).toHaveLength(1);
    expect(discovered.hardware).toEqual({
      totalMemoryBytes: 8_000_000_000,
      availableMemoryBytes: 4_000_000_000,
    });
  });
});

describe("deterministic tool-only fallback", () => {
  it("renders bounded analyzer items when a local model returns no prose", () => {
    expect(fallbackToolText({
      component: "ItemListResult",
      data: {
        resolved_scope: { display_path: "C:\\Work" },
        items: [{ name: "build", allocated_bytes: "1073741824" }],
      },
    })).toContain("build: 1.0 GB");
  });

  it("returns an explicit diagnostic when a model produces no text or tool result", () => {
    expect(fallbackToolText(null)).toContain("without an answer or storage evidence");
  });

  it("treats factual item results as authoritative even when model prose exists", () => {
    expect(authoritativeToolText({
      component: "ItemListResult",
      data: {
        resolved_scope: { display_path: "C:\\Users\\redma" },
        query_context: { sort: "logical", kinds: ["directory"] },
        items: [{
          name: "AppData",
          display_path: "C:\\Users\\redma\\AppData",
          logical_bytes: "2147483648",
          allocated_bytes: "1073741824",
        }],
      },
    })).toContain("C:\\Users\\redma\\AppData: 2.0 GB");
  });

  it("formats folder inspection and cleanup opportunities from typed evidence", () => {
    expect(authoritativeToolText({
      component: "FolderInspectionResult",
      data: {
        scope: { display_path: "C:\\Work", allocated_bytes: "4294967296" },
        top_children: [{ display_path: "C:\\Work\\target", allocated_bytes: "3221225472" }],
      },
    })).toContain("C:\\Work\\target: 3.0 GB");
    expect(authoritativeToolText({
      component: "CleanupOpportunitiesResult",
      data: {
        conservative_bytes: "1073741824",
        review_potential_bytes: "2147483648",
        items: [{ title: "Generated build data", tier: "review_required", reclaimable_bytes: "2147483648" }],
      },
    })).toContain("Generated build data: 2.0 GB (review required)");
  });
});

describe("deterministic evidence routing", () => {
  it("turns common ranked storage questions into typed local queries", () => {
    expect(deterministicStorageQueryForPrompt("Which folders in GitTree are the biggest?"))
      .toEqual({
        scope: "GitTree",
        kinds: ["directory"],
        sort: "allocated",
        direction: "desc",
        cursor: null,
        limit: 25,
      });
    expect(deterministicStorageQueryForPrompt("Show top 10 files in C:\\Users\\redma by logical size"))
      .toMatchObject({
        scope: "C:\\Users\\redma",
        kinds: ["file"],
        sort: "logical",
        direction: "desc",
        limit: 10,
        recursive: true,
        topOnly: true,
        mode: "largest",
      });
    expect(deterministicStorageQueryForPrompt("All folders?"))
      .toMatchObject({ scope: undefined, kinds: ["directory"], limit: 100 });
    expect(deterministicStorageQueryForPrompt(
      "Call list_folder_children once with scope Projects, sort allocated, and report the largest item.",
    )).toMatchObject({ scope: "Projects", sort: "allocated" });
    expect(deterministicStorageQueryForPrompt(
      "All files? Keep the same folder scope and use a fresh storage query.",
    )).toMatchObject({ scope: undefined, kinds: ["file"] });
  });

  it("leaves ambiguous conversation to the model", () => {
    expect(deterministicStorageQueryForPrompt("Why is my storage filling up?"))
      .toBeNull();
  });

  it("forces fresh item queries for folder questions and path corrections", () => {
    expect(evidenceToolForPrompt("What are the largest folders in C:\\Users\\redma?", "investigate"))
      .toBe("list_folder_children");
    expect(evidenceToolForPrompt("All folders?", "investigate")).toBe("list_folder_children");
    expect(evidenceToolForPrompt("No, I mean Users/redma", "investigate")).toBe("list_folder_children");
  });

  it("routes aggregate and overview questions without forcing ordinary chat", () => {
    expect(evidenceToolForPrompt("Break this down by extension", "investigate")).toBe("summarize_storage");
    expect(evidenceToolForPrompt("What is the scan coverage?", "investigate")).toBe("get_storage_overview");
    expect(evidenceToolForPrompt("Inspect this item", "investigate")).toBe("inspect_item");
    expect(evidenceToolForPrompt("Can I delete pagefile.sys?", "investigate")).toBe("inspect_item");
    expect(evidenceToolForPrompt("Can I remove AppData?", "investigate")).toBe("inspect_item");
    expect(evidenceToolForPrompt("Why is this folder so large?", "investigate")).toBe("inspect_folder");
    expect(evidenceToolForPrompt("What can I safely remove?", "investigate")).toBe("list_cleanup_opportunities");
    expect(evidenceToolForPrompt("What should I delete?", "investigate")).toBe("list_cleanup_opportunities");
    expect(evidenceToolForPrompt("Which folders can I remove?", "investigate")).toBe("list_cleanup_opportunities");
    expect(evidenceToolForPrompt("Give me deletion recommendations", "investigate")).toBe("list_cleanup_opportunities");
    expect(evidenceToolForPrompt("Largest files anywhere under Downloads?", "investigate")).toBe("list_largest_items");
    expect(evidenceToolForPrompt("Find files named archive", "investigate")).toBe("search_storage");
    expect(evidenceToolForPrompt("Hello there", "investigate")).toBeNull();
  });

  it("allows root scope only when the user explicitly requests it", () => {
    expect(promptRequestsScanRoot("Show the entire drive")).toBe(true);
    expect(promptRequestsScanRoot("Show C:\\")).toBe(true);
    expect(promptRequestsScanRoot("What is inside the selected folder?")).toBe(false);
  });

  it("rejects model prose when its required evidence tool never ran", () => {
    const resultState = { latest: null, completed: [], presentedCount: 0 };
    const result = turnResult(
      {
        text: "GitTree/Dockerfile is 900 GB.",
        finishReason: "stop",
        usage: {},
      },
      [],
      [],
      null,
      resultState,
      "list_folder_children",
    );

    expect(result.text).toContain("did not execute");
    expect(result.text).not.toContain("Dockerfile");
    expect(result.activities[0]).toMatchObject({
      tool: "list_folder_children",
      state: "failed",
    });
    expect(result.results[0]).toMatchObject({ component: "ToolErrorResult" });
  });
});

describe("bounded session context", () => {
  it("retains recent turns and summarizes dropped local conversation text", () => {
    const input = Array.from({ length: 16 }, (_, index) => ({
      role: index % 2 === 0 ? "user" as const : "assistant" as const,
      content: `message-${index}`,
    }));
    const compacted = compactSessionHistory(input);
    expect(compacted.messages).toHaveLength(12);
    expect(compacted.messages[0]).toEqual({ role: "user", content: "message-4" });
    expect(compacted.summary).toContain("User: message-0");
    expect(compacted.summary).toContain("Assistant: message-3");
  });
});
