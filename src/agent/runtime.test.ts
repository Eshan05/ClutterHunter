import { describe, expect, it } from "vitest";
import { compactSessionHistory, fallbackToolText, OllamaAgentRuntime } from "./runtime";

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
