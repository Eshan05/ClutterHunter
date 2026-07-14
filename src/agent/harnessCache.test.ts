import { describe, expect, it } from "vitest";
import { MODEL_HARNESS_VERSION } from "./harness";
import { LocalHarnessCache } from "./harnessCache";
import type { LocalModelPreflight, ModelHarnessResult } from "./types";

describe("harness cache", () => {
  it("keys results by digest, Ollama version, and harness version", () => {
    const values = new Map<string, string>();
    const cache = new LocalHarnessCache({
      getItem: (key) => values.get(key) ?? null,
      setItem: (key, value) => values.set(key, value),
    });
    const preflight = fixturePreflight();
    const result: ModelHarnessResult = {
      harnessVersion: MODEL_HARNESS_VERSION,
      model: preflight.model.name,
      digest: preflight.model.digest,
      ollamaVersion: preflight.ollamaVersion,
      passed: true,
      firstTokenMs: null,
      totalElapsedMs: 10,
      scenarios: ["overview-query", "cleanup-plan", "empty-result", "bounded-retry"].map((id) => ({
        id,
        passed: true,
        firstTokenMs: 1,
        elapsedMs: 1,
        detail: "Passed",
      })),
    };
    cache.set(result);
    expect(cache.get(preflight)).toEqual(result);
    expect(cache.get({ ...preflight, ollamaVersion: "different" })).toBeNull();
  });
});

function fixturePreflight(): LocalModelPreflight {
  return {
    model: {
      name: "qwen3.5:2b",
      model: "qwen3.5:2b",
      modified_at: "2026-07-14T00:00:00Z",
      size: 1_600_000_000,
      digest: "a".repeat(64),
      details: { format: "gguf", family: "qwen", parameter_size: "2B" },
    },
    show: { capabilities: ["tools"] },
    ollamaVersion: "0.12.0",
    totalDurationNs: 1,
  };
}
