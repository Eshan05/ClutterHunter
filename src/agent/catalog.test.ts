import { describe, expect, it } from "vitest";
import { rankInstalledModels } from "./catalog";
import type { InstalledOllamaModel, ModelHarnessResult } from "./types";

function model(name: string, digest: string, size: number): InstalledOllamaModel {
  return {
    name,
    model: name,
    modified_at: "2026-07-14T00:00:00Z",
    size,
    digest,
    details: { format: "gguf", family: "test", parameter_size: "2B" },
  };
}

function harness(target: InstalledOllamaModel, passed: boolean, elapsed: number): ModelHarnessResult {
  return {
    harnessVersion: 1,
    model: target.name,
    digest: target.digest,
    ollamaVersion: "0.12.0",
    passed,
    firstTokenMs: null,
    totalElapsedMs: elapsed,
    scenarios: [{ id: "one", passed, firstTokenMs: 1, elapsedMs: elapsed, detail: "test" }],
  };
}

describe("model ranking", () => {
  it("puts harness correctness before speed or curated quality", () => {
    const balanced = model("qwen3.5:2b", "a".repeat(64), 1_600_000_000);
    const light = model("qwen3.5:0.8b", "b".repeat(64), 700_000_000);
    const results = new Map([
      [balanced.digest, harness(balanced, true, 20_000)],
      [light.digest, harness(light, false, 2_000)],
    ]);
    const ranked = rankInstalledModels([light, balanced], { totalMemoryBytes: 8_000_000_000 }, results);
    expect(ranked[0]?.installed.name).toBe(balanced.name);
    expect(ranked[0]?.memoryFit).toBe(true);
  });

  it("marks a model unfit when current available memory cannot load its local blob", () => {
    const balanced = model("qwen3.5:2b", "c".repeat(64), 2_741_192_820);
    const [ranked] = rankInstalledModels(
      [balanced],
      { totalMemoryBytes: 8_000_000_000, availableMemoryBytes: 2_100_000_000 },
      new Map(),
    );

    expect(ranked?.memoryFit).toBe(false);
    expect(ranked?.headroomBytes).toBeLessThan(0);
  });

  it("does not charge an already resident model against free RAM a second time", () => {
    const light = model("granite4:1b-h", "d".repeat(64), 1_600_000_000);
    light.loaded = {
      sizeBytes: 1_692_244_376,
      sizeVramBytes: 1_692_244_376,
      contextLength: 4_096,
      expiresAt: "2026-07-15T10:00:00+05:30",
    };
    const [ranked] = rankInstalledModels(
      [light],
      { totalMemoryBytes: 8_000_000_000, availableMemoryBytes: 300_000_000 },
      new Map(),
    );

    expect(ranked?.memoryFit).toBe(true);
  });
});
