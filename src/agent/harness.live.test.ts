import { describe, expect, it } from "vitest";
import { canonicalizeOllamaEndpoint, createLoopbackFetch } from "./endpoint";
import { runCompatibilityHarness } from "./harness";
import { OllamaClient } from "./ollama";

const environment = (globalThis as {
  process?: { env?: Record<string, string | undefined> };
}).process?.env;
const liveModels = environment?.CLUTTERHUNTER_LIVE_MODELS
  ?.split(",")
  .map((model) => model.trim())
  .filter(Boolean) ?? [];

describe.skipIf(liveModels.length === 0)("live Ollama compatibility", () => {
  for (const model of liveModels) {
    it(`proves and exercises ${model}`, async () => {
      const endpoint = canonicalizeOllamaEndpoint(11_434);
      const fetch = createLoopbackFetch(endpoint, (input, init) => globalThis.fetch(input, init));
      const client = new OllamaClient(endpoint, fetch);
      const preflight = await client.proveLocalModel(model);
      const result = await runCompatibilityHarness(endpoint, fetch, preflight);

      console.info(JSON.stringify(result, null, 2));
      expect(result.passed, result.scenarios.map((scenario) => `${scenario.id}: ${scenario.detail}`).join("\n"))
        .toBe(true);
    }, 240_000);
  }
});
