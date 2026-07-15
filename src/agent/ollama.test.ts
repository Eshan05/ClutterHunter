import { describe, expect, it } from "vitest";
import { canonicalizeOllamaEndpoint, createLoopbackFetch } from "./endpoint";
import { OllamaClient, assertNoRemoteMetadata, assertPlausiblyLocal, isCloudModelName } from "./ollama";
import type { InstalledOllamaModel } from "./types";

const digest = "a".repeat(64);
const localModel: InstalledOllamaModel = {
  name: "qwen3.5:2b",
  model: "qwen3.5:2b",
  modified_at: "2026-07-14T00:00:00Z",
  size: 1_600_000_000,
  digest,
  details: { format: "gguf", family: "qwen", parameter_size: "2B", quantization_level: "Q4_K_M" },
};

describe("Ollama local residency gate", () => {
  it("rejects cloud naming variants", () => {
    expect(isCloudModelName("gpt-oss:120b-cloud")).toBe(true);
    expect(isCloudModelName("namespace/model-cloud:latest")).toBe(true);
    expect(isCloudModelName("qwen3.5:2b")).toBe(false);
  });

  it("requires a digest, blob size, and plausible model details", () => {
    expect(() => assertPlausiblyLocal(localModel)).not.toThrow();
    expect(() => assertPlausiblyLocal({ ...localModel, digest: "short" })).toThrow(/trustworthy/);
    expect(() => assertPlausiblyLocal({ ...localModel, size: 0 })).toThrow(/trustworthy/);
  });

  it("filters mixed cloud catalog entries without rejecting local discovery", async () => {
    const endpoint = canonicalizeOllamaEndpoint(11_434);
    const fetch = createLoopbackFetch(endpoint, async () => Response.json({
      models: [
        {
          ...localModel,
          name: "glm-5.2:cloud",
          model: "glm-5.2:cloud",
          size: 338,
          remote_model: "glm-5.2",
          remote_host: "https://ollama.com:443",
          details: { format: "", family: "glm", families: null, parameter_size: "756b" },
        },
        localModel,
      ],
    }));

    await expect(new OllamaClient(endpoint, fetch).listModels()).resolves.toEqual([localModel]);
  });

  it("reads current model residency from the bounded local ps endpoint", async () => {
    const endpoint = canonicalizeOllamaEndpoint(11_434);
    const fetch = createLoopbackFetch(endpoint, async () => Response.json({
      models: [{
        name: localModel.name,
        model: localModel.model,
        digest: localModel.digest,
        size: 1_692_244_376,
        size_vram: 1_692_244_376,
        context_length: 4_096,
        expires_at: "2026-07-15T10:00:00+05:30",
      }],
    }));

    await expect(new OllamaClient(endpoint, fetch).listRunningModels()).resolves.toEqual([{
      name: localModel.name,
      digest: localModel.digest,
      sizeBytes: 1_692_244_376,
      sizeVramBytes: 1_692_244_376,
      contextLength: 4_096,
      expiresAt: "2026-07-15T10:00:00+05:30",
    }]);
  });

  it("ignores assistant content but rejects remote response metadata", () => {
    expect(() => assertNoRemoteMetadata({
      model: "qwen3.5:2b",
      message: { content: "The word cloud in user data is untrusted content" },
      done: true,
    })).not.toThrow();
    expect(() => assertNoRemoteMetadata({
      model: "qwen3.5:2b",
      remote_host: "example.com",
      message: { content: "LOCAL" },
    })).toThrow(/remote or cloud/);
  });

  it("completes version, tags, show, and native-chat preflight", async () => {
    const endpoint = canonicalizeOllamaEndpoint(11_434);
    const fetch = createLoopbackFetch(endpoint, async (input) => {
      const path = new URL(typeof input === "string" ? input : input instanceof URL ? input : input.url).pathname;
      const payload = path === "/api/version"
        ? { version: "0.12.0" }
        : path === "/api/tags"
          ? { models: [localModel] }
          : path === "/api/show"
            ? { capabilities: ["completion", "tools"], details: localModel.details }
            : { model: localModel.name, message: { role: "assistant", content: "LOCAL" }, done: true, total_duration: 42 };
      return Response.json(payload);
    });
    const result = await new OllamaClient(endpoint, fetch).proveLocalModel(localModel.name);
    expect(result.model.digest).toBe(digest);
    expect(result.show.capabilities).toContain("tools");
    expect(result.totalDurationNs).toBe(42);
  });

  it("reports an unavailable local service without falling back to another host", async () => {
    const endpoint = canonicalizeOllamaEndpoint(11_434);
    const client = new OllamaClient(endpoint, async () => {
      throw new TypeError("connection refused");
    });
    await expect(client.listModels()).rejects.toMatchObject({ code: "OLLAMA_UNAVAILABLE" });
  });
});
