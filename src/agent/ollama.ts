import { z } from "zod";
import type { AgentFetch } from "./endpoint";
import { AgentRuntimeError, type InstalledOllamaModel, type LocalModelPreflight, type OllamaEndpoint, type OllamaModelShow } from "./types";

const MAX_OLLAMA_RESPONSE_BYTES = 2 * 1024 * 1024;
const MODEL_PREFLIGHT_TIMEOUT_MS = 120_000;
const digestPattern = /^[a-f0-9]{64}$/i;
const forbiddenMetadataPattern = /(?:remote[_ -]?(?:model|host)?|cloud|web[_ -]?search|offload)/i;

const modelDetailsSchema = z.object({
  format: z.string().optional(),
  family: z.string().optional(),
  families: z.array(z.string()).nullable().optional().transform((families) => families ?? undefined),
  parameter_size: z.string().optional(),
  quantization_level: z.string().optional(),
}).passthrough();

const installedModelSchema = z.object({
  name: z.string().min(1),
  model: z.string().min(1),
  modified_at: z.string(),
  size: z.number().positive(),
  digest: z.string().min(1),
  details: modelDetailsSchema,
});

const tagsSchema = z.object({ models: z.array(installedModelSchema) });
const runningModelSchema = z.object({
  name: z.string().min(1),
  model: z.string().min(1),
  size: z.number().nonnegative(),
  digest: z.string().min(1),
  size_vram: z.number().nonnegative(),
  context_length: z.number().int().nonnegative(),
  expires_at: z.string(),
});
const runningModelsSchema = z.object({ models: z.array(runningModelSchema) });
const versionSchema = z.object({ version: z.string().min(1) }).passthrough();
const showSchema = z.object({
  capabilities: z.array(z.string()).default([]),
  modified_at: z.string().optional(),
  details: modelDetailsSchema.optional(),
  model_info: z.record(z.string(), z.unknown()).optional(),
  parameters: z.string().optional(),
}).passthrough();
const chatSchema = z.object({
  model: z.string().min(1),
  message: z.object({
    role: z.string(),
    content: z.string().optional(),
    thinking: z.string().optional(),
    tool_calls: z.array(z.unknown()).optional(),
  }).passthrough(),
  done: z.boolean(),
  total_duration: z.number().optional(),
}).passthrough();

export class OllamaClient {
  readonly endpoint: OllamaEndpoint;
  readonly fetch: AgentFetch;

  constructor(endpoint: OllamaEndpoint, fetch: AgentFetch) {
    this.endpoint = endpoint;
    this.fetch = fetch;
  }

  async getVersion(): Promise<string> {
    const payload = await this.requestJson("/api/version", { method: "GET" });
    return parseResponse(versionSchema, payload, "version").version;
  }

  async listModels(): Promise<InstalledOllamaModel[]> {
    const payload = await this.requestJson("/api/tags", { method: "GET" });
    return parseResponse(tagsSchema, payload, "model list").models.filter(isPlausiblyLocal);
  }

  async listRunningModels(): Promise<Array<NonNullable<InstalledOllamaModel["loaded"]> & { name: string; digest: string }>> {
    const payload = await this.requestJson("/api/ps", { method: "GET" });
    return parseResponse(runningModelsSchema, payload, "running model list").models.map((model) => ({
      name: model.name,
      digest: model.digest,
      sizeBytes: model.size,
      sizeVramBytes: model.size_vram,
      contextLength: model.context_length,
      expiresAt: model.expires_at,
    }));
  }

  async showModel(name: string): Promise<OllamaModelShow> {
    const payload = await this.requestJson("/api/show", jsonRequest({ model: name, verbose: false }));
    return parseResponse(showSchema, payload, "model details");
  }

  async proveLocalModel(name: string): Promise<LocalModelPreflight> {
    if (isCloudModelName(name)) {
      throw new AgentRuntimeError("MODEL_NOT_LOCAL", `Model ${name} is a cloud model`, false);
    }
    const [ollamaVersion, models] = await Promise.all([this.getVersion(), this.listModels()]);
    const model = models.find((candidate) => candidate.name === name || candidate.model === name);
    if (!model) {
      throw new AgentRuntimeError("MODEL_NOT_INSTALLED", `Model ${name} is not installed locally`);
    }
    assertPlausiblyLocal(model);

    const show = await this.showModel(model.name);
    if (!show.capabilities.some((capability) => capability.toLocaleLowerCase() === "tools")) {
      throw new AgentRuntimeError(
        "MODEL_TOOLS_UNSUPPORTED",
        `Model ${model.name} does not report Ollama tool capability`,
      );
    }

    const rawChat = await this.requestJson("/api/chat", jsonRequest({
      model: model.name,
      messages: [{ role: "user", content: "Reply with the single word LOCAL." }],
      stream: false,
      think: false,
      options: { num_predict: 8, num_ctx: 512, temperature: 0 },
    }), MODEL_PREFLIGHT_TIMEOUT_MS);
    const chat = parseResponse(chatSchema, rawChat, "native preflight");
    if (isCloudModelName(chat.model)) {
      throw new AgentRuntimeError("MODEL_NOT_LOCAL", "Ollama resolved the model to a cloud tag", false);
    }
    const acceptedNames = new Set([model.name.toLocaleLowerCase(), model.model.toLocaleLowerCase()]);
    if (!acceptedNames.has(chat.model.toLocaleLowerCase())) {
      throw new AgentRuntimeError(
        "MODEL_NOT_LOCAL",
        `Ollama resolved ${model.name} to unexpected model ${chat.model}`,
        false,
      );
    }
    assertNoRemoteMetadata(rawChat);
    return {
      model,
      show,
      ollamaVersion,
      totalDurationNs: chat.total_duration ?? null,
    };
  }

  private async requestJson(
    path: string,
    init: RequestInit,
    timeoutMs = 5_000,
  ): Promise<unknown> {
    let response: Response;
    try {
      response = await this.fetch(`${this.endpoint.origin}${path}`, {
        ...init,
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      if (error instanceof AgentRuntimeError) throw error;
      throw new AgentRuntimeError(
        "OLLAMA_UNAVAILABLE",
        `Could not reach Ollama on ${this.endpoint.origin}: ${String(error)}`,
      );
    }
    const text = await response.text();
    if (text.length > MAX_OLLAMA_RESPONSE_BYTES) {
      throw new AgentRuntimeError("OLLAMA_RESPONSE_INVALID", "Ollama response exceeded 2 MiB", false);
    }
    if (!response.ok) {
      throw new AgentRuntimeError(
        "OLLAMA_UNAVAILABLE",
        `Ollama returned HTTP ${response.status}: ${text.slice(0, 300)}`,
      );
    }
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new AgentRuntimeError("OLLAMA_RESPONSE_INVALID", "Ollama returned invalid JSON", false);
    }
  }
}

export function isCloudModelName(name: string): boolean {
  const normalized = name.trim().toLocaleLowerCase();
  const tag = normalized.split("/").at(-1) ?? normalized;
  const [repository, variant = ""] = tag.split(":", 2);
  return repository.endsWith("-cloud") || variant === "cloud" || variant.endsWith("-cloud");
}

export function assertPlausiblyLocal(model: InstalledOllamaModel): void {
  if (!isPlausiblyLocal(model)) {
    throw new AgentRuntimeError(
      "MODEL_NOT_LOCAL",
      `Model ${model.name} lacks trustworthy local blob metadata`,
      false,
    );
  }
}

function isPlausiblyLocal(model: InstalledOllamaModel): boolean {
  const details = model.details;
  const metadata = model as unknown as Record<string, unknown>;
  return !(
    isCloudModelName(model.name)
    || isCloudModelName(model.model)
    || typeof metadata.remote_host === "string"
    || typeof metadata.remote_model === "string"
    || !digestPattern.test(model.digest)
    || !Number.isSafeInteger(model.size)
    || model.size <= 0
    || !details.format
    || !(details.family || details.parameter_size || details.quantization_level)
  );
}

export function assertNoRemoteMetadata(payload: unknown): void {
  if (!payload || typeof payload !== "object") {
    throw new AgentRuntimeError("MODEL_PREFLIGHT_FAILED", "Ollama preflight metadata was invalid", false);
  }
  const metadata = { ...(payload as Record<string, unknown>) };
  delete metadata.message;
  const pending: unknown[] = [metadata];
  let visited = 0;
  while (pending.length > 0 && visited < 10_000) {
    const value = pending.pop();
    visited += 1;
    if (typeof value === "string" && forbiddenMetadataPattern.test(value)) {
      throw new AgentRuntimeError("MODEL_NOT_LOCAL", "Ollama reported remote or cloud execution metadata", false);
    }
    if (Array.isArray(value)) {
      pending.push(...value);
    } else if (value && typeof value === "object") {
      for (const [key, child] of Object.entries(value)) {
        if (forbiddenMetadataPattern.test(key)) {
          throw new AgentRuntimeError("MODEL_NOT_LOCAL", "Ollama reported remote or cloud execution metadata", false);
        }
        pending.push(child);
      }
    }
  }
  if (pending.length > 0) {
    throw new AgentRuntimeError(
      "MODEL_PREFLIGHT_FAILED",
      "Ollama preflight metadata was too complex to validate safely",
      false,
    );
  }
}

function jsonRequest(body: unknown): RequestInit {
  return {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  };
}

function parseResponse<T>(schema: z.ZodType<T>, payload: unknown, label: string): T {
  const parsed = schema.safeParse(payload);
  if (!parsed.success) {
    throw new AgentRuntimeError(
      "OLLAMA_RESPONSE_INVALID",
      `Ollama ${label} response did not match the expected schema`,
      false,
    );
  }
  return parsed.data;
}
