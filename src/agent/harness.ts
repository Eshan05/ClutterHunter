import { ToolLoopAgent, stepCountIs, tool, type LanguageModel } from "ai";
import { createOllama } from "ai-sdk-ollama";
import { z } from "zod";
import type { AgentFetch } from "./endpoint";
import type { HarnessScenarioResult, LocalModelPreflight, ModelHarnessResult, OllamaEndpoint } from "./types";

export const MODEL_HARNESS_VERSION = 7;

type HarnessTool = ReturnType<typeof tool<any, any, any>>;

const harnessInstructions = [
  "You are running a synthetic compatibility test.",
  "Use only supplied fake storage tools.",
  "Never invent paths, files, byte counts, or tool results.",
  "Keep the final answer below 80 words.",
].join(" ");

export async function runCompatibilityHarness(
  endpoint: OllamaEndpoint,
  fetch: AgentFetch,
  preflight: LocalModelPreflight,
  signal?: AbortSignal,
): Promise<ModelHarnessResult> {
  const provider = createOllama({
    baseURL: endpoint.origin,
    fetch,
  });
  const model = provider(preflight.model.name, { think: false });
  const started = performance.now();
  const scenarios: HarnessScenarioResult[] = [];

  scenarios.push(await runScenario(
    "overview-query",
    model,
    {
      get_storage_overview: tool({
        description: "Return synthetic scan totals.",
        inputSchema: z.object({}),
        execute: async () => ({ allocated_bytes: "10000000000", entry_count: "7", coverage: "complete" }),
      }),
      list_folder_children: tool({
        description: "Return synthetic immediate children inside a named folder scope.",
        inputSchema: z.object({
          scope: z.string().describe("Folder name or path to query inside."),
          limit: z.number().int().min(1).max(10),
        }),
        execute: async ({ scope }) => {
          if (scope !== "Projects") throw new Error("Use Projects as the folder scope");
          return { items: [{ id: "fixture-1", name: "video.iso", allocated_bytes: "4000000000" }] };
        },
      }),
    },
    "Call get_storage_overview, then list_folder_children inside the Projects folder with limit 5. Explain the largest item using only returned facts.",
    ["get_storage_overview", "list_folder_children"],
    (text) => /video\.iso|4000000000|4\s*gb/i.test(text),
    signal,
  ));

  scenarios.push(await runScenario(
    "cleanup-plan",
    model,
    {
      build_cleanup_plan: tool({
        description: "Return a synthetic deterministic cleanup proposal.",
        inputSchema: z.object({ target_bytes: z.string().regex(/^\d+$/) }),
        execute: async () => ({
          selected_candidate_bytes: "5000000000",
          selected_review_bytes: "0",
          review_potential_bytes: "2000000000",
          target_shortfall_bytes: "0",
        }),
      }),
    },
    "Call build_cleanup_plan for target_bytes 5000000000. Keep conservative and review-potential totals separate.",
    ["build_cleanup_plan"],
    (text) => {
      const compact = text.replace(/[,_\s]/g, "");
      return /review/i.test(text) && /5000000000|5gb/i.test(compact);
    },
    signal,
  ));

  scenarios.push(await runScenario(
    "empty-result",
    model,
    {
      search_storage: tool({
        description: "Return an empty synthetic query result.",
        inputSchema: z.object({ text: z.string(), limit: z.number().int().min(1).max(10) }),
        execute: async () => ({ items: [], next_cursor: null }),
      }),
    },
    "Search for never-present using search_storage with limit 5. State that no matching item was returned and invent nothing.",
    ["search_storage"],
    (text) => /no |none|empty|not (?:found|returned)/i.test(text) && !/[a-z]:\\/i.test(text),
    signal,
  ));

  let rejectedOnce = false;
  scenarios.push(await runScenario(
    "bounded-retry",
    model,
    {
      list_folder_children: tool({
        description: "Return synthetic items. If the tool reports a transient constraint, retry once with limit 2.",
        inputSchema: z.object({ limit: z.number().int().min(1).max(2) }),
        execute: async ({ limit }) => {
          if (!rejectedOnce) {
            rejectedOnce = true;
            throw new Error("Synthetic constraint: retry once with limit 2");
          }
          return { items: [{ id: "fixture-2", name: "retry.log", limit }] };
        },
      }),
    },
    "Call list_folder_children with limit 2. If the tool reports a constraint, retry once, then report the returned item.",
    ["list_folder_children", "list_folder_children"],
    (text) => /retry\.log/i.test(text),
    signal,
  ));

  const totalElapsedMs = Math.round(performance.now() - started);
  return {
    harnessVersion: MODEL_HARNESS_VERSION,
    model: preflight.model.name,
    digest: preflight.model.digest,
    ollamaVersion: preflight.ollamaVersion,
    passed: scenarios.every((scenario) => scenario.passed),
    firstTokenMs: median(scenarios.flatMap((scenario) =>
      scenario.firstTokenMs === null ? [] : [scenario.firstTokenMs])),
    totalElapsedMs,
    scenarios,
  };
}

async function runScenario(
  id: string,
  model: LanguageModel,
  tools: Record<string, HarnessTool>,
  prompt: string,
  expectedCalls: string[],
  answerCheck: (text: string) => boolean,
  signal?: AbortSignal,
): Promise<HarnessScenarioResult> {
  const started = performance.now();
  let firstTokenMs: number | null = null;
  try {
    const agent = new ToolLoopAgent({
      model,
      instructions: harnessInstructions,
      tools,
      stopWhen: stepCountIs(8),
      maxOutputTokens: 256,
      temperature: 0,
      maxRetries: 1,
      include: { requestBody: false, responseBody: false },
    });
    const stream = await agent.stream({
      prompt,
      abortSignal: signal,
      timeout: { totalMs: 45_000, stepMs: 20_000, chunkMs: 10_000 },
    });
    for await (const delta of stream.textStream) {
      if (firstTokenMs === null && delta.length > 0) {
        firstTokenMs = Math.round(performance.now() - started);
      }
    }
    const [text, steps] = await Promise.all([stream.text, stream.steps]);
    const calls = steps.flatMap((step) => step.toolCalls.map((call) => call.toolName));
    const outputs = steps.flatMap((step) => step.toolResults.map((result) => result.output));
    const callsPass = expectedCalls.every((name, index) => calls[index] === name);
    const effectiveAnswer = harnessAnswer(text, outputs);
    const answerPass = answerCheck(effectiveAnswer);
    return {
      id,
      passed: callsPass && answerPass,
      firstTokenMs,
      elapsedMs: Math.round(performance.now() - started),
      detail: callsPass && answerPass
        ? text.trim() ? "Passed" : "Passed with deterministic tool-result presentation"
        : [
          `Expected ${expectedCalls.join(" -> ")}; received ${calls.join(" -> ") || "no tools"}`,
          answerPass ? null : `Answer: ${effectiveAnswer.replace(/\s+/g, " ").slice(0, 180) || "<empty>"}`,
        ].filter(Boolean).join("; "),
    };
  } catch (error) {
    return {
      id,
      passed: false,
      firstTokenMs,
      elapsedMs: Math.round(performance.now() - started),
      detail: String(error).slice(0, 300),
    };
  }
}

export function harnessAnswer(text: string, toolOutputs: unknown[]): string {
  if (text.trim()) return text;
  const latest = toolOutputs.at(-1);
  if (latest && typeof latest === "object") {
    const items = (latest as Record<string, unknown>).items;
    if (Array.isArray(items) && items.length === 0) return "No matching item was returned.";
  }
  try {
    return JSON.stringify(toolOutputs);
  } catch {
    return "";
  }
}

function median(values: number[]): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? Math.round(((sorted[middle - 1] ?? 0) + (sorted[middle] ?? 0)) / 2)
    : sorted[middle] ?? null;
}
