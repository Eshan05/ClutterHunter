import { generateText, tool } from "ai";
import { createOllama } from "ai-sdk-ollama";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { canonicalizeOllamaEndpoint, createLoopbackFetch } from "./endpoint";

const environment = (globalThis as {
  process?: { env?: Record<string, string | undefined> };
}).process?.env;
const liveModel = environment?.CLUTTERHUNTER_ROUTER_LIVE_MODEL?.trim() ?? "";

const routerTools = {
  get_storage_overview: tool({
    description: "Read scan totals and coverage.",
    inputSchema: z.object({}),
  }),
  list_folder_children: tool({
    description: "List immediate files or folders inside an optional named scope.",
    inputSchema: z.object({
      scope: z.string().optional(),
      kinds: z.array(z.enum(["file", "directory"])).optional(),
      sort: z.enum(["allocated", "logical", "modified", "name"]),
      direction: z.enum(["asc", "desc"]),
      limit: z.number().int().min(1).max(100),
    }),
  }),
  summarize_storage: tool({
    description: "Group storage by extension, owner, policy, or kind.",
    inputSchema: z.object({
      scope: z.string().optional(),
      group_by: z.enum(["extension", "owner", "policy", "kind"]),
      limit: z.number().int().min(1).max(50),
    }),
  }),
  build_cleanup_plan: tool({
    description: "Build a deterministic cleanup proposal for an optional target byte count.",
    inputSchema: z.object({ target_bytes: z.string().regex(/^\d+$/).optional() }),
  }),
};

const scenarios = [
  {
    prompt: "How much space is indexed and is scan coverage complete?",
    tool: "get_storage_overview",
    arguments: {},
  },
  {
    prompt: "Which folders in GitTree are the biggest? Show 25 by allocated size.",
    tool: "list_folder_children",
    arguments: {
      scope: "GitTree",
      kinds: ["directory"],
      sort: "allocated",
      direction: "desc",
      limit: 25,
    },
  },
  {
    prompt: "Break down the selected folder by extension. Show 20 groups.",
    tool: "summarize_storage",
    arguments: { group_by: "extension", limit: 20 },
  },
  {
    prompt: "Build a cleanup plan targeting exactly 5000000000 bytes.",
    tool: "build_cleanup_plan",
    arguments: { target_bytes: "5000000000" },
  },
] as const;

describe.skipIf(!liveModel)("live single-call function router", () => {
  it("selects exact storage tools and validated arguments", async () => {
    const endpoint = canonicalizeOllamaEndpoint(11_434);
    const provider = createOllama({
      baseURL: endpoint.origin,
      fetch: createLoopbackFetch(endpoint, (input, init) => globalThis.fetch(input, init)),
    });
    const model = provider(liveModel, { think: false });
    const failures: string[] = [];

    for (const scenario of scenarios) {
      try {
        const result = await generateText({
          model,
          tools: routerTools,
          toolChoice: "required",
          prompt: scenario.prompt,
          temperature: 0,
          maxOutputTokens: 128,
          timeout: { totalMs: 30_000 },
        });
        const call = result.toolCalls[0];
        if (!call || call.toolName !== scenario.tool) {
          failures.push(`${scenario.tool}: received ${call?.toolName ?? "no tool"}`);
          continue;
        }
        if (JSON.stringify(call.input) !== JSON.stringify(scenario.arguments)) {
          failures.push(`${scenario.tool}: received ${JSON.stringify(call.input)}`);
        }
      } catch (error) {
        failures.push(`${scenario.tool}: ${String(error).slice(0, 240)}`);
      }
    }

    expect(failures, failures.join("\n")).toEqual([]);
  }, 180_000);
});
