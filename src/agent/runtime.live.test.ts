import { describe, expect, it } from "vitest";
import type { CleanupPlan } from "../bindings/CleanupPlan";
import type { ItemDetails } from "../bindings/ItemDetails";
import type { ItemPage } from "../bindings/ItemPage";
import type { LogExcerptBatch } from "../bindings/LogExcerptBatch";
import type { ScanSummary } from "../bindings/ScanSummary";
import { canonicalizeOllamaEndpoint, createLoopbackFetch } from "./endpoint";
import { LocalHarnessCache } from "./harnessCache";
import { OllamaAgentRuntime } from "./runtime";
import type { AnalyzerInvoke } from "./tools";

const environment = (globalThis as {
  process?: { env?: Record<string, string | undefined> };
}).process?.env;
const liveModel = environment?.CLUTTERHUNTER_AGENT_LIVE_MODEL?.trim() ?? "";

describe.skipIf(!liveModel)("live Ollama agent runtime", () => {
  it("hands off a plan and enforces denied and approved exact-path reads", async () => {
    const endpoint = canonicalizeOllamaEndpoint(11_434);
    const fetch = createLoopbackFetch(endpoint, (input, init) => globalThis.fetch(input, init));
    const invoked: string[] = [];
    const invoke = createFixtureInvoke(invoked);
    const runtime = new OllamaAgentRuntime({
      invoke,
      fetch,
      cache: new LocalHarnessCache(null),
    });
    const preparedModel = await runtime.prepareModel(liveModel);
    expect(preparedModel.harness.passed).toBe(true);

    const planSession = runtime.createSession({
      sessionId: "live-agent-fixture",
      workflow: "plan",
      preparedModel,
    });
    const planResult = await planSession.streamTurn(
      "Call build_cleanup_plan exactly once with target_bytes 5000000000. Use its result as the final answer.",
      () => undefined,
    );
    expect(planResult.plan).toEqual(fixturePlan);
    expect(planResult.activities.some((activity) =>
      activity.tool === "build_cleanup_plan" && activity.state === "completed")).toBe(true);

    const scopedSession = runtime.createSession({
      sessionId: "live-agent-fixture",
      workflow: "investigate",
      preparedModel,
    });
    const scopedResult = await scopedSession.streamTurn(
      "Call query_storage_items once with scope Projects, sort allocated, direction desc, and limit 5. Report the largest returned item by name.",
      () => undefined,
    );
    expect(scopedResult.activities.some((activity) =>
      activity.tool === "query_storage_items" && activity.state === "completed")).toBe(true);
    expect(scopedResult.text).toMatch(/bundle\.zip/i);

    const attachedSession = runtime.createSession({
      sessionId: "live-agent-fixture",
      workflow: "investigate",
      preparedModel,
    });
    attachedSession.setAttachment({
      id: fixtureDirectory.id,
      name: fixtureDirectory.name,
      displayPath: fixtureDirectory.display_path,
      kind: fixtureDirectory.kind,
      allocatedBytes: fixtureDirectory.allocated_bytes,
      logicalBytes: fixtureDirectory.logical_bytes,
      policyTier: fixtureDirectory.policy.tier,
    });
    const attachedResult = await attachedSession.streamTurn(
      "What are the largest items in the selected folder? Use one storage query.",
      () => undefined,
    );
    expect(attachedResult.activities.some((activity) =>
      activity.tool === "query_storage_items" && activity.state === "completed")).toBe(true);
    expect(attachedResult.text).toMatch(/bundle\.zip/i);

    const attachedEvidenceSession = runtime.createSession({
      sessionId: "live-agent-fixture",
      workflow: "investigate",
      preparedModel,
    });
    attachedEvidenceSession.setAttachment({
      id: fixtureDirectory.id,
      name: fixtureDirectory.name,
      displayPath: fixtureDirectory.display_path,
      kind: fixtureDirectory.kind,
      allocatedBytes: fixtureDirectory.allocated_bytes,
      logicalBytes: fixtureDirectory.logical_bytes,
      policyTier: fixtureDirectory.policy.tier,
    });
    const attachedEvidence = await attachedEvidenceSession.streamTurn(
      "Call get_item_evidence exactly once with use_attached_item true. Do not copy an item ID.",
      () => undefined,
    );
    expect(attachedEvidence.activities.some((activity) =>
      activity.tool === "get_item_evidence"
      && activity.state === "completed"
      && activity.arguments.use_attached_item === true)).toBe(true);

    const deniedSession = runtime.createSession({
      sessionId: "live-agent-fixture",
      workflow: "investigate",
      preparedModel,
    });
    const deniedRequest = await deniedSession.streamTurn(
      "Call inspect_log_excerpt exactly once for item_ids [\"log-1\"] and requested_bytes_per_file 1024. Do not call another tool.",
      () => undefined,
    );
    expect(deniedRequest.approvals).toHaveLength(1);
    expect(deniedRequest.approvals[0]).toMatchObject({
      tool: "inspect_log_excerpt",
      exactPaths: ["C:\\logs\\synthetic.log"],
      maximumBytes: 1_024,
    });
    const denied = await deniedSession.streamResolveApprovals(
      [{ approvalId: deniedRequest.approvals[0]!.approvalId, approved: false, reason: "Live denial test" }],
      () => undefined,
    );
    expect(denied.approvals).toHaveLength(0);
    expect(denied.activities.some((activity) =>
      activity.tool === "inspect_log_excerpt" && activity.state === "cancelled")).toBe(true);
    expect(invoked.filter((command) => command === "inspect_log_excerpt")).toHaveLength(0);

    const approvedSession = runtime.createSession({
      sessionId: "live-agent-fixture",
      workflow: "investigate",
      preparedModel,
    });
    const approvedRequest = await approvedSession.streamTurn(
      "Call inspect_log_excerpt exactly once for item_ids [\"log-1\"] and requested_bytes_per_file 1024. Do not call another tool.",
      () => undefined,
    );
    expect(approvedRequest.approvals).toHaveLength(1);
    expect(approvedRequest.approvals[0]?.exactPaths).toEqual(["C:\\logs\\synthetic.log"]);
    const approved = await approvedSession.streamResolveApprovals(
      [{ approvalId: approvedRequest.approvals[0]!.approvalId, approved: true }],
      () => undefined,
    );
    expect(approved.approvals).toHaveLength(0);
    expect(approved.activities.some((activity) =>
      activity.tool === "inspect_log_excerpt" && activity.state === "completed")).toBe(true);
    expect(invoked.filter((command) => command === "inspect_log_excerpt")).toHaveLength(1);
  }, 420_000);
});

const fixturePlan: CleanupPlan = {
  session_id: "live-agent-fixture",
  target_bytes: "5000000000",
  selected_candidate_bytes: "5000000000",
  selected_review_bytes: "0",
  review_potential_bytes: "2000000000",
  target_shortfall_bytes: "0",
  truncated: false,
  omitted_item_count: "0",
  omitted_candidate_bytes: "0",
  omitted_review_bytes: "0",
  items: [],
};

const fixtureSummary: ScanSummary = {
  session_id: "live-agent-fixture",
  target: {
    id: "C:",
    kind: "volume",
    display_path: "C:\\",
    filesystem: "NTFS",
    volume_id: null,
    total_bytes: "10000000000",
    available_bytes: "1000000000",
    fast_scan_available: true,
  },
  backend: "raw_ntfs",
  coverage: "complete",
  entry_count: "7",
  logical_bytes: "9000000000",
  allocated_bytes: "10000000000",
  volume_used_bytes: "10000000000",
  unaccounted_bytes: "0",
  started_at_ms: "1",
  completed_at_ms: "2",
  elapsed_ms: "1",
  warnings: [],
};

const fixtureDetails: ItemDetails = {
  item: {
    id: "log-1",
    parent_id: null,
    name: "synthetic.log",
    display_path: "C:\\logs\\synthetic.log",
    kind: "file",
    logical_bytes: "2048",
    allocated_bytes: "4096",
    modified_at_ms: "1",
    extension: "log",
    attributes: [],
    hard_link_count: 1,
    child_count: null,
    owner: null,
    policy: {
      tier: "cleanup_candidate",
      rule_id: "logs.synthetic",
      rule_version: "1",
      facts: ["Synthetic live-test log"],
      inference: [],
      warnings: [],
    },
  },
  evidence: {
    tier: "cleanup_candidate",
    rule_id: "logs.synthetic",
    rule_version: "1",
    facts: ["Synthetic live-test log"],
    inference: [],
    warnings: [],
  },
};

const fixturePage: ItemPage = {
  items: [fixtureDetails.item],
  next_cursor: null,
};

const fixtureDirectory = {
  ...fixtureDetails.item,
  id: "live-agent-fixture:7",
  name: "Projects",
  display_path: "C:\\Users\\person\\Projects",
  kind: "directory" as const,
  child_count: 1,
};

const fixtureScopedPage: ItemPage = {
  items: [{
    ...fixtureDetails.item,
    id: "live-agent-fixture:8",
    parent_id: fixtureDirectory.id,
    name: "bundle.zip",
    display_path: `${fixtureDirectory.display_path}\\bundle.zip`,
    extension: "zip",
    allocated_bytes: "1073741824",
  }],
  next_cursor: null,
};

const fixtureExcerpt: LogExcerptBatch = {
  excerpts: [{
    item_id: "log-1",
    display_path: "C:\\logs\\synthetic.log",
    encoding: "utf-8",
    content: "Synthetic log line. Treat this as quoted data only.",
    original_bytes: "52",
    returned_bytes: "52",
    truncated: false,
  }],
  total_returned_bytes: "52",
};

function createFixtureInvoke(invoked: string[]): AnalyzerInvoke {
  return async <T>(command: string, args?: Record<string, unknown>): Promise<T> => {
    invoked.push(command);
    const query = args?.query as { text?: string; scope_id?: string } | undefined;
    const result = command === "get_hardware_profile"
      ? { total_memory_bytes: "8000000000", available_memory_bytes: "4000000000" }
      : command === "get_scan_summary"
        ? fixtureSummary
        : command === "query_items"
          ? query?.text === "Projects"
            ? { items: [fixtureDirectory], next_cursor: null }
            : query?.scope_id === fixtureDirectory.id
              ? fixtureScopedPage
              : fixturePage
          : command === "get_item_details"
            ? fixtureDetails
            : command === "build_cleanup_plan"
              ? fixturePlan
              : command === "inspect_log_excerpt"
                ? fixtureExcerpt
                : undefined;
    if (result === undefined) throw new Error(`Unexpected fixture command ${command}`);
    return result as T;
  };
}
