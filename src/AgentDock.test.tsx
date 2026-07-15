// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CleanupPlan } from "./bindings/CleanupPlan";
import type { ItemRow } from "./bindings/ItemRow";
import type { ScanSummary } from "./bindings/ScanSummary";
import type { AgentActivity } from "./agent/types";

const mocks = vi.hoisted(() => ({
  discover: vi.fn(),
  prepareModel: vi.fn(),
  createSession: vi.fn(),
  streamTurn: vi.fn(),
  streamResolveApprovals: vi.fn(),
  clearConversation: vi.fn(),
  setAttachment: vi.fn(),
  invoke: vi.fn(),
  onActivity: undefined as ((activity: AgentActivity) => void) | undefined,
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: mocks.invoke }));
vi.mock("./agent/runtime", () => ({
  OllamaAgentRuntime: class {
    discover = mocks.discover;
    prepareModel = mocks.prepareModel;
    createSession(options: { onActivity?: (activity: AgentActivity) => void }) {
      mocks.onActivity = options.onActivity;
      mocks.createSession(options);
      return {
        streamTurn: mocks.streamTurn,
        streamResolveApprovals: mocks.streamResolveApprovals,
        clearConversation: mocks.clearConversation,
        setAttachment: mocks.setAttachment,
      };
    }
  },
}));

import { AgentDock } from "./AgentDock";

const model = {
  name: "granite4:1b-h",
  model: "granite4:1b-h",
  modified_at: "2026-07-14T00:00:00Z",
  size: 1_558_945_427,
  digest: "7".repeat(64),
  details: { format: "gguf", family: "granitehybrid", parameter_size: "1.5B" },
};

const preparedModel = {
  preflight: {
    model,
    show: { capabilities: ["tools"] },
    ollamaVersion: "0.30.7",
    totalDurationNs: 1,
  },
  harness: {
    harnessVersion: 1,
    model: model.name,
    digest: model.digest,
    ollamaVersion: "0.30.7",
    passed: true,
    firstTokenMs: 100,
    totalElapsedMs: 14_800,
    scenarios: [],
  },
};

const summary: ScanSummary = {
  session_id: "scan-1",
  target: {
    id: "C:",
    kind: "volume",
    display_path: "C:\\",
    filesystem: "NTFS",
    volume_id: null,
    total_bytes: null,
    available_bytes: null,
    fast_scan_available: true,
  },
  backend: "traversal",
  coverage: "complete",
  entry_count: "10",
  logical_bytes: "1000",
  allocated_bytes: "1200",
  volume_used_bytes: null,
  unaccounted_bytes: null,
  started_at_ms: "1",
  completed_at_ms: "2",
  elapsed_ms: "1",
  warnings: [],
};

const plan: CleanupPlan = {
  session_id: "scan-1",
  target_bytes: null,
  selected_candidate_bytes: "4096",
  selected_review_bytes: "0",
  review_potential_bytes: "1024",
  target_shortfall_bytes: "0",
  truncated: false,
  omitted_item_count: "0",
  omitted_candidate_bytes: "0",
  omitted_review_bytes: "0",
  items: [{
    id: "plan-1",
    node_ids: ["item-1"],
    title: "Old crash report",
    category: "Crash reports",
    tier: "cleanup_candidate",
    selected: true,
    reclaimable_bytes: "4096",
    evidence: [],
    warnings: [],
    action_kind: "inspect",
  }],
};

const activity: AgentActivity = {
  id: "tool-1",
  tool: "build_cleanup_plan",
  purpose: "Build a non-destructive cleanup proposal",
  state: "completed",
  arguments: {},
  resultCount: 1,
  elapsedMs: 4,
  truncated: false,
};

const attachedItem: ItemRow = {
  id: "scan-1:42",
  parent_id: null,
  name: "Downloads",
  display_path: "C:\\Users\\Demo\\Downloads",
  kind: "directory",
  logical_bytes: "2147483648",
  allocated_bytes: "2147483648",
  modified_at_ms: null,
  extension: null,
  attributes: [],
  hard_link_count: null,
  child_count: 12,
  owner: null,
  policy: {
    tier: "review_required",
    rule_id: "fallback",
    rule_version: "1",
    facts: [],
    inference: [],
    warnings: [],
  },
};

describe("AgentDock", () => {
  beforeEach(() => {
    window.localStorage.clear();
    Object.values(mocks).forEach((value) => {
      if (typeof value === "function" && "mockReset" in value) value.mockReset();
    });
    mocks.onActivity = undefined;
    mocks.discover.mockResolvedValue({
      ollamaVersion: "0.30.7",
      models: [model],
      hardware: { totalMemoryBytes: 8_000_000_000, availableMemoryBytes: 4_000_000_000 },
    });
    mocks.prepareModel.mockResolvedValue(preparedModel);
    mocks.streamTurn.mockImplementation(async (_prompt, onText) => {
      onText("Found", "Found");
      onText(" a plan.", "Found a plan.");
      return turnResult({ text: "Found a plan.", activities: [activity], plan });
    });
    mocks.streamResolveApprovals.mockResolvedValue(turnResult({ text: "Approved safely." }));
    mocks.invoke.mockResolvedValue(plan);
  });

  afterEach(cleanup);

  it("keeps the analyzer usable when Ollama is unavailable", async () => {
    mocks.discover.mockRejectedValueOnce(new Error("connection refused"));
    render(<AgentDock desktopRuntime hidden={false} summary={summary} />);

    expect(await screen.findByText("Ollama unavailable")).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toContain("connection refused");
    expect(screen.getByRole("textbox", { name: "Message ClutterHunter" }).hasAttribute("disabled")).toBe(true);
  });

  it("builds and edits a deterministic cleanup plan without Ollama", async () => {
    const user = userEvent.setup();
    mocks.discover.mockRejectedValueOnce(new Error("connection refused"));
    render(<AgentDock desktopRuntime hidden={false} summary={summary} />);

    await screen.findByText("Ollama unavailable");
    await user.click(screen.getByRole("tab", { name: /Plan 0/i }));
    await user.type(screen.getByRole("textbox", { name: "Cleanup target in GB" }), "1.5");
    await user.click(screen.getByRole("button", { name: "Find cleanup" }));

    expect(mocks.invoke).toHaveBeenCalledWith("build_cleanup_plan", {
      sessionId: "scan-1",
      request: { target_bytes: "1610612736" },
    });
    expect(await screen.findByText("Old crash report")).toBeTruthy();

    await user.click(screen.getByRole("tab", { name: "Chat" }));
    await user.selectOptions(screen.getByRole("combobox", { name: "Agent workflow" }), "plan");
    await user.click(screen.getByRole("tab", { name: /Plan 1/i }));
    expect(screen.getByText("Old crash report")).toBeTruthy();

    await user.click(screen.getByRole("checkbox"));
    expect(mocks.invoke).toHaveBeenCalledWith("edit_cleanup_plan", {
      sessionId: "scan-1",
      edit: { item_id: "plan-1", selected: false },
    });
  });

  it("requires confirmation before overriding a low-memory estimate", async () => {
    const user = userEvent.setup();
    mocks.discover.mockResolvedValueOnce({
      ollamaVersion: "0.30.7",
      models: [model],
      hardware: { totalMemoryBytes: 8_000_000_000, availableMemoryBytes: 320_000_000 },
    });
    render(<AgentDock desktopRuntime hidden={false} summary={summary} />);

    expect(await screen.findByText("Low memory")).toBeTruthy();
    const prepareButton = screen.getByRole("button", { name: /Test & use/i });
    expect(prepareButton.hasAttribute("disabled")).toBe(false);

    await user.click(prepareButton);
    expect(screen.getByRole("alertdialog", { name: "Low memory warning" })).toBeTruthy();
    expect(mocks.prepareModel).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Try anyway" }));
    expect(mocks.prepareModel).toHaveBeenCalledWith(model.name, expect.any(AbortSignal));
    expect(await screen.findByText("Ready for this scan")).toBeTruthy();
  });

  it("verifies a local model, streams a turn, and hands a plan to the Plan tab", async () => {
    const user = userEvent.setup();
    render(<AgentDock desktopRuntime hidden={false} summary={summary} />);

    expect(await screen.findByText("Granite 4 1B Hybrid")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: /Test & use/i }));
    expect(await screen.findByText("Ready for this scan")).toBeTruthy();

    await user.type(screen.getByRole("textbox", { name: "Message ClutterHunter" }), "Build a cleanup plan");
    await user.click(screen.getByRole("button", { name: "Send message" }));
    expect(await screen.findByText("Found a plan.")).toBeTruthy();
    expect(screen.getByText("Build a non-destructive cleanup proposal")).toBeTruthy();

    await user.click(screen.getByRole("tab", { name: /Plan 1/i }));
    expect(screen.getByText("Old crash report")).toBeTruthy();
    expect(screen.getByText("4.0 KB")).toBeTruthy();
  });

  it("renders typed bounded tool results in the assistant turn", async () => {
    const user = userEvent.setup();
    mocks.streamTurn.mockResolvedValue(turnResult({
      text: "Largest item found.",
      results: [{
        component: "ItemListResult",
        data: { items: [attachedItem] },
        truncated: false,
        serializedBytes: 100,
      }],
    }));
    render(<AgentDock desktopRuntime hidden={false} summary={summary} />);
    await user.click(await screen.findByRole("button", { name: /Test & use/i }));
    await screen.findByText("Ready for this scan");
    await user.type(screen.getByRole("textbox", { name: "Message ClutterHunter" }), "Largest item");
    await user.click(screen.getByRole("button", { name: "Send message" }));

    expect(await screen.findByRole("region", { name: "Storage items" })).toBeTruthy();
    expect(screen.getByText("Downloads")).toBeTruthy();
    expect(screen.getByText("2.0 GB")).toBeTruthy();
  });

  it("renders folder inspection and cleanup opportunities as deterministic cards", async () => {
    const user = userEvent.setup();
    mocks.streamTurn.mockResolvedValue(turnResult({
      text: "Local evidence ready.",
      results: [{
        component: "FolderInspectionResult",
        data: {
          scope: { display_path: "C:\\Work", allocated_bytes: "4294967296" },
          top_children: [{ name: "target", display_path: "C:\\Work\\target", allocated_bytes: "3221225472" }],
          top_files: [{ name: "model.bin", display_path: "C:\\Work\\target\\model.bin", allocated_bytes: "2147483648" }],
          extension_buckets: [{ label: "bin", allocated_bytes: "2147483648" }],
        },
        truncated: false,
        serializedBytes: 200,
      }, {
        component: "CleanupOpportunitiesResult",
        data: {
          conservative_bytes: "1073741824",
          review_potential_bytes: "2147483648",
          items: [{ title: "Generated build data", tier: "review_required", reclaimable_bytes: "2147483648" }],
        },
        truncated: false,
        serializedBytes: 200,
      }],
    }));
    render(<AgentDock desktopRuntime hidden={false} summary={summary} />);
    await user.click(await screen.findByRole("button", { name: /Test & use/i }));
    await screen.findByText("Ready for this scan");
    await user.type(screen.getByRole("textbox", { name: "Message ClutterHunter" }), "Why is Work large and what can I clean?");
    await user.click(screen.getByRole("button", { name: "Send message" }));

    expect(await screen.findByRole("region", { name: "Folder inspection" })).toBeTruthy();
    expect(screen.getByRole("region", { name: "Cleanup opportunities" })).toBeTruthy();
    expect(screen.getByText("Child · target")).toBeTruthy();
    expect(screen.getByText("File · model.bin")).toBeTruthy();
    expect(screen.getByText("Type · bin")).toBeTruthy();
    expect(screen.getByText(/Generated build data/)).toBeTruthy();
  });

  it("renders incomplete and completed assistant Markdown with Streamdown", async () => {
    const user = userEvent.setup();
    mocks.streamTurn.mockImplementation(async (_prompt, onText) => {
      onText("**Grounded", "**Grounded");
      onText(" answer**", "**Grounded answer**");
      return turnResult({ text: "**Grounded answer**" });
    });
    render(<AgentDock desktopRuntime hidden={false} summary={summary} />);
    await user.click(await screen.findByRole("button", { name: /Test & use/i }));
    await screen.findByText("Ready for this scan");
    await user.type(screen.getByRole("textbox", { name: "Message ClutterHunter" }), "Explain the result");
    await user.click(screen.getByRole("button", { name: "Send message" }));

    await waitFor(() => {
      expect(screen.getByText("Grounded answer").getAttribute("data-streamdown")).toBe("strong");
    });
  });

  it("attaches exact current analyzer metadata and allows removing it", async () => {
    const user = userEvent.setup();
    const clearAttachment = vi.fn();
    render(
      <AgentDock
        desktopRuntime
        hidden={false}
        summary={summary}
        attachment={attachedItem}
        onClearAttachment={clearAttachment}
      />,
    );
    await user.click(await screen.findByRole("button", { name: /Test & use/i }));

    expect(await screen.findByLabelText("Attached analyzer item Downloads")).toBeTruthy();
    expect(mocks.setAttachment).toHaveBeenLastCalledWith(expect.objectContaining({
      id: "scan-1:42",
      displayPath: "C:\\Users\\Demo\\Downloads",
    }));
    await user.click(screen.getByRole("button", { name: "Remove attached item" }));
    expect(clearAttachment).toHaveBeenCalledOnce();
  });

  it("requires an explicit exact-path decision before continuing", async () => {
    const user = userEvent.setup();
    mocks.streamTurn.mockResolvedValue(turnResult({
      text: "",
      approvals: [{
        approvalId: "approval-1",
        tool: "inspect_log_excerpt",
        arguments: { item_ids: ["item-1"], requested_bytes_per_file: 1024 },
        exactPaths: ["C:\\logs\\app.log"],
        maximumBytes: 1024,
      }],
    }));
    render(<AgentDock desktopRuntime hidden={false} summary={summary} />);
    await user.click(await screen.findByRole("button", { name: /Test & use/i }));
    await screen.findByText("Ready for this scan");
    await user.type(screen.getByRole("textbox", { name: "Message ClutterHunter" }), "Inspect the log");
    await user.click(screen.getByRole("button", { name: "Send message" }));

    expect(await screen.findByText("C:\\logs\\app.log")).toBeTruthy();
    const continueButton = screen.getByRole("button", { name: "Continue" });
    expect(continueButton.hasAttribute("disabled")).toBe(true);
    await user.click(screen.getByRole("button", { name: "Allow" }));
    await user.click(continueButton);
    expect(await screen.findByText("Approved safely.")).toBeTruthy();
    expect(mocks.streamResolveApprovals).toHaveBeenCalledWith(
      [{ approvalId: "approval-1", approved: true }],
      expect.any(Function),
      expect.any(AbortSignal),
    );
  });

  it("passes an explicit denial without treating it as approval", async () => {
    const user = userEvent.setup();
    mocks.streamTurn.mockResolvedValue(turnResult({
      text: "",
      approvals: [{
        approvalId: "approval-denied",
        tool: "inspect_log_excerpt",
        arguments: { item_ids: ["item-1"], requested_bytes_per_file: 1024 },
        exactPaths: ["C:\\logs\\denied.log"],
        maximumBytes: 1024,
      }],
    }));
    mocks.streamResolveApprovals.mockResolvedValue(turnResult({ text: "The log was not read." }));
    render(<AgentDock desktopRuntime hidden={false} summary={summary} />);
    await user.click(await screen.findByRole("button", { name: /Test & use/i }));
    await screen.findByText("Ready for this scan");
    await user.type(screen.getByRole("textbox", { name: "Message ClutterHunter" }), "Inspect the log");
    await user.click(screen.getByRole("button", { name: "Send message" }));

    expect(await screen.findByText("C:\\logs\\denied.log")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Deny" }));
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByText("The log was not read.")).toBeTruthy();
    expect(mocks.streamResolveApprovals).toHaveBeenCalledWith(
      [{ approvalId: "approval-denied", approved: false }],
      expect.any(Function),
      expect.any(AbortSignal),
    );
  });

  it("clears approval context when continuation is cancelled", async () => {
    const user = userEvent.setup();
    mocks.streamTurn.mockResolvedValue(turnResult({
      text: "",
      approvals: [{
        approvalId: "approval-cancelled",
        tool: "inspect_log_excerpt",
        arguments: { item_ids: ["item-1"], requested_bytes_per_file: 1024 },
        exactPaths: ["C:\\logs\\cancelled.log"],
        maximumBytes: 1024,
      }],
    }));
    mocks.streamResolveApprovals.mockImplementation((_decisions, _onText, signal: AbortSignal) =>
      new Promise((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
      }));
    render(<AgentDock desktopRuntime hidden={false} summary={summary} />);
    await user.click(await screen.findByRole("button", { name: /Test & use/i }));
    await screen.findByText("Ready for this scan");
    await user.type(screen.getByRole("textbox", { name: "Message ClutterHunter" }), "Inspect the log");
    await user.click(screen.getByRole("button", { name: "Send message" }));
    await screen.findByText("C:\\logs\\cancelled.log");
    await user.click(screen.getByRole("button", { name: "Allow" }));
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.click(await screen.findByRole("button", { name: "Cancel response" }));

    expect(mocks.clearConversation).toHaveBeenCalledOnce();
    expect(await screen.findByText(/Conversation context was reset safely/i)).toBeTruthy();
    expect(screen.queryByText("C:\\logs\\cancelled.log")).toBeNull();
  });

  it("cancels a streaming turn without accepting a partial answer", async () => {
    const user = userEvent.setup();
    mocks.streamTurn.mockImplementation((_prompt, onText, signal: AbortSignal) => {
      onText("Partial", "Partial");
      return new Promise((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
      });
    });
    render(<AgentDock desktopRuntime hidden={false} summary={summary} />);
    await user.click(await screen.findByRole("button", { name: /Test & use/i }));
    await screen.findByText("Ready for this scan");
    await user.type(screen.getByRole("textbox", { name: "Message ClutterHunter" }), "Long request");
    await user.click(screen.getByRole("button", { name: "Send message" }));
    await user.click(await screen.findByRole("button", { name: "Cancel response" }));

    await waitFor(() => expect(screen.getByText("Partial").closest(".chat-message")?.className).toContain("message-cancelled"));
  });
});

function turnResult(overrides: Record<string, unknown> = {}) {
  return {
    text: "Done.",
    activities: [],
    approvals: [],
    results: [],
    plan: null,
    finishReason: "stop",
    usage: {},
    ...overrides,
  };
}
