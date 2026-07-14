import { invoke } from "@tauri-apps/api/core";
import {
  ArrowUp,
  BarChart3,
  Bot,
  Check,
  ChevronDown,
  CircleAlert,
  Database,
  FileText,
  FolderSearch,
  LoaderCircle,
  MessageSquareText,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Square,
  Wrench,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Streamdown, type Components } from "streamdown";
import "streamdown/styles.css";
import type { CleanupPlan } from "./bindings/CleanupPlan";
import type { ItemRow } from "./bindings/ItemRow";
import type { ScanSummary } from "./bindings/ScanSummary";
import { rankInstalledModels, type RankedModel } from "./agent/catalog";
import {
  OllamaAgentRuntime,
  type ClutterAgentSession,
  type AgentApprovalDecision,
  type AgentTurnResult,
  type AgentWorkflow,
  type PendingAgentApproval,
  type PreparedAgentModel,
} from "./agent/runtime";
import type { AnalyzerInvoke } from "./agent/tools";
import {
  formatAgentError,
  type AgentActivity,
  type AgentToolResult,
  type AnalyzerAttachment,
  type HardwareProfile,
  type InstalledOllamaModel,
} from "./agent/types";

type DockTab = "chat" | "plan";
type MessageStatus = "streaming" | "complete" | "cancelled" | "error";

const assistantMarkdownComponents: Components = {
  a: ({ children }) => <span className="markdown-link-label">{children}</span>,
  img: ({ alt }) => <span className="markdown-image-blocked">{alt ? `[Image omitted: ${alt}]` : "[Image omitted]"}</span>,
};

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  text: string;
  status: MessageStatus;
  results: AgentToolResult<unknown>[];
}

interface DiscoveryResult {
  ollamaVersion: string;
  models: InstalledOllamaModel[];
  hardware: HardwareProfile;
}

interface AgentDockProps {
  desktopRuntime: boolean;
  hidden: boolean;
  summary: ScanSummary | null;
  attachment?: ItemRow | null;
  onClearAttachment?: () => void;
}

const agentInvoke: AnalyzerInvoke = <T,>(command: string, args?: Record<string, unknown>) =>
  invoke<T>(command, args);

export function AgentDock({
  desktopRuntime,
  hidden,
  summary,
  attachment = null,
  onClearAttachment = () => undefined,
}: AgentDockProps) {
  const runtime = useMemo(
    () => desktopRuntime ? new OllamaAgentRuntime({ invoke: agentInvoke }) : null,
    [desktopRuntime],
  );
  const sessionRef = useRef<ClutterAgentSession | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const activeRunRef = useRef(false);
  const runIdRef = useRef(0);
  const resolvingApprovalRef = useRef(false);
  const [tab, setTab] = useState<DockTab>("chat");
  const [setupOpen, setSetupOpen] = useState(true);
  const [checking, setChecking] = useState(desktopRuntime);
  const [preparing, setPreparing] = useState(false);
  const [discovery, setDiscovery] = useState<DiscoveryResult | null>(null);
  const [selectedModel, setSelectedModel] = useState("");
  const [preparedModel, setPreparedModel] = useState<PreparedAgentModel | null>(null);
  const [workflow, setWorkflow] = useState<AgentWorkflow>("investigate");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [activities, setActivities] = useState<AgentActivity[]>([]);
  const [approvals, setApprovals] = useState<PendingAgentApproval[]>([]);
  const [approvalDecisions, setApprovalDecisions] = useState<Record<string, boolean>>({});
  const [plan, setPlan] = useState<CleanupPlan | null>(null);
  const [planTargetGb, setPlanTargetGb] = useState("");
  const [planBuilding, setPlanBuilding] = useState(false);
  const [planError, setPlanError] = useState<string | null>(null);
  const [prompt, setPrompt] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [memoryWarningOpen, setMemoryWarningOpen] = useState(false);

  const rankedModels = useMemo(() => {
    if (!discovery) return [];
    const harnesses = new Map(
      preparedModel ? [[preparedModel.preflight.model.digest, preparedModel.harness]] : [],
    );
    return rankInstalledModels(discovery.models, discovery.hardware, harnesses);
  }, [discovery, preparedModel]);
  const selectedRank = rankedModels.find((entry) => entry.installed.name === selectedModel) ?? null;
  const selectedPlanItems = plan?.items.filter((item) => item.selected) ?? [];

  const updateActivity = useCallback((next: AgentActivity) => {
    if (!activeRunRef.current) return;
    setActivities((current) => {
      const index = current.findIndex((activity) => activity.id === next.id);
      if (index < 0) return [...current, next];
      const updated = [...current];
      updated[index] = next;
      return updated;
    });
  }, []);

  const discoverModels = useCallback(async (resetPrepared = false) => {
    if (!runtime) return;
    setChecking(true);
    setError(null);
    setMemoryWarningOpen(false);
    if (resetPrepared) setPreparedModel(null);
    try {
      const result = await runtime.discover();
      setDiscovery(result);
      const ranked = rankInstalledModels(result.models, result.hardware, new Map());
      const remembered = window.localStorage.getItem("clutterhunter:ollama-model");
      setSelectedModel((current) => {
        for (const candidate of [current, remembered, ranked[0]?.installed.name]) {
          if (candidate && ranked.some((entry) => entry.installed.name === candidate)) return candidate;
        }
        return "";
      });
    } catch (nextError) {
      setDiscovery(null);
      setPreparedModel(null);
      setError(agentErrorMessage(nextError));
    } finally {
      setChecking(false);
    }
  }, [runtime]);

  useEffect(() => {
    if (runtime) void discoverModels();
  }, [discoverModels, runtime]);

  useEffect(() => () => abortRef.current?.abort(), []);

  useEffect(() => {
    abortRef.current?.abort();
    runIdRef.current += 1;
    activeRunRef.current = false;
    setRunning(false);
    setMessages([]);
    setActivities([]);
    setApprovals([]);
    setApprovalDecisions({});
    setError(null);
    sessionRef.current = runtime && preparedModel && summary
      ? runtime.createSession({
        sessionId: summary.session_id,
        workflow,
        preparedModel,
        onActivity: updateActivity,
      })
      : null;
  }, [preparedModel, runtime, summary, updateActivity, workflow]);

  useEffect(() => {
    setPlan(null);
    setPlanTargetGb("");
    setPlanBuilding(false);
    setPlanError(null);
  }, [summary?.session_id]);

  useEffect(() => {
    sessionRef.current?.setAttachment(attachment ? toAnalyzerAttachment(attachment) : null);
  }, [attachment, preparedModel, summary, workflow]);

  const prepareSelectedModel = async (bypassMemoryWarning = false) => {
    if (!runtime || !selectedModel || preparing) return;
    if (selectedRank && !selectedRank.memoryFit && !bypassMemoryWarning) {
      setMemoryWarningOpen(true);
      return;
    }
    setMemoryWarningOpen(false);
    const controller = new AbortController();
    abortRef.current = controller;
    setPreparing(true);
    setError(null);
    try {
      const prepared = await runtime.prepareModel(selectedModel, controller.signal);
      setPreparedModel(prepared);
      window.localStorage.setItem("clutterhunter:ollama-model", selectedModel);
      setSetupOpen(false);
    } catch (nextError) {
      setPreparedModel(null);
      setError(agentErrorMessage(nextError));
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
      setPreparing(false);
    }
  };

  const updateAssistant = (id: string, text: string, status?: MessageStatus) => {
    setMessages((current) => current.map((message) => message.id === id
      ? { ...message, text, status: status ?? message.status }
      : message));
  };

  const applyResult = (result: AgentTurnResult, assistantId: string) => {
    setMessages((current) => current.map((message) => message.id === assistantId
      ? {
        ...message,
        text: result.text || (result.approvals.length > 0
          ? "Approval required before continuing."
          : "Local model completed without usable output."),
        status: "complete",
        results: result.results,
      }
      : message));
    setActivities(result.activities);
    setApprovals(result.approvals);
    setApprovalDecisions({});
    if (result.plan) {
      setPlan(result.plan);
      setPlanError(null);
    }
  };

  const sendPrompt = async () => {
    const session = sessionRef.current;
    const cleanPrompt = prompt.trim();
    if (!session || !cleanPrompt || running || approvals.length > 0) return;
    const userId = newId("user");
    const assistantId = newId("assistant");
    const runId = ++runIdRef.current;
    const controller = new AbortController();
    abortRef.current = controller;
    activeRunRef.current = true;
    resolvingApprovalRef.current = false;
    setPrompt("");
    setError(null);
    setActivities([]);
    setRunning(true);
    setMessages((current) => [
      ...current,
      { id: userId, role: "user", text: cleanPrompt, status: "complete", results: [] },
      { id: assistantId, role: "assistant", text: "", status: "streaming", results: [] },
    ]);
    try {
      const result = await session.streamTurn(
        cleanPrompt,
        (_delta, accumulated) => {
          if (runIdRef.current === runId) updateAssistant(assistantId, accumulated);
        },
        controller.signal,
      );
      if (runIdRef.current === runId) applyResult(result, assistantId);
    } catch (nextError) {
      if (runIdRef.current === runId) {
        const cancelled = controller.signal.aborted;
        updateAssistant(assistantId, cancelled ? "Cancelled." : agentErrorMessage(nextError), cancelled ? "cancelled" : "error");
        if (!cancelled) setError(agentErrorMessage(nextError));
      }
    } finally {
      if (runIdRef.current === runId) {
        activeRunRef.current = false;
        setRunning(false);
        abortRef.current = null;
      }
    }
  };

  const continueAfterApprovals = async () => {
    const session = sessionRef.current;
    if (!session || running || approvals.length === 0) return;
    if (approvals.some((approval) => approvalDecisions[approval.approvalId] === undefined)) return;
    const assistantId = newId("assistant");
    const runId = ++runIdRef.current;
    const controller = new AbortController();
    const decisions: AgentApprovalDecision[] = approvals.map((approval) => ({
      approvalId: approval.approvalId,
      approved: approvalDecisions[approval.approvalId] ?? false,
    }));
    abortRef.current = controller;
    activeRunRef.current = true;
    resolvingApprovalRef.current = true;
    setRunning(true);
    setError(null);
    setMessages((current) => [
      ...current,
      { id: assistantId, role: "assistant", text: "", status: "streaming", results: [] },
    ]);
    try {
      const result = await session.streamResolveApprovals(
        decisions,
        (_delta, accumulated) => {
          if (runIdRef.current === runId) updateAssistant(assistantId, accumulated);
        },
        controller.signal,
      );
      if (runIdRef.current === runId) applyResult(result, assistantId);
    } catch (nextError) {
      if (runIdRef.current === runId) {
        const cancelled = controller.signal.aborted;
        updateAssistant(assistantId, cancelled ? "Cancelled." : agentErrorMessage(nextError), cancelled ? "cancelled" : "error");
        if (!cancelled) setError(agentErrorMessage(nextError));
      }
    } finally {
      if (runIdRef.current === runId) {
        activeRunRef.current = false;
        resolvingApprovalRef.current = false;
        setRunning(false);
        abortRef.current = null;
      }
    }
  };

  const cancelTurn = () => {
    runIdRef.current += 1;
    activeRunRef.current = false;
    abortRef.current?.abort();
    abortRef.current = null;
    setRunning(false);
    setMessages((current) => current.map((message) => message.status === "streaming"
      ? { ...message, text: message.text || "Cancelled.", status: "cancelled" }
      : message));
    if (resolvingApprovalRef.current) {
      sessionRef.current?.clearConversation();
      setApprovals([]);
      setApprovalDecisions({});
      setError("Approval continuation cancelled. Conversation context was reset safely.");
    }
    resolvingApprovalRef.current = false;
  };

  const togglePlanItem = async (itemId: string, selected: boolean) => {
    if (!summary || running || planBuilding) return;
    setPlanError(null);
    try {
      const nextPlan = await invoke<CleanupPlan>("edit_cleanup_plan", {
        sessionId: summary.session_id,
        edit: { item_id: itemId, selected },
      });
      setPlan(nextPlan);
    } catch (nextError) {
      setPlanError(agentErrorMessage(nextError));
    }
  };

  const buildDeterministicPlan = async () => {
    if (!summary || running || planBuilding) return;
    const targetBytes = gibibytesToBytes(planTargetGb);
    if (planTargetGb.trim() && targetBytes === null) {
      setPlanError("Enter a positive cleanup target in GB.");
      return;
    }
    setPlanBuilding(true);
    setPlanError(null);
    try {
      const nextPlan = await invoke<CleanupPlan>("build_cleanup_plan", {
        sessionId: summary.session_id,
        request: { target_bytes: targetBytes },
      });
      setPlan(nextPlan);
    } catch (nextError) {
      setPlanError(agentErrorMessage(nextError));
    } finally {
      setPlanBuilding(false);
    }
  };

  const modelHeadline = preparedModel?.preflight.model.name
    ?? (checking ? "Checking Ollama" : discovery ? "Choose local model" : "Ollama unavailable");
  const modelDetail = preparedModel
    ? `Verified locally · ${formatDuration(preparedModel.harness.totalElapsedMs)}`
    : discovery ? `Ollama ${discovery.ollamaVersion}` : "Local service required";
  const composerDisabled = !sessionRef.current || running || approvals.length > 0;

  return (
    <aside className="ai-dock" aria-label="On-device AI" hidden={hidden}>
      <div className="dock-tabs" role="tablist" aria-label="AI workspace">
        <button type="button" role="tab" aria-selected={tab === "chat"} className={tab === "chat" ? "active" : ""} onClick={() => setTab("chat")}>
          <MessageSquareText size={16} /> Chat
        </button>
        <button type="button" role="tab" aria-selected={tab === "plan"} className={tab === "plan" ? "active" : ""} onClick={() => setTab("plan")}>
          <ShieldCheck size={16} /> Plan <span className="count">{selectedPlanItems.length}</span>
        </button>
      </div>

      {tab === "chat" ? (
        <div className={`dock-content chat-content ${setupOpen ? "setup-visible" : ""} ${attachment ? "attachment-visible" : ""}`}>
          <button className="model-status" type="button" aria-expanded={setupOpen} onClick={() => setSetupOpen((open) => !open)}>
            <span className="model-icon">{checking || preparing ? <LoaderCircle className="spin" size={18} /> : <Bot size={19} />}</span>
            <span><strong>{modelHeadline}</strong><small>{modelDetail}</small></span>
            <ChevronDown className={setupOpen ? "chevron-open" : ""} size={15} />
          </button>

          {setupOpen && (
            <section className="model-setup" aria-label="Local model setup">
              <div className="setup-row">
                <select
                  aria-label="Local Ollama model"
                  value={selectedModel}
                  disabled={checking || preparing || rankedModels.length === 0}
                  onChange={(event) => {
                    setSelectedModel(event.target.value);
                    setPreparedModel(null);
                    setMemoryWarningOpen(false);
                  }}
                >
                  {rankedModels.length === 0 && <option value="">No eligible local models</option>}
                  {rankedModels.map((entry) => (
                    <option key={entry.installed.digest} value={entry.installed.name}>
                      {entry.catalog?.label ?? entry.installed.name}
                    </option>
                  ))}
                </select>
                <button className="icon-button compact" type="button" title="Refresh Ollama" aria-label="Refresh Ollama" disabled={checking || preparing} onClick={() => void discoverModels(true)}>
                  <RefreshCw className={checking ? "spin" : ""} size={15} />
                </button>
              </div>
              {selectedRank && <ModelFacts entry={selectedRank} hardware={discovery?.hardware ?? null} />}
              {memoryWarningOpen && (
                <div className="memory-warning" role="alertdialog" aria-label="Low memory warning">
                  <CircleAlert size={15} />
                  <div>
                    <strong>Available memory is below estimate</strong>
                    <span>Ollama may still use GPU memory. Loading can fail or slow Windows; scan data stays unchanged.</span>
                  </div>
                  <div className="memory-warning-actions">
                    <button type="button" onClick={() => setMemoryWarningOpen(false)}>Cancel</button>
                    <button type="button" onClick={() => void prepareSelectedModel(true)}>Try anyway</button>
                  </div>
                </div>
              )}
              <div className="setup-row setup-actions">
                <select aria-label="Agent workflow" value={workflow} disabled={preparing || running} onChange={(event) => setWorkflow(event.target.value as AgentWorkflow)}>
                  <option value="investigate">Investigate</option>
                  <option value="plan">Plan cleanup</option>
                  <option value="policy">Protect paths</option>
                </select>
                <button className="primary-action" type="button" disabled={!selectedModel || checking || preparing} onClick={() => void prepareSelectedModel()}>
                  {preparing ? <LoaderCircle className="spin" size={14} /> : preparedModel ? <Check size={14} /> : <Wrench size={14} />}
                  {preparing ? "Testing" : preparedModel ? "Verified" : "Test & use"}
                </button>
              </div>
            </section>
          )}

          <div className="chat-thread" aria-live="polite">
            {messages.length === 0 ? (
              <div className="chat-empty">
                <Sparkles size={22} />
                <strong>{preparedModel ? summary ? "Ready for this scan" : "Scan required" : "Local assistant offline"}</strong>
                <span>{preparedModel ? summary ? preparedModel.preflight.model.name : "Analyzer session not available" : "Verify a local model to begin"}</span>
              </div>
            ) : messages.map((message) => (
              <div key={message.id} className={`chat-message message-${message.role} message-${message.status}`}>
                <span>{message.role === "assistant" ? <Bot size={13} /> : "You"}</span>
                <div className="message-body">
                  {message.role === "assistant" ? message.text ? (
                    <Streamdown
                      animated
                      className="message-markdown"
                      components={assistantMarkdownComponents}
                      isAnimating={message.status === "streaming"}
                      lineNumbers={false}
                      mode={message.status === "streaming" ? "streaming" : "static"}
                    >
                      {message.text}
                    </Streamdown>
                  ) : <div className="message-loading"><LoaderCircle className="spin" size={14} /></div>
                    : <p>{message.text}</p>}
                  {message.results.length > 0 && (
                    <div className="tool-result-list">
                      {message.results.map((result, index) => (
                        <ToolResultCard key={`${message.id}-${result.component}-${index}`} result={result} />
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
            {activities.length > 0 && (
              <section className="activity-list" aria-label="Agent activity">
                {activities.map((activity) => <ActivityRow key={activity.id} activity={activity} />)}
              </section>
            )}
            {approvals.length > 0 && (
              <section className="approval-list" aria-label="Pending approvals">
                {approvals.map((approval) => (
                  <div className="approval-row" key={approval.approvalId}>
                    <div className="approval-title"><ShieldCheck size={14} /><strong>{approvalLabel(approval)}</strong></div>
                    {approval.exactPaths.map((path) => <code key={path} title={path}>{path}</code>)}
                    {approval.maximumBytes !== null && <small>Maximum read: {formatBytes(approval.maximumBytes)}</small>}
                    <div className="approval-options" role="group" aria-label={`Decision for ${approvalLabel(approval)}`}>
                      <button type="button" aria-pressed={approvalDecisions[approval.approvalId] === true} className={approvalDecisions[approval.approvalId] === true ? "selected allow" : ""} onClick={() => setApprovalDecisions((current) => ({ ...current, [approval.approvalId]: true }))}><Check size={13} /> Allow</button>
                      <button type="button" aria-pressed={approvalDecisions[approval.approvalId] === false} className={approvalDecisions[approval.approvalId] === false ? "selected deny" : ""} onClick={() => setApprovalDecisions((current) => ({ ...current, [approval.approvalId]: false }))}><X size={13} /> Deny</button>
                    </div>
                  </div>
                ))}
                <button className="approval-continue" type="button" disabled={running || approvals.some((approval) => approvalDecisions[approval.approvalId] === undefined)} onClick={() => void continueAfterApprovals()}>
                  Continue
                </button>
              </section>
            )}
            {error && <div className="agent-error" role="alert"><CircleAlert size={14} /><span>{error}</span></div>}
          </div>

          <div className="composer-region">
            {attachment && (
              <div className="attachment-chip" aria-label={`Attached analyzer item ${attachment.name}`}>
                <FolderSearch size={13} />
                <span><strong>{attachment.name}</strong><small>{formatBytes(attachment.allocated_bytes)} · {attachment.policy.tier.replaceAll("_", " ")}</small></span>
                <button type="button" title="Remove attached item" aria-label="Remove attached item" disabled={running || approvals.length > 0} onClick={onClearAttachment}><X size={13} /></button>
              </div>
            )}
            <div className="chat-composer">
              <textarea
                aria-label="Message ClutterHunter"
                placeholder={preparedModel ? summary ? "Ask about this scan" : "Run a scan first" : "Verify a local model first"}
                value={prompt}
                disabled={composerDisabled}
                onChange={(event) => setPrompt(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    void sendPrompt();
                  }
                }}
              />
              <button type="button" title={running ? "Cancel response" : "Send message"} aria-label={running ? "Cancel response" : "Send message"} disabled={!running && (composerDisabled || !prompt.trim())} onClick={running ? cancelTurn : () => void sendPrompt()}>
                {running ? <Square size={13} fill="currentColor" /> : <ArrowUp size={17} />}
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="dock-content plan-content">
          <div className="plan-controls">
            <label className="plan-target">
              <input
                type="text"
                inputMode="decimal"
                aria-label="Cleanup target in GB"
                placeholder="Target"
                value={planTargetGb}
                disabled={!summary || running || planBuilding}
                onChange={(event) => setPlanTargetGb(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") void buildDeterministicPlan();
                }}
              />
              <span>GB</span>
            </label>
            <button type="button" disabled={!summary || running || planBuilding} onClick={() => void buildDeterministicPlan()}>
              {planBuilding ? <LoaderCircle className="spin" size={14} /> : <FolderSearch size={14} />}
              Find cleanup
            </button>
          </div>
          <div className="plan-totals">
            <div><span>Conservative</span><strong>{formatBytes(plan?.selected_candidate_bytes ?? "0")}</strong></div>
            <div><span>Review potential</span><strong>{formatBytes(plan?.review_potential_bytes ?? "0")}</strong></div>
          </div>
          <div className="plan-list">
            {!plan ? (
              <div className="plan-empty"><ShieldCheck size={24} /><strong>No cleanup plan</strong><span>No proposal for this scan</span></div>
            ) : plan.items.length === 0 ? (
              <div className="plan-empty"><ShieldCheck size={24} /><strong>No eligible items</strong><span>Deterministic planner returned no candidates</span></div>
            ) : plan.items.map((item) => (
              <label className="plan-row" key={item.id}>
                <input type="checkbox" checked={item.selected} disabled={running || planBuilding} onChange={(event) => void togglePlanItem(item.id, event.target.checked)} />
                <span className="plan-row-copy">
                  <strong>{item.title}</strong>
                  <small>{item.category} · {formatBytes(item.reclaimable_bytes)} · {item.tier.replace("_", " ")}</small>
                  {item.warnings[0] && <em>{item.warnings[0]}</em>}
                </span>
              </label>
            ))}
          </div>
          {planError && <div className="agent-error plan-error" role="alert"><CircleAlert size={14} /><span>{planError}</span></div>}
        </div>
      )}
    </aside>
  );
}

function ModelFacts({ entry, hardware }: { entry: RankedModel; hardware: HardwareProfile | null }) {
  const available = hardware?.availableMemoryBytes;
  return (
    <div className={`model-facts ${entry.memoryFit ? "fit" : "unfit"}`}>
      <span>{entry.catalog?.class ?? "custom"}</span>
      <span>{formatBytes(entry.installed.size)} local</span>
      <span>{available === undefined ? "Memory unknown" : `${formatBytes(available)} free`}</span>
      <strong>{entry.installed.loaded ? "Loaded" : entry.memoryFit ? "Fits" : "Low memory"}</strong>
    </div>
  );
}

function ActivityRow({ activity }: { activity: AgentActivity }) {
  return (
    <div className={`activity-row activity-${activity.state}`}>
      <span className="activity-icon">
        {activity.state === "running" ? <LoaderCircle className="spin" size={13} />
          : activity.state === "completed" ? <Check size={13} />
            : activity.state === "approval_required" ? <ShieldCheck size={13} />
              : <CircleAlert size={13} />}
      </span>
      <span><strong>{activity.purpose}</strong><small>{activityDetail(activity)}</small></span>
    </div>
  );
}

function ToolResultCard({ result }: { result: AgentToolResult<unknown> }) {
  const data = asRecord(result.data);
  const config = resultCardConfig(result.component);
  const rows = resultRows(result.component, data);
  const emptyText = stringField(data, "query_note", "No matching storage evidence");
  return (
    <section className={`tool-result-card result-${result.component}`} aria-label={config.label}>
      <header><config.icon size={13} /><strong>{config.label}</strong>{result.truncated && <small>Bounded</small>}</header>
      <div className="tool-result-content">
        {rows.length > 0 ? rows.map((row, index) => (
          <div className="tool-result-row" key={`${row.label}-${index}`} title={row.title ?? row.label}>
            <span>{row.label}</span><strong>{row.value}</strong>
          </div>
        )) : <span className="tool-result-empty">{emptyText}</span>}
      </div>
    </section>
  );
}

function resultCardConfig(component: AgentToolResult<unknown>["component"]) {
  if (component === "StorageOverviewResult") return { label: "Scan overview", icon: Database };
  if (component === "ItemListResult") return { label: "Storage items", icon: FolderSearch };
  if (component === "FolderInspectionResult") return { label: "Folder inspection", icon: FolderSearch };
  if (component === "CleanupOpportunitiesResult") return { label: "Cleanup opportunities", icon: ShieldCheck };
  if (component === "AggregateResult") return { label: "Storage groups", icon: BarChart3 };
  if (component === "OwnershipEvidenceResult") return { label: "Item evidence", icon: ShieldCheck };
  if (component === "LogExcerptApproval") return { label: "Approved log excerpt", icon: FileText };
  if (component === "CleanupProposalResult") return { label: "Cleanup proposal", icon: ShieldCheck };
  if (component === "PolicyChangeApproval") return { label: "Protection updated", icon: ShieldCheck };
  return { label: "Tool error", icon: CircleAlert };
}

function resultRows(component: AgentToolResult<unknown>["component"], data: Record<string, unknown>) {
  if (component === "StorageOverviewResult") {
    return [
      resultRow(typeof data.target === "object" ? stringField(asRecord(data.target), "display_path", "Target") : "Target", stringField(data, "allocated_bytes", "0"), true),
      resultRow("Indexed items", stringField(data, "entry_count", "0")),
      resultRow("Coverage", stringField(data, "coverage", "unknown").replaceAll("_", " ")),
    ];
  }
  if (component === "ItemListResult") {
    const items = Array.isArray(data.items) ? data.items.slice(0, 8) : [];
    const queryContext = asRecord(data.query_context);
    const sizeField = queryContext.sort === "logical" ? "logical_bytes" : "allocated_bytes";
    return items.flatMap((item) => {
      const record = asRecord(item);
      const name = stringField(record, "name", "Unnamed item");
      return [resultRow(name, stringField(record, sizeField, "0"), true, stringField(record, "display_path", name))];
    });
  }
  if (component === "FolderInspectionResult") {
    const scope = asRecord(data.scope);
    const children = Array.isArray(data.top_children) ? data.top_children.slice(0, 4) : [];
    const files = Array.isArray(data.top_files) ? data.top_files.slice(0, 4) : [];
    const extensions = Array.isArray(data.extension_buckets) ? data.extension_buckets.slice(0, 3) : [];
    const scopePath = stringField(scope, "display_path", "Selected folder");
    return [
      resultRow(scopePath, stringField(scope, "allocated_bytes", "0"), true, scopePath),
      ...children.map((item) => {
        const record = asRecord(item);
        const name = stringField(record, "name", "Unnamed item");
        return resultRow(`Child · ${name}`, stringField(record, "allocated_bytes", "0"), true, stringField(record, "display_path", name));
      }),
      ...files.map((item) => {
        const record = asRecord(item);
        const name = stringField(record, "name", "Unnamed file");
        return resultRow(`File · ${name}`, stringField(record, "allocated_bytes", "0"), true, stringField(record, "display_path", name));
      }),
      ...extensions.map((bucket) => {
        const record = asRecord(bucket);
        return resultRow(`Type · ${stringField(record, "label", "Other")}`, stringField(record, "allocated_bytes", "0"), true);
      }),
    ];
  }
  if (component === "CleanupOpportunitiesResult") {
    const items = Array.isArray(data.items) ? data.items.slice(0, 6) : [];
    return [
      resultRow("Conservative", stringField(data, "conservative_bytes", "0"), true),
      resultRow("Review potential", stringField(data, "review_potential_bytes", "0"), true),
      ...items.map((item) => {
        const record = asRecord(item);
        const title = stringField(record, "title", "Cleanup opportunity");
        const path = stringField(record, "display_path", title);
        const tier = stringField(record, "tier", "review_required").replaceAll("_", " ");
        const action = stringField(record, "action_kind", "none").replaceAll("_", " ");
        return resultRow(`${path} · ${tier}`, stringField(record, "reclaimable_bytes", "0"), true, action === "none" ? title : `${title} · ${action}`);
      }),
    ];
  }
  if (component === "AggregateResult") {
    const buckets = Array.isArray(data.buckets) ? data.buckets.slice(0, 8) : [];
    return buckets.map((bucket) => {
      const record = asRecord(bucket);
      return resultRow(stringField(record, "label", "Other"), stringField(record, "allocated_bytes", "0"), true);
    });
  }
  if (component === "OwnershipEvidenceResult") {
    const items = Array.isArray(data.items) ? data.items.slice(0, 3) : [];
    return items.flatMap((details) => {
      const item = asRecord(asRecord(details).item);
      const evidence = asRecord(asRecord(details).evidence);
      const owner = asRecord(item.owner);
      const path = stringField(item, "display_path", stringField(item, "name", "Item"));
      return [
        resultRow(path, stringField(item, "allocated_bytes", "0"), true, path),
        resultRow("Owner", stringField(owner, "name", "Unknown")),
        resultRow("Policy", stringField(evidence, "tier", "unknown").replaceAll("_", " ")),
      ];
    });
  }
  if (component === "LogExcerptApproval") {
    const excerpts = Array.isArray(data.excerpts) ? data.excerpts : [];
    return excerpts.slice(0, 5).map((excerpt) => {
      const record = asRecord(excerpt);
      return resultRow(stringField(record, "display_path", "Log"), stringField(record, "returned_bytes", "0"), true);
    });
  }
  if (component === "CleanupProposalResult") {
    return [
      resultRow("Conservative", stringField(data, "selected_candidate_bytes", "0"), true),
      resultRow("Review potential", stringField(data, "review_potential_bytes", "0"), true),
    ];
  }
  if (component === "PolicyChangeApproval") return [resultRow("Policy", "protected")];
  return [resultRow("Error", stringField(data, "error", "Unknown tool error"))];
}

function resultRow(label: string, value: string, bytes = false, title?: string) {
  return { label, value: bytes ? formatBytes(value) : value, title };
}

function gibibytesToBytes(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  const match = /^(\d+)(?:\.(\d{1,3}))?$/.exec(trimmed);
  if (!match) return null;
  const whole = BigInt(match[1] ?? "0");
  const fraction = BigInt((match[2] ?? "").padEnd(3, "0"));
  const milliGibibytes = whole * 1000n + fraction;
  if (milliGibibytes === 0n) return null;
  return ((milliGibibytes * 1024n * 1024n * 1024n) / 1000n).toString();
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function stringField(record: Record<string, unknown>, key: string, fallback: string) {
  const value = record[key];
  return typeof value === "string" ? value : fallback;
}

function toAnalyzerAttachment(item: ItemRow): AnalyzerAttachment {
  return {
    id: item.id,
    name: item.name,
    displayPath: item.display_path,
    kind: item.kind,
    allocatedBytes: item.allocated_bytes,
    logicalBytes: item.logical_bytes,
    policyTier: item.policy.tier,
  };
}

function activityDetail(activity: AgentActivity) {
  if (activity.state === "running") return "Running locally";
  if (activity.state === "approval_required") return "Waiting for approval";
  if (activity.state === "cancelled") return "Denied or cancelled";
  if (activity.state === "failed") return activity.error ?? "Tool failed";
  const parts = [
    activity.resultCount === null ? null : `${activity.resultCount} results`,
    activity.elapsedMs === null ? null : `${activity.elapsedMs} ms`,
    activity.truncated ? "bounded" : null,
  ].filter(Boolean);
  return parts.join(" · ") || "Completed";
}

function approvalLabel(approval: PendingAgentApproval) {
  return approval.tool === "inspect_log_excerpt" ? "Read bounded log excerpt" : "Protect exact path";
}

function agentErrorMessage(error: unknown) {
  return formatAgentError(error);
}

function formatBytes(value: string | number) {
  let bytes: bigint;
  try { bytes = BigInt(value); } catch { return "0 B"; }
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let divisor = 1n;
  let unit = 0;
  while (unit < units.length - 1 && bytes >= divisor * 1024n) {
    divisor *= 1024n;
    unit += 1;
  }
  if (unit === 0) return `${bytes} B`;
  const tenths = (bytes * 10n) / divisor;
  return `${tenths / 10n}.${tenths % 10n} ${units[unit]}`;
}

function formatDuration(milliseconds: number) {
  return milliseconds < 1_000 ? `${milliseconds} ms` : `${(milliseconds / 1_000).toFixed(1)} s`;
}

let idSequence = 0;
function newId(prefix: string) {
  idSequence += 1;
  return `${prefix}-${Date.now()}-${idSequence}`;
}
