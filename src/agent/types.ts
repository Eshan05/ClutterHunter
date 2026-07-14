export type AgentErrorCode =
  | "INVALID_ENDPOINT"
  | "OLLAMA_UNAVAILABLE"
  | "OLLAMA_RESPONSE_INVALID"
  | "MODEL_NOT_INSTALLED"
  | "MODEL_NOT_LOCAL"
  | "MODEL_TOOLS_UNSUPPORTED"
  | "MODEL_PREFLIGHT_FAILED"
  | "MODEL_INCOMPATIBLE"
  | "TOOL_RESULT_LIMIT"
  | "APPROVAL_REQUIRED";

export class AgentRuntimeError extends Error {
  readonly code: AgentErrorCode;
  readonly recoverable: boolean;

  constructor(code: AgentErrorCode, message: string, recoverable = true) {
    super(message);
    this.name = "AgentRuntimeError";
    this.code = code;
    this.recoverable = recoverable;
  }
}

export function formatAgentError(error: unknown, maximumLength = 300): string {
  return describeAgentError(error, new Set()).slice(0, maximumLength);
}

function describeAgentError(error: unknown, seen: Set<object>): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message || error.name;
  if (error && typeof error === "object") {
    if (seen.has(error)) return "Unknown agent error";
    seen.add(error);
    const record = error as Record<string, unknown>;
    for (const key of ["detail", "message", "error", "cause"] as const) {
      if (record[key] !== undefined) {
        const message = describeAgentError(record[key], seen);
        if (message && message !== "Unknown agent error") return message;
      }
    }
    try {
      return JSON.stringify(error, (_, value) => typeof value === "bigint" ? value.toString() : value);
    } catch {
      return "Unknown agent error";
    }
  }
  return String(error);
}

export interface OllamaEndpoint {
  port: number;
  origin: string;
  nativeApiUrl: string;
}

export interface OllamaModelDetails {
  format?: string;
  family?: string;
  families?: string[];
  parameter_size?: string;
  quantization_level?: string;
}

export interface InstalledOllamaModel {
  name: string;
  model: string;
  modified_at: string;
  size: number;
  digest: string;
  details: OllamaModelDetails;
  loaded?: {
    sizeBytes: number;
    sizeVramBytes: number;
    contextLength: number;
    expiresAt: string;
  };
}

export interface OllamaModelShow {
  capabilities: string[];
  modified_at?: string;
  details?: OllamaModelDetails;
  model_info?: Record<string, unknown>;
  parameters?: string;
}

export interface LocalModelPreflight {
  model: InstalledOllamaModel;
  show: OllamaModelShow;
  ollamaVersion: string;
  totalDurationNs: number | null;
}

export type ModelClass = "light" | "balanced" | "heavy";

export interface ModelCatalogEntry {
  id: string;
  label: string;
  class: ModelClass;
  expectedBytes: number;
  minMemoryBytes: number;
  recommendedContext: number;
  qualityRank: number;
  officialUrl: string;
}

export interface HardwareProfile {
  totalMemoryBytes: number;
  availableMemoryBytes?: number;
  dedicatedGpuMemoryBytes?: number;
}

export interface HarnessScenarioResult {
  id: string;
  passed: boolean;
  firstTokenMs: number | null;
  elapsedMs: number;
  detail: string;
}

export interface ModelHarnessResult {
  harnessVersion: number;
  model: string;
  digest: string;
  ollamaVersion: string;
  passed: boolean;
  firstTokenMs: number | null;
  totalElapsedMs: number;
  scenarios: HarnessScenarioResult[];
}

export type AgentToolName =
  | "get_storage_overview"
  | "list_folder_children"
  | "list_largest_items"
  | "search_storage"
  | "inspect_folder"
  | "list_cleanup_opportunities"
  | "summarize_storage"
  | "inspect_item"
  | "inspect_log_excerpt"
  | "build_cleanup_plan"
  | "edit_cleanup_plan"
  | "protect_path";

export type AgentActivityState =
  | "running"
  | "completed"
  | "failed"
  | "approval_required"
  | "cancelled";

export interface AgentActivity {
  id: string;
  tool: AgentToolName;
  purpose: string;
  state: AgentActivityState;
  arguments: Record<string, unknown>;
  resultCount: number | null;
  elapsedMs: number | null;
  truncated: boolean;
  error?: string;
}

export type AgentResultComponent =
  | "StorageOverviewResult"
  | "ItemListResult"
  | "FolderInspectionResult"
  | "CleanupOpportunitiesResult"
  | "AggregateResult"
  | "OwnershipEvidenceResult"
  | "LogExcerptApproval"
  | "CleanupProposalResult"
  | "PolicyChangeApproval"
  | "ToolErrorResult";

export interface AgentToolResult<T> {
  component: AgentResultComponent;
  data: T;
  truncated: boolean;
  serializedBytes: number;
}

export interface AnalyzerAttachment {
  id: string;
  name: string;
  displayPath: string;
  kind: "file" | "directory" | "reparse_point";
  allocatedBytes: string;
  logicalBytes: string;
  policyTier: "protected" | "review_required" | "cleanup_candidate";
}

export type AgentActivityListener = (activity: AgentActivity) => void;
