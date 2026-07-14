import { tool } from "ai";
import { z } from "zod";
import type { CleanupPlan } from "../bindings/CleanupPlan";
import type { ItemDetails } from "../bindings/ItemDetails";
import type { ItemPage } from "../bindings/ItemPage";
import type { ItemQuery } from "../bindings/ItemQuery";
import type { LogExcerptBatch } from "../bindings/LogExcerptBatch";
import type { PolicyEvidence } from "../bindings/PolicyEvidence";
import type { ScanSummary } from "../bindings/ScanSummary";
import type { StorageAggregate } from "../bindings/StorageAggregate";
import type { StorageAggregateQuery } from "../bindings/StorageAggregateQuery";
import {
  AgentRuntimeError,
  type AgentResultComponent,
  type AgentToolResult,
  type AnalyzerAttachment,
} from "./types";

export const MAX_TOOL_RESULT_BYTES = 12 * 1024;
export const MAX_TURN_TOOL_BYTES = 32 * 1024;

export type AnalyzerInvoke = <T>(
  command: string,
  args?: Record<string, unknown>,
) => Promise<T>;

export interface AnalyzerToolDependencies {
  sessionId: string;
  invoke: AnalyzerInvoke;
  budget?: ToolResultBudget;
  attachment?: AnalyzerAttachment | null;
}

const byteString = z.string().regex(/^\d+$/, "Expected a non-negative decimal byte string");
const policyTier = z.enum(["protected", "review_required", "cleanup_candidate"]);
const itemKind = z.enum(["file", "directory", "reparse_point"]);
const itemSort = z.enum(["name", "allocated", "logical", "modified", "type", "policy", "owner"]);
const sortDirection = z.enum(["asc", "desc"]);
const aggregateDimension = z.enum(["extension", "owner", "policy", "kind"]);

export class ToolResultBudget {
  private usedBytes = 0;

  get remainingBytes(): number {
    return Math.max(0, MAX_TURN_TOOL_BYTES - this.usedBytes);
  }

  wrap<T>(component: AgentResultComponent, data: T): AgentToolResult<T> {
    const maximum = Math.min(MAX_TOOL_RESULT_BYTES, this.remainingBytes);
    if (maximum < 256) {
      throw new AgentRuntimeError(
        "TOOL_RESULT_LIMIT",
        "This turn exhausted its 32 KiB tool-result budget",
      );
    }
    const fitted = fitResult(component, data, maximum);
    this.usedBytes += fitted.serializedBytes;
    return fitted;
  }
}

export function createAnalyzerTools(dependencies: AnalyzerToolDependencies) {
  const budget = dependencies.budget ?? new ToolResultBudget();
  const invoke = dependencies.invoke;
  const sessionId = dependencies.sessionId;
  const attachment = dependencies.attachment ?? null;

  return {
    get_storage_overview: tool({
      description: "Get stable totals, coverage, warnings, and target metadata for the current scan.",
      inputSchema: z.object({}),
      execute: async () => {
        const summary = await invoke<ScanSummary | null>("get_scan_summary");
        if (!summary || summary.session_id !== sessionId) {
          throw new Error("The requested scan session is no longer active");
        }
        return budget.wrap("StorageOverviewResult", summary);
      },
    }),

    query_storage_items: tool({
      description: "Query at most 100 storage items. scope accepts a folder name, path, or exact returned item id and is resolved locally before querying inside it.",
      inputSchema: z.object({
        scope: z.string().max(1_024).optional().describe("Folder name, folder path, or exact item id to query inside."),
        text: z.string().max(256).optional().describe("Optional item name/path filter inside scope, or across the scan when scope is omitted."),
        kinds: z.array(itemKind).max(3).optional(),
        extensions: z.array(z.string().max(32)).max(20).optional(),
        policy_tiers: z.array(policyTier).max(3).optional(),
        owner_ids: z.array(z.string().max(256)).max(20).optional(),
        min_bytes: byteString.optional(),
        modified_before_ms: byteString.optional(),
        sort: itemSort.default("allocated"),
        direction: sortDirection.default("desc"),
        cursor: z.string().max(2_048).nullable().default(null),
        limit: z.number().int().min(1).max(100).default(25),
      }),
      execute: async (input) => {
        const resolved = await resolveQueryScope(sessionId, input.scope, invoke, attachment);
        if (resolved.result) return budget.wrap("ItemListResult", resolved.result);
        const query: ItemQuery = {
          parent_id: null,
          scope_id: resolved.scope?.id,
          text: input.text,
          kinds: input.kinds,
          extensions: input.extensions,
          policy_tiers: input.policy_tiers,
          owner_ids: input.owner_ids,
          min_bytes: input.min_bytes,
          modified_before_ms: input.modified_before_ms,
          sort: input.sort,
          direction: input.direction,
          cursor: input.cursor,
          limit: input.limit,
        };
        const page = await invoke<ItemPage>("query_items", { sessionId, query });
        return budget.wrap(
          "ItemListResult",
          resolved.scope ? { ...page, resolved_scope: resolved.scope } : page,
        );
      },
    }),

    summarize_storage: tool({
      description: "Summarize storage into at most 50 deterministic extension, owner, policy, or kind buckets. scope accepts a folder name, path, or exact current item id.",
      inputSchema: z.object({
        scope: z.string().max(1_024).optional(),
        group_by: aggregateDimension,
        limit: z.number().int().min(1).max(50).default(20),
      }),
      execute: async (input) => {
        const resolved = await resolveQueryScope(sessionId, input.scope, invoke, attachment);
        if (resolved.result) {
          return budget.wrap("AggregateResult", {
            buckets: [],
            other_item_count: "0",
            other_logical_bytes: "0",
            other_allocated_bytes: "0",
            scope_candidates: resolved.result.scope_candidates ?? [],
            query_note: resolved.result.query_note,
          });
        }
        const query: StorageAggregateQuery = {
          scope_id: resolved.scope?.id ?? null,
          dimension: input.group_by,
          limit: input.limit,
        };
        const aggregate = await invoke<StorageAggregate>("get_storage_aggregate", { sessionId, query });
        return budget.wrap(
          "AggregateResult",
          resolved.scope ? { ...aggregate, resolved_scope: resolved.scope } : aggregate,
        );
      },
    }),

    get_item_evidence: tool({
      description: "Get deterministic policy and ownership evidence. For the selected UI item, set use_attached_item instead of copying its internal ID.",
      inputSchema: z.object({
        item_ids: z.array(z.string().min(1)).max(20).default([]),
        use_attached_item: z.boolean().default(false),
      }).refine(
        ({ item_ids, use_attached_item }) => use_attached_item || item_ids.length > 0,
        "Choose the attached item or provide at least one returned item ID",
      ),
      execute: async ({ item_ids, use_attached_item }) => {
        const resolvedItemIds = attachedOrExplicitItemIds(item_ids, use_attached_item, attachment);
        const details: ItemDetails[] = [];
        for (const nodeId of resolvedItemIds) {
          details.push(await invoke<ItemDetails>("get_item_details", { sessionId, nodeId }));
        }
        return budget.wrap("OwnershipEvidenceResult", { items: details });
      },
    }),

    inspect_log_excerpt: tool({
      description: "Read bounded beginning/end excerpts from recognized text logs after exact-path user approval.",
      inputSchema: z.object({
        item_ids: z.array(z.string().min(1)).max(5).default([]),
        use_attached_item: z.boolean().default(false),
        requested_bytes_per_file: z.number().int().min(1).max(64 * 1024),
      }).refine(
        ({ item_ids, use_attached_item }) => use_attached_item || item_ids.length > 0,
        "Choose the attached item or provide at least one returned item ID",
      ).refine(
        ({ item_ids, use_attached_item, requested_bytes_per_file }) =>
          (use_attached_item ? 1 : item_ids.length) * requested_bytes_per_file <= 256 * 1024,
        "Log excerpts are limited to 256 KiB total",
      ),
      needsApproval: true,
      execute: async ({ item_ids, use_attached_item, requested_bytes_per_file }) => {
        const resolvedItemIds = attachedOrExplicitItemIds(item_ids, use_attached_item, attachment);
        const excerpts = await invoke<LogExcerptBatch>("inspect_log_excerpt", {
          sessionId,
          request: { item_ids: resolvedItemIds, requested_bytes_per_file },
        });
        return budget.wrap("LogExcerptApproval", excerpts);
      },
    }),

    build_cleanup_plan: tool({
      description: "Build a deterministic proposal. This does not delete, move, recycle, or uninstall anything.",
      inputSchema: z.object({ target_bytes: byteString.nullable().default(null) }),
      execute: async ({ target_bytes }) => {
        const plan = await invoke<CleanupPlan>("build_cleanup_plan", {
          sessionId,
          request: { target_bytes },
        });
        return budget.wrap("CleanupProposalResult", plan);
      },
    }),

    edit_cleanup_plan: tool({
      description: "Select or unselect existing deterministic plan items. Changes are session-only and reversible.",
      inputSchema: z.object({
        add_item_ids: z.array(z.string().min(1)).max(50).default([]),
        remove_item_ids: z.array(z.string().min(1)).max(50).default([]),
      }).refine(
        ({ add_item_ids, remove_item_ids }) => add_item_ids.length + remove_item_ids.length > 0,
        "At least one plan item ID is required",
      ),
      execute: async ({ add_item_ids, remove_item_ids }) => {
        let plan: CleanupPlan | null = null;
        for (const itemId of add_item_ids) {
          plan = await invoke<CleanupPlan>("edit_cleanup_plan", {
            sessionId,
            edit: { item_id: itemId, selected: true },
          });
        }
        for (const itemId of remove_item_ids) {
          plan = await invoke<CleanupPlan>("edit_cleanup_plan", {
            sessionId,
            edit: { item_id: itemId, selected: false },
          });
        }
        if (!plan) throw new Error("No cleanup-plan edit was applied");
        return budget.wrap("CleanupProposalResult", plan);
      },
    }),

    protect_path: tool({
      description: "Persistently protect one exact analyzer item from future cleanup suggestions.",
      inputSchema: z.object({
        item_id: z.string().min(1).optional(),
        use_attached_item: z.boolean().default(false),
        reason: z.string().max(300).optional(),
      }).refine(
        ({ item_id, use_attached_item }) => use_attached_item || Boolean(item_id),
        "Choose the attached item or provide one returned item ID",
      ),
      needsApproval: true,
      execute: async ({ item_id, use_attached_item, reason }) => {
        const [resolvedItemId] = attachedOrExplicitItemIds(
          item_id ? [item_id] : [],
          use_attached_item,
          attachment,
        );
        if (!resolvedItemId) throw new Error("No analyzer item was selected for protection");
        const evidence = await invoke<PolicyEvidence>("set_path_protection", {
          sessionId,
          request: { node_id: resolvedItemId, protected: true },
        });
        return budget.wrap("PolicyChangeApproval", {
          item_id: resolvedItemId,
          reason: reason ?? null,
          evidence,
        });
      },
    }),
  };
}

async function resolveQueryScope(
  sessionId: string,
  requestedScope: string | undefined,
  invoke: AnalyzerInvoke,
  attachment: AnalyzerAttachment | null,
) {
  const scope = requestedScope?.trim();
  if (!scope) {
    return attachment?.kind === "directory"
      ? { scope: attachmentScope(attachment), result: null }
      : { scope: null, result: null };
  }
  const normalizedScope = normalizePath(scope);
  if (!normalizedScope || /^[a-z]:$/i.test(normalizedScope)) {
    return { scope: null, result: null };
  }
  if (attachment?.kind === "directory" && (
    scope === attachment.id
    || normalizedScope === normalizePath(attachment.displayPath)
    || scope.toLocaleLowerCase() === attachment.name.trim().toLocaleLowerCase()
  )) {
    return { scope: attachmentScope(attachment), result: null };
  }
  if (scope.startsWith(`${sessionId}:`)) {
    return { scope: { id: scope, name: scope, display_path: null }, result: null };
  }
  if (/:\d+$/.test(scope)) {
    return {
      scope: null,
      result: {
        items: [],
        next_cursor: null,
        query_note: "That item id belongs to an earlier scan. Provide the folder name or path so it can be resolved again.",
      },
    };
  }

  const candidates = await invoke<ItemPage>("query_items", {
    sessionId,
    query: {
      parent_id: null,
      scope_id: undefined,
      text: scopeSearchText(scope),
      kinds: ["directory"],
      sort: "allocated",
      direction: "desc",
      cursor: null,
      limit: 100,
    } satisfies ItemQuery,
  });
  const matches = bestScopeMatches(candidates.items, scope);
  if (matches.length !== 1) {
    return {
      scope: null,
      result: {
        items: [],
        next_cursor: null,
        scope_candidates: matches.slice(0, 10),
        query_note: matches.length === 0
          ? `No folder matched scope ${JSON.stringify(scope)}.`
          : `Multiple folders matched scope ${JSON.stringify(scope)}. Use one returned display_path as scope.`,
      },
    };
  }
  const match = matches[0];
  return {
    scope: { id: match.id, name: match.name, display_path: match.display_path },
    result: null,
  };
}

function attachmentScope(attachment: AnalyzerAttachment) {
  return {
    id: attachment.id,
    name: attachment.name,
    display_path: attachment.displayPath,
  };
}

function attachedOrExplicitItemIds(
  itemIds: string[],
  useAttachedItem: boolean,
  attachment: AnalyzerAttachment | null,
) {
  if (!useAttachedItem) return [...new Set(itemIds)];
  if (!attachment) throw new Error("No analyzer item is attached to this message");
  return [attachment.id];
}

function scopeSearchText(scope: string) {
  const normalized = scope.trim().replaceAll("/", "\\").replace(/\\+$/, "");
  return normalized.slice(normalized.lastIndexOf("\\") + 1) || normalized;
}

function bestScopeMatches(items: ItemPage["items"], scope: string) {
  const normalizedScope = normalizePath(scope);
  const exactPaths = items.filter((item) => normalizePath(item.display_path) === normalizedScope);
  if (exactPaths.length > 0) return exactPaths;
  const exactNames = items.filter((item) => item.name.trim().toLocaleLowerCase() === scope.trim().toLocaleLowerCase());
  if (exactNames.length > 0) return exactNames;
  return items.length === 1 ? items : items.filter((item) =>
    normalizePath(item.display_path).endsWith(`\\${normalizedScope}`));
}

function normalizePath(value: string) {
  return value.trim().replaceAll("/", "\\").replace(/\\+$/, "").toLocaleLowerCase();
}

function fitResult<T>(
  component: AgentResultComponent,
  data: T,
  maximumBytes: number,
): AgentToolResult<T> {
  const candidate = cloneJson(data);
  let truncated = false;
  let envelope = sizedEnvelope(component, candidate, truncated);
  while (serializedBytes(envelope) > maximumBytes) {
    const array = largestArray(candidate);
    if (array && array.length > 1) {
      array.pop();
    } else if (component === "LogExcerptApproval" && shrinkLargestLogContent(candidate)) {
      // Keep a bounded beginning and end of a single approved log instead of
      // dropping the only excerpt when its content exceeds the model budget.
    } else if (array && array.length === 1) {
      array.pop();
    } else {
      throw new AgentRuntimeError(
        "TOOL_RESULT_LIMIT",
        `${component} cannot fit within the tool-result budget`,
      );
    }
    truncated = true;
    envelope = sizedEnvelope(component, candidate, truncated);
  }
  return envelope as AgentToolResult<T>;
}

function sizedEnvelope<T>(component: AgentResultComponent, data: T, truncated: boolean) {
  const envelope = { component, data, truncated, serializedBytes: 0 };
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const size = serializedBytes(envelope);
    if (size === envelope.serializedBytes) break;
    envelope.serializedBytes = size;
  }
  return envelope;
}

function largestArray(value: unknown): unknown[] | null {
  let largest: unknown[] | null = null;
  const pending = [value];
  while (pending.length > 0) {
    const current = pending.pop();
    if (Array.isArray(current)) {
      if (!largest || current.length > largest.length) largest = current;
      pending.push(...current);
    } else if (current && typeof current === "object") {
      pending.push(...Object.values(current));
    }
  }
  return largest;
}

function shrinkLargestLogContent(value: unknown): boolean {
  let owner: Record<string, unknown> | null = null;
  let longest = "";
  const pending = [value];
  while (pending.length > 0) {
    const current = pending.pop();
    if (Array.isArray(current)) {
      pending.push(...current);
    } else if (current && typeof current === "object") {
      const record = current as Record<string, unknown>;
      if (typeof record.content === "string" && record.content.length > longest.length) {
        owner = record;
        longest = record.content;
      }
      pending.push(...Object.values(record));
    }
  }

  if (!owner || longest.length <= 256) return false;
  const marker = "\n...[tool result truncated]...\n";
  const keep = Math.max(64, Math.floor((longest.length - marker.length) / 4));
  owner.content = `${longest.slice(0, keep)}${marker}${longest.slice(-keep)}`;
  return true;
}

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function serializedBytes(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

export function countToolResultItems(result: unknown): number | null {
  if (!result || typeof result !== "object") return null;
  const data = (result as { data?: unknown }).data;
  if (data && typeof data === "object") {
    for (const key of ["items", "buckets", "scenarios"]) {
      const value = (data as Record<string, unknown>)[key];
      if (Array.isArray(value)) return value.length;
    }
  }
  return null;
}
