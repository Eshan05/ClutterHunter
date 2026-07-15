import { invoke } from "@tauri-apps/api/core";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  ArrowDown,
  ArrowLeft,
  ArrowRight,
  ArrowUp,
  ChevronRight,
  CircleGauge,
  Columns3,
  Copy,
  Database,
  File,
  Folder,
  FolderOpen,
  HardDrive,
  Link2,
  LoaderCircle,
  Search,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ItemPage } from "./bindings/ItemPage";
import type { ItemQuery } from "./bindings/ItemQuery";
import type { ItemRow } from "./bindings/ItemRow";
import type { ItemSort } from "./bindings/ItemSort";
import type { ScanFailure } from "./bindings/ScanFailure";
import type { ScanProgress } from "./bindings/ScanProgress";
import type { ScanSummary } from "./bindings/ScanSummary";
import type { SortDirection } from "./bindings/SortDirection";
import type { StorageAggregate } from "./bindings/StorageAggregate";
import type { TreemapNode } from "./bindings/TreemapNode";
import type { TreemapSlice } from "./bindings/TreemapSlice";
import { TreemapCanvas } from "./analyzer/TreemapCanvas";

export type AnalyzerMetric = "allocated" | "logical";
export type AnalyzerScanStatus = "idle" | "scanning" | "cancelling" | "complete" | "error";

interface AnalyzerWorkspaceProps {
  summary: ScanSummary | null;
  progress: ScanProgress | null;
  scanStatus: AnalyzerScanStatus;
  scanError: ScanFailure | null;
  metric: AnalyzerMetric;
  onMetricChange: (metric: AnalyzerMetric) => void;
  onSelectionChange: (item: ItemRow | null) => void;
}

interface ScopeEntry {
  id: string | null;
  name: string;
  displayPath: string;
  allocatedBytes: string;
  logicalBytes: string;
}

const PAGE_SIZE = 100;
const extensionColors = ["#317d70", "#b8734f", "#536f9f", "#a3873d", "#735f8d", "#4d8264", "#a45656"];

export function AnalyzerWorkspace({
  summary,
  progress,
  scanStatus,
  scanError,
  metric,
  onMetricChange,
  onSelectionChange,
}: AnalyzerWorkspaceProps) {
  const rootScope = useMemo<ScopeEntry>(() => ({
    id: null,
    name: summary?.target.display_path ?? "Computer",
    displayPath: summary?.target.display_path ?? "Computer",
    allocatedBytes: summary?.allocated_bytes ?? "0",
    logicalBytes: summary?.logical_bytes ?? "0",
  }), [summary]);
  const [navigation, setNavigation] = useState<ScopeEntry[][]>([[rootScope]]);
  const [navigationIndex, setNavigationIndex] = useState(0);
  const [items, setItems] = useState<ItemRow[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [selectedItem, setSelectedItem] = useState<ItemRow | null>(null);
  const [searchInput, setSearchInput] = useState("");
  const searchText = useDebouncedValue(searchInput.trim(), 250);
  const [sort, setSort] = useState<ItemSort>("allocated");
  const [direction, setDirection] = useState<SortDirection>("desc");
  const [aggregate, setAggregate] = useState<StorageAggregate | null>(null);
  const [treemap, setTreemap] = useState<TreemapSlice | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [viewError, setViewError] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const querySerial = useRef(0);
  const crumbs = navigation[navigationIndex] ?? [rootScope];
  const scope = crumbs.at(-1) ?? rootScope;

  useEffect(() => {
    const nextRoot = [{ ...rootScope }];
    setNavigation([nextRoot]);
    setNavigationIndex(0);
    setItems([]);
    setNextCursor(null);
    setSelectedItem(null);
    setSearchInput("");
    setViewError(null);
    onSelectionChange(null);
  }, [onSelectionChange, rootScope, summary?.session_id]);

  const makeQuery = useCallback((cursor: string | null, queryId: string): ItemQuery => ({
    parent_id: searchText ? null : scope.id,
    recursive: Boolean(searchText),
    scope_id: searchText && scope.id ? scope.id : undefined,
    text: searchText || undefined,
    query_id: queryId,
    sort,
    direction,
    cursor,
    limit: PAGE_SIZE,
  }), [direction, scope.id, searchText, sort]);

  useEffect(() => {
    if (!summary) {
      setItems([]);
      setNextCursor(null);
      return;
    }
    const queryId = `analyzer-${Date.now().toString(36)}-${++querySerial.current}`;
    let active = true;
    setLoading(true);
    setViewError(null);
    setSelectedItem(null);
    onSelectionChange(null);
    void invoke<ItemPage>("query_items", {
      sessionId: summary.session_id,
      query: makeQuery(null, queryId),
    }).then((page) => {
      if (!active) return;
      setItems(page.items);
      setNextCursor(page.next_cursor);
      scrollRef.current?.scrollTo({ top: 0 });
    }).catch((error) => {
      if (active) setViewError(failureDetail(error));
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => {
      active = false;
      void invoke<boolean>("cancel_item_query", {
        sessionId: summary.session_id,
        queryId,
      }).catch(() => undefined);
    };
  }, [makeQuery, onSelectionChange, summary]);

  useEffect(() => {
    if (!summary) {
      setAggregate(null);
      setTreemap(null);
      return;
    }
    let active = true;
    void Promise.all([
      invoke<StorageAggregate>("get_storage_aggregate", {
        sessionId: summary.session_id,
        query: { scope_id: scope.id, dimension: "extension", limit: 12 },
      }),
      invoke<TreemapSlice>("get_treemap_slice", {
        sessionId: summary.session_id,
        query: { scope_id: scope.id, max_nodes: 2_500 },
      }),
    ]).then(([nextAggregate, nextTreemap]) => {
      if (!active) return;
      setAggregate(nextAggregate);
      setTreemap(nextTreemap);
    }).catch((error) => {
      if (active) setViewError(failureDetail(error));
    });
    return () => { active = false; };
  }, [scope.id, summary]);

  const loadMore = useCallback(async () => {
    if (!summary || !nextCursor || loadingMore) return;
    const queryId = `analyzer-page-${Date.now().toString(36)}-${++querySerial.current}`;
    setLoadingMore(true);
    try {
      const page = await invoke<ItemPage>("query_items", {
        sessionId: summary.session_id,
        query: makeQuery(nextCursor, queryId),
      });
      setItems((current) => [...current, ...page.items]);
      setNextCursor(page.next_cursor);
    } catch (error) {
      setViewError(failureDetail(error));
    } finally {
      setLoadingMore(false);
    }
  }, [loadingMore, makeQuery, nextCursor, summary]);

  const rowVirtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 30,
    overscan: 10,
  });
  const virtualRows = rowVirtualizer.getVirtualItems();

  useEffect(() => {
    const last = virtualRows.at(-1);
    if (last && last.index >= items.length - 8 && nextCursor && !loadingMore) void loadMore();
  }, [items.length, loadMore, loadingMore, nextCursor, virtualRows]);

  const chooseItem = useCallback((item: ItemRow | null) => {
    setSelectedItem(item);
    onSelectionChange(item);
  }, [onSelectionChange]);

  const navigate = useCallback((nextCrumbs: ScopeEntry[]) => {
    setNavigation((current) => [...current.slice(0, navigationIndex + 1), nextCrumbs]);
    setNavigationIndex((current) => current + 1);
    setSearchInput("");
  }, [navigationIndex]);

  const openItem = useCallback((item: ItemRow) => {
    if (item.kind !== "directory") return;
    navigate([...crumbs, scopeFromItem(item)]);
  }, [crumbs, navigate]);

  const resolveTreemapNode = useCallback(async (node: TreemapNode, open: boolean) => {
    if (!summary || node.synthetic) return;
    const visible = items.find((item) => item.id === node.id);
    if (visible) {
      if (open) openItem(visible);
      else chooseItem(visible);
      return;
    }
    try {
      const details = await invoke<{ item: ItemRow }>("get_item_details", {
        sessionId: summary.session_id,
        nodeId: node.id,
      });
      if (open) openItem(details.item);
      else chooseItem(details.item);
    } catch (error) {
      setViewError(failureDetail(error));
    }
  }, [chooseItem, items, openItem, summary]);

  const changeSort = (nextSort: ItemSort) => {
    if (sort === nextSort) setDirection((current) => current === "asc" ? "desc" : "asc");
    else {
      setSort(nextSort);
      setDirection(nextSort === "name" ? "asc" : "desc");
    }
  };

  const copySelectedPath = async () => {
    if (!selectedItem) return;
    try {
      await navigator.clipboard.writeText(selectedItem.display_path);
    } catch (error) {
      setViewError(failureDetail(error));
    }
  };

  const revealSelectedItem = async () => {
    if (!selectedItem) return;
    try {
      await revealItemInDir(selectedItem.display_path);
    } catch (error) {
      setViewError(failureDetail(error));
    }
  };
  const scopeBytes = metric === "allocated" ? scope.allocatedBytes : scope.logicalBytes;
  const noRows = !loading && items.length === 0;

  return (
    <div className="analyzer-pane">
      <div className="analyzer-toolbar">
        <div className="history-controls" aria-label="Navigation history">
          <button type="button" title="Back" aria-label="Back" disabled={navigationIndex === 0} onClick={() => setNavigationIndex((index) => Math.max(0, index - 1))}><ArrowLeft size={15} /></button>
          <button type="button" title="Forward" aria-label="Forward" disabled={navigationIndex >= navigation.length - 1} onClick={() => setNavigationIndex((index) => Math.min(navigation.length - 1, index + 1))}><ArrowRight size={15} /></button>
        </div>
        <nav className="breadcrumb" aria-label="Current location">
          {crumbs.map((entry, index) => (
            <span className="breadcrumb-part" key={entry.id ?? "root"}>
              {index > 0 && <ChevronRight size={13} />}
              <button type="button" title={entry.displayPath} onClick={() => index < crumbs.length - 1 && navigate(crumbs.slice(0, index + 1))}>
                {index === 0 && <HardDrive size={14} />}{entry.name}
              </button>
            </span>
          ))}
        </nav>
        {selectedItem && (
          <div className="selection-actions" aria-label="Selected item actions">
            <button type="button" title="Copy path" aria-label="Copy selected path" onClick={() => void copySelectedPath()}><Copy size={14} /></button>
            <button type="button" title="Reveal in Explorer" aria-label="Reveal selected item in Explorer" onClick={() => void revealSelectedItem()}><FolderOpen size={14} /></button>
          </div>
        )}
        <label className="search-control">
          <Search size={15} />
          <input aria-label="Search storage items" placeholder={`Search in ${scope.name}`} value={searchInput} onChange={(event) => setSearchInput(event.target.value)} />
          {searchInput && <button type="button" title="Clear search" aria-label="Clear search" onClick={() => setSearchInput("")}><X size={13} /></button>}
        </label>
        <div className="segmented-control" aria-label="Size metric">
          <button type="button" aria-pressed={metric === "allocated"} className={metric === "allocated" ? "active" : ""} onClick={() => onMetricChange("allocated")}>Allocated</button>
          <button type="button" aria-pressed={metric === "logical"} className={metric === "logical" ? "active" : ""} onClick={() => onMetricChange("logical")}>Logical</button>
        </div>
      </div>

      <div className="analyzer-grid">
        <section className="table-panel" aria-label="Storage hierarchy">
          <div className="table-header table-row analyzer-table-row">
            <SortHeader label="Name" icon={<Columns3 size={14} />} active={sort === "name"} direction={direction} onClick={() => changeSort("name")} />
            <SortHeader label="Allocated" active={sort === "allocated"} direction={direction} onClick={() => changeSort("allocated")} />
            <SortHeader label="Logical" active={sort === "logical"} direction={direction} onClick={() => changeSort("logical")} />
            <span>Percent</span>
            <SortHeader label="Modified" active={sort === "modified"} direction={direction} onClick={() => changeSort("modified")} />
            <SortHeader label="AI policy" active={sort === "policy"} direction={direction} onClick={() => changeSort("policy")} />
            <SortHeader label="Owner" active={sort === "owner"} direction={direction} onClick={() => changeSort("owner")} />
          </div>
          <div ref={scrollRef} className="table-scroll">
            <div className="virtual-table" style={{ height: rowVirtualizer.getTotalSize() }}>
              {virtualRows.map((virtualRow) => {
                const item = items[virtualRow.index];
                if (!item) return null;
                return (
                  <div
                    className={`table-row analyzer-table-row data-row virtual-table-row ${selectedItem?.id === item.id ? "selected" : ""}`}
                    key={item.id}
                    role="button"
                    tabIndex={0}
                    aria-pressed={selectedItem?.id === item.id}
                    style={{ height: virtualRow.size, transform: `translateY(${virtualRow.start}px)` }}
                    onClick={() => chooseItem(selectedItem?.id === item.id ? null : item)}
                    onDoubleClick={() => openItem(item)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter") {
                        event.preventDefault();
                        item.kind === "directory" ? openItem(item) : chooseItem(item);
                      } else if (event.key === " ") {
                        event.preventDefault();
                        chooseItem(selectedItem?.id === item.id ? null : item);
                      }
                    }}
                  >
                    <span className="name-cell item-name" title={item.display_path}>
                      {item.kind === "directory" ? <Folder size={15} /> : item.kind === "reparse_point" ? <Link2 size={15} /> : <File size={15} />}
                      <span>{item.name}</span>
                    </span>
                    <span>{formatBytes(item.allocated_bytes)}</span>
                    <span>{formatBytes(item.logical_bytes)}</span>
                    <span className="percent-cell">
                      <span className="percent-track" aria-hidden="true"><span style={{ width: percentWidth(item, scopeBytes, metric) }} /></span>
                      <span>{formatPercent(item, scopeBytes, metric)}</span>
                    </span>
                    <span>{formatModified(item.modified_at_ms)}</span>
                    <span
                      className={`policy-tier policy-${item.policy.tier}`}
                      title={policyTitle(item.policy.tier)}
                    >
                      {policyLabel(item.policy.tier)}
                    </span>
                    <span className="owner-cell" title={item.owner?.name}>{item.owner?.name ?? "-"}</span>
                  </div>
                );
              })}
            </div>
            {loadingMore && <div className="table-loading-more"><LoaderCircle className="spin" size={13} />Loading more</div>}
            {(loading || noRows) && (
              <div className="empty-state">
                {loading || scanStatus === "scanning" || scanStatus === "cancelling" ? <LoaderCircle className="spin" size={22} /> : <Database size={22} />}
                <strong>{loading ? "Loading analyzer" : searchText ? "No matching items" : scanError?.detail ?? "No items in this location"}</strong>
                <span>{loading ? "Reading bounded analyzer results" : searchText ? "Clear search or choose another folder" : `${formatCount(progress?.entries_seen ?? "0")} indexed items`}</span>
              </div>
            )}
          </div>
          {viewError && <div className="analyzer-error">{viewError}</div>}
        </section>

        <aside className="extension-panel" aria-label="Extension summary">
          <div className="panel-title"><span>File types</span><CircleGauge size={15} /></div>
          <div className="extension-list">
            {aggregate?.buckets.map((bucket, index) => {
              const value = metric === "allocated" ? bucket.allocated_bytes : bucket.logical_bytes;
              const largest = aggregate.buckets[0];
              const maximum = largest ? (metric === "allocated" ? largest.allocated_bytes : largest.logical_bytes) : "0";
              return (
                <div className="extension-row" key={bucket.key}>
                  <span className="extension-swatch" style={{ backgroundColor: extensionColors[index % extensionColors.length] }} />
                  <span title={bucket.label}>{bucket.label || "No extension"}</span>
                  <strong>{formatBytes(value)}</strong>
                  <span className="extension-track"><span style={{ width: ratioWidth(value, maximum) }} /></span>
                </div>
              );
            })}
            {aggregate && BigInt(aggregate.other_allocated_bytes) > 0n && (
              <div className="extension-row extension-other"><span className="extension-swatch" /><span>Other</span><strong>{formatBytes(metric === "allocated" ? aggregate.other_allocated_bytes : aggregate.other_logical_bytes)}</strong><span className="extension-track"><span /></span></div>
            )}
            {!aggregate && summary && <div className="panel-loading"><LoaderCircle className="spin" size={15} />Loading types</div>}
          </div>
        </aside>

        <section className="treemap-panel" aria-label="Storage treemap panel">
          <div className="panel-title">
            <span className="treemap-scope-title">
              <span>Treemap</span>
              <strong title={scope.displayPath}>{scope.name}</strong>
            </span>
            <span className="metric-caption">Allocated size</span>
          </div>
          {treemap?.nodes.length ? (
            <TreemapCanvas
              nodes={treemap.nodes}
              omittedAllocatedBytes={treemap.other_allocated_bytes}
              scopeName={scope.name}
              scopePath={scope.displayPath}
              selectedId={selectedItem?.id ?? null}
              onSelect={(node) => void resolveTreemapNode(node, false)}
              onOpen={(node) => void resolveTreemapNode(node, true)}
              formatBytes={formatBytes}
            />
          ) : (
            <div className="treemap-status"><Database size={19} /><span>{summary ? "No allocated children in this location" : "Run a scan to build the treemap"}</span></div>
          )}
        </section>
      </div>
    </div>
  );
}

function SortHeader({
  label,
  icon,
  active,
  direction,
  onClick,
}: {
  label: string;
  icon?: React.ReactNode;
  active: boolean;
  direction: SortDirection;
  onClick: () => void;
}) {
  return (
    <button type="button" className={`sort-header ${active ? "active" : ""}`} onClick={onClick}>
      {icon}{label}{active && (direction === "asc" ? <ArrowUp size={11} /> : <ArrowDown size={11} />)}
    </button>
  );
}

function scopeFromItem(item: ItemRow): ScopeEntry {
  return {
    id: item.id,
    name: item.name,
    displayPath: item.display_path,
    allocatedBytes: item.allocated_bytes,
    logicalBytes: item.logical_bytes,
  };
}

function useDebouncedValue<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timeout = window.setTimeout(() => setDebounced(value), delay);
    return () => window.clearTimeout(timeout);
  }, [delay, value]);
  return debounced;
}

function failureDetail(error: unknown): string {
  if (error && typeof error === "object" && "detail" in error && typeof error.detail === "string") return error.detail;
  if (error instanceof Error) return error.message;
  return String(error);
}

function policyLabel(tier: ItemRow["policy"]["tier"]): string {
  return tier === "cleanup_candidate" ? "Suggested" : tier === "review_required" ? "Ask first" : "Not suggested";
}

function policyTitle(tier: ItemRow["policy"]["tier"]): string {
  if (tier === "cleanup_candidate") return "AI may include this in conservative cleanup plans";
  if (tier === "review_required") return "AI may surface this only for your review";
  return "Excluded from AI-generated cleanup plans; this does not restrict your own actions";
}

function formatModified(value: string | null): string {
  if (!value) return "-";
  const date = new Date(Number(value));
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleDateString();
}

export function formatBytes(value: string): string {
  let bytes: bigint;
  try { bytes = BigInt(value); } catch { return value; }
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

function formatCount(value: string): string {
  try { return BigInt(value).toLocaleString(); } catch { return value; }
}

function itemMetricBytes(item: ItemRow, metric: AnalyzerMetric): bigint {
  return BigInt(metric === "allocated" ? item.allocated_bytes : item.logical_bytes);
}

function formatPercent(item: ItemRow, scopeBytes: string, metric: AnalyzerMetric): string {
  const total = BigInt(scopeBytes);
  if (total === 0n) return "0%";
  const tenths = (itemMetricBytes(item, metric) * 1000n) / total;
  return `${tenths / 10n}.${tenths % 10n}%`;
}

function percentWidth(item: ItemRow, scopeBytes: string, metric: AnalyzerMetric): string {
  const total = BigInt(scopeBytes);
  if (total === 0n) return "0%";
  const thousandths = (itemMetricBytes(item, metric) * 100_000n) / total;
  return `${Number(thousandths > 100_000n ? 100_000n : thousandths) / 1000}%`;
}

function ratioWidth(value: string, maximum: string): string {
  const max = BigInt(maximum);
  if (max === 0n) return "0%";
  return `${Number((BigInt(value) * 1000n) / max) / 10}%`;
}
