import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { Channel, invoke, isTauri } from "@tauri-apps/api/core";
import {
  ChevronLeft,
  ChevronRight,
  CircleGauge,
  Columns3,
  Database,
  File,
  Folder,
  FolderOpen,
  HardDrive,
  Link2,
  ListTree,
  LoaderCircle,
  PanelRightClose,
  PanelRightOpen,
  Play,
  Search,
  ShieldCheck,
  Square,
  Trash2,
  FolderInput,
} from "lucide-react";
import type { ItemPage } from "./bindings/ItemPage";
import type { ItemQuery } from "./bindings/ItemQuery";
import type { ItemRow } from "./bindings/ItemRow";
import type { ScanFailure } from "./bindings/ScanFailure";
import type { ScanProgress } from "./bindings/ScanProgress";
import type { ScanRequest } from "./bindings/ScanRequest";
import type { ScanSummary } from "./bindings/ScanSummary";
import type { ScanTarget } from "./bindings/ScanTarget";
import type { TreemapNode } from "./bindings/TreemapNode";
import type { TreemapSlice } from "./bindings/TreemapSlice";
import { HoverAIInsightCard } from "./analyzer/HoverAIInsightCard";
import { TreemapCanvas } from "./analyzer/TreemapCanvas";
import "./App.css";

type Metric = "allocated" | "logical";
type ScanStatus = "idle" | "scanning" | "cancelling" | "complete" | "error";

const desktopRuntime = isTauri();
const AgentDock = lazy(() => import("./AgentDock").then((module) => ({ default: module.AgentDock })));
const browserTarget: ScanTarget = {
  id: "browser-preview",
  kind: "volume",
  display_path: "C:\\",
  filesystem: "NTFS",
  volume_id: null,
  total_bytes: null,
  available_bytes: null,
  fast_scan_available: true,
};
const emptyRows = Array.from({ length: 7 }, (_, index) => index);

function treemapNodeToItemRow(node: TreemapNode): ItemRow {
  return {
    id: node.id,
    parent_id: node.parent_id,
    name: node.name,
    display_path: node.name,
    kind: node.kind,
    logical_bytes: node.allocated_bytes,
    allocated_bytes: node.allocated_bytes,
    modified_at_ms: null,
    extension: node.name.includes(".") ? node.name.split(".").pop() ?? null : null,
    attributes: [],
    hard_link_count: null,
    child_count: null,
    owner: null,
    policy: {
      tier: node.policy_tier,
      rule_id: "treemap_slice",
      rule_version: "1.0",
      facts: [],
      inference: [],
      warnings: [],
    },
  };
}

function App() {
  const [targets, setTargets] = useState<ScanTarget[]>([browserTarget]);
  const [selectedTargetId, setSelectedTargetId] = useState(browserTarget.id);
  const [metric, setMetric] = useState<Metric>("allocated");
  const [dockOpen, setDockOpen] = useState(
    () => window.localStorage.getItem("clutterhunter:dock-open") !== "false",
  );
  const [scanStatus, setScanStatus] = useState<ScanStatus>("idle");
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [items, setItems] = useState<ItemRow[]>([]);
  const [selectedItem, setSelectedItem] = useState<ItemRow | null>(null);
  const [hoveredItem, setHoveredItem] = useState<ItemRow | null>(null);
  const [hoverAnchor, setHoverAnchor] = useState<DOMRect | null>(null);
  const [scanError, setScanError] = useState<ScanFailure | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [useTraversalFallback, setUseTraversalFallback] = useState(false);

  const [treemapNodes, setTreemapNodes] = useState<TreemapNode[]>([]);
  const [treemapScopePath, setTreemapScopePath] = useState<Array<{ id: string | null; name: string }>>([
    { id: null, name: "Root" },
  ]);

  const currentTreemapScope = treemapScopePath[treemapScopePath.length - 1]?.id ?? null;

  useEffect(() => {
    if (!summary || !desktopRuntime) {
      setTreemapNodes([]);
      return;
    }
    void invoke<TreemapSlice>("get_treemap_slice", {
      sessionId: summary.session_id,
      query: { scope_id: currentTreemapScope, max_nodes: 35 },
    }).then((slice) => {
      setTreemapNodes(slice.nodes);
    }).catch(() => {
      setTreemapNodes([]);
    });
  }, [summary, currentTreemapScope]);

  const [tableScopePath, setTableScopePath] = useState<Array<{ id: string | null; name: string }>>([
    { id: null, name: "Root" },
  ]);
  const [deleteConfirmItem, setDeleteConfirmItem] = useState<ItemRow | null>(null);
  const [isDeleting, setIsDeleting] = useState<boolean>(false);
  const [deleteNotice, setDeleteNotice] = useState<string | null>(null);

  const currentTableParentId = tableScopePath[tableScopePath.length - 1]?.id ?? null;

  useEffect(() => {
    if (!summary || !desktopRuntime) return;
    const query: ItemQuery = {
      parent_id: currentTableParentId,
      sort: "allocated",
      direction: "desc",
      cursor: null,
      limit: 150,
    };
    void invoke<ItemPage>("query_items", {
      sessionId: summary.session_id,
      query,
    }).then((page) => {
      setItems(page.items);
    }).catch(() => {});
  }, [summary, currentTableParentId]);

  const handleTableNavigateUp = () => {
    if (tableScopePath.length > 1) {
      setTableScopePath((current) => current.slice(0, current.length - 1));
    }
  };

  const handleOpenSubfolder = (item: ItemRow) => {
    if (item.kind === "directory" || item.kind === "reparse_point") {
      setTableScopePath((current) => [...current, { id: item.id, name: item.name }]);
    }
  };

  const handleDeleteItem = async (item: ItemRow) => {
    if (!desktopRuntime) {
      setItems((prev) => prev.filter((i) => i.id !== item.id));
      setDeleteConfirmItem(null);
      return;
    }
    setIsDeleting(true);
    try {
      await invoke<boolean>("delete_file_item", { path: item.display_path });
      setItems((prev) => prev.filter((i) => i.id !== item.id));
      if (selectedItem?.id === item.id) setSelectedItem(null);
      setDeleteNotice(`Successfully deleted ${item.name}`);
      setTimeout(() => setDeleteNotice(null), 3500);
    } catch (err) {
      setDeleteNotice(`Failed to delete: ${String(err)}`);
      setTimeout(() => setDeleteNotice(null), 5000);
    } finally {
      setIsDeleting(false);
      setDeleteConfirmItem(null);
    }
  };

  const handleTreemapNavigateUp = () => {
    if (treemapScopePath.length > 1) {
      setTreemapScopePath((current) => current.slice(0, current.length - 1));
    }
  };

  useEffect(() => {
    window.localStorage.setItem("clutterhunter:dock-open", String(dockOpen));
  }, [dockOpen]);

  useEffect(() => {
    if (!desktopRuntime) return;

    void invoke<ScanTarget[]>("list_scan_targets")
      .then((availableTargets) => {
        if (availableTargets.length === 0) return;
        setTargets(availableTargets);
        setSelectedTargetId(availableTargets[0].id);
      })
      .catch(() => setTargets([browserTarget]));
  }, []);

  const selectedTarget = useMemo(
    () => targets.find((target) => target.id === selectedTargetId) ?? targets[0],
    [selectedTargetId, targets],
  );
  const metricLabel = metric === "allocated" ? "Allocated" : "Logical";
  const visibleExtensions = useMemo(
    () => new Set(items.map((item) => item.extension).filter(Boolean)).size,
    [items],
  );
  const visibleItems = useMemo(() => {
    const query = searchQuery.trim().toLocaleLowerCase();
    if (!query) return items;
    return items.filter((item) =>
      item.name.toLocaleLowerCase().includes(query)
      || item.display_path.toLocaleLowerCase().includes(query),
    );
  }, [items, searchQuery]);
  const allocatedValue = summary?.allocated_bytes ?? progress?.bytes_accounted ?? "0";
  const itemValue = summary?.entry_count ?? progress?.entries_seen ?? "0";
  const statusText = getStatusText(scanStatus, progress, summary, scanError);
  const preferredBackend: ScanRequest["preferred_backend"] =
    selectedTarget?.fast_scan_available && !useTraversalFallback ? "raw_ntfs" : "traversal";
  const backendLabel = preferredBackend === "raw_ntfs" ? "MFT fast scan" : "traversal";

  const selectTarget = (targetId: string) => {
    setSelectedTargetId(targetId);
    setProgress(null);
    setSummary(null);
    setItems([]);
    setSelectedItem(null);
    setSearchQuery("");
    setScanError(null);
    setScanStatus("idle");
    setUseTraversalFallback(false);
  };

  const startOrCancelScan = async () => {
    if (!desktopRuntime) return;
    if (scanStatus === "scanning" || scanStatus === "cancelling") {
      setScanStatus("cancelling");
      await invoke<boolean>("cancel_scan");
      return;
    }
    if (!selectedTarget) return;

    setScanStatus("scanning");
    setProgress(null);
    setSelectedItem(null);
    setScanError(null);
    const onProgress = new Channel<ScanProgress>();
    onProgress.onmessage = (update) => setProgress(update);
    const request: ScanRequest = {
      target: selectedTarget,
      preferred_backend: preferredBackend,
    };

    try {
      const nextSummary = await invoke<ScanSummary>("start_scan", { request, onProgress });
      const query: ItemQuery = {
        parent_id: null,
        sort: "allocated",
        direction: "desc",
        cursor: null,
        limit: 100,
      };
      const page = await invoke<ItemPage>("query_items", {
        sessionId: nextSummary.session_id,
        query,
      });
      setSummary(nextSummary);
      setItems(page.items);
      setScanStatus("complete");
    } catch (error) {
      const failure = normalizeFailure(error);
      setScanError(failure);
      if (
        preferredBackend === "raw_ntfs"
        && failure.recoverable
        && failure.code !== "SCAN_CANCELLED"
      ) {
        setUseTraversalFallback(true);
      }
      setScanStatus(failure.code === "SCAN_CANCELLED" ? "idle" : "error");
    }
  };

  return (
    <main className={dockOpen ? "app-shell" : "app-shell dock-collapsed"}>
      <header className="topbar">
        <div className="brand" aria-label="ClutterHunter">
          <span className="brand-mark"><ListTree size={18} /></span>
          <strong>ClutterHunter</strong>
        </div>

        <div className="target-control">
          <HardDrive size={16} aria-hidden="true" />
          <select
            aria-label="Scan target"
            value={selectedTargetId}
            disabled={scanStatus === "scanning" || scanStatus === "cancelling"}
            onChange={(event) => selectTarget(event.target.value)}
          >
            {targets.map((target) => (
              <option key={target.id} value={target.id}>{target.display_path}</option>
            ))}
          </select>
          <span className="target-meta">
            {selectedTarget?.filesystem ?? "Unknown FS"} · {backendLabel}
          </span>
        </div>

        <button
          className="scan-button"
          type="button"
          disabled={!desktopRuntime || scanStatus === "cancelling"}
          title={desktopRuntime
            ? preferredBackend === "raw_ntfs"
              ? "Run the read-only MFT scanner (Windows will request access)"
              : scanError
                ? `Use traversal after ${scanError.code}`
                : "Run the read-only traversal scanner"
            : "Open the Tauri desktop app to scan"}
          onClick={() => void startOrCancelScan()}
        >
          {scanStatus === "scanning" || scanStatus === "cancelling"
            ? <Square size={14} fill="currentColor" />
            : <Play size={16} fill="currentColor" />}
          {scanStatus === "cancelling"
            ? "Cancelling"
            : scanStatus === "scanning"
              ? "Cancel"
              : scanStatus === "error" && useTraversalFallback
                ? "Use traversal"
                : summary
                  ? "Rescan"
                  : "Scan"}
        </button>
        {(scanStatus === "scanning" || scanStatus === "cancelling") && (
          <span className="scan-progress-rail" aria-hidden="true"><span /></span>
        )}

        <div className="topbar-spacer" />

        <div className={`status-indicator status-${scanStatus}`} aria-label="Scanner status">
          <span className="status-dot" />
          {statusText}
        </div>

        <button
          className="icon-button"
          type="button"
          title={dockOpen ? "Close AI dock" : "Open AI dock"}
          aria-label={dockOpen ? "Close AI dock" : "Open AI dock"}
          onClick={() => setDockOpen((open) => !open)}
        >
          {dockOpen ? <PanelRightClose size={18} /> : <PanelRightOpen size={18} />}
        </button>
      </header>

      <section className="summary-strip" aria-label="Storage summary">
        <div className="summary-primary">
          <span className="summary-label">Target</span>
          <strong>{selectedTarget?.display_path ?? "No target"}</strong>
        </div>
        <div><span className="summary-label">Allocated</span><strong>{formatBytes(allocatedValue)}</strong></div>
        <div><span className="summary-label">Items</span><strong>{formatCount(itemValue)}</strong></div>
        <div><span className="summary-label">Candidates</span><strong>0 B</strong></div>
        <div className="summary-health">
          <ShieldCheck size={17} />
          <span><strong>Read only</strong><small>{summary ? coverageLabel(summary) : "No changes"}</small></span>
        </div>
      </section>

      <section className="workspace">
        <div className="analyzer-pane">
          <div className="analyzer-toolbar flex flex-wrap items-center justify-between gap-2 p-2 bg-[#181818] border-b border-[#2d2d2d]">
            <div className="breadcrumb flex items-center gap-1 text-xs text-[#cccccc]" aria-label="Current directory location">
              {tableScopePath.length > 1 && (
                <button
                  type="button"
                  className="p-1 hover:bg-[#2a2a2a] rounded text-[#8ce1cb] transition-colors"
                  title="Navigate up to parent directory"
                  onClick={handleTableNavigateUp}
                >
                  <ChevronLeft size={14} />
                </button>
              )}
              <HardDrive size={14} className="text-[#8ce1cb]" />
              <span className="font-medium">{selectedTarget?.display_path ?? "Computer"}</span>
              {tableScopePath.slice(1).map((crumb, idx) => (
                <span key={crumb.id ?? idx} className="flex items-center gap-1">
                  <ChevronRight size={12} className="text-[#666666]" />
                  <button
                    type="button"
                    onClick={() => setTableScopePath((prev) => prev.slice(0, idx + 2))}
                    className="hover:text-[#8ce1cb] hover:underline transition-colors cursor-pointer"
                  >
                    {crumb.name}
                  </button>
                </span>
              ))}
            </div>

            {deleteNotice && (
              <div className="text-[11px] px-2.5 py-1 rounded bg-[#25382e] text-[#a8f0d0] border border-[#3b5947] animate-pulse">
                {deleteNotice}
              </div>
            )}

            <div className="flex items-center gap-2">
              <label className="search-control">
                <Search size={15} />
                <input
                  aria-label="Search storage items"
                  placeholder="Filter visible items"
                  value={searchQuery}
                  onChange={(event) => setSearchQuery(event.target.value)}
                />
              </label>
              <div className="segmented-control" aria-label="Size metric">
                <button type="button" aria-pressed={metric === "allocated"} className={metric === "allocated" ? "active" : ""} onClick={() => setMetric("allocated")}>Allocated</button>
                <button type="button" aria-pressed={metric === "logical"} className={metric === "logical" ? "active" : ""} onClick={() => setMetric("logical")}>Logical</button>
              </div>
            </div>
          </div>

          <div className="analyzer-grid">
            <section className="table-panel" aria-label="Storage hierarchy">
              <div className="table-header table-row">
                <span className="name-cell"><Columns3 size={14} /> Name</span>
                <span>{metricLabel}</span><span>Percent</span><span>Modified</span><span>Action</span>
              </div>
              <div className="empty-table">
                {visibleItems.length > 0 ? visibleItems.map((item) => (
                  <div
                    className={`table-row data-row group ${selectedItem?.id === item.id ? "selected" : ""}`}
                    key={item.id}
                    role="button"
                    tabIndex={0}
                    aria-pressed={selectedItem?.id === item.id}
                    onClick={() => setSelectedItem((current) => current?.id === item.id ? null : item)}
                    onDoubleClick={() => handleOpenSubfolder(item)}
                    onMouseEnter={(event) => {
                      setHoveredItem(item);
                      setHoverAnchor(event.currentTarget.getBoundingClientRect());
                    }}
                    onMouseLeave={() => {
                      setHoveredItem(null);
                      setHoverAnchor(null);
                    }}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        if (item.kind === "directory") {
                          handleOpenSubfolder(item);
                        } else {
                          setSelectedItem((current) => current?.id === item.id ? null : item);
                        }
                      }
                    }}
                  >
                    <span className="name-cell item-name" title={`${item.display_path} (Double-click to open)`}>
                      {item.kind === "directory" ? <Folder size={15} className="text-[#e3b341]" /> : item.kind === "reparse_point" ? <Link2 size={15} className="text-[#8ce1cb]" /> : <File size={15} className="text-[#a0a5aa]" />}
                      <span className="truncate">{item.name}</span>
                      {item.kind === "directory" && (
                        <button
                          type="button"
                          onClick={(e) => { e.stopPropagation(); handleOpenSubfolder(item); }}
                          className="opacity-0 group-hover:opacity-100 p-0.5 hover:bg-[#333333] text-[#8ce1cb] rounded transition-opacity"
                          title="Open subfolder"
                        >
                          <FolderInput size={13} />
                        </button>
                      )}
                    </span>
                    <span>{formatBytes(metric === "allocated" ? item.allocated_bytes : item.logical_bytes)}</span>
                    <span className="percent-cell">
                      <span className="percent-track" aria-hidden="true"><span style={{ width: percentWidth(item, summary, metric) }} /></span>
                      <span>{formatPercent(item, summary, metric)}</span>
                    </span>
                    <span>{formatModified(item.modified_at_ms)}</span>
                    <span className="flex items-center gap-1">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setDeleteConfirmItem(item);
                        }}
                        className="p-1 hover:bg-[#4a1c1d] hover:text-[#ff8080] text-[#888888] rounded transition-colors"
                        title={`Delete ${item.kind === "directory" ? "folder" : "file"}`}
                      >
                        <Trash2 size={13} />
                      </button>
                    </span>
                  </div>
                )) : emptyRows.map((row) => (
                  <div className="table-row skeleton-row" key={row} aria-hidden="true">
                    <span className="skeleton skeleton-name" /><span className="skeleton skeleton-value" />
                    <span className="skeleton skeleton-short" /><span className="skeleton skeleton-value" />
                    <span className="skeleton skeleton-short" />
                  </div>
                ))}
                {visibleItems.length === 0 && (
                  <div className="empty-state">
                    {scanStatus === "scanning" || scanStatus === "cancelling" ? <LoaderCircle className="spin" size={22} /> : <Database size={22} />}
                    <strong>{searchQuery ? "No visible items match" : scanError?.detail ?? (scanStatus === "scanning" ? "Scanning filesystem" : "Awaiting scan")}</strong>
                    <span>{searchQuery ? "Adjust the filter to continue" : `${formatCount(progress?.entries_seen ?? "0")} indexed items`}</span>
                  </div>
                )}
              </div>

              {hoveredItem && (
                <HoverAIInsightCard
                  item={hoveredItem}
                  anchorRect={hoverAnchor}
                  selectedModelName={window.localStorage.getItem("clutterhunter:ollama-model") ?? undefined}
                />
              )}
            </section>

            <aside className="extension-panel" aria-label="Extension summary">
              <div className="panel-title"><span>Visible types</span><CircleGauge size={15} /></div>
              <div className="extension-empty">
                {['#2f7d73', '#d87b52', '#5b78b8', '#c39b3d', '#7f68a8'].map((color) => <span key={color} style={{ backgroundColor: color }} />)}
              </div>
              <div className="extension-zero"><strong>{visibleExtensions}</strong><span>types</span></div>
            </aside>

            <section className="treemap-panel" aria-label="Storage treemap">
              <div className="panel-title">
                <div className="breadcrumb" aria-label="Treemap location">
                  {treemapScopePath.length > 1 && (
                    <button
                      type="button"
                      className="icon-button compact"
                      title="Navigate up to parent directory"
                      onClick={handleTreemapNavigateUp}
                      style={{ width: 22, height: 22, padding: 0, marginRight: 4 }}
                    >
                      <ChevronLeft size={14} />
                    </button>
                  )}
                  <span>{treemapScopePath.map((s) => s.name).join(" / ")}</span>
                </div>
                <span className="metric-caption">{metricLabel} size</span>
              </div>
              {treemapNodes.length > 0 ? (
                <TreemapCanvas
                  nodes={treemapNodes}
                  selectedId={selectedItem?.id ?? null}
                  onSelect={(node) => setSelectedItem(treemapNodeToItemRow(node))}
                  onOpen={(node) => {
                    if (node.kind === "directory" && !node.synthetic) {
                      setTreemapScopePath((current) => [...current, { id: node.id, name: node.name }]);
                    }
                  }}
                  onHoverItem={(node, rect) => {
                    setHoveredItem(node ? treemapNodeToItemRow(node) : null);
                    setHoverAnchor(rect);
                  }}
                  formatBytes={formatBytes}
                />
              ) : (
                <>
                  <div className="treemap-empty" aria-hidden="true">
                    <span className="treemap-block block-a" />
                    <span className="treemap-block block-b" />
                    <span className="treemap-block block-c" />
                    <span className="treemap-block block-d" />
                    <span className="treemap-block block-e" />
                  </div>
                  <div className="treemap-status">
                    <FolderOpen size={19} />
                    <span>{summary ? "Loading interactive treemap..." : "Run a scan to view Treemap"}</span>
                  </div>
                </>
              )}
            </section>
          </div>
        </div>

        <Suspense fallback={null}>
          <AgentDock
            desktopRuntime={desktopRuntime}
            hidden={!dockOpen}
            summary={summary}
            attachment={selectedItem}
            onClearAttachment={() => setSelectedItem(null)}
          />
        </Suspense>
      </section>
      {deleteConfirmItem && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-[#1c221e] border border-[#3b4c42] rounded-lg shadow-2xl p-5 max-w-md w-full flex flex-col gap-4 text-xs text-[#e0ede6]">
            <div className="flex items-center gap-2 text-[#ff8080] font-semibold text-sm">
              <Trash2 size={18} />
              <span>Confirm Permanent Deletion</span>
            </div>
            <p className="text-[#a0b3a8] leading-relaxed">
              Are you sure you want to delete <strong className="text-white">{deleteConfirmItem.name}</strong>?
            </p>
            <div className="bg-[#121614] p-2.5 rounded border border-[#26332c] font-mono text-[11px] text-[#8ce1cb] truncate">
              Path: {deleteConfirmItem.display_path}
            </div>
            <div className="flex items-center justify-end gap-2 mt-2">
              <button
                type="button"
                disabled={isDeleting}
                onClick={() => setDeleteConfirmItem(null)}
                className="px-3 py-1.5 rounded bg-[#27332c] hover:bg-[#34443b] text-[#c5dbd0] transition-colors cursor-pointer disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={isDeleting}
                onClick={() => handleDeleteItem(deleteConfirmItem)}
                className="px-3 py-1.5 rounded bg-[#b91c1c] hover:bg-[#dc2626] text-white font-medium transition-colors cursor-pointer flex items-center gap-1.5 disabled:opacity-50"
              >
                {isDeleting ? "Deleting..." : "Delete Item"}
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

function normalizeFailure(error: unknown): ScanFailure {
  if (error && typeof error === "object" && "code" in error && "detail" in error) {
    return error as ScanFailure;
  }
  return { code: "SCAN_FAILED", detail: String(error), recoverable: true };
}

function getStatusText(status: ScanStatus, progress: ScanProgress | null, summary: ScanSummary | null, error: ScanFailure | null) {
  if (status === "scanning" || status === "cancelling") return status === "cancelling" ? "Stopping scan" : phaseLabel(progress?.phase);
  if (status === "complete" && summary) return `${formatBackend(summary.backend)} · ${formatDuration(summary.elapsed_ms)}`;
  if (status === "error") return error?.code ?? "Scan failed";
  return desktopRuntime ? "Scanner ready" : "Desktop preview";
}

function phaseLabel(phase: ScanProgress["phase"] | undefined) {
  if (!phase) return "Preparing scan";
  return ({ preparing: "Preparing scan", elevating: "Requesting access", enumerating: "Enumerating", indexing: "Building index", classifying: "Classifying", finalizing: "Finalizing" })[phase];
}

function formatBytes(value: string | null | undefined) {
  let bytes: bigint;
  try { bytes = BigInt(value ?? "0"); } catch { return "0 B"; }
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let divisor = 1n;
  let unit = 0;
  while (unit < units.length - 1 && bytes >= divisor * 1024n) { divisor *= 1024n; unit += 1; }
  if (unit === 0) return `${bytes} B`;
  const tenths = (bytes * 10n) / divisor;
  return `${tenths / 10n}.${tenths % 10n} ${units[unit]}`;
}

function formatCount(value: string) {
  const number = Number(value);
  return Number.isFinite(number) ? new Intl.NumberFormat().format(number) : value;
}

function formatDuration(value: string) {
  const milliseconds = Number(value);
  return milliseconds < 1000 ? `${milliseconds} ms` : `${(milliseconds / 1000).toFixed(1)} s`;
}

function formatModified(value: string | null) {
  if (!value) return "—";
  const date = new Date(Number(value));
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleDateString();
}

function formatPercent(item: ItemRow, summary: ScanSummary | null, metric: Metric) {
  if (!summary) return "0%";
  const value = BigInt(metric === "allocated" ? item.allocated_bytes : item.logical_bytes);
  const total = BigInt(metric === "allocated" ? summary.allocated_bytes : summary.logical_bytes);
  if (total === 0n) return "0%";
  const tenths = (value * 1000n) / total;
  return `${tenths / 10n}.${tenths % 10n}%`;
}

function percentWidth(item: ItemRow, summary: ScanSummary | null, metric: Metric) {
  if (!summary) return "0%";
  const value = BigInt(metric === "allocated" ? item.allocated_bytes : item.logical_bytes);
  const total = BigInt(metric === "allocated" ? summary.allocated_bytes : summary.logical_bytes);
  if (total === 0n) return "0%";
  const thousandths = (value * 100_000n) / total;
  const bounded = thousandths > 100_000n ? 100_000n : thousandths;
  return `${Number(bounded) / 1000}%`;
}

function coverageLabel(summary: ScanSummary) {
  if (summary.coverage === "partial") return "Partial coverage";
  if (summary.coverage === "potentially_stale") return "Potentially stale";
  return summary.backend === "raw_ntfs" ? "Complete MFT index" : "Complete traversal";
}

function formatBackend(backend: ScanSummary["backend"]) {
  return backend === "raw_ntfs" ? "MFT" : "Traversal";
}

export default App;
