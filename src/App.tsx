import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { Channel, invoke, isTauri } from "@tauri-apps/api/core";
import {
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
} from "lucide-react";
import type { ItemPage } from "./bindings/ItemPage";
import type { ItemQuery } from "./bindings/ItemQuery";
import type { ItemRow } from "./bindings/ItemRow";
import type { ScanFailure } from "./bindings/ScanFailure";
import type { ScanProgress } from "./bindings/ScanProgress";
import type { ScanRequest } from "./bindings/ScanRequest";
import type { ScanSummary } from "./bindings/ScanSummary";
import type { ScanTarget } from "./bindings/ScanTarget";
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
  const [scanError, setScanError] = useState<ScanFailure | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [useTraversalFallback, setUseTraversalFallback] = useState(false);

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
          <div className="analyzer-toolbar">
            <div className="breadcrumb" aria-label="Current location">
              <HardDrive size={15} />
              <span>{selectedTarget?.display_path ?? "Computer"}</span>
              <ChevronRight size={14} />
            </div>
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

          <div className="analyzer-grid">
            <section className="table-panel" aria-label="Storage hierarchy">
              <div className="table-header table-row">
                <span className="name-cell"><Columns3 size={14} /> Name</span>
                <span>{metricLabel}</span><span>Percent</span><span>Modified</span><span>Policy</span>
              </div>
              <div className="empty-table">
                {visibleItems.length > 0 ? visibleItems.map((item) => (
                  <div
                    className={`table-row data-row ${selectedItem?.id === item.id ? "selected" : ""}`}
                    key={item.id}
                    role="button"
                    tabIndex={0}
                    aria-pressed={selectedItem?.id === item.id}
                    onClick={() => setSelectedItem((current) => current?.id === item.id ? null : item)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        setSelectedItem((current) => current?.id === item.id ? null : item);
                      }
                    }}
                  >
                    <span className="name-cell item-name" title={item.display_path}>
                      {item.kind === "directory" ? <Folder size={15} /> : item.kind === "reparse_point" ? <Link2 size={15} /> : <File size={15} />}
                      <span>{item.name}</span>
                    </span>
                    <span>{formatBytes(metric === "allocated" ? item.allocated_bytes : item.logical_bytes)}</span>
                    <span className="percent-cell">
                      <span className="percent-track" aria-hidden="true"><span style={{ width: percentWidth(item, summary, metric) }} /></span>
                      <span>{formatPercent(item, summary, metric)}</span>
                    </span>
                    <span>{formatModified(item.modified_at_ms)}</span>
                    <span className="policy-pending">Pending</span>
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
            </section>

            <aside className="extension-panel" aria-label="Extension summary">
              <div className="panel-title"><span>Visible types</span><CircleGauge size={15} /></div>
              <div className="extension-empty">
                {['#2f7d73', '#d87b52', '#5b78b8', '#c39b3d', '#7f68a8'].map((color) => <span key={color} style={{ backgroundColor: color }} />)}
              </div>
              <div className="extension-zero"><strong>{visibleExtensions}</strong><span>types</span></div>
            </aside>

            <section className="treemap-panel" aria-label="Storage treemap">
              <div className="panel-title"><span>Treemap</span><span className="metric-caption">{metricLabel} size</span></div>
              <div className="treemap-empty" aria-hidden="true">
                <span className="treemap-block block-a" /><span className="treemap-block block-b" />
                <span className="treemap-block block-c" /><span className="treemap-block block-d" /><span className="treemap-block block-e" />
              </div>
              <div className="treemap-status"><FolderOpen size={19} /><span>{summary ? "Bounded treemap query is the next analyzer slice" : "No indexed allocation"}</span></div>
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
