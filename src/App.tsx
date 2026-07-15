import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { Channel, invoke, isTauri } from "@tauri-apps/api/core";
import {
  HardDrive,
  ListTree,
  PanelRightClose,
  PanelRightOpen,
  Play,
  ShieldCheck,
  Square,
} from "lucide-react";
import { AnalyzerWorkspace, type AnalyzerMetric, type AnalyzerScanStatus } from "./AnalyzerWorkspace";
import type { ItemRow } from "./bindings/ItemRow";
import type { ScanFailure } from "./bindings/ScanFailure";
import type { ScanProgress } from "./bindings/ScanProgress";
import type { ScanRequest } from "./bindings/ScanRequest";
import type { ScanSummary } from "./bindings/ScanSummary";
import type { ScanTarget } from "./bindings/ScanTarget";
import type { StorageAggregate } from "./bindings/StorageAggregate";
import "./App.css";

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
function App() {
  const [targets, setTargets] = useState<ScanTarget[]>([browserTarget]);
  const [selectedTargetId, setSelectedTargetId] = useState(browserTarget.id);
  const [metric, setMetric] = useState<AnalyzerMetric>("allocated");
  const [dockOpen, setDockOpen] = useState(
    () => window.localStorage.getItem("clutterhunter:dock-open") !== "false",
  );
  const [scanStatus, setScanStatus] = useState<AnalyzerScanStatus>("idle");
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [selectedItem, setSelectedItem] = useState<ItemRow | null>(null);
  const [scanError, setScanError] = useState<ScanFailure | null>(null);
  const [candidateBytes, setCandidateBytes] = useState<string | null | undefined>(undefined);
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
  const allocatedValue = summary?.allocated_bytes ?? progress?.bytes_accounted ?? "0";
  const itemValue = summary?.entry_count ?? progress?.entries_seen ?? "0";
  const statusText = getStatusText(scanStatus, progress, summary, scanError);
  const preferredBackend: ScanRequest["preferred_backend"] =
    selectedTarget?.fast_scan_available && !useTraversalFallback ? "raw_ntfs" : "traversal";
  const backendLabel = preferredBackend === "raw_ntfs" ? "MFT fast scan" : "traversal";

  useEffect(() => {
    if (!desktopRuntime || !summary) {
      setCandidateBytes(undefined);
      return;
    }
    let active = true;
    setCandidateBytes(null);
    void invoke<StorageAggregate>("get_storage_aggregate", {
      sessionId: summary.session_id,
      query: { scope_id: null, dimension: "policy", limit: 3 },
    }).then((aggregate) => {
      if (active) setCandidateBytes(
        aggregate.buckets.find((bucket) => bucket.key === "cleanup_candidate")?.allocated_bytes ?? "0",
      );
    }).catch(() => {
      if (active) setCandidateBytes(undefined);
    });
    return () => { active = false; };
  }, [summary]);

  const selectTarget = (targetId: string) => {
    setSelectedTargetId(targetId);
    setProgress(null);
    setSummary(null);
    setSelectedItem(null);
    setCandidateBytes(undefined);
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
      setCandidateBytes(null);
      setSummary(nextSummary);
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
        <div><span className="summary-label">Candidates</span><strong>{summary ? candidateBytes === null ? "..." : candidateBytes === undefined ? "—" : formatBytes(candidateBytes) : "0 B"}</strong></div>
        <div className="summary-health">
          <ShieldCheck size={17} />
          <span><strong>Read only</strong><small>{summary ? coverageLabel(summary) : "No changes"}</small></span>
        </div>
      </section>

      <section className="workspace">
        <AnalyzerWorkspace
          summary={summary}
          progress={progress}
          scanStatus={scanStatus}
          scanError={scanError}
          metric={metric}
          onMetricChange={setMetric}
          onSelectionChange={setSelectedItem}
        />

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

function getStatusText(status: AnalyzerScanStatus, progress: ScanProgress | null, summary: ScanSummary | null, error: ScanFailure | null) {
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

function coverageLabel(summary: ScanSummary) {
  if (summary.coverage === "partial") return "Partial coverage";
  if (summary.coverage === "potentially_stale") return "Potentially stale";
  return summary.backend === "raw_ntfs" ? "Complete MFT index" : "Complete traversal";
}

function formatBackend(backend: ScanSummary["backend"]) {
  return backend === "raw_ntfs" ? "MFT" : "Traversal";
}

export default App;
