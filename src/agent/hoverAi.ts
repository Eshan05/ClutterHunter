import type { ItemRow } from "../bindings/ItemRow";

const insightCache = new Map<string, string>();

/**
 * Deterministic fast insights based on Windows file rules, extensions, policy tiers, and names.
 */
export function getDeterministicInsight(item: ItemRow): string {
  const pathLower = item.display_path.toLocaleLowerCase();
  const nameLower = item.name.toLocaleLowerCase();
  const extLower = (item.extension ?? "").toLocaleLowerCase();
  const tier = item.policy.tier;

  // Specific system folders
  if (pathLower.includes("\\winsxs")) {
    return "Windows Component Store (WinSxS). Contains critical OS assemblies required for system stability and servicing.";
  }
  if (pathLower.includes("\\system volume information")) {
    return "Windows System Restore point and Volume Shadow Copy store. Protected by system access policies.";
  }
  if (pathLower.includes("\\$recycle.bin")) {
    return "Windows Recycle Bin directory. Contains deleted files queued for permanent removal.";
  }
  if (pathLower.includes("\\program files") || pathLower.includes("\\program files (x86)")) {
    return "Installed system binary directory. Contains core application executables and libraries.";
  }
  if (pathLower.includes("\\windows\\system32") || pathLower.includes("\\windows\\syswow64")) {
    return "Essential Windows OS kernel binaries and core drivers. Highly protected system files.";
  }

  // Developer & Cache folders
  if (nameLower === "node_modules" || pathLower.includes("\\node_modules\\")) {
    return "Node.js dependency package tree. High reclaimability candidate if project is inactive.";
  }
  if (nameLower === ".git" || pathLower.includes("\\.git\\")) {
    return "Git version control repository index and object store. Do not remove active source code history.";
  }
  if (nameLower === "target" && pathLower.includes("cargo")) {
    return "Rust Cargo build target artifacts directory. Safe to clean using cargo clean.";
  }
  if (nameLower === ".venv" || nameLower === "venv" || nameLower === "__pycache__") {
    return "Python virtual environment or bytecode cache directory. Safe to regenerate.";
  }
  if (pathLower.includes("\\appdata\\local\\temp") || pathLower.includes("\\temp\\") || nameLower === "temp") {
    return "Temporary application working directory. Prime candidate for non-destructive cleanup.";
  }
  if (pathLower.includes("\\appdata\\local\\npm-cache") || pathLower.includes(".pnpm-store")) {
    return "Package manager global cache store. Safe to purge via package manager cleanup CLI.";
  }
  if (pathLower.includes("\\appdata\\local\\google\\chrome") || pathLower.includes("\\appdata\\local\\microsoft\\edge")) {
    return "Web browser profile and disk cache storage. Contains user browsing cache and data.";
  }

  // Extensions
  if (extLower === ".log" || extLower === ".etl") {
    return "Diagnostic event log file. Safe to compress or remove if disk space is low.";
  }
  if (extLower === ".tmp" || extLower === ".bak" || extLower === ".old") {
    return "Stale temporary or backup file. Low risk cleanup candidate.";
  }
  if (extLower === ".iso" || extLower === ".vhd" || extLower === ".vhdx" || extLower === ".img") {
    return "Large virtual disk image or disk installer. High storage impact item.";
  }
  if (extLower === ".exe" || extLower === ".msi") {
    return "Executable application or installer package.";
  }
  if (extLower === ".sys" || extLower === ".dll" || extLower === ".drv") {
    return "System module or dynamic link library runtime file.";
  }
  if (extLower === ".zip" || extLower === ".tar" || extLower === ".gz" || extLower === ".7z" || extLower === ".rar") {
    return "Compressed archive file. Check contents before extracting or removing.";
  }

  // Policy tier defaults
  if (tier === "protected") {
    return "Protected System Resource. Restricted access to prevent operating system instability.";
  }
  if (tier === "review_required") {
    return "Review Required Tier. Item may belong to user data or application state; verify before cleanup.";
  }
  if (tier === "user_cleanable") {
    return "User Cleanable Tier. Identified as non-essential data candidate suitable for space reclamation.";
  }

  if (item.kind === "directory") {
    return `Directory containing indexed file assets. Allocated size: ${formatBytes(item.allocated_bytes)}.`;
  }

  return `Storage item asset. Path: ${item.display_path}`;
}

/**
 * Fast AI generation / retrieval for a hovered item.
 */
export async function getHoverAiInsight(
  item: ItemRow,
  selectedModelName?: string,
  signal?: AbortSignal,
): Promise<string> {
  if (insightCache.has(item.id)) {
    return insightCache.get(item.id)!;
  }

  const fallback = getDeterministicInsight(item);

  // If no model or signal already aborted, return deterministic immediately
  if (!selectedModelName || signal?.aborted) {
    insightCache.set(item.id, fallback);
    return fallback;
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 1800); // 1.8s timeout for hover speed
    const combinedSignal = signal
      ? AbortSignal.any([signal, controller.signal])
      : controller.signal;

    const response = await fetch("http://127.0.0.1:11434/api/chat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      signal: combinedSignal,
      body: JSON.stringify({
        model: selectedModelName,
        messages: [
          {
            role: "system",
            content: "You are ClutterHunter private local AI. Provide a 1-sentence analysis of the given file/folder item: what it is and cleanup/safety recommendation. No markdown header, no bullet points, be direct and concise.",
          },
          {
            role: "user",
            content: `Item: "${item.name}" | Path: "${item.display_path}" | Kind: ${item.kind} | Size: ${formatBytes(item.allocated_bytes)} | Extension: ${item.extension ?? "none"} | Policy: ${item.policy.tier}`,
          },
        ],
        stream: false,
        options: {
          num_predict: 48,
          temperature: 0.1,
        },
      }),
    });

    clearTimeout(timer);

    if (response.ok) {
      const data = (await response.json()) as { message?: { content?: string } };
      const text = data.message?.content?.trim();
      if (text && text.length > 5) {
        // Clean up text
        const cleaned = text.replace(/^["'\s]+|["'\s]+$/g, "").replace(/\n+/g, " ");
        insightCache.set(item.id, cleaned);
        return cleaned;
      }
    }
  } catch {
    // Ignore error, fallback to deterministic insight
  }

  insightCache.set(item.id, fallback);
  return fallback;
}

function formatBytes(value: string | number) {
  let bytes: bigint;
  try {
    bytes = BigInt(value);
  } catch {
    return "0 B";
  }
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
