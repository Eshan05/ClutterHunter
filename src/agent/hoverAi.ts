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

  // Server stacks & Development tools
  if (nameLower === "xampp" || pathLower.includes("\\xampp\\") || nameLower === "wamp" || pathLower.includes("\\wamp64\\")) {
    return "Local web development stack (Apache, MySQL, PHP). Stores web application files in htdocs and database storage in mysql/data.";
  }
  if (nameLower === "htdocs" || nameLower === "www") {
    return "Web server root root directory. Contains local website source files and assets.";
  }
  if (nameLower === "docker" || pathLower.includes("\\.docker\\")) {
    return "Docker container data store. Contains virtual machine disks, container layers, and image caches.";
  }
  if (nameLower === "virtualbox vms" || pathLower.includes("\\virtualbox\\")) {
    return "VirtualBox machine images directory. Large VDI/VMDK virtual disks store virtualized OS environments.";
  }

  // Specific system & OS folders
  if (pathLower.includes("\\winsxs")) {
    return "Windows Component Store (WinSxS). Contains OS assemblies required for system servicing and updates.";
  }
  if (pathLower.includes("\\system volume information")) {
    return "Windows System Volume Information. Stores system restore checkpoints and volume shadow copies.";
  }
  if (pathLower.includes("\\$recycle.bin")) {
    return "Windows Recycle Bin directory containing queued deleted files awaiting permanent purge.";
  }
  if (pathLower.includes("\\program files") || pathLower.includes("\\program files (x86)")) {
    return "Software Application installation directory. Contains application binaries and shared runtime libraries.";
  }
  if (pathLower.includes("\\windows\\system32") || pathLower.includes("\\windows\\syswow64")) {
    return "Essential Windows System binary directory containing core OS kernel executables and system drivers.";
  }
  if (pathLower.includes("\\windows")) {
    return "Windows Operating System root directory. Core OS system files and configuration resources.";
  }

  // Developer, Cache & Hidden Data
  if (nameLower === "node_modules" || pathLower.includes("\\node_modules\\")) {
    return "Node.js dependency package tree. High reclaimability candidate if project is inactive.";
  }
  if (nameLower === ".git" || pathLower.includes("\\.git\\")) {
    return "Git version control repository index and object history store.";
  }
  if (nameLower === "target" && (pathLower.includes("cargo") || pathLower.includes("rust"))) {
    return "Rust Cargo build target artifacts store. Reclaim space via 'cargo clean'.";
  }
  if (nameLower === ".venv" || nameLower === "venv" || nameLower === "__pycache__") {
    return "Python virtual environment or compiled bytecode cache folder.";
  }
  if (pathLower.includes("\\appdata\\local\\temp") || pathLower.includes("\\temp") || nameLower === "temp" || nameLower === "tmp") {
    return "Temporary working directory. Prime candidate for non-destructive disk space reclamation.";
  }
  if (pathLower.includes("\\appdata\\local\\npm-cache") || pathLower.includes(".pnpm-store")) {
    return "Package manager global cache store. Safe to purge via package manager CLI.";
  }
  if (pathLower.includes("\\appdata\\local\\google\\chrome") || pathLower.includes("\\appdata\\local\\microsoft\\edge")) {
    return "Web browser profile and offline disk cache directory.";
  }
  if (pathLower.includes("\\appdata\\local") || pathLower.includes("\\appdata\\roaming")) {
    return "Application Data directory containing program configuration, local state, and application logs.";
  }

  // Extensions & Hidden Files
  if (nameLower.startsWith(".") || item.attributes?.includes("hidden")) {
    return "Hidden configuration or system asset file.";
  }
  if (extLower === ".log" || extLower === ".etl") {
    return "Diagnostic log file. Safe to archive or remove if disk space is needed.";
  }
  if (extLower === ".tmp" || extLower === ".bak" || extLower === ".old") {
    return "Temporary or legacy backup file. Excellent space reclamation candidate.";
  }
  if (extLower === ".iso" || extLower === ".vhd" || extLower === ".vhdx" || extLower === ".img") {
    return "Large virtual disk image or OS installer. Significant disk space impact.";
  }
  if (extLower === ".exe" || extLower === ".msi") {
    return "Executable application software or system installation package.";
  }
  if (extLower === ".sys" || extLower === ".dll" || extLower === ".drv") {
    return "System module runtime library or hardware driver resource.";
  }
  if (extLower === ".zip" || extLower === ".tar" || extLower === ".gz" || extLower === ".7z" || extLower === ".rar") {
    return "Compressed archive file containing packaged files.";
  }

  // Policy tier defaults (Informative & actionable)
  if (tier === "protected") {
    return `Protected OS or Core Application Directory (${item.name}). System access active; inspect contents carefully before cleaning.`;
  }
  if (tier === "review_required") {
    return `Review Required (${item.name}). Contains user data or application configuration; review before purging.`;
  }
  if (tier === "cleanup_candidate") {
    return `Cleanup Candidate (${item.name}). Identified as non-essential data suitable for disk space reclamation.`;
  }

  if (item.kind === "directory") {
    return `Directory container (${item.name}). Total allocated storage: ${formatBytes(item.allocated_bytes)}.`;
  }

  return `File asset. Path: ${item.display_path}`;
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
