import { expect, test, type Page } from "@playwright/test";

type MockScenario = "complete" | "cancel" | "raw-fallback";

test("completes a fast scan and keeps the analyzer bounded and linked", async ({ page }) => {
  await boot(page, "complete");

  await expect(page.getByLabel("Scanner status")).toContainText("Scanner ready");
  await page.getByRole("button", { name: "Scan", exact: true }).click();

  const summary = page.getByLabel("Storage summary");
  await expect(summary.getByText("2.0 GB", { exact: true })).toBeVisible();
  await expect(summary.getByText("2,500", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Scanner status")).toContainText("MFT");
  await expect(summary.getByText("6.0 GB", { exact: true })).toBeVisible();
  await expect(summary.getByText("12,345", { exact: true })).toBeVisible();
  await expect(summary.getByText("1.0 GB", { exact: true })).toBeVisible();

  const hierarchy = page.getByLabel("Storage hierarchy");
  const users = hierarchy.locator(".data-row", { hasText: "Users" });
  await expect(users).toBeVisible();
  await expect(page.getByLabel("Extension summary").getByText(".zip")).toBeVisible();
  await expect(page.getByLabel("Storage treemap", { exact: true })).toBeVisible();

  expect(await hierarchy.locator(".data-row").count()).toBeLessThan(45);
  await users.click();
  await expect(page.locator(".attachment-chip", { hasText: "Users" })).toBeVisible();
  await users.press("Enter");
  await expect(page.getByRole("button", { name: "Users", exact: true })).toBeVisible();
  await expect(hierarchy.locator(".data-row", { hasText: "Downloads" })).toBeVisible();
});

test("offers traversal after a recoverable MFT failure", async ({ page }) => {
  await boot(page, "raw-fallback");

  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await expect(page.getByRole("button", { name: "Use traversal" })).toBeVisible();
  await expect(page.getByLabel("Scanner status")).toContainText("MFT_ACCESS_DENIED");

  await page.getByRole("button", { name: "Use traversal" }).click();
  await expect(page.getByLabel("Scanner status")).toContainText("Traversal");
  await expect(page.getByText("Complete traversal")).toBeVisible();

  const backends = await page.evaluate(() => window.__TAURI_MOCK__?.scanBackends ?? []);
  expect(backends).toEqual(["raw_ntfs", "traversal"]);
});

test("cancels an active scan without replacing the analyzer", async ({ page }) => {
  await boot(page, "cancel");

  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await expect(page.getByLabel("Scanner status")).toContainText("Enumerating");
  await page.getByRole("button", { name: "Cancel", exact: true }).click();

  await expect(page.getByLabel("Scanner status")).toContainText("Scanner ready");
  await expect(page.getByRole("button", { name: "Scan", exact: true })).toBeVisible();
  await expect(page.getByText("Run a scan to build the treemap")).toBeVisible();
});

test("remains usable without Ollama and at the minimum desktop viewport", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 680 });
  await boot(page, "complete");

  await expect(page.getByText("Ollama unavailable")).toBeVisible();
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await expect(page.getByLabel("Scanner status")).toContainText("MFT");

  const overflow = await page.evaluate(() => ({
    document: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    body: document.body.scrollWidth - document.body.clientWidth,
  }));
  expect(overflow.document).toBeLessThanOrEqual(1);
  expect(overflow.body).toBeLessThanOrEqual(1);
  await expect(page.getByLabel("Storage hierarchy")).toBeVisible();

  await page.getByRole("tab", { name: /Plan 0/i }).click();
  await page.getByRole("textbox", { name: "Cleanup target in GB" }).fill("1");
  await page.getByRole("button", { name: "Find cleanup" }).click();
  await expect(page.getByText("Old crash report")).toBeVisible();
});

async function boot(page: Page, scenario: MockScenario) {
  await page.addInitScript(({ selectedScenario }) => {
    const gib = 1024 ** 3;
    const callbacks = new Map<number, { callback: (payload: unknown) => void; once: boolean }>();
    let nextCallbackId = 1;
    let scanAttempts = 0;
    let activeScan: { reject: (reason: unknown) => void; timer: number } | null = null;
    const state = { scanBackends: [] as string[] };
    window.__TAURI_MOCK__ = state;
    window.isTauri = true;

    const target = {
      id: "C:",
      kind: "volume",
      display_path: "C:\\",
      filesystem: "NTFS",
      volume_id: "volume-c",
      total_bytes: String(500 * gib),
      available_bytes: String(200 * gib),
      fast_scan_available: true,
    };
    const policy = (tier = "protected") => ({
      tier,
      rule_id: "fixture",
      rule_version: "1",
      facts: [],
      inference: [],
      warnings: [],
    });
    const item = (
      id: string,
      parentId: string | null,
      name: string,
      displayPath: string,
      allocatedBytes: number,
    ) => ({
      id,
      parent_id: parentId,
      name,
      display_path: displayPath,
      kind: "directory",
      logical_bytes: String(allocatedBytes),
      allocated_bytes: String(allocatedBytes),
      modified_at_ms: "1750000000000",
      extension: null,
      attributes: [],
      hard_link_count: null,
      child_count: 2,
      owner: null,
      policy: policy(),
    });
    const users = item("scan-1:users", null, "Users", "C:\\Users", 4 * gib);
    const windows = item("scan-1:windows", null, "Windows", "C:\\Windows", 1.5 * gib);
    const rootItems = [users, windows, ...Array.from({ length: 138 }, (_, index) => item(
      `scan-1:filler-${index}`,
      null,
      `Folder ${String(index + 1).padStart(3, "0")}`,
      `C:\\Folder ${String(index + 1).padStart(3, "0")}`,
      Math.max(1, 500 - index) * 1024 * 1024,
    ))];
    const userItems = [
      item("scan-1:downloads", users.id, "Downloads", "C:\\Users\\Downloads", 2 * gib),
      item("scan-1:appdata", users.id, "AppData", "C:\\Users\\AppData", 1.5 * gib),
    ];

    const summary = (backend: "raw_ntfs" | "traversal") => ({
      session_id: "scan-1",
      target,
      backend,
      coverage: "complete",
      entry_count: "12345",
      logical_bytes: String(7 * gib),
      allocated_bytes: String(6 * gib),
      volume_used_bytes: String(6 * gib),
      unaccounted_bytes: "0",
      started_at_ms: "1000",
      completed_at_ms: "2800",
      elapsed_ms: "1800",
      warnings: [],
    });
    const progress = (entries: number, bytes: number) => ({
      session_id: "scan-1",
      phase: "enumerating",
      backend: "raw_ntfs",
      entries_seen: String(entries),
      bytes_accounted: String(bytes),
      elapsed_ms: "300",
      warnings: [],
    });
    const emit = (channel: { id: number }, index: number, message: unknown) => {
      callbacks.get(channel.id)?.callback({ index, message });
    };
    const finishScan = (
      backend: "raw_ntfs" | "traversal",
      channel: { id: number },
      resolve: (value: unknown) => void,
      reject: (reason: unknown) => void,
    ) => {
      emit(channel, 0, progress(2500, 2 * gib));
      const delay = selectedScenario === "cancel" ? 5_000 : 450;
      const timer = window.setTimeout(() => {
        activeScan = null;
        resolve(summary(backend));
      }, delay);
      activeScan = { reject, timer };
    };
    const aggregate = (dimension: string) => dimension === "policy"
      ? {
          buckets: [{ key: "cleanup_candidate", label: "Candidate", item_count: "2", logical_bytes: String(gib), allocated_bytes: String(gib) }],
          other_item_count: "0",
          other_logical_bytes: "0",
          other_allocated_bytes: "0",
        }
      : {
          buckets: [
            { key: "zip", label: ".zip", item_count: "12", logical_bytes: String(gib), allocated_bytes: String(gib) },
            { key: "log", label: ".log", item_count: "30", logical_bytes: String(gib / 2), allocated_bytes: String(gib / 2) },
          ],
          other_item_count: "0",
          other_logical_bytes: "0",
          other_allocated_bytes: "0",
        };
    const cleanupPlan = {
      session_id: "scan-1",
      target_bytes: String(gib),
      selected_candidate_bytes: "4096",
      selected_review_bytes: "0",
      review_potential_bytes: "0",
      target_shortfall_bytes: String(gib - 4096),
      truncated: false,
      omitted_item_count: "0",
      omitted_candidate_bytes: "0",
      omitted_review_bytes: "0",
      items: [{
        id: "plan-1",
        node_ids: ["scan-1:crash"],
        title: "Old crash report",
        category: "Crash dumps",
        tier: "cleanup_candidate",
        selected: true,
        reclaimable_bytes: "4096",
        evidence: [],
        warnings: [],
        action_kind: "open_location",
      }],
    };

    window.__TAURI_INTERNALS__ = {
      transformCallback(callback: (payload: unknown) => void, once = false) {
        const id = nextCallbackId++;
        callbacks.set(id, { callback, once });
        return id;
      },
      unregisterCallback(id: number) {
        callbacks.delete(id);
      },
      async invoke(command: string, args: Record<string, any> = {}) {
        if (command === "list_scan_targets") return [target];
        if (command === "start_scan") {
          scanAttempts += 1;
          const backend = args.request.preferred_backend as "raw_ntfs" | "traversal";
          state.scanBackends.push(backend);
          if (selectedScenario === "raw-fallback" && scanAttempts === 1) {
            await new Promise((resolve) => setTimeout(resolve, 40));
            throw { code: "MFT_ACCESS_DENIED", detail: "Raw MFT access was denied", recoverable: true };
          }
          return new Promise((resolve, reject) => finishScan(backend, args.onProgress, resolve, reject));
        }
        if (command === "cancel_scan") {
          if (activeScan) {
            window.clearTimeout(activeScan.timer);
            const reject = activeScan.reject;
            activeScan = null;
            reject({ code: "SCAN_CANCELLED", detail: "Scan cancelled", recoverable: true });
          }
          return true;
        }
        if (command === "query_items") {
          const query = args.query;
          let items = query.parent_id === users.id ? userItems : rootItems;
          if (query.text) {
            const text = String(query.text).toLocaleLowerCase();
            items = [...rootItems, ...userItems].filter((entry) => entry.display_path.toLocaleLowerCase().includes(text));
          }
          return { items: items.slice(0, query.limit), next_cursor: null };
        }
        if (command === "cancel_item_query") return true;
        if (command === "get_storage_aggregate") return aggregate(args.query.dimension);
        if (command === "get_treemap_slice") return {
          nodes: [users, windows].map((entry) => ({
            id: entry.id,
            parent_id: entry.parent_id,
            name: entry.name,
            allocated_bytes: entry.allocated_bytes,
            kind: entry.kind,
            policy_tier: entry.policy.tier,
            owner_id: null,
            synthetic: false,
          })),
          truncated: false,
          other_allocated_bytes: "0",
        };
        if (command === "get_item_details") {
          const found = [...rootItems, ...userItems].find((entry) => entry.id === args.nodeId);
          return { item: found };
        }
        if (command === "get_hardware_profile") return {
          total_memory_bytes: String(16 * gib),
          available_memory_bytes: String(8 * gib),
        };
        if (command === "build_cleanup_plan" || command === "edit_cleanup_plan") return cleanupPlan;
        if (command.startsWith("plugin:http|")) throw new Error("Ollama is unavailable in this test");
        if (command.startsWith("plugin:opener|")) return undefined;
        throw new Error(`Unhandled mocked Tauri command: ${command}`);
      },
    };
  }, { selectedScenario: scenario });
  await page.goto("/");
}

declare global {
  interface Window {
    isTauri?: boolean;
    __TAURI_INTERNALS__?: {
      transformCallback: (callback: (payload: unknown) => void, once?: boolean) => number;
      unregisterCallback: (id: number) => void;
      invoke: (command: string, args?: Record<string, any>) => Promise<any>;
    };
    __TAURI_MOCK__?: { scanBackends: string[] };
  }
}
