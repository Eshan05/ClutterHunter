# ClutterHunter Product and Implementation Plan

Status: decision-complete specification for the first polished milestone  
Product name: ClutterHunter  
Primary platform: Windows 10/11 x64  
Last updated: 2026-07-13

## 1. Executive Summary

ClutterHunter is a private, evidence-based storage agent. Its first layer is a
fast disk analyzer in the class of WizTree and WinDirStat. Its second layer is
an on-device AI agent that selectively queries the scan index, explains what is
using space, and assembles a conservative cleanup plan.

The product is not a disk visualizer with an unrestricted chatbot attached. The
Rust analyzer and policy engine remain authoritative. The model can investigate,
explain, navigate through bounded tools, and refine a plan, but it cannot invent
safety classifications or bypass protections.

The hero workflow is:

> Free 5 GB without touching projects, photos, or installed applications.

The first milestone is intentionally non-destructive. It scans, visualizes,
explains, chats, and proposes. It does not delete, recycle, uninstall, or alter
filesystem contents.

## 2. Product Positioning

### 2.1 Audience

- Primary: developers and Windows power users with large, complicated disks.
- Secondary: everyday users who benefit from plain-language AI explanations.
- There is no basic/advanced mode. The interface uses progressive disclosure:
  common actions stay obvious while evidence and filesystem details remain
  available when requested.

### 2.2 Core Value

- Scan an NTFS volume at metadata speed rather than walking every file.
- Make large storage structures easy to inspect in a familiar analyzer.
- Answer storage questions without sending paths, prompts, or results off-device.
- Separate deterministic safety evidence from model-generated prose.
- Produce a visible, editable plan instead of losing recommendations in chat.

### 2.3 Product Principles

1. Analyzer first: useful without Ollama or a compatible model.
2. Local by construction: inference is loopback-only and cloud models are barred.
3. Evidence before confidence: every recommendation cites deterministic facts.
4. No surprise work: scans, model loading, heavy reads, and approvals are explicit.
5. No surprise navigation: the agent offers actions; the user changes the view.
6. No destructive v1 tools: the model has no path to delete or modify data.
7. Performance is a product feature: the usable analyzer, not a raw parser timer,
   is measured against WizTree.

## 3. First Milestone Contract

### 3.1 Included

- One volume or one folder per scan session.
- Whole-volume NTFS scanning through an elevated, read-only MFT helper.
- NTFS folder scanning through the MFT by default, with clear disclosure that the
  helper reads containing-volume metadata to reconstruct the selected subtree.
- Ordinary traversal fallback when elevation or raw NTFS access is unavailable.
- Selected-folder traversal on exFAT, FAT32, ReFS, or another locally accessible
  Windows filesystem, labeled as a fallback with no NTFS performance guarantee.
- Dense tree/table navigation, treemap, extension summary, search, sorting,
  filtering, breadcrumbs, scan progress, cancellation, and rescan.
- Logical and allocated byte counts, with allocated size as the default metric.
- Deterministic policy tiers and evidence.
- Installed application and AppX ownership correlation.
- Persistent protected paths and dismissed suggestions.
- A session-bound cleanup plan with separate conservative and review totals.
- Ollama discovery, model ranking, compatibility testing, streaming chat, tools,
  approvals, activity trace, and typed local result components.
- Bounded, approved inspection of known text log/crash files only.
- A dedicated, cancellable exact-duplicate workflow if schedule permits.
- A portable ZIP for Windows.

### 3.2 Explicitly Deferred

- Deleting files, emptying the Recycle Bin, uninstalling applications, or any
  other filesystem mutation.
- Persistent scan indexes, chat history, or cleanup plans.
- Exporting plans to Markdown, JSON, or another format.
- Multiple simultaneous scans or cross-volume aggregate sessions.
- Live USN journal updates after a scan.
- Non-NTFS whole-volume scans.
- OCR, image understanding, PDF/Office extraction, broad document inspection,
  source-code reading, and arbitrary file-content access.
- Embeddings, semantic indexing, vector databases, and long-term AI memory.
- LAN, remote, or cloud model endpoints.
- Ollama/model bundling or in-app model downloads.
- Kernel drivers, Ring0 code, or filesystem filter drivers.
- Raw chain-of-thought display.
- A Windows installer or single-file self-extracting executable.
- Automatic cleanup-rule downloads or user-imported rule packs.

### 3.3 Scope Cut Order

If quality, scan performance, or agent reliability needs more time, exact
duplicate hashing leaves the milestone first. Log inspection, application
ownership, deterministic planning, and the core agent workflow stay ahead of it.

## 4. User Experience

### 4.1 First Run

1. Open directly into the analyzer workspace, not a landing page.
2. Preselect the Windows system drive but do not scan automatically.
3. Show an explicit Scan button. No UAC prompt appears until it is pressed.
4. Keep the AI dock available. If Ollama is missing, show a restrained setup
   state without blocking storage analysis.
5. Do not load a model automatically after a scan. Show deterministic insights
   immediately and a prominent **Find safe cleanup** action.

### 4.2 Scan Flow

1. The user chooses a volume or folder and presses Scan.
2. Fast NTFS mode explains that a separate elevated read-only helper will inspect
   filesystem metadata.
3. The helper requests UAC and streams progress to the non-elevated application.
4. If elevation is declined, raw access fails, or the helper cannot start, show
   the reason and offer/enter traversal fallback. Never silently change backends.
5. A cancelled or failed replacement scan leaves the previous completed session
   intact and discards the partial replacement index.
6. When complete, table, totals, policy tiers, warnings, and first treemap are
   stable. Late enrichment must not change an item's safety tier.

### 4.3 Analyzer Workspace

- Top toolbar: target picker, Scan/Cancel/Rescan, back/forward navigation,
  breadcrumb, search, metric toggle, and scan status.
- Main surface: virtualized hierarchy/table above a linked treemap.
- Table defaults: Name, Allocated Size, Percent of Scope, Logical Size, Type,
  Modified, Policy, and Owner. Extra technical columns are optional.
- Treemap uses allocated size by default and stable multi-hue file-type colors.
- Extension summary is available alongside the hierarchy/treemap workflow.
- Hover, row selection, treemap selection, and breadcrumbs remain synchronized.
- Fixed row and toolbar dimensions prevent layout shifting during loading.
- Open containing folder and Copy path are available from item actions.
- The product follows the system theme, meets keyboard/focus expectations, and
  remains usable when the desktop window is narrowed.

### 4.4 AI Dock and Plan

- A restrained right dock contains Chat and Plan tabs.
- The dock remembers its previous open/collapsed state. On constrained widths it
  collapses or becomes an overlay rather than crushing the analyzer.
- Selecting an analyzer item creates a visible, removable metadata chip for the
  next message. File content is never attached implicitly.
- Agent result cards can offer **Show in analyzer**. Tool calls never navigate or
  replace filters automatically.
- The Plan tab has a persistent item count and separate totals for:
  - selected cleanup candidates;
  - unchecked review-required potential.
- An optional size input sits beside **Find safe cleanup**. With no target, the
  deterministic engine produces the strongest conservative plan available.
- Cleanup candidates are selected by default. Review-required proposals appear
  in the same plan but remain unchecked until the user adds them.
- The plan is editable and reversible within the session, but not persisted or
  exported in v1.

### 4.5 Assistant Voice

- Concise and evidence-first.
- Lead with the answer, conservative total, and any shortfall.
- Cite tool evidence and distinguish facts from inference.
- Use plain language first; expose filesystem terminology when it helps.
- Never claim that an item is unused, abandoned, or safe solely from timestamps.

## 5. Scan Architecture

### 5.1 Process Boundary

The application has three Rust boundaries plus the React webview:

1. `clutter-core`: scan arena, aggregation, queries, policy, ownership, plan,
   duplicate algorithms, and shared domain types.
2. Tauri host: non-elevated application lifecycle, commands, channels, settings,
   Ollama HTTP capability, and window integration.
3. Scanner helper: short-lived, elevated, read-only NTFS metadata reader.
4. React webview: analyzer UI and AI SDK 7 orchestration.

The Cargo workspace should keep the helper protocol in a small shared crate so
the elevated binary cannot acquire unrelated application capabilities.

### 5.2 Backend Selection

- `RawNtfsBackend`: preferred for NTFS volumes and folders; elevation required.
- `TraversalBackend`: fallback for selected folders and degraded NTFS scans.
- Whole non-NTFS volumes are rejected with a clear explanation.
- Selected non-NTFS folders may use traversal.
- Put `ntfs-reader` behind the backend trait. The initial scanner spike must prove
  its accuracy and throughput; a backend replacement must not affect public DTOs.

### 5.3 Elevated Helper Security

- The main process creates a Windows named pipe restricted to the current user.
- The pipe name and handshake nonce are cryptographically random per launch.
- The main process verifies the elevated client's PID and expected executable.
- Messages are versioned, length-prefixed, bounded, and decoded with strict size
  limits. Bincode 2 is the default Rust-to-Rust serializer.
- The helper accepts only a scan target, backend options, and cancellation. It has
  no delete, move, write, shell, arbitrary command, or network operation.
- The helper streams node batches and exits after Complete, Error, or Cancel.
- Malformed frames, version mismatch, nonce failure, or unexpected client PID
  terminate the helper session and discard its partial index.

Protocol messages:

```text
Hello { protocol_version, nonce, helper_pid, target }
NodeBatch { sequence, nodes }
Progress { phase, entries_seen, bytes_accounted, elapsed_ms }
Warning { code, item_reference?, detail }
Complete { statistics, journal_end }
Error { code, recoverable, detail }
Cancel
```

### 5.4 Scan Arena

Rust owns the complete in-memory session. The webview never receives millions of
records in one IPC response.

Use compact, interned storage:

- Contiguous node arena indexed by a 32-bit internal index.
- Interned native Windows names and paths with a lossless display representation.
- Contiguous child-index ranges for directory traversal.
- Interned extensions, owners, and policy rule identifiers.
- Sparse storage for warnings, extra streams, and policy reasons.
- Temporary MFT-reference map released or compacted after hierarchy finalization.
- On-demand or cached sort indexes for hot directories rather than every possible
  sort order across the volume.

The public `NodeId` is opaque and scan-local. It includes/derives from the session
identity so stale IDs from a prior scan fail validation.

### 5.5 Accuracy Rules

- Default measure: allocated bytes. Logical bytes remain visible.
- Query cluster/allocation unit size from the target volume.
- Aggregate directories from child contribution after hard-link normalization.
- Count physical allocation for a hard-linked file once. The stable canonical
  entry is the lowest file reference; aliases retain logical size and a hard-link
  badge but contribute zero additional allocated bytes to parent totals.
- Include named data-stream allocation when the backend exposes it and show an
  alternate-data-stream indicator. If unavailable, emit a coverage warning.
- Do not follow junctions, symlinks, mount points, or other reparse targets.
- Preserve the reparse item itself and label it.
- Respect sparse and compressed allocation rather than treating logical length as
  physical disk usage.
- Use modified time as age evidence. Last-access time may be displayed as an
  explicitly unreliable field but never drives cleanup classification.
- Capture USN journal position at scan start/end when available. A changed journal
  marks the scan as potentially stale and offers Rescan; v1 does not patch live.
- Compare accounted allocation with volume used space and show the remainder as
  filesystem metadata/reserved/unaccounted space instead of forcing a false sum.
- Traversal fallbacks mark inaccessible paths and incomplete totals prominently.

### 5.6 Query Model

- Child listing, global search, aggregates, and treemap requests run in Rust.
- Default page size is 50; maximum page/tool page size is 100.
- Cursors are opaque and invalidated with the session.
- Search is debounced, cancellable, and may run in parallel over the compact arena.
- A treemap request returns at most 5,000 weighted nodes and deterministic `Other`
  buckets. D3 hierarchy computes layout; Canvas 2D renders rectangles.
- Table rendering uses a proven row virtualizer and receives only the visible
  window plus a small overscan buffer.

## 6. Public Data Contracts

Rust DTOs derive Serde and `ts-rs` bindings. Checked-in generated bindings are the
source of truth for the TypeScript boundary, and CI fails if regeneration differs.
Do not use prerelease `tauri-specta` for this milestone.

JSON cannot safely represent every Rust `u64`. Byte counts, file references, and
other full-width integers cross IPC as branded decimal strings and are converted
to `bigint` only inside formatting/calculation helpers.

Core types:

```text
ScanSessionId = opaque string
NodeId = opaque string
ByteCount = decimal string
Cursor = opaque string

ScanTarget {
  kind: volume | folder
  display_path
  filesystem
  volume_id?
}

ScanRequest {
  target
  preferred_backend: raw_ntfs | traversal
}

ScanProgress {
  session_id
  phase: preparing | elevating | enumerating | indexing | classifying | finalizing
  backend
  entries_seen
  bytes_accounted
  elapsed_ms
  warnings[]
}

ScanSummary {
  session_id
  target
  backend
  coverage: complete | partial | potentially_stale
  entry_count
  logical_bytes
  allocated_bytes
  volume_used_bytes?
  unaccounted_bytes?
  started_at
  completed_at
  warnings[]
}

ItemQuery {
  scope_id?
  text?
  kinds[]?
  extensions[]?
  policy_tiers[]?
  owner_ids[]?
  min_bytes?
  modified_before?
  sort: name | allocated | logical | modified | type | policy | owner
  direction: asc | desc
  cursor?
  limit
}

ItemRow {
  id
  parent_id?
  name
  display_path
  kind
  logical_bytes
  allocated_bytes
  modified_at?
  extension?
  attributes[]
  hard_link_count?
  owner?
  policy
  child_count?
}

PolicyEvidence {
  tier: protected | review_required | cleanup_candidate
  rule_id
  rule_version
  facts[]
  inference[]
  warnings[]
}

CleanupPlan {
  target_bytes?
  selected_candidate_bytes
  review_potential_bytes
  target_shortfall_bytes
  items[]
}

PlanItem {
  id
  node_ids[]
  title
  category
  tier
  selected
  reclaimable_bytes
  evidence[]
  warnings[]
  action_kind: inspect | open_location | open_windows_settings | none
}

ModelProfile {
  model_id
  digest
  installed
  local_residency
  size_bytes
  parameter_size?
  context_length?
  capabilities[]
  fit: light | balanced | heavy | incompatible
  harness?
}

HarnessResult {
  harness_version
  compatible
  scenarios_passed
  scenarios_total
  median_first_token_ms?
  median_turn_ms?
  failure_code?
}
```

Tauri commands:

```text
list_scan_targets
start_scan
cancel_scan
get_scan_summary
query_items
get_item_details
get_storage_aggregate
get_treemap_slice
build_cleanup_plan
edit_cleanup_plan
set_path_protection
dismiss_suggestion
list_model_profiles
save_model_selection
start_duplicate_analysis
cancel_duplicate_analysis
get_duplicate_results
read_log_excerpt
open_item_location
```

Long-running work uses Tauri channels rather than emitting thousands of global
events. Commands return typed error unions with stable codes such as
`ELEVATION_DECLINED`, `UNSUPPORTED_FILESYSTEM`, `STALE_SESSION`,
`PARTIAL_COVERAGE`, `INVALID_NODE`, `OLLAMA_UNAVAILABLE`, `MODEL_CLOUD`,
`MODEL_INCOMPATIBLE`, and `APPROVAL_REQUIRED`.

## 7. Policy Engine

### 7.1 Authority and Evidence

The Rust policy engine owns safety tiers. Every decision records:

- rule ID and bundled rule-set version;
- exact structural/path match;
- filesystem facts and byte counts;
- known application ownership facts;
- rebuild or disposal semantics;
- explicit uncertainty and coverage warnings.

There is no LLM confidence score. Model prose cannot change a tier.

### 7.2 Protected

- Windows and operating-system directories unless a narrow reviewed rule produces
  a review item for an official Windows-managed action.
- Installed application binaries and primary application directories.
- User documents, photos, videos, audio, and other personal data.
- Source repositories and source/VCS metadata.
- Encrypted, unknown, or opaque containers.
- Backups and low-confidence classifications.
- User-configured protected paths.

Protected items remain visible in the analyzer but never enter a generated plan.

### 7.3 Review Required

- Generated project data such as `node_modules`, Rust `target`, build outputs,
  virtual environments, and ignored artifacts. Evidence includes likely rebuild
  cost; source remains protected.
- Exact duplicates after full hashing.
- Recycle Bin contents, shown as one grouped opportunity and excluded from the
  conservative total.
- Large or old personal files. Age is evidence, never proof of disuse.
- Whole projects, but only after direct user intent names the project for removal.
- Installed application storage and possible uninstall decisions.
- Possible application leftovers without conclusive ownership.
- System-managed cleanup areas surfaced with official Windows actions.

### 7.4 Cleanup Candidates

Only an app-bundled allowlist may create this tier:

- known temporary directories;
- known application/browser caches;
- known disposable logs;
- known crash dumps/reports;
- clearly disposable application data with exact ownership and path evidence.

Personal-file type, project membership, unknown ownership, encryption, partial
scan coverage, or a user protection always wins over a cleanup rule.

### 7.5 User Policy

- Users may add persistent protected folders.
- An agent request such as "never suggest this folder again" prepares a change
  but requires explicit approval before storage.
- Built-in protections cannot be weakened or reordered in v1.
- Dismissed suggestions persist by canonical target and rule ID.
- NTFS protections use volume identity plus normalized relative path; traversal
  targets retain a normalized absolute Windows path fallback.
- Rules and the bundled model catalog update only with application releases.

## 8. Cleanup Plan Algorithm

The same deterministic planner powers the no-AI and AI experiences.

1. Exclude protected, partial-confidence, stale, and invalid items.
2. Group rule-defined opportunities so thousands of cache files become one
   understandable plan item.
3. Rank cleanup candidates by fixed rule safety priority, then reclaimable bytes.
4. Select candidates until the optional target is reached or candidates end.
5. Add relevant review-required opportunities unchecked.
6. Compute conservative selected total, review potential, and target shortfall
   independently. Never display a blended headline total.
7. Revalidate item IDs and current policy tier on every plan edit.

The agent may call the planner and edit session selections. These operations are
visible, reversible, and do not require approval because no filesystem state is
changed. The user remains the only party that checks a review-required item.

## 9. Application Ownership

Build an ownership index before final policy classification from:

- HKLM and HKCU uninstall registry records, including 32/64-bit views;
- installed AppX/MSIX package metadata;
- known Windows application roots;
- exact install locations and longest-prefix path relationships;
- bundled narrow mappings for known cache roots.

Label exact registry/package matches as facts. Label root/name heuristics as
inference. Late or heuristic ownership may improve explanation but cannot promote
an item to `cleanup_candidate` after scan completion.

### 9.1 Owner-Native Actions

The first milestone remains proposal-only, but plan items must identify the
correct future action boundary. ClutterHunter hardcodes reviewed ownership and
disposal evidence; it does not hardcode arbitrary path deletion as a substitute
for an application's supported lifecycle.

- Ollama models use `ollama rm <model>`. Never delete content-addressed blob or
  manifest files directly because blobs may be shared by multiple model tags.
- Scoop applications use `scoop uninstall`; old installed versions use
  `scoop cleanup`; its download cache uses `scoop cache`. Never remove Scoop's
  version, `current`, shim, or persisted-data directories behind Scoop's back.
- AppX/MSIX and registered Win32 applications open Windows Apps settings or the
  exact registered uninstaller rather than deleting their install directory.
- Windows-managed storage opens the relevant Windows Storage/cleanup surface.
- Only narrowly allowlisted caches, temporary data, logs, and crash reports may
  eventually receive a direct recycle/delete action after revalidation.
- Unknown, heuristic, protected, or user-owned paths expose inspect/open actions
  only.

Future executable actions are typed adapters with exact arguments, an ownership
proof, a byte estimate, a preview, and explicit approval. No adapter accepts an
arbitrary command or model-authored shell string. Example action kinds include
`run_ollama_rm`, `run_scoop_cleanup`, `run_scoop_cache`,
`open_windows_apps_settings`, `open_location`, and `none`.

## 10. Duplicate Analysis

Duplicate analysis is not part of the initial MFT scan and is not an autonomous
agent tool. The MFT provides size and file-reference metadata, not proof that two
ordinary files contain identical bytes.

The user starts a dedicated workflow after seeing an estimate of candidate count
and bytes. It is cancellable and reports progress.

Algorithm:

1. Group non-zero files by logical size.
2. Exclude hard-link aliases of the same physical file.
3. Re-stat candidates before reading.
4. Hash bounded beginning/middle/end samples with BLAKE3.
5. Fully hash only surviving groups.
6. Re-stat after hashing and discard files changed during analysis.
7. Call results exact only after matching full hashes and stable metadata.

The agent may query and explain completed results. If implementation time is
tight, this whole feature is deferred before any core feature is weakened.

## 11. On-Device AI Architecture

### 11.1 Runtime

- AI SDK 7 `ToolLoopAgent` runs inside the React/Tauri webview.
- Use the first-party `@ai-sdk/openai-compatible` provider against Ollama's
  `/v1/chat/completions` API.
- Inject `@tauri-apps/plugin-http` fetch so CORS configuration is not delegated to
  the user's Ollama environment.
- Tauri HTTP capabilities allow only `http://127.0.0.1:*` and no redirects to a
  non-loopback destination.
- The configured endpoint accepts a numeric custom loopback port and is
  canonicalized to `127.0.0.1`. Hostnames, LAN IPs, and internet URLs are rejected.
- Do not use `ai-sdk-ollama`; known releases were compromised in a 2026 npm
  supply-chain incident.
- Do not add a Node sidecar, hidden local proxy, Tambo runtime, Postgres, auth, or
  another service process.

### 11.2 Local-Only Enforcement

The privacy promise is that real paths, prompts, tool results, and responses never
leave the machine.

Before a model receives real scan context:

1. It must be returned by the loopback Ollama `/api/tags` endpoint with a digest,
   non-zero local size, and plausible local model details.
2. Reject tags or aliases ending in or resolving to `-cloud`.
3. `/api/show` must report tool capability.
4. Send a synthetic, non-streaming preflight through Ollama's native `/api/chat`
   endpoint so the raw response can be inspected before AI SDK sees real data.
5. Reject any response metadata containing `remote_model`, `remote_host`, cloud,
   web-search, or offload evidence.
6. Only then run the AI SDK tool harness with fake paths and fake storage data.

The application exposes no Ollama web-search tool. Setup recommends Ollama's
`disable_ollama_cloud`/`OLLAMA_NO_CLOUD=1` option but does not modify Ollama's
configuration itself.

### 11.3 Model Setup and Ranking

- Detect an existing Ollama service. If absent, show instructions and an official
  download link; do not bundle or install it.
- If no suitable model is installed, show copyable `ollama pull` commands and
  official model pages. Do not pull models in-app.
- Merge locally installed models with a versioned bundled catalog. Do not fetch a
  catalog in the background.
- Hard-gate non-local, non-tool-capable, and failed-harness models.
- Rank remaining models lexicographically by:
  1. local/tool compatibility;
  2. hardware fit/headroom;
  3. harness correctness and repeatability;
  4. measured first-token and full-turn latency;
  5. curated quality and usable context.
- Present plain-language `Light`, `Balanced`, and `Heavy` labels plus exact size,
  context, and test details. Do not silently choose a model.
- Uninstalled catalog entries show expected fit. Installed entries show measured
  fit after the harness.

Initial catalog candidates:

- `lfm2.5-thinking:1.2b` as a light on-device candidate.
- Qwen 3.5 0.8B/2B/4B variants, with 2B the likely balanced candidate on the
  prepared 8 GB RAM, GTX 1650 machine.
- `functiongemma` may be noted as a specialized function model but is not eligible
  as the single conversational assistant because it is not intended for direct
  dialogue without fine-tuning.

### 11.4 Compatibility Harness

Run automatically when an installed model is selected, after the native local-
residency preflight. Use only a bundled synthetic scan fixture and cache by model
digest, Ollama version, harness version, and relevant model options.

Scenarios:

1. Call overview, then a bounded item query, then answer using returned facts.
2. Build a cleanup plan for a fake target and preserve separate safety totals.
3. Handle an unavailable/empty result without inventing files, IDs, or bytes.
4. Produce schema-valid calls and recover from one deliberately constrained input
   error without entering a loop.

A failed model is clearly incompatible and cannot be used as a chat-only fallback.
One selected model handles conversation and tools.

### 11.5 Agent Tools

Keep schemas small and use AI SDK `activeTools` so each workflow exposes only the
tools it needs.

```text
get_storage_overview(scope_id?)
query_storage_items(scope_id?, text?, filters?, sort?, cursor?, limit <= 100)
summarize_storage(scope_id?, group_by: extension | age | owner | policy, limit <= 50)
get_item_evidence(item_ids <= 20)
build_cleanup_plan(target_bytes?, constraints?)
edit_cleanup_plan(add_item_ids?, remove_item_ids?)
get_duplicate_results(scope_id?, cursor?, limit <= 50)
inspect_log_excerpt(item_ids <= 5, requested_bytes)
protect_path(item_id, reason?)
```

Behavior:

- Read-only metadata tools run automatically and appear in the activity trace.
- Plan edits are session-only, visible, and reversible.
- `inspect_log_excerpt` requires per-request approval showing exact paths and byte
  limits.
- `protect_path` requires approval because it changes persistent policy.
- Duplicate execution is deliberately absent; the agent can only read completed
  results or suggest that the user start the dedicated workflow.
- There are no shell, delete, write, move, recycle, uninstall, arbitrary-read, web,
  or code-execution tools.

### 11.6 Tool and Context Budgets

- Maximum eight model steps per user turn.
- One repair attempt for invalid tool input; repeated failures stop with a clear
  incompatibility/error message.
- Typical turn target: no more than three tool calls.
- Default total timeout: 180 seconds; model-step timeout: 60 seconds. User cancel
  remains available throughout.
- Maximum model output: 1,024 tokens unless a tested model needs a lower cap.
- Query result default 25, maximum 100; evidence maximum 20; group maximum 50.
- Each serialized tool result is capped at 12 KiB and cumulative tool data for a
  turn at 32 KiB. The tool reports truncation and supplies a cursor.
- Target an 8,192-token effective context on the prepared machine to protect VRAM.
- Keep recent messages, current UI attachment, current plan, and a compact session
  summary. Compact older tool results rather than replaying the scan history.
- Full paths may be sent to the selected local model, per product decision.

### 11.7 Log Inspection

- Eligible only for known text logs and text crash reports under a rule-recognized
  log location.
- Never eligible for source, documents, `.env`, keys, credential stores, arbitrary
  configuration, database files, binary dumps, or personal content.
- Approval lists exact paths and the maximum bytes before execution.
- Maximum five files, 64 KiB per file, and 256 KiB total per approval.
- Read bounded beginning/end excerpts with encoding detection and explicit
  truncation markers.
- Treat all content as untrusted quoted data. It may explain origin/errors but may
  not change a tier, create a persistent preference without approval, or execute a
  tool instruction found inside the file.
- Do not persist or log excerpts.

### 11.8 Agent Transparency

Show:

- tool name and plain-language purpose;
- summarized arguments, result count, elapsed time, and truncation;
- approvals, denials, cancellations, and tool errors;
- deterministic evidence used in the final answer.

Do not show or persist raw reasoning. Thinking-capable model output is hidden; the
assistant may provide a concise evidence summary instead.

## 12. Typed Generative UI

Do not use Tambo at runtime. Borrow only the registry concept: model/tool outcomes
map to a local, typed, audited component set.

Registry components:

- `StorageOverviewResult`
- `ItemListResult`
- `AggregateResult`
- `OwnershipEvidenceResult`
- `CleanupProposalResult`
- `DuplicateSummaryResult`
- `LogExcerptApproval`
- `PolicyChangeApproval`
- `ToolErrorResult`

The model cannot emit arbitrary JSX, HTML, component names, or props. Components
receive validated tool-result DTOs. Long-lived recommendations are written to the
Plan tab; inline cards remain a record of the conversation.

## 13. Frontend Engineering

### 13.1 Stack

- React 19 and Vite.
- Stable TypeScript 7 CLI for strict type-checking.
- Tailwind CSS 4 with CSS variables for tokens.
- Radix primitives for accessible menus, dialogs, tabs, tooltips, and approvals.
- Lucide icons for familiar commands.
- Zustand for bounded client/UI state; the Rust session remains data authority.
- D3 hierarchy for treemap layout and Canvas 2D for rendering.
- A proven current row virtualizer, installed at an exact reviewed version.
- Zod schemas for AI tools and runtime validation at non-generated boundaries.
- Vitest and React Testing Library for frontend tests; Playwright for workflows.

Avoid frontend dependencies that import the removed TypeScript compiler API.
Install current stable packages with exact lockfile resolution and verify npm
advisories/provenance, especially after the 2026 supply-chain incidents.

### 13.2 Visual Direction

- Quiet, utilitarian desktop analyzer rather than a marketing dashboard.
- Neutral application chrome with multiple distinguishable file-type colors.
- No one-hue palette, decorative gradients/orbs, oversized hero, nested cards, or
  floating page-section cards.
- Cards are limited to repeated tool results, approval prompts, and modals.
- Stable grid tracks, fixed toolbar/button sizes, and zero negative letter spacing.
- Treemap and selected table row use the same color/selection vocabulary.
- Default wide layout reserves roughly 360-400 px for the remembered AI dock; the
  analyzer receives the remaining space.

## 14. Persistence and Privacy

Persist locally:

- protected paths and dismissed suggestions;
- selected Ollama loopback port and selected model;
- model harness cache;
- dock state, theme preference, table columns, and other UI preferences.

Do not persist:

- scan arena or file index;
- chat history and compact context;
- cleanup plan;
- tool results, prompts, model responses, log excerpts, or raw paths in diagnostics.

There is no telemetry, analytics upload, cloud crash reporting, or background
network request. Local operational logs default to error codes, timings, counts,
and redacted targets. Explicit external links are the only non-loopback network
entry points in v1.

## 15. Performance Contract

### 15.1 Scan

- Target: five million entries.
- Peak combined memory for Tauri host, Rust arena, and first-view webview: about
  1.2 GB or less. Ollama is measured separately and documented alongside it.
- Raw NTFS completion: within 2x WizTree on the same hardware and volume.
- Benchmark endpoint: stable hierarchy, totals, coverage warnings, policy tiers,
  and interactive first analyzer view. UAC decision time is excluded.
- Record cold-cache and warm-cache runs separately; use median of at least three
  runs and record ClutterHunter/WizTree versions and target statistics.

### 15.2 Interaction

- Cached directory navigation and sort: target p95 under 100 ms.
- First bounded search results: target under 300 ms after debounce.
- Treemap replacement: target under 500 ms for the bounded slice.
- Cancel controls acknowledge immediately and stop at the next safe cancellation
  point without freezing the webview.
- No IPC response may contain the full scan tree.

### 15.3 AI on Prepared Hardware

Prepared demo machine: 8 GB system RAM and GTX 1650.

- Balanced model: first visible streamed output within 5 seconds.
- Typical one-to-three-tool turn: complete within 30 seconds.
- Rank and demonstrate a light fallback when the balanced model misses headroom.
- Do not preload a model until the user invokes AI; keep only one model active.

## 16. Testing Strategy

### 16.1 Rust Unit and Property Tests

- Node arena construction and parent/child aggregation.
- Logical/allocated byte arithmetic using full-width values.
- Hard-link canonicalization and no-double-count totals.
- Reparse-point non-traversal.
- Compressed, sparse, alternate-stream, and zero-length cases.
- Policy precedence, rule evidence, user protections, and partial-scan behavior.
- Registry/AppX ownership fact versus inference.
- Cleanup target selection, separate totals, stale IDs, and invalid plan edits.
- Duplicate staged hashing, mutation during hashing, cancellation, and hard links.
- Helper frame length/version/nonce validation and malformed-input rejection.

### 16.2 Scanner Integration Tests

- Frozen raw NTFS/MFT fixtures for deterministic parser coverage.
- Differential comparison of raw backend and traversal backend on the same test
  tree, with documented exceptions.
- Manual/elevated Windows test for real volume handles and UAC helper launch.
- Inaccessible directories, changing files, journal changes, and helper crashes.
- Non-NTFS whole-volume rejection and selected-folder traversal.

### 16.3 TypeScript and Agent Tests

- Generated Rust binding drift.
- Query validation, cursor handling, truncation, and stale sessions.
- Deterministic no-AI plan path.
- Model host validation, cloud tag rejection, remote-metadata rejection, and failed
  compatibility harness behavior.
- AI SDK mock-model tests for every tool, active-tool set, invalid calls, step cap,
  timeout, cancellation, and approval resume/deny.
- Log inspection eligibility, approval detail, byte caps, encoding, and prompt
  injection content treated as data.
- Typed result registry rejects unknown component/result types.

### 16.4 UI and Packaged Tests

Use mocked Tauri commands for browser-level Playwright coverage:

- first run and explicit scan;
- UAC failure/fallback explanation;
- scan progress, cancel, complete, partial/stale warnings, and rescan;
- million-row-like virtual navigation without DOM explosion;
- linked table/treemap/extension interactions;
- responsive dock and no text/control overlap at supported window sizes;
- missing Ollama, missing model, ranked model list, harness pass/fail;
- streamed chat, visible metadata chip, tool activity, approval, Plan tab, and
  explicit Show in analyzer action;
- protected path approval and persistence;
- deterministic fallback when AI disconnects;
- keyboard navigation, focus return, contrast, and reduced motion.

Smoke-test the actual portable ZIP on clean Windows 10/11 machines, including
WebView2 detection, unsigned SmartScreen behavior, UAC publisher text, helper
launch, loopback Ollama, and paths containing spaces/Unicode.

### 16.5 Privacy/Security Acceptance

- Capture network traffic during the complete hero workflow and verify that model
  traffic is loopback-only.
- Confirm Tauri capability denial for LAN/internet URLs and redirect attempts.
- Confirm no scan/chat/plan/log data appears in persisted settings or local logs.
- Attempt cloud models and models returning remote metadata; both must fail before
  real scan context is available.
- Fuzz helper frames and Tauri query inputs.
- Verify the elevated helper cannot be invoked for a non-scan operation.

## 17. Demo Fixture and Script

### 17.1 Fixture

Prepare an attachable NTFS VHD for repeatable judging. It is a test/demo artifact,
not bundled into the normal portable ZIP.

The fixture must contain physically allocated data sufficient to guarantee:

- at least 5 GB of cleanup candidates across known cache/temp/log/crash rules;
- a protected source repository with generated subdirectories;
- protected personal photos/documents;
- review-required Recycle Bin-like data;
- application-owned cache and installed-application-like primary data;
- system-managed and unknown areas;
- a known text log eligible for approval;
- optional duplicate groups when duplicate analysis is present.

Do not use sparse fixture files when validating the 5 GB allocated-space promise.
Generate a smaller fast UI fixture separately for ordinary automated tests.

### 17.2 Hero Script

1. Scan the prepared NTFS fixture and show stable completion.
2. Briefly link table, extension view, and treemap selections.
3. Invoke: "Free 5 GB without touching projects, photos, or installed apps."
4. Show the agent's bounded tool activity and the deterministic Plan tab.
5. Point out conservative versus review potential totals and protected evidence.
6. Ask why one candidate is safe and show its exact rule evidence.
7. Select an analyzer item, attach its visible metadata chip, and ask about it.
8. Say "Never suggest this folder again" and approve the persistent protection.
9. Optionally approve a bounded known-log excerpt.
10. Separately scan a real NTFS volume to demonstrate authentic speed and compare
    the recorded benchmark with WizTree.

## 18. Packaging and Release

- Produce a portable ZIP, not an installer or single EXE.
- Include the main executable, elevated helper, required resources, licenses,
  third-party notices, and concise prerequisites.
- Do not bundle Ollama, models, the demo VHD, or WebView2 installers.
- Detect missing WebView2/Ollama and guide the user to official sources.
- The first milestone is unsigned. Test and document SmartScreen and UAC behavior;
  do not pretend Unknown Publisher can be eliminated without a certificate.
- Build metadata, executable names, window title, docs, and ZIP use ClutterHunter.
- Reproducible release notes include dependency versions, rule/catalog versions,
  benchmark results, known limitations, and hashes for ZIP contents.

## 19. Implementation Sequence

### Phase 0: Documentation and Skeleton

- Make this document the product/source-of-truth plan.
- Tighten `Idea.md` into a concise product brief and keep `References.md` as a
  researched source index.
- Scaffold Tauri 2 + React 19 + Vite with TypeScript 7 and a Cargo workspace.
- Add strict formatting/type/clippy/test checks without replacing generated
  `package.json` scripts beyond what project instructions allow.
- Generate and validate the first Rust/TypeScript DTO binding.

Exit: clean build/test shell, documented architecture, portable hello-world build.

### Phase 1: Scanner and Performance Spike

- Implement backend trait, helper protocol, UAC launch, named pipe, raw MFT scan,
  traversal fallback, cancellation, compact arena, aggregation, and warnings.
- Build differential fixtures and five-million-entry in-memory stress fixture.
- Prove `ntfs-reader` correctness or replace it behind the adapter.
- Establish benchmark and memory reporting before UI complexity accumulates.

Exit: accurate stable ScanSummary and queryable arena within target trajectory.

### Phase 2: Analyzer and Policy

- Implement paged queries, search, aggregates, bounded treemap, linked analyzer UI,
  ownership index, policy rules/evidence, protected settings, and deterministic
  cleanup planner.
- Complete no-AI hero workflow first.

Exit: polished analyzer and editable conservative plan with Ollama switched off.

### Phase 3: Local Agent

- Add loopback HTTP capability, Ollama discovery, bundled model catalog, hardware
  fit, harness cache, AI SDK provider, agent loop, bounded tools, activity trace,
  typed result registry, approvals, log excerpts, and plan refinement.

Exit: prepared light/balanced models pass harness and hero latency/correctness.

### Phase 4: Hardening and Demo

- Add real/synthetic benchmarks, privacy capture, full Playwright coverage,
  packaged Windows smoke tests, accessibility, failure UX, and visual polish.
- Create fixture generator/VHD instructions and rehearse the fixed hero script.
- Implement duplicate analysis only after all earlier exit criteria pass.

Exit: unsigned portable ZIP and recorded acceptance evidence.

## 20. Failure Behavior

- Elevation declined: explain and offer traversal; no repeated UAC loop.
- Raw scan fails: discard partial raw index before fallback; never merge uncertain
  backend results into a supposedly complete scan.
- Helper crashes/protocol fails: terminate session safely and preserve the prior
  completed scan.
- Scan changes during enumeration: mark potentially stale and offer Rescan.
- Unsupported whole volume: reject before UAC or long work.
- Memory pressure: abort cleanly with measured counts and guidance rather than
  allowing the OS to terminate the app.
- Ollama missing: analyzer and deterministic plan remain available.
- Ollama disconnects mid-turn: stop the loop, keep session plan/chat UI state, and
  offer Retry after reconnection.
- Model fails harness/runtime schema repeatedly: disable it as incompatible; do not
  silently downgrade to untooled chat.
- Approval denied: return a normal denied tool result and continue safely.
- Plan target cannot be met: report exact conservative shortfall and keep review
  potential separate.

Only one scan, one heavy analysis job, and one active model generation run at a
time. All three are cancellable.

## 21. Locked Decisions and Engineering Defaults

Locked product decisions:

- Analyzer-first first screen and explicit Scan button.
- MFT first for NTFS volumes and folders; visible traversal fallback.
- Non-NTFS whole volumes rejected; selected folders allowed via traversal.
- Five-million-entry target, usable-view benchmark endpoint, and about 1.2 GB
  combined analyzer memory budget.
- No filesystem mutations in v1.
- Both policy tiers in Plan; only cleanup candidates selected by default.
- Separate totals, never a blended reclaimable headline.
- Deterministic no-AI cleanup fallback.
- Persistent protected paths; agent policy change requires approval.
- Model harness automatic and cached.
- Bundled ranked catalog, no background catalog fetch, no in-app pulling.
- Custom loopback Ollama port only; cloud/LAN models rejected.
- Full paths may be sent to the selected local model.
- Log-only bounded content inspection with per-request approval.
- Recycle Bin is review-required.
- Projects protected unless directly named; whole project becomes one review item.
- AI dock remembers state; Plan is a separate dock tab; navigation is user-driven.
- Session-only plan with no export.
- Portable ZIP, unsigned, prepared demo machine.
- Exact duplicates are first cut.

Engineering defaults chosen to make implementation decision-complete:

- Rust arena and Tauri query boundary, not a full-tree JSON transfer.
- Separate elevated helper with named pipe, nonce, PID validation, Bincode 2.
- `ts-rs` generated DTOs; no prerelease binding framework.
- AI SDK 7 first-party OpenAI-compatible provider through Tauri native fetch.
- Eight-step agent cap, bounded result sizes, 8K effective demo context.
- D3 hierarchy plus Canvas treemap, virtualized table, neutral multi-hue UI.
- No telemetry and redacted operational logs.
- App-bundled policies/catalogs update only with releases.

The only remaining choices are empirical validation results, not product design:

- whether `ntfs-reader` passes the accuracy/performance spike;
- which exact light and balanced model tags pass the harness on the prepared PC;
- whether duplicate analysis fits after all release gates pass.

## 22. Primary Technical References

- [WizTree FAQ and elevation behavior](https://diskanalyzer.com/faq)
- [WizTree product overview](https://diskanalyzer.com/)
- [Windows FSCTL_ENUM_USN_DATA](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_enum_usn_data)
- [ntfs-reader repository](https://github.com/kikijiki/ntfs-reader)
- [EDirStat reference implementation](https://github.com/xangelix/edirstat)
- [Tauri with Vite](https://v2.tauri.app/start/frontend/vite/)
- [Tauri command channels](https://v2.tauri.app/develop/calling-rust/)
- [Tauri HTTP client](https://v2.tauri.app/plugin/http-client/)
- [TypeScript 7 announcement](https://devblogs.microsoft.com/typescript/announcing-typescript-7-0/)
- [React versions](https://react.dev/versions)
- [ts-rs documentation](https://docs.rs/crate/ts-rs/latest)
- [AI SDK ToolLoopAgent](https://ai-sdk.dev/docs/reference/ai-sdk-core/tool-loop-agent)
- [AI SDK tools and approval](https://ai-sdk.dev/docs/ai-sdk-core/tools-and-tool-calling)
- [AI SDK loop control](https://ai-sdk.dev/docs/agents/loop-control)
- [AI SDK OpenAI-compatible provider](https://ai-sdk.dev/providers/openai-compatible-providers)
- [AI SDK environment compatibility](https://ai-sdk.dev/docs/getting-started/navigating-the-library)
- [Ollama OpenAI compatibility](https://docs.ollama.com/api/openai-compatibility)
- [Ollama tool calling](https://docs.ollama.com/capabilities/tool-calling)
- [Ollama model details API](https://docs.ollama.com/api-reference/show-model-details)
- [Ollama installed model API](https://docs.ollama.com/api/tags)
- [Ollama local/cloud privacy FAQ](https://docs.ollama.com/faq)
- [Qwen 3.5 model catalog](https://ollama.com/library/qwen3.5/tags)
- [LFM 2.5 Thinking](https://ollama.com/library/lfm2.5-thinking)
- [FunctionGemma limitations](https://registry.ollama.com/library/functiongemma)
- [ai-sdk-ollama malicious-version advisory](https://security.snyk.io/vuln/SNYK-JS-AISDKOLLAMA-17146454)
- [D3 treemap](https://d3js.org/d3-hierarchy/treemap)
- [Tambo self-hosting requirements, evaluated and rejected for v1](https://docs.tambo.co/guides/self-hosting)
