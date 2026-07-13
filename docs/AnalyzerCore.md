# Analyzer Core Notes

Status: Rust analyzer and proposal-only policy/planner verified; UI integration pending  
Last updated: 2026-07-14

This file records the implemented Phase 2 Rust boundary. The durable product and
safety contract remains [ProductPlan.md](ProductPlan.md).

## Implemented Session Model

Each completed scan owns a compact `ScanArena` plus an `AnalyzerIndex`. The index
stores one compact rule and owner reference per node; it does not duplicate full
paths. The Tauri webview receives bounded DTOs rather than the arena.

Implemented commands:

- `query_items`: direct children or recursive scoped search with kind, extension,
  policy, owner, minimum allocation, and modified-time filters; seven stable sort
  modes; query-fingerprinted scan-local cursors; maximum 100 rows. Optional
  `query_id` values support explicit `cancel_item_query` calls, and a new scan
  cancels every outstanding query.
- `get_item_details`: the row plus deterministic policy evidence.
- `get_storage_aggregate`: bounded extension, owner, policy, or kind buckets with
  explicit `Other` totals.
- `get_treemap_slice`: at most 5,000 immediate weighted children plus a synthetic
  deterministic `Other` node.
- `build_cleanup_plan` and `edit_cleanup_plan`: deterministic grouped proposals,
  separate candidate/review totals, target shortfall, edit-time node/tier
  revalidation, and a hard 500-item output limit with explicit omitted counts and
  byte totals.
- `set_path_protection` and `dismiss_suggestion`: current-session reclassification
  plus durable local settings in
  `%LOCALAPPDATA%\ClutterHunter\policy-settings.json`. Protection identities use
  volume identity plus relative path when available, migrate legacy absolute
  paths, and save through a flushed atomic replacement bounded to 1 MiB.

All byte counts remain decimal strings across IPC. Generated `ts-rs` bindings are
checked into `src/bindings`.

## Ownership

The ownership index reads exact install locations from HKLM/HKCU uninstall keys
in both registry views, enumerates AppX packages with Windows
`PackageManager`, enriches display names where Windows exposes them, and includes
narrow known mappings for Windows, Ollama, and Scoop roots. The AppX registry is
a fallback when WinRT enumeration is unavailable. Exact roots are facts;
inherited longest-prefix relationships are labelled as prefix inference.

Ownership does not grant cleanup authority. Installed application and shared
Ollama blob storage remain protected. Planner actions preserve owner-native
boundaries such as `run_ollama_rm`, `run_scoop_cache`, Windows Apps settings, and
Windows Storage settings; this milestone does not execute them.

## Policy Precedence

The bundled rule set is intentionally narrow:

1. user protection, personal data, source/VCS data, system paths, application
   installs, shared Ollama blobs, and unknown data are protected;
2. generated project data, Recycle Bin content, and Ollama model decisions require
   review;
3. only exact user-temp, browser-cache, crash-report, npm-cache/log, and
   Scoop-cache roots can be cleanup candidates;
4. partial or potentially stale coverage downgrades cleanup candidates and blocks
   plan selection.

Candidate grouping is subtree-safe. A directory is proposed as one opportunity
only when every contributing descendant has the same candidate rule. A protected
photo or source file inside a cache/temp tree is excluded rather than hidden in
the parent reclaim total.

Dismissals use canonical path plus rule ID. Built-in protections cannot be
weakened by settings. Plans remain proposals only: no delete, recycle, uninstall,
shell, or arbitrary command execution exists in the analyzer.

## Measurements

The release-mode five-million-entry synthetic gate on 2026-07-14 measured:

- compact arena plus analyzer side tables: `370,000,065` bytes;
- first-view state including the bounded sort cache: `390,000,065` bytes;
- policy/ownership classification: `5,784` ms;
- first 50 results from a five-million-match bounded search: `200` ms;
- first navigation sort: `159` ms; cached repeat: below the millisecond timer;
- aggregate: `177` ms; bounded treemap: `73` ms; and
- bounded 500-item cleanup plan: `2,026` ms.

These are deterministic synthetic, warm, single-run measurements, not the final
whole-application benchmark. Registry owner strings, allocator overhead, Tauri,
the webview, and Ollama are outside the arena estimate. Current-machine ownership
discovery also passed with 275 roots: 62 Win32 registry, 210 AppX, and 3 known
roots. The production frontend, Rust workspace, clippy, MSI, and NSIS builds pass.

The real `C:` warm usable-view gate now has three complete runs: `18,484`,
`18,074`, and `18,035` ms from elevation completion through raw scan,
ownership/policy classification, stable summary, and first-query readiness. The
median is `18,074` ms. Its first 50-row allocated-size query was below the
millisecond timer, and arena plus analyzer state was about `664` MB for 7.30
million entries. The raw phase's sampled concurrent host/helper peak was `1.275`
GB at 7.30 million entries, or about `873` MB when normalized to the five-million-
entry product target.

## Remaining Item 5 Hardening Gates

- Preserve the passing elevated differential, warm median, and concurrent memory
  gates. Record three cold-cache usable-view runs after a controlled cache reset
  or reboot; do not relabel warm runs as cold.
- Capture a controlled same-volume WizTree comparison. Computer Use launched the
  installed app, but Windows Graphics Capture failed with
  `SetIsBorderRequired ... 0x80004002`, so the user's earlier 21.00-second
  observation remains contextual rather than controlled evidence.
- Repeat unsigned Windows security behavior from an installed package, including
  inaccessible registry/package records. Current protocol-v10 MSI/NSIS builds,
  extracted-sidecar hash validation, and release GUI launch pass. Computer Use's
  native transport was unavailable for the final packaged-window repetition, so
  that visual/UAC recording remains item 5 evidence rather than an item 2 defect.
- Complete the analyzer UI slices in implementation-order item 3. Existing bounded
  commands already back the first view and local-agent tools.
