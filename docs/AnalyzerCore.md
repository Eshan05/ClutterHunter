# Analyzer Core Notes

Status: Rust analyzer and proposal-only policy/planner implemented; UI integration pending  
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
  modes; opaque scan-local cursors; maximum 100 rows.
- `get_item_details`: the row plus deterministic policy evidence.
- `get_storage_aggregate`: bounded extension, owner, policy, or kind buckets with
  explicit `Other` totals.
- `get_treemap_slice`: at most 5,000 immediate weighted children plus a synthetic
  deterministic `Other` node.
- `build_cleanup_plan` and `edit_cleanup_plan`: deterministic grouped proposals,
  separate candidate/review totals, target shortfall, and edit-time node/tier
  revalidation.
- `set_path_protection` and `dismiss_suggestion`: current-session reclassification
  plus durable local settings in
  `%LOCALAPPDATA%\ClutterHunter\policy-settings.json`.

All byte counts remain decimal strings across IPC. Generated `ts-rs` bindings are
checked into `src/bindings`.

## Ownership

The ownership index reads exact install locations from HKLM/HKCU uninstall keys
in both registry views, reads installed AppX package identities from the Windows
AppX registry store, and includes narrow known mappings for Windows, Ollama, and
Scoop roots. Exact roots are facts; inherited longest-prefix relationships are
labelled as prefix inference.

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
3. only exact user-temp, browser-cache, crash-report, and Scoop-cache roots can be
   cleanup candidates;
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
- policy/ownership classification: `3.276-3.425` seconds across recorded runs;
- first 50 results from a five-million-match bounded search: `205-249` ms after
  removing per-node lowercase allocation; and
- the earlier arena-only adoption gate: `340,000,059` bytes and `523` ms.

These are deterministic synthetic, warm, single-run measurements, not the final
whole-application benchmark. Registry owner strings, allocator overhead, Tauri,
the webview, and Ollama are outside the arena estimate. The elevated real-volume
benchmark still needs a clean rerun after Windows Computer Use/elevation becomes
available following the reboot.

## Remaining Gates Before UI Integration

- Run the ignored elevated raw-versus-traversal folder fixture and record explained
  allocation differences for sparse/compressed/reparse/ADS cases.
- Record median cold/warm full-volume runs through the usable analyzer endpoint,
  including journal coverage, classification, first query, and combined process
  working sets.
- Validate registry and AppX ownership samples on the packaged app, including
  inaccessible registry/package records.
- Add AppX display-name enrichment where Windows exposes it without weakening the
  exact package-root fact.
- Wire these bounded commands into the analyzer UI only after the Rust gates are
  accepted.
