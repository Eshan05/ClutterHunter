• ClutterHunter V1 Plan

  Product Contract

  - A private, evidence-based storage agent, not merely a disk visualizer with chat.
  - Analyzer works fully without Ollama. AI investigates, explains, refines, and operates the cleanup-plan workflow.
  - Windows 10/11 x64. Whole-volume scans support NTFS only; selected non-NTFS folders may use labeled traversal.
  - No filesystem deletion, uninstall, recycle, or modification in v1.
  - Scan index, chat, and cleanup plan remain session-only. Protected paths, model choice, harness results, and UI preferences persist locally.
  - Safety tiers are deterministic: protected, review-required, and cleanup-candidate. The model cannot promote an item into the safe tier.

  Architecture

  - Tauri 2, Rust, React 19, Vite, and stable TypeScript 7.0.2. TypeScript 7 (https://devblogs.microsoft.com/typescript/announcing-typescript-7-0/)
  - Main application remains non-elevated. A narrowly scoped scanner helper requests elevation and performs read-only MFT enumeration.
  - The helper communicates through a current-user-restricted Windows named pipe using versioned, length-prefixed binary batches. It exposes no general filesystem commands.
  - Prefer ntfs-reader behind a ScanBackend adapter; validate its output against Windows APIs and traversal fixtures before committing to it.
  - Rust retains a compact in-memory arena for up to five million entries. The webview receives paginated queries, aggregates, and bounded treemap slices rather than the complete tree.
  - Scan completeness includes stable hierarchy, allocated/logical totals, coverage warnings, policy tiers, and an interactive first view.
  - Correctness rules include hard-link accounting, no reparse-point traversal, compressed/sparse allocation, inaccessible-path warnings, and filesystem-change detection.
  - Generate checked TypeScript DTOs from Rust using stable ts-rs; fail CI on binding drift.

  Analyzer And Policy

  - Explicit Scan button with the system drive preselected. Fast mode explains MFT access before UAC.
  - Failed or declined elevation shows an alert and falls back to ordinary traversal.
  - Allocated size is primary; logical size is secondary.
  - Dense virtualized tree/table, linked canvas treemap, extension summary, breadcrumbs, search, filters, sortable columns, cancellation, and rescan.
  - Right AI dock remembers its state. It contains separate Chat and Plan tabs; agent results require an explicit Show in analyzer action.
  - Optional cleanup target input, such as 5 GB. Safe candidates are preselected; review-required items are included unchecked with a separate potential total.
  - Built-in rules cover known caches, temporary data, logs, and crash artifacts. Rules change only with reviewed app releases.
  - Projects are protected by default. Generated folders are review-required; a whole project becomes a review item only after direct user intent.
  - Personal files, applications, Recycle Bin contents, duplicates, and system-managed storage remain review-required.
  - Application attribution uses registry, AppX, known roots, and clearly labeled inference. Ownership never implies that an app is unused.
  - Persistent user protections can only strengthen policy and require approval when proposed through chat.

  On-Device Agent
  - Use first-party @ai-sdk/openai-compatible with Tauri’s scoped native fetch, targeting only 127.0.0.1:<port>/v1. Ollama officially supports streaming and tools there. AI SDK provider
    (https://ai-sdk.dev/providers/openai-compatible-providers), Ollama compatibility (https://docs.ollama.com/api/openai-compatibility)

    harness passes.

  - Bundle a ranked offline catalog. Rank by tool reliability, hardware headroom, context, measured latency, and curated quality.
  - Target the actual demo machine: 8 GB RAM and GTX 1650. Begin validation with approximately 1.2B “Light” and 2B “Balanced” models.
  - Tools cover overview, bounded item queries, aggregates, evidence, deterministic plan generation/editing, completed duplicate results, approved log excerpts, and protected-path
  - Log inspection is limited to approved known text logs, exact displayed paths, and strict byte limits; content cannot affect safety classification.
  - Hide raw reasoning. Show tool name, purpose, result count, timing, approval state, and errors.
  - Bound loops to eight steps, cap tool results, support cancellation, and retain only recent chat plus compact session summaries.

  Implementation Order

  1. Tighten docs: product specification, v1 scope, safety policy, architecture, benchmark contract, demo script, and updated references.
  2. Scaffold the TypeScript 7/Tauri workspace and prove MFT scanning, elevated-helper isolation, fallback traversal, bindings, and the five-million-entry memory model.
  3. Build the analyzer workspace, policy engine, application ownership, protected paths, and deterministic cleanup plan.
  4. Add loopback Ollama discovery, ranked model setup, synthetic harness, AI SDK tools, chat cards, approvals, and plan refinement.
  5. Harden the portable ZIP, visual polish, fixture/demo flow, accessibility, security review, and benchmarks. Duplicate hashing lands last and is the first scope cut.

  Acceptance

  - Five-million-entry scan reaches a stable usable analyzer within 2x WizTree on the same target and hardware, excluding user UAC time.
  - Combined Rust process and webview peak around 1.2 GB or less.
  - Prepared NTFS fixture guarantees at least 5 GB of conservative candidates plus protected projects, personal data, apps, Recycle Bin data, and review opportunities.
  - Demonstrate the fixture workflow and separately compare real-volume scan speed.
  - Balanced demo model shows visible output within five seconds and completes a typical one-to-three-tool turn within thirty seconds.
  - Rust tests cover scan aggregation, policies, hard links, reparse points, partial scans, ownership, plan validation, and helper protocol.
  - TypeScript tests cover tools, model gating, approvals, context limits, and deterministic fallback.
  - Playwright tests use mocked Tauri APIs for scan, analyzer, chat, plan, Ollama-missing, incompatible-model, and narrow-window workflows.
  - Release is an unsigned portable ZIP containing ClutterHunter, the helper, resources, licenses, and documented SmartScreen/UAC expectations.

  Deferred
  Deletion, Recycle Bin emptying, uninstall execution, persisted scans, plan export, live USN updates, OCR, images, PDFs, Office parsing, embeddings, semantic search, LAN/cloud AI, non-
  NTFS volume scans, multiple simultaneous scans, drivers, and raw chain-of-thought.