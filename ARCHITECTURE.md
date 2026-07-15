# ClutterHunter Architecture

ClutterHunter is a Windows desktop storage analyzer with a read-only Rust data
plane and an optional on-device AI control plane. Rust owns filesystem facts,
policy, and cleanup-plan construction. React owns presentation and interaction.
The local model can request bounded evidence but cannot read the filesystem or
change safety classifications itself.

## System Map

```mermaid
flowchart TB
  subgraph StandardUser["Standard user process"]
    subgraph WebView["React 19 WebView"]
      App["App.tsx<br/>scan controls and session shell"]
      Workspace["AnalyzerWorkspace<br/>table, search, extensions, Plan"]
      Treemap["TreemapCanvas<br/>bounded SVG hierarchy"]
      Dock["AgentDock<br/>model setup, chat, typed results"]
      Runtime["AI SDK 7 runtime<br/>routing, tools, budgets, approvals"]
    end

    subgraph TauriHost["Tauri v2 host"]
      Commands["commands.rs<br/>typed IPC boundary"]
      State["ScannerState<br/>active scan, completed scan, queries, plan, settings"]
      Core["clutter-core<br/>arena, analyzer, ownership, policy"]
      HttpPlugin["tauri-plugin-http"]
      OpenerPlugin["tauri-plugin-opener"]
    end
  end

  subgraph ElevatedProcess["Elevated helper process"]
    Helper["clutter-scanner-helper<br/>read-only raw NTFS scanner"]
  end

  subgraph Windows["Windows and local services"]
    NTFS[("NTFS volume metadata")]
    Registry["Win32 uninstall registry"]
    AppX["AppX PackageManager"]
    Settings[("Local policy settings")]
    Ollama["Ollama<br/>127.0.0.1 only"]
    Explorer["Windows Explorer"]
  end

  App --> Workspace --> Treemap
  App --> Dock --> Runtime
  App -->|"Tauri invoke + progress Channel"| Commands
  Workspace -->|"bounded queries"| Commands
  Runtime -->|"bounded tool invokes"| Commands
  Commands <--> State
  State <--> Core
  Commands <-->|"authenticated named pipes"| Helper
  Helper -->|"read metadata"| NTFS
  Core --> Registry
  Core --> AppX
  Commands <--> Settings
  Runtime <--> HttpPlugin
  HttpPlugin <-->|"native local chat"| Ollama
  Workspace --> OpenerPlugin -->|"reveal selected path"| Explorer
```

### Trust Boundaries

| Boundary | Allowed | Not allowed |
| --- | --- | --- |
| React WebView to Tauri | Registered typed commands and progress channels | Direct raw-volume access or arbitrary native calls |
| Tauri host to helper | Versioned scan protocol, bounded frames, progress, cancellation | General elevated command execution |
| Agent to analyzer | Schema-validated, session-bound, bounded evidence tools | Raw arena access, arbitrary file reads, shell, writes, or deletion |
| Agent to Ollama | Numeric port on `127.0.0.1` | LAN, remote, cloud, redirected, or credential-bearing endpoints |
| Policy to Plan | Deterministic tiers, reasons, warnings, and grouped proposals | Model-created eligibility or silent protection bypass |

## Source Ownership

| Area | Primary files | Responsibility |
| --- | --- | --- |
| Application shell | `src/App.tsx` | Target discovery, scan lifecycle, progress, summary, dock visibility |
| Analyzer UI | `src/AnalyzerWorkspace.tsx` | Bounded navigation, virtual rows, search, sorting, selection, aggregates, Plan |
| Treemap | `src/analyzer/treemap.ts`, `src/analyzer/TreemapCanvas.tsx` | Convert bounded Rust slice into linked SVG hierarchy |
| Agent UI | `src/AgentDock.tsx` | Ollama setup, chat, approvals, result cards, Plan handoff |
| Agent runtime | `src/agent/runtime.ts` | Intent routing, AI SDK loop, context, tool selection, streaming, cancellation |
| Agent tools | `src/agent/tools.ts` | Zod schemas, scope resolution, budgets, Tauri analyzer calls |
| Ollama boundary | `src/agent/endpoint.ts`, `ollama.ts`, `harness.ts`, `catalog.ts` | Loopback enforcement, discovery, preflight, compatibility, model ranking |
| Generated IPC types | `src/bindings/*` | TypeScript DTOs generated from Rust with `ts-rs` |
| Tauri commands | `src-tauri/src/commands.rs` | Native API, shared state, session checks, settings persistence |
| Scan core | `src-tauri/crates/clutter-core/src/backend.rs`, `arena.rs` | Backend selection, compact arena construction/adoption, scan summary |
| Analyzer core | `src-tauri/crates/clutter-core/src/analyzer.rs` | Queries, indexes, ownership links, policy, aggregates, treemap, plans |
| Traversal backend | `src-tauri/crates/clutter-core/src/traversal.rs` | Read-only filesystem traversal fallback |
| Raw helper host | `src-tauri/crates/clutter-core/src/raw_snapshot.rs` | Helper launch, authenticated pipes, frame validation, cancellation |
| Raw helper | `src-tauri/crates/clutter-scanner-helper/src/raw_mft.rs` | MFT reads, NTFS parsing, hierarchy and allocation accounting |
| Shared protocol | `src-tauri/crates/clutter-protocol/src/lib.rs` | Protocol version, flags, frames, raw arena DTOs, validation constants |

## Scan Pipeline

```mermaid
sequenceDiagram
  autonumber
  actor User
  participant UI as App.tsx
  participant Cmd as start_scan command
  participant State as ScannerState
  participant Backend as clutter-core backend
  participant Helper as Elevated helper
  participant Disk as NTFS volume
  participant Analyzer as AnalyzerIndex

  User->>UI: Select target and press Scan
  UI->>Cmd: start_scan(request, progress Channel)
  Cmd->>State: reserve active session and cancellation token
  Cmd->>Backend: spawn_blocking run_scan(...)

  alt Raw NTFS backend
    Backend->>Helper: launch with target, nonce, and named pipes
    Helper-->>Backend: protocol version, nonce, PID, target
    Helper->>Disk: read boot sector, MFT data runs, and journal position
    loop overlapped MFT blocks
      Helper->>Disk: read metadata block
      Helper-->>UI: entries and allocated-byte progress
    end
    Helper->>Helper: aggregate hierarchy and pack names
    Helper-->>Backend: bounded sequenced arena frames
    Backend->>Backend: validate and adopt RawArenaSnapshot
  else Traversal backend
    Backend->>Disk: enumerate without following reparse points
    Backend->>Backend: normalize hard-link allocation and build ScanArena
    Backend-->>UI: traversal progress and warnings
  end

  Backend->>Analyzer: build ownership and deterministic policy indexes
  Cmd->>Cmd: apply persisted analyzer settings
  Cmd->>State: atomically replace completed ScanOutput and clear old Plan
  Cmd-->>UI: stable ScanSummary
```

Raw NTFS and traversal both produce the same `ScanOutput`. Backend differences are
preserved in `ScanSummary`, coverage, and warnings rather than hidden from the UI.

## Scan Session State

Only one scan runs at a time. A completed scan is immutable to readers except for
explicit policy-setting reclassification. Starting a replacement scan does not
discard the previous completed result.

```mermaid
stateDiagram-v2
  [*] --> NoCompletedScan
  NoCompletedScan --> FirstScanActive: start_scan
  FirstScanActive --> CompletedScan: success
  FirstScanActive --> NoCompletedScan: cancel or failure

  CompletedScan --> ReplacementActive: rescan or new target
  ReplacementActive --> CompletedScan: cancel or failure / keep old result
  ReplacementActive --> CompletedScan: success / atomically install new result

  FirstScanActive --> FirstScanActive: progress Channel updates
  ReplacementActive --> ReplacementActive: progress Channel updates
  CompletedScan --> CompletedScan: bounded query or Plan edit
```

Every analyzer request carries the completed `session_id`. Stale node IDs,
cursors, plans, and AI attachments are rejected instead of being interpreted
against another scan.

## In-Memory Data Model

```mermaid
classDiagram
  class ScannerState {
    active: Option~ActiveScan~
    completed: Option~ScanOutput~
    queries: Map~QueryKey, CancelToken~
    plan: Option~CleanupPlan~
    settings: AnalyzerSettings
  }

  class ActiveScan {
    session_id: String
    cancel: AtomicBool
  }

  class ScanOutput {
    arena: ScanArena
    analyzer: AnalyzerIndex
    summary: ScanSummary
  }

  class ScanArena {
    session_id: String
    root_path: PathBuf
    nodes: Vec~RawArenaNode~
    names: Vec~u8~
  }

  class RawArenaNode {
    name_offset: u32
    name_length: u32
    parent: u32
    first_child: u32
    next_sibling: u32
    logical_bytes: u64
    allocated_bytes: u64
    flags: u16
  }

  class AnalyzerIndex {
    coverage: ScanCoverage
    rules: Vec~Rule~
    owners: Vec~OwnerRecord~
    node_owners: Vec~u32~
    user_protected: Vec~bool~
    sort_cache: bounded LRU
  }

  class ScanSummary {
    session_id: String
    backend: ScanBackend
    coverage: ScanCoverage
    entry_count: decimal String
    allocated_bytes: decimal String
    warnings: Vec~ScanWarning~
  }

  class CleanupPlan {
    items: Vec~PlanItem~
    selected_candidate_bytes: decimal String
    review_potential_bytes: decimal String
    shortfall_bytes: decimal String
  }

  class AnalyzerSettings {
    protected_paths
    dismissed_suggestions
  }

  ScannerState o-- ActiveScan
  ScannerState o-- ScanOutput
  ScannerState o-- CleanupPlan
  ScannerState *-- AnalyzerSettings
  ScanOutput *-- ScanArena
  ScanOutput *-- AnalyzerIndex
  ScanOutput *-- ScanSummary
  ScanArena *-- RawArenaNode
  AnalyzerIndex --> ScanArena: aligned node indexes
```

The arena stores fixed-size nodes and one packed UTF-8 name pool. Parent, child,
and sibling relationships are `u32` indexes. `AnalyzerIndex` stores aligned rule
and owner references rather than duplicating full paths for every item.

All byte counts cross IPC as decimal strings, avoiding JavaScript integer
precision loss on large volumes.

## Bounded Analyzer Queries

```mermaid
flowchart LR
  Request["ItemQuery / aggregate / treemap / plan request"]
  Session{"session_id matches?"}
  Scope["Resolve node and validate cursor"]
  Filter["Apply kind, text, extension, policy, owner, size, and time filters"]
  Rank{"Query mode"}
  Direct["Immediate children<br/>cached stable sort"]
  Search["Recursive search<br/>cancellable traversal"]
  TopN["Recursive largest<br/>bounded top-N heap"]
  DTO["Bounded DTO"]
  Reject["Typed ScanFailure"]

  Request --> Session
  Session -->|No| Reject
  Session -->|Yes| Scope --> Filter --> Rank
  Rank -->|Navigate| Direct
  Rank -->|Search| Search
  Rank -->|Largest| TopN
  Direct --> DTO
  Search --> DTO
  TopN --> DTO
```

Core response bounds:

- item pages: at most 100 rows;
- recursive top-N: retains at most the requested 100 results;
- treemap: at most 5,000 largest file leaves plus required ancestors;
- cleanup Plan: at most 500 returned items with explicit omitted totals;
- log inspection: at most 5 approved files, 64 KiB each, 256 KiB total.

The browser never receives the complete scan tree.

## Policy and Planning

Policy is deterministic and evaluated in Rust. "Not suggested" is an AI/planner
classification, not a filesystem permission.

```mermaid
flowchart TD
  Facts["Path, type, extension, owner, attributes, coverage, user settings"]
  UserProtect{"User-protected path?"}
  HardProtect{"System, personal/source data, install root, shared blob, or unknown?"}
  Review{"Generated project data, Recycle Bin, model decision, or managed area?"}
  Candidate{"Exact known temp, cache, log, or crash rule?"}
  Coverage{"Coverage complete and stable?"}

  Protected["Not suggested<br/>excluded from automatic proposal"]
  ReviewTier["Ask first<br/>unchecked review potential"]
  CandidateTier["Suggested<br/>selected conservative opportunity"]
  Group["Subtree-safe grouping<br/>same rule across contributing descendants"]
  Plan["Editable session CleanupPlan"]

  Facts --> UserProtect
  UserProtect -->|Yes| Protected
  UserProtect -->|No| HardProtect
  HardProtect -->|Yes| Protected
  HardProtect -->|No| Review
  Review -->|Yes| ReviewTier
  Review -->|No| Candidate
  Candidate -->|No| Protected
  Candidate -->|Yes| Coverage
  Coverage -->|No| ReviewTier
  Coverage -->|Yes| CandidateTier
  CandidateTier --> Group --> Plan
  ReviewTier --> Plan
```

Size ranks opportunities only after policy eligibility is known. It never turns
an arbitrary large directory into a cleanup candidate. Installed applications,
Ollama models, Scoop data, and Windows-managed storage retain owner-native action
metadata instead of being represented as direct file deletion.

## Local Agent Flow

```mermaid
sequenceDiagram
  autonumber
  actor User
  participant Dock as AgentDock
  participant Runtime as OllamaAgentRuntime
  participant Router as Deterministic router
  participant Model as Local Ollama model
  participant Tools as Analyzer tools
  participant IPC as Tauri commands
  participant Core as AnalyzerIndex

  User->>Dock: Ask about the active scan
  Dock->>Runtime: prompt + workflow + trusted attachment
  Runtime->>Router: classify common factual intent and scope

  alt Common ranked storage query
    Router->>Tools: execute exact bounded query
    Tools->>IPC: invoke with active session_id
    IPC->>Core: query deterministic index
    Core-->>Tools: bounded typed DTO
    Tools-->>Dock: authoritative answer + typed card
  else Investigation or explanation
    Runtime->>Model: recent bounded context and tool schemas
    Model-->>Runtime: prose delta or tool request
    Runtime->>Runtime: require intent-matched evidence tool
    Runtime->>Tools: schema-validated call
    Tools->>IPC: bounded session query
    IPC->>Core: read facts or construct proposal
    Core-->>Tools: typed evidence envelope
    Tools-->>Runtime: capped tool result
    Runtime->>Model: evidence for concise explanation
    Model-->>Dock: streamed answer
    Runtime-->>Dock: typed activity and result cards
  end
```

### Agent Controls

- Installed models must be local, have a stable digest, report tool capability,
  pass native preflight, and pass the compatibility harness.
- Common factual questions use deterministic routing where possible, removing the
  model as a correctness dependency.
- Other factual turns require an intent-matched evidence tool. Unrelated tools are
  closed after that evidence call so a speculative second query cannot replace it.
- Tool results are capped at 12 KiB each and 32 KiB per turn.
- Recent context is limited to 12 messages and 24,000 characters; older text is
  reduced to a bounded deterministic session summary.
- Turns stop after bounded steps, output, time, and invalid-call repair limits.
- Log excerpts and path protection require explicit AI SDK approval.
- Result cards are selected by a fixed local component registry, never by
  model-generated component names or props.

## Tauri Command Surface

The registered native API is intentionally narrow:

| Group | Commands |
| --- | --- |
| Discovery | `list_scan_targets`, `get_hardware_profile` |
| Scan lifecycle | `start_scan`, `cancel_scan`, `get_scan_summary` |
| Analyzer | `query_items`, `cancel_item_query`, `get_item_details`, `get_storage_aggregate`, `get_treemap_slice` |
| Evidence | `inspect_log_excerpt`, `get_cleanup_opportunities` |
| Plan | `build_cleanup_plan`, `edit_cleanup_plan` |
| Policy settings | `set_path_protection`, `dismiss_suggestion` |

Commands validate the active session before using scan-local IDs. Expensive scans
and recursive queries run through Tauri's blocking runtime rather than blocking
the WebView event loop.

## Persistence

```mermaid
flowchart LR
  Persistent[("Persisted locally")]
  SessionOnly[("Session memory only")]
  NeverPersisted[("Not persisted")]

  Persistent --> ProtectedPaths["Protected path identities"]
  Persistent --> Dismissals["Dismissed suggestion keys"]
  Persistent --> HarnessCache["Model compatibility cache"]
  Persistent --> DockPreference["Dock open/collapsed preference"]

  SessionOnly --> ScanArenaState["ScanArena + AnalyzerIndex"]
  SessionOnly --> CleanupPlanState["Cleanup Plan"]
  SessionOnly --> AgentState["Agent session and trusted attachment"]

  NeverPersisted --> RawThinking["Raw model thinking"]
  NeverPersisted --> LogContent["Approved log content"]
  NeverPersisted --> FullScanExport["Full scan index export"]
```

Analyzer settings are written through a bounded, flushed atomic replacement in
the user's local application-data directory. Scan indexes, cleanup plans, and
chat sessions are discarded with the application session or when their binding
scan changes.

## Architectural Invariants

1. Rust is the source of truth for paths, sizes, ownership, policy, and plans.
2. One active scan and one completed immutable scan are retained at most.
3. Failed or cancelled replacement scans do not destroy the usable completed scan.
4. The WebView and the model receive bounded DTOs, never the raw arena.
5. Every scan-local reference is checked against the active session.
6. The fast helper is elevated; the main application and AI runtime are not.
7. Local inference is loopback-only and analyzer functionality does not depend on Ollama.
8. Policy evidence decides eligibility; size only ranks eligible opportunities.
9. No registered command or agent tool deletes, moves, recycles, uninstalls, or
   executes arbitrary code.

## Related Documentation

- [README](README.md)
- [Product specification](docs/ProductPlan.md)
- [Scanner architecture and measurements](docs/ScannerSpike.md)
- [Analyzer, policy, and planner notes](docs/AnalyzerCore.md)
- [Local agent notes](docs/LocalAgent.md)
