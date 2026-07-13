# Local Agent Notes

Status: implementation-order item 4 complete; packaged-window acceptance recorded separately  
Last updated: 2026-07-15

This file records implementation evidence for implementation-order item 4. The
durable privacy, tool, and model contracts remain in
[ProductPlan.md](ProductPlan.md#11-on-device-ai-architecture).

## Implemented Boundary

- AI SDK `7.0.26` `ToolLoopAgent` uses exactly pinned `ai-sdk-ollama` `4.0.0`
  against Ollama's native `/api/chat` stream. It uses the official `ollama-js`
  client underneath. No cloud provider, Node sidecar, or proxy service is present.
  The four known malicious `ai-sdk-ollama` releases (`0.13.1`, `1.1.1`, `2.2.1`,
  and `3.8.5`) are excluded; the lockfile pins `4.0.0` by integrity and passed the
  repository supply-chain policy.
- Tauri's HTTP plugin is compiled without default TLS/cookie features and scoped
  to `http://127.0.0.1:*`. Application code accepts only a numeric port,
  canonicalizes it to `127.0.0.1`, rejects host aliases/LAN/internet URLs and
  credentials, disables redirects, and verifies the response URL.
- Discovery reads `/api/version`, `/api/tags`, and `/api/ps`. A model is ineligible unless it
  has a 64-character digest, non-zero local blob size, plausible GGUF details,
  a non-cloud tag, and `/api/show` reports `tools` capability.
- Before real scan context, a native non-streaming `/api/chat` request uses only a
  synthetic prompt. Its response model must resolve to the selected installed
  model, while all non-message metadata is checked for cloud, remote-host,
  web-search, and offload evidence.
- A versioned four-scenario streaming harness tests overview plus named-folder
  scope/query, conservative versus review plan totals, empty-result honesty, and
  one bounded retry. Results cache by model digest, Ollama version, and harness
  version. Harness v5 uses the native
  production stream, records median first-token latency, accepts the same typed
  deterministic presentation used when a small model finishes a valid tool call
  without prose, and invalidates earlier
  OpenAI-compatible/non-streaming cache entries. A
  failed model cannot create a real agent session.
- The bundled offline catalog and deterministic ranker cover Light, Balanced,
  and Heavy candidates. Rust exposes physical/available memory through a bounded
  `get_hardware_profile` command for fit calculations; model choice remains
  explicit. Current Ollama residency is matched by digest, so an already-loaded
  GPU model is not incorrectly charged against free system RAM a second time.

## Agent Runtime

The session exposes three `activeTools` workflows: investigation, plan, and
policy. Current tools are:

- `get_storage_overview`
- `query_storage_items`
- `summarize_storage`
- `get_item_evidence`
- `inspect_log_excerpt`
- `build_cleanup_plan`
- `edit_cleanup_plan`
- `protect_path`

All storage facts come from existing bounded Tauri analyzer commands. Query,
evidence, aggregation, and plan limits are schema-enforced. Each tool result is
capped at 12 KiB and each turn at 32 KiB with explicit truncation. Turns stop at
eight model steps, allow one invalid-call repair, target one to three tools, cap
output at 1,024 tokens, and enforce 60-second step/180-second total timeouts.

The model-facing item query and aggregate tools accept a folder name/path as
`scope`; each resolves it against bounded analyzer results and performs the
scoped operation in one execution. Opaque scan-local node IDs remain an internal
implementation detail rather than a value small models must copy between calls.
An attached directory becomes the default scope, while `/` explicitly means the
scan root. A matching attached name or full path resolves directly to trusted UI
metadata; other full paths search by final component and require an exact returned
path. Evidence and approval tools use `use_attached_item`, and attachment JSON sent
to the model deliberately omits the node ID.
If a local model completes a tool call without prose, the runtime renders a
bounded, deterministic answer from that tool result instead of showing an empty
response.

Only recent user/assistant text is retained, bounded to 12 messages and 24,000
characters. Older local conversation text is reduced into a deterministic
2,400-character session summary; tool history is not replayed. Raw thinking is
neither returned nor persisted. Typed activity records expose tool purpose,
summarized arguments, count, elapsed time, truncation, approval state, and error
state.

`protect_path` and `inspect_log_excerpt` use AI SDK approval requests. Single and
batched decisions are supported; every pending approval must receive an explicit
decision, denied actions are not executed, and new chat turns are blocked while
approval remains. Cleanup plans remain proposals and session-only.

Log inspection is implemented behind a Rust command rather than arbitrary webview
file access. It revalidates exact item IDs against the current scan, permits only
unprotected candidate text logs under the crash-report and npm-log rules, rejects
reparse/encrypted/binary/changed files, opens Windows paths without following
reparse points, and returns bounded beginning/end excerpts. Limits are five files,
64 KiB per file, and 256 KiB total; excerpts are never persisted or logged.

## Agent Dock

- Ollama discovery, explicit model selection, memory-fit status, refresh, native
  preflight, and compatibility testing are wired into the persistent dock.
- Memory fit is advisory because Ollama may offload to otherwise-free GPU VRAM.
  A low estimate opens an explicit warning instead of disabling model loading;
  `Try anyway` runs normal Ollama preflight, and failure leaves scan data intact.
- The dock offers explicit Investigate, Plan cleanup, and Protect paths workflows.
  A prepared model binds only to the current analyzer session; rescan, target,
  model, or workflow changes discard stale conversation and plan state.
- Assistant text streams through AI SDK 7. Tool activity shows purpose, state,
  result count, elapsed time, and truncation without exposing raw thinking.
- Cancellation aborts the active stream. Cancelling an approval continuation also
  clears pending conversation context to prevent an approved action from being
  replayed accidentally.
- Exact paths and maximum log bytes are shown before approval. Every pending
  action needs an Allow or Deny decision before continuation.
- Cleanup proposal results flow directly into Plan, whose selected items and
  conservative/review totals remain editable through deterministic Tauri commands.
- Selecting a current analyzer row attaches its exact item ID, path, kind, sizes,
  and policy tier as trusted local turn context. The chip is visible and removable;
  rescans still discard stale context.
- Validated tool-result envelopes render through the fixed local result registry
  for overview, item list, aggregate, evidence, approved log, cleanup proposal,
  protection, and tool-error cards. The model cannot select components or props.
- AI code is lazy-loaded into a separate frontend chunk so analyzer startup does
  not absorb the AI SDK bundle.

## Deliberately Not Exposed

No shell, delete, write, move, recycle, uninstall, web-search, arbitrary-read, or
code-execution tool exists. `get_duplicate_results` remains absent until the
dedicated duplicate workflow can produce completed deterministic results. Age
aggregation is also not advertised until the analyzer supplies native age buckets.

## Verification

- TypeScript 7 production build passes.
- Thirty-nine enabled Vitest tests cover endpoint isolation, redirect denial, local metadata,
  cloud-response rejection, service-unavailable behavior, catalog ranking,
  harness caching, Tauri command mapping, approval declaration, and tool budgets,
  including attached-scope/full-path resolution, trusted attachment evidence, root
  selection, and bounded preservation of a single large approved log excerpt. Nine
  jsdom/Testing Library cases cover Ollama failure, low-memory warning/override,
  streaming chat plus Plan handoff, typed cards, analyzer attachment, exact-path
  approval, and cancellation.
- All 111 enabled Rust workspace tests pass (seven platform/helper tests remain
  intentionally ignored), and warning-denied workspace clippy is clean.
- The production Tauri release, MSI, and NSIS builds pass with scanner protocol
  v10 and the loopback-scoped HTTP plugin enabled. The staged and MSI-extracted
  helper SHA-256 is
  `a2ae1b262c9ecad5dfe619b96076a60ff6b6291657344bcfe931325741a1c5fd`.
- Native Tauri inspection verified unavailable-service recovery, local Ollama
  0.30.7 discovery, current-memory reporting, scan-session gating, and cancellation
  while the analyzer remained usable.
- The local `granite4:1b-h` digest `7761ae79cab9...` passed all four native
  streaming harness v5 scenarios with Ollama `0.30.7`, including the generic
  `Projects` named-scope contract. The complete live runtime suite then passed
  scoped query, selected-directory default scope, trusted attachment evidence,
  plan handoff, approval denial, and approved exact-path execution in 46.7 seconds.
- The retry isolated an Ollama compatibility issue rather than an inference
  problem: warmed native `/api/chat` streamed its first LFM token in about 350 ms,
  while `/v1/chat/completions` returned no headers within 35 seconds. Moving the
  AI SDK transport to the native provider fixed Granite immediately.
- `lfm2.5-thinking:latest` streams natively but emitted only thinking and no tool
  calls in the harness, so that digest remains ineligible. `qwen3.5:2b` could not
  load under the available system-memory pressure. The ranker incorporates
  currently available memory rather than treating total RAM alone as a fit.

## Acceptance Boundary

Implementation-order item 4 is complete: local discovery/ranking, hardware fit,
native preflight, harness gating, bounded agent tools, typed presentation,
session context, approvals, cancellation, and deterministic Plan refinement are
implemented and automated. The accepted demo choice on the prepared 8 GB machine
is the passing Granite light fallback; Qwen 3.5 2B remains rejected after its
overview step exceeded the harness timeout under current memory pressure.
Packaged-window repetition and Playwright expansion are implementation-order item
5 hardening, not missing local-agent architecture.
