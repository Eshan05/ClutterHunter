# Local Agent Notes

Status: item 4 architecture complete; real-scan answer-quality acceptance open
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
  version. Harness v6 uses the native
  production stream, records median first-token latency, accepts the same typed
  deterministic presentation used when a small model finishes a valid tool call
  without prose, and invalidates earlier
  OpenAI-compatible/non-streaming cache entries. A
  failed model cannot create a real agent session. Native requests set
  `think: false`; this avoids spending the small-model latency budget on hidden
  reasoning and bumped the harness version to invalidate older cached passes.
- The bundled offline catalog and deterministic ranker cover Light, Balanced,
  and Heavy candidates. Rust exposes physical/available memory through a bounded
  `get_hardware_profile` command for fit calculations; model choice remains
  explicit. Current Ollama residency is matched by digest, so an already-loaded
  GPU model is not incorrectly charged against free system RAM a second time.

## Agent Runtime

The session exposes three `activeTools` workflows: investigation, plan, and
policy. Current tools are:

- `get_storage_overview`
- `list_folder_children`
- `list_largest_items`
- `search_storage`
- `inspect_folder`
- `list_cleanup_opportunities`
- `summarize_storage`
- `inspect_item`
- `inspect_log_excerpt`
- `build_cleanup_plan`
- `edit_cleanup_plan`
- `protect_path`

All storage facts come from existing bounded Tauri analyzer commands. Query,
evidence, aggregation, and plan limits are schema-enforced. Each tool result is
capped at 12 KiB and each turn at 32 KiB with explicit truncation. Turns stop at
eight model steps, allow one invalid-call repair, target one to three tools, cap
output at 1,024 tokens, and enforce 60-second step/180-second total timeouts.

The model-facing list, search, inspection, and aggregate tools accept a folder name/path as
`scope`; each resolves it against bounded analyzer results and performs the
scoped operation in one execution. Opaque scan-local node IDs remain an internal
implementation detail rather than a value small models must copy between calls.
`list_folder_children` always returns only the resolved folder's immediate
children. `search_storage` requires non-empty text and explicitly selects
recursive traversal bounded to the resolved subtree. `list_largest_items` is the
separate recursive top-N path for largest files/items without search text. Rust
carries recursion as an explicit flag and uses `top_only` to retain at most the
requested 100 ranked nodes instead of sorting every descendant.

`inspect_folder` composes exact folder totals, largest immediate children, largest
files at any depth, top extensions, kind/policy aggregates, coverage, and warnings
into one bounded result. `list_cleanup_opportunities` can resolve one folder and
reads a scoped deterministic policy/planner result without creating or replacing
the current Plan; conservative and review-potential totals remain separate.
Read-only opportunity rows expose exact display paths, reasons, safety tier,
proposed action, and bytes while omitting scan-local node IDs.
`inspect_item` resolves one exact file/folder path or name, or consumes the trusted
UI attachment, then returns deterministic size, ownership, attributes, and policy.
An attached directory becomes the default scope, while `/` explicitly means the
scan root. A matching attached name or full path resolves directly to trusted UI
metadata; other full paths search by final component and require an exact returned
path. Evidence and approval tools use `use_attached_item`, and attachment JSON sent
to the model deliberately omits the node ID.
If a local model completes a tool call without prose, the runtime renders a
bounded, deterministic answer from that tool result instead of showing an empty
response.

Common ranked list intents, explicit `top N`, and same-scope `all` follow-ups use
a deterministic front-controller. Largest folders stay immediate-child queries;
largest files use bounded recursive top-N ranking. It extracts kind, metric,
direction, limit, and optional named/path scope before invoking Rust directly.
The language model is not a correctness dependency for these frequent facts. Other factual prompts
still force an evidence tool; if the model skips it, generated paths and sizes
are discarded and a visible tool diagnostic is returned.

Ordinary cleanup wording such as "what should I delete?" and "which folders can I
remove?" routes to `list_cleanup_opportunities`. Size only ranks items already
made eligible by deterministic policy evidence; it never makes an item safe to
remove. After the required evidence call, unrelated storage tools are disabled
for that turn so a later speculative query cannot replace the cleanup result.
Cleanup cards and deterministic fallback text surface the policy reason and any
warning beside each candidate. The model's role is explanation, not eligibility.

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
- Assistant prose streams through AI SDK 7 and renders with Streamdown. Remote
  images and generated links are inert so Markdown cannot bypass local privacy.
  Tool activity shows purpose, state, result count, elapsed time, and truncation
  without exposing raw thinking.
- Factual prompts are routed to one required intent-matched evidence tool, then
  unrelated tools are closed for that turn. Item, aggregate, overview, and
  cleanup values are formatted from deterministic envelopes rather than model
  prose. Query context echoes scope, metric, direction, kinds, and limit.
- The last exact resolved scope survives ambiguous follow-ups. A model-invented
  root scope is rejected unless the user explicitly asks for the scan/drive root.
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
- Sixty-two enabled Vitest tests cover endpoint isolation, redirect denial, local metadata,
  cloud-response rejection, service-unavailable behavior, catalog ranking,
  harness caching, Tauri command mapping, approval declaration, and tool budgets,
  including attached-scope/full-path resolution, trusted attachment evidence, root
  selection, grounded routing, scope retention, and bounded preservation of a
  single large approved log excerpt. Fourteen
  jsdom/Testing Library cases cover Ollama failure, low-memory warning/override,
  Streamdown rendering, streaming chat plus Plan handoff, typed cards, analyzer
  attachment, exact-path approval, cancellation, and deterministic offline Plan
  creation/editing.
- All 114 enabled Rust workspace tests pass (seven platform/helper tests remain
  intentionally ignored), and warning-denied workspace clippy is clean.
- The production Tauri release, MSI, and NSIS builds pass with scanner protocol
  v10 and the loopback-scoped HTTP plugin enabled. The staged and MSI-extracted
  helper SHA-256 is
  `a2ae1b262c9ecad5dfe619b96076a60ff6b6291657344bcfe931325741a1c5fd`.
- Native Tauri inspection verified unavailable-service recovery, local Ollama
  0.30.7 discovery, current-memory reporting, scan-session gating, and cancellation
  while the analyzer remained usable.
- The local `granite4:1b-h` digest `7761ae79cab9...` passed all four native
  streaming harness v7 scenarios with Ollama `0.30.7`, including the generic
  `Projects` named-scope contract. The complete live runtime suite then passed
  forced scoped query, same-scope follow-up, selected-directory default scope,
  invented-root rejection, bounded recursive top-N ranking, trusted attachment
  and path-addressed item evidence, composite folder inspection, scoped cleanup
  opportunities, plan handoff, approval denial, and approved exact-path execution
  in 53.1 seconds.
- The retry isolated an Ollama compatibility issue rather than an inference
  problem: warmed native `/api/chat` streamed its first LFM token in about 350 ms,
  while `/v1/chat/completions` returned no headers within 35 seconds. Moving the
  AI SDK transport to the native provider fixed Granite immediately.
- `functiongemma:latest` failed three full-agent harness scenarios and scored
  0/4 in a separate fair single-call router test, choosing wrong tools, producing
  no valid scoped call, or dropping required arguments. Stock FunctionGemma is
  not used in a compound runtime; a domain fine-tune remains an experiment.
- `lfm2.5-thinking:latest` streams natively but emitted only thinking and no tool
  calls in the harness, so that digest remains ineligible. `qwen3.5:2b` loaded
  after memory pressure eased, but even with `think: false` its overview scenario
  exceeded the 20-second step limit; the rejected run took 80.6 seconds. The
  ranker incorporates available memory rather than treating total RAM alone as
  a fit.

## Acceptance Boundary

Implementation-order item 4 architecture is complete: local discovery/ranking, hardware fit,
native preflight, harness gating, bounded agent tools, typed presentation,
session context, approvals, cancellation, and deterministic Plan refinement are
implemented and automated. Final quality acceptance remains open until the exact
reported path/follow-up prompts pass against the user's real MFT scan in Tauri.
The current demo choice on the prepared 8 GB machine
is the passing Granite light fallback; Qwen 3.5 2B remains rejected after its
overview step exceeded the harness timeout under current memory pressure.
Packaged-window repetition and Playwright expansion are implementation-order item
5 hardening, not missing local-agent architecture.
