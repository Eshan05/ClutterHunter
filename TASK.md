# ClutterHunter Work Queue

Last updated: 2026-07-15

This file is the durable execution queue. Product decisions live in `docs/`; this
file records what is complete, what is currently half-finished, and the acceptance
checks required before an item can be called done.

## Current State

- [x] Item 1: fast Windows scanner and NTFS MFT path implemented.
- [x] Item 2: bounded analyzer/query core implemented.
- [ ] Item 3: full analyzer UI is in progress. New workspace, virtualization, and
  treemap files exist but are not yet integrated into the main application.
- [ ] Item 4: local Ollama agent architecture is implemented, but answer quality
  has reopened this item. Tool routing and factual grounding are not yet reliable
  enough for release.
- [ ] Item 5: packaged-app hardening, end-to-end UI coverage, and final release QA.

Last clean verification before the current partial agent changes:

- 39 enabled Vitest tests passed.
- TypeScript 7 production build passed.
- Current tool-routing edits below have not yet been compiled or tested.

## Immediate Priority: Grounded Storage Answers

Observed failure:

- Granite 4 1B answered folder-size questions without a fresh tool call.
- Follow-ups such as `All folders?` drifted from `C:\Users\redma` to `C:\Users`.
- Model-generated Markdown tables contained malformed or unsupported byte values.
- Typed result cards were absent because no tool result was produced.

Existing capability that should be used rather than rebuilt:

- `query_storage_items` already supports `sort` with `allocated`, `logical`,
  `name`, `modified`, `type`, `policy`, and `owner`.
- It already supports `direction`, `kinds`, bounded `limit`, text filters, and a
  locally resolved folder/path scope.
- Rust performs deterministic sorting. The model must not sort or reproduce raw
  storage data itself.

### Partially Implemented

- [x] Added `evidenceToolForPrompt` intent routing in `src/agent/runtime.ts`.
- [x] Added per-step AI SDK `prepareStep` logic that can force a specific evidence
  tool on the first step of a factual turn.
- [x] Added instructions requiring fresh tool evidence for storage follow-ups.
- [x] Suppressed provisional model prose while a forced evidence query runs.
- [ ] Compile and test these changes. They were interrupted before verification.

### Remaining Implementation

- [ ] Test intent routing for largest folders, all folders, explicit Windows
  paths, aggregate requests, overview requests, and ordinary conversation.
- [ ] Ensure forced tool choice applies only to the first user step and never
  repeats during approval continuation.
- [ ] Echo deterministic query context in `ItemListResult`: resolved scope, sort,
  direction, kinds, and limit.
- [ ] Make factual tool output authoritative. For item lists, aggregates, and scan
  totals, final visible values must be formatted from tool data rather than model
  prose.
- [ ] Show the requested metric in result cards. `logical` queries must not be
  relabeled as allocated size.
- [ ] Keep model prose for explanation/workflow tasks, but never allow it to
  replace or contradict deterministic values.
- [ ] Improve ambiguous follow-up handling. `All folders?` should inherit the last
  resolved scope unless the user names a new scope.
- [ ] Add a visible diagnostic when a factual turn somehow completes without an
  evidence tool call.

### Acceptance Scenarios

- [ ] `What are the largest folders in C:\Users\redma?` calls
  `query_storage_items` with scope `C:\Users\redma`, directory kind, descending
  allocated size, and a useful bounded limit.
- [ ] `All folders?` performs a fresh tool call and retains `C:\Users\redma`.
- [ ] `No, I mean Users/redma` resolves to the same exact folder and performs a
  fresh query.
- [ ] Every displayed name, path, size, count, and policy value exists verbatim in
  the returned tool envelope.
- [ ] Result card and activity row appear for every factual storage query.
- [ ] No raw Markdown table is needed to communicate analyzer rows.
- [ ] Empty, ambiguous, stale-session, and truncated results are stated plainly
  without invented replacements.

## Streamdown

Decision: use Streamdown for assistant prose presentation, not for factual
correctness. It can render incomplete streaming Markdown cleanly, but it cannot
make Granite call tools or prevent hallucinated data.

Current state:

- [x] Added `streamdown` 2.5.0 to dependencies.
- [ ] It is not yet imported or rendered by `AgentDock`.

Remaining:

- [ ] Replace the assistant's plain `<p>` renderer with `Streamdown`.
- [ ] Use streaming mode only while a response is active and static mode after it
  finishes.
- [ ] Preserve the compact dock layout for headings, paragraphs, lists, code, and
  tables at narrow widths.
- [ ] Block remote image loading and unsafe navigation. Assistant Markdown must
  not create an unexpected network request in this local/private application.
- [ ] Keep typed tool cards outside Markdown and visually more authoritative than
  generated prose.
- [ ] Add component tests for partial Markdown, completed Markdown, long paths,
  and narrow dock width.
- [ ] Measure the lazy AgentDock chunk. Streamdown 2.5.0 brings a large dependency
  graph, so retain it only if production bundle and startup cost remain reasonable.

Official reference: <https://streamdown.ai/docs/usage>

## Model Strategy

### Granite 4 1B

- [x] Passed the compatibility harness and works under current memory pressure.
- [ ] Not accepted as an ungrounded answerer. Current real conversation quality is
  too poor.
- [ ] Re-run the live harness after forced routing and deterministic presentation.

### FunctionGemma

Decision: do not recommend stock FunctionGemma as the primary chat model.

- It is a 270M function-calling foundation model, available in Ollama at roughly
  301 MB with a 32K context window.
- Google explicitly positions it for task-specific fine-tuning, not direct
  dialogue.
- It is promising as a ClutterHunter-specific tool router after fine-tuning.

Tasks:

- [ ] Add FunctionGemma as an experimental catalog entry, not a recommended model.
- [ ] Run the same ClutterHunter tool harness against the stock Ollama model.
- [ ] Measure correct tool selection, correct arguments, irrelevant-tool refusal,
  multi-turn scope retention, latency, and memory.
- [ ] Design a small domain dataset from deterministic ClutterHunter scenarios.
- [ ] Fine-tune only if stock results justify the maintenance cost.
- [ ] Consider a compound path: FunctionGemma routes tools, Rust returns evidence,
  deterministic UI presents facts, and a stronger optional model explains them.

Official references:

- <https://ai.google.dev/gemma/docs/functiongemma>
- <https://huggingface.co/google/functiongemma-270m-it>
- <https://registry.ollama.com/library/functiongemma/tags>

## Analyzer UI: Item 3

Current unintegrated files:

- `src/AnalyzerWorkspace.tsx`
- `src/analyzer/TreemapCanvas.tsx`
- `src/analyzer/treemap.ts`

Remaining:

- [ ] Integrate `AnalyzerWorkspace` into `App.tsx`.
- [ ] Replace placeholder extension and treemap panels with live bounded queries.
- [ ] Finish virtual table navigation, sorting, filtering, pagination, selection,
  breadcrumbs, back/forward history, and cancellation states.
- [ ] Connect analyzer selection to the trusted AgentDock attachment.
- [ ] Add responsive CSS and verify no overlap at desktop and laptop viewports.
- [ ] Add unit tests for navigation/query state and canvas layout.
- [ ] Perform visual QA in the real Tauri window after Computer Use is available,
  or through user-driven screenshots if it remains unavailable.

## Final Verification

- [ ] `pnpm exec vitest run`
- [ ] `pnpm -s build`
- [ ] Rust workspace tests and warning-denied clippy after Rust changes.
- [ ] Tauri dev test with live Ollama and a completed MFT scan.
- [ ] Repeat the three exact folder prompts from the reported failure.
- [ ] Test low-memory warning -> `Try anyway` -> successful and failed Ollama load.
- [ ] Confirm analyzer remains usable while Ollama is absent, loading, cancelled,
  or out of memory.
- [ ] Build release executable, MSI, and NSIS only after live behavior passes.
- [ ] Update `docs/LocalAgent.md`, `docs/AnalyzerCore.md`, and `docs/ProductPlan.md`
  with final verified behavior rather than planned behavior.

