# ClutterHunter Work Queue

Last updated: 2026-07-15

This file is the durable execution queue. Product decisions live in `docs/`; this
file records what is complete, what is currently half-finished, and the acceptance
checks required before an item can be called done.

## Current State

- [x] Item 1: fast Windows scanner and NTFS MFT path implemented.
- [x] Item 2: bounded analyzer/query core implemented.
- [x] Item 3: bounded analyzer UI and deterministic no-AI Plan are integrated.
  Native completed-scan visual acceptance remains in final verification.
- [ ] Item 4: local Ollama agent architecture is implemented. Common factual
  storage lists now bypass model routing, but real-scan Tauri acceptance remains
  open before answer quality can be called release-ready.
- [ ] Item 5: packaged-app hardening, end-to-end UI coverage, and final release QA.

Current verification:

- 62 enabled Vitest tests pass; two opt-in live suites are skipped by default.
- TypeScript 7 production build passes.
- Live Granite 4 1B runtime suite passes with harness v7 and `think: false` in
  53.1 seconds, including exact scoped results, same-scope follow-up, bounded
  recursive ranking, richer folder inspection, scoped cleanup, item evidence,
  plan handoff, and approvals.

## Immediate Priority: Grounded Storage Answers

Observed failure:

- Granite 4 1B answered folder-size questions without a fresh tool call.
- Follow-ups such as `All folders?` drifted from `C:\Users\redma` to `C:\Users`.
- Model-generated Markdown tables contained malformed or unsupported byte values.
- Typed result cards were absent because no tool result was produced.

Existing capability that should be used rather than rebuilt:

- `list_folder_children`, `list_largest_items`, and `search_storage` share
  deterministic analyzer filters and exact locally resolved scope.
- Direct listing never recurses. Search recurses only with required name/path text;
  largest-item ranking recurses through a bounded top-N heap.
- Rust performs deterministic sorting. The model must not sort or reproduce raw
  storage data itself.

### Partially Implemented

- [x] Added `evidenceToolForPrompt` intent routing in `src/agent/runtime.ts`.
- [x] Added per-step AI SDK `prepareStep` logic that can force a specific evidence
  tool on the first step of a factual turn.
- [x] Added instructions requiring fresh tool evidence for storage follow-ups.
- [x] Suppressed provisional model prose while a forced evidence query runs.
- [x] Added a deterministic front-controller for common ranked folder/file
  questions. It resolves scope and calls the bounded analyzer query without an
  LLM round trip.
- [x] Added an explicit Rust `recursive` query flag. Filters no longer silently
  turn immediate-child navigation into descendant search.
- [x] Replaced the overloaded model-visible query with narrow
  `list_folder_children` and `search_storage` tools.
- [x] Added `inspect_folder`: exact totals, immediate contributors, kind/policy
  composition, coverage, and warnings in one bounded result.
- [x] Added `list_cleanup_opportunities`: deterministic candidate/review evidence
  without creating or replacing the user's Plan.
- [x] Route ordinary delete/remove phrasing to cleanup evidence, rank only
  policy-eligible opportunities by size, and surface each deterministic reason.
- [x] Close unrelated tools after the required evidence call so a speculative
  second call cannot replace the authoritative cleanup result.
- [x] Added recursive `list_largest_items` without requiring fake search text or
  sorting every matching descendant.
- [x] Extended `inspect_folder` with largest recursive files and top extensions.
- [x] Scoped cleanup opportunities to a locally resolved folder.
- [x] Replaced ID-oriented evidence input with `inspect_item`, accepting one exact
  path/name or trusted UI attachment.
- [x] Compile and test these changes.

### Remaining Implementation

- [x] Test intent routing for largest folders, all folders, explicit Windows
  paths, aggregate requests, overview requests, and ordinary conversation.
- [x] Ensure forced tool choice applies only to the first user step and never
  repeats during approval continuation.
- [x] Echo deterministic query context in `ItemListResult`: resolved scope, sort,
  direction, kinds, and limit.
- [x] Make factual tool output authoritative. For item lists, aggregates, and scan
  totals, final visible values must be formatted from tool data rather than model
  prose.
- [x] Show the requested metric in result cards. `logical` queries must not be
  relabeled as allocated size.
- [x] Keep model prose for explanation/workflow tasks, but never allow it to
  replace or contradict deterministic values.
- [x] Improve ambiguous follow-up handling. `All folders?` inherits the last
  resolved scope unless the user names a new scope.
- [x] Reject a model-invented `/` root scope when the user did not explicitly ask
  for the scan or drive root. Trusted attachment/last scope wins instead.
- [x] Add a visible diagnostic when a factual turn somehow completes without an
  evidence tool call.

### Acceptance Scenarios

- [ ] `What are the largest folders in C:\Users\redma?` calls
  `list_folder_children` with scope `C:\Users\redma`, directory kind, descending
  allocated size, and a useful bounded limit.
- [ ] `All folders?` performs a fresh tool call and retains `C:\Users\redma`.
- [ ] `Largest files anywhere under Downloads?` calls `list_largest_items`, keeps
  Downloads as scope, and returns only the bounded recursive top N.
- [ ] `What can I clean inside AppData?` returns only scoped deterministic policy
  opportunities and does not replace the Plan tab.
- [ ] `Can I delete pagefile.sys?` calls `inspect_item` and reports deterministic
  ownership/policy evidence instead of inferring from its filename.
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
- [x] Integrated into `AgentDock` for assistant prose.

Remaining:

- [x] Replace the assistant's plain `<p>` renderer with `Streamdown`.
- [x] Use streaming mode only while a response is active and static mode after it
  finishes.
- [x] Add compact dock styles for headings, paragraphs, lists, code, and
  tables at narrow widths.
- [x] Block remote image loading and unsafe navigation. Assistant Markdown cannot
  create an unexpected network request in this local/private application.
- [x] Keep typed tool cards outside Markdown and make their values authoritative
  over generated prose.
  generated prose.
- [ ] Add component tests for partial Markdown, completed Markdown, long paths,
  and narrow dock width.
- [x] Measure the lazy bundle: Streamdown adds a 476.26 kB/144.50 kB gzip shared
  chunk; AgentDock is 795.58 kB/196.04 kB gzip. It stays lazy-loaded, but final
  startup/memory QA is still required before release.

Official reference: <https://streamdown.ai/docs/usage>

## Model Strategy

### Granite 4 1B

- [x] Passed the compatibility harness and works under current memory pressure.
- [ ] Not accepted as an ungrounded answerer. Current real conversation quality is
  too poor.
- [x] Re-run the live harness after forced routing and deterministic presentation.
- [x] Disable Ollama thinking at the native request boundary; harness v7
  invalidates older cached passes.

### Qwen 3.5 2B

- [x] Re-run with the native Ollama `think: false` setting.
- [ ] Do not recommend on the current 8 GB laptop: the overview scenario still
  exceeded the 20-second step limit and the rejected run took 80.6 seconds.

### FunctionGemma

Decision: do not recommend stock FunctionGemma as the primary chat model.

- It is a 270M function-calling foundation model, available in Ollama at roughly
  301 MB with a 32K context window.
- Google explicitly positions it for task-specific fine-tuning, not direct
  dialogue.
- It is promising as a ClutterHunter-specific tool router after fine-tuning.

Tasks:

- [ ] Add FunctionGemma as an experimental catalog entry, not a recommended model.
- [x] Run the same ClutterHunter tool harness against the stock Ollama model.
- [x] Measure correct tool selection and arguments with a dedicated one-call
  router harness. Stock `functiongemma:latest` scored 0/4: wrong overview tool,
  no valid scoped-query call, wrong aggregate tool, and missing plan arguments.
- [ ] Measure irrelevant-tool refusal,
  multi-turn scope retention, latency, and memory.
- [ ] Design a small domain dataset from deterministic ClutterHunter scenarios.
- [ ] Fine-tune only if stock results justify the maintenance cost.
- [x] Reject stock FunctionGemma as a compound-path router. Reconsider only after
  a domain fine-tune beats deterministic routing on exact arguments and latency.

Official references:

- <https://ai.google.dev/gemma/docs/functiongemma>
- <https://huggingface.co/google/functiongemma-270m-it>
- <https://registry.ollama.com/library/functiongemma/tags>

## Analyzer UI: Item 3

- [x] Integrated `AnalyzerWorkspace` into `App.tsx`; scan completion no longer
  waits on a duplicate first-page query in the shell.
- [x] Replaced placeholder extension and treemap panels with live bounded queries.
- [x] Finished virtual table navigation, sorting, recursive scoped search, pagination, selection,
  breadcrumbs, back/forward history, and cancellation states.
- [x] Connected analyzer selection to the trusted AgentDock attachment and added
  Copy path plus Reveal in Explorer item actions.
- [x] Made the top Candidates total deterministic and non-mutating.
- [x] Added direct offline cleanup-plan creation with an optional GB target;
  session plan edits survive Ollama model/workflow changes.
- [x] Added responsive CSS and verified no overlap in browser renders at
  `1440x900` and `1038x663`.
- [x] Added unit tests for bounded navigation/query state, paging, selection
  handoff, Explorer reveal, offline plan creation/editing, and canvas layout.
- [ ] Perform visual QA in the real Tauri window after Computer Use is available,
  or through user-driven screenshots if it remains unavailable.

## Final Verification

- [x] `pnpm exec vitest run`
- [x] `pnpm -s build`
- [x] Rust workspace tests and warning-denied clippy after Rust changes.
- [x] Live Ollama fixture runtime test with Granite 4 1B.
- [ ] Tauri UI test against the user's completed MFT scan.
- [ ] Repeat the three exact folder prompts from the reported failure.
- [ ] Test low-memory warning -> `Try anyway` -> successful and failed Ollama load.
- [ ] Confirm analyzer remains usable while Ollama is absent, loading, cancelled,
  or out of memory.
- [ ] Build release executable, MSI, and NSIS only after live behavior passes.
- [x] Update `docs/LocalAgent.md`, `docs/AnalyzerCore.md`, and `docs/ProductPlan.md`
  with final verified behavior rather than planned behavior.
