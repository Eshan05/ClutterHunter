# ClutterHunter Technical Report

This report consolidates implementation evidence, local-AI verification,
evaluation results, and privacy/safety boundaries for ClutterHunter. Detailed
engineering records remain available in the linked source documents.

## 4. Technical Report

### System Summary

ClutterHunter combines two local systems:

1. a Rust storage analyzer that reads NTFS metadata through a narrow elevated
   helper and exposes bounded queries to a React/Tauri interface; and
2. an optional AI SDK agent that talks only to a local Ollama service and uses
   schema-constrained analyzer tools for storage evidence.

The analyzer and policy engine are authoritative. The model explains and
navigates deterministic results but does not classify files as safe by itself.

### Model and Runtime

| Component | Selected configuration |
| --- | --- |
| Primary tested model | `granite4:1b-h` |
| Model architecture | Granite Hybrid |
| Parameters | 1.5 billion |
| Local blob size | 1.6 GB as reported by `ollama list` |
| Quantization | `Q8_0` |
| Reported model context | 1,048,576 tokens; ClutterHunter applies much smaller application-level context limits |
| Model capability | Completion and tool calling |
| Model license | Apache License 2.0 |
| Inference runtime | Ollama `0.30.7`, native `/api/chat` streaming |
| Agent runtime | AI SDK `7.0.26` `ToolLoopAgent` |
| Ollama provider | `ai-sdk-ollama` `4.0.0` |
| Presentation | Streamdown `2.5.0` for streaming Markdown; typed local components for factual results |

The model is not bundled. Users explicitly select an installed, tool-capable
local model after discovery and compatibility testing.

### Optimization Techniques

#### AI path

- `Q8_0` quantization reduces the selected Granite model's memory/storage cost.
- Native Ollama chat streaming is used instead of the OpenAI-compatible endpoint,
  which timed out on the tested Ollama/model combination.
- `think: false` avoids spending the small-model latency budget on hidden
  reasoning for supported models.
- Common ranked storage questions use a deterministic front-controller and do
  not require an LLM round trip for correctness.
- Other factual prompts require one intent-matched evidence tool. Irrelevant
  tools are closed after the evidence call so a later speculative query cannot
  replace the authoritative result.
- Recent context is capped at 12 messages and 24,000 characters. Older text is
  reduced to a deterministic 2,400-character session summary.
- Tool results are capped at 12 KiB each and 32 KiB per turn; output is capped at
  1,024 tokens.
- AI code is loaded as a separate frontend chunk so analyzer startup does not
  require loading the agent bundle.

#### Scanner and analyzer path

- Four reusable, aligned 4 MiB buffers overlap raw NTFS reads with record parsing.
- The scanner transfers a hierarchy-complete compact arena rather than millions
  of general-purpose objects or a temporary JSON snapshot.
- Arena nodes use `u32` hierarchy links and a packed UTF-8 name pool.
- Owner tables are released in chunks while final arena data is adopted.
- Analyzer pages return at most 100 rows.
- Recursive largest-item queries use a bounded top-N heap rather than sorting
  every descendant.
- Treemap queries return at most 5,000 file leaves plus required ancestors.
- Cleanup plans return at most 500 items with explicit omitted totals.

### Tested Device

| Component | Specification |
| --- | --- |
| Device | HP Victus by HP Laptop 16-e0xxx |
| Operating system | Windows 10 Home Single Language, version `10.0.19045`, build `19045` |
| CPU | AMD Ryzen 5 5600H, 6 cores / 12 logical processors |
| System memory | 7,887,114,240 bytes, approximately 7.35 GiB |
| Discrete GPU | NVIDIA GeForce GTX 1650, approximately 4 GiB VRAM |
| Integrated GPU | AMD Radeon Graphics; Windows reported a 512 MiB adapter aperture |
| NPU | None used |
| Ollama | `0.30.7` |

### Latency and Resource Measurements

#### Storage pipeline

The measured warm usable-view benchmark covered raw scan, ownership/policy
classification, stable totals, and the first 50-row analyzer query.

| Measurement | Result |
| --- | ---: |
| Complete warm usable view, run 1 | 18.484 s |
| Complete warm usable view, run 2 | 18.074 s |
| Complete warm usable view, run 3 | 18.035 s |
| Median | **18.074 s** |
| Indexed entries | approximately 7.30 million |
| First 50-row allocated-size query | below the millisecond timer |
| Arena plus analyzer state | approximately 664 MB |
| Helper peak working set | approximately 1.13 GB |
| Host peak working set | approximately 657 MB |
| Sampled concurrent helper + host peak | approximately 1.275 GB |

The five-million-entry synthetic analyzer gate measured:

| Operation | Result |
| --- | ---: |
| Policy and ownership classification | 5,784 ms |
| First 50 results from a five-million-match search | 200 ms |
| First navigation sort | 159 ms |
| Cached navigation sort | below the millisecond timer |
| Storage aggregate | 160 ms |
| Bounded hierarchical treemap | 285 ms |
| Bounded 500-item cleanup plan | 2,026 ms |

#### Local inference

| Measurement | Result |
| --- | ---: |
| Warm native Ollama first token during transport diagnosis | approximately 350 ms |
| Granite four-scenario compatibility harness | 4/4 scenarios passed |
| Complete live runtime acceptance sequence | 53.1 s |
| Step timeout | 60 s in the application; focused harness scenarios use stricter limits |
| Turn timeout | 180 s |

CPU utilization percentage, GPU utilization percentage, inference-energy use,
and model-specific peak VRAM have not yet been captured with a repeatable
profiler. Ollama decides CPU/GPU placement; ClutterHunter does not claim a fixed
offload ratio. The application reports model fit as advisory because available
GPU VRAM can make a model usable even when a system-RAM estimate is conservative.

## 5. Local AI Verification

### What Runs On Device

| Function | Execution location | Internet required during use? | User data sent off-device? |
| --- | --- | --- | --- |
| NTFS MFT scan | Local elevated helper | No | No |
| Traversal scan | Local Rust process | No | No |
| Storage index and queries | Local Rust process | No | No |
| Ownership and policy classification | Local Rust process plus local Windows metadata | No | No |
| Cleanup-plan construction | Local Rust process | No | No |
| Model inference | Local Ollama on `127.0.0.1` | No | No |
| Tool orchestration | React WebView through AI SDK | No | No |
| Approved log excerpt analysis | Local Rust read, then local Ollama context | No | No |
| Reveal in Explorer | Local Windows shell integration | No | No |

Internet access is needed only for external setup actions such as cloning the
repository, downloading dependencies, installing Ollama, or obtaining a model.
Once installed, scanning, analysis, planning, and compatible-model chat operate
without an internet connection.

### Enforcement

- Ollama configuration accepts only a numeric port and canonicalizes it to
  `127.0.0.1`.
- Host aliases, credentials, redirects, LAN addresses, internet addresses, and
  cloud-tagged models are rejected.
- Discovery checks Ollama version, installed tags, current residency, model
  digest, local blob size, GGUF details, and tool capability.
- A synthetic preflight verifies that Ollama reports the exact selected local
  model before any real scan context is supplied.
- A four-scenario compatibility harness must pass before the model can open a
  real agent session.
- Scan data stays in Rust. Only bounded results selected by analyzer tools enter
  the local model context.
- No telemetry, analytics, cloud inference provider, proxy service, remote model
  endpoint, or web-search tool is present.

### Persistence

Persisted locally:

- protected-path identities and dismissed suggestion keys;
- local model compatibility cache keyed by digest and Ollama version; and
- the remembered open/collapsed state of the AI dock.

Session-only:

- scan arena and analyzer index;
- chat context and deterministic session summary;
- trusted analyzer attachment; and
- cleanup Plan.

Never persisted by ClutterHunter:

- raw model thinking;
- approved log contents;
- full scan-index exports; and
- model prompts or results in a cloud service.

## 6. Evaluation

### Storage Evaluation Method

The usable-view benchmark starts after elevation completes and stops only after
the raw scan, deterministic enrichment, stable summary, and first analyzer query
are ready. This avoids reporting only the MFT parser time while the interface is
still unusable.

The nearby WizTree observation on the same machine reported 21.00 seconds at its
scan-complete indicator and required additional time before all files and the
treemap appeared. ClutterHunter's measured three-run warm median was 18.074
seconds to a usable view. This is encouraging observational evidence, not a
controlled universal claim: a strict comparison still requires matched cache
state, volume state, process load, and repeated runs for both applications.

### Local Model Evaluation

The compatibility harness checks four behaviors:

1. scan overview from bounded evidence;
2. named-folder scope and storage query;
3. conservative versus review cleanup totals; and
4. honest handling of empty results, with one bounded repair attempt.

| Model | Outcome | Decision |
| --- | --- | --- |
| `granite4:1b-h` | Passed 4/4 native streaming scenarios and the full live runtime sequence | Supported light fallback on tested hardware |
| `functiongemma:latest` | Failed three full-agent scenarios and scored 0/4 in a separate router test | Not used in a two-model pipeline |
| `lfm2.5-thinking:latest` | Streamed thinking but produced no usable tool calls | Rejected |
| `qwen3.5:2b` | Overview exceeded the focused 20-second step limit; rejected run took 80.6 s | Rejected on tested hardware |

### Automated Verification

- 114 enabled Rust workspace tests pass; seven platform/helper diagnostics are
  intentionally ignored unless their required environment is present.
- 62 frontend tests pass; two live-model tests remain opt-in.
- Four Playwright desktop workflow tests pass.
- Warning-denied Rust workspace Clippy passes.
- TypeScript 7 production build passes.
- Release, MSI, and NSIS builds have been exercised, while the distributed format
  remains the portable Windows build described by the project.

### Known Failure Cases and Limitations

- Small models can produce weak explanations or hallucinated prose. Deterministic
  routing, authoritative typed result cards, and evidence-only values reduce but
  do not eliminate prose-quality limitations.
- A model that advertises tool capability can still fail the behavior harness.
- Ollama memory estimates can be pessimistic when GPU VRAM is free, so users may
  explicitly try a model after a warning.
- Partial access or a changing USN journal downgrades coverage and prevents
  automatic candidate selection until a fresh scan is available.
- Traversal fallback is slower and cannot account for NTFS alternate data streams.
- Ownership mapping is evidence, not proof of cleanup safety.
- Direct deletion, recycling, moving, and uninstall execution are intentionally
  absent.

## 7. Privacy and Safety

### Data Handling

- Filesystem names, paths, sizes, ownership, policy evidence, and approved text
  excerpts remain on the device.
- The model receives only the bounded evidence required for the current turn.
- Selecting an analyzer row attaches metadata, not file content.
- File content can be read only through the approved log-inspection command and
  only for narrowly classified text log/crash files.
- Log reads are bounded, revalidated against the active scan, and rejected for
  reparse points, encryption, binary content, changed files, or unsupported rules.

### Permissions and Process Isolation

- The main Tauri application and AI runtime run without elevation.
- Fast NTFS scanning uses a separate helper launched through Windows `runas`.
- Data and cancellation use separate authenticated named pipes restricted to the
  current Windows user.
- The host verifies protocol version, nonce, helper PID, connected client PID,
  target, frame ordering, frame sizes, UTF-8 names, hierarchy links, and cycles.
- The helper opens the raw volume read-only and exposes no general elevated shell
  or file-operation interface.
- Ordinary traversal avoids reparse traversal, stays on the source volume, and
  detects cycles.

### Agent Safety

- No shell, delete, write, move, recycle, uninstall, arbitrary-read, web-search,
  or code-execution agent tool exists.
- Cleanup classifications come from deterministic Rust policy rules.
- Cleanup plans are editable proposals and do not mutate the filesystem.
- User-protected paths, personal/source data, system paths, installed
  applications, shared Ollama blobs, and unknown data are excluded from automatic
  suggestions.
- Generated project data, Recycle Bin contents, and owner-managed cleanup areas
  require review.
- Exact user-temp, known cache, crash-report, npm cache/log, and Scoop cache roots
  can qualify as candidates only when scan coverage is stable.
- Log inspection and persistent path protection require explicit approval.

### Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Model hallucination | Deterministic routing, required evidence tools, typed cards, model-independent values |
| Wrong or stale scan reference | Session-bound IDs/cursors, stale-session rejection, rescan warnings |
| Sensitive text entering context | Explicit approval, narrow file rules, strict byte caps, local-only inference, no persistence |
| Elevated parser or protocol defect | Small helper boundary, read-only volume handle, authenticated pipes, bounded validation, cancellation watchdog |
| Unsafe cleanup suggestion | Fixed policy precedence, coverage downgrade, subtree-safe grouping, editable proposal only |
| Local Ollama misconfiguration | Loopback canonicalization, redirect/remote/cloud rejection, exact-model preflight |
| Resource pressure | Model fit estimate, visible warning and override, bounded context/results, explicit model loading |

ClutterHunter reduces risk through read-only operation and deterministic evidence,
but it cannot guarantee that every third-party cache is disposable or that every
local model explanation is correct. Users should review paths, ownership,
warnings, and proposed owner-native actions before acting outside the application.

## Evidence and Attribution

- [Architecture](ARCHITECTURE.md)
- [Scanner measurements](docs/ScannerSpike.md)
- [Analyzer and policy measurements](docs/AnalyzerCore.md)
- [Local agent verification](docs/LocalAgent.md)
- [Product specification](docs/ProductPlan.md)
- [Third-party attribution](THIRD_PARTY_NOTICES.md)
