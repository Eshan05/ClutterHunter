# Scanner Spike Notes

Status: implementation-order item 2 complete; remaining benchmark repetition belongs to item 5 hardening  
Last updated: 2026-07-15

This file records scanner decisions and measured gaps that are too detailed for
the product contract in [ProductPlan.md](ProductPlan.md).

## Current Vertical Slice

- Windows volumes are enumerated through Win32 volume APIs rather than a
  hardcoded `C:` target. Targets include filesystem type, volume identity, total
  bytes, available bytes, and whether the NTFS fast path is eligible.
- The Tauri host owns one active scan and one completed immutable scan. A failed
  or cancelled replacement does not overwrite the previous completed result.
- The real read-only traversal backend streams typed progress over a Tauri
  channel, supports cancellation, avoids reparse traversal, stays within the
  source volume, detects cycles, records inaccessible paths, and normalizes
  hard-link allocation.
- Results land in a compact contiguous arena with `u32` relationships and a
  packed name pool. The webview receives a maximum of 100 rows per query.
- Eligible NTFS targets now select the raw MFT backend by default, matching
  eDirStat's MFT-first behavior. A recoverable raw/UAC failure is shown before
  the Scan control offers an explicit traversal retry; backends never switch
  silently.
- Raw progress streams both parsed-entry count and physical allocated bytes.
  The allocation accumulator uses the same unnamed-data, named-stream,
  directory, and hard-link ownership rules as final arena construction rather
  than displaying MFT bytes read as disk usage.

## Raw NTFS Backend

The Rust fast path is implemented behind the helper boundary and is the default
for eligible NTFS targets. Its current pipeline:

1. creates separate random per-scan data and cancellation pipes whose ACLs grant
   only the current Windows user, then launches the narrow helper through the
   `runas` verb;
2. verifies the connected pipe client PID plus a protocol-version, nonce,
   helper-PID, and target handshake before accepting scan data;
3. opens the direct DOS volume path with eDirStat's proven sharing and sequential
   non-buffered flags, plus a separate buffered handle for the NTFS boot sector,
   `$MFT` data-run map, and journal queries;
4. overlaps four reusable, 4096-byte-aligned 4 MiB reads with parallel record
   parsing while reusing the validated raw-volume handle;
5. applies update-sequence fixups and parses resident/non-resident attributes;
6. preserves separate logical and allocated sizes, compressed/sparse allocation,
   alternate-stream evidence, reparse flags, timestamps, and all non-DOS links;
7. assigns physical allocation to one deterministic hard-link entry;
8. builds the hierarchy-complete compact arena in helper record order, including
   directory aggregation, then streams bounded sequenced node/name frames;
9. validates frame sizes, ordering, declared counts, UTF-8 names, hierarchy links,
   and parent cycles before adopting the arena directly in `clutter-core`; and
10. captures bounded USN journal positions through duplicates of the metadata
    handle before and after enumeration, marks a changed journal as
    potentially stale, and records exact arena/process memory diagnostics;
11. streams live MFT progress while cooperative cancellation travels over its own
    authenticated pipe, avoiding synchronous duplex-handle serialization; and
12. cancels synchronous Windows I/O after 15 seconds without progress, retains a
    termination fallback, and bounds the host's helper-exit wait.

The application path no longer writes a temporary scan snapshot. The helper's
`snapshot` and `inspect` commands remain as explicit diagnostic tools for frozen
fixtures and offline transport inspection; they are not used by a normal scan.

Tauri packages the helper through `bundle.externalBin`. The CLI hooks build the
matching Rust target/profile and stage the required target-triple filename before
both development and release builds.

## Current Measurement

The accepted optimized warm-cache smoke run on the current `C:` volume after the
reboot on 2026-07-14 produced:

- 6,146,048 MFT slots and 6,293,553,152 MFT bytes read;
- 7,299,752 adopted entries;
- helper raw scan and arena finalization: 6.820 seconds;
- named-pipe transfer: 1.292 seconds; direct core adoption: 0.601 seconds;
- 9.66 seconds for the complete Rust smoke-test body;
- 472,736,309,248 allocated bytes indexed;
- 620,160,659 bytes of final arena capacity;
- lifetime peaks of 1,133,899,776 helper bytes and 656,871,424 host bytes; and
- a sampled concurrent helper-plus-host peak of 1,275,105,280 bytes.

The helper owner table is now independently releasable chunks rather than one
monolithic allocation. Owner paths use packed 16-byte links and shared name bytes
instead of millions of inline `String`/`SmallVec` values. Finalization compacts
only accepted names into an exact-capacity arena and releases source chunks as it
progresses. Compared with the initial accepted post-reboot run, helper peak fell
from 1.92 GB to 1.13 GB and complete smoke time fell from 10.52 to 9.66 seconds.
The measured 7.30-million-entry concurrent peak scales to about 873 MB at the
five-million-entry contract target, before the helper exits.

The warm usable-view benchmark now includes raw scan, ownership/policy
classification, stable coverage/totals, and the first 50-row analyzer query. Its
three runs were 18.484, 18.074, and 18.035 seconds, for an 18.074-second median;
the bounded first query was below the millisecond timer and real-session Rust
state was about 664 MB at 7.30 million entries. The user's nearby WizTree
observation was 21.00 seconds for displayed scan completion, followed by more time
before all files and the treemap appeared. This is useful trajectory evidence,
not a controlled product comparison: a same-session WizTree capture and three
cold-cache ClutterHunter runs remain required.

After enabling the raw backend in the release UI on 2026-07-15, the user's next
real `C:` scan reported 6,941,824 items, 440.4 GB allocated, and 19.6 seconds to
the populated analyzer view. The nearby WizTree observation was 21.00 seconds
to its scan-complete indicator and still needed additional population time.
This confirms the UI was previously timing traversal rather than the implemented
fast path; it remains an observational comparison until the controlled
three-run cold/warm protocol is completed.

Protocol v10 then added running physical-allocation progress using the same
unnamed-stream, named-stream, directory, and hard-link ownership rules as final
aggregation. The user confirmed that both Items and Allocated now advance during
a real MFT scan; the final totals remain authoritative.

The reboot-only hold was not a raw-volume `CreateFile` failure. The helper had
duplicated one synchronous duplex named-pipe handle: a blocking cancellation read
could serialize a progress write on the shared Windows pipe object, which also
prevented the watchdog from reporting. Separate data and cancellation pipe
instances removed that race. The elevated raw-versus-traversal fixture now passes
resident/non-resident, sparse, compressed, hard-link, alternate-stream, Unicode,
reparse, zero-byte, and concurrently changing-file checks. Its accepted warm run
finished in 8.67 seconds. Sparse/compressed physical allocation now uses the NTFS
compressed-size field rather than the reserved-allocation field.

The synthetic analyzer gate remains healthy independently: five million entries
reached the first bounded search in 200 ms with 390,000,065 bytes of modeled
first-view Rust state. Current-machine ownership discovery passed for 275 roots.
The full Rust workspace, warning-denied clippy, TypeScript/Vite production build,
and Tauri release build pass. Protocol v10 adds physical allocation to bounded
progress frames and rebuilds both host and helper. MSI/NSIS archive acceptance
must be repeated for this wire revision. Windows Graphics Capture still fails
with `SetIsBorderRequired ... 0x80004002`; ShareX screenshots and accessibility
state provide current visual evidence instead.

## eDirStat Reuse

[eDirStat](https://github.com/xangelix/edirstat) is MIT-licensed and provides a
strong reference implementation for the analyzer core. ClutterHunter adapts its
work-stealing traversal design and raw-volume ingestion mechanics with
attribution rather than reimplementing stable low-level mechanics.

Code cannot be copied unchanged because eDirStat currently:

- stores one size rather than separate logical and allocated sizes;
- assigns size to secondary hard-link paths, which would overcount physical use;
- runs raw disk access in the application process rather than a narrow helper;
- publishes an egui-oriented snapshot rather than bounded Tauri DTO queries;
- does not carry ClutterHunter's coverage and policy evidence contracts.

We retain its high-value ingestion, fixup, data-run, work-stealing, and arena
ideas while correcting those boundaries. See
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) for attribution.

## ntfs-reader Spike

`ntfs-reader` 0.4.5 remains useful as an independent parser and differential
oracle. The helper now compiles a raw-volume probe that counts records, logical
and allocated data attributes, hard-linked records, reparse points, named data
streams, and attribute-list records.

The crate's high-level `FileInfo` is not sufficient as ClutterHunter's final
backend because it exposes one data size, selects one preferred path, and does
not provide the complete allocation/hard-link/alternate-stream model required by
the product contract. It remains behind the helper boundary and can be replaced
without changing public DTOs.

## Differential Fixtures

Validation before enabling `RawNtfsBackend` compared eDirStat-derived parsing,
`ntfs-reader`, Win32 metadata, and traversal on fixtures containing:

1. resident and non-resident data;
2. sparse and compressed files;
3. multiple hard links in different directories;
4. junctions, symlinks, and mount points;
5. named data streams;
6. attribute-list extension records;
7. inaccessible directories;
8. paths with spaces, Unicode, and non-round-trippable display names;
9. files changed during enumeration;
10. enough synthetic nodes to measure five-million-entry arena memory.

Frozen MFT records now cover resident/non-resident data, sparse/compressed-style
allocation, hard links, named streams, attribute lists, fixups, Unicode, corrupt
records, and subtree rebasing. Named-stream logical and allocated bytes are now
included in the owning file totals rather than only counted diagnostically. The
ignored elevated folder fixture creates resident/non-resident, sparse, compressed,
hard-link, alternate-stream, Unicode, reparse, zero-byte, and mutating-file cases,
then compares raw and traversal totals and hierarchy. It passes on the current
real NTFS volume. The five-million-entry arena gate measured `340,000,059` bytes
and `523` ms adoption.

Raw mode is enabled by default for eligible NTFS targets after the warm memory,
usable-view, differential-fixture, and release-UI trajectories passed. UAC launch,
isolated restricted named-pipe transport,
nonce/PID validation, bounded Bincode frames, live progress, USN staleness fields,
packaged sidecar staging, cooperative cancellation, synchronous-I/O cancellation,
stall termination, concurrent memory sampling, and stable decline/helper-failure
codes are present. The protocol-v10 release, MSI, and NSIS builds pass; MSI
extraction reproduces the staged helper byte-for-byte with SHA-256
`a2ae1b262c9ecad5dfe619b96076a60ff6b6291657344bcfe931325741a1c5fd`.
Three controlled cold-cache runs and a same-session WizTree repetition remain
item 5 benchmark evidence; they are not scanner implementation gaps.

## Owner-Native Cleanup

Storage ownership and cleanup execution are separate. The product may recognize
Ollama blobs, Scoop versions, or application directories, but future actions use
the owner's supported command or Windows surface. Direct deletion is reserved
for reviewed disposable cache/temp/log rules. The durable action policy is in
[ProductPlan.md](ProductPlan.md#91-owner-native-actions).
