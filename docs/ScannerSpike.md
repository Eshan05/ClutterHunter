# Scanner Spike Notes

Status: scanner gates implemented in Rust; elevated differential rerun pending  
Last updated: 2026-07-14

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
- The current UI explicitly labels this backend as traversal. It does not claim
  MFT performance or silently switch from a failed raw scan.

## Raw NTFS Backend

The Rust fast path is implemented behind the helper boundary, but is not yet
the UI default. Its current pipeline:

1. creates a random per-scan named pipe whose ACL grants only the current
   Windows user, then launches the narrow helper through the `runas` verb;
2. verifies the connected pipe client PID plus a protocol-version, nonce,
   helper-PID, and target handshake before accepting scan data;
3. reads the NTFS boot sector and `$MFT` data-run map from the raw volume;
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
10. captures bounded USN journal positions before and after enumeration, marks a
    changed journal as potentially stale, and records exact arena/process memory
    diagnostics; and
11. streams live MFT progress and sends cooperative cancellation back over the
    same authenticated duplex pipe.

The application path no longer writes a temporary scan snapshot. The helper's
`snapshot` and `inspect` commands remain as explicit diagnostic tools for frozen
fixtures and offline transport inspection; they are not used by a normal scan.

Tauri packages the helper through `bundle.externalBin`. The CLI hooks build the
matching Rust target/profile and stage the required target-triple filename before
both development and release builds.

## Current Measurement

One optimized warm-cache smoke run on the current `C:` volume on 2026-07-14
produced:

- 7,281,764 adopted entries;
- helper raw scan and arena finalization: 8.010 seconds;
- named-pipe transfer, strict validation, and direct core arena adoption included:
  11.57 seconds for the complete Rust smoke-test body; and
- 464,675,604,328 allocated bytes indexed.

The user's nearby WizTree observation was 21.00 seconds for its displayed scan
completion, followed by additional time before all files and the treemap appeared.
These numbers are encouraging but are not a benchmark result: both are single,
uncontrolled runs, cache and system load differ, and ClutterHunter's measurement
does not yet include policy classification or the first interactive analyzer
view. Analyzer classification and bounded first-query measurements are now in
[AnalyzerCore.md](AnalyzerCore.md). The release gate remains median cold/warm runs
against the same volume and the same usable-view endpoint. A fresh elevated run
after the laptop reboot was not claimed: the manual helper remained at the Windows
elevation boundary while Computer Use was unavailable.

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

## Required Differential Fixtures

Before enabling `RawNtfsBackend` in the UI, compare eDirStat-derived parsing,
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
records, and subtree rebasing. An ignored elevated folder fixture compares raw and
traversal totals and hierarchy on the same generated tree. The five-million-entry
arena gate measured `340,000,059` bytes and `523` ms adoption.

Raw mode is enabled in the UI only after the ignored real-volume fixture and
controlled cold/warm benchmark are rerun successfully. UAC launch, restricted
named-pipe transport, nonce/PID validation, bounded Bincode frames, live progress,
USN staleness fields, packaged sidecar staging, cooperative pipe cancellation,
and stable decline/helper-failure codes are present.

## Owner-Native Cleanup

Storage ownership and cleanup execution are separate. The product may recognize
Ollama blobs, Scoop versions, or application directories, but future actions use
the owner's supported command or Windows surface. Direct deletion is reserved
for reviewed disposable cache/temp/log rules. The durable action policy is in
[ProductPlan.md](ProductPlan.md#91-owner-native-actions).
