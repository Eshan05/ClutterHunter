# ClutterHunter 0.1.0

Prototype release for the on-device AI storage analyzer milestone.

## Included

- Read-only NTFS MFT fast scan with a traversal fallback.
- Bounded native analyzer queries, virtualized hierarchy, extension summary,
  linked treemap, ownership/policy evidence, and deterministic cleanup plans.
- Optional loopback-only Ollama chat with local-model verification, bounded
  tools, approvals, cancellation, and typed evidence cards.
- Portable x64 payload: `ClutterHunter.exe`, the scanner helper, prerequisites,
  third-party notices, dependency inventory, and per-file SHA-256 hashes.

## Known Limitations

- The binaries are unsigned, so SmartScreen and UAC report Unknown Publisher.
- Fast scanning is Windows/NTFS-only. Other supported targets use traversal.
- Ollama and model files are not bundled. AI quality and speed depend on the
  locally selected model and hardware; the analyzer remains usable without AI.
- No delete, Recycle Bin, uninstall, shell-command, persisted-scan, or plan
  export action is included in this milestone.
- The demo VHD and WebView2 installer are deliberately not bundled.

`DEPENDENCY_LICENSES.txt` records the locked Rust and production JavaScript
dependency versions and declared licenses. `SHA256SUMS.txt` hashes every file
inside the portable folder; the adjacent `.zip.sha256` hashes the ZIP itself.
