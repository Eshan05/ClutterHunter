# ClutterHunter

ClutterHunter is a private, evidence-based storage analyzer and on-device AI
agent for Windows. The first milestone is non-destructive: it scans, visualizes,
explains, and builds cleanup plans without deleting files.

The decision-complete product and implementation specification lives in
[`docs/ProductPlan.md`](docs/ProductPlan.md). Current Rust implementation notes
live in [`docs/ScannerSpike.md`](docs/ScannerSpike.md) and
[`docs/AnalyzerCore.md`](docs/AnalyzerCore.md). Local Ollama/AI SDK implementation
evidence lives in [`docs/LocalAgent.md`](docs/LocalAgent.md).

## Development

Requirements:

- Windows 10/11 x64
- pnpm 11+
- Rust 1.85+
- WebView2

```powershell
pnpm install
pnpm tauri dev
```

Useful verification commands:

```powershell
pnpm build
cargo test --workspace --manifest-path src-tauri/Cargo.toml
```

The React webview owns presentation and bounded AI SDK 7 orchestration through
the loopback-only Ollama provider. Rust owns
scan data, bounded analyzer queries, ownership, policy, cleanup-plan proposals,
and the elevated scanner-helper boundary.
