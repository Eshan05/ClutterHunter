# ClutterHunter Portable Prerequisites

ClutterHunter 0.1.0 is an unsigned Windows x64 prototype. Extract the complete
ZIP before running `ClutterHunter.exe`; keep `clutter-scanner-helper.exe` beside
it. The helper is required for the fast NTFS scan and is not a standalone app.

## Required

- Windows 10 or Windows 11 on x64 hardware.
- Microsoft Edge WebView2 Evergreen Runtime. It is normally present on current
  Windows installations. If Windows reports that WebView2 is missing, install
  the official runtime from
  <https://developer.microsoft.com/en-us/microsoft-edge/webview2/>.

## Optional Local AI

The storage analyzer and deterministic cleanup Plan work without Ollama. Chat
requires a local Ollama installation and a locally downloaded tool-capable
model. ClutterHunter connects only to the loopback Ollama API; it does not use a
cloud AI provider. Official Windows instructions are at
<https://docs.ollama.com/windows>.

## Windows Security Prompts

This prototype is not code-signed. Windows SmartScreen may show an Unknown
Publisher warning. Verify the downloaded ZIP against its adjacent `.sha256`
file before choosing to run it. Do not bypass a warning for an artifact whose
source or hash you cannot verify.

The fast MFT scan requests elevation because raw NTFS access requires it. The
prompt should name `clutter-scanner-helper.exe` and show Unknown Publisher.
Declining elevation is safe: ClutterHunter offers the slower traversal scanner
instead. The application is read-only and does not delete or uninstall data.
