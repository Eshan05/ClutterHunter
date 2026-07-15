param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("dev", "build")]
    [string]$Frontend
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$tauriRoot = Join-Path $repoRoot "src-tauri"
$targetTriple = $env:TAURI_ENV_TARGET_TRIPLE
if ([string]::IsNullOrWhiteSpace($targetTriple)) {
    $targetTriple = (& rustc --print host-tuple).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($targetTriple)) {
        throw "Could not determine the Rust target triple."
    }
}
if ($targetTriple -notmatch "windows") {
    throw "ClutterHunter's raw scanner sidecar currently supports Windows targets only."
}

$debugBuild = $env:TAURI_ENV_DEBUG -eq "true"
$profile = if ($debugBuild) { "debug" } else { "release" }
$cargoArgs = @(
    "build",
    "--manifest-path", (Join-Path $tauriRoot "Cargo.toml"),
    "--package", "clutter-scanner-helper",
    "--target", $targetTriple
)
if (-not $debugBuild) {
    $cargoArgs += "--release"
}

& cargo @cargoArgs
if ($LASTEXITCODE -ne 0) {
    throw "Scanner sidecar build failed with status $LASTEXITCODE."
}

$source = Join-Path $tauriRoot "target\$targetTriple\$profile\clutter-scanner-helper.exe"
$binaryDirectory = Join-Path $tauriRoot "binaries"
$destination = Join-Path $binaryDirectory "clutter-scanner-helper-$targetTriple.exe"
New-Item -ItemType Directory -Force -Path $binaryDirectory | Out-Null
Copy-Item -Force -LiteralPath $source -Destination $destination

Push-Location $repoRoot
try {
    & pnpm $Frontend
    if ($LASTEXITCODE -ne 0) {
        throw "Frontend $Frontend command failed with status $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
