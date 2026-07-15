param(
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

function Get-Sha256([string]$Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace("-", "").ToLowerInvariant()
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

$repoRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$tauriRoot = Join-Path $repoRoot "src-tauri"
$artifactRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot "artifacts"))
$config = Get-Content -Raw -LiteralPath (Join-Path $tauriRoot "tauri.conf.json") | ConvertFrom-Json
$version = [string]$config.version
$targetTriple = (& rustc --print host-tuple).Trim()
if ($LASTEXITCODE -ne 0 -or $targetTriple -notmatch "^x86_64-.*-windows-") {
    throw "The portable packager currently supports Windows x64 hosts only. Detected '$targetTriple'."
}

if (-not $SkipBuild) {
    Push-Location $repoRoot
    try {
        & pnpm tauri build --no-bundle --ci --no-sign
        if ($LASTEXITCODE -ne 0) {
            throw "Tauri release build failed with status $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}

$mainCandidates = @(
    (Join-Path $tauriRoot "target\release\clutterhunter.exe"),
    (Join-Path $tauriRoot "target\$targetTriple\release\clutterhunter.exe")
)
$mainExe = $mainCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
$helperExe = Join-Path $tauriRoot "binaries\clutter-scanner-helper-$targetTriple.exe"
if (-not $mainExe) {
    throw "Release executable was not found. Run this script without -SkipBuild."
}
if (-not (Test-Path -LiteralPath $helperExe -PathType Leaf)) {
    throw "Staged scanner helper was not found at '$helperExe'. Run this script without -SkipBuild."
}

$packageName = "ClutterHunter-$version-windows-x64"
$stage = [System.IO.Path]::GetFullPath((Join-Path $artifactRoot $packageName))
$zipPath = [System.IO.Path]::GetFullPath((Join-Path $artifactRoot "$packageName.zip"))
if (-not $stage.StartsWith($artifactRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to stage outside the artifact directory."
}

New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null
if (Test-Path -LiteralPath $stage) {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
New-Item -ItemType Directory -Path $stage | Out-Null

Copy-Item -LiteralPath $mainExe -Destination (Join-Path $stage "ClutterHunter.exe")
Copy-Item -LiteralPath $helperExe -Destination (Join-Path $stage "clutter-scanner-helper.exe")
Copy-Item -LiteralPath (Join-Path $repoRoot "README.md") -Destination $stage
Copy-Item -LiteralPath (Join-Path $repoRoot "THIRD_PARTY_NOTICES.md") -Destination $stage
Copy-Item -LiteralPath (Join-Path $repoRoot "release\PREREQUISITES.md") -Destination $stage
Copy-Item -LiteralPath (Join-Path $repoRoot "release\RELEASE_NOTES.md") -Destination $stage

$inventory = [System.Collections.Generic.List[string]]::new()
$inventory.Add("ClutterHunter $version dependency license inventory")
$inventory.Add("Generated UTC: $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))")
$inventory.Add("")
$inventory.Add("Rust dependencies")
$inventory.Add("-----------------")
$cargoRows = & cargo tree `
    --manifest-path (Join-Path $tauriRoot "Cargo.toml") `
    --locked `
    --offline `
    --target $targetTriple `
    --edges normal,build `
    --prefix none `
    --format "{p}|{l}"
if ($LASTEXITCODE -ne 0) { throw "cargo license inventory failed with status $LASTEXITCODE." }
$cargoRows |
    ForEach-Object { $_ -replace " \(\*\)$", "" -replace " \(proc-macro\)", "" } |
    Sort-Object -Unique |
    ForEach-Object { $inventory.Add($_) }

$inventory.Add("")
$inventory.Add("Production JavaScript dependencies")
$inventory.Add("----------------------------------")
$pnpmJson = (& pnpm licenses list --prod --json | Out-String)
if ($LASTEXITCODE -ne 0) { throw "pnpm license inventory failed with status $LASTEXITCODE." }
$pnpmLicenses = $pnpmJson | ConvertFrom-Json
$javascriptRows = foreach ($licenseGroup in $pnpmLicenses.PSObject.Properties) {
    foreach ($dependency in $licenseGroup.Value) {
        foreach ($dependencyVersion in $dependency.versions) {
            "$($dependency.name) $dependencyVersion | $($licenseGroup.Name)"
        }
    }
}
$javascriptRows | Sort-Object -Unique | ForEach-Object { $inventory.Add($_) }
$inventory | Set-Content -LiteralPath (Join-Path $stage "DEPENDENCY_LICENSES.txt") -Encoding utf8

$hashLines = Get-ChildItem -LiteralPath $stage -File -Recurse |
    Sort-Object FullName |
    ForEach-Object {
        $relative = $_.FullName.Substring($stage.Length).TrimStart([char[]]@('\', '/')).Replace('\', '/')
        "$(Get-Sha256 $_.FullName) *$relative"
    }
$hashLines | Set-Content -LiteralPath (Join-Path $stage "SHA256SUMS.txt") -Encoding ascii

Compress-Archive -LiteralPath $stage -DestinationPath $zipPath -CompressionLevel Optimal
$zipHash = Get-Sha256 $zipPath
"$zipHash *$([System.IO.Path]::GetFileName($zipPath))" |
    Set-Content -LiteralPath "$zipPath.sha256" -Encoding ascii

Write-Host "Portable package: $zipPath"
Write-Host "ZIP SHA-256:    $zipHash"
