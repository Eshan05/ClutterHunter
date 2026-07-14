param(
    [Parameter(Mandatory = $true)]
    [string]$ZipPath
)

$ErrorActionPreference = "Stop"

function Get-StreamSha256([System.IO.Stream]$Stream) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($Stream))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

$resolvedZip = (Resolve-Path -LiteralPath $ZipPath).Path
$sidecarHashPath = "$resolvedZip.sha256"
if (-not (Test-Path -LiteralPath $sidecarHashPath -PathType Leaf)) {
    throw "ZIP hash file is missing: '$sidecarHashPath'."
}

$zipStream = [System.IO.File]::OpenRead($resolvedZip)
try {
    $actualZipHash = Get-StreamSha256 $zipStream
}
finally {
    $zipStream.Dispose()
}
$expectedZipHash = ((Get-Content -Raw -LiteralPath $sidecarHashPath) -split "\s+")[0].ToLowerInvariant()
if ($expectedZipHash -notmatch "^[0-9a-f]{64}$" -or $actualZipHash -ne $expectedZipHash) {
    throw "ZIP SHA-256 mismatch. Expected '$expectedZipHash', got '$actualZipHash'."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($resolvedZip)
try {
    $files = @($archive.Entries | Where-Object { -not [string]::IsNullOrEmpty($_.Name) })
    if ($files.Count -eq 0) { throw "Portable ZIP is empty." }
    foreach ($entry in $files) {
        $normalized = $entry.FullName.Replace('\', '/')
        if ($normalized.StartsWith("/") -or $normalized -match "(^|/)\.\.(/|$)") {
            throw "Unsafe ZIP entry: '$($entry.FullName)'."
        }
    }

    $roots = @($files | ForEach-Object { $_.FullName.Replace('\', '/').Split('/')[0] } | Sort-Object -Unique)
    if ($roots.Count -ne 1 -or $roots[0] -notmatch "^ClutterHunter-[0-9]+\.[0-9]+\.[0-9]+-windows-x64$") {
        throw "Expected one versioned ClutterHunter root folder; found '$($roots -join ', ')'."
    }
    $root = $roots[0]
    $entries = @{}
    foreach ($entry in $files) {
        $entries[$entry.FullName.Replace('\', '/')] = $entry
    }
    $required = @(
        "ClutterHunter.exe",
        "clutter-scanner-helper.exe",
        "README.md",
        "PREREQUISITES.md",
        "RELEASE_NOTES.md",
        "THIRD_PARTY_NOTICES.md",
        "DEPENDENCY_LICENSES.txt",
        "SHA256SUMS.txt"
    )
    foreach ($name in $required) {
        if (-not $entries.ContainsKey("$root/$name")) { throw "Portable payload is missing '$name'." }
    }

    $manifestEntry = $entries["$root/SHA256SUMS.txt"]
    $reader = [System.IO.StreamReader]::new($manifestEntry.Open())
    try {
        $manifestText = $reader.ReadToEnd()
    }
    finally {
        $reader.Dispose()
    }
    $manifestFiles = @{}
    foreach ($line in ($manifestText -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -notmatch "^([0-9a-f]{64}) \*(.+)$") { throw "Invalid manifest line: '$line'." }
        $manifestFiles[$matches[2].Replace('\', '/')] = $matches[1]
    }

    foreach ($entry in $files | Where-Object { $_.Name -ne "SHA256SUMS.txt" }) {
        $relative = $entry.FullName.Replace('\', '/').Substring($root.Length + 1)
        if (-not $manifestFiles.ContainsKey($relative)) { throw "Manifest omits '$relative'." }
        $stream = $entry.Open()
        try {
            $actual = Get-StreamSha256 $stream
        }
        finally {
            $stream.Dispose()
        }
        if ($actual -ne $manifestFiles[$relative]) {
            throw "Payload SHA-256 mismatch for '$relative'."
        }
        $manifestFiles.Remove($relative)
    }
    if ($manifestFiles.Count -ne 0) {
        throw "Manifest references missing files: $($manifestFiles.Keys -join ', ')."
    }
}
finally {
    $archive.Dispose()
}

Write-Host "Verified portable ZIP: $resolvedZip"
Write-Host "ZIP SHA-256:         $actualZipHash"
