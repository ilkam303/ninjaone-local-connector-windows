# NinjaOne local connector installer (Windows 11). PowerShell 5.1+, no admin needed.
#
# Mirrors the macOS installer's rules:
#  - Discovers a usable Python 3 (>= 3.9, working sqlite3 + ssl, and a CA trust
#    store that can actually verify HTTPS). Treats the Microsoft Store python
#    stub as absent. Records the ABSOLUTE interpreter path. NEVER installs
#    Python silently - if none is found it prints one clear remediation and
#    exits nonzero.
#  - Copies the connector to a private app root (%LOCALAPPDATA%\ninjaone-connector),
#    hardens its ACLs, installs the reporting skill, stages the uninstaller,
#    then runs interactive setup. Credentials go straight into Windows
#    Credential Manager and are never written to a file or passed as arguments.
#
# Run:  powershell -ExecutionPolicy Bypass -File install.ps1
# Test-only flag: -DiscoverOnly prints the chosen interpreter and exits.

param(
    [switch]$DiscoverOnly
)

$ErrorActionPreference = "Stop"
$SrcDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$AppRoot = Join-Path $env:LOCALAPPDATA "ninjaone-connector"

function Test-Python {
    param([string]$Exe)
    if (-not $Exe -or -not (Test-Path $Exe)) { return $false }
    # The Microsoft Store stub lives in WindowsApps and just opens the Store.
    if ($Exe -like "*\Microsoft\WindowsApps\*") { return $false }
    try {
        & $Exe -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" 2>$null
        if ($LASTEXITCODE -ne 0) { return $false }
        & $Exe -c "import sqlite3, ssl" 2>$null
        if ($LASTEXITCODE -ne 0) { return $false }
        # Reject interpreters whose TLS trust store is empty - they import ssl
        # fine but every HTTPS call dies with CERTIFICATE_VERIFY_FAILED. Same
        # failure class the macOS installer guards against.
        & $Exe -c "import ssl,sys; sys.exit(0 if ssl.create_default_context().cert_store_stats()['x509_ca']>0 else 1)" 2>$null
        if ($LASTEXITCODE -ne 0) { return $false }
        return $true
    } catch { return $false }
}

function Find-Python {
    $candidates = @()
    # 1. The py launcher's idea of the newest Python 3.
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        try {
            $resolved = & $py.Source -3 -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $resolved) { $candidates += $resolved.Trim() }
        } catch {}
    }
    # 2. python on PATH (Store stub filtered inside Test-Python).
    Get-Command python -All -ErrorAction SilentlyContinue | ForEach-Object {
        $candidates += $_.Source
    }
    # 3. Standard per-user and machine install locations, newest first.
    $globs = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python3*\python.exe"),
        "C:\Program Files\Python3*\python.exe",
        "C:\Python3*\python.exe"
    )
    foreach ($glob in $globs) {
        # Sort on the PARSED version, not the name: a lexical descending sort
        # ranks Python39 above Python312.
        Get-Item $glob -ErrorAction SilentlyContinue |
            Sort-Object -Descending -Property @{ Expression = {
                if ($_.Directory.Name -match 'Python(\d)(\d+)$') {
                    [int]$Matches[1] * 1000 + [int]$Matches[2]
                } else { 0 }
            }} | ForEach-Object {
                $candidates += $_.FullName
            }
    }
    foreach ($candidate in $candidates) {
        if (Test-Python $candidate) { return $candidate }
    }
    return $null
}

$Python = Find-Python
if (-not $Python) {
    Write-Host "No usable Python 3 (>= 3.9 with sqlite3, ssl, and a working"
    Write-Host "certificate store) was found. Fix with ONE of:"
    Write-Host "  1. winget install -e --id Python.Python.3.12   (recommended)"
    Write-Host "  2. Install from https://www.python.org/downloads/windows/"
    Write-Host "Then re-run this installer. (The Microsoft Store 'python' stub"
    Write-Host "does not count - it only opens the Store.)"
    exit 1
}

if ($DiscoverOnly) { Write-Output $Python; exit 0 }

Write-Host "Using Python: $Python"

# ---------------------------------------------------------------------------
# Sanity: the pieces of Windows this connector needs (all standard on Win 11)
# ---------------------------------------------------------------------------
$schtasks = Join-Path $env:SystemRoot "System32\schtasks.exe"
if (-not (Test-Path $schtasks)) {
    Write-Host "ERROR: schtasks.exe not found - cannot register background jobs."
    exit 1
}

# ---------------------------------------------------------------------------
# Exchange-folder sanity: OneDrive / redirected known folders
#
# If the exchange folder ends up inside a OneDrive-synced or redirected
# location, the sync client re-writes, locks and may cloud-tier the request and
# response files underneath the bridge. That produces intermittent, extremely
# confusing failures. Warn before setup rather than debugging it later.
# ---------------------------------------------------------------------------
$DefaultExchange = Join-Path $env:USERPROFILE "NinjaOneData"
$syncRoots = @()
foreach ($var in @("OneDrive", "OneDriveCommercial", "OneDriveConsumer")) {
    $val = [Environment]::GetEnvironmentVariable($var)
    if ($val) { $syncRoots += $val }
}
function Test-UnderSyncRoot {
    param([string]$Candidate, [string[]]$Roots)
    foreach ($r in $Roots) {
        if (-not $r) { continue }
        # Compare on a separator boundary: a bare StartsWith would match
        # C:\Users\me\OneDriveNotes against C:\Users\me\OneDrive, and miss
        # nothing-in-common cases the other way.
        $normRoot = $r.TrimEnd('\') + '\'
        $normCand = $Candidate.TrimEnd('\') + '\'
        if ($normCand.StartsWith($normRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $r
        }
    }
    return $null
}

foreach ($root in $syncRoots) {
    if (Test-UnderSyncRoot -Candidate $DefaultExchange -Roots @($root)) {
        Write-Host ""
        Write-Host "WARNING: the default exchange folder"
        Write-Host "  $DefaultExchange"
        Write-Host "sits inside a OneDrive-synced location ($root)."
        Write-Host "OneDrive can lock, re-write or cloud-tier the bridge files."
        Write-Host "Choose a NON-synced folder when setup asks (for example C:\NinjaOneData)."
        Write-Host ""
    }
}

# ---------------------------------------------------------------------------
# Install to the private app root
# ---------------------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $AppRoot | Out-Null

$modules = @("connector.py", "nj_api.py", "nj_bridge.py", "nj_common.py",
             "nj_credstore.py", "nj_sync.py", "nj_watch.py")
foreach ($module in $modules) {
    $src = Join-Path $SrcDir $module
    if (-not (Test-Path $src)) {
        Write-Host "ERROR: missing $module next to install.ps1"
        exit 1
    }
    Copy-Item $src (Join-Path $AppRoot $module) -Force
}

# Stage the uninstaller and docs inside the app root so a full teardown is
# possible after the download folder is gone.
foreach ($extra in @("uninstall.ps1", "README.md", "START-HERE.txt")) {
    $src = Join-Path $SrcDir $extra
    if (Test-Path $src) { Copy-Item $src (Join-Path $AppRoot $extra) -Force }
}

# Harden the app root: strip inheritance, grant only this user + SYSTEM
# (the NTFS equivalent of macOS 0700). Best effort.
$icacls = Join-Path $env:SystemRoot "System32\icacls.exe"
& $icacls $AppRoot /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" /grant:r "SYSTEM:(OI)(CI)F" | Out-Null

# Install the Cowork/Claude Code reporting skill (documentation-only).
$skillSrc = Join-Path $SrcDir "ninjaone-reporting\SKILL.md"
if (Test-Path $skillSrc) {
    $skillDir = Join-Path $env:USERPROFILE ".claude\skills\ninjaone-reporting"
    New-Item -ItemType Directory -Force -Path $skillDir | Out-Null
    Copy-Item $skillSrc (Join-Path $skillDir "SKILL.md") -Force
    Write-Host "Reporting skill installed to ~\.claude\skills\ninjaone-reporting\"
}

Write-Host ""
Write-Host "Connector installed to: $AppRoot"
Write-Host "Starting one-time setup. You will be asked for:"
Write-Host "  1. the NinjaOne instance (app / us2 / eu / ca / oc .ninjarmm.com)"
Write-Host "  2. the API client's Client ID and Client Secret (typing is hidden;"
Write-Host "     both are stored ONLY in Windows Credential Manager)"
Write-Host "  3. the exchange folder to connect to Cowork"
Write-Host ""
if ($syncRoots.Count -gt 0) {
    Write-Host "NOTE: if you type an exchange folder inside any of these synced"
    Write-Host "      locations, OneDrive can lock or cloud-tier the bridge files:"
    foreach ($r in $syncRoots) { Write-Host "        $r" }
    Write-Host ""
}
Write-Host "Create the API client first in NinjaOne:"
Write-Host "  Administration -> Apps -> API -> Client App IDs"
Write-Host "  Machine to Machine (client credentials), MONITORING scope only."
Write-Host ""

& $Python (Join-Path $AppRoot "connector.py") setup
exit $LASTEXITCODE
