# NinjaOne local connector uninstaller (Windows 11). PowerShell 5.1+, no admin.
#
# Removes every trace: both scheduled tasks, the Credential Manager item, the
# reporting skill, the private app root, and the exchange folder. Anything you
# saved in exports\keep\ is MOVED to your profile folder first, never deleted.
# Python itself is left untouched. Idempotent.
#
# Run:  powershell -ExecutionPolicy Bypass -File uninstall.ps1
# Flags: -Force skips the REMOVE confirmation. -KeepData leaves the exchange
#        folder and app root in place (tasks and credential still go).

param(
    [switch]$Force,
    [switch]$KeepData
)

$ErrorActionPreference = "Continue"
$AppRoot = Join-Path $env:LOCALAPPDATA "ninjaone-connector"
$SyncTask = "NinjaOneConnectorSync"
$BridgeTask = "NinjaOneConnectorBridge"
$cfgPath = Join-Path $AppRoot "config.json"

Write-Host "This removes the NinjaOne connector from this PC:"
Write-Host "  - both scheduled tasks ($SyncTask, $BridgeTask)"
Write-Host "  - the Windows Credential Manager item (Client ID + Secret)"
Write-Host "  - the reporting skill (~\.claude\skills\ninjaone-reporting)"
if (-not $KeepData) {
    Write-Host "  - the private app root (database and logs)"
    Write-Host "  - the exchange folder"
    Write-Host ""
    Write-Host "Anything in exports\keep\ is MOVED to your profile folder, not deleted."
}
Write-Host ""

if (-not $Force) {
    $answer = Read-Host "Type REMOVE to confirm"
    if ($answer -ne "REMOVE") {
        Write-Host "Cancelled - nothing was changed."
        exit 0
    }
}

function Test-ExchangeRootSafe {
    <#
      The uninstaller hands this path to a recursive delete. config.json lives
      in the hardened app root, but it was never re-validated after setup, so
      an exchange_root of C:\Users\<you> or \\server\share would simply be
      deleted. Refuse anything that is not a dedicated folder.
    #>
    param([string]$Path)
    if (-not $Path) { return $false }
    if ($Path.StartsWith("\\")) { return $false }                 # UNC / device
    if ($Path -match '^[A-Za-z]:$') { return $false }              # drive root
    if ($Path -match '^[A-Za-z]:\\?$') { return $false }
    try { $full = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path }
    catch { return $false }
    $forbidden = @($env:USERPROFILE, $env:LOCALAPPDATA, $env:APPDATA,
                   $env:SystemRoot, $env:ProgramFiles, "C:\")
    foreach ($f in $forbidden) {
        if ($f -and ($full.TrimEnd('\') -ieq $f.TrimEnd('\'))) { return $false }
    }
    return $true
}

function Remove-TreeSafely {
    <#
      Remove-Item -Recurse on Windows PowerShell 5.1 recurses THROUGH a
      junction and deletes the target's contents. The exchange root is
      writable by whatever was connected to it, so a planted junction is a
      landmine that detonates on uninstall. Delete depth-first, unlinking
      reparse points instead of descending into them.
    #>
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item) { return }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        # Remove the link itself, never what it points at.
        [IO.Directory]::Delete($item.FullName, $false)
        return
    }
    foreach ($child in Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue) {
        if ($child.PSIsContainer) {
            Remove-TreeSafely $child.FullName
        } else {
            Remove-Item -LiteralPath $child.FullName -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# 1. Scheduled tasks
# ---------------------------------------------------------------------------
$schtasks = Join-Path $env:SystemRoot "System32\schtasks.exe"
foreach ($task in @($SyncTask, $BridgeTask)) {
    & $schtasks /End /TN $task 2>$null | Out-Null
    & $schtasks /Delete /TN $task /F 2>$null | Out-Null
}
Write-Host "Scheduled tasks removed."

# ---------------------------------------------------------------------------
# 2. Prefer the connector's own teardown when a usable Python is still around:
#    it handles the credential item and the exports\keep\ preservation.
# ---------------------------------------------------------------------------
$ranTeardown = $false
$connector = Join-Path $AppRoot "connector.py"
if ((Test-Path $connector) -and (-not $KeepData)) {
    $python = $null
    if (Test-Path $cfgPath) {
        try {
            $python = (Get-Content $cfgPath -Raw | ConvertFrom-Json).python_path
        } catch {}
    }
    # config.json is the one attacker-influenceable input that reaches an
    # exec here. Require an actual python executable, not an arbitrary path.
    if ($python) {
        $leaf = Split-Path $python -Leaf
        if ($leaf -notmatch '^python(w)?\.exe$' -or -not (Test-Path $python -PathType Leaf)) {
            Write-Host "Ignoring an implausible python_path from config.json."
            $python = $null
        }
    }
    if (-not $python) {
        $cmd = Get-Command python -ErrorAction SilentlyContinue
        if ($cmd) { $python = $cmd.Source }
    }
    if ($python -and (Test-Path $python)) {
        & $python $connector teardown --all
        if ($LASTEXITCODE -eq 0) { $ranTeardown = $true }
    }
}

# ---------------------------------------------------------------------------
# 3. Best-effort fallback when no Python is left to run the clean teardown
# ---------------------------------------------------------------------------
if (-not $ranTeardown) {
    # Credential Manager item, via cmdkey (ships with Windows).
    & (Join-Path $env:SystemRoot "System32\cmdkey.exe") /delete:ninjaone-connector 2>$null | Out-Null

    $skillDir = Join-Path $env:USERPROFILE ".claude\skills\ninjaone-reporting"
    if (Test-Path $skillDir) { Remove-Item $skillDir -Recurse -Force -ErrorAction SilentlyContinue }

    if (-not $KeepData) {
        # Preserve saved exports before deleting anything.
        $exchange = Join-Path $env:USERPROFILE "NinjaOneData"
        if (Test-Path $cfgPath) {
            try {
                $fromCfg = (Get-Content $cfgPath -Raw | ConvertFrom-Json).exchange_root
                if ($fromCfg -and (Test-ExchangeRootSafe $fromCfg)) {
                    $exchange = $fromCfg
                } elseif ($fromCfg) {
                    Write-Host "Refusing the exchange_root in config.json ($fromCfg)."
                    Write-Host "Delete that folder yourself if you want it gone."
                    $exchange = $null
                }
            } catch {}
        }
        $keep = Join-Path $exchange "exports\keep"
        if ((Test-Path $keep) -and (Get-ChildItem $keep -Force -ErrorAction SilentlyContinue)) {
            $dest = Join-Path $env:USERPROFILE "NinjaOneData_saved_exports"
            $suffix = 1
            while (Test-Path $dest) {
                $dest = Join-Path $env:USERPROFILE ("NinjaOneData_saved_exports_" + $suffix)
                $suffix++
            }
            Move-Item $keep $dest -Force -ErrorAction SilentlyContinue
            Write-Host "Preserved your saved exports at: $dest"
        }
        if ($exchange -and (Test-Path $exchange)) { Remove-TreeSafely $exchange }
        if (Test-Path $AppRoot)  { Remove-TreeSafely $AppRoot }
    }
    Write-Host "Best-effort cleanup done."
}

Write-Host ""
Write-Host "Uninstall complete. Python itself was left untouched."
