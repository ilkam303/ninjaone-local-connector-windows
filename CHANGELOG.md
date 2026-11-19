# Changelog

## 1.0.0-win — 2026-11-18

First Windows 11 release. Ported from the macOS connector at v1.1.0; the API
client, sync engine, bridge protocol, and reporting skill are carried over
unchanged, so bridge behaviour is identical across platforms.

### Platform layer (new)

- **Credential storage** moved to Windows Credential Manager via ctypes
  (`advapi32` CredReadW/CredWriteW/CredDeleteW). Client ID in the user-name
  field, Client Secret in the DPAPI-protected blob. In-process: the secret
  never reaches argv, stdin, the environment, or a child process. The macOS
  Keychain backend is retained behind the same API, so the tree runs and tests
  on either platform.
- **App root** is `%LOCALAPPDATA%\ninjaone-connector`.
- **Permissions** via `icacls /inheritance:r`, granting only the current user
  and SYSTEM — the NTFS equivalent of the macOS 0700/0600 regime. Best effort
  and reported by `doctor`, never fatal mid-run.
- **Scheduling** via Task Scheduler XML (`NinjaOneConnectorSync`,
  `NinjaOneConnectorBridge`): LeastPrivilege, hidden, InteractiveToken, written
  UTF-16 as declared, absolute interpreter and script paths. `pythonw.exe` is
  preferred so the watcher has no console window.
- **Bridge trigger** is a resident watcher (`bridge --watch`, `nj_watch.py`)
  that blocks in the kernel on `ReadDirectoryChangesW`, rather than a poll
  loop. It coalesces change bursts so one request file causes one drain, and
  re-drains on startup to recover anything missed while it was down.
- **Locking** uses `msvcrt.locking` byte-range locks where POSIX used
  `fcntl.flock`, released on every path.
- **Installers** `install.ps1` / `uninstall.ps1` replace the shell scripts.

### Carried over deliberately unchanged

- The sync task has a **logon trigger and nothing else** — no repeating
  trigger, no interval. This connector's sync model is on-demand; freshness
  comes from each bridge request delta-syncing when the cache exceeds the
  staleness budget. A repeating trigger here would silently reintroduce
  polling, so a test pins its absence.
- `scope=monitoring` only, plus the GET-only choke point with a single carve-out
  for the OAuth token POST.
- Inventory syncs from `/v2/devices-detailed`, not `/v2/devices` — the lean
  endpoint omits OS, boot time, and IP, and `lastBootTime` is nested inside
  the `os` object.
- CSV hardening (`csv_cell`): control characters stripped, newlines folded,
  spreadsheet formula injection defused.

### Windows-specific hardening added during the build

- Installer rejects the Microsoft Store `python` stub (it only opens the Store)
  and any interpreter whose TLS trust store is empty.
- Installer warns when the default exchange folder sits inside a
  OneDrive-synced location, which can lock, re-write, or cloud-tier bridge
  files underneath the connector.
- `uninstall.ps1` prefers the connector's own `teardown --all` (which preserves
  `exports\keep\`) and only falls back to direct file removal when no usable
  Python remains.

### Adversarial review (2026-11-18)

Reviewed by a separate agent that did not write the code, findings-only. 26
findings; all addressed before first release, each with a regression test. See
`SECURITY_REVIEW.md`. Headline items:

- **C1** `atomic_write` used bare `os.O_NOFOLLOW` — a POSIX-only constant — so
  the connector could not complete setup on Windows at all. The 223-test suite
  missed it because the Windows tests mocked `IS_WINDOWS` instead of exercising
  the branch; regressions now remove the attribute for real.
- **C2** the same line lacked `O_BINARY`, which would have corrupted the
  published SQLite snapshot through text-mode newline translation.
- **C3** `_archive()` had no containment check, so a redirected archive
  directory could cause writes to land outside the exchange root. Now guarded
  in two independent places.
- **C9** log redaction missed tracebacks; a secret inside an exception reached
  the log verbatim (reproduced). Now redacted by the Formatter.
- **C10/C11** `doctor` could never pass on Windows, and verified the generated
  task XML rather than the registered task.

### Known limitations

- Windows-native code paths (ctypes into advapi32, msvcrt locks,
  ReadDirectoryChangesW, schtasks, icacls) are reviewed, unit-tested where the
  branch point allows, and PowerShell-parsed — but **not yet smoke-tested on a
  real Windows machine**. First install should run `doctor` and the full test
  suite before the connector is trusted.
