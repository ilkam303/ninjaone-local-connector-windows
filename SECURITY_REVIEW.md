# NinjaOne Local Connector (Windows) — Security Review

Adversarial review of the Windows port, performed **by a separate agent that
did not write the code**, reporting findings only with no authority to edit —
per the house rule for connector builds. 26 findings were raised (21 confirmed,
5 suspected). All are addressed below; each has a regression test in
`tests/test_redteam_regressions.py` written to fail against the pre-fix code.

Suite: `python -m unittest discover -s tests -t .` — **260 tests**, fully
offline behind a socket-level network guard.

---

## 1. What the review found that the test suite did not

The port shipped to review with 223 green tests. The reviewer's central
criticism was that those tests **mocked the platform flag rather than
exercising the platform branch**:

```python
with mock.patch.object(nj_common, "IS_WINDOWS", True):   # proves nothing
```

Patching a boolean does not execute Windows code. That is how a defect which
made the connector **unable to run on Windows at all** passed a full green
suite. The regressions added since do the opposite — for example, C1's test
genuinely removes `os.O_NOFOLLOW` from the `os` module and calls the real
function:

```python
saved = os.O_NOFOLLOW
try:
    del os.O_NOFOLLOW          # now the module looks like Windows
    nj_common.atomic_write(target, b'{"ok": true}')
finally:
    os.O_NOFOLLOW = saved
```

---

## 2. Confirmed findings and fixes

### Blockers — the connector could not run

| # | Finding | Fix |
|---|---|---|
| **C1** CRITICAL | `atomic_write` used bare `os.O_NOFOLLOW`, a POSIX-only constant. The first `save_config()` raised `AttributeError`, so setup could never complete; every bridge reply, export and publish would have failed the same way. `nj_bridge.py` already did this correctly, which made the omission easy to miss | Flags built with `getattr(os, "O_NOFOLLOW", 0)` |
| **C2** HIGH | Same line omitted `O_BINARY`. On Windows `os.open` returns a **text-mode** fd, so every `0x0A` written becomes `0x0D 0x0A` — silently corrupting the published `ninjaone.sqlite`, which is pushed through `atomic_write` whole | `getattr(os, "O_BINARY", 0)` added; a regression writes a 256-byte binary payload and asserts byte-exact round trip |

### Containment — the exchange root is hostile by design

| # | Finding | Fix |
|---|---|---|
| **C3** HIGH→CRITICAL | `_archive()` had **no containment check**, unlike `_respond`, which had one. Because the archive folder lives inside the hostile-writable exchange root, a redirected directory entry could cause the archive step to write outside that root — a containment break with serious consequences depending on where it lands | Two layers: `Exchange.ensure_dirs()` refuses to operate through any reparse point, and `_archive` independently sanitizes the name, re-checks `exchange.contains(dest)`, and deletes rather than relocates if either fails |
| **C4** HIGH | The export containment check resolved **both** sides of the comparison, so a redirected `exports/` made them agree while the write landed elsewhere | Anchored on the exchange root via `contains()`, plus an explicit reparse-point check on `exports/` and on the destination name |
| **C5/C21** MED | `exchange_root` was validated at setup and **never again**, yet it feeds `Exchange` and the recursive delete in `teardown --all`. An unexpected value could therefore reach a recursive delete. `uninstall.ps1` had the same exposure | `validate_exchange_root()` runs on every `load_config()`, rejecting home, drive roots, app-root overlap, UNC, device paths and drive-relative paths. `uninstall.ps1` gained `Test-ExchangeRootSafe` |
| **S5** LOW | `shutil.rmtree(..., ignore_errors=True)` and PowerShell's `Remove-Item -Recurse` both walk **through** reparse points, deleting the target's contents rather than just the link | `_safe_rmtree()` and `Remove-TreeSafely` delete depth-first, unlinking reparse points instead of descending |
| **C6** MED | `act_export` would happily write `sync_manifest.json` or `devices_summary.csv` — the two files the skill trusts — and `_sweep_exports` exempts them from cleanup, so a forgery persisted until the next publish | Both basenames reserved and rejected |
| **S3** LOW | Windows reserved device names (`NUL.csv` is still the NUL device) were admitted by `FILENAME_RE` | Explicit reject list (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`), rather than relying on path resolution to fail closed by accident |

### Availability and correctness

| # | Finding | Fix |
|---|---|---|
| **C7** MED | The watcher ignored a `FALSE` return from `ReadDirectoryChangesW`. Deleting `requests/` (which the hostile side can do) returns `ERROR_NOTIFY_CLEANUP` immediately and forever on the stale handle — **pinning a CPU core indefinitely** in a process documented as "effectively no CPU while idle", and the bridge never fires again | Breaks out to the reopen path, recreates the folder, paces reopens |
| **C12** MED | `drain()` had no cap on `requests/`, and each file can cost up to a second. On macOS launchd re-fires a fresh one-shot; on Windows this is **one long-lived process**, so a flood wedged the bridge | Capped at 200 files and 120 s per drain; overflow is answered `too_many_requests` and archived, never silently dropped |
| **C15** LOW | `ID_RE` was case-sensitive but NTFS and default APFS are not, so `request-ABC` and `request-abc` answered into one response file — one caller could race and replace another's reply | Ids restricted to lowercase. The filename-derived id is casefolded first so a mixed-case caller still receives a **findable** error rather than an unfindable `response-unknown.json` |
| **S1** MED | The lock file was opened `"w"` (TRUNCATE_EXISTING). A Windows byte-range lock covers offset 0 past EOF, so a second process could get `PermissionError` from `open()` — **before** the guarded block — and die with a traceback instead of logging "already running" | Opened `"a+"`, with the `open()` itself inside the `try` |

### Secret handling and observability

| # | Finding | Fix |
|---|---|---|
| **C9** MED | Log redaction filtered only `record.getMessage()`. Exception text is rendered separately by the Formatter and **bypassed redaction entirely** — reproduced on the live code: a registered secret appeared verbatim in `connector.log` via `log.exception`. This directly contradicted the module docstring | `RedactingFormatter` overrides `format`, `formatException` and `formatStack`; the regression asserts the record is written but the secret is not |
| **C14** LOW→MED | The Credential Manager read path indexed the blob with a trusted size and decoded UTF-16 unguarded: an odd or foreign blob raised an uncaught `UnicodeDecodeError` (which, via C9, then logged the credential bytes), and a NULL pointer with nonzero size would be an access violation | Size capped at `CRED_MAX_CREDENTIAL_BLOB_SIZE`, required even, NULL checked, decode wrapped into `CredentialStoreError` **without echoing the bytes**, `ctypes.string_at` instead of per-byte indexing, and `_validate()` now also runs on read |
| **C10** MED | `doctor` checked POSIX mode bits. Windows synthesises `0o777`, so the row could **never** pass and `doctor` always exited 1 — while the checklist told the user every row should say PASS. Since `harden()` swallowed icacls' result, this was also the only feedback channel for ACL failure | `_windows_acl_status()` reads the real DACL via `icacls` and asserts only this user and SYSTEM; `harden()` now returns whether it applied |
| **C11** MED | The on-demand invariant was checked against **our own generated XML file**, not the registered task — `schtasks /Change` or the UI could add a trigger and `doctor` would still report PASS. It also only looked for two trigger types | `_registered_task_xml()` queries the live task via `schtasks /Query /XML` and rejects `TimeTrigger`, `CalendarTrigger`, `BootTrigger`, `IdleTrigger`, `EventTrigger`, `SessionStateChangeTrigger` and `Repetition`, requiring exactly one `LogonTrigger` |
| **C16** LOW | `harden()` spawned icacls with no `CREATE_NO_WINDOW` (console flash from a process designed to be windowless), and used **display names** as principals — which fail the SID lookup on non-English Windows or an Entra/MSA account, causing icacls to reject the whole command silently | `CREATE_NO_WINDOW`, and well-known/resolved SIDs (`*S-1-5-18`, the user's SID from `whoami`) with a name fallback |

### Documentation that would mislead a user or an agent

| # | Finding | Fix |
|---|---|---|
| **C13** MED (partly disputed) | The first-run leak check shipped unchanged from macOS — `security find-generic-password` does not exist on Windows. The reviewer additionally claimed it would print a false `CLEAN`; **I tested that and it is wrong** (`xargs` with empty stdin exits 0, so it prints nothing). The real defect was the wrong platform, not a false all-clear | Rewritten in PowerShell with an explicit `INCONCLUSIVE` branch, so `CLEAN` is printed only when the search actually ran |
| **C18** LOW | `EXCHANGE_README` (the **only** protocol reference a Cowork session ever sees), the setup checklist and `SKILL.md` all still named `~/Library/Application Support/`, "Keychain", "Terminal", and a bash recipe using `uuidgen`/`mv` | All ported to Windows paths and PowerShell |
| **C8** MED | The TOCTOU docstring claimed `O_NOFOLLOW` protection that is `0` on Windows | Docstring corrected to state what the platform actually provides |
| **C17** LOW | TLS failure text told Windows users to run `Install Certificates.command` | Platform-specific remediation |
| **C19/C20** INFO/LOW | `Find-Python` sorted lexically (`Python39` above `Python312`); `uninstall.ps1` executed `python_path` from config unvalidated | Parsed-version sort; `python(w).exe` shape required |
| **S4** LOW | The OneDrive warning used a bare `StartsWith` with no separator boundary and only checked the **default** path | Boundary-aware comparison, and all sync roots are listed before the folder prompt |

---

## 3. Checked and CLEAN

The reviewer probed these and found no defect; they are recorded so the review
is auditable and so they are not re-litigated:

- **`_build_url` path validation.** Every Windows-shaped attack fails closed:
  UNC (`//server/share`), device paths (`\\.\`, `\\?\`), drive-relative
  (`C:foo`), absolute URLs, scheme downgrade, backslash traversal, and
  traversal through up to three rounds of percent-decoding. A final
  `urlsplit(url).hostname != self.host` backstop. No bypass found.
- **Read-only guarantee.** POST permitted only for the fixed token paths and
  only without query params; every other method rejected; `scope=monitoring`
  the only scope ever requested, with an over-grant warning.
- **Certificate verification** never disabled anywhere — no `CERT_NONE`, no
  `check_hostname=False`, no unverified context. The empty-store path fails
  closed rather than downgrading.
- **SQL.** Every tenant- and request-derived value is a bound parameter,
  including `COLLATE NOCASE` comparisons, escaped `LIKE` needles and
  placeholder-generated `IN (...)` lists. The only f-strings reaching
  `execute()` interpolate code-literal table names.
- **Task Scheduler XML injection.** Every interpolated field passes through
  `xml_escape`, including `USERDOMAIN\USERNAME`. A crafted username cannot
  inject an `<Exec>` or change the command run. XML is written UTF-16 as
  declared.
- **Credential write path.** Pure in-process ctypes: the secret never reaches
  argv, stdin, the environment or any child process. `CredFree` is called on
  success and correctly *not* called when `CredReadW` fails.
- **No credential disclosure through any bridge action**; the bearer token is
  never persisted.
- **NTFS alternate data streams** (`x.json:evil` — `scandir` never enumerates
  streams, and neither `ID_RE` nor `FILENAME_RE` admits `:`), **8.3 short
  names** (`resolve()` expands them before containment checks), and
  case-insensitive `PurePath` comparison on Windows.
- **No dangerous constructs**: no `eval`, `exec`, `pickle`, `os.system`, or
  `shell=True`; subprocess calls are list-form with absolute binaries.

---

## 4. Residual risk — read this before trusting the connector

**The Windows-native code paths have still never executed on Windows.** This
port was written and reviewed on macOS. ctypes calls into `advapi32`,
`msvcrt` byte-range locks, `ReadDirectoryChangesW`, `schtasks` registration
and `icacls` are reviewed, unit-tested where the branch point allows, and
PowerShell-parsed — but not smoke-tested. C1 is precisely what that gap
produces, and S1/S2 remain *suspected* for the same reason.

**First install must run `doctor` and the full suite before the connector is
relied on**, and a failure there should be treated as a real finding, not a
setup quirk.

All findings raised by the review are addressed in this repository.
