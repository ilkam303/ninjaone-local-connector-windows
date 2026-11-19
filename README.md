# NinjaOne Local Connector — Windows 11

A local-only data connector for NinjaOne (NinjaRMM). A small background Python
process syncs devices, organizations, alerts, and activities into a SQLite
cache on your PC and answers ad-hoc queries through a filesystem
request/response bridge. Claude Cowork reads one folder; nothing —
credentials, tokens, or data — ever leaves the machine.

**This is not an MCP server.** There is no network listener, no HTTP server, no
socket interface. The only interface between the daemon and any consumer is the
filesystem.

This is the Windows port of the macOS build of the same connector
The API client, sync engine, bridge protocol, and reporting skill are identical;
only the platform layer differs.

## What changed from the macOS build

| Concern | macOS | Windows |
|---|---|---|
| Credential store | login Keychain via `/usr/bin/security` | **Credential Manager** via ctypes `advapi32` (in-process, DPAPI-backed — the secret never touches argv, stdin, or a child process) |
| App root | `~/Library/Application Support/ninjaone-connector` | `%LOCALAPPDATA%\ninjaone-connector` |
| Permissions | `chmod 0700/0600` | `icacls /inheritance:r`, granting only you + SYSTEM |
| Scheduler | launchd LaunchAgents | **Task Scheduler** tasks from generated XML (LeastPrivilege, hidden, logon-triggered) |
| Bridge trigger | launchd `WatchPaths` | **resident watcher** blocking in the kernel on `ReadDirectoryChangesW` (`bridge --watch`) — effectively zero CPU while idle |
| Locking | `fcntl.flock` | `msvcrt.locking` byte-range lock |
| Installer | `install.sh` | `install.ps1` |

Deliberately **unchanged**: the sync task carries a logon trigger and nothing
else. There is no repeating trigger and no `StartInterval` equivalent, because
this connector's sync model is on-demand only, and a repeating trigger would
silently reintroduce polling.

## Using it

Once setup finishes, connect **one folder** to your assistant — the exchange
folder (`%USERPROFILE%\NinjaOneData` by default). Never connect the private
app root; it holds the database and logs and is deliberately not shareable.

With the bundled reporting skill installed, you ask in plain language:

- "Which devices are offline right now, by organization?"
- "What alerts are firing for \<client\>?"
- "How many Windows servers do we manage?"
- "Full detail and recent activity for device 1234"
- "Patch compliance for \<client\>"

**The first question each morning is slower.** At logon the connector clears
the previous day's alerts and activities; the first request rebuilds them and
its reply carries `"rebuilt": true`. Everything after that is fast.

**Answers are current.** Each bridge request delta-syncs first if the cache is
older than the staleness budget, and every reply carries a `data_as_of` stamp.
The snapshot file on disk, however, is only as fresh as the last request.

### Driving it without an assistant

The bridge is just files, so anything can use it. Write a request, then poll
for the reply:

```powershell
$EX = "$env:USERPROFILE\NinjaOneData"
$ID = [guid]::NewGuid().ToString().ToLower()   # ids MUST be lowercase
$body = @{ id = $ID; action = "query_devices"
           params = @{ offline = $true; limit = 500 } } | ConvertTo-Json -Compress -Depth 5

# Write to a temp name and rename in, so the daemon never reads a partial file.
Set-Content -LiteralPath "$EX\.tmp-$ID" -Value $body -Encoding utf8 -NoNewline
Move-Item   -LiteralPath "$EX\.tmp-$ID" -Destination "$EX\requests\request-$ID.json"

# Poll for up to 60s (180s if the manifest shows "state": "cleared").
$reply = "$EX\responses\response-$ID.json"
while (-not (Test-Path $reply)) { Start-Sleep -Seconds 2 }
Get-Content $reply -Raw | ConvertFrom-Json
```

Actions: `status`, `sync_now`, `query_devices`, `get_device`, `query_alerts`,
`query_activities`, `api_get` (any read-only `/v2/` endpoint, which is how
patch and antivirus posture are reached), and `export`. Full parameter tables
are in [`ninjaone-reporting/SKILL.md`](ninjaone-reporting/SKILL.md); the
exchange folder also grows a `README.md` describing the protocol in place.

Every reply is `{"id": ..., "status": "ok"|"error", ...}`. Cache-backed replies
also carry `source`, `rebuilt`, `synced` and `data_as_of`.

## Requirements

- Windows 11 (Windows 10 should work; untested)
- Python 3.9+ that can verify HTTPS. The installer finds one for you, rejects
  the Microsoft Store `python` stub, and rejects any interpreter whose CA trust
  store is empty. It never installs Python silently.
- A NinjaOne API client (machine-to-machine / client credentials) with **only
  the Monitoring scope**

No pip installs. No third-party packages. Standard library only.

## Install

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

The installer discovers a usable Python, copies the connector into the private
app root, hardens its ACLs, installs the Cowork reporting skill, stages the
uninstaller, then runs interactive setup.

### Create the API client first

In NinjaOne: **Administration → Apps → API → Client App IDs** → add an
application.

- Application platform: **Machine to Machine** (client credentials)
- Scopes: **Monitoring only** — do not grant `management` or `control`
- Copy the Client ID and Client Secret; they go straight into Credential Manager

Setup validates them against your tenant with a single read-only call, verifies
the granted scope is monitoring-only (warning loudly if the tenant granted
more), then registers the two scheduled tasks.

### Pick a non-synced exchange folder

The installer warns if the default exchange folder sits inside OneDrive. A
synced or redirected folder is a genuine problem here: OneDrive can lock,
re-write, or cloud-tier the request and response files underneath the bridge,
producing intermittent failures that are miserable to diagnose. Use something
like `C:\NinjaOneData` if your profile is redirected.

## The two folders

```
%LOCALAPPDATA%\ninjaone-connector\     PRIVATE — never connect this
├── connector.py, nj_*.py              the code
├── config.json                        no credentials in it
├── ninjaone.db                        authoritative working database
├── tasks\                             generated Task Scheduler XML
└── logs\                              rotating, credential-redacted

%USERPROFILE%\NinjaOneData\            the ONLY folder to connect to Cowork
├── ninjaone.sqlite                    read-optimized snapshot
├── exports\
│   ├── sync_manifest.json             freshness + counts — read this first
│   ├── devices_summary.csv            flat denormalized device view
│   └── keep\                          exports here survive the daily sweep
├── requests\                          consumers write request files here
│   └── processed\
└── responses\
```

## How syncing works

**On-demand only — there is no polling timer.**

- At logon, the sync task runs a *morning reset*: alerts and activities are
  cleared, cursors reset, the DB vacuumed, an empty snapshot published with
  `"state": "cleared"`. It makes no API calls. Device inventory is
  current-state, so it survives but is marked `inventory_stale`.
- The first real use of the day triggers a lazy rebuild; that response carries
  `"rebuilt": true` and takes longer.
- Every later bridge request delta-syncs first if the cache is older than the
  staleness budget. Check `data_as_of` on the response.
- The **snapshot file** is only as fresh as the last request. Send a `sync_now`
  before querying `ninjaone.sqlite` directly if currency matters.

## Commands

Run with the interpreter recorded at install (`doctor` prints it):

```powershell
& "$env:LOCALAPPDATA\ninjaone-connector\connector.py" doctor
```

| Command | Purpose |
|---|---|
| `setup` | One-time configuration |
| `doctor` | PASS/FAIL health table: interpreter, TLS store, config, Credential Manager, scope, tasks, folders, tenant reachability |
| `status` | Manifest + recent log lines |
| `sync` | Force a delta sync (`--auto` for the logon task, `--morning-reset` to clear) |
| `bridge --drain` | Process pending requests once, then exit |
| `bridge --watch` | Resident folder watcher (what the Task Scheduler task runs) |
| `backfill --since YYYY-MM-DD` | One-off deeper activity pull |
| `teardown` | Remove tasks + credential (`--purge` app root, `--all` everything) |

## Security summary

- **Credentials**: Windows Credential Manager only (DPAPI, per-user). Client ID
  in the user-name field, Client Secret in the credential blob. Read and
  written in-process via ctypes — never argv, stdin, environment, a file, or a
  child process.
- **Bearer tokens**: process memory only. Never cached to disk, config, or the
  exchange root. Refreshed proactively before expiry; on a 401 refreshed
  exactly once, then failed cleanly — never looped.
- **Read-only at two layers**: `scope=monitoring` makes mutation impossible at
  the API level, and a single request-building choke point rejects every method
  except GET, with one carve-out for the token POST.
- **One allowed host**, HTTPS only, certificate verification never disabled.
- Full adversarial review in [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md).

## Tests

```powershell
python -m unittest discover -s tests -t .
```

Entirely offline. A suite-level network guard replaces the socket layer so any
attempt to reach a real host fails loudly — the suite can never touch your live
tenant.

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File uninstall.ps1
```

Type `REMOVE` to confirm. Removes both tasks, the Credential Manager item, the
skill, the app root, and the exchange folder. Anything in `exports\keep\` is
**moved** to `%USERPROFILE%\NinjaOneData_saved_exports` first, never deleted.
Python is left untouched. Idempotent. `-KeepData` spares the data folders.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Installer finds no Python | `winget install -e --id Python.Python.3.12`, then re-run. The Store stub does not count |
| `doctor` FAILs on the TLS trust store | That interpreter cannot verify HTTPS; install a python.org or winget build |
| No response file appears | Bridge task not running — `doctor`; or the first-of-day rebuild is still going (allow 180 s) |
| Intermittent bridge failures | Exchange folder is inside OneDrive or a redirected known folder. Move it |
| `auth_failed` | Secret rotated/revoked, or the API client lost Monitoring scope — re-run `setup` |
| Scope warning | Tenant granted more than Monitoring — reduce it in Administration → Apps → API |

## How this was built

This connector was written with substantial AI assistance (Anthropic's Claude),
and that shaped both what is here and what to check.

- The code, tests, installers and documentation were largely AI-authored, then
  reviewed, corrected and re-tested by a human maintainer.
- The security review in [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md) was
  performed by a **separate** AI agent that had no part in writing the code and
  no authority to edit it — findings only. It raised 26 issues; all are fixed
  here, each with a regression test. One of its claims was checked and found
  wrong, and is recorded as such rather than quietly dropped.
- The test suite is the main safety net: 260 offline tests behind a
  socket-level network guard. Several exist specifically because an earlier
  green suite missed a defect that made the connector unable to run at all —
  the Windows tests had mocked a platform flag instead of exercising the
  branch.

**Read this before trusting it:** the Windows-native paths (ctypes into
`advapi32`, `msvcrt` locks, `ReadDirectoryChangesW`, `schtasks`, `icacls`) were
developed and reviewed on macOS. They are unit-tested where the branch point
allows and the PowerShell parses cleanly, but they have **not been smoke-tested
on real Windows hardware**. Run `doctor` and the full suite on first install,
and treat a failure there as a real finding rather than a setup quirk.

Review it as you would any unfamiliar code before pointing it at a production
tenant. It is read-only by construction — a monitoring-scope token plus a
GET-only choke point — but that is a claim you should verify, not take.

## Licence

MIT — see [LICENSE](LICENSE).
