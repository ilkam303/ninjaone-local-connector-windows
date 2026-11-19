#!/usr/bin/env python3
"""NinjaOne local connector — entry point.

Subcommands: setup, teardown, sync (--auto / --morning-reset), bridge --drain,
backfill --since, status, doctor. Runs unattended under launchd; every code
path assumes no console is watching, so state and errors land in the rotating
log (with credential and bearer-token redaction) and in the exchange manifest.
"""

import argparse
import getpass
import json
import logging
import os
import plistlib
from datetime import datetime
from xml.sax.saxutils import escape as xml_escape
import shutil
import subprocess
import sys
from pathlib import Path

import nj_credstore
from nj_api import (ALLOWED_INSTANCES, ApiError, AuthError, NjClient, SCOPE,
                    TOKEN_PATHS, build_ssl_context)
from nj_bridge import Bridge
from nj_common import (IS_WINDOWS, ConfigError, Exchange, app_root, config_path,
                       ensure_app_dirs, exclusive_lock, iso, load_config,
                       log_dir, norm_date, save_config, setup_logging,
                       today_str, utc_now)
from nj_sync import SyncEngine, activity_row

log = logging.getLogger("njc.cli")

LAUNCHCTL = "/bin/launchctl"
SYNC_LABEL = "com.user.ninjaone-connector.sync"
BRIDGE_LABEL = "com.user.ninjaone-connector.bridge"

# Windows Task Scheduler names (the launchd-label analog).
WIN_SYNC_TASK = "NinjaOneConnectorSync"
WIN_BRIDGE_TASK = "NinjaOneConnectorBridge"


def launch_agents_dir():
    return Path.home() / "Library" / "LaunchAgents"


def _fail(message, code=1):
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(code)


# ------------------------------------------------------------------- launchd

def make_plists(cfg):
    """Both plists use the absolute interpreter path recorded at install —
    launchd does not inherit shell PATH, so bare 'python3' is a latent failure."""
    python = cfg["python_path"]
    script = str(app_root() / "connector.py")
    exchange = Exchange(cfg)
    common = {
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "Nice": 10,
        "StandardOutPath": str(log_dir() / "launchd.log"),
        "StandardErrorPath": str(log_dir() / "launchd.log"),
    }
    # No StartInterval: syncing is on-demand only. Each bridge request
    # delta-syncs first when the cache exceeds the staleness budget, so this
    # agent exists solely for the login-triggered morning reset — which makes
    # no API calls at all.
    sync_plist = dict(common, Label=SYNC_LABEL,
                      ProgramArguments=[python, script, "sync", "--auto"],
                      RunAtLoad=True)
    bridge_plist = dict(common, Label=BRIDGE_LABEL,
                        ProgramArguments=[python, script, "bridge", "--drain"],
                        WatchPaths=[str(exchange.requests)],
                        RunAtLoad=False, KeepAlive=False)
    return {SYNC_LABEL: sync_plist, BRIDGE_LABEL: bridge_plist}


# ---------------------------------------------------------------------------
# Windows Task Scheduler (the launchd analog: generated task XML, absolute
# interpreter + script paths, least privilege, hidden, user-level only)
# ---------------------------------------------------------------------------

def _windows_pythonw(python):
    """Prefer pythonw.exe (no console window) beside the chosen python.exe."""
    candidate = Path(python).with_name("pythonw.exe")
    return str(candidate) if candidate.exists() else str(python)


_WIN_TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{description}</Description>
  </RegistrationInfo>
  <Triggers>
{triggers}
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user_id}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowHardTerminate>true</AllowHardTerminate>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>{time_limit}</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def build_windows_task_xml(cfg):
    """Return {task_name: xml_string} for both scheduled tasks.

    Absolute interpreter and script paths always — Task Scheduler no more
    inherits a shell PATH than launchd does.

    NOTE: the sync task carries a LogonTrigger and NOTHING ELSE. There is no
    TimeTrigger and no Repetition, because this connector's sync model is
    on-demand only — the logon run does the morning reset, and freshness comes
    from each bridge request delta-syncing when the cache exceeds the
    staleness budget. A repeating trigger here would silently reintroduce
    polling.
    """
    python = _windows_pythonw(cfg["python_path"])
    script = str(app_root() / "connector.py")
    user_id = os.environ.get("USERNAME", "")
    domain = os.environ.get("USERDOMAIN", "")
    if domain and user_id:
        user_id = "%s\\%s" % (domain, user_id)

    logon_trigger = "    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>"

    def render(description, triggers, arguments, time_limit):
        return _WIN_TASK_XML.format(
            description=xml_escape(description),
            triggers=triggers,
            user_id=xml_escape(user_id),
            command=xml_escape(python),
            arguments=xml_escape(arguments),
            time_limit=time_limit,
        )

    return {
        WIN_SYNC_TASK: render(
            "NinjaOne connector: morning reset of the local cache (read-only)",
            logon_trigger,
            '"%s" sync --auto' % script,
            "PT1H"),
        WIN_BRIDGE_TASK: render(
            "NinjaOne connector: watch the request folder (local bridge)",
            logon_trigger,
            '"%s" bridge --watch' % script,
            "PT0S"),  # PT0S = no execution time limit (long-lived watcher)
    }


def _schtasks(args, check=False):
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                       "System32", "schtasks.exe")
    proc = subprocess.run([exe] + args,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and proc.returncode != 0:
        raise RuntimeError(
            "schtasks %s failed: %s"
            % (args[0], proc.stderr.decode("utf-8", "replace").strip()))
    return proc.returncode


def write_and_register_windows_tasks(cfg):
    tasks_dir = app_root() / "tasks"
    tasks_dir.mkdir(parents=True, exist_ok=True)
    for name, xml in build_windows_task_xml(cfg).items():
        xml_path = tasks_dir / ("%s.xml" % name)
        # schtasks expects UTF-16 for XML files declaring UTF-16.
        xml_path.write_text(xml, encoding="utf-16")
        _schtasks(["/Create", "/TN", name, "/XML", str(xml_path), "/F"],
                  check=True)
    # Start the watcher right away rather than waiting for the next logon.
    _schtasks(["/Run", "/TN", WIN_BRIDGE_TASK])
    _schtasks(["/Run", "/TN", WIN_SYNC_TASK])


def unregister_windows_tasks():
    for name in (WIN_SYNC_TASK, WIN_BRIDGE_TASK):
        _schtasks(["/End", "/TN", name])
        _schtasks(["/Delete", "/TN", name, "/F"])


def windows_task_registered(name):
    return _schtasks(["/Query", "/TN", name]) == 0


def _registered_task_xml(name):
    """The XML the SCHEDULER holds for this task, not the file we generated."""
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                       "System32", "schtasks.exe")
    try:
        proc = subprocess.run([exe, "/Query", "/TN", name, "/XML"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    raw = proc.stdout
    for encoding in ("utf-16", "utf-8-sig", "utf-8"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return None


def _windows_acl_status(path):
    """Read the real DACL via icacls and judge it. Returns (ok, detail)."""
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                       "System32", "icacls.exe")
    try:
        proc = subprocess.run([exe, str(path)], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, timeout=30,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"icacls could not be run: {e}"
    if proc.returncode != 0:
        return False, proc.stderr.strip()[:120]
    body = proc.stdout
    allowed_markers = ("S-1-5-18", "SYSTEM", os.environ.get("USERNAME", "\0"))
    bad = []
    for line in body.splitlines()[1:]:
        line = line.strip()
        if not line or ":" not in line:
            continue
        principal = line.split(":")[0].strip()
        if not principal:
            continue
        if any(m and m in principal for m in allowed_markers):
            continue
        bad.append(principal)
    if bad:
        return False, f"unexpected principals on the app root: {sorted(set(bad))}"
    return True, "inheritance disabled; owner + SYSTEM only"


def install_launch_agents(cfg):
    launch_agents_dir().mkdir(exist_ok=True)
    uid = os.getuid()
    for label, plist in make_plists(cfg).items():
        path = launch_agents_dir() / f"{label}.plist"
        subprocess.run([LAUNCHCTL, "bootout", f"gui/{uid}/{label}"],
                       capture_output=True)
        with open(path, "wb") as f:
            plistlib.dump(plist, f)
        result = subprocess.run([LAUNCHCTL, "bootstrap", f"gui/{uid}", str(path)],
                                capture_output=True, text=True)
        if result.returncode != 0:
            _fail(f"launchctl bootstrap failed for {label}: {result.stderr.strip()}")


def remove_launch_agents():
    uid = os.getuid()
    for label in (SYNC_LABEL, BRIDGE_LABEL):
        subprocess.run([LAUNCHCTL, "bootout", f"gui/{uid}/{label}"],
                       capture_output=True)
        path = launch_agents_dir() / f"{label}.plist"
        if path.exists():
            path.unlink()


def agent_loaded(label):
    return subprocess.run([LAUNCHCTL, "print", f"gui/{os.getuid()}/{label}"],
                          capture_output=True).returncode == 0


# --- platform-neutral entry points the rest of the CLI calls ----------------

def install_background_jobs(cfg):
    if IS_WINDOWS:
        write_and_register_windows_tasks(cfg)
    else:
        install_launch_agents(cfg)


def remove_background_jobs():
    if IS_WINDOWS:
        unregister_windows_tasks()
    else:
        remove_launch_agents()


def job_names():
    """(sync, bridge) identifiers for this platform, for doctor output."""
    return ((WIN_SYNC_TASK, WIN_BRIDGE_TASK) if IS_WINDOWS
            else (SYNC_LABEL, BRIDGE_LABEL))


def job_registered(name):
    return windows_task_registered(name) if IS_WINDOWS else agent_loaded(name)


# --------------------------------------------------------------------- setup

CHECKLIST_TEMPLATE = """# NinjaOne Connector — Setup Checklist

Do these in order. Nothing else is required.

- [ ] 1. On macOS, if a Keychain access prompt appears on the first sync,
      click **Always Allow** (one-time). On Windows nothing is prompted —
      Credential Manager reads are in-process.
- [ ] 2. Connect ONLY this folder to Cowork: `{exchange_root}`
      **Never connect** the private app root
      (`%LOCALAPPDATA%\\ninjaone-connector` on Windows,
      `~/Library/Application Support/ninjaone-connector/` on macOS)
      (that private folder holds the working database and logs).
- [ ] 3. Confirm both background agents are loaded — run in Terminal:
      `"{python}" "{script}" doctor`
      (every row should say PASS).
- [ ] 4. Reply "done" to the agent so it can run the live verification
      (status check, one sync, five real devices displayed for your
      confirmation, and a secret/token leak scan).

## About the API client you created in NinjaOne

This connector requests the **Monitoring** scope and nothing else, so the
token it holds physically cannot change anything in your tenant. If you gave
the API client `management` or `control` as well, setup warned you — go to
Administration → Apps → API → Client App IDs and reduce it to Monitoring only.
"""


def _prompt_instance(default="app.ninjarmm.com"):
    print("\nWhich NinjaOne instance is your tenant on?")
    for index, host in enumerate(ALLOWED_INSTANCES, start=1):
        print(f"  {index}. {host}")
    answer = input(f"Choose 1-{len(ALLOWED_INSTANCES)} [1]: ").strip() or "1"
    if answer.isdigit() and 1 <= int(answer) <= len(ALLOWED_INSTANCES):
        return ALLOWED_INSTANCES[int(answer) - 1]
    if answer in ALLOWED_INSTANCES:
        return answer
    _fail(f"Not a known NinjaOne instance: {answer!r}")
    return default


def _validate_tenant(instance, client_id, client_secret):
    """Mint a token and make one read-only probe. Returns (client, token_path).
    Tries the documented token path first and falls back to the older one."""
    last_error = None
    for token_path in TOKEN_PATHS:
        client = NjClient(instance, client_id, client_secret, token_path=token_path)
        try:
            client.probe()
            return client, token_path
        except AuthError:
            raise
        except ApiError as e:
            if e.code == 404:
                last_error = e
                continue
            raise
    raise ApiError(f"no working OAuth token endpoint on {instance} "
                   f"(tried {', '.join(TOKEN_PATHS)}): {last_error}")


def cmd_setup(args):
    if args.non_interactive:
        if not args.instance:
            _fail("--non-interactive requires --instance")
        if not args.secret_stdin:
            _fail("--non-interactive requires --secret-stdin (Client ID on the first "
                  "line, Client Secret on the second). Credentials are never flags.")
        instance = args.instance
        exchange_root = args.exchange_root or str(Path.home() / "NinjaOneData")
        interval = args.interval or 15
        retention = args.retention_days or 1
        max_db = args.max_db_mb or 100
    else:
        if not sys.stdin.isatty():
            _fail("Interactive setup needs a Terminal. Either run this in Terminal "
                  "yourself, or use --non-interactive with flags (the credentials "
                  "are still collected via prompt or --secret-stdin, never flags).")
        instance = args.instance or _prompt_instance()
        exchange_root = args.exchange_root or (
            input(f"Exchange folder for Cowork [{Path.home() / 'NinjaOneData'}]: ").strip()
            or str(Path.home() / "NinjaOneData"))
        interval = args.interval or int(
            input("Staleness budget in minutes [15]: ").strip() or "15")
        retention = args.retention_days or int(
            input("Retention window days [1]: ").strip() or "1")
        max_db = args.max_db_mb or int(input("Soft DB size cap MB [100]: ").strip() or "100")

    instance = instance.strip().lower().replace("https://", "").strip("/ ")
    if instance not in ALLOWED_INSTANCES:
        _fail(f"{instance!r} is not a known NinjaOne instance. Allowed: "
              f"{', '.join(ALLOWED_INSTANCES)}")

    exchange_path = Path(exchange_root).expanduser().resolve()
    forbidden = {Path.home().resolve(), Path("/").resolve(), app_root().resolve()}
    if (exchange_path in forbidden or exchange_path in app_root().resolve().parents
            or app_root().resolve() in exchange_path.parents):
        _fail(f"Refusing to use {exchange_path} as the exchange root: it must be a "
              "dedicated folder, not your home directory, the filesystem root, or "
              "anything overlapping the private app root.")

    # Credentials are never accepted as arguments or environment variables.
    if args.secret_stdin:
        client_id = sys.stdin.readline().strip()
        client_secret = sys.stdin.readline().strip()
        if not client_id or not client_secret:
            _fail("--secret-stdin expects two lines: Client ID, then Client Secret")
    else:
        if not sys.stdin.isatty():
            _fail("The credentials must be entered interactively (or piped with "
                  "--secret-stdin). Run setup in Terminal.")
        print("\nCreate the API client in NinjaOne first: Administration → Apps → API →"
              "\nClient App IDs → add a machine-to-machine (client credentials) app with"
              f"\nONLY the '{SCOPE}' scope. Then paste its values here.\n")
        client_id = getpass.getpass("NinjaOne Client ID (input hidden): ").strip()
        client_secret = getpass.getpass("NinjaOne Client Secret (input hidden): ").strip()

    # Validate BEFORE storing, so a typo never leaves a broken credential pair
    # sitting in the Keychain for later runs to trip over.
    print("Validating the credentials against NinjaOne (read-only) ...")
    try:
        client, token_path = _validate_tenant(instance, client_id, client_secret)
    except AuthError as e:
        _fail(str(e))
    except ApiError as e:
        _fail(f"Could not validate against {instance}: {e}")
    nj_credstore.store_credentials(client_id, client_secret)

    cfg = {
        "instance": instance,
        "token_path": token_path,
        "exchange_root": exchange_root,
        "sync_interval_minutes": int(interval or 15),
        "retention_days": int(retention or 1),
        "max_db_mb": int(max_db or 100),
        "python_path": sys.executable,
        "debug": False,
    }
    save_config(cfg)
    ensure_app_dirs()
    exchange = Exchange(cfg)
    exchange.ensure_dirs()

    print(f"✓ Authenticated against {instance} (token endpoint {token_path})")
    if client.scope_warning:
        print("\n!! SCOPE WARNING !!")
        print(client.scope_warning)
        print("The connector will still only ever issue read requests.\n")
    else:
        print(f"✓ Granted scope is read-only ({client.granted_scope or SCOPE})")

    if not args.skip_launchd:
        install_background_jobs(cfg)
        print("✓ Scheduled tasks installed and started" if IS_WINDOWS
              else "✓ LaunchAgents installed and loaded")

    checklist = CHECKLIST_TEMPLATE.format(
        exchange_root=exchange.root, python=cfg["python_path"],
        script=app_root() / "connector.py")
    (exchange.root / "SETUP_CHECKLIST.md").write_text(checklist)
    print("\n" + checklist)


def _skill_dir():
    """The Cowork skill directory this connector installs (and ONLY this one —
    never its parents ~/.claude or ~/.claude/skills, which belong to other
    tools)."""
    return Path.home() / ".claude" / "skills" / "ninjaone-reporting"


def _exchange_root_from_config():
    """Best-effort discovery of the exchange root before we delete config.
    Falls back to the documented default; returns None if nothing exists."""
    try:
        cfg = load_config()
        root = Path(cfg["exchange_root"]).expanduser()
        if root.exists():
            return root
    except (ConfigError, KeyError, OSError):
        pass
    default = Path.home() / "NinjaOneData"
    return default if default.exists() else None


def _safe_rmtree(path):
    """Recursive delete that refuses to follow a symlink/junction.

    shutil.rmtree before 3.12 can mishandle junctions, and ignore_errors=True
    hid that — leaving the tree half-present after a teardown that reported
    success. The exchange root is hostile-writable, so a planted junction here
    is a landmine that detonates on uninstall."""
    from nj_common import is_reparse_point
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        return True
    if is_reparse_point(path):
        log.warning("refusing to delete through a symlink/junction: %s", path)
        try:
            path.unlink()      # remove the link itself, never its target
        except OSError:
            try:
                os.rmdir(path)  # a junction is a directory entry
            except OSError:
                return False
        return True
    ok = True
    try:
        for child in path.iterdir():
            if child.is_dir() and not is_reparse_point(child):
                ok &= _safe_rmtree(child)
            else:
                if is_reparse_point(child):
                    try:
                        child.unlink()
                    except OSError:
                        try:
                            os.rmdir(child)
                        except OSError:
                            ok = False
                else:
                    try:
                        child.unlink()
                    except OSError:
                        ok = False
        path.rmdir()
    except OSError as e:
        log.warning("could not fully remove %s: %s", path, e)
        return False
    return ok


def _preserve_user_exports(exchange_root):
    """User-saved exports live in exports/keep/. They are the user's data, not a
    trace of the connector, so a full uninstall moves any that exist to a
    clearly-named folder in the home directory rather than deleting them.
    Returns the destination path if anything was preserved, else None."""
    keep = exchange_root / "exports" / "keep"
    if not (keep.is_dir() and any(keep.iterdir())):
        return None
    dest = Path.home() / "NinjaOneData_saved_exports"
    suffix = 1
    while dest.exists():
        dest = Path.home() / f"NinjaOneData_saved_exports_{suffix}"
        suffix += 1
    shutil.move(str(keep), str(dest))
    return dest


def cmd_teardown(args):
    # Capture the exchange root now, while config is still readable.
    full = args.purge or args.all
    exchange_root = _exchange_root_from_config() if args.all else None

    remove_background_jobs()
    nj_credstore.delete_credentials()
    print("Scheduled tasks removed and Credential Manager item deleted."
          if IS_WINDOWS else
          "LaunchAgents unloaded and Keychain item deleted.")

    # The Cowork skill is a connector artifact — always remove it (our subdir
    # only; ~/.claude and ~/.claude/skills are left untouched for other tools).
    skill = _skill_dir()
    if skill.exists():
        shutil.rmtree(skill, ignore_errors=True)
        print(f"Removed skill {skill}")

    if full:
        _safe_rmtree(app_root())
        print(f"Removed {app_root()}")
    else:
        print(f"Data left in place at {app_root()} (use --purge to remove it, "
              "or --all to remove every trace including the exchange folder).")

    if args.all and exchange_root is not None:
        preserved = _preserve_user_exports(exchange_root)
        _safe_rmtree(exchange_root)
        print(f"Removed {exchange_root}")
        if preserved is not None:
            print(f"Preserved your saved exports (from exports/keep/) at: {preserved}")
    elif args.all:
        print("No exchange folder found to remove.")

    if args.all:
        print("Uninstall complete — all connector traces removed. "
              "Python itself was left untouched.")


# ---------------------------------------------------------------- operations

def cmd_sync(args):
    cfg = load_config()
    setup_logging(cfg.get("debug"))
    with exclusive_lock("sync") as acquired:
        if not acquired:
            log.info("another sync is running; exiting")
            return
        engine = SyncEngine(cfg)
        if args.morning_reset:
            engine.morning_reset()
        elif args.auto:
            # launchd login firing: clear the previous day's windowed data and
            # stop. Never syncs — the sync model is on-demand only (bridge
            # requests and explicit `sync` invocations).
            if engine.get_state("last_reset_date") != today_str():
                engine.morning_reset()
            else:
                log.info("auto: reset already done today; on-demand model — nothing to do")
        else:
            engine.ensure_fresh()
            engine.interval_sync(force=True)


def cmd_bridge(args):
    cfg = load_config()
    setup_logging(cfg.get("debug"))
    if getattr(args, "watch", False):
        # Long-lived Windows watcher: blocks in the kernel on directory
        # changes. It takes its own "watch" lock, so it does not contend with
        # one-shot drains.
        if not IS_WINDOWS:
            _fail("--watch is the Windows bridge trigger; on macOS the launchd "
                  "WatchPaths agent runs `bridge --drain` instead.")
        import nj_watch
        nj_watch.watch(cfg)
        return
    if not getattr(args, "drain", False):
        _fail("bridge requires --drain (one shot) or --watch (resident, Windows)")
    with exclusive_lock("bridge") as acquired:
        if not acquired:
            log.info("another bridge drain is running; exiting")
            return
        handled = Bridge(cfg).drain()
        log.info("bridge drain: handled %d request(s)", handled)


def cmd_backfill(args):
    """One-off deeper pull of the activity stream. Anything older than the
    retention window is pruned by the next sync — this is for an immediate
    look further back, not a way to grow the working set permanently."""
    cfg = load_config()
    setup_logging(cfg.get("debug"))
    since = norm_date(args.since)
    with exclusive_lock("sync") as acquired:
        if not acquired:
            _fail("a sync is currently running; try again shortly")
        engine = SyncEngine(cfg)
        engine.sync_inventory()
        engine.sync_alerts()
        count = 0
        for activity in engine.client.iter_activities_older():
            if activity.get("id") is None:
                continue
            row = activity_row(activity)
            if row[2] and row[2] < since:
                break
            engine.con.execute(
                """INSERT OR REPLACE INTO activities(id, device_id, activity_time,
                     activity_type, status_name, message, raw_json)
                   VALUES(?,?,?,?,?,?,?)""", row)
            count += 1
        engine.con.commit()
        engine.set_state("state", "ready")
        engine.set_state("last_backfill_date", today_str())
        engine.set_state("window_start", since)
        engine.set_state("last_sync", iso(utc_now()))
        engine.publish()
        print(json.dumps({
            "backfilled_activities": count, "since": since,
            "note": "activities older than the retention window will be pruned by "
                    "the next sync"}))


def cmd_status(args):
    cfg = load_config()
    setup_logging(cfg.get("debug"))
    engine = SyncEngine(cfg)
    print(json.dumps(engine.manifest(), indent=2))
    log_file = log_dir() / "connector.log"
    if log_file.exists():
        lines = log_file.read_text().splitlines()[-15:]
        print("\n--- last log lines ---")
        print("\n".join(lines))


def cmd_doctor(args):
    checks = []

    def check(name, ok, detail=""):
        checks.append((name, ok, detail))

    v = sys.version_info
    check("python >= 3.9", v >= (3, 9), f"{v.major}.{v.minor}.{v.micro} at {sys.executable}")

    try:
        import sqlite3 as _s
        # Same helper the runtime client uses, so doctor can never report a
        # failure for a trust store the connector actually works with.
        context, detail, _repaired = build_ssl_context()
        check("sqlite3 + TLS trust store", context is not None,
              f"sqlite {_s.sqlite_version}, {detail}")
    except ImportError as e:
        check("sqlite3 + TLS trust store", False, str(e))

    cfg = None
    try:
        cfg = load_config()
        check("config.json", True,
              f"instance={cfg['instance']} token_path={cfg.get('token_path')}")
    except ConfigError as e:
        check("config.json", False, str(e))

    check("credentials in Credential Manager" if IS_WINDOWS
          else "credentials in Keychain", nj_credstore.has_credentials(),
          "service 'ninjaone-connector'")

    if app_root().exists():
        if IS_WINDOWS:
            # Windows synthesises 0o777 for every directory, so the POSIX mode
            # check used here before could NEVER pass — doctor always exited 1
            # while telling the user every row should say PASS. Read the real
            # DACL instead: inheritance disabled, and no principal beyond this
            # user and SYSTEM.
            ok, detail = _windows_acl_status(app_root())
            check("app root ACL (owner + SYSTEM only)", ok, detail)
        else:
            mode = app_root().stat().st_mode & 0o777
            check("app root permissions 0700", mode == 0o700, oct(mode))
    else:
        check("app root exists", False, str(app_root()))

    if config_path().exists() and not IS_WINDOWS:
        mode = config_path().stat().st_mode & 0o777
        check("config permissions 0600", mode == 0o600, oct(mode))

    if cfg:
        exchange = Exchange(cfg)
        needed = [exchange.requests, exchange.responses, exchange.exports]
        check("exchange folders", all(d.is_dir() for d in needed), str(exchange.root))
        sync_job, bridge_job = job_names()
        kind = "scheduled task" if IS_WINDOWS else "launchd agent"
        check(f"{kind} sync ({sync_job})", job_registered(sync_job))
        check(f"{kind} bridge ({bridge_job})", job_registered(bridge_job))
        if IS_WINDOWS:
            # Query the LIVE task. Reading back our own generated XML proved
            # nothing: schtasks /Change or the Task Scheduler UI can add a
            # trigger afterwards and the file would still look clean.
            xml = _registered_task_xml(sync_job)
            if xml is None:
                check("sync task readable from the scheduler", False,
                      "schtasks /Query /XML returned nothing")
            else:
                extra = [t for t in ("TimeTrigger", "CalendarTrigger",
                                     "BootTrigger", "IdleTrigger", "EventTrigger",
                                     "SessionStateChangeTrigger", "Repetition")
                         if f"<{t}>" in xml]
                check("sync task has no repeating trigger (on-demand model)",
                      not extra, f"found {extra}" if extra else "logon trigger only")
                check("sync task has exactly one logon trigger",
                      xml.count("<LogonTrigger>") == 1)
                check("sync task runs at LeastPrivilege",
                      "<RunLevel>LeastPrivilege</RunLevel>" in xml)
        else:
            plist = launch_agents_dir() / f"{SYNC_LABEL}.plist"
            if plist.exists():
                with open(plist, "rb") as f:
                    data = plistlib.load(f)
                check("sync agent has no StartInterval (on-demand model)",
                      "StartInterval" not in data)
        if nj_credstore.has_credentials():
            try:
                client_id, client_secret = nj_credstore.get_credentials()
                client = NjClient(cfg["instance"], client_id, client_secret,
                                  token_path=cfg.get("token_path", TOKEN_PATHS[0]))
                client.probe()
                check("NinjaOne reachable (read-only probe)", True, cfg["instance"])
                check("granted scope is monitoring-only", not client.scope_warning,
                      client.scope_warning or f"scope={client.granted_scope or SCOPE}")
            except Exception as e:
                check("NinjaOne reachable (read-only probe)", False, str(e)[:100])

    width = max(len(name) for name, _, _ in checks) + 2
    all_ok = True
    for name, ok, detail in checks:
        mark = "PASS" if ok else "FAIL"
        all_ok &= ok
        print(f"  {name:<{width}} {mark}  {detail}")
    sys.exit(0 if all_ok else 1)


# ------------------------------------------------------------------ argparse

def main():
    os.umask(0o077)  # every file we create defaults to owner-only
    parser = argparse.ArgumentParser(prog="connector", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("setup",
                       help="one-time configuration (credentials via prompt or "
                            "--secret-stdin; never flags)")
    p.add_argument("--non-interactive", action="store_true")
    p.add_argument("--instance", help=f"one of: {', '.join(ALLOWED_INSTANCES)}")
    p.add_argument("--exchange-root")
    p.add_argument("--interval", type=int, help="staleness budget in minutes")
    p.add_argument("--retention-days", type=int)
    p.add_argument("--max-db-mb", type=int)
    p.add_argument("--secret-stdin", action="store_true",
                   help="read Client ID (line 1) and Client Secret (line 2) from "
                        "stdin; neither is ever an argument")
    p.add_argument("--skip-launchd", action="store_true", help=argparse.SUPPRESS)
    p.set_defaults(fn=cmd_setup)

    p = sub.add_parser("teardown", help="unload agents and delete the Keychain item")
    p.add_argument("--purge", action="store_true", help="also delete the app root")
    p.add_argument("--all", action="store_true",
                   help="remove EVERY trace: agents, Keychain item, skill, app "
                        "root, and the exchange folder (saved exports in "
                        "exports/keep/ are moved to your home folder first)")
    p.set_defaults(fn=cmd_teardown)

    p = sub.add_parser("sync", help="delta sync (--auto for launchd; --morning-reset to clear)")
    p.add_argument("--auto", action="store_true")
    p.add_argument("--morning-reset", dest="morning_reset", action="store_true")
    p.set_defaults(fn=cmd_sync)

    p = sub.add_parser("bridge", help="process pending bridge requests")
    p.add_argument("--drain", action="store_true",
                   help="process everything pending, then exit (launchd/manual)")
    p.add_argument("--watch", action="store_true",
                   help="resident folder watcher (Windows Task Scheduler)")
    p.set_defaults(fn=cmd_bridge)

    p = sub.add_parser("backfill", help="one-off deeper activity pull")
    p.add_argument("--since", required=True, help="YYYY-MM-DD")
    p.set_defaults(fn=cmd_backfill)

    p = sub.add_parser("status", help="print manifest + recent log lines")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("doctor", help="pass/fail health table")
    p.set_defaults(fn=cmd_doctor)

    args = parser.parse_args()
    try:
        args.fn(args)
    except ConfigError as e:
        _fail(str(e))
    except nj_credstore.KeychainError as e:
        _fail(str(e))
    except AuthError as e:
        _fail(str(e))


if __name__ == "__main__":
    main()
