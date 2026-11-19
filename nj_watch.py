"""Resident directory watcher — the Windows analog of launchd WatchPaths.

Trust-boundary role: this process is the bridge trigger. Windows Task
Scheduler has no clean "watch this folder" trigger, so rather than burn a poll
loop we run one tiny background process (launched windowless via pythonw at
logon) that blocks inside the kernel on ReadDirectoryChangesW until something
appears in the exchange `requests/` folder, then drains the bridge. Blocked on
a kernel wait it uses effectively no CPU while idle, so it never shows up in
day-to-day work.

It still speaks only the filesystem — no network listener, no socket. A single
instance is enforced with the shared exclusive_lock; a stray second watcher
exits immediately. It never inspects the change buffer: any change simply
means "drain now", and the bridge itself does all validation of what it finds.
"""

import ctypes
import logging
import time

from nj_bridge import Bridge
from nj_common import Exchange, IS_WINDOWS, exclusive_lock, setup_logging

log = logging.getLogger("njc.watch")

# ReadDirectoryChangesW filters: fire on names appearing and on writes settling.
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
_FILTER = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE

FILE_LIST_DIRECTORY = 0x0001
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# A single writer produces several change events (create, then write, then
# close). Coalesce them so one request file causes one drain, not three.
COALESCE_SECONDS = 0.4


def _open_dir(path):
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32.ReadDirectoryChangesW.restype = wintypes.BOOL
    kernel32.ReadDirectoryChangesW.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
        ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.CreateFileW(
        str(path),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        None)
    if not handle or handle == INVALID_HANDLE_VALUE:
        raise OSError(f"CreateFileW failed for {path}: {ctypes.get_last_error()}")
    return kernel32, handle


def _watch_once(kernel32, handle):
    """Block until at least one change is reported in the watched folder.
    The buffer is deliberately not parsed — any change means 'drain now', and
    the bridge re-validates every file it picks up regardless."""
    from ctypes import wintypes
    buf = ctypes.create_string_buffer(8192)
    bytes_returned = wintypes.DWORD(0)
    ok = kernel32.ReadDirectoryChangesW(
        handle, buf, len(buf),
        False,            # watch requests/ only, not subtrees
        _FILTER,
        ctypes.byref(bytes_returned),
        None, None)       # synchronous (blocking) call
    return bool(ok)


def _safe_drain(cfg):
    """A malformed or hostile request must never kill the watcher: the bridge
    already answers errors per request, and anything that escapes it is logged
    and swallowed here."""
    try:
        handled = Bridge(cfg).drain()
        if handled:
            log.info("watcher drained %d request(s)", handled)
    except Exception as e:  # noqa: BLE001
        log.warning("drain error: %s", e)


def watch(cfg):
    """Run the watcher loop. Intended to be the long-lived logon process."""
    setup_logging(cfg.get("debug"))
    if not IS_WINDOWS:
        raise RuntimeError("The directory watcher runs on Windows only. "
                           "On macOS, launchd WatchPaths triggers the bridge.")
    with exclusive_lock("watch") as acquired:
        if not acquired:
            log.info("another watcher is already running; exiting")
            return
        exchange = Exchange(cfg)
        exchange.ensure_dirs()
        requests = exchange.requests
        log.info("watcher starting on %s", requests)

        # Drain anything already pending before we start blocking. This is
        # also the recovery path for a change notification missed while the
        # watcher was down.
        _safe_drain(cfg)

        while True:
            try:
                # Recreate the folder if it was removed, then reopen.
                exchange.ensure_dirs()
                kernel32, handle = _open_dir(requests)
            except (OSError, Exception) as e:
                log.warning("watch open failed (%s); retrying in 5s", e)
                time.sleep(5)
                continue
            try:
                while True:
                    if not _watch_once(kernel32, handle):
                        # FALSE means the wait ended without a usable change —
                        # typically ERROR_NOTIFY_CLEANUP because the watched
                        # directory was deleted or renamed. It raises nothing,
                        # so ignoring it spun this loop at 100% CPU forever on
                        # a stale handle, and the bridge never fired again.
                        # Break out to the reopen path instead.
                        log.warning("directory watch ended (folder deleted or "
                                    "renamed); reopening")
                        break
                    # Let the burst settle, then drain once for all of it.
                    time.sleep(COALESCE_SECONDS)
                    _safe_drain(cfg)
            except Exception as e:  # noqa: BLE001 - keep the watcher alive
                log.warning("watch loop error (%s); reopening in 5s", e)
                time.sleep(5)
            finally:
                try:
                    kernel32.CloseHandle(handle)
                except Exception:
                    pass
                # A tight reopen loop would be its own CPU burn.
                time.sleep(1)
