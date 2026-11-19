"""The platform layer itself: paths, ACL hardening, locking, credential store,
and the resident watcher.

Most of this is testable from either platform because the branch point is a
single module-level flag. Where a branch genuinely needs the OS (ctypes into
advapi32, msvcrt byte-range locks), the test is skipped rather than faked, and
says so.
"""

import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from tests.base import ConnectorCase, DUMMY_CLIENT_ID, DUMMY_SECRET

import nj_common

IS_WINDOWS = os.name == "nt"


class AppRootLocation(unittest.TestCase):
    def test_windows_uses_localappdata(self):
        with mock.patch.object(nj_common, "IS_WINDOWS", True), \
                mock.patch.dict(os.environ, {"LOCALAPPDATA": r"C:\Users\test\AppData\Local"}), \
                mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NJC_APP_ROOT", None)
            root = nj_common.app_root()
        self.assertEqual(root.name, "ninjaone-connector")
        self.assertIn("AppData", str(root))

    def test_windows_falls_back_when_localappdata_is_unset(self):
        with mock.patch.object(nj_common, "IS_WINDOWS", True):
            saved = os.environ.pop("LOCALAPPDATA", None)
            os.environ.pop("NJC_APP_ROOT", None)
            try:
                root = nj_common.app_root()
            finally:
                if saved is not None:
                    os.environ["LOCALAPPDATA"] = saved
        self.assertEqual(root.name, "ninjaone-connector")
        self.assertIn("Local", str(root))

    def test_env_override_wins_on_both_platforms(self):
        with mock.patch.dict(os.environ, {"NJC_APP_ROOT": "/tmp/override-root"}):
            self.assertEqual(nj_common.app_root(), Path("/tmp/override-root"))

    def test_app_root_is_never_the_exchange_root(self):
        """The two-root trust boundary is the whole security model."""
        with mock.patch.dict(os.environ, {"NJC_APP_ROOT": "/tmp/approot"}):
            self.assertNotEqual(str(nj_common.app_root()),
                                str(Path.home() / "NinjaOneData"))


class Hardening(ConnectorCase):
    def test_posix_hardening_sets_owner_only_bits(self):
        if IS_WINDOWS:
            self.skipTest("POSIX mode bits are meaningless on NTFS")
        d = self.tmp / "hard"
        d.mkdir()
        f = d / "file"
        f.write_text("x")
        nj_common.harden(d, is_dir=True)
        nj_common.harden(f)
        self.assertEqual(d.stat().st_mode & 0o777, 0o700)
        self.assertEqual(f.stat().st_mode & 0o777, 0o600)

    def test_windows_hardening_invokes_icacls_with_inheritance_stripped(self):
        with mock.patch.object(nj_common, "IS_WINDOWS", True), \
                mock.patch.dict(os.environ, {"USERNAME": "tester",
                                             "SystemRoot": r"C:\Windows"}), \
                mock.patch.object(nj_common, "_current_user_sid",
                                  return_value="S-1-5-21-1-2-3-1001"), \
                mock.patch("subprocess.run") as run:
            nj_common.harden(Path(r"C:\some\dir"), is_dir=True)
        argv = run.call_args.args[0]
        self.assertTrue(argv[0].endswith("icacls.exe"))
        self.assertIn("/inheritance:r", argv)
        self.assertIn("/grant:r", argv)
        # Well-known / resolved SIDs, not display names: a name-based
        # principal fails the lookup on non-English Windows or an Entra
        # account, and icacls then rejects the WHOLE command silently.
        self.assertIn("*S-1-5-21-1-2-3-1001:(OI)(CI)F", argv)
        self.assertIn("*S-1-5-18:(OI)(CI)F", argv)

    def test_windows_hardening_falls_back_to_the_name_without_a_sid(self):
        with mock.patch.object(nj_common, "IS_WINDOWS", True), \
                mock.patch.dict(os.environ, {"USERNAME": "tester"}), \
                mock.patch.object(nj_common, "_current_user_sid", return_value=None), \
                mock.patch("subprocess.run") as run:
            nj_common.harden(Path(r"C:\some\dir"), is_dir=True)
        self.assertIn("tester:(OI)(CI)F", run.call_args.args[0])

    def test_windows_hardening_suppresses_the_console_window(self):
        """The watcher runs under pythonw.exe; a visible console flash on every
        harden() call contradicts the windowless design."""
        with mock.patch.object(nj_common, "IS_WINDOWS", True), \
                mock.patch.dict(os.environ, {"USERNAME": "tester"}), \
                mock.patch.object(nj_common, "_current_user_sid", return_value=None), \
                mock.patch("subprocess.run") as run:
            nj_common.harden(Path(r"C:\some\dir"), is_dir=True)
        self.assertIn("creationflags", run.call_args.kwargs)

    def test_harden_reports_whether_it_actually_applied(self):
        """doctor is the only feedback channel for ACL failure, so harden must
        not swallow the result."""
        d = self.tmp / "reportable"
        d.mkdir()
        if IS_WINDOWS:
            self.skipTest("POSIX branch only")
        self.assertIs(nj_common.harden(d, is_dir=True), True)
        self.assertIs(nj_common.harden(self.tmp / "missing"), False)

    def test_windows_hardening_is_best_effort_not_fatal(self):
        with mock.patch.object(nj_common, "IS_WINDOWS", True), \
                mock.patch.dict(os.environ, {"USERNAME": "tester"}), \
                mock.patch("subprocess.run", side_effect=OSError("boom")):
            nj_common.harden(Path(r"C:\some\dir"), is_dir=True)  # must not raise

    def test_windows_hardening_without_a_username_does_nothing(self):
        with mock.patch.object(nj_common, "IS_WINDOWS", True), \
                mock.patch("subprocess.run") as run:
            saved = os.environ.pop("USERNAME", None)
            try:
                nj_common.harden(Path(r"C:\some\dir"), is_dir=True)
            finally:
                if saved is not None:
                    os.environ["USERNAME"] = saved
        run.assert_not_called()


class Locking(ConnectorCase):
    def test_lock_is_exclusive_across_processes(self):
        nj_common.ensure_app_dirs()
        with nj_common.exclusive_lock("sync") as first:
            self.assertTrue(first)
            script = (
                "import sys, os; sys.path.insert(0, %r);"
                "os.environ['NJC_APP_ROOT'] = %r;"
                "from nj_common import exclusive_lock;"
                "ctx = exclusive_lock('sync');"
                "print('ACQUIRED' if ctx.__enter__() else 'BLOCKED')"
                % (str(Path(__file__).resolve().parent.parent),
                   os.environ["NJC_APP_ROOT"]))
            result = subprocess.run([sys.executable, "-c", script],
                                    capture_output=True, text=True)
            self.assertIn("BLOCKED", result.stdout, result.stderr)

    def test_lock_releases_cleanly_and_can_be_retaken(self):
        nj_common.ensure_app_dirs()
        with nj_common.exclusive_lock("sync") as a:
            self.assertTrue(a)
        with nj_common.exclusive_lock("sync") as b:
            self.assertTrue(b)

    def test_distinct_lock_names_do_not_contend(self):
        nj_common.ensure_app_dirs()
        with nj_common.exclusive_lock("sync") as a, \
                nj_common.exclusive_lock("bridge") as b, \
                nj_common.exclusive_lock("watch") as c:
            self.assertTrue(a and b and c)


class CredentialStoreContract(unittest.TestCase):
    """Both backends must expose the same API and the same validation."""

    def test_api_surface_is_identical_on_either_backend(self):
        import nj_credstore
        for name in ("store_credentials", "get_credentials",
                     "has_credentials", "delete_credentials"):
            self.assertTrue(callable(getattr(nj_credstore, name)), name)
        self.assertEqual(nj_credstore.SERVICE, "ninjaone-connector")

    def test_charset_gates_reject_dangerous_values(self):
        import nj_credstore
        bad_ids = ["", "short", 'has"quote', "has space", "has$dollar",
                   "has`backtick", "has\\backslash", "x" * 200, "has\nnewline"]
        for value in bad_ids:
            with self.subTest(client_id=value):
                with self.assertRaises(nj_credstore.CredentialStoreError):
                    nj_credstore._validate(value, DUMMY_SECRET)
        bad_secrets = ["", "tooshort", 'has"quote', "has space",
                       "has;semicolon", "x" * 400, "has\rcr"]
        for value in bad_secrets:
            with self.subTest(secret=value):
                with self.assertRaises(nj_credstore.CredentialStoreError):
                    nj_credstore._validate(DUMMY_CLIENT_ID, value)

    def test_valid_pair_passes_the_gate(self):
        import nj_credstore
        cid, secret = nj_credstore._validate(DUMMY_CLIENT_ID, DUMMY_SECRET)
        self.assertEqual((cid, secret), (DUMMY_CLIENT_ID, DUMMY_SECRET))

    def test_legacy_error_alias_is_kept(self):
        import nj_credstore
        self.assertIs(nj_credstore.KeychainError,
                      nj_credstore.CredentialStoreError)

    @unittest.skipUnless(IS_WINDOWS, "advapi32 is Windows-only")
    def test_windows_backend_round_trip(self):
        """Only meaningful on Windows: write, read back, delete."""
        import nj_credstore
        had = nj_credstore.has_credentials()
        if had:
            self.skipTest("refusing to clobber a real credential on this machine")
        nj_credstore.store_credentials(DUMMY_CLIENT_ID, DUMMY_SECRET)
        try:
            self.assertTrue(nj_credstore.has_credentials())
            self.assertEqual(nj_credstore.get_credentials(),
                             (DUMMY_CLIENT_ID, DUMMY_SECRET))
        finally:
            nj_credstore.delete_credentials()
        self.assertFalse(nj_credstore.has_credentials())


class WatcherGuards(ConnectorCase):
    def test_watcher_refuses_to_run_off_windows(self):
        if IS_WINDOWS:
            self.skipTest("this guard only fires off-Windows")
        import nj_watch
        with self.assertRaises(RuntimeError) as ctx:
            nj_watch.watch(self.cfg)
        self.assertIn("Windows", str(ctx.exception))

    def test_bridge_watch_is_rejected_off_windows(self):
        if IS_WINDOWS:
            self.skipTest("this guard only fires off-Windows")
        import argparse

        import connector
        from nj_common import save_config
        save_config(self.cfg)
        args = argparse.Namespace(watch=True, drain=False)
        with self.assertRaises(SystemExit):
            connector.cmd_bridge(args)

    def test_bridge_requires_a_mode(self):
        import argparse

        import connector
        from nj_common import save_config
        save_config(self.cfg)
        with self.assertRaises(SystemExit):
            connector.cmd_bridge(argparse.Namespace(watch=False, drain=False))

    def test_watcher_drain_swallows_errors_to_stay_alive(self):
        """A hostile request must never take the watcher down."""
        import nj_watch
        with mock.patch("nj_watch.Bridge") as bridge:
            bridge.return_value.drain.side_effect = RuntimeError("bad request")
            nj_watch._safe_drain(self.cfg)  # must not raise

    def test_watcher_coalesces_bursts(self):
        import nj_watch
        self.assertGreater(nj_watch.COALESCE_SECONDS, 0)
        self.assertLess(nj_watch.COALESCE_SECONDS, 2)


if __name__ == "__main__":
    unittest.main()
