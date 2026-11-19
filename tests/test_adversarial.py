"""Red-team regressions: credential exfiltration attempts, process-listing
exposure, path containment, locking, and CLI abuse.

Every finding documented in SECURITY_REVIEW.md that is testable offline has a
test here so it cannot silently regress.
"""

import json
import os
import stat
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from tests.base import (ConnectorCase, DUMMY_CLIENT_ID, DUMMY_SECRET,
                        MockHttp, make_client)

import nj_credstore
from nj_common import Exchange, atomic_write, exclusive_lock


class NoBridgeActionDisclosesSecrets(ConnectorCase):
    def test_the_action_set_is_exactly_the_documented_eight(self):
        bridge = self.make_bridge()
        self.assertEqual(sorted(bridge.actions), [
            "api_get", "export", "get_device", "query_activities",
            "query_alerts", "query_devices", "status", "sync_now"])

    def test_no_response_ever_carries_credential_material(self):
        bridge = self.make_bridge()
        for rid, action, params in (
                ("a", "status", {}),
                ("b", "query_devices", {}),
                ("c", "query_alerts", {}),
                ("d", "query_activities", {}),
                ("e", "get_device", {"device_id": 1}),
                ("f", "api_get", {"path": "/v2/devices"}),
        ):
            response = self.roundtrip(bridge, action, params, rid=rid)
            blob = json.dumps(response).lower()
            for forbidden in ("client_secret", "access_token", "bearer",
                              "keychain", "password", "authorization"):
                self.assertNotIn(forbidden, blob, f"{action} leaked {forbidden}")

    def test_status_does_not_expose_the_app_root_path(self):
        """The manifest tells the skill about the exchange root only; the
        private root is not advertised to anything that reads responses."""
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, "status")
        self.assertNotIn("Application Support", json.dumps(response))
        self.assertIn("exchange_root", response["data"])

    def test_api_get_cannot_be_pointed_at_the_token_endpoint(self):
        engine = self.make_engine()
        engine._client = make_client()
        bridge = self.make_bridge(engine=engine)
        for path in ("/ws/oauth/token", "/oauth/token"):
            response = self.roundtrip(bridge, "api_get", {"path": path},
                                      rid="tok" + str(len(path)))
            self.assertEqual(response["status"], "error")


class ResponsePathContainment(ConnectorCase):
    def test_response_filename_is_sanitized_from_the_request_id(self):
        bridge = self.make_bridge()
        # A traversal id is rejected at validation, and the error response
        # still lands inside responses/ under a sanitized name.
        self.write_request(bridge, None, rid="x", raw=json.dumps(
            {"id": "../../../../tmp/pwned", "action": "status", "params": {}}),
            filename="request-..%2F..%2Ftmp%2Fpwned.json")
        bridge.drain()
        written = list(bridge.exchange.responses.iterdir())
        self.assertTrue(written)
        for path in written:
            self.assertTrue(bridge.exchange.contains(path))
            self.assertNotIn("..", path.name)
        self.assertFalse(Path("/tmp/pwned").exists())

    def test_exchange_contains_rejects_outside_paths(self):
        exchange = Exchange(self.cfg)
        exchange.ensure_dirs()
        self.assertTrue(exchange.contains(exchange.responses / "a.json"))
        self.assertFalse(exchange.contains(self.tmp / "outside.json"))
        self.assertFalse(exchange.contains(Path("/etc/passwd")))

    def test_non_regular_files_are_not_processed(self):
        bridge = self.make_bridge()
        bridge.exchange.ensure_dirs()
        fifo = bridge.exchange.requests / "request-fifo.json"
        try:
            os.mkfifo(fifo)
        except (OSError, AttributeError):
            self.skipTest("mkfifo unavailable")
        bridge.drain()
        response = self.read_response(bridge, "fifo")
        self.assertEqual(response["error"]["code"], "not_a_file")

    def test_atomic_write_refuses_a_planted_symlink_at_the_temp_name(self):
        target = self.tmp / "victim.txt"
        target.write_text("original")
        dest_dir = self.tmp / "dest"
        dest_dir.mkdir()
        dest = dest_dir / "out.json"
        planted = dest_dir / f".{dest.name}.tmp-{os.getpid()}"
        planted.symlink_to(target)
        atomic_write(dest, "new content")
        self.assertEqual(target.read_text(), "original")   # never written through
        self.assertEqual(dest.read_text(), "new content")

    def test_export_onto_a_planted_symlink_is_refused_not_followed(self):
        """An attacker who can write to exports/ may pre-plant a symlink at a
        name the user is about to export to. Resolved-path containment catches
        it and the export is refused outright — the link target is never
        touched. (Refusing rather than replacing costs an attacker-chosen
        filename until the user removes the link; that tradeoff is recorded in
        SECURITY_REVIEW.md.)"""
        bridge = self.make_bridge()
        bridge.exchange.ensure_dirs()
        outside = self.tmp / "outside.csv"
        outside.write_text("untouched")
        (bridge.exchange.exports / "sneaky.csv").symlink_to(outside)
        response = self.roundtrip(bridge, "export", {
            "entity": "devices", "format": "csv", "filename": "sneaky"})
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["error"]["code"], "path_rejected")
        self.assertEqual(outside.read_text(), "untouched")

    def test_export_to_a_clean_name_still_works_alongside_a_planted_link(self):
        bridge = self.make_bridge()
        bridge.exchange.ensure_dirs()
        outside = self.tmp / "outside.csv"
        outside.write_text("untouched")
        (bridge.exchange.exports / "sneaky.csv").symlink_to(outside)
        response = self.roundtrip(bridge, "export", {
            "entity": "devices", "format": "csv", "filename": "clean_name"})
        self.assertEqual(response["status"], "ok")
        self.assertEqual(outside.read_text(), "untouched")


class CredentialsNeverInProcessListings(unittest.TestCase):
    def test_store_credentials_passes_the_secret_on_stdin_not_argv(self):
        with mock.patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, "", "")
            nj_credstore.store_credentials(DUMMY_CLIENT_ID, DUMMY_SECRET)
        args, kwargs = run.call_args
        argv = args[0]
        self.assertEqual(argv, ["/usr/bin/security", "-i"])
        for element in argv:
            self.assertNotIn(DUMMY_SECRET, element)
            self.assertNotIn(DUMMY_CLIENT_ID, element)
        # The secret travels through stdin, where `ps` cannot see it.
        self.assertIn(DUMMY_SECRET, kwargs["input"])

    def test_reading_credentials_never_puts_the_secret_in_argv(self):
        attrs = subprocess.CompletedProcess(
            [], 0, f'"acct"<blob>="{DUMMY_CLIENT_ID}"\n', "")
        secret = subprocess.CompletedProcess([], 0, DUMMY_SECRET + "\n", "")
        with mock.patch("subprocess.run", side_effect=[attrs, secret]) as run:
            client_id, client_secret = nj_credstore.get_credentials()
        self.assertEqual(client_id, DUMMY_CLIENT_ID)
        self.assertEqual(client_secret, DUMMY_SECRET)
        for call in run.call_args_list:
            for element in call.args[0]:
                self.assertNotIn(DUMMY_SECRET, element)

    def test_malformed_credentials_are_refused_before_they_reach_security(self):
        bad_ids = ["", "short", 'has"quote', "has space", "has$dollar",
                   "has`backtick", "has\\backslash", "x" * 200]
        for value in bad_ids:
            with self.subTest(client_id=value):
                with self.assertRaises(nj_credstore.KeychainError):
                    nj_credstore.store_credentials(value, DUMMY_SECRET)
        bad_secrets = ["", "tooshort", 'has"quote', "has space",
                       "has;semicolon", "x" * 400]
        for value in bad_secrets:
            with self.subTest(secret=value):
                with self.assertRaises(nj_credstore.KeychainError):
                    nj_credstore.store_credentials(DUMMY_CLIENT_ID, value)

    def test_a_keychain_item_without_an_account_is_a_clean_error(self):
        attrs = subprocess.CompletedProcess([], 0, "no account field here", "")
        with mock.patch("subprocess.run", return_value=attrs):
            with self.assertRaises(nj_credstore.KeychainError):
                nj_credstore.get_credentials()


class CliAbuse(ConnectorCase):
    def _setup_args(self, **kw):
        import argparse
        defaults = dict(non_interactive=True, instance="app.ninjarmm.com",
                        exchange_root=str(self.exchange_root), interval=15,
                        retention_days=1, max_db_mb=100, secret_stdin=False,
                        skip_launchd=True)
        defaults.update(kw)
        return argparse.Namespace(**defaults)

    def test_non_interactive_without_secret_stdin_is_refused(self):
        import connector
        with self.assertRaises(SystemExit):
            connector.cmd_setup(self._setup_args())

    def test_non_interactive_without_instance_is_refused(self):
        import connector
        with self.assertRaises(SystemExit):
            connector.cmd_setup(self._setup_args(instance=None, secret_stdin=True))

    def test_unknown_instance_is_refused(self):
        import connector
        with self.assertRaises(SystemExit):
            connector.cmd_setup(self._setup_args(
                instance="evil.example.com", secret_stdin=True))

    def test_exchange_root_cannot_be_home_or_root_or_the_app_root(self):
        import connector
        from nj_common import app_root
        for bad in (str(Path.home()), "/", str(app_root()),
                    str(app_root() / "nested")):
            with self.subTest(root=bad):
                with self.assertRaises(SystemExit):
                    connector.cmd_setup(self._setup_args(
                        exchange_root=bad, secret_stdin=True))

    def test_credentials_are_not_accepted_as_flags(self):
        """The parser must have no option that could put a secret in argv."""
        import argparse as ap

        import connector
        parser_actions = []
        real_add = ap._ActionsContainer.add_argument

        def spy(self, *args, **kwargs):
            parser_actions.extend(a for a in args if isinstance(a, str))
            return real_add(self, *args, **kwargs)

        with mock.patch.object(ap._ActionsContainer, "add_argument", spy):
            with mock.patch("sys.argv", ["connector", "setup", "--help"]):
                with self.assertRaises(SystemExit):
                    connector.main()
        for flag in parser_actions:
            self.assertNotIn("secret", flag.replace("--secret-stdin", ""))
            self.assertNotIn("--client-secret", flag)
            self.assertNotIn("--client-id", flag)
            self.assertNotIn("--password", flag)


class Locking(ConnectorCase):
    def test_second_holder_of_a_lock_is_told_to_stand_down(self):
        from nj_common import ensure_app_dirs
        ensure_app_dirs()
        with exclusive_lock("sync") as first:
            self.assertTrue(first)
            script = (
                "import sys; sys.path.insert(0, %r);"
                "import os; os.environ['NJC_APP_ROOT'] = %r;"
                "from nj_common import exclusive_lock;"
                "ctx = exclusive_lock('sync');"
                "print('ACQUIRED' if ctx.__enter__() else 'BLOCKED')"
                % (str(Path(__file__).resolve().parent.parent),
                   os.environ["NJC_APP_ROOT"]))
            result = subprocess.run(["/usr/bin/python3", "-c", script],
                                    capture_output=True, text=True)
            self.assertIn("BLOCKED", result.stdout, result.stderr)

    def test_lock_is_released_after_the_block(self):
        from nj_common import ensure_app_dirs
        ensure_app_dirs()
        with exclusive_lock("sync") as acquired:
            self.assertTrue(acquired)
        with exclusive_lock("sync") as acquired_again:
            self.assertTrue(acquired_again)


class SnapshotIntegrity(ConnectorCase):
    def test_snapshot_is_never_left_partially_written(self):
        """publish() builds in the private root and renames into place, so a
        reader either sees the old file or the complete new one."""
        import sqlite3
        engine = self.make_engine()
        engine.publish()
        first = engine.exchange.snapshot.read_bytes()
        engine.publish()
        second = engine.exchange.snapshot.read_bytes()
        for blob in (first, second):
            self.assertTrue(blob.startswith(b"SQLite format 3"))
        con = sqlite3.connect(engine.exchange.snapshot)
        try:
            self.assertEqual(con.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        finally:
            con.close()

    def test_no_temp_files_are_left_in_the_exchange_root(self):
        engine = self.make_engine()
        engine.publish()
        leftovers = [p.name for p in engine.exchange.root.rglob("*")
                     if p.is_file() and (".tmp-" in p.name or p.name.startswith(".snapshot"))]
        self.assertEqual(leftovers, [])

    def test_app_root_permissions_are_owner_only(self):
        from nj_common import app_root, config_path, ensure_app_dirs, save_config
        ensure_app_dirs()
        save_config(self.cfg)
        self.assertEqual(stat.S_IMODE(app_root().stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(config_path().stat().st_mode), 0o600)


class NoDangerousPrimitives(unittest.TestCase):
    def test_source_uses_no_eval_exec_pickle_or_shell(self):
        src = Path(__file__).resolve().parent.parent
        offenders = []
        for module in src.glob("nj_*.py"):
            text = module.read_text()
            for pattern in ("eval(", "exec(", "import pickle", "shell=True",
                            "os.system(", "__import__("):
                if pattern in text:
                    offenders.append((module.name, pattern))
        connector_text = (src / "connector.py").read_text()
        for pattern in ("eval(", "exec(", "import pickle", "shell=True",
                        "os.system("):
            if pattern in connector_text:
                offenders.append(("connector.py", pattern))
        self.assertEqual(offenders, [])

    def test_subprocess_calls_use_absolute_binaries_in_list_form(self):
        src = Path(__file__).resolve().parent.parent
        text = (src / "nj_credstore.py").read_text()
        self.assertIn('SECURITY = "/usr/bin/security"', text)
        self.assertNotIn('"security"', text.replace('SECURITY = "/usr/bin/security"', ""))


if __name__ == "__main__":
    import argparse  # noqa: F401  (used inside CliAbuse)
    unittest.main()
