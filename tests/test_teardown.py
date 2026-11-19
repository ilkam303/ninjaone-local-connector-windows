"""Acceptance test 14: teardown --all removes every trace, preserves
exports/keep/, is idempotent, and touches nothing outside the connector's own
footprint.

Every system-mutating call (launchctl, the Keychain) is patched out — this
suite must never disturb a real installation on the machine running it.
"""

import argparse
import json
import unittest
from pathlib import Path
from unittest import mock

from tests.base import ConnectorCase


class TeardownCase(ConnectorCase):
    def setUp(self):
        super().setUp()
        import connector
        from nj_common import Exchange, save_config

        self.home = self.tmp / "home"
        self.home.mkdir()
        save_config(self.cfg)
        self.exchange = Exchange(self.cfg)
        self.exchange.ensure_dirs()
        (self.exchange.root / "ninjaone.sqlite").write_text("snapshot")
        (self.exchange.exports / "sync_manifest.json").write_text("{}")
        (self.exchange.keep / "my_report.csv").write_text("id,name\n1,keepme\n")

        # A sibling skill from an unrelated tool — must survive untouched.
        self.sibling = self.home / ".claude" / "skills" / "another-tool-reporting"
        self.sibling.mkdir(parents=True)
        (self.sibling / "SKILL.md").write_text("someone else's skill")
        self.our_skill = self.home / ".claude" / "skills" / "ninjaone-reporting"
        self.our_skill.mkdir(parents=True)
        (self.our_skill / "SKILL.md").write_text("ours")

        # Unrelated user data in the fake home — must survive.
        self.bystander = self.home / "Documents"
        self.bystander.mkdir()
        (self.bystander / "taxes.pdf").write_text("do not touch")

        patches = [
            mock.patch.object(connector, "remove_launch_agents"),
            mock.patch("nj_credstore.delete_credentials"),
            mock.patch.object(Path, "home", return_value=self.home),
        ]
        self.mocks = [p.start() for p in patches]
        for p in patches:
            self.addCleanup(p.stop)
        self.connector = connector

    def teardown_args(self, **kw):
        return argparse.Namespace(purge=kw.get("purge", False),
                                  all=kw.get("all", False))


class FullTeardown(TeardownCase):
    def test_all_removes_every_connector_trace(self):
        from nj_common import app_root
        self.connector.cmd_teardown(self.teardown_args(all=True))
        self.assertFalse(app_root().exists())
        self.assertFalse(self.exchange.root.exists())
        self.assertFalse(self.our_skill.exists())
        self.connector.remove_launch_agents.assert_called_once()

    def test_saved_exports_are_preserved_to_the_home_folder(self):
        self.connector.cmd_teardown(self.teardown_args(all=True))
        preserved = self.home / "NinjaOneData_saved_exports"
        self.assertTrue(preserved.is_dir())
        self.assertEqual((preserved / "my_report.csv").read_text(),
                         "id,name\n1,keepme\n")

    def test_preserved_exports_never_overwrite_an_existing_folder(self):
        (self.home / "NinjaOneData_saved_exports").mkdir()
        (self.home / "NinjaOneData_saved_exports" / "older.csv").write_text("old")
        self.connector.cmd_teardown(self.teardown_args(all=True))
        self.assertTrue((self.home / "NinjaOneData_saved_exports" / "older.csv").exists())
        self.assertTrue((self.home / "NinjaOneData_saved_exports_1" / "my_report.csv").exists())

    def test_sibling_skills_and_unrelated_files_survive(self):
        self.connector.cmd_teardown(self.teardown_args(all=True))
        self.assertTrue(self.sibling.exists())
        self.assertEqual((self.sibling / "SKILL.md").read_text(),
                         "someone else's skill")
        self.assertTrue((self.home / ".claude" / "skills").is_dir())
        self.assertTrue((self.bystander / "taxes.pdf").exists())

    def test_teardown_is_idempotent(self):
        self.connector.cmd_teardown(self.teardown_args(all=True))
        self.connector.cmd_teardown(self.teardown_args(all=True))
        self.connector.cmd_teardown(self.teardown_args(all=True))
        self.assertFalse(self.exchange.root.exists())

    def test_keychain_item_is_deleted_exactly_once_per_run(self):
        import nj_credstore
        self.connector.cmd_teardown(self.teardown_args(all=True))
        nj_credstore.delete_credentials.assert_called_once()


class PartialTeardown(TeardownCase):
    def test_default_leaves_data_in_place(self):
        from nj_common import app_root
        self.connector.cmd_teardown(self.teardown_args())
        self.assertTrue(app_root().exists())
        self.assertTrue(self.exchange.root.exists())
        # The skill is a connector artifact and always goes.
        self.assertFalse(self.our_skill.exists())

    def test_purge_removes_the_app_root_but_keeps_the_exchange_folder(self):
        from nj_common import app_root
        self.connector.cmd_teardown(self.teardown_args(purge=True))
        self.assertFalse(app_root().exists())
        self.assertTrue(self.exchange.root.exists())
        self.assertTrue((self.exchange.keep / "my_report.csv").exists())


class UninstallScriptDelegation(unittest.TestCase):
    """The Windows uninstaller prefers the connector's own `teardown --all`
    (which preserves exports/keep) and only falls back to raw file removal
    when no Python is left. Static assertion: the fallback must come after,
    and must still preserve saved exports."""

    @classmethod
    def setUpClass(cls):
        from pathlib import Path as P
        cls.text = (P(__file__).resolve().parent.parent / "uninstall.ps1").read_text()

    def test_prefers_the_python_teardown_path(self):
        self.assertIn("teardown --all", self.text)
        teardown_at = self.text.index("teardown --all")
        fallback_at = self.text.index("Best-effort cleanup done")
        self.assertLess(teardown_at, fallback_at)

    def test_fallback_still_preserves_saved_exports(self):
        fallback = self.text[self.text.index("if (-not $ranTeardown)"):]
        self.assertIn("NinjaOneData_saved_exports", fallback)

    def test_keepdata_flag_spares_the_data(self):
        self.assertIn("$KeepData", self.text)


if __name__ == "__main__":
    unittest.main()
