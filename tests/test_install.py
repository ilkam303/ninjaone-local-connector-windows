"""Installer and Task Scheduler wiring (Windows port).

The macOS tree tests install.sh and launchd plists; here the equivalents are
install.ps1 and the generated Task Scheduler XML. The XML builder is pure
Python, so it is fully testable from any platform; install.ps1 is checked
statically and, when pwsh is present, parsed for real.
"""

import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.base import ConnectorCase

SRC = Path(__file__).resolve().parent.parent
PWSH = shutil.which("pwsh") or shutil.which("powershell")


class WindowsTaskXml(ConnectorCase):
    """The launchd-plist analog. Acceptance test 12, Windows edition."""

    def tasks(self):
        import connector
        return connector.build_windows_task_xml(self.cfg)

    def test_both_tasks_are_generated(self):
        import connector
        tasks = self.tasks()
        self.assertEqual(sorted(tasks),
                         sorted([connector.WIN_SYNC_TASK, connector.WIN_BRIDGE_TASK]))

    def test_sync_task_has_no_repeating_trigger(self):
        """The on-demand model: a logon trigger and nothing else. A Repetition
        or TimeTrigger here would silently reintroduce polling — which is
        a repeating trigger would silently reintroduce polling, so its
        absence is pinned here."""
        import connector
        xml = self.tasks()[connector.WIN_SYNC_TASK]
        self.assertIn("<LogonTrigger>", xml)
        self.assertNotIn("<Repetition>", xml)
        self.assertNotIn("<TimeTrigger>", xml)
        self.assertNotIn("<CalendarTrigger>", xml)

    def test_bridge_task_is_a_resident_watcher_with_no_time_limit(self):
        import connector
        xml = self.tasks()[connector.WIN_BRIDGE_TASK]
        self.assertIn("bridge --watch", xml)
        self.assertIn("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>", xml)
        self.assertNotIn("<Repetition>", xml)

    def test_sync_task_invokes_the_auto_morning_reset(self):
        import connector
        self.assertIn("sync --auto", self.tasks()[connector.WIN_SYNC_TASK])

    def test_tasks_use_absolute_interpreter_and_script_paths(self):
        for name, xml in self.tasks().items():
            command = re.search(r"<Command>(.*?)</Command>", xml, re.S).group(1)
            args = re.search(r"<Arguments>(.*?)</Arguments>", xml, re.S).group(1)
            with self.subTest(task=name):
                self.assertTrue(os.path.isabs(command), command)
                script = args.split('"')[1]
                self.assertTrue(os.path.isabs(script), script)
                self.assertTrue(script.endswith("connector.py"))

    def test_tasks_run_least_privilege_and_hidden(self):
        for name, xml in self.tasks().items():
            with self.subTest(task=name):
                self.assertIn("<RunLevel>LeastPrivilege</RunLevel>", xml)
                self.assertIn("<Hidden>true</Hidden>", xml)
                self.assertIn("<LogonType>InteractiveToken</LogonType>", xml)

    def test_xml_declares_utf16_and_is_well_formed(self):
        import xml.etree.ElementTree as ET
        for name, xml in self.tasks().items():
            with self.subTest(task=name):
                self.assertTrue(xml.startswith('<?xml version="1.0" encoding="UTF-16"?>'))
                # Strip the declaration so ElementTree will parse the str.
                ET.fromstring(xml.split("?>", 1)[1])

    def test_hostile_user_name_is_xml_escaped(self):
        """USERNAME/USERDOMAIN come from the environment; a crafted value must
        not be able to break out of the XML and inject another element."""
        import connector
        with mock.patch.dict(os.environ, {"USERNAME": 'a"><Exec><Command>calc</Command></Exec><x y="',
                                          "USERDOMAIN": "DOM&CO"}):
            xml = connector.build_windows_task_xml(self.cfg)[connector.WIN_SYNC_TASK]
        self.assertNotIn("<Command>calc</Command>", xml)
        self.assertIn("&amp;", xml)
        self.assertIn("&lt;", xml)

    def test_pythonw_is_preferred_when_present(self):
        import connector
        with tempfile.TemporaryDirectory() as tmp:
            py = Path(tmp) / "python.exe"
            py.write_text("")
            self.assertEqual(connector._windows_pythonw(str(py)), str(py))
            pyw = Path(tmp) / "pythonw.exe"
            pyw.write_text("")
            self.assertEqual(connector._windows_pythonw(str(py)), str(pyw))


class MacLaunchAgentsStillWork(ConnectorCase):
    """The tree keeps both backends; the macOS half must not rot."""

    @unittest.skipIf(os.name == "nt", "launchd is macOS-only")
    def test_sync_plist_has_no_start_interval(self):
        import connector
        plist = connector.make_plists(self.cfg)[connector.SYNC_LABEL]
        self.assertNotIn("StartInterval", plist)
        self.assertTrue(plist["RunAtLoad"])
        restored = plistlib.loads(plistlib.dumps(plist))
        self.assertEqual(restored["Label"], connector.SYNC_LABEL)

    @unittest.skipIf(os.name == "nt", "launchd is macOS-only")
    def test_bridge_plist_watches_requests(self):
        import connector
        plist = connector.make_plists(self.cfg)[connector.BRIDGE_LABEL]
        self.assertEqual(plist["WatchPaths"],
                         [str(self.exchange_root / "requests")])


class InstallScriptStatic(unittest.TestCase):
    """install.ps1 cannot be executed on macOS, so assert the guarantees it is
    required to carry. Each of these is a lesson paid for by an earlier
    connector in this family."""

    @classmethod
    def setUpClass(cls):
        cls.text = (SRC / "install.ps1").read_text()

    def test_rejects_the_microsoft_store_python_stub(self):
        self.assertIn("WindowsApps", self.text)

    def test_rejects_an_empty_tls_trust_store(self):
        self.assertIn("cert_store_stats", self.text)
        self.assertIn("x509_ca", self.text)

    def test_never_installs_python_silently(self):
        for forbidden in ("winget install -e --id Python", "Invoke-WebRequest"):
            if forbidden == "winget install -e --id Python":
                # It may only be PRINTED as advice, never executed.
                for line in self.text.splitlines():
                    if forbidden in line:
                        self.assertIn("Write-Host", line, line)
            else:
                self.assertNotIn(forbidden, self.text)

    def test_hardens_the_app_root_with_icacls(self):
        self.assertIn("icacls", self.text)
        self.assertIn("/inheritance:r", self.text)
        self.assertIn("SYSTEM:(OI)(CI)F", self.text)

    def test_warns_about_onedrive_synced_exchange_folders(self):
        """A OneDrive-synced exchange folder locks and re-writes bridge files
        underneath the connector."""
        self.assertIn("OneDrive", self.text)

    def test_installs_into_localappdata_not_a_synced_location(self):
        self.assertIn('Join-Path $env:LOCALAPPDATA "ninjaone-connector"', self.text)

    def test_copies_exactly_the_modules_that_exist(self):
        listed = re.search(r"\$modules = @\((.*?)\)", self.text, re.S).group(1)
        names = set(re.findall(r'"([^"]+\.py)"', listed))
        on_disk = {p.name for p in SRC.glob("nj_*.py")} | {"connector.py"}
        self.assertEqual(names, on_disk,
                         "install.ps1 module list drifted from the files on disk")

    def test_passes_no_credentials_on_the_command_line(self):
        for flag in ("--client-id", "--client-secret", "--password", "-w "):
            self.assertNotIn(flag, self.text)

    def test_discover_only_flag_exists_for_testing(self):
        self.assertIn("DiscoverOnly", self.text)


class UninstallScriptStatic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (SRC / "uninstall.ps1").read_text()

    def test_requires_typed_confirmation(self):
        self.assertIn("REMOVE", self.text)
        self.assertIn("Read-Host", self.text)

    def test_removes_both_tasks_and_the_credential(self):
        self.assertIn("NinjaOneConnectorSync", self.text)
        self.assertIn("NinjaOneConnectorBridge", self.text)
        self.assertIn("cmdkey.exe", self.text)

    def test_preserves_saved_exports_before_deleting(self):
        self.assertIn("NinjaOneData_saved_exports", self.text)
        keep_at = self.text.index("exports\\keep")
        remove_at = self.text.index("Remove-TreeSafely $exchange")
        self.assertLess(keep_at, remove_at,
                        "exports\\keep must be preserved BEFORE the delete")

    def test_deletes_junction_safely(self):
        """Remove-Item -Recurse on PS 5.1 recurses THROUGH a junction and
        deletes the target's contents. The exchange root is hostile-writable."""
        self.assertIn("Remove-TreeSafely", self.text)
        self.assertIn("ReparsePoint", self.text)

    def test_validates_the_exchange_root_before_deleting_it(self):
        self.assertIn("Test-ExchangeRootSafe", self.text)

    def test_validates_python_path_from_config(self):
        self.assertIn("python(w)?\\.exe", self.text)

    def test_leaves_python_untouched(self):
        self.assertNotIn("Uninstall-Package", self.text)
        self.assertIn("Python itself was left untouched", self.text)


@unittest.skipUnless(PWSH, "pwsh/powershell not available to parse the scripts")
class PowerShellParses(unittest.TestCase):
    def _parse(self, name):
        script = (
            "$tokens=$null; $errors=$null; "
            "[void][System.Management.Automation.Language.Parser]::ParseFile("
            f"'{SRC / name}', [ref]$tokens, [ref]$errors); "
            "if ($errors.Count -gt 0) { $errors | ForEach-Object "
            "{ Write-Output $_.Message }; exit 1 } else { exit 0 }")
        result = subprocess.run([PWSH, "-NoProfile", "-Command", script],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0,
                         f"{name} failed to parse:\n{result.stdout}")

    def test_install_ps1_parses(self):
        self._parse("install.ps1")

    def test_uninstall_ps1_parses(self):
        self._parse("uninstall.ps1")


if __name__ == "__main__":
    unittest.main()
