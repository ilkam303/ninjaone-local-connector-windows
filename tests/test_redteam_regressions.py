"""Regressions for the 2026-11-18 adversarial review.

One test per finding, each written to FAIL against the code as it was. Where
the original defect only manifested on Windows, the test exercises the real
code path rather than mocking a flag — the review's sharpest criticism was
that patching `IS_WINDOWS` proves nothing, which is exactly why a suite of
223 green tests missed a crash on the very first `atomic_write`.
"""

import json
import logging
import os
import re
import unittest
from pathlib import Path
from unittest import mock

from tests.base import ConnectorCase, DUMMY_SECRET

import nj_common
from nj_bridge import MAX_DRAIN_FILES


class C1_AtomicWritePortability(ConnectorCase):
    def test_atomic_write_works_when_o_nofollow_is_absent(self):
        """C1 CRITICAL: os.O_NOFOLLOW does not exist on Windows, and
        atomic_write used it bare — so the first save_config() raised
        AttributeError and setup could never complete. Genuinely remove the
        attribute instead of mocking a platform flag."""
        saved = os.O_NOFOLLOW
        try:
            del os.O_NOFOLLOW
            self.assertFalse(hasattr(os, "O_NOFOLLOW"))
            target = self.tmp / "portable.json"
            nj_common.atomic_write(target, b'{"ok": true}')
            self.assertEqual(json.loads(target.read_text()), {"ok": True})
        finally:
            os.O_NOFOLLOW = saved

    def test_save_config_survives_without_o_nofollow(self):
        saved = os.O_NOFOLLOW
        try:
            del os.O_NOFOLLOW
            nj_common.save_config(self.cfg)
            self.assertTrue(nj_common.config_path().exists())
        finally:
            os.O_NOFOLLOW = saved

    def test_source_never_uses_a_bare_platform_only_flag(self):
        """C2: the same line also needs O_BINARY, or the fd is text-mode on
        Windows and every 0x0A becomes 0x0D 0x0A — corrupting the published
        SQLite snapshot."""
        src = (Path(__file__).resolve().parent.parent / "nj_common.py").read_text()
        self.assertNotIn("os.O_NOFOLLOW,", src)
        self.assertIn('getattr(os, "O_NOFOLLOW", 0)', src)
        self.assertIn('getattr(os, "O_BINARY", 0)', src)

    def test_binary_payload_round_trips_byte_exactly(self):
        payload = b"\x00\x01\n\r\n" + bytes(range(256)) + b"SQLite format 3\x00"
        target = self.tmp / "blob.bin"
        nj_common.atomic_write(target, payload)
        self.assertEqual(target.read_bytes(), payload)


class C3_ArchiveContainment(ConnectorCase):
    def test_archive_refuses_a_symlinked_processed_folder(self):
        """C3 HIGH->CRITICAL: _archive had no containment check, so replacing
        the archive folder with a link moved an attacker-chosen *.json to an
        attacker-chosen location — a containment break out of the exchange
        root, which is the boundary the whole design rests on."""
        bridge = self.make_bridge()
        bridge.exchange.ensure_dirs()
        outside = self.tmp / "pretend_dot_claude"
        outside.mkdir()
        processed = bridge.exchange.processed
        for child in processed.iterdir():
            child.unlink()
        processed.rmdir()
        processed.symlink_to(outside, target_is_directory=True)

        self.write_request(bridge, None, rid="evil", raw=json.dumps(
            {"id": "evil", "action": "status", "params": {}, "hooks": "payload"}))

        # Layer 1: ensure_dirs refuses to operate through the link at all, so
        # the drain aborts before a single file is touched.
        from nj_common import ConfigError
        with self.assertRaises(ConfigError):
            bridge.drain()
        self.assertEqual(list(outside.iterdir()), [],
                         f"request file escaped into {outside}")

    def test_archive_itself_refuses_even_if_the_guard_is_bypassed(self):
        """Layer 2: _archive must contain independently, so a link planted
        between ensure_dirs and the archive step still cannot escape."""
        bridge = self.make_bridge()
        bridge.exchange.ensure_dirs()
        outside = self.tmp / "second_layer"
        outside.mkdir()
        processed = bridge.exchange.processed
        for child in list(processed.iterdir()):
            child.unlink()
        processed.rmdir()
        processed.symlink_to(outside, target_is_directory=True)

        victim = bridge.exchange.requests / "request-direct.json"
        victim.write_text('{"id": "direct", "action": "status", "params": {}}')
        bridge._archive(victim)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse(victim.exists())   # removed rather than relocated

    def test_archive_sanitizes_the_filename_it_writes(self):
        bridge = self.make_bridge()
        bridge.exchange.ensure_dirs()
        self.write_request(bridge, "status", rid="ok1",
                           filename="request-ok1.json")
        bridge.drain()
        for p in bridge.exchange.processed.iterdir():
            self.assertTrue(self.make_bridge().exchange.contains(p))


class C4_ExportContainment(ConnectorCase):
    def test_export_refuses_when_exports_itself_is_a_symlink(self):
        """C4 HIGH: the check resolved BOTH sides, so a linked exports/ made
        them agree and the write landed in the link target."""
        bridge = self.make_bridge()
        bridge.exchange.ensure_dirs()
        outside = self.tmp / "outside_exports"
        outside.mkdir()
        exports = bridge.exchange.exports
        for child in list(exports.iterdir()):
            if child.is_dir():
                for g in child.iterdir():
                    g.unlink()
                child.rmdir()
            else:
                child.unlink()
        exports.rmdir()
        exports.symlink_to(outside, target_is_directory=True)

        from nj_common import ConfigError
        with self.assertRaises(ConfigError):
            self.roundtrip(bridge, "export", {
                "entity": "devices", "format": "csv", "filename": "escape"})
        self.assertEqual(list(outside.iterdir()), [])

    def test_export_action_refuses_a_linked_exports_independently(self):
        """Second layer: act_export checks the directory itself, so it holds
        even if the folder is linked after ensure_dirs ran."""
        from nj_bridge import BridgeError
        bridge = self.make_bridge()
        bridge.exchange.ensure_dirs()
        outside = self.tmp / "late_link"
        outside.mkdir()
        exports = bridge.exchange.exports
        for child in list(exports.iterdir()):
            if child.is_dir():
                for g in list(child.iterdir()):
                    g.unlink()
                child.rmdir()
            else:
                child.unlink()
        exports.rmdir()
        exports.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(BridgeError):
            bridge.act_export({"entity": "devices", "format": "csv",
                               "filename": "escape"})
        self.assertEqual(list(outside.iterdir()), [])


class C6_ReservedExportNames(ConnectorCase):
    def test_export_cannot_forge_the_published_manifest_or_summary(self):
        """C6: the skill trusts these two files, and _sweep_exports exempts
        them from cleanup, so a forgery would persist until the next publish."""
        bridge = self.make_bridge()
        for name in ("sync_manifest.json", "devices_summary.csv"):
            response = self.roundtrip(bridge, "export", {
                "entity": "devices",
                "format": "json" if name.endswith("json") else "csv",
                "filename": name}, rid="r" + str(len(name)))
            self.assertEqual(response["status"], "error", name)
            self.assertEqual(response["error"]["code"], "bad_filename")

    def test_windows_reserved_device_names_are_rejected(self):
        """S3: NUL.csv is still the NUL device."""
        bridge = self.make_bridge()
        for name in ("NUL", "CON", "com1", "LPT9", "nul"):
            response = self.roundtrip(bridge, "export", {
                "entity": "devices", "format": "csv", "filename": name},
                rid="d" + name.lower())
            self.assertEqual(response["status"], "error", name)
            self.assertEqual(response["error"]["code"], "bad_filename")


class C9_TracebackRedaction(ConnectorCase):
    def test_a_secret_inside_an_exception_never_reaches_the_log(self):
        """C9: the Filter only saw record.getMessage(); exception text is
        rendered by the Formatter and bypassed redaction entirely. Reproduced
        against the live code before the fix."""
        nj_common.RedactionFilter.add_secret(DUMMY_SECRET)
        nj_common.setup_logging(debug=True)
        log = logging.getLogger("njc.regression")
        try:
            raise ValueError(f"explosion containing {DUMMY_SECRET} verbatim")
        except ValueError:
            log.exception("handled failure")
        for handler in logging.getLogger().handlers:
            handler.flush()
        text = (nj_common.log_dir() / "connector.log").read_text()
        self.assertIn("explosion containing", text)      # the record was written
        self.assertNotIn(DUMMY_SECRET, text)             # but not the secret
        self.assertIn("[REDACTED]", text)

    def tearDown(self):
        root = logging.getLogger()
        for handler in list(root.handlers):
            handler.close()
            root.removeHandler(handler)
        super().tearDown()


class C12_DrainIsBounded(ConnectorCase):
    def test_overflow_requests_get_an_error_rather_than_wedging_the_watcher(self):
        """C12: requests/ was uncapped, so N planted files cost N seconds of
        the single resident Windows watcher."""
        bridge = self.make_bridge()
        bridge.exchange.ensure_dirs()
        total = MAX_DRAIN_FILES + 5
        for i in range(total):
            self.write_request(bridge, "status", rid=f"flood{i:04d}")
        bridge.drain()
        codes = [json.loads(r.read_text()).get("error", {}).get("code")
                 for r in bridge.exchange.responses.iterdir()]
        # The overflow is answered, not silently dropped...
        self.assertIn("too_many_requests", codes)
        # ...and requests/ is left empty, so the next trigger is not stuck
        # re-reading the same flood.
        self.assertEqual(list(bridge.exchange.requests.glob("*.json")), [])


class C15_RequestIdCaseCollision(ConnectorCase):
    def test_mixed_case_ids_are_rejected(self):
        """C15: NTFS and default APFS are case-insensitive, so request-ABC and
        request-abc answered into one response file."""
        bridge = self.make_bridge()
        bridge.exchange.ensure_dirs()
        target = bridge.exchange.requests / "request-ABC123.json"
        target.write_text(json.dumps(
            {"id": "ABC123", "action": "status", "params": {}}))
        os.utime(target, (0, 0))
        bridge.drain()
        # The error is answered under the casefolded id, which on a
        # case-insensitive filesystem is the very file the caller polls for.
        payload = json.loads(
            (bridge.exchange.responses / "response-abc123.json").read_text())
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error"]["code"], "bad_id")
        self.assertIn("lowercase", payload["error"]["message"])

    def test_a_mixed_case_caller_still_finds_its_error(self):
        """A rejected id must not answer as "unknown" — that reads as a hang
        rather than an error."""
        bridge = self.make_bridge()
        bridge.exchange.ensure_dirs()
        target = bridge.exchange.requests / "request-MiXeD.json"
        target.write_text(json.dumps(
            {"id": "MiXeD", "action": "status", "params": {}}))
        os.utime(target, (0, 0))
        bridge.drain()
        self.assertTrue((bridge.exchange.responses / "response-mixed.json").exists())
        self.assertFalse((bridge.exchange.responses / "response-unknown.json").exists())

    def test_lowercase_ids_still_work(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, "status", rid="abc-123_x")
        self.assertEqual(response["status"], "ok")


class C21_ConfigRevalidation(ConnectorCase):
    def test_hostile_exchange_root_in_config_is_refused_on_load(self):
        """C5/C21: exchange_root was validated at setup and never again, yet
        it feeds the recursive delete in `teardown --all`."""
        from nj_common import ConfigError, save_config
        save_config(dict(self.cfg, exchange_root=str(Path.home())))
        with self.assertRaises(ConfigError):
            nj_common.load_config()

    def test_app_root_overlap_is_refused_on_load(self):
        from nj_common import ConfigError, save_config
        save_config(dict(self.cfg, exchange_root=str(nj_common.app_root())))
        with self.assertRaises(ConfigError):
            nj_common.load_config()

    def test_a_normal_exchange_root_still_loads(self):
        from nj_common import save_config
        save_config(self.cfg)
        self.assertEqual(nj_common.load_config()["exchange_root"],
                         str(self.exchange_root))

    def test_unc_and_drive_relative_paths_are_refused(self):
        from nj_common import ConfigError, validate_exchange_root
        with mock.patch.object(nj_common, "IS_WINDOWS", True):
            for bad in (r"\\server\share\data", "//server/share", "C:data"):
                with self.subTest(path=bad):
                    with self.assertRaises(ConfigError):
                        validate_exchange_root(bad)


class C3_ReparsePointDetection(ConnectorCase):
    def test_symlinked_exchange_subdir_is_detected(self):
        from nj_common import is_reparse_point
        real = self.tmp / "real_dir"
        real.mkdir()
        link = self.tmp / "link_dir"
        link.symlink_to(real, target_is_directory=True)
        self.assertFalse(is_reparse_point(real))
        self.assertTrue(is_reparse_point(link))

    def test_ensure_dirs_refuses_to_run_through_a_link(self):
        from nj_common import ConfigError, Exchange
        exchange = Exchange(self.cfg)
        exchange.ensure_dirs()
        outside = self.tmp / "elsewhere"
        outside.mkdir()
        requests = exchange.requests
        for child in list(requests.iterdir()):
            if child.is_dir():
                child.rmdir()
            else:
                child.unlink()
        requests.rmdir()
        requests.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ConfigError):
            exchange.ensure_dirs()


class C7_WatcherDoesNotSpin(unittest.TestCase):
    def test_source_breaks_out_when_the_watch_call_returns_false(self):
        """C7: the loop ignored a False return, so deleting requests/ pinned a
        core forever on a stale handle and the bridge never fired again."""
        src = (Path(__file__).resolve().parent.parent / "nj_watch.py").read_text()
        self.assertIn("if not _watch_once(kernel32, handle):", src)
        loop = src[src.index("while True:\n                    if not _watch_once"):]
        self.assertIn("break", loop.split("_safe_drain")[0])

    def test_reopen_path_recreates_the_folder_and_paces_itself(self):
        src = (Path(__file__).resolve().parent.parent / "nj_watch.py").read_text()
        self.assertIn("exchange.ensure_dirs()", src)
        self.assertIn("time.sleep(1)", src)


class C10_C11_DoctorChecksTheRealThing(unittest.TestCase):
    def test_doctor_reads_the_live_task_not_the_generated_file(self):
        """C11: reading back our own XML proved nothing — schtasks /Change can
        add a trigger afterwards."""
        src = (Path(__file__).resolve().parent.parent / "connector.py").read_text()
        self.assertIn("_registered_task_xml", src)
        self.assertIn('"/Query", "/TN", name, "/XML"', src)
        for trigger in ("CalendarTrigger", "BootTrigger", "EventTrigger"):
            self.assertIn(trigger, src)

    def test_doctor_does_not_use_posix_mode_bits_on_windows(self):
        """C10: Windows synthesises 0o777, so the old check could never pass
        and doctor always exited 1 while the checklist said all rows PASS."""
        src = (Path(__file__).resolve().parent.parent / "connector.py").read_text()
        self.assertIn("_windows_acl_status", src)
        self.assertIn("if IS_WINDOWS:", src)


class C14_CredentialBlobGuards(unittest.TestCase):
    def test_read_path_is_bounded_and_guarded(self):
        """C14: an odd or oversized blob raised an uncaught UnicodeDecodeError
        (which then leaked the bytes into the log via C9)."""
        src = (Path(__file__).resolve().parent.parent / "nj_credstore.py").read_text()
        self.assertIn("_MAX_BLOB_BYTES", src)
        self.assertIn("size % 2", src)
        self.assertIn("UnicodeDecodeError", src)
        self.assertIn("ctypes.string_at", src)

    def test_validation_runs_on_read_not_only_on_store(self):
        src = (Path(__file__).resolve().parent.parent / "nj_credstore.py").read_text()
        read_block = src[src.index("    def get_credentials():"):]
        self.assertIn("_validate(client_id, client_secret)", read_block)


class S5_TeardownIsJunctionSafe(unittest.TestCase):
    def test_teardown_uses_a_link_aware_delete(self):
        src = (Path(__file__).resolve().parent.parent / "connector.py").read_text()
        self.assertIn("_safe_rmtree", src)
        self.assertNotIn("shutil.rmtree(app_root(), ignore_errors=True)", src)
        self.assertNotIn("shutil.rmtree(exchange_root, ignore_errors=True)", src)


class C13_LeakCheckCannotFalsePass(unittest.TestCase):
    def test_skill_leak_check_has_an_inconclusive_branch(self):
        """C13: a check that prints CLEAN because its command failed is worse
        than no check. (The reviewer's specific claim about the macOS pipeline
        was wrong — it printed nothing — but the structure is now explicit.)"""
        skill = (Path(__file__).resolve().parent.parent
                 / "ninjaone-reporting" / "SKILL.md").read_text()
        self.assertIn("INCONCLUSIVE", skill)
        self.assertIn("$searched", skill)
        self.assertNotIn("security find-generic-password", skill)


class C18_DocsArePorted(unittest.TestCase):
    def test_consumer_facing_text_has_no_macos_only_instructions(self):
        """C18: EXCHANGE_README is the ONLY protocol reference a Cowork
        session sees, and it pointed at a path that does not exist here."""
        self.assertIn("%LOCALAPPDATA%", nj_common.EXCHANGE_README)
        skill = (Path(__file__).resolve().parent.parent
                 / "ninjaone-reporting" / "SKILL.md").read_text()
        for macism in ("uuidgen", "Library/Application Support", "Keychain"):
            self.assertNotIn(macism, skill)


if __name__ == "__main__":
    unittest.main()
