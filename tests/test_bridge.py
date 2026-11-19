"""Bridge: hostile-input handling, query semantics, live scope, path safety.
Acceptance tests 8, 9, 11.
"""

import json
import os
import unittest

from tests.base import (ConnectorCase, FakeClient, make_activity, make_alert,
                        make_device)

from nj_bridge import MAX_REQUEST_BYTES


class RequestHandling(ConnectorCase):
    def test_status_returns_the_manifest_without_rebuilding(self):
        client = FakeClient()
        bridge = self.make_bridge(engine=self.make_engine(client=client))
        bridge.engine.morning_reset()
        client.calls.clear()
        response = self.roundtrip(bridge, "status")
        self.assertEqual(response["status"], "ok")
        self.assertEqual(response["data"]["manifest"]["state"], "cleared")
        self.assertEqual(client.calls, [])          # no rebuild, no API traffic

    def test_malformed_json_still_gets_an_error_response(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, None, raw="{not json at all",
                                  rid="badjson")
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["error"]["code"], "malformed_json")
        self.assertEqual(response["id"], "badjson")

    def test_non_object_payload_is_rejected(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, None, raw='["a", "list"]', rid="listy")
        self.assertEqual(response["error"]["code"], "malformed_request")

    def test_unknown_action_and_unknown_keys_are_rejected(self):
        bridge = self.make_bridge()
        r1 = self.roundtrip(bridge, "delete_everything", rid="r1")
        self.assertEqual(r1["error"]["code"], "unknown_action")
        r2 = self.roundtrip(bridge, None, rid="r2", raw=json.dumps(
            {"id": "r2", "action": "status", "params": {}, "extra": "surprise"}))
        self.assertEqual(r2["error"]["code"], "unknown_keys")

    def test_unknown_params_are_rejected(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, "query_devices",
                                  {"org": "Contoso", "sneaky": "x"})
        self.assertEqual(response["error"]["code"], "unknown_params")

    def test_bad_id_is_rejected_but_still_answered(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, None, rid="ok", raw=json.dumps(
            {"id": "../../escape", "action": "status", "params": {}}))
        self.assertEqual(response["error"]["code"], "bad_id")

    def test_oversized_request_is_rejected(self):
        bridge = self.make_bridge()
        blob = "x" * (MAX_REQUEST_BYTES + 100)
        response = self.roundtrip(bridge, None, rid="big", raw=json.dumps(
            {"id": "big", "action": "query_devices",
             "params": {"text_contains": blob}}))
        self.assertEqual(response["error"]["code"], "request_too_large")

    def test_symlinked_request_is_rejected(self):
        """Acceptance test 11: a symlink in requests/ is never followed."""
        bridge = self.make_bridge()
        bridge.exchange.ensure_dirs()
        target = self.tmp / "elsewhere.json"
        target.write_text(json.dumps({"id": "link", "action": "status", "params": {}}))
        link = bridge.exchange.requests / "request-link.json"
        link.symlink_to(target)
        bridge.drain()
        response = self.read_response(bridge, "link")
        self.assertEqual(response["error"]["code"], "symlink_rejected")

    def test_duplicate_request_ids_do_not_collide(self):
        bridge = self.make_bridge()
        self.write_request(bridge, "status", rid="dup", filename="request-dup.json")
        bridge.drain()
        first = self.read_response(bridge, "dup")
        self.write_request(bridge, "status", rid="dup", filename="request-dup.json")
        bridge.drain()
        second = self.read_response(bridge, "dup")
        self.assertEqual(first["status"], "ok")
        self.assertEqual(second["status"], "ok")
        archived = list(bridge.exchange.processed.iterdir())
        self.assertEqual(len(archived), 2)          # both preserved, distinct names

    def test_requests_are_archived_after_handling(self):
        bridge = self.make_bridge()
        path = self.write_request(bridge, "status", rid="arch")
        bridge.drain()
        self.assertFalse(path.exists())
        self.assertTrue((bridge.exchange.processed / "request-arch.json").exists())


class DeviceQueries(ConnectorCase):
    def test_offline_filter_and_name_resolution(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, "query_devices", {"offline": True})
        self.assertEqual(response["status"], "ok")
        rows = response["data"]["rows"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], 2)
        self.assertEqual(rows[0]["organization"], "Contoso")
        self.assertEqual(rows[0]["location"], "HQ")
        self.assertIn("data_as_of", response)
        self.assertEqual(response["source"], "cache")

    def test_org_filter_resolves_case_insensitively(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, "query_devices", {"org": "contoso"})
        ids = sorted(r["id"] for r in response["data"]["rows"])
        self.assertEqual(ids, [1, 2])

    def test_unknown_org_is_a_clean_error(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, "query_devices", {"org": "Nonexistent"})
        self.assertEqual(response["error"]["code"], "unknown_org")

    def test_location_class_and_os_filters(self):
        bridge = self.make_bridge()
        r1 = self.roundtrip(bridge, "query_devices", {"location": "hq"}, rid="a")
        self.assertEqual(len(r1["data"]["rows"]), 2)
        r2 = self.roundtrip(bridge, "query_devices",
                            {"node_class": "WINDOWS_WORKSTATION"}, rid="b")
        self.assertEqual(len(r2["data"]["rows"]), 3)
        r3 = self.roundtrip(bridge, "query_devices", {"os_contains": "Windows 11"},
                            rid="c")
        self.assertEqual(len(r3["data"]["rows"]), 3)
        r4 = self.roundtrip(bridge, "query_devices", {"os_contains": "Ubuntu"},
                            rid="d")
        self.assertEqual(len(r4["data"]["rows"]), 0)

    def test_last_contact_range_filters(self):
        client = FakeClient(devices=[
            make_device(1, minutes_ago=1), make_device(2, minutes_ago=60 * 40)])
        bridge = self.make_bridge(engine=self.make_engine(client=client))
        response = self.roundtrip(bridge, "query_devices",
                                  {"last_contact_since": "2000-01-01"})
        self.assertEqual(len(response["data"]["rows"]), 2)

    def test_bad_date_is_rejected(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, "query_devices",
                                  {"last_contact_since": "not-a-date"})
        self.assertEqual(response["error"]["code"], "bad_param")

    def test_limit_bounds_are_enforced(self):
        bridge = self.make_bridge()
        for limit in (0, -5, 99999):
            response = self.roundtrip(bridge, "query_devices", {"limit": limit},
                                      rid=f"l{abs(limit)}")
            self.assertEqual(response["error"]["code"], "bad_param")

    def test_wrong_param_types_are_rejected(self):
        bridge = self.make_bridge()
        r1 = self.roundtrip(bridge, "query_devices", {"offline": "yes"}, rid="t1")
        self.assertEqual(r1["error"]["code"], "bad_param")
        r2 = self.roundtrip(bridge, "query_devices", {"limit": "500"}, rid="t2")
        self.assertEqual(r2["error"]["code"], "bad_param")


class AlertAndActivityQueries(ConnectorCase):
    def test_alerts_from_cache_resolve_device_and_org(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, "query_alerts")
        rows = response["data"]["rows"]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["organization"], "Contoso")
        self.assertIn(rows[0]["device"], ("Device 1", "Device 2"))

    def test_alert_live_scope_pulls_fresh_and_does_not_persist(self):
        client = FakeClient()
        engine = self.make_engine(client=client)
        bridge = self.make_bridge(engine=engine)
        client.alert_rows = [make_alert("live-only", device_id=1)]
        response = self.roundtrip(bridge, "query_alerts", {"scope": "live"})
        self.assertEqual(response["source"], "live")
        self.assertEqual([r["uid"] for r in response["data"]["rows"]], ["live-only"])
        cached = [r[0] for r in engine.con.execute("SELECT uid FROM alerts")]
        self.assertNotIn("live-only", cached)

    def test_activities_from_cache_carry_oldest_retained(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, "query_activities")
        self.assertEqual(response["source"], "cache")
        self.assertIn("oldest_retained", response)
        self.assertEqual(len(response["data"]["rows"]), 2)

    def test_historical_range_goes_live_automatically_and_is_not_persisted(self):
        """Acceptance test 9."""
        client = FakeClient(activities=[
            make_activity(900, minutes_ago=5),
            make_activity(800, days_ago=6)])
        engine = self.make_engine(client=client)
        bridge = self.make_bridge(engine=engine)
        before = engine.counts()["activities"]
        response = self.roundtrip(bridge, "query_activities",
                                  {"since": "2000-01-01"})
        self.assertEqual(response["source"], "live")
        self.assertIn("note", response)
        ids = [r["id"] for r in response["data"]["rows"]]
        self.assertIn(800, ids)                          # the old row came back
        self.assertEqual(engine.counts()["activities"], before)   # not persisted
        self.assertNotIn(800, [r[0] for r in engine.con.execute(
            "SELECT id FROM activities")])

    def test_explicit_live_scope_is_honored(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, "query_activities", {"scope": "live"})
        self.assertEqual(response["source"], "live")

    def test_bad_scope_is_rejected(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, "query_activities", {"scope": "everything"})
        self.assertEqual(response["error"]["code"], "bad_param")

    def test_device_filter_accepts_id_or_name(self):
        bridge = self.make_bridge()
        r1 = self.roundtrip(bridge, "query_activities", {"device": "1"}, rid="x1")
        self.assertTrue(all(r["device_id"] == 1 for r in r1["data"]["rows"]))
        r2 = self.roundtrip(bridge, "query_activities", {"device": "Device 1"},
                            rid="x2")
        self.assertTrue(all(r["device_id"] == 1 for r in r2["data"]["rows"]))


class GetDeviceAndApiGet(ConnectorCase):
    def test_get_device_resolves_names_and_includes_detail(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, "get_device", {
            "device_id": 1, "include_alerts": True, "include_activities": True})
        data = response["data"]
        self.assertEqual(response["source"], "live")
        self.assertEqual(data["organization"], "Contoso")
        self.assertEqual(data["location"], "HQ")
        self.assertEqual(data["os"], "Windows 11 Pro")
        self.assertRegex(data["last_contact"], r"^\d{4}-\d{2}-\d{2}T")
        self.assertEqual(len(data["alerts"]), 1)
        self.assertEqual(len(data["activities"]), 1)

    def test_get_device_requires_a_positive_id(self):
        bridge = self.make_bridge()
        for bad in (0, -1):
            response = self.roundtrip(bridge, "get_device", {"device_id": bad},
                                      rid=f"d{abs(bad)}")
            self.assertEqual(response["error"]["code"], "bad_param")

    def test_api_get_passthrough_reaches_the_query_endpoints(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, "api_get", {
            "path": "/v2/queries/os-patches", "params": {"status": "PENDING"}})
        self.assertEqual(response["status"], "ok")
        self.assertEqual(response["source"], "live")
        self.assertEqual(response["data"]["echo"], "/v2/queries/os-patches")

    def test_api_get_rejects_non_scalar_params(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, "api_get", {
            "path": "/v2/devices", "params": {"df": ["a", "b"]}})
        self.assertEqual(response["error"]["code"], "bad_param")

    def test_api_get_path_validation_surfaces_as_an_error_response(self):
        """The choke point lives in nj_api; here we prove the bridge surfaces
        its rejection cleanly instead of crashing. Uses a real client."""
        from tests.base import make_client
        engine = self.make_engine()
        engine._client = make_client()
        bridge = self.make_bridge(engine=engine)
        for path in ("/v1/admin", "/v2/../v1/admin", "https://evil.com/v2/x"):
            response = self.roundtrip(bridge, "api_get", {"path": path},
                                      rid="p" + str(abs(hash(path)) % 1000))
            self.assertEqual(response["status"], "error")


class Exports(ConnectorCase):
    def test_export_writes_csv_into_exports(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, "export", {
            "entity": "devices", "format": "csv", "filename": "offline_report"})
        self.assertEqual(response["status"], "ok")
        path = bridge.exchange.exports / "offline_report.csv"
        self.assertTrue(path.exists())
        self.assertIn("Contoso", path.read_text())

    def test_export_writes_json(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, "export", {
            "entity": "alerts", "format": "json", "filename": "alerts_now"})
        path = bridge.exchange.exports / "alerts_now.json"
        self.assertTrue(path.exists())
        self.assertIsInstance(json.loads(path.read_text()), list)

    def test_export_filename_traversal_is_rejected(self):
        """Acceptance test 11."""
        bridge = self.make_bridge()
        for name in ("../escape", "../../etc/passwd", "/tmp/absolute",
                     ".hidden", "sub/dir", "back\\slash", "..", "a" * 200):
            response = self.roundtrip(bridge, "export", {
                "entity": "devices", "format": "csv", "filename": name},
                rid="e" + str(abs(hash(name)) % 10000))
            self.assertEqual(response["status"], "error", name)
            self.assertIn(response["error"]["code"],
                          ("bad_filename", "path_rejected"))
        # Nothing escaped the exchange root.
        self.assertFalse((self.tmp / "escape.csv").exists())

    def test_export_rejects_unknown_entity_and_format(self):
        bridge = self.make_bridge()
        r1 = self.roundtrip(bridge, "export", {
            "entity": "secrets", "format": "csv", "filename": "x"}, rid="q1")
        self.assertEqual(r1["error"]["code"], "bad_param")
        r2 = self.roundtrip(bridge, "export", {
            "entity": "devices", "format": "exe", "filename": "x"}, rid="q2")
        self.assertEqual(r2["error"]["code"], "bad_param")

    def test_export_query_params_are_validated_against_the_entity(self):
        bridge = self.make_bridge()
        response = self.roundtrip(bridge, "export", {
            "entity": "devices", "format": "csv", "filename": "x",
            "query": {"activity_type": "CONDITION"}})
        self.assertEqual(response["error"]["code"], "unknown_params")


class SyncNow(ConnectorCase):
    def test_sync_now_rebuilds_when_cleared(self):
        bridge = self.make_bridge()
        bridge.engine.morning_reset()
        response = self.roundtrip(bridge, "sync_now")
        self.assertEqual(response["status"], "ok")
        self.assertTrue(response["rebuilt"])
        self.assertEqual(response["data"]["state"], "ready")

    def test_query_after_reset_reports_rebuilt_and_synced(self):
        bridge = self.make_bridge()
        bridge.engine.morning_reset()
        response = self.roundtrip(bridge, "query_devices")
        self.assertTrue(response["rebuilt"])
        self.assertTrue(response["synced"])


class FutureMtimeTest(ConnectorCase):
    """A future mtime on a request file (attacker-controlled) must not become
    a years-long sleep while the bridge holds its locks."""

    def test_future_mtime_sleep_is_clamped(self):
        from unittest import mock
        bridge = self.make_bridge(client=FakeClient())
        path = self.write_request(bridge, "status", rid="fut")
        os.utime(path, (4102444800, 4102444800))
        slept = []
        with mock.patch("nj_bridge.time.sleep", side_effect=slept.append):
            bridge.drain()
        self.assertTrue(slept)
        self.assertLessEqual(max(slept), 1.0)
        self.assertEqual(self.read_response(bridge, "fut")["status"], "ok")


if __name__ == "__main__":
    unittest.main()


class ReplyCorrelationTest(ConnectorCase):
    """Regression: a reply must land at the filename the caller polls.

    A regression here is silent: the caller simply never finds its reply.
"""

    def _exchange(self):
        from nj_common import Exchange
        return Exchange(self.cfg)

    def test_body_id_must_match_the_filename(self):
        bridge = self.make_bridge()
        ex = self._exchange()
        (ex.requests / "request-abc.json").write_text(
            json.dumps({"id": "xyz", "action": "status", "params": {}}))
        bridge.drain()
        polled = ex.responses / "response-abc.json"
        self.assertTrue(polled.exists(), "reply must use the polled filename")
        self.assertFalse((ex.responses / "response-xyz.json").exists())
        self.assertEqual(json.loads(polled.read_text())["error"]["code"],
                         "id_mismatch")

    def test_dotted_id_is_accepted_and_correlatable(self):
        bridge = self.make_bridge()
        ex = self._exchange()
        rid = "rpt.status.1"
        (ex.requests / f"request-{rid}.json").write_text(
            json.dumps({"id": rid, "action": "status", "params": {}}))
        bridge.drain()
        polled = ex.responses / f"response-{rid}.json"
        self.assertTrue(polled.exists())
        self.assertEqual(json.loads(polled.read_text())["status"], "ok")

    def test_malformed_json_reply_is_still_correlatable(self):
        bridge = self.make_bridge()
        ex = self._exchange()
        rid = "rpt.bad.1"
        (ex.requests / f"request-{rid}.json").write_text("{not json")
        bridge.drain()
        self.assertTrue((ex.responses / f"response-{rid}.json").exists())

    def test_traversal_and_leading_dot_ids_are_refused(self):
        from nj_bridge import ID_RE
        for bad in ("../escape", "..", ".hidden", "a/b", "has space", ""):
            self.assertFalse(bool(ID_RE.fullmatch(bad)) and ".." not in bad, bad)

    def test_symlinked_request_is_not_followed_on_read(self):
        bridge = self.make_bridge()
        ex = self._exchange()
        secret = self.tmp / "outside.json"
        secret.write_text(json.dumps({"id": "s", "action": "status", "params": {}}))
        link = ex.requests / "request-s.json"
        try:
            os.symlink(secret, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        bridge.drain()
        response = json.loads((ex.responses / "response-s.json").read_text())
        self.assertEqual(response["status"], "error")
        self.assertIn(response["error"]["code"], ("symlink_rejected", "unreadable"))
