"""Acceptance test 13: malicious tenant content flows through sync, query, and
export as inert literal data, and never reaches a filename, a request id,
response metadata, or executed SQL.
"""

import json
import sqlite3
import unittest

from tests.base import ConnectorCase, FakeClient
from tests.fixtures import (ALL_PAYLOADS, API_GET_STEERING_STRINGS,
                            EGRESS_URLS, PROMPT_INJECTION_STRINGS,
                            SQL_INJECTION_STRINGS, malicious_activity,
                            malicious_alert, malicious_device,
                            malicious_location, malicious_org)


def poisoned_client():
    """A tenant where every name and message is an attack payload."""
    devices = [malicious_device(i + 1, payload)
               for i, payload in enumerate(ALL_PAYLOADS)]
    orgs = [{"id": 10, "name": "Contoso"}]
    orgs += [malicious_org(100 + i, payload)
             for i, payload in enumerate(SQL_INJECTION_STRINGS)]
    locations = [malicious_location(200 + i, payload)
                 for i, payload in enumerate(PROMPT_INJECTION_STRINGS)]
    locations.append({"id": 100, "organizationId": 10, "name": "HQ"})
    alerts = [malicious_alert(f"alert-{i}", payload, device_id=1)
              for i, payload in enumerate(ALL_PAYLOADS)]
    activities = [malicious_activity(1000 + i, payload, device_id=1)
                  for i, payload in enumerate(ALL_PAYLOADS)]
    return FakeClient(devices=devices, orgs=orgs, locations=locations,
                      alerts=alerts, activities=activities)


class PayloadsSurviveIngestAsData(ConnectorCase):
    def setUp(self):
        super().setUp()
        self.client = poisoned_client()
        self.engine = self.make_engine(client=self.client)

    def test_the_tables_still_exist_and_are_fully_populated(self):
        """If any payload had executed as SQL, a table would be gone or short."""
        counts = self.engine.counts()
        self.assertEqual(counts["devices"], len(ALL_PAYLOADS))
        self.assertEqual(counts["alerts"], len(ALL_PAYLOADS))
        self.assertEqual(counts["activities"], len(ALL_PAYLOADS))
        tables = {r[0] for r in self.engine.con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for expected in ("devices", "organizations", "locations", "alerts",
                         "activities", "sync_state"):
            self.assertIn(expected, tables)

    def test_payloads_are_stored_verbatim(self):
        stored = {r[0] for r in self.engine.con.execute(
            "SELECT display_name FROM devices")}
        for payload in ALL_PAYLOADS:
            self.assertIn(payload, stored)

    def test_offline_devices_still_counted_correctly(self):
        """`'; UPDATE devices SET offline=0;--` must not have run."""
        self.assertEqual(self.engine.counts()["devices_offline"], len(ALL_PAYLOADS))

    def test_sync_state_is_untouched_by_payloads(self):
        self.assertEqual(self.engine.get_state("state"), "ready")
        self.assertIsNotNone(self.engine.get_state("activity_cursor"))


class PayloadsAreInertThroughTheBridge(ConnectorCase):
    def setUp(self):
        super().setUp()
        self.client = poisoned_client()
        self.engine = self.make_engine(client=self.client)
        self.bridge = self.make_bridge(engine=self.engine)

    def test_sql_payloads_as_filter_values_are_parameterized(self):
        """Every string param, fed the full SQL-injection corpus."""
        cases = [
            ("query_devices", "text_contains"),
            ("query_devices", "os_contains"),
            ("query_devices", "node_class"),
            ("query_devices", "location"),
            ("query_alerts", "source_type"),
            ("query_alerts", "severity"),
            ("query_activities", "activity_type"),
            ("query_activities", "status"),
            ("query_activities", "text_contains"),
        ]
        for action, param in cases:
            for index, payload in enumerate(SQL_INJECTION_STRINGS):
                with self.subTest(action=action, param=param, payload=payload):
                    response = self.roundtrip(
                        self.bridge, action, {param: payload},
                        rid=f"{param}{index}")
                    self.assertIn(response["status"], ("ok", "error"))
                    if response["status"] == "error":
                        # Only ever a clean validation error, never a SQL error.
                        self.assertNotIn("syntax", response["error"]["message"].lower())
        # The database survived every one of them.
        self.assertEqual(self.engine.counts()["devices"], len(ALL_PAYLOADS))

    def test_org_and_device_name_lookups_are_parameterized(self):
        for index, payload in enumerate(SQL_INJECTION_STRINGS):
            response = self.roundtrip(self.bridge, "query_devices",
                                      {"org": payload}, rid=f"org{index}")
            # Either it resolves to the poisoned org, or it is a clean
            # unknown_org — never a SQL error, never a dropped table.
            self.assertIn(response["status"], ("ok", "error"))
            if response["status"] == "error":
                self.assertEqual(response["error"]["code"], "unknown_org")
        self.assertEqual(self.engine.counts()["devices"], len(ALL_PAYLOADS))

    def test_payload_named_org_actually_resolves_to_its_devices(self):
        """Parameterization must not break legitimate lookups of odd names."""
        payload = SQL_INJECTION_STRINGS[0]
        self.engine.con.execute(
            "UPDATE devices SET org_id=100 WHERE id=1")
        self.engine.con.commit()
        response = self.roundtrip(self.bridge, "query_devices", {"org": payload})
        self.assertEqual(response["status"], "ok")
        self.assertEqual([r["id"] for r in response["data"]["rows"]], [1])

    def test_like_wildcards_in_payloads_are_escaped_not_expanded(self):
        response = self.roundtrip(self.bridge, "query_devices",
                                  {"text_contains": "%"})
        # A bare % must match the literal character, not every row.
        self.assertLess(len(response["data"]["rows"]), len(ALL_PAYLOADS))

    def test_api_get_steering_payloads_are_all_rejected(self):
        from tests.base import make_client
        self.engine._client = make_client()
        for index, path in enumerate(API_GET_STEERING_STRINGS):
            with self.subTest(path=path):
                response = self.roundtrip(self.bridge, "api_get", {"path": path},
                                          rid=f"steer{index}")
                self.assertEqual(response["status"], "error")

    def test_payloads_never_appear_in_response_metadata_or_filenames(self):
        """Content may appear inside data rows; it must never appear in the
        response envelope, the response filename, or any file we create."""
        response = self.roundtrip(self.bridge, "query_devices", {"limit": 5000},
                                  rid="meta")
        envelope = {k: v for k, v in response.items() if k != "data"}
        blob = json.dumps(envelope)
        for payload in ALL_PAYLOADS:
            self.assertNotIn(payload, blob)
        names = [p.name for p in self.bridge.exchange.responses.iterdir()]
        names += [p.name for p in self.bridge.exchange.processed.iterdir()]
        names += [p.name for p in self.bridge.exchange.exports.iterdir()]
        for name in names:
            for payload in ALL_PAYLOADS:
                self.assertNotIn(payload[:20], name)

    def test_egress_urls_are_returned_as_data_only(self):
        response = self.roundtrip(self.bridge, "query_alerts", {"limit": 5000})
        messages = [r["message"] for r in response["data"]["rows"]]
        for url in EGRESS_URLS:
            self.assertIn(url, messages)   # present as data
        # Nothing in the connector ever dereferences them: the only network
        # call made was the mocked client's alerts() fetch.
        self.assertNotIn("api_get", [c[0] for c in self.client.calls])


class PayloadsAreInertThroughExport(ConnectorCase):
    def setUp(self):
        super().setUp()
        self.engine = self.make_engine(client=poisoned_client())
        self.bridge = self.make_bridge(engine=self.engine)

    def test_export_writes_payloads_as_quoted_csv_cells(self):
        from nj_common import csv_cell
        response = self.roundtrip(self.bridge, "export", {
            "entity": "devices", "format": "csv", "filename": "poisoned"})
        self.assertEqual(response["status"], "ok")
        path = self.bridge.exchange.exports / "poisoned.csv"
        # CSV quoting keeps commas/quotes/newlines inside their cell; csv_cell
        # additionally strips control characters and defuses formulas.
        import csv
        rows = list(csv.DictReader(path.read_text().splitlines()))
        exported = {r["display_name"] for r in rows}
        for payload in ALL_PAYLOADS:
            self.assertIn(csv_cell(payload), exported)

    def test_csv_export_is_hardened_against_nul_and_formulas(self):
        """A NUL in a device name must not make the file unreadable, and a
        cell starting with '=' must not execute when opened in a spreadsheet."""
        from nj_common import csv_cell
        self.assertNotIn("\x00", csv_cell("/v2/devices\x00/v1/admin"))
        for leader in ("=", "+", "-", "@"):
            self.assertTrue(csv_cell(f"{leader}cmd|' /c calc'!A1").startswith("'"))
        self.assertEqual(csv_cell("Device 1"), "Device 1")   # ordinary text intact

    def test_export_json_round_trips_payloads_exactly(self):
        self.roundtrip(self.bridge, "export", {
            "entity": "activities", "format": "json", "filename": "acts"})
        path = self.bridge.exchange.exports / "acts.json"
        rows = json.loads(path.read_text())
        messages = {r["message"] for r in rows}
        for payload in ALL_PAYLOADS:
            self.assertIn(payload, messages)

    def test_nothing_was_written_outside_the_exchange_root(self):
        self.roundtrip(self.bridge, "export", {
            "entity": "devices", "format": "csv", "filename": "poisoned"})
        stray = [p for p in self.tmp.rglob("*")
                 if p.is_file() and not str(p).startswith(str(self.exchange_root))
                 and "approot" not in str(p)]
        self.assertEqual(stray, [])


class SnapshotIsSafeToQuery(ConnectorCase):
    def test_published_snapshot_holds_payloads_as_data(self):
        engine = self.make_engine(client=poisoned_client())
        engine.publish()
        con = sqlite3.connect(engine.exchange.snapshot)
        try:
            names = {r[0] for r in con.execute("SELECT display_name FROM devices")}
            tables = {r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            con.close()
        self.assertIn("devices", tables)
        for payload in ALL_PAYLOADS:
            self.assertIn(payload, names)

    def test_summary_csv_is_parseable_despite_payloads(self):
        import csv
        engine = self.make_engine(client=poisoned_client())
        engine.publish()
        rows = list(csv.DictReader(engine.exchange.summary_csv.read_text().splitlines()))
        self.assertEqual(len(rows), len(ALL_PAYLOADS))
        for row in rows:
            self.assertIn("offline", row)


if __name__ == "__main__":
    unittest.main()
