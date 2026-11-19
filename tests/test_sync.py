"""Sync engine: reconciliation, retention, and the daily lifecycle.
Acceptance tests 5 (reconciliation), 6 (retention), 7 (reset/rebuild/staleness).
"""

import json
import unittest
from datetime import timedelta

from tests.base import (ConnectorCase, FakeClient, make_activity, make_alert,
                        make_device)

from nj_common import iso, today_str, utc_now


class InventoryReconciliation(ConnectorCase):
    def test_devices_orgs_and_locations_are_ingested(self):
        engine = self.make_engine()
        counts = engine.counts()
        self.assertEqual(counts["devices"], 3)
        self.assertEqual(counts["organizations"], 2)
        self.assertEqual(counts["locations"], 2)
        self.assertEqual(counts["devices_offline"], 1)

    def test_vanished_devices_are_removed_by_full_set_reconciliation(self):
        client = FakeClient()
        engine = self.make_engine(client=client)
        self.assertEqual(engine.counts()["devices"], 3)
        client.devices = [d for d in client.devices if d["id"] != 2]
        engine.sync_inventory()
        remaining = [r[0] for r in engine.con.execute("SELECT id FROM devices")]
        self.assertEqual(sorted(remaining), [1, 3])

    def test_vanished_organizations_are_removed(self):
        client = FakeClient()
        engine = self.make_engine(client=client)
        client.orgs = [{"id": 10, "name": "Contoso"}]
        engine.sync_inventory()
        self.assertEqual([r[0] for r in engine.con.execute(
            "SELECT id FROM organizations")], [10])

    def test_an_empty_walk_is_treated_as_a_failed_fetch_not_a_mass_delete(self):
        """Guard: a transient API hiccup returning [] must never wipe the cache."""
        client = FakeClient()
        engine = self.make_engine(client=client)
        client.devices = []
        client.orgs = []
        client.locs = []
        engine.sync_inventory()
        self.assertEqual(engine.counts()["devices"], 3)
        self.assertEqual(engine.counts()["organizations"], 2)

    def test_reconciliation_scales_past_the_sqlite_parameter_limit(self):
        """A real MSP fleet is thousands of devices. An inline IN (...) list
        would blow SQLite's bound-parameter cap (999 on older builds), so
        reconciliation goes through a temp table."""
        big = [make_device(i) for i in range(1, 2600)]
        client = FakeClient(devices=big)
        engine = self.make_engine(client=client, ready=False)
        engine.sync_inventory()
        self.assertEqual(engine.counts()["devices"], 2599)
        client.devices = big[:1200]
        engine.sync_inventory()
        self.assertEqual(engine.counts()["devices"], 1200)
        surviving = {r[0] for r in engine.con.execute("SELECT id FROM devices")}
        self.assertEqual(surviving, set(range(1, 1201)))

    def test_inventory_syncs_from_the_detailed_endpoint(self):
        """/v2/devices omits os, boot time, and IP — all of which are columns
        and documented filters. Inventory must use /v2/devices-detailed."""
        client = FakeClient()
        engine = self.make_engine(client=client, ready=False)
        engine.sync_inventory()
        detailed_flags = [c[2] for c in client.calls if c[0] == "iter_devices"]
        self.assertTrue(detailed_flags and all(detailed_flags))

    def test_detailed_payload_populates_os_boot_and_ip(self):
        engine = self.make_engine()
        row = engine.con.execute(
            "SELECT os_name, last_boot, ip FROM devices WHERE id=1").fetchone()
        self.assertEqual(row["os_name"], "Windows 11 Pro")
        self.assertRegex(row["last_boot"], r"^\d{4}-\d{2}-\d{2}T")
        self.assertEqual(row["ip"], "203.0.113.7")

    def test_nested_last_boot_time_is_read_from_the_os_object(self):
        """NinjaOne nests lastBootTime inside os; a top-level-only lookup
        silently yields null for every device in the fleet."""
        from nj_sync import device_row
        nested = make_device(1)
        self.assertIsNotNone(device_row(nested)[10])
        # A top-level lastBootTime (older shape) still works.
        flat = make_device(2, os="Ubuntu 22.04")
        flat["lastBootTime"] = flat.pop("os") and 1_700_000_000
        flat["os"] = "Ubuntu 22.04"
        self.assertIsNotNone(device_row(flat)[10])

    def test_lean_payload_degrades_gracefully(self):
        """If a tenant only serves the lean shape, ingest must still succeed —
        with nulls, not an exception."""
        from tests.base import make_lean_device
        engine = self.make_engine(client=FakeClient(
            devices=[make_lean_device(1)]), ready=False)
        engine.sync_inventory()
        row = engine.con.execute("SELECT * FROM devices WHERE id=1").fetchone()
        self.assertEqual(row["system_name"], "HOST-1")
        self.assertIsNone(row["os_name"])
        self.assertIsNone(row["last_boot"])

    def test_ip_falls_back_to_the_first_address_when_public_ip_is_absent(self):
        device = make_device(1)
        device.pop("publicIP")
        engine = self.make_engine(client=FakeClient(devices=[device]),
                                  ready=False)
        engine.sync_inventory()
        self.assertEqual(engine.con.execute(
            "SELECT ip FROM devices WHERE id=1").fetchone()[0], "172.20.0.5")

    def test_millisecond_epochs_are_rescaled_not_discarded(self):
        from nj_common import epoch_to_iso
        seconds = 1_700_000_000
        self.assertEqual(epoch_to_iso(seconds), epoch_to_iso(seconds * 1000))
        self.assertIsNone(epoch_to_iso(0))
        self.assertIsNone(epoch_to_iso(None))
        self.assertIsNone(epoch_to_iso("not a timestamp"))

    def test_epoch_timestamps_are_normalized_to_iso(self):
        engine = self.make_engine()
        row = engine.con.execute(
            "SELECT last_contact, last_boot, raw_json FROM devices WHERE id=1").fetchone()
        self.assertRegex(row["last_contact"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertRegex(row["last_boot"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        # The untouched original payload is kept alongside.
        self.assertIsInstance(json.loads(row["raw_json"])["lastContact"], float)

    def test_missing_and_odd_fields_do_not_break_ingest(self):
        odd = {"id": 42, "organizationId": 10, "displayName": None,
               "os": "Ubuntu 22.04", "lastContact": None, "offline": None}
        engine = self.make_engine(client=FakeClient(devices=[odd]))
        row = engine.con.execute("SELECT * FROM devices WHERE id=42").fetchone()
        self.assertEqual(row["os_name"], "Ubuntu 22.04")
        self.assertIsNone(row["last_contact"])
        self.assertEqual(row["offline"], 0)


class AlertsAndActivities(ConnectorCase):
    def test_alerts_are_replaced_wholesale_each_sync(self):
        client = FakeClient()
        engine = self.make_engine(client=client)
        self.assertEqual(engine.counts()["alerts"], 2)
        client.alert_rows = [make_alert("a3", device_id=1)]
        engine.sync_alerts()
        uids = [r[0] for r in engine.con.execute("SELECT uid FROM alerts")]
        self.assertEqual(uids, ["a3"])

    def test_cold_start_walks_backward_and_stops_at_the_retention_cutoff(self):
        client = FakeClient(activities=[
            make_activity(900, minutes_ago=5),
            make_activity(899, minutes_ago=60),
            make_activity(898, days_ago=3),      # outside the 1-day window
            make_activity(897, days_ago=9),
        ])
        engine = self.make_engine(client=client, ready=False)
        engine.sync_activities()
        ids = sorted(r[0] for r in engine.con.execute("SELECT id FROM activities"))
        self.assertEqual(ids, [899, 900])
        self.assertIn(("iter_activities_older", None), client.calls)

    def test_delta_walk_uses_the_forward_cursor(self):
        client = FakeClient(activities=[make_activity(900), make_activity(901)])
        engine = self.make_engine(client=client, ready=False)
        engine.sync_activities()
        self.assertEqual(engine.get_state("activity_cursor"), "901")
        client.activity_rows.append(make_activity(902))
        client.calls.clear()
        engine.sync_activities()
        self.assertIn(("iter_activities", 901), client.calls)
        ids = sorted(r[0] for r in engine.con.execute("SELECT id FROM activities"))
        self.assertEqual(ids, [900, 901, 902])

    def test_repeated_syncs_do_not_duplicate_activities(self):
        engine = self.make_engine()
        before = engine.counts()["activities"]
        engine.sync_activities()
        engine.sync_activities()
        self.assertEqual(engine.counts()["activities"], before)

    def test_prune_enforces_the_retention_window(self):
        client = FakeClient(activities=[
            make_activity(1, minutes_ago=5), make_activity(2, days_ago=5)])
        engine = self.make_engine(client=client, ready=False)
        # Force both rows in, bypassing the cold-start cutoff, then prune.
        for activity in client.activity_rows:
            from nj_sync import activity_row
            engine.con.execute(
                "INSERT OR REPLACE INTO activities VALUES(?,?,?,?,?,?,?)",
                activity_row(activity))
        engine.con.commit()
        self.assertEqual(engine.counts()["activities"], 2)
        pruned = engine.prune()
        self.assertEqual(pruned, 1)
        self.assertEqual([r[0] for r in engine.con.execute(
            "SELECT id FROM activities")], [1])


class DailyLifecycle(ConnectorCase):
    def test_morning_reset_clears_windowed_data_but_keeps_inventory(self):
        engine = self.make_engine()
        self.assertTrue(engine.morning_reset())
        counts = engine.counts()
        self.assertEqual(counts["alerts"], 0)
        self.assertEqual(counts["activities"], 0)
        self.assertEqual(counts["devices"], 3)          # current-state, persists
        self.assertEqual(engine.get_state("state"), "cleared")
        self.assertEqual(engine.get_state("inventory_stale"), "1")

    def test_morning_reset_is_idempotent_within_a_day(self):
        engine = self.make_engine()
        self.assertTrue(engine.morning_reset())
        self.assertFalse(engine.morning_reset())
        self.assertFalse(engine.morning_reset())

    def test_morning_reset_publishes_a_cleared_manifest(self):
        engine = self.make_engine()
        engine.morning_reset()
        manifest = json.loads(engine.exchange.manifest.read_text())
        self.assertEqual(manifest["state"], "cleared")
        self.assertEqual(manifest["counts"]["activities"], 0)
        self.assertTrue(manifest["inventory_stale"])

    def test_interval_sync_is_a_no_op_while_cleared(self):
        client = FakeClient()
        engine = self.make_engine(client=client)
        engine.morning_reset()
        client.calls.clear()
        self.assertIsNone(engine.interval_sync())
        self.assertEqual(client.calls, [])

    def test_lazy_rebuild_happens_on_first_use(self):
        engine = self.make_engine()
        engine.morning_reset()
        self.assertEqual(engine.get_state("state"), "cleared")
        self.assertTrue(engine.ensure_fresh())          # rebuild ran
        self.assertEqual(engine.get_state("state"), "ready")
        self.assertEqual(engine.get_state("inventory_stale"), "0")
        self.assertGreater(engine.counts()["activities"], 0)
        self.assertFalse(engine.ensure_fresh())         # second call is a no-op

    def test_rebuild_is_forced_when_the_last_one_was_a_previous_day(self):
        engine = self.make_engine()
        engine.set_state("last_backfill_date", "2000-01-01")
        self.assertTrue(engine.ensure_fresh())
        self.assertEqual(engine.get_state("last_backfill_date"), today_str())

    def test_refresh_if_stale_respects_the_staleness_budget(self):
        client = FakeClient()
        engine = self.make_engine(client=client)
        engine.set_state("last_sync", iso(utc_now()))
        client.calls.clear()
        self.assertFalse(engine.refresh_if_stale())     # fresh — no API traffic
        self.assertEqual(client.calls, [])
        engine.set_state("last_sync", iso(utc_now() - timedelta(minutes=45)))
        self.assertTrue(engine.refresh_if_stale())      # stale — syncs
        self.assertTrue(client.calls)

    def test_refresh_if_stale_never_runs_while_cleared(self):
        engine = self.make_engine()
        engine.morning_reset()
        engine.set_state("last_sync", iso(utc_now() - timedelta(days=2)))
        self.assertFalse(engine.refresh_if_stale())


class Publishing(ConnectorCase):
    def test_snapshot_manifest_and_csv_are_published(self):
        engine = self.make_engine()
        engine.publish()
        self.assertTrue(engine.exchange.snapshot.exists())
        self.assertTrue(engine.exchange.manifest.exists())
        self.assertTrue(engine.exchange.summary_csv.exists())
        csv_text = engine.exchange.summary_csv.read_text()
        self.assertIn("Contoso", csv_text)
        self.assertIn("Device 1", csv_text)
        self.assertIn("device_id,display_name", csv_text)

    def test_snapshot_is_queryable_and_carries_the_join_tables(self):
        import sqlite3
        engine = self.make_engine()
        engine.publish()
        con = sqlite3.connect(engine.exchange.snapshot)
        rows = con.execute(
            "SELECT d.display_name, o.name FROM devices d "
            "LEFT JOIN organizations o ON o.id = d.org_id ORDER BY d.id").fetchall()
        con.close()
        self.assertEqual(rows[0], ("Device 1", "Contoso"))

    def test_manifest_reports_size_warning_over_the_cap(self):
        engine = self.make_engine()
        engine.cfg = dict(self.cfg, max_db_mb=0)
        self.assertTrue(engine.manifest()["size_warning"])

    def test_manifest_counts_and_oldest_activity(self):
        engine = self.make_engine()
        manifest = engine.manifest()
        self.assertEqual(manifest["counts"]["devices"], 3)
        self.assertEqual(manifest["counts"]["alerts"], 2)
        self.assertIsNotNone(manifest["oldest_retained_activity"])
        self.assertEqual(manifest["retention_days"], 1)

    def test_publish_replaces_a_planted_symlink_rather_than_writing_through_it(self):
        engine = self.make_engine()
        engine.exchange.ensure_dirs()
        victim = self.tmp / "outside.txt"
        victim.write_text("untouched")
        engine.exchange.manifest.parent.mkdir(parents=True, exist_ok=True)
        if engine.exchange.manifest.exists():
            engine.exchange.manifest.unlink()
        engine.exchange.manifest.symlink_to(victim)
        engine.publish()
        self.assertEqual(victim.read_text(), "untouched")
        self.assertFalse(engine.exchange.manifest.is_symlink())


if __name__ == "__main__":
    unittest.main()


class RepublishIfMissingTest(ConnectorCase):
    """Regression: freshness state lives in the database, so deleting the
    published manifest or snapshot used to leave a 'ready' cache with nothing
    for a consumer to read, and no path that ever rewrote them."""

    def test_missing_manifest_is_republished_without_api_calls(self):
        from nj_common import Exchange
        engine = self.make_engine()
        engine.publish()
        ex = Exchange(self.cfg)
        self.assertTrue(ex.manifest.exists())
        ex.manifest.unlink()
        ex.snapshot.unlink()
        engine.client.calls = []
        self.assertFalse(engine.ensure_fresh(), "should not trigger a rebuild")
        self.assertTrue(ex.manifest.exists(), "manifest must be republished")
        self.assertTrue(ex.snapshot.exists(), "snapshot must be republished")
        self.assertEqual(engine.client.calls, [], "republish must not hit the API")

    def test_no_op_when_artifacts_are_present(self):
        engine = self.make_engine()
        engine.publish()
        self.assertFalse(engine.republish_if_missing())
