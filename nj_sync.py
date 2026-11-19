"""Sync engine: authoritative SQLite cache + published exchange snapshot.

Trust-boundary role: owns the private working database in the app root and is
the only writer of the exchange-root snapshot/manifest/CSV. The cache is a
one-day working set, not an archive.

Two entity classes with different sync semantics:

  * Snapshot entities (organizations, locations, devices) are current-state
    inventory: upserted whole on each sync, with full-set reconciliation so a
    device that vanished from the tenant is removed from the cache.
  * Windowed entities (alerts, activities) are time-bounded. /v2/alerts is
    itself current-state and is replaced wholesale; activities are cursor-
    walked forward with `newerThan` and pruned to the retention window.

There is no background timer. A login-triggered morning reset clears the
windowed data; the day's rebuild happens lazily via ensure_fresh() on first
real use; and each bridge request delta-syncs first when the cache is older
than the staleness budget.
"""

import csv
import io
import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timedelta

import nj_credstore
from nj_api import NjClient
from nj_common import (Exchange, SCHEMA_VERSION, atomic_write, csv_cell,
                       db_path, epoch_to_iso, iso, parse_iso, today_str,
                       utc_now, window_cutoff)

log = logging.getLogger("njc.sync")

MIGRATIONS = [
    # v1 — initial schema
    """
    CREATE TABLE organizations(
        id INTEGER PRIMARY KEY, name TEXT, raw_json TEXT);
    CREATE TABLE locations(
        id INTEGER PRIMARY KEY, org_id INTEGER, name TEXT, raw_json TEXT);
    CREATE INDEX ix_locations_org ON locations(org_id);
    CREATE TABLE devices(
        id INTEGER PRIMARY KEY, org_id INTEGER, location_id INTEGER,
        system_name TEXT, display_name TEXT, node_class TEXT, role TEXT,
        os_name TEXT, offline INTEGER, last_contact TEXT, last_boot TEXT,
        ip TEXT, raw_json TEXT);
    CREATE INDEX ix_devices_org ON devices(org_id);
    CREATE INDEX ix_devices_offline ON devices(offline);
    CREATE INDEX ix_devices_contact ON devices(last_contact);
    CREATE TABLE alerts(
        uid TEXT PRIMARY KEY, device_id INTEGER, message TEXT,
        source_type TEXT, created TEXT, raw_json TEXT);
    CREATE INDEX ix_alerts_device ON alerts(device_id);
    CREATE TABLE activities(
        id INTEGER PRIMARY KEY, device_id INTEGER, activity_time TEXT,
        activity_type TEXT, status_name TEXT, message TEXT, raw_json TEXT);
    CREATE INDEX ix_activities_time ON activities(activity_time);
    CREATE INDEX ix_activities_device ON activities(device_id);
    CREATE TABLE sync_state(key TEXT PRIMARY KEY, value TEXT);
    """,
]


def open_db(path=None):
    path = path or db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    if con.execute("PRAGMA auto_vacuum").fetchone()[0] != 2:
        con.execute("PRAGMA auto_vacuum=INCREMENTAL")
        con.execute("VACUUM")
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA journal_size_limit=4194304")
    con.execute("CREATE TABLE IF NOT EXISTS schema_migrations("
                "version INTEGER PRIMARY KEY, applied_at TEXT)")
    applied = {r[0] for r in con.execute("SELECT version FROM schema_migrations")}
    for version, script in enumerate(MIGRATIONS, start=1):
        if version not in applied:
            con.executescript(script)
            con.execute("INSERT INTO schema_migrations VALUES(?,?)",
                        (version, iso(utc_now())))
            con.commit()
    return con


def _first(mapping, *names):
    """NinjaOne field names vary a little across endpoints and versions; take
    the first present, non-empty value."""
    for name in names:
        if isinstance(mapping, dict) and mapping.get(name) not in (None, ""):
            return mapping[name]
    return None


def _text(value):
    """Coerce an arbitrary API value into a text column without ever executing
    or interpreting it. Structured values are stored as compact JSON."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return str(value)


def device_row(device):
    os_field = device.get("os")
    os_name = None
    last_boot = None
    if isinstance(os_field, dict):
        os_name = _first(os_field, "name", "displayName", "manufacturer")
        # NinjaOne nests lastBootTime INSIDE the os object on
        # /v2/devices-detailed; it is not a top-level device field.
        last_boot = _first(os_field, "lastBootTime", "lastBoot")
    elif isinstance(os_field, str):
        os_name = os_field
    if not os_name:
        os_name = _first(device, "osName", "operatingSystem")
    if last_boot is None:
        last_boot = _first(device, "lastBootTime", "lastBoot")

    ip = _first(device, "publicIP", "publicIp", "ipAddress")
    if not ip:
        addresses = device.get("ipAddresses")
        if isinstance(addresses, list) and addresses:
            ip = addresses[0]
    return (
        int(device["id"]),
        _first(device, "organizationId", "orgId"),
        _first(device, "locationId"),
        _text(_first(device, "systemName", "dnsName", "hostname")),
        _text(_first(device, "displayName", "systemName", "dnsName")),
        _text(_first(device, "nodeClass", "deviceClass")),
        _text(_first(device, "nodeRoleId", "role", "deviceRole")),
        _text(os_name),
        1 if device.get("offline") else 0,
        epoch_to_iso(_first(device, "lastContact", "lastSeen")),
        epoch_to_iso(last_boot),
        _text(ip),
        json.dumps(device, default=str),
    )


def alert_row(alert):
    uid = _first(alert, "uid", "id")
    message = _first(alert, "message", "subject")
    if message is None:
        data = alert.get("data")
        if isinstance(data, dict):
            message = _first(data, "message", "subject")
    return (
        _text(uid),
        _first(alert, "deviceId", "device_id"),
        _text(message),
        _text(_first(alert, "sourceType", "source_type", "severity")),
        epoch_to_iso(_first(alert, "createTime", "createdAt", "created")),
        json.dumps(alert, default=str),
    )


def activity_row(activity):
    return (
        int(activity["id"]),
        _first(activity, "deviceId", "device_id"),
        epoch_to_iso(_first(activity, "activityTime", "createTime", "time")),
        _text(_first(activity, "activityType", "type")),
        _text(_first(activity, "statusName", "status", "statusCode")),
        _text(_first(activity, "message", "subject", "description")),
        json.dumps(activity, default=str),
    )


class SyncEngine:
    def __init__(self, cfg, client=None, con=None):
        self.cfg = cfg
        self.exchange = Exchange(cfg)
        self.con = con or open_db()
        self._client = client

    @property
    def client(self):
        if self._client is None:
            client_id, client_secret = nj_credstore.get_credentials()
            self._client = NjClient(self.cfg["instance"], client_id, client_secret,
                                    token_path=self.cfg.get("token_path", "/ws/oauth/token"))
        return self._client

    # ------------------------------------------------------------ state kv

    def get_state(self, key, default=None):
        row = self.con.execute("SELECT value FROM sync_state WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set_state(self, key, value):
        self.con.execute("INSERT INTO sync_state(key,value) VALUES(?,?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                         (key, str(value)))
        self.con.commit()

    def window_start(self):
        return self.get_state("window_start") or window_cutoff(self.cfg["retention_days"])

    # -------------------------------------------------------- daily lifecycle

    def morning_reset(self):
        """Login-triggered clear. Idempotent per calendar day; never rebuilds —
        the first real use of the day triggers the backfill (ensure_fresh).

        Device/organization/location inventory is current-state, so it MAY
        survive the reset to keep the snapshot answerable; it is marked stale
        and the first rebuild refreshes it."""
        today = today_str()
        if self.get_state("last_reset_date") == today:
            log.info("morning reset: already done today; no-op")
            return False
        self.con.execute("DELETE FROM alerts")
        self.con.execute("DELETE FROM activities")
        self.con.commit()
        self.con.execute("VACUUM")
        window = window_cutoff(self.cfg["retention_days"])
        self.set_state("activity_cursor", "")
        self.set_state("window_start", window)
        self.set_state("state", "cleared")
        self.set_state("inventory_stale", "1")
        self.set_state("last_reset_date", today)
        self.publish()
        self._sweep_exports(morning=True)
        log.info("morning reset: alerts/activities cleared; window starts %s", window)
        return True

    def republish_if_missing(self):
        """Re-publish when the exchange artifacts have gone missing.

        Freshness state lives in the working database, not in the exchange
        folder, so if the published manifest or snapshot is deleted (the folder
        recreated, a file-sync client reaping it, a user clearing it) the engine
        still believes it is "ready" and nothing ever rewrites them. Consumers
        are told to read the manifest first, so they hit a missing file and
        cannot even tell that the data is stale. Re-publishing is cheap: it
        copies the existing database out, with no API calls.
        """
        missing = [str(p) for p in (self.exchange.manifest, self.exchange.snapshot)
                   if not p.exists()]
        if not missing:
            return False
        log.warning("republishing: exchange artifacts missing (%s)",
                    ", ".join(missing))
        self.publish()
        return True

    def ensure_fresh(self):
        """Called before serving any cache-backed request. Rebuilds the day's
        working set synchronously if the cache was cleared (or the last
        rebuild is from a previous day). Returns True when a rebuild ran."""
        if (self.get_state("state") == "ready"
                and self.get_state("last_backfill_date") == today_str()):
            self.republish_if_missing()
            return False
        window = window_cutoff(self.cfg["retention_days"])
        self.con.execute("DELETE FROM activities")
        self.con.commit()
        self.set_state("window_start", window)
        self.set_state("activity_cursor", "")
        log.info("rebuild: refreshing inventory and backfilling window since %s", window)
        self.sync_inventory()
        self.sync_alerts()
        self.sync_activities()
        self.prune()
        self.set_state("state", "ready")
        self.set_state("inventory_stale", "0")
        self.set_state("last_backfill_date", today_str())
        self.set_state("last_sync", iso(utc_now()))
        self.publish()
        return True

    def refresh_if_stale(self, max_age_minutes=None):
        """On-demand freshness (no background timer): delta-sync only when a
        request is actually being served and the cache is older than the
        staleness budget (config sync_interval_minutes). Returns True if a
        sync ran."""
        if self.get_state("state") != "ready":
            return False
        max_age = int(max_age_minutes if max_age_minutes is not None
                      else self.cfg.get("sync_interval_minutes", 15))
        last = self.get_state("last_sync")
        if last and (utc_now() - parse_iso(last)) < timedelta(minutes=max_age):
            return False
        self.interval_sync(force=True)
        return True

    # --------------------------------------------------------------- syncing

    def sync_inventory(self):
        """Snapshot entities: organizations, locations, devices. Upserted whole,
        then reconciled — anything not seen in this full walk is deleted, which
        is how device removals propagate."""
        orgs = self.client.organizations()
        self.con.executemany(
            "INSERT OR REPLACE INTO organizations(id,name,raw_json) VALUES(?,?,?)",
            [(int(o["id"]), _text(_first(o, "name", "displayName")),
              json.dumps(o, default=str)) for o in orgs if o.get("id") is not None])
        org_ids = [int(o["id"]) for o in orgs if o.get("id") is not None]
        self._reconcile("organizations", org_ids)

        locations = self.client.locations()
        self.con.executemany(
            "INSERT OR REPLACE INTO locations(id,org_id,name,raw_json) VALUES(?,?,?,?)",
            [(int(loc["id"]), _first(loc, "organizationId", "orgId"),
              _text(_first(loc, "name", "displayName")), json.dumps(loc, default=str))
             for loc in locations if loc.get("id") is not None])
        self._reconcile("locations",
                        [int(loc["id"]) for loc in locations if loc.get("id") is not None])

        seen = []
        count = 0
        # /v2/devices is a lean payload: no OS, no boot time, no IP addresses.
        # Every one of those is a column in our schema and a documented filter
        # (os_contains, and the skill's "how many Windows servers" example), so
        # inventory syncs from /v2/devices-detailed. Same `after` cursor, same
        # pagination semantics.
        for device in self.client.iter_devices(detailed=True):
            if device.get("id") is None:
                continue
            self.con.execute(
                """INSERT OR REPLACE INTO devices(id, org_id, location_id, system_name,
                     display_name, node_class, role, os_name, offline, last_contact,
                     last_boot, ip, raw_json)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""", device_row(device))
            seen.append(int(device["id"]))
            count += 1
            if count % 1000 == 0:
                self.con.commit()
                log.info("device sync progress: %d", count)
        self.con.commit()
        removed = self._reconcile("devices", seen)
        log.info("inventory sync: %d orgs, %d locations, %d devices (%d removed)",
                 len(orgs), len(locations), count, removed)
        return count

    def _reconcile(self, table, seen_ids):
        """Delete rows whose id was absent from the latest full walk. Guarded:
        an empty walk is treated as a failed fetch, never as 'everything was
        deleted upstream'.

        The id set goes through a temp table rather than an inline IN (...)
        list: SQLite caps bound parameters per statement (999 on the SQLite
        that ships with older Pythons), and an MSP tenant can easily hold
        several thousand devices — an inline list would raise OperationalError
        on exactly the fleets this connector is built for.
        """
        if not seen_ids:
            self.con.commit()
            return 0
        self.con.execute("CREATE TEMP TABLE IF NOT EXISTS reconcile_ids(id INTEGER PRIMARY KEY)")
        self.con.execute("DELETE FROM reconcile_ids")
        self.con.executemany("INSERT OR IGNORE INTO reconcile_ids(id) VALUES(?)",
                             ((i,) for i in seen_ids))
        removed = self.con.execute(
            f"DELETE FROM {table} WHERE id NOT IN (SELECT id FROM reconcile_ids)").rowcount
        self.con.execute("DELETE FROM reconcile_ids")
        self.con.commit()
        return removed

    def sync_alerts(self):
        """/v2/alerts is current-state (triggered conditions right now, no
        history), so the table is replaced wholesale each sync."""
        alerts = self.client.alerts()
        rows = [alert_row(a) for a in alerts if _first(a, "uid", "id") is not None]
        self.con.execute("DELETE FROM alerts")
        self.con.executemany(
            "INSERT OR REPLACE INTO alerts(uid,device_id,message,source_type,created,"
            "raw_json) VALUES(?,?,?,?,?,?)", rows)
        self.con.commit()
        log.info("alert sync: %d current alerts", len(rows))
        return len(rows)

    def sync_activities(self):
        """Ingest the audit stream, bounded by the retention window.

        Two directions, because an id cursor only walks one way:

          * Cold start (no cursor — a cleared cache or a fresh install): walk
            BACKWARD from the present with `olderThan` and stop at the
            retention cutoff. Forward-walking from nothing would only ever
            reach the single newest page.
          * Delta (cursor present): walk FORWARD with `newerThan`, which picks
            up exactly what has happened since the last sync.
        """
        cursor = self.get_state("activity_cursor") or ""
        newer_than = int(cursor) if str(cursor).isdigit() else None
        cutoff = window_cutoff(self.cfg["retention_days"])
        highest = newer_than or 0
        count = 0

        if newer_than is None:
            stream = self.client.iter_activities_older()
            backward = True
        else:
            stream = self.client.iter_activities(newer_than=newer_than)
            backward = False

        for activity in stream:
            if activity.get("id") is None:
                continue
            row = activity_row(activity)
            if backward and row[2] and row[2] < cutoff:
                # Newest-first walk: everything beyond here is older still.
                break
            self.con.execute(
                """INSERT OR REPLACE INTO activities(id, device_id, activity_time,
                     activity_type, status_name, message, raw_json)
                   VALUES(?,?,?,?,?,?,?)""", row)
            try:
                highest = max(highest, int(activity["id"]))
            except (TypeError, ValueError):
                pass
            count += 1
            if count % 1000 == 0:
                self.con.commit()
        self.con.commit()
        if highest:
            self.set_state("activity_cursor", highest)
        log.info("activity sync: %d activities ingested %s (cursor %s)", count,
                 "backward to the retention cutoff" if backward else "forward", highest)
        return count

    def interval_sync(self, force=False):
        """Delta sync. NO-OPs while the cache is cleared — a delta run keeps a
        built working set fresh, it never initiates the day's rebuild."""
        if self.get_state("state") != "ready" and not force:
            log.info("interval sync: cache state is cleared; waiting for first use (no-op)")
            return None
        self.sync_inventory()
        self.set_state("inventory_stale", "0")
        self.sync_alerts()
        self.sync_activities()
        self.prune()
        self.set_state("last_sync", iso(utc_now()))
        self.publish()
        return self.manifest()

    def prune(self):
        cutoff = window_cutoff(self.cfg["retention_days"])
        pruned = self.con.execute(
            "DELETE FROM activities WHERE activity_time IS NOT NULL AND activity_time < ?",
            (cutoff,)).rowcount
        self.con.commit()
        self.con.execute("PRAGMA incremental_vacuum")
        self.set_state("window_start", cutoff)
        if pruned:
            log.info("pruned %d activities older than %s", pruned, cutoff)
        return pruned

    # ------------------------------------------------------------- publishing

    def counts(self):
        def one(sql):
            return self.con.execute(sql).fetchone()[0]
        return {
            "organizations": one("SELECT COUNT(*) FROM organizations"),
            "locations": one("SELECT COUNT(*) FROM locations"),
            "devices": one("SELECT COUNT(*) FROM devices"),
            "devices_offline": one("SELECT COUNT(*) FROM devices WHERE offline=1"),
            "alerts": one("SELECT COUNT(*) FROM alerts"),
            "activities": one("SELECT COUNT(*) FROM activities"),
        }

    def manifest(self):
        counts = self.counts()
        oldest = self.con.execute(
            "SELECT MIN(activity_time) FROM activities").fetchone()[0]
        db_size = db_path().stat().st_size if db_path().exists() else 0
        snap = self.exchange.snapshot
        snapshot_size = snap.stat().st_size if snap.exists() else 0
        max_bytes = int(self.cfg["max_db_mb"]) * 1024 * 1024
        size_warning = db_size > max_bytes
        if size_warning:
            log.warning("database is %.1f MB, above the %s MB soft cap — check "
                        "retention settings", db_size / 1e6, self.cfg["max_db_mb"])
        return {
            "schema_version": SCHEMA_VERSION,
            "state": self.get_state("state") or "cleared",
            "generated_at": iso(utc_now()),
            "last_sync_utc": self.get_state("last_sync"),
            "last_morning_reset": self.get_state("last_reset_date"),
            "inventory_stale": self.get_state("inventory_stale") == "1",
            "counts": counts,
            "activity_cursor": self.get_state("activity_cursor") or None,
            "retention_days": int(self.cfg["retention_days"]),
            "window_start": self.window_start(),
            "oldest_retained_activity": oldest,
            "db_size_bytes": db_size,
            "snapshot_size_bytes": snapshot_size,
            "size_warning": size_warning,
        }

    def publish(self):
        """Atomically replace the exchange snapshot + manifest + summary CSV.

        The backup is built inside the PRIVATE app root (where nothing that can
        write to the exchange folder can plant a symlink under it), then moved
        into the exchange root through the hardened atomic_write path."""
        self.exchange.ensure_dirs()
        tmp = db_path().parent / f".snapshot-tmp-{os.getpid()}.sqlite"
        if tmp.exists() or tmp.is_symlink():
            tmp.unlink()
        dest = sqlite3.connect(tmp)
        try:
            self.con.commit()
            self.con.backup(dest)
        finally:
            dest.close()
        try:
            atomic_write(self.exchange.snapshot, tmp.read_bytes())
        finally:
            tmp.unlink(missing_ok=True)

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["device_id", "display_name", "system_name", "organization",
                         "location", "node_class", "os", "offline", "last_contact"])
        # Every cell is tenant-authored text; csv_cell strips control
        # characters and neutralizes spreadsheet formulas.
        writer.writerows(
            [csv_cell(value) for value in row]
            for row in self.con.execute("""
                SELECT d.id, d.display_name, d.system_name, o.name, l.name,
                       d.node_class, d.os_name,
                       CASE WHEN d.offline=1 THEN 'yes' ELSE 'no' END,
                       d.last_contact
                FROM devices d
                LEFT JOIN organizations o ON o.id = d.org_id
                LEFT JOIN locations l ON l.id = d.location_id
                ORDER BY o.name, d.display_name""").fetchall())
        atomic_write(self.exchange.summary_csv, buf.getvalue())
        atomic_write(self.exchange.manifest, json.dumps(self.manifest(), indent=2))
        self._sweep_exports()

    def _sweep_exports(self, morning=False, max_files=20, max_bytes=200_000_000):
        """Cap exports/ at 20 files / 200 MB, oldest first. The keep/ subfolder
        and the two standard published files are exempt. Morning sweeps also
        drop files from previous days."""
        standard = {self.exchange.manifest.name, self.exchange.summary_csv.name}
        entries = []
        for p in self.exchange.exports.iterdir():
            if p.is_dir() or p.name in standard:
                continue
            st = p.stat()
            entries.append((st.st_mtime, st.st_size, p))
        entries.sort()
        if morning:
            midnight = time.mktime(datetime.now().replace(
                hour=0, minute=0, second=0, microsecond=0).timetuple())
            for mtime, _, p in list(entries):
                if mtime < midnight:
                    p.unlink(missing_ok=True)
            entries = [e for e in entries if e[2].exists()]
        total = sum(size for _, size, _ in entries)
        while entries and (len(entries) > max_files or total > max_bytes):
            _, size, victim = entries.pop(0)
            victim.unlink(missing_ok=True)
            total -= size
