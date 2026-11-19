"""Shared fixtures: temp roots, a canned FakeClient, an HTTP mock, helpers."""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.error
from datetime import timedelta
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SRC))

from nj_common import iso, today_str, utc_now  # noqa: E402

# Distinctive dummy secrets. The leak-sweep tests grep both roots for these
# exact strings (and their encoded forms), so they must not appear in any
# artifact the connector writes.
DUMMY_CLIENT_ID = "njclientidAAAA1111"
DUMMY_SECRET = "njSECRETvalue0000000000ZZZZ"
DUMMY_TOKEN = "njBEARERtoken9999999999YYYY"


def epoch(minutes_ago=5, days_ago=0):
    return (utc_now() - timedelta(days=days_ago, minutes=minutes_ago)).timestamp()


def make_device(device_id, org_id=10, location_id=100, offline=False,
                minutes_ago=5, **overrides):
    """Shaped like a real /v2/devices-detailed row, which is what the sync
    engine actually consumes. Note lastBootTime is nested INSIDE os — that is
    where NinjaOne puts it, and a top-level lookup silently yields null."""
    device = {
        "id": device_id,
        "organizationId": org_id,
        "locationId": location_id,
        "systemName": f"HOST-{device_id}",
        "displayName": f"Device {device_id}",
        "dnsName": f"HOST-{device_id}",
        "nodeClass": "WINDOWS_WORKSTATION",
        "nodeRoleId": 4,
        "offline": offline,
        "lastContact": epoch(minutes_ago=minutes_ago),
        "publicIP": "203.0.113.7",
        "ipAddresses": ["172.20.0.5"],
        "os": {"name": "Windows 11 Pro", "buildNumber": "22631",
               "architecture": "64-bit", "lastBootTime": epoch(days_ago=2)},
    }
    device.update(overrides)
    return device


def make_lean_device(device_id, org_id=10, location_id=100, offline=False,
                     minutes_ago=5):
    """Shaped like a real /v2/devices row — no os, no boot time, no IP. Kept
    so the tests can prove why inventory syncs from the detailed endpoint."""
    return {
        "id": device_id, "organizationId": org_id, "locationId": location_id,
        "nodeClass": "WINDOWS_WORKSTATION", "nodeRoleId": 202,
        "offline": offline, "systemName": f"HOST-{device_id}",
        "dnsName": f"HOST-{device_id}",
        "lastContact": epoch(minutes_ago=minutes_ago),
        "lastUpdate": epoch(minutes_ago=minutes_ago),
    }


def make_alert(uid, device_id=1, **overrides):
    alert = {
        "uid": uid,
        "deviceId": device_id,
        "message": f"Condition {uid} triggered",
        "sourceType": "CONDITION",
        "createTime": epoch(minutes_ago=30),
    }
    alert.update(overrides)
    return alert


def make_activity(activity_id, device_id=1, minutes_ago=10, days_ago=0, **overrides):
    activity = {
        "id": activity_id,
        "deviceId": device_id,
        "activityTime": epoch(minutes_ago=minutes_ago, days_ago=days_ago),
        "activityType": "CONDITION",
        "statusName": "COMPLETED",
        "message": f"Activity {activity_id} happened",
    }
    activity.update(overrides)
    return activity


class FakeClient:
    """Offline stand-in for NjClient. Serves canned data; records calls."""

    def __init__(self, devices=None, orgs=None, locations=None, alerts=None,
                 activities=None):
        self.devices = devices if devices is not None else [
            make_device(1), make_device(2, offline=True),
            make_device(3, org_id=11, location_id=101)]
        self.orgs = orgs if orgs is not None else [
            {"id": 10, "name": "Contoso"}, {"id": 11, "name": "Fabrikam"}]
        self.locs = locations if locations is not None else [
            {"id": 100, "organizationId": 10, "name": "HQ"},
            {"id": 101, "organizationId": 11, "name": "Warehouse"}]
        self.alert_rows = alerts if alerts is not None else [
            make_alert("a1", device_id=1), make_alert("a2", device_id=2)]
        self.activity_rows = activities if activities is not None else [
            make_activity(500, device_id=1), make_activity(501, device_id=2)]
        self.calls = []
        self.granted_scope = "monitoring"
        self.scope_warning = None

    def probe(self):
        self.calls.append(("probe",))
        return self.orgs[:1]

    def organizations(self):
        self.calls.append(("organizations",))
        return list(self.orgs)

    def locations(self):
        self.calls.append(("locations",))
        return list(self.locs)

    def iter_devices(self, page_size=1000, detailed=False):
        self.calls.append(("iter_devices", page_size, detailed))
        yield from self.devices

    def device(self, device_id):
        self.calls.append(("device", device_id))
        for d in self.devices:
            if d["id"] == device_id:
                return d
        from nj_api import ApiError
        raise ApiError("device not found", 404)

    def device_alerts(self, device_id):
        self.calls.append(("device_alerts", device_id))
        return [a for a in self.alert_rows if a.get("deviceId") == device_id]

    def device_activities(self, device_id, count=100):
        self.calls.append(("device_activities", device_id))
        return [a for a in self.activity_rows if a.get("deviceId") == device_id]

    def alerts(self):
        self.calls.append(("alerts",))
        return list(self.alert_rows)

    def iter_activities(self, newer_than=None, count=500, max_pages=200):
        self.calls.append(("iter_activities", newer_than))
        for a in sorted(self.activity_rows, key=lambda r: r["id"]):
            if newer_than is None or a["id"] > int(newer_than):
                yield a

    def iter_activities_older(self, older_than=None, count=500, max_pages=200):
        self.calls.append(("iter_activities_older", older_than))
        for a in sorted(self.activity_rows, key=lambda r: r["id"], reverse=True):
            if older_than is None or a["id"] < int(older_than):
                yield a

    def api_get(self, path, params=None):
        self.calls.append(("api_get", path, params))
        return {"echo": path, "params": params or {}}


class MockResponse(io.BytesIO):
    """Minimal stand-in for the object urlopen returns."""

    def __init__(self, payload, headers=None):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        super().__init__(data)
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class MockHttp:
    """Records every urllib Request and answers from a routing table.

    Routes are (predicate, responder) pairs; the first matching predicate
    wins. A responder may return a payload or raise an HTTPError.
    """

    def __init__(self):
        self.requests = []
        self.routes = []
        self.token_mint_count = 0

    def route(self, predicate, responder):
        self.routes.append((predicate, responder))
        return self

    def token_route(self, scope="monitoring", expires_in=3600, token=DUMMY_TOKEN):
        def responder(request):
            self.token_mint_count += 1
            return MockResponse({"access_token": token, "token_type": "Bearer",
                                 "expires_in": expires_in, "scope": scope})
        self.route(lambda r: "oauth/token" in r.full_url, responder)
        return self

    def json_route(self, contains, payload):
        self.route(lambda r: contains in r.full_url,
                   lambda r: MockResponse(payload))
        return self

    def error_route(self, contains, code, headers=None, times=None):
        state = {"left": times}

        def responder(request):
            if state["left"] is not None:
                if state["left"] <= 0:
                    return MockResponse([])
                state["left"] -= 1
            raise urllib.error.HTTPError(request.full_url, code, f"HTTP {code}",
                                         headers or {}, io.BytesIO(b""))
        self.route(lambda r: contains in r.full_url, responder)
        return self

    def __call__(self, request, timeout=None, context=None):
        self.requests.append(request)
        for predicate, responder in self.routes:
            if predicate(request):
                return responder(request)
        return MockResponse([])

    # -- introspection helpers -------------------------------------------
    @property
    def urls(self):
        return [r.full_url for r in self.requests]

    @property
    def methods(self):
        return [r.get_method() for r in self.requests]

    def bodies(self):
        return [(r.data or b"").decode() for r in self.requests]


def make_client(http=None, instance="app.ninjarmm.com", **kw):
    """Build a real NjClient wired to a MockHttp opener (never the network)."""
    from nj_api import NjClient
    http = http or MockHttp().token_route()
    client = NjClient(instance, DUMMY_CLIENT_ID, DUMMY_SECRET,
                      sleeper=lambda *_: None, opener=http, **kw)
    client._http = http
    return client


class ConnectorCase(unittest.TestCase):
    """Creates isolated app + exchange roots and a config for each test."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="njc-test-"))
        os.environ["NJC_APP_ROOT"] = str(self.tmp / "approot")
        self.exchange_root = self.tmp / "exchange"
        self.cfg = {
            "instance": "app.ninjarmm.com",
            "token_path": "/ws/oauth/token",
            "exchange_root": str(self.exchange_root),
            "sync_interval_minutes": 15,
            "retention_days": 1,
            "max_db_mb": 100,
            "python_path": sys.executable,
            "debug": False,
        }

    def tearDown(self):
        os.environ.pop("NJC_APP_ROOT", None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_engine(self, client=None, ready=True):
        from nj_sync import SyncEngine
        engine = SyncEngine(self.cfg, client=client or FakeClient())
        self.addCleanup(engine.con.close)
        if ready:
            engine.set_state("state", "ready")
            engine.set_state("last_backfill_date", today_str())
            engine.set_state("window_start", iso(utc_now() - timedelta(days=1)))
            engine.set_state("last_sync", iso(utc_now()))
            engine.sync_inventory()
            engine.sync_alerts()
            engine.sync_activities()
        return engine

    def make_bridge(self, engine=None, client=None):
        from nj_bridge import Bridge
        from nj_common import Exchange
        Exchange(self.cfg).ensure_dirs()
        return Bridge(self.cfg, engine=engine or self.make_engine(client=client))

    def write_request(self, bridge, action, params=None, rid="req1", raw=None,
                      filename=None):
        payload = raw if raw is not None else json.dumps(
            {"id": rid, "action": action, "params": params or {}})
        name = filename or f"request-{rid}.json"
        target = bridge.exchange.requests / name
        tmp = target.with_name(f".{name}.tmp")
        tmp.write_text(payload)
        os.replace(tmp, target)
        os.utime(target, (0, 0))  # bypass the 1-second-young safety wait
        return target

    def read_response(self, bridge, rid):
        path = bridge.exchange.responses / f"response-{rid}.json"
        self.assertTrue(path.exists(), f"no response for {rid}")
        return json.loads(path.read_text())

    def roundtrip(self, bridge, action, params=None, rid="req1", **kw):
        self.write_request(bridge, action, params, rid=rid, **kw)
        bridge.drain()
        return self.read_response(bridge, rid)
