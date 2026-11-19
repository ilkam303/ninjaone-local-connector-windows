"""Filesystem request/response bridge.

Trust-boundary role: everything under exchange/requests/ is HOSTILE input —
anything that can write to the connected folder (including a prompt-injected
agent) is untrusted. Every request file is size-capped, symlink-checked,
schema-validated with an allowlist of actions and parameters, and served with
parameterized SQL only. The bridge writes only inside the exchange root
(responses/, exports/, processed/), verified by path resolution, and has no
action that can disclose the client credentials or the bearer token.
"""

import json
import logging
import os
import re
import stat
import time

from nj_api import ApiError, RequestRejected
from pathlib import Path

from nj_common import (Exchange, atomic_write, csv_cell, epoch_to_iso,
                       is_reparse_point, norm_date, redact)
from nj_sync import SyncEngine, activity_row, alert_row

log = logging.getLogger("njc.bridge")

MAX_REQUEST_BYTES = 64 * 1024
MAX_FOLDER_FILES = 200
# A drain must be bounded. requests/ is hostile-writable and was uncapped, so
# N planted files cost N seconds of the single resident watcher on Windows
# (launchd re-fires a fresh one-shot; Task Scheduler does not).
MAX_DRAIN_FILES = 200
MAX_DRAIN_SECONDS = 120
MIN_FILE_AGE_SECONDS = 1.0
# A request id is also the response FILENAME the caller polls, so it must be
# a safe basename. Dots are allowed (callers use ids like "rpt.status.1");
# a leading dot is not, and ".." is rejected outright below.
# Lowercase only. NTFS and the default APFS are case-insensitive, so
# request-ABC and request-abc are two distinct ids answering into ONE
# response file — letting one caller race and replace another's reply.
# Restricting the charset makes the collision impossible rather than
# merely unlikely.
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,80}$")
RESERVED_DEVICE_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
RESERVED_EXPORT_NAMES = {"sync_manifest.json", "devices_summary.csv"}

DEVICE_PARAMS = {
    "org": str, "location": str, "node_class": str, "os_contains": str,
    "offline": bool, "last_contact_before": str, "last_contact_since": str,
    "text_contains": str, "limit": int,
}
ALERT_PARAMS = {
    "org": str, "device": str, "source_type": str, "severity": str,
    "limit": int, "scope": str,
}
ACTIVITY_PARAMS = {
    "org": str, "device": str, "activity_type": str, "status": str,
    "since": str, "until": str, "text_contains": str, "limit": int, "scope": str,
}
ENTITY_PARAMS = {"devices": DEVICE_PARAMS, "alerts": ALERT_PARAMS,
                 "activities": ACTIVITY_PARAMS}

DEFAULT_LIMIT = 500
MAX_LIMIT = 5000
LIVE_SCAN_CAP = 20_000  # max activities scanned for a live-scope query


class BridgeError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _like_escape(value):
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class Bridge:
    def __init__(self, cfg, engine=None):
        self.cfg = cfg
        self.exchange = Exchange(cfg)
        self.engine = engine or SyncEngine(cfg)
        self.actions = {
            "status": self.act_status,
            "sync_now": self.act_sync_now,
            "query_devices": self.act_query_devices,
            "get_device": self.act_get_device,
            "query_alerts": self.act_query_alerts,
            "query_activities": self.act_query_activities,
            "api_get": self.act_api_get,
            "export": self.act_export,
        }

    # ------------------------------------------------------------- drain loop

    def drain(self):
        self.exchange.ensure_dirs()

        def sort_key(p):
            try:
                return os.lstat(p).st_mtime
            except OSError:
                return 0

        pending = sorted(self.exchange.requests.glob("*.json"), key=sort_key)
        overflow = pending[MAX_DRAIN_FILES:]
        pending = pending[:MAX_DRAIN_FILES]
        if overflow:
            log.warning("drain: %d request(s) over the %d-file cap; answering "
                        "them with an error instead of processing",
                        len(overflow), MAX_DRAIN_FILES)
        handled = 0
        started = time.time()
        for path in pending:
            try:
                os.lstat(path)  # vanished between glob and now?
            except OSError:
                continue
            if time.time() - started > MAX_DRAIN_SECONDS:
                log.warning("drain: %ds budget exhausted; remaining requests "
                            "wait for the next trigger", MAX_DRAIN_SECONDS)
                break
            self._handle_file(path)
            handled += 1
        for path in overflow:
            rid = self._id_from_filename(path)
            self._respond(rid, {"id": rid, "status": "error",
                                "error": {"code": "too_many_requests",
                                          "message": f"more than {MAX_DRAIN_FILES} "
                                                     "requests were pending; this one "
                                                     "was not processed"}})
            self._archive(path)
        self._cap_folder(self.exchange.responses)
        self._cap_folder(self.exchange.processed)
        return handled

    def _handle_file(self, path):
        rid = self._id_from_filename(path)
        try:
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode):
                raise BridgeError("symlink_rejected",
                                  "symlinked request files are not processed")
            if not stat.S_ISREG(st.st_mode):
                raise BridgeError("not_a_file",
                                  "only regular files are processed (no FIFOs/devices)")
            age = time.time() - st.st_mtime
            if age < MIN_FILE_AGE_SECONDS:
                time.sleep(max(0.0, min(MIN_FILE_AGE_SECONDS, MIN_FILE_AGE_SECONDS - age)))  # let the writer finish; clamp: mtime is untrusted
            if os.lstat(path).st_size > MAX_REQUEST_BYTES:
                raise BridgeError("request_too_large",
                                  f"request files are capped at {MAX_REQUEST_BYTES} bytes")
            if not self.exchange.contains(path):
                raise BridgeError("path_rejected", "request escapes the exchange root")
            request = self._parse(path)
            if request["id"] != rid:
                # Answering under the body id would strand a caller polling the
                # filename it chose, which reads as a hang rather than an error.
                raise BridgeError(
                    "id_mismatch",
                    "body id %r must equal the id in the filename (%r)"
                    % (request["id"], rid))
            response = self._dispatch(request)
            self._respond(rid, {"id": rid, "status": "ok", **response})
        except BridgeError as e:
            self._respond(rid, {"id": rid, "status": "error",
                                "error": {"code": e.code, "message": redact(str(e))}})
        except (ApiError, RequestRejected) as e:
            code = "auth_failed" if getattr(e, "code", None) in (401, 403) else "api_error"
            self._respond(rid, {"id": rid, "status": "error",
                                "error": {"code": code, "message": redact(str(e))}})
        except Exception as e:
            log.exception("unhandled bridge error for %s", path.name)
            self._respond(rid, {"id": rid, "status": "error",
                                "error": {"code": "internal_error",
                                          "message": redact(f"{type(e).__name__}: {e}")}})
        finally:
            self._archive(path)

    def _id_from_filename(self, path):
        """The id encoded in the request filename, used verbatim for the reply.

        Never sanitize here: the caller polls response-<the-name-it-chose>.json,
        so silently rewriting the id (stripping dots, say) writes the answer to
        a path the caller never looks at, and it sees a timeout instead of the
        reply. Unusable names fall back to a sentinel, which is the only case
        where correlation is genuinely impossible.
        """
        stem = path.stem
        if stem.startswith("request-"):
            stem = stem[len("request-"):]
        # Casefold before validating: ids are lowercase-only (see ID_RE), but
        # a caller that used mixed case must still receive a findable error.
        # On a case-insensitive filesystem response-abc.json IS the file they
        # are polling for; answering as "unknown" would read as a hang.
        stem = stem.lower()
        if ID_RE.fullmatch(stem) and ".." not in stem:
            return stem
        return "unknown"

    @staticmethod
    def _read_no_follow(path):
        """Read via O_NOFOLLOW, where the platform HAS it, so a symlink
        swapped in after the lstat check
        cannot redirect the read. The requests folder is consumer-writable and
        this bridge deliberately sleeps between the check and the read, so the
        window is wide enough to matter."""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(str(path), flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise BridgeError("not_a_file", "request is not a regular file")
            if st.st_size > MAX_REQUEST_BYTES:
                raise BridgeError("request_too_large", "request exceeds the size cap")
            return os.read(fd, MAX_REQUEST_BYTES + 1)
        finally:
            os.close(fd)

    def _parse(self, path):
        try:
            payload = json.loads(self._read_no_follow(path).decode("utf-8"))
        except OSError as e:
            raise BridgeError("unreadable", "request could not be opened: %s" % e)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise BridgeError("malformed_json", f"request is not valid JSON: {e}")
        if not isinstance(payload, dict):
            raise BridgeError("malformed_request", "request must be a JSON object")
        unknown = set(payload) - {"id", "action", "params"}
        if unknown:
            raise BridgeError("unknown_keys", f"unknown top-level keys: {sorted(unknown)}")
        rid = payload.get("id")
        if not isinstance(rid, str) or not ID_RE.fullmatch(rid):
            raise BridgeError(
                "bad_id",
                "id must be 1-64 chars of [a-z0-9_-] (lowercase only: the "
                "filesystem is case-insensitive, so mixed case would let two "
                "ids collide onto one response file)")
        action = payload.get("action")
        if action not in self.actions:
            raise BridgeError("unknown_action",
                              f"action must be one of {sorted(self.actions)}")
        params = payload.get("params", {})
        if not isinstance(params, dict):
            raise BridgeError("bad_params", "params must be an object")
        return {"id": rid, "action": action, "params": params}

    def _dispatch(self, request):
        return self.actions[request["action"]](request["params"])

    def _respond(self, rid, payload):
        # Defensive only: every caller passes an already-validated id. Do not
        # rewrite a bad one into a different filename, which would hide the reply.
        cleaned = rid if (ID_RE.fullmatch(rid or "") and ".." not in rid) else "unknown"
        dest = self.exchange.responses / f"response-{cleaned}.json"
        if not self.exchange.contains(dest):
            log.error("refusing to write response outside exchange root")
            return
        atomic_write(dest, json.dumps(payload, indent=2, default=str))

    def _archive(self, path):
        try:
            if not path.exists() and not path.is_symlink():
                return
            # Containment, same rule _respond already applies. Without it,
            # replacing this folder with a symlink or reparse point turns the
            # os.replace below into a write at a location outside the exchange
            # root — which is a containment break, not merely a misfiled file.
            processed = self.exchange.processed
            if is_reparse_point(processed):
                log.error("refusing to archive: %s is a symlink/junction", processed)
                path.unlink(missing_ok=True)
                return
            safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", path.name)[:120] or "request.json"
            dest = processed / safe_name
            counter = 1
            while dest.exists():
                dest = processed / f"{Path(safe_name).stem}.{counter}.json"
                counter += 1
            if not self.exchange.contains(dest):
                log.error("refusing to archive outside the exchange root")
                path.unlink(missing_ok=True)
                return
            os.replace(path, dest)
        except OSError as e:
            log.warning("could not archive %s: %s", path.name, e)

    def _cap_folder(self, folder, max_files=MAX_FOLDER_FILES):
        try:
            files = sorted((p for p in folder.iterdir() if p.is_file()),
                           key=lambda p: p.stat().st_mtime)
            for victim in files[:max(0, len(files) - max_files)]:
                victim.unlink(missing_ok=True)
        except OSError:
            pass

    # ----------------------------------------------------------- validation

    def _validate_params(self, params, spec, required=()):
        unknown = set(params) - set(spec)
        if unknown:
            raise BridgeError("unknown_params", f"unknown params: {sorted(unknown)}")
        for name in required:
            if name not in params:
                raise BridgeError("missing_param", f"missing required param: {name}")
        for name, value in params.items():
            expected = spec[name]
            if expected is bool:
                if not isinstance(value, bool):
                    raise BridgeError("bad_param", f"{name} must be a boolean")
            elif expected is int:
                if not isinstance(value, int) or isinstance(value, bool):
                    raise BridgeError("bad_param", f"{name} must be an integer")
            elif expected is str:
                if not isinstance(value, str) or len(value) > 500:
                    raise BridgeError("bad_param", f"{name} must be a string (max 500 chars)")
            elif expected is dict:
                if not isinstance(value, dict):
                    raise BridgeError("bad_param", f"{name} must be an object")
        return params

    def _limit_of(self, params, default=DEFAULT_LIMIT):
        limit = params.get("limit", default)
        if not 1 <= limit <= MAX_LIMIT:
            raise BridgeError("bad_param", f"limit must be 1..{MAX_LIMIT}")
        return limit

    def _scope_of(self, params):
        scope = params.get("scope", "cache")
        if scope not in ("cache", "live"):
            raise BridgeError("bad_param", "scope must be 'cache' or 'live'")
        return scope

    def _org_ids(self, name):
        """Resolve an organization name (case-insensitive) to its ids. Names are
        tenant-authored text, so this is a parameterized lookup, never splicing."""
        rows = self.engine.con.execute(
            "SELECT id FROM organizations WHERE name = ? COLLATE NOCASE", (name,)).fetchall()
        if not rows:
            raise BridgeError("unknown_org", f"no organization named {name!r} in the cache")
        return [r[0] for r in rows]

    def _device_ids(self, text):
        """Resolve a device by numeric id or by display/system name."""
        if text.strip().isdigit():
            return [int(text.strip())]
        rows = self.engine.con.execute(
            "SELECT id FROM devices WHERE display_name = ? COLLATE NOCASE "
            "OR system_name = ? COLLATE NOCASE", (text, text)).fetchall()
        if not rows:
            raise BridgeError("unknown_device", f"no device named {text!r} in the cache")
        return [r[0] for r in rows]

    def _in_clause(self, column, values):
        placeholders = ",".join("?" * len(values))
        return f"{column} IN ({placeholders})", list(values)

    # -------------------------------------------------------------- actions

    def act_status(self, params):
        """Cheap health check. Never triggers a rebuild."""
        self._validate_params(params, {})
        return {"data": {"manifest": self.engine.manifest(),
                         "exchange_root": str(self.exchange.root)}}

    def act_sync_now(self, params):
        self._validate_params(params, {})
        rebuilt = self.engine.ensure_fresh()
        manifest = self.engine.interval_sync(force=True)
        return {"data": manifest, "rebuilt": rebuilt}

    def act_query_devices(self, params):
        self._validate_params(params, DEVICE_PARAMS)
        limit = self._limit_of(params)
        for key in ("last_contact_before", "last_contact_since"):
            if key in params:
                try:
                    params[key] = norm_date(params[key], end=(key == "last_contact_before"))
                except ValueError:
                    raise BridgeError("bad_param",
                                      f"{key} must be YYYY-MM-DD or ISO8601")
        rebuilt = self.engine.ensure_fresh()
        synced = self.engine.refresh_if_stale() if not rebuilt else False

        where, bind = [], []
        if "org" in params:
            clause, values = self._in_clause("d.org_id", self._org_ids(params["org"]))
            where.append(clause)
            bind += values
        if "location" in params:
            where.append("l.name = ? COLLATE NOCASE")
            bind.append(params["location"])
        if "node_class" in params:
            where.append("d.node_class = ? COLLATE NOCASE")
            bind.append(params["node_class"])
        if "os_contains" in params:
            where.append("d.os_name LIKE ? ESCAPE '\\'")
            bind.append(f"%{_like_escape(params['os_contains'])}%")
        if "offline" in params:
            where.append("d.offline = ?")
            bind.append(1 if params["offline"] else 0)
        if "last_contact_before" in params:
            where.append("(d.last_contact IS NULL OR d.last_contact < ?)")
            bind.append(params["last_contact_before"])
        if "last_contact_since" in params:
            where.append("d.last_contact >= ?")
            bind.append(params["last_contact_since"])
        if "text_contains" in params:
            needle = f"%{_like_escape(params['text_contains'])}%"
            where.append("(d.display_name LIKE ? ESCAPE '\\' OR d.system_name LIKE ? "
                         "ESCAPE '\\' OR d.os_name LIKE ? ESCAPE '\\')")
            bind += [needle] * 3

        sql = ("SELECT d.id, d.display_name, d.system_name, d.node_class, d.role, "
               "d.os_name, d.offline, d.last_contact, d.last_boot, d.ip, "
               "o.name AS org_name, l.name AS location_name "
               "FROM devices d "
               "LEFT JOIN organizations o ON o.id = d.org_id "
               "LEFT JOIN locations l ON l.id = d.location_id ")
        if where:
            sql += "WHERE " + " AND ".join(where) + " "
        sql += "ORDER BY o.name, d.display_name LIMIT ?"
        bind.append(limit)
        rows = [{
            "id": r["id"], "display_name": r["display_name"],
            "system_name": r["system_name"], "organization": r["org_name"],
            "location": r["location_name"], "node_class": r["node_class"],
            "role": r["role"], "os": r["os_name"], "offline": bool(r["offline"]),
            "last_contact": r["last_contact"], "last_boot": r["last_boot"],
            "ip": r["ip"],
        } for r in self.engine.con.execute(sql, bind)]
        return {"data": {"rows": rows, "count": len(rows)}, "source": "cache",
                "rebuilt": rebuilt, "synced": synced or rebuilt,
                "data_as_of": self.engine.get_state("last_sync")}

    def act_get_device(self, params):
        self._validate_params(
            params, {"device_id": int, "include_alerts": bool,
                     "include_activities": bool}, required=("device_id",))
        device_id = params["device_id"]
        if device_id <= 0:
            raise BridgeError("bad_param", "device_id must be positive")
        device = self.engine.client.device(device_id)
        if not isinstance(device, dict):
            raise BridgeError("not_found", f"no device {device_id} returned by NinjaOne")

        def name_of(table, id_):
            if id_ is None:
                return None
            row = self.engine.con.execute(
                f"SELECT name FROM {table} WHERE id=?", (id_,)).fetchone()
            return row[0] if row else str(id_)

        org_id = device.get("organizationId")
        location_id = device.get("locationId")
        os_field = device.get("os")
        data = {
            "id": device.get("id"),
            "display_name": device.get("displayName") or device.get("systemName"),
            "system_name": device.get("systemName") or device.get("dnsName"),
            "organization": name_of("organizations", org_id),
            "location": name_of("locations", location_id),
            "node_class": device.get("nodeClass"),
            "role": device.get("nodeRoleId"),
            "os": os_field.get("name") if isinstance(os_field, dict) else os_field,
            "offline": bool(device.get("offline")),
            "last_contact": epoch_to_iso(device.get("lastContact")),
            "last_boot": epoch_to_iso(device.get("lastBootTime")),
            "public_ip": device.get("publicIP"),
            "raw": device,
        }
        if params.get("include_alerts"):
            data["alerts"] = [
                {"uid": a[0], "device_id": a[1], "message": a[2],
                 "source_type": a[3], "created": a[4]}
                for a in (alert_row(x) for x in self.engine.client.device_alerts(device_id))]
        if params.get("include_activities"):
            rows = []
            for activity in self.engine.client.device_activities(device_id):
                if activity.get("id") is None:
                    continue
                shaped = activity_row(activity)
                rows.append({"id": shaped[0], "device_id": shaped[1],
                             "activity_time": shaped[2], "activity_type": shaped[3],
                             "status": shaped[4], "message": shaped[5]})
            data["activities"] = rows
        return {"data": data, "source": "live"}

    def act_query_alerts(self, params):
        self._validate_params(params, ALERT_PARAMS)
        limit = self._limit_of(params)
        scope = self._scope_of(params)
        if scope == "live":
            return self._live_alerts(params, limit)

        rebuilt = self.engine.ensure_fresh()
        synced = self.engine.refresh_if_stale() if not rebuilt else False
        where, bind = [], []
        if "org" in params:
            clause, values = self._in_clause("d.org_id", self._org_ids(params["org"]))
            where.append(clause)
            bind += values
        if "device" in params:
            clause, values = self._in_clause("a.device_id", self._device_ids(params["device"]))
            where.append(clause)
            bind += values
        for key in ("source_type", "severity"):
            if key in params:
                where.append("a.source_type = ? COLLATE NOCASE")
                bind.append(params[key])
        sql = ("SELECT a.uid, a.device_id, a.message, a.source_type, a.created, "
               "d.display_name, o.name AS org_name FROM alerts a "
               "LEFT JOIN devices d ON d.id = a.device_id "
               "LEFT JOIN organizations o ON o.id = d.org_id ")
        if where:
            sql += "WHERE " + " AND ".join(where) + " "
        sql += "ORDER BY a.created DESC LIMIT ?"
        bind.append(limit)
        rows = [{
            "uid": r["uid"], "device_id": r["device_id"],
            "device": r["display_name"], "organization": r["org_name"],
            "message": r["message"], "source_type": r["source_type"],
            "created": r["created"],
        } for r in self.engine.con.execute(sql, bind)]
        return {"data": {"rows": rows, "count": len(rows)}, "source": "cache",
                "rebuilt": rebuilt, "synced": synced or rebuilt,
                "data_as_of": self.engine.get_state("last_sync")}

    def _live_alerts(self, params, limit):
        """Fresh pull straight from /v2/alerts for this request only — never
        persisted, so the cache stays a clean one-day working set."""
        device_names = {r["id"]: r["display_name"] for r in
                        self.engine.con.execute("SELECT id, display_name FROM devices")}
        device_orgs = {r["id"]: r["org_id"] for r in
                       self.engine.con.execute("SELECT id, org_id FROM devices")}
        org_names = {r["id"]: r["name"] for r in
                     self.engine.con.execute("SELECT id, name FROM organizations")}
        want_orgs = set(self._org_ids(params["org"])) if "org" in params else None
        want_devices = set(self._device_ids(params["device"])) if "device" in params else None
        want_type = (params.get("source_type") or params.get("severity") or "").lower() or None

        rows = []
        for alert in self.engine.client.alerts():
            uid, device_id, message, source_type, created, _ = alert_row(alert)
            if want_devices is not None and device_id not in want_devices:
                continue
            if want_orgs is not None and device_orgs.get(device_id) not in want_orgs:
                continue
            if want_type is not None and (source_type or "").lower() != want_type:
                continue
            rows.append({
                "uid": uid, "device_id": device_id,
                "device": device_names.get(device_id),
                "organization": org_names.get(device_orgs.get(device_id)),
                "message": message, "source_type": source_type, "created": created,
            })
            if len(rows) >= limit:
                break
        return {"data": {"rows": rows, "count": len(rows)}, "source": "live"}

    def act_query_activities(self, params):
        self._validate_params(params, ACTIVITY_PARAMS)
        limit = self._limit_of(params)
        scope = self._scope_of(params)
        for key in ("since", "until"):
            if key in params:
                try:
                    params[key] = norm_date(params[key], end=(key == "until"))
                except ValueError:
                    raise BridgeError("bad_param", f"{key} must be YYYY-MM-DD or ISO8601")

        window_start = self.engine.window_start()
        # A range reaching back before the retention window cannot be answered
        # from the cache; go live automatically rather than under-reporting.
        predates = bool(params.get("since")) and params["since"] < window_start
        if scope == "live" or predates:
            result = self._live_activities(params, limit)
            oldest = self.engine.con.execute(
                "SELECT MIN(activity_time) FROM activities").fetchone()[0]
            result["oldest_retained"] = oldest or window_start
            if predates and scope != "live":
                result["note"] = (
                    "the requested range predates the local retention window, so this "
                    "was answered live from NinjaOne and not persisted")
            return result

        rebuilt = self.engine.ensure_fresh()
        synced = self.engine.refresh_if_stale() if not rebuilt else False
        where, bind = [], []
        if "org" in params:
            clause, values = self._in_clause("d.org_id", self._org_ids(params["org"]))
            where.append(clause)
            bind += values
        if "device" in params:
            clause, values = self._in_clause("a.device_id",
                                             self._device_ids(params["device"]))
            where.append(clause)
            bind += values
        if "activity_type" in params:
            where.append("a.activity_type = ? COLLATE NOCASE")
            bind.append(params["activity_type"])
        if "status" in params:
            where.append("a.status_name = ? COLLATE NOCASE")
            bind.append(params["status"])
        if "since" in params:
            where.append("a.activity_time >= ?")
            bind.append(params["since"])
        if "until" in params:
            where.append("a.activity_time <= ?")
            bind.append(params["until"])
        if "text_contains" in params:
            where.append("a.message LIKE ? ESCAPE '\\'")
            bind.append(f"%{_like_escape(params['text_contains'])}%")
        sql = ("SELECT a.id, a.device_id, a.activity_time, a.activity_type, "
               "a.status_name, a.message, d.display_name, o.name AS org_name "
               "FROM activities a "
               "LEFT JOIN devices d ON d.id = a.device_id "
               "LEFT JOIN organizations o ON o.id = d.org_id ")
        if where:
            sql += "WHERE " + " AND ".join(where) + " "
        sql += "ORDER BY a.activity_time DESC LIMIT ?"
        bind.append(limit)
        rows = [{
            "id": r["id"], "device_id": r["device_id"], "device": r["display_name"],
            "organization": r["org_name"], "activity_time": r["activity_time"],
            "activity_type": r["activity_type"], "status": r["status_name"],
            "message": r["message"],
        } for r in self.engine.con.execute(sql, bind)]
        oldest = self.engine.con.execute(
            "SELECT MIN(activity_time) FROM activities").fetchone()[0]
        return {"data": {"rows": rows, "count": len(rows)}, "source": "cache",
                "oldest_retained": oldest or window_start,
                "rebuilt": rebuilt, "synced": synced or rebuilt,
                "data_as_of": self.engine.get_state("last_sync")}

    def _live_activities(self, params, limit):
        """Historical / live-scope query: walk the audit stream backward from
        the present for THIS request only and never persist the rows."""
        device_names = {r["id"]: r["display_name"] for r in
                        self.engine.con.execute("SELECT id, display_name FROM devices")}
        device_orgs = {r["id"]: r["org_id"] for r in
                       self.engine.con.execute("SELECT id, org_id FROM devices")}
        org_names = {r["id"]: r["name"] for r in
                     self.engine.con.execute("SELECT id, name FROM organizations")}
        want_orgs = set(self._org_ids(params["org"])) if "org" in params else None
        want_devices = set(self._device_ids(params["device"])) if "device" in params else None
        since = params.get("since")
        until = params.get("until")
        needle = (params.get("text_contains") or "").lower() or None

        rows, scanned, truncated = [], 0, False
        for activity in self.engine.client.iter_activities_older():
            scanned += 1
            if scanned > LIVE_SCAN_CAP:
                truncated = True
                break
            if activity.get("id") is None:
                continue
            _, device_id, when, activity_type, status, message, _ = activity_row(activity)
            # The walk is newest-first, so once we pass below `since` there is
            # nothing older worth scanning.
            if since and when and when < since:
                break
            if until and when and when > until:
                continue
            if want_devices is not None and device_id not in want_devices:
                continue
            if want_orgs is not None and device_orgs.get(device_id) not in want_orgs:
                continue
            if "activity_type" in params and (activity_type or "").lower() != \
                    params["activity_type"].lower():
                continue
            if "status" in params and (status or "").lower() != params["status"].lower():
                continue
            if needle and needle not in (message or "").lower():
                continue
            rows.append({
                "id": activity.get("id"), "device_id": device_id,
                "device": device_names.get(device_id),
                "organization": org_names.get(device_orgs.get(device_id)),
                "activity_time": when, "activity_type": activity_type,
                "status": status, "message": message,
            })
            if len(rows) >= limit:
                break
        result = {"data": {"rows": rows, "count": len(rows)}, "source": "live"}
        if truncated:
            result["truncated"] = True
            result["note"] = (f"live scan stopped after {LIVE_SCAN_CAP} activities; "
                              "narrow the range for complete results")
        return result

    def act_api_get(self, params):
        """Passthrough to the generic read function — this is how the
        /v2/queries/* reporting endpoints (os-patches, antivirus-status,
        software, …) are reached without code changes. Results are returned,
        never persisted."""
        self._validate_params(params, {"path": str, "params": dict}, required=("path",))
        query = params.get("params", {})
        for k, v in query.items():
            if not isinstance(k, str) or not isinstance(v, (str, int, float, bool)):
                raise BridgeError("bad_param", "api_get params values must be scalars")
        # Path validation (GET-only, /v2/ prefix, single host, no traversal)
        # happens at the client choke point in nj_api.
        result = self.engine.client.api_get(params["path"], query)
        return {"data": result, "source": "live"}

    def act_export(self, params):
        self._validate_params(
            params, {"query": dict, "entity": str, "format": str, "filename": str},
            required=("entity", "format", "filename"))
        entity = params["entity"]
        if entity not in ENTITY_PARAMS:
            raise BridgeError("bad_param",
                              f"entity must be one of {sorted(ENTITY_PARAMS)}")
        fmt = params["format"]
        if fmt not in ("csv", "json"):
            raise BridgeError("bad_param", "format must be 'csv' or 'json'")
        filename = params["filename"]
        if ("/" in filename or "\\" in filename or filename.startswith(".")
                or ".." in filename or ":" in filename
                or not FILENAME_RE.fullmatch(filename)):
            raise BridgeError("bad_filename",
                              "filename must be a plain basename (letters, digits, ._ -)")
        # Windows reserved device names stay devices whatever suffix follows,
        # so NUL.csv is still NUL. Rejected explicitly rather than relying on
        # path resolution to fail closed by accident.
        if Path(filename).stem.upper() in RESERVED_DEVICE_NAMES:
            raise BridgeError("bad_filename",
                              f"{filename!r} is a reserved device name")
        # The connector publishes these two and the skill trusts them; an
        # export must never be able to forge either. _sweep_exports also
        # exempts them from cleanup, so a forgery would persist.
        if filename.lower() in RESERVED_EXPORT_NAMES:
            raise BridgeError("bad_filename",
                              f"{filename!r} is published by the connector and "
                              "cannot be overwritten by an export")
        if not filename.endswith(f".{fmt}"):
            filename += f".{fmt}"
        exports = self.exchange.exports
        # If exports/ is itself a symlink or junction, resolving BOTH sides
        # makes them agree and the containment check passes while the write
        # lands wherever the link points. Check the directory itself first,
        # then anchor on the exchange root rather than on exports/.
        if is_reparse_point(exports):
            raise BridgeError("path_rejected",
                              "exports/ is a symlink or junction; refusing to write")
        dest = exports / filename
        resolved = dest.resolve()
        if not self.exchange.contains(resolved) or resolved.parent != exports.resolve():
            raise BridgeError("path_rejected", "export must land directly in exports/")
        if is_reparse_point(dest):
            raise BridgeError("path_rejected",
                              "an existing symlink/junction occupies that export name")

        query = dict(params.get("query", {}))
        query.pop("scope", None)  # exports always come from the cache
        spec = {k: v for k, v in ENTITY_PARAMS[entity].items() if k != "scope"}
        self._validate_params(query, spec)
        query.setdefault("limit", MAX_LIMIT)
        action = {"devices": self.act_query_devices,
                  "alerts": self.act_query_alerts,
                  "activities": self.act_query_activities}[entity]
        result = action(query)
        rows = result["data"]["rows"]

        if fmt == "json":
            atomic_write(dest, json.dumps(rows, indent=2, default=str))
        else:
            import csv as _csv
            import io as _io
            buf = _io.StringIO()
            if rows:
                writer = _csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                for row in rows:
                    writer.writerow({k: _flat(v) for k, v in row.items()})
            atomic_write(dest, buf.getvalue())
        return {"data": {"path": str(dest), "rows": len(rows), "entity": entity},
                "source": result.get("source", "cache"),
                "rebuilt": result.get("rebuilt", False)}


def _flat(value):
    """Flatten for a CSV cell, then apply the same tenant-content hardening the
    published summary CSV uses (control-character stripping and spreadsheet
    formula neutralization)."""
    if isinstance(value, (list, dict)):
        value = json.dumps(value, default=str)
    return csv_cell(value)
