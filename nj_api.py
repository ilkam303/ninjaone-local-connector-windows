"""NinjaOne API client.

Trust-boundary role: this is the single choke point where outbound requests
are built. It enforces the connector's read-only guarantee at the CODE layer —
every request is a GET, with exactly one carve-out for the OAuth token POST,
which is permitted only for the fixed token path and only with form-encoded
grant parameters. It pins one host (the configured *.ninjarmm.com instance)
over HTTPS with certificate verification always on, and validates every path
so `api_get` cannot be steered to another host, another scheme, or outside
`/v2/`.

The read-only guarantee also holds at the AUTHORIZATION layer: the token
request asks for `scope=monitoring` and nothing else, so even a fully
compromised connector holds a token that cannot mutate the tenant. If the
tenant granted a broader scope, that is detected and warned about loudly.

Bearer tokens are secrets: the access token lives ONLY in this object's
memory, is registered with the log-redaction filter the instant it is minted,
and is never written to config, the database, the exchange root, or a log.
"""

import json
import logging
import os
import posixpath
import random
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from nj_common import ALLOWED_INSTANCES, RedactionFilter, redact

log = logging.getLogger("njc.api")

USER_AGENT = "ninjaone-local-connector/1.0"

# The ONLY scope this connector will ever request. Monitoring is read-only;
# `management` and `control` can mutate the tenant and are never asked for.
SCOPE = "monitoring"

# The two token endpoint shapes seen across NinjaOne instances. A POST is
# permitted to these paths and nowhere else.
TOKEN_PATHS = ("/ws/oauth/token", "/oauth/token")

DEVICE_PAGE_SIZE = 1000
ACTIVITY_PAGE_SIZE = 500
ACTIVITY_COUNT_PARAM = "count"   # per NinjaOne docs; pageSize is not used here
TOKEN_REFRESH_MARGIN = 300       # refresh proactively at <5 min remaining
MAX_ACTIVITY_PAGES = 200         # backstop against a pathological cursor loop


class ApiError(Exception):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


class AuthError(ApiError):
    """401/403 — retried at most once with a fresh token, then failed cleanly.
    Never retried in a loop: bad or revoked client credentials must surface."""


class RequestRejected(ApiError):
    """Client-side validation failure; no connection was opened."""


_ssl_ctx = None
# POSIX only: on Windows create_default_context() populates from the ROOT
# store, and there is no equivalent file to fall back to.
SYSTEM_CA_BUNDLE = None if os.name == "nt" else "/etc/ssl/cert.pem"


def build_ssl_context():
    """Return (context, detail, repaired).

    python.org framework builds ship with an EMPTY CA trust store until
    "Install Certificates.command" is run — ssl imports fine while every HTTPS
    call dies with CERTIFICATE_VERIFY_FAILED. Such an interpreter is repaired
    from the macOS system bundle; verification is NEVER disabled. If the repair
    is unavailable too, the context is unusable and the caller must fail.

    This is the single implementation of that rule. The runtime client and
    `doctor` both call it, so they can never disagree about whether this
    interpreter can actually verify certificates.
    """
    ctx = ssl.create_default_context()
    count = ctx.cert_store_stats().get("x509_ca", 0)
    if count > 0:
        return ctx, f"{count} CA certs", False
    if SYSTEM_CA_BUNDLE and os.path.exists(SYSTEM_CA_BUNDLE):
        try:
            ctx.load_verify_locations(SYSTEM_CA_BUNDLE)
        except (OSError, ssl.SSLError):
            pass
        count = ctx.cert_store_stats().get("x509_ca", 0)
        if count > 0:
            return ctx, (
                f"interpreter's own trust store is empty; repaired from the macOS "
                f"system bundle ({count} CA certs). HTTPS verification is working, "
                f"but running \"Install Certificates.command\" for this Python would "
                f"make it self-sufficient"), True
    if os.name == "nt":
        return None, (
            "ssl trust store is EMPTY — this Python cannot verify HTTPS. A "
            "normal Windows build populates it from the system ROOT store, so "
            "this is usually an embeddable or stripped interpreter. Install a "
            "standard build (winget install -e --id Python.Python.3.12) and "
            "re-run install.ps1 to pin it.")
    return None, (
        "ssl trust store is EMPTY and the macOS system CA bundle did not repair it "
        "— this Python cannot verify HTTPS. Run \"Install Certificates.command\" for "
        "it, or re-run install.sh to pin a working interpreter."), False


def _ssl_context():
    global _ssl_ctx
    if _ssl_ctx is None:
        ctx, detail, repaired = build_ssl_context()
        if ctx is None:
            raise ApiError(detail)
        if repaired:
            log.info("TLS trust store: %s", detail)
        _ssl_ctx = ctx
    return _ssl_ctx


class NjClient:
    def __init__(self, instance, client_id, client_secret,
                 token_path=TOKEN_PATHS[0], sleeper=time.sleep, opener=None):
        instance = (instance or "").strip().lower()
        if instance not in ALLOWED_INSTANCES:
            raise RequestRejected(
                f"Unknown NinjaOne instance {instance!r}; allowed: "
                f"{', '.join(ALLOWED_INSTANCES)}")
        if token_path not in TOKEN_PATHS:
            raise RequestRejected(f"Unknown token path {token_path!r}")
        self.host = instance
        self.token_path = token_path
        self._client_id = client_id
        self._client_secret = client_secret
        RedactionFilter.add_secret(client_secret)
        self._sleep = sleeper
        self._urlopen = opener or urllib.request.urlopen
        # Token state — memory only, never persisted.
        self._token = None
        self._token_expires_at = 0.0
        self.granted_scope = None
        self.scope_warning = None

    # ------------------------------------------------------------ choke point

    def _build_url(self, method, path, params=None):
        """Every outbound request is built here and nowhere else.

        GET is the only method allowed for the API surface. POST is allowed
        exclusively for the fixed OAuth token paths — that single carve-out is
        what lets the connector authenticate without opening a general write
        channel."""
        if method == "POST":
            if path not in TOKEN_PATHS:
                raise RequestRejected(
                    "read-only connector: POST is permitted only for the OAuth "
                    f"token endpoint, not {path!r}")
            if params:
                raise RequestRejected(
                    "the token POST carries form-encoded grant parameters in its "
                    "body only; query parameters are not permitted")
            return f"https://{self.host}{path}"
        if method != "GET":
            raise RequestRejected(
                f"read-only connector: method {method!r} is not permitted")
        if not isinstance(path, str) or not path:
            raise RequestRejected("path must be a non-empty string")
        if "\\" in path or any(ord(c) < 0x20 or ord(c) == 0x7F or c == " " for c in path):
            raise RequestRejected("path contains illegal characters")
        parsed = urllib.parse.urlsplit(path)
        if parsed.scheme or parsed.netloc:
            raise RequestRejected("absolute URLs are not allowed; pass a /v2/ path")
        # Validate the DECODED form too: the server percent-decodes, so
        # /v2/%2e%2e/x would otherwise escape the prefix server-side. Decode
        # repeatedly so double-encoded traversal cannot slip through.
        candidates = [parsed.path]
        decoded = parsed.path
        for _ in range(3):
            once = urllib.parse.unquote(decoded)
            if once == decoded:
                break
            decoded = once
            candidates.append(decoded)
        for candidate in candidates:
            if ".." in candidate.split("/") or "\\" in candidate:
                raise RequestRejected("path traversal is not allowed")
            if any(ord(c) < 0x20 or ord(c) == 0x7F for c in candidate):
                raise RequestRejected("path contains illegal characters")
            if not posixpath.normpath(candidate).startswith("/v2/"):
                raise RequestRejected("path must be under /v2/")
        norm = posixpath.normpath(parsed.path)
        url = f"https://{self.host}{norm}"
        query = {}
        if parsed.query:
            query.update(urllib.parse.parse_qsl(parsed.query))
        if params:
            for k, v in params.items():
                if not isinstance(k, str) or not isinstance(v, (str, int, float, bool)):
                    raise RequestRejected("query params must be scalar values")
                query[k] = v
        if query:
            url += "?" + urllib.parse.urlencode(query)
        if urllib.parse.urlsplit(url).hostname != self.host:
            raise RequestRejected("request escaped the configured NinjaOne host")
        return url

    # ----------------------------------------------------------------- tokens

    def _mint_token(self):
        """The one POST this connector can make. Body is form-encoded grant
        parameters; the resulting token is registered for redaction before it
        can reach any log line, and is never written anywhere."""
        url = self._build_url("POST", self.token_path)
        body = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": SCOPE,
        }).encode()
        request = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "User-Agent": USER_AGENT})
        try:
            with self._urlopen(request, timeout=60, context=_ssl_context()) as resp:
                payload = json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            if e.code in (400, 401, 403):
                raise AuthError(
                    f"NinjaOne rejected the client credentials ({e.code}). The Client "
                    "ID/Secret are wrong, expired, or revoked, or the API client is "
                    "not enabled for client-credentials with the Monitoring scope. "
                    "Not retrying.", e.code)
            raise ApiError(f"token request failed: HTTP {e.code}", e.code)
        except urllib.error.URLError as e:
            raise ApiError(f"cannot reach {self.host} for a token: {e.reason}")

        token = payload.get("access_token")
        if not token:
            raise AuthError("token response contained no access_token")
        RedactionFilter.add_secret(token)
        self._token = token
        expires_in = payload.get("expires_in")
        try:
            expires_in = int(expires_in)
        except (TypeError, ValueError):
            expires_in = 3600
        self._token_expires_at = time.time() + max(60, expires_in)
        self._check_scope(payload.get("scope"))
        log.info("minted a bearer token (expires in %ss, scope %r)",
                 expires_in, self.granted_scope)
        return token

    def _check_scope(self, granted):
        """Hard constraint 3a: we only ever ASK for monitoring. If the tenant
        granted more, the connector still never issues a mutating request, but
        the over-grant is a tenant misconfiguration worth shouting about."""
        self.granted_scope = granted
        self.scope_warning = None
        if granted is None:
            return
        scopes = {s for s in re.split(r"[\s,]+", str(granted)) if s}
        extra = scopes - {SCOPE}
        if extra:
            self.scope_warning = (
                f"NinjaOne granted this API client broader scope than requested: "
                f"{sorted(extra)}. The connector never issues a non-GET request, but "
                f"you should edit the API client in NinjaOne (Administration → Apps → "
                f"API) to allow ONLY the Monitoring scope.")
            log.warning("%s", self.scope_warning)

    def _bearer(self):
        if self._token and time.time() < self._token_expires_at - TOKEN_REFRESH_MARGIN:
            return self._token
        return self._mint_token()

    def invalidate_token(self):
        self._token = None
        self._token_expires_at = 0.0

    # -------------------------------------------------------------- transport

    def api_get(self, path, params=None):
        """Generic read. Callable for ANY GET under /v2/, which is what keeps
        the full read API available to the skill without code changes."""
        url = self._build_url("GET", path, params)
        retries_5xx = 0
        retries_429 = 0
        auth_retried = False
        while True:
            token = self._bearer()
            headers = {"Authorization": f"Bearer {token}",
                       "Accept": "application/json",
                       "User-Agent": USER_AGENT}
            request = urllib.request.Request(url, headers=headers, method="GET")
            try:
                with self._urlopen(request, timeout=90, context=_ssl_context()) as resp:
                    body = resp.read()
                    return json.loads(body) if body and body.strip() else None
            except urllib.error.HTTPError as e:
                if e.code == 401 and not auth_retried:
                    # The token may have been revoked or expired early. Refresh
                    # exactly once, then give up — never loop on auth.
                    auth_retried = True
                    self.invalidate_token()
                    log.info("401 from NinjaOne; refreshing the token once and retrying")
                    continue
                if e.code in (401, 403):
                    raise AuthError(
                        f"NinjaOne authentication failed ({e.code}) after a token "
                        "refresh: the client credentials are invalid, revoked, or "
                        "lack the Monitoring scope. Not retrying.", e.code)
                if e.code == 429:
                    retries_429 += 1
                    if retries_429 > 8:
                        raise ApiError(
                            "still rate-limited after 8 waits; giving up this cycle", 429)
                    retry_after = e.headers.get("Retry-After", "60")
                    wait = int(retry_after) if str(retry_after).isdigit() else 60
                    log.info("429 rate-limited; sleeping %ss", wait)
                    self._sleep(min(wait, 300))
                    continue
                if 500 <= e.code < 600:
                    retries_5xx += 1
                    if retries_5xx > 5:
                        raise ApiError(
                            f"NinjaOne server error {e.code}; gave up after 5 retries",
                            e.code)
                    self._sleep(min(60, 2 ** retries_5xx + random.uniform(0, 1)))
                    continue
                try:
                    detail = e.read()[:200].decode("utf-8", "replace")
                except Exception:
                    detail = ""
                raise ApiError(f"HTTP {e.code} from NinjaOne: {redact(detail)}", e.code)
            except urllib.error.URLError as e:
                retries_5xx += 1
                if retries_5xx > 5:
                    raise ApiError(f"cannot reach {self.host}: {e.reason}")
                self._sleep(min(60, 2 ** retries_5xx))
                continue

    # ----------------------------------------------------- named endpoints

    def probe(self):
        """Cheapest read-only call that proves credentials + reachability."""
        return self.api_get("/v2/organizations", {"pageSize": 1})

    def organizations(self):
        return self.api_get("/v2/organizations") or []

    def locations(self):
        return self.api_get("/v2/locations") or []

    def iter_devices(self, page_size=DEVICE_PAGE_SIZE, detailed=False):
        """Cursor-walk /v2/devices with the `after` device-id cursor. The list
        is ordered by id, so the highest id in a batch is the next cursor —
        that is stable even if the page is short or contains duplicates."""
        path = "/v2/devices-detailed" if detailed else "/v2/devices"
        after = 0
        while True:
            batch = self.api_get(path, {"pageSize": page_size, "after": after}) or []
            if not batch:
                return
            highest = after
            for device in batch:
                try:
                    highest = max(highest, int(device.get("id")))
                except (TypeError, ValueError):
                    continue
            # A server that ignores `after` would hand back the same page
            # forever. Detect that BEFORE yielding, so the repeat page is never
            # emitted at all.
            if highest <= after:
                log.warning("device cursor did not advance past %s; stopping the walk",
                            after)
                return
            yield from batch
            if len(batch) < page_size:
                return
            after = highest

    def device(self, device_id):
        return self.api_get(f"/v2/device/{int(device_id)}")

    def device_alerts(self, device_id):
        return self.api_get(f"/v2/device/{int(device_id)}/alerts") or []

    def device_activities(self, device_id, count=100):
        data = self.api_get(f"/v2/device/{int(device_id)}/activities",
                            {ACTIVITY_COUNT_PARAM: count})
        return _activity_rows(data)

    def alerts(self):
        """/v2/alerts is inherently current-state: the triggered conditions
        right now, with no history."""
        return self.api_get("/v2/alerts") or []

    def iter_activities(self, newer_than=None, count=ACTIVITY_PAGE_SIZE,
                        max_pages=MAX_ACTIVITY_PAGES):
        """Walk the audit stream forward with the `newerThan` activity-id
        cursor. Yields every activity with an id greater than newer_than."""
        cursor = int(newer_than) if newer_than else 0
        for _ in range(max_pages):
            params = {ACTIVITY_COUNT_PARAM: count}
            if cursor:
                params["newerThan"] = cursor
            rows = _activity_rows(self.api_get("/v2/activities", params))
            if not rows:
                return
            highest = cursor
            for row in rows:
                yield row
                try:
                    highest = max(highest, int(row.get("id")))
                except (TypeError, ValueError):
                    continue
            if len(rows) < count or highest <= cursor:
                return
            cursor = highest
        log.warning("activity walk stopped at the %d-page backstop", max_pages)

    def iter_activities_older(self, older_than=None, count=ACTIVITY_PAGE_SIZE,
                              max_pages=MAX_ACTIVITY_PAGES):
        """Walk the audit stream BACKWARD with the `olderThan` activity-id
        cursor. This is the shape a historical (live-scope) query needs, since
        the cache only ever holds the retention window."""
        cursor = int(older_than) if older_than else None
        for _ in range(max_pages):
            params = {ACTIVITY_COUNT_PARAM: count}
            if cursor:
                params["olderThan"] = cursor
            rows = _activity_rows(self.api_get("/v2/activities", params))
            if not rows:
                return
            lowest = None
            for row in rows:
                yield row
                try:
                    row_id = int(row.get("id"))
                except (TypeError, ValueError):
                    continue
                lowest = row_id if lowest is None else min(lowest, row_id)
            if (len(rows) < count or lowest is None
                    or (cursor is not None and lowest >= cursor)):
                return
            cursor = lowest
        log.warning("historical activity walk stopped at the %d-page backstop", max_pages)


def _activity_rows(payload):
    """/v2/activities answers with {"activities": [...], "lastActivityId": N}
    on some instances and a bare list on others. Accept both."""
    if payload is None:
        return []
    if isinstance(payload, dict):
        rows = payload.get("activities")
        return rows if isinstance(rows, list) else []
    return payload if isinstance(payload, list) else []
