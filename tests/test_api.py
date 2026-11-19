"""API client: the read-only choke point, token lifecycle, scope guard,
cursor pagination, and path validation. Acceptance tests 2, 3, 4, 5, 6, 10.
"""

import io
import os
import ssl
import unittest
import urllib.error
import urllib.parse
from unittest import mock

from tests.base import (DUMMY_SECRET, DUMMY_TOKEN, MockHttp, MockResponse,
                        ConnectorCase, make_activity, make_client, make_device)

from nj_api import (ApiError, AuthError, NjClient, RequestRejected, SCOPE,
                    TOKEN_PATHS)


def query_of(url):
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))


class ReadOnlyChokePoint(unittest.TestCase):
    """Acceptance test 4: no non-GET can be constructed, except the one
    permitted POST to the fixed token path."""

    def setUp(self):
        self.http = MockHttp().token_route()
        self.client = make_client(self.http)

    def test_every_mutating_method_is_rejected(self):
        for method in ("PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE",
                       "get", "Get", ""):
            with self.subTest(method=method):
                with self.assertRaises(RequestRejected):
                    self.client._build_url(method, "/v2/devices", None)
        # Nothing above opened a connection.
        self.assertEqual(self.http.requests, [])

    def test_post_is_rejected_for_every_path_but_the_token_endpoint(self):
        for path in ("/v2/devices", "/v2/organizations", "/ws/oauth/tokenx",
                     "/oauth/tokens", "/v2/queries/software"):
            with self.subTest(path=path):
                with self.assertRaises(RequestRejected):
                    self.client._build_url("POST", path, None)
        self.assertEqual(self.http.requests, [])

    def test_post_is_permitted_only_for_the_fixed_token_paths(self):
        for path in TOKEN_PATHS:
            url = self.client._build_url("POST", path, None)
            self.assertEqual(url, f"https://app.ninjarmm.com{path}")

    def test_token_post_refuses_query_parameters(self):
        with self.assertRaises(RequestRejected):
            self.client._build_url("POST", TOKEN_PATHS[0], {"client_secret": "x"})

    def test_unknown_instance_is_refused(self):
        with self.assertRaises(RequestRejected):
            NjClient("evil.example.com", "id", "secret")
        with self.assertRaises(RequestRejected):
            NjClient("app.ninjarmm.com.evil.com", "id", "secret")


class PathValidation(unittest.TestCase):
    """Acceptance test 10: api_get cannot be steered off /v2/ or off-host."""

    def setUp(self):
        self.http = MockHttp().token_route()
        self.client = make_client(self.http)

    def test_rejected_paths(self):
        bad = [
            "/v2/../v1/admin",
            "/v2/%2e%2e/v1/admin",
            "/v2/%252e%252e/v1/admin",       # double-encoded
            "/v2/devices/../../etc/passwd",
            "https://evil.example.com/v2/devices",
            "//evil.example.com/v2/devices",
            "http://app.ninjarmm.com/v2/devices",
            "/v1/devices",
            "/ws/oauth/token",               # not a GET target
            "/v2/dev ices",
            "/v2/devices\n/x",
            "/v2/devices\x00",
            "/v2/devices\x7f",
            "\\v2\\devices",
            "",
        ]
        for path in bad:
            with self.subTest(path=path):
                with self.assertRaises(RequestRejected):
                    self.client._build_url("GET", path, None)
        self.assertEqual(self.http.requests, [])

    def test_accepted_paths_stay_on_host(self):
        for path in ("/v2/devices", "/v2/organizations",
                     "/v2/device/12/alerts", "/v2/queries/os-patches"):
            url = self.client._build_url("GET", path, None)
            self.assertTrue(url.startswith("https://app.ninjarmm.com/v2/"), url)

    def test_query_params_must_be_scalars(self):
        with self.assertRaises(RequestRejected):
            self.client._build_url("GET", "/v2/devices", {"df": ["a", "b"]})
        with self.assertRaises(RequestRejected):
            self.client._build_url("GET", "/v2/devices", {"df": {"nested": 1}})

    def test_embedded_query_cannot_override_host(self):
        url = self.client._build_url("GET", "/v2/devices?pageSize=5", None)
        self.assertEqual(urllib.parse.urlsplit(url).hostname, "app.ninjarmm.com")


class TokenLifecycle(unittest.TestCase):
    """Acceptance tests 2 and 3."""

    def test_token_request_always_asks_for_monitoring_only(self):
        http = MockHttp().token_route().json_route("/v2/organizations", [])
        client = make_client(http)
        client.api_get("/v2/organizations")
        token_requests = [r for r in http.requests if "oauth/token" in r.full_url]
        self.assertEqual(len(token_requests), 1)
        body = dict(urllib.parse.parse_qsl(token_requests[0].data.decode()))
        self.assertEqual(body["scope"], SCOPE)
        self.assertEqual(body["scope"], "monitoring")
        self.assertEqual(body["grant_type"], "client_credentials")
        self.assertNotIn("management", body["scope"])
        self.assertNotIn("control", body["scope"])
        self.assertEqual(token_requests[0].get_method(), "POST")
        self.assertEqual(
            token_requests[0].get_header("Content-type"),
            "application/x-www-form-urlencoded")

    def test_broader_granted_scope_triggers_the_warning_path(self):
        http = MockHttp().token_route(scope="monitoring management control")
        http.json_route("/v2/organizations", [])
        client = make_client(http)
        client.api_get("/v2/organizations")
        self.assertIsNotNone(client.scope_warning)
        self.assertIn("management", client.scope_warning)
        self.assertIn("control", client.scope_warning)

    def test_monitoring_only_grant_produces_no_warning(self):
        http = MockHttp().token_route(scope="monitoring")
        http.json_route("/v2/organizations", [])
        client = make_client(http)
        client.api_get("/v2/organizations")
        self.assertIsNone(client.scope_warning)

    def test_token_is_reused_until_close_to_expiry(self):
        http = MockHttp().token_route().json_route("/v2/organizations", [])
        client = make_client(http)
        for _ in range(4):
            client.api_get("/v2/organizations")
        self.assertEqual(http.token_mint_count, 1)

    def test_token_refreshes_proactively_near_expiry(self):
        # expires_in below the 300 s refresh margin forces a mint per call.
        http = MockHttp().token_route(expires_in=60).json_route("/v2/organizations", [])
        client = make_client(http)
        client.api_get("/v2/organizations")
        client.api_get("/v2/organizations")
        self.assertEqual(http.token_mint_count, 2)

    def test_401_causes_exactly_one_refresh_and_retry(self):
        http = MockHttp().token_route()
        state = {"first": True}

        def devices(request):
            if state["first"]:
                state["first"] = False
                raise urllib.error.HTTPError(request.full_url, 401, "unauthorized",
                                             {}, io.BytesIO(b""))
            return MockResponse([make_device(1)])

        http.route(lambda r: "/v2/devices" in r.full_url, devices)
        client = make_client(http)
        result = client.api_get("/v2/devices")
        self.assertEqual(len(result), 1)
        self.assertEqual(http.token_mint_count, 2)   # initial + one refresh

    def test_persistent_401_aborts_cleanly_without_looping(self):
        http = MockHttp().token_route().error_route("/v2/devices", 401)
        client = make_client(http)
        with self.assertRaises(AuthError):
            client.api_get("/v2/devices")
        self.assertEqual(http.token_mint_count, 2)   # one refresh, then give up
        device_calls = [r for r in http.requests if "/v2/devices" in r.full_url]
        self.assertEqual(len(device_calls), 2)

    def test_403_is_not_retried_at_all(self):
        http = MockHttp().token_route().error_route("/v2/devices", 403)
        client = make_client(http)
        with self.assertRaises(AuthError):
            client.api_get("/v2/devices")
        device_calls = [r for r in http.requests if "/v2/devices" in r.full_url]
        self.assertEqual(len(device_calls), 1)

    def test_bad_credentials_fail_cleanly_at_the_token_endpoint(self):
        http = MockHttp().error_route("oauth/token", 400)
        client = make_client(http)
        with self.assertRaises(AuthError):
            client.api_get("/v2/devices")

    def test_token_never_appears_in_client_state_on_disk(self):
        """The token lives in memory only; nothing about it is serializable
        into config. (The filesystem sweep is in test_secrets.py.)"""
        http = MockHttp().token_route().json_route("/v2/organizations", [])
        client = make_client(http)
        client.api_get("/v2/organizations")
        self.assertEqual(client._token, DUMMY_TOKEN)
        client.invalidate_token()
        self.assertIsNone(client._token)


class RateLimiting(unittest.TestCase):
    def test_429_honors_retry_after_then_succeeds(self):
        http = MockHttp().token_route()
        http.error_route("/v2/devices", 429, headers={"Retry-After": "1"}, times=2)
        slept = []
        client = make_client(http)
        client._sleep = slept.append
        self.assertEqual(client.api_get("/v2/devices"), [])
        self.assertEqual(slept, [1, 1])

    def test_5xx_backs_off_and_gives_up_after_five_retries(self):
        http = MockHttp().token_route().error_route("/v2/devices", 503)
        slept = []
        client = make_client(http)
        client._sleep = slept.append
        with self.assertRaises(ApiError):
            client.api_get("/v2/devices")
        self.assertEqual(len(slept), 5)


class DevicePagination(unittest.TestCase):
    """Acceptance test 5: the `after` cursor crosses page boundaries with no
    dropped or duplicated devices."""

    def _paged_http(self, total, page_size):
        http = MockHttp().token_route()
        all_devices = [make_device(i) for i in range(1, total + 1)]

        def devices(request):
            params = query_of(request.full_url)
            after = int(params.get("after", 0))
            size = int(params.get("pageSize", page_size))
            batch = [d for d in all_devices if d["id"] > after][:size]
            return MockResponse(batch)

        http.route(lambda r: r.full_url.startswith(
            "https://app.ninjarmm.com/v2/devices"), devices)
        return http

    def test_multi_page_walk_is_complete_and_unique(self):
        http = self._paged_http(total=2500, page_size=1000)
        client = make_client(http)
        ids = [d["id"] for d in client.iter_devices(page_size=1000)]
        self.assertEqual(len(ids), 2500)
        self.assertEqual(len(set(ids)), 2500)
        self.assertEqual(ids, sorted(ids))
        # 3 pages of devices (1000/1000/500) — the short page ends the walk.
        device_calls = [r for r in http.requests if "/v2/devices" in r.full_url]
        self.assertEqual(len(device_calls), 3)

    def test_exact_multiple_of_page_size_terminates(self):
        http = self._paged_http(total=2000, page_size=1000)
        client = make_client(http)
        ids = [d["id"] for d in client.iter_devices(page_size=1000)]
        self.assertEqual(len(ids), 2000)
        self.assertEqual(len(set(ids)), 2000)

    def test_cursor_that_fails_to_advance_stops_the_walk(self):
        """A server that ignores `after` must not spin the client forever."""
        http = MockHttp().token_route()
        http.json_route("/v2/devices", [make_device(1), make_device(2)])
        client = make_client(http)
        ids = [d["id"] for d in client.iter_devices(page_size=2)]
        self.assertEqual(ids, [1, 2])


class ActivityWindowing(unittest.TestCase):
    """Acceptance test 6: newerThan cursor windowing, no gaps or duplicates."""

    def _stream_http(self, ids, page_size):
        http = MockHttp().token_route()
        rows = [make_activity(i) for i in ids]

        def activities(request):
            params = query_of(request.full_url)
            count = int(params.get("count", page_size))
            if "newerThan" in params:
                newer = int(params["newerThan"])
                batch = [a for a in rows if a["id"] > newer]
            elif "olderThan" in params:
                older = int(params["olderThan"])
                batch = sorted([a for a in rows if a["id"] < older],
                               key=lambda a: a["id"], reverse=True)
            else:
                batch = sorted(rows, key=lambda a: a["id"], reverse=True)
            return MockResponse({"activities": batch[:count],
                                 "lastActivityId": max(ids)})

        http.route(lambda r: "/v2/activities" in r.full_url, activities)
        return http

    def test_forward_walk_captures_the_stream_without_gaps(self):
        """A delta walk from a known cursor must cross page boundaries with
        neither a gap nor a duplicate."""
        ids = list(range(1000, 1250))
        http = self._stream_http(ids, page_size=100)
        client = make_client(http)
        seen = [a["id"] for a in client.iter_activities(newer_than=999, count=100)]
        self.assertEqual(sorted(seen), sorted(set(seen)))   # no duplicates
        self.assertEqual(set(seen), set(ids))               # no gaps

    def test_cold_forward_walk_only_reaches_the_newest_page(self):
        """Without a cursor a forward walk cannot reach back in time — which is
        exactly why sync_activities cold-starts with the backward walk."""
        ids = list(range(1000, 1250))
        http = self._stream_http(ids, page_size=100)
        client = make_client(http)
        seen = [a["id"] for a in client.iter_activities(newer_than=None, count=100)]
        self.assertEqual(len(seen), 100)
        self.assertEqual(max(seen), 1249)

    def test_forward_walk_respects_the_cursor(self):
        ids = list(range(1000, 1100))
        http = self._stream_http(ids, page_size=50)
        client = make_client(http)
        seen = [a["id"] for a in client.iter_activities(newer_than=1049, count=50)]
        self.assertEqual(set(seen), set(range(1050, 1100)))

    def test_backward_walk_is_used_for_history(self):
        ids = list(range(1000, 1100))
        http = self._stream_http(ids, page_size=25)
        client = make_client(http)
        seen = [a["id"] for a in client.iter_activities_older(count=25)]
        self.assertEqual(set(seen), set(ids))
        self.assertEqual(seen, sorted(seen, reverse=True))

    def test_bare_list_response_shape_is_accepted(self):
        http = MockHttp().token_route()
        http.json_route("/v2/activities", [make_activity(7)])
        client = make_client(http)
        self.assertEqual([a["id"] for a in client.iter_activities(count=500)], [7])


class TlsTrustStore(unittest.TestCase):
    """One implementation of the trust-store rule, shared by the runtime client
    and `doctor`, so the two can never disagree about whether this interpreter
    can verify certificates."""

    def test_healthy_store_is_reported_as_native(self):
        from nj_api import build_ssl_context
        context, detail, repaired = build_ssl_context()
        self.assertIsNotNone(context)
        self.assertFalse(repaired)
        self.assertIn("CA certs", detail)

    def test_empty_store_is_repaired_from_the_system_bundle(self):
        import ssl as _ssl

        import nj_api
        real = _ssl.create_default_context

        def empty_context(*a, **kw):
            ctx = real(*a, **kw)
            # A context with no roots loaded is what a python.org build ships.
            return _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT) if True else ctx

        with mock.patch.object(_ssl, "create_default_context", empty_context):
            context, detail, repaired = nj_api.build_ssl_context()
        if os.path.exists(nj_api.SYSTEM_CA_BUNDLE):
            self.assertIsNotNone(context)
            self.assertTrue(repaired)
            self.assertIn("system bundle", detail)
        else:
            self.assertIsNone(context)

    def test_unrepairable_store_yields_no_context_and_a_clear_remedy(self):
        import ssl as _ssl

        import nj_api

        def empty_context(*a, **kw):
            return _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)

        with mock.patch.object(_ssl, "create_default_context", empty_context), \
                mock.patch.object(nj_api, "SYSTEM_CA_BUNDLE", "/nonexistent/ca.pem"):
            context, detail, repaired = nj_api.build_ssl_context()
        self.assertIsNone(context)
        self.assertFalse(repaired)
        self.assertIn("Install Certificates.command", detail)

    def test_verification_is_never_disabled(self):
        """No code path may produce a context that skips verification."""
        from nj_api import build_ssl_context
        context, _, _ = build_ssl_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)


class NetworkGuard(unittest.TestCase):
    """Acceptance test 4 (final clause): the guard itself works."""

    def test_guard_blocks_dns_and_connect(self):
        import socket
        with self.assertRaises(AssertionError):
            socket.getaddrinfo("app.ninjarmm.com", 443)
        with self.assertRaises(AssertionError):
            socket.create_connection(("app.ninjarmm.com", 443))

    def test_real_client_without_a_mock_opener_cannot_reach_the_network(self):
        client = NjClient("app.ninjarmm.com", "id-value-1234", "secret-value-1234567890")
        with self.assertRaises((AssertionError, ApiError)):
            client.api_get("/v2/organizations")


if __name__ == "__main__":
    unittest.main()
