"""Secret containment. Acceptance tests 1 and 2.

Neither the OAuth client secret nor a minted bearer token may appear anywhere
under either root after a full setup + sync + bridge cycle, in any encoding.
"""

import base64
import json
import logging
import unittest
import urllib.parse

from tests.base import (ConnectorCase, DUMMY_CLIENT_ID, DUMMY_SECRET,
                        DUMMY_TOKEN, MockHttp, make_activity, make_alert,
                        make_client, make_device)

from nj_common import RedactionFilter, app_root, redact, save_config


def needles():
    """Every form a secret could plausibly take on disk."""
    forms = []
    for secret in (DUMMY_SECRET, DUMMY_TOKEN):
        forms.append(secret.encode())
        forms.append(base64.b64encode(secret.encode()))
        forms.append(base64.b64encode(f"{secret}:X".encode()))
        forms.append(base64.b64encode(f"Bearer {secret}".encode()))
        forms.append(urllib.parse.quote(secret).encode())
        forms.append(secret.encode().hex().encode())
    return forms


def sweep(*roots):
    """Return [(path, needle)] for every secret form found in every file."""
    hits = []
    patterns = needles()
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                blob = path.read_bytes()
            except OSError:
                continue
            for needle in patterns:
                if needle in blob:
                    hits.append((str(path), needle.decode("utf-8", "replace")))
    return hits


class FullCycleLeakSweep(ConnectorCase):
    """Acceptance test 1: run the whole thing, then grep both roots."""

    def _full_cycle(self):
        from nj_bridge import Bridge
        from nj_common import setup_logging
        from nj_sync import SyncEngine

        save_config(self.cfg)
        setup_logging(debug=True)

        http = MockHttp().token_route()
        http.json_route("/v2/organizations", [{"id": 10, "name": "Contoso"}])
        http.json_route("/v2/locations", [{"id": 100, "organizationId": 10,
                                           "name": "HQ"}])
        http.json_route("/v2/devices", [make_device(1), make_device(2, offline=True)])
        http.json_route("/v2/alerts", [make_alert("a1")])
        http.json_route("/v2/activities", {"activities": [make_activity(5)]})
        client = make_client(http)

        engine = SyncEngine(self.cfg, client=client)
        self.addCleanup(engine.con.close)
        engine.ensure_fresh()
        engine.interval_sync(force=True)
        engine.morning_reset()

        bridge = Bridge(self.cfg, engine=engine)
        for rid, action, params in (
                ("s1", "status", {}),
                ("s2", "sync_now", {}),
                ("s3", "query_devices", {"offline": True}),
                ("s4", "query_alerts", {}),
                ("s5", "query_activities", {}),
                ("s6", "get_device", {"device_id": 1}),
                ("s7", "api_get", {"path": "/v2/queries/os-patches"}),
                ("s8", "export", {"entity": "devices", "format": "csv",
                                  "filename": "devices_out"}),
                # Deliberate failures: error paths must not echo secrets either.
                ("s9", "api_get", {"path": "/v1/nope"}),
                ("s10", "query_devices", {"org": "Nope"}),
        ):
            self.write_request(bridge, action, params, rid=rid)
        bridge.drain()
        # The token really was minted and used, or this test proves nothing.
        self.assertGreaterEqual(http.token_mint_count, 1)
        self.assertEqual(client._token, DUMMY_TOKEN)
        return engine

    def test_no_secret_or_token_anywhere_under_either_root(self):
        self._full_cycle()
        hits = sweep(app_root(), self.exchange_root)
        self.assertEqual(hits, [], f"secret material leaked to disk: {hits}")

    def test_config_holds_no_credential_material(self):
        self._full_cycle()
        config = json.loads((app_root() / "config.json").read_text())
        blob = json.dumps(config)
        self.assertNotIn(DUMMY_SECRET, blob)
        self.assertNotIn(DUMMY_TOKEN, blob)
        self.assertNotIn(DUMMY_CLIENT_ID, blob)
        self.assertNotIn("access_token", blob)
        self.assertNotIn("password", blob)

    def test_responses_and_manifest_hold_no_credential_material(self):
        engine = self._full_cycle()
        for path in list(engine.exchange.responses.iterdir()) + [engine.exchange.manifest]:
            blob = path.read_text()
            self.assertNotIn(DUMMY_SECRET, blob, path.name)
            self.assertNotIn(DUMMY_TOKEN, blob, path.name)

    def test_token_is_written_by_no_code_path(self):
        """Acceptance test 2, final clause: a filesystem sweep specifically for
        the bearer token, including the private app root and its logs."""
        self._full_cycle()
        token_hits = [h for h in sweep(app_root(), self.exchange_root)
                      if DUMMY_TOKEN in h[1]]
        self.assertEqual(token_hits, [])


class RedactionFilterBehavior(unittest.TestCase):
    def test_registered_secrets_are_masked(self):
        RedactionFilter.add_secret(DUMMY_SECRET)
        RedactionFilter.add_secret(DUMMY_TOKEN)
        self.assertNotIn(DUMMY_SECRET, redact(f"secret={DUMMY_SECRET} end"))
        self.assertNotIn(DUMMY_TOKEN, redact(f"Authorization: Bearer {DUMMY_TOKEN}"))

    def test_header_patterns_are_masked_even_when_unregistered(self):
        unknown = "unregistered0token0value0000"
        self.assertNotIn(unknown, redact(f"Authorization: Bearer {unknown}"))
        self.assertNotIn(unknown, redact(f"bearer {unknown}"))
        self.assertNotIn(unknown, redact(f'"authorization": "{unknown}"'))

    def test_form_body_and_json_token_shapes_are_masked(self):
        self.assertNotIn("s3cr3tvalue", redact(
            "grant_type=client_credentials&client_secret=s3cr3tvalue&scope=monitoring"))
        self.assertNotIn("tok3nvalue", redact('{"access_token": "tok3nvalue"}'))

    def test_filter_rewrites_log_records(self):
        RedactionFilter.add_secret(DUMMY_TOKEN)
        record = logging.LogRecord("t", logging.INFO, __file__, 1,
                                   "using token %s", (DUMMY_TOKEN,), None)
        RedactionFilter().filter(record)
        self.assertNotIn(DUMMY_TOKEN, record.getMessage())

    def test_short_values_are_not_registered(self):
        """A 3-character 'secret' would redact half the log file."""
        before = set(RedactionFilter._secrets)
        RedactionFilter.add_secret("abc")
        self.assertEqual(set(RedactionFilter._secrets), before)


class TokenNeverPersisted(ConnectorCase):
    def test_client_exposes_no_serialization_of_the_token(self):
        client = make_client()
        client.api_get("/v2/organizations")
        state = {k: v for k, v in vars(client).items()
                 if isinstance(v, (str, int, float, type(None)))}
        # The token attribute exists in memory but is not part of anything the
        # connector serializes; assert no *other* attribute mirrors it.
        mirrors = [k for k, v in state.items()
                   if v == DUMMY_TOKEN and k != "_token"]
        self.assertEqual(mirrors, [])

    def test_manifest_never_includes_auth_fields(self):
        engine = self.make_engine()
        manifest = engine.manifest()
        for key in manifest:
            self.assertNotIn("token", key.lower())
            self.assertNotIn("secret", key.lower())
            self.assertNotIn("client_id", key.lower())


if __name__ == "__main__":
    unittest.main()
