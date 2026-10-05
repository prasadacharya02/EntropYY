"""Control-plane authorization tests for the attacker console.

The console can start and kill processes, so its control routes are
gated.  This file pins the two accepted ways in — loopback peer or the
per-process operator token — because the demo browser reaches the
console through a reverse proxy and is *not* on loopback.

These tests exercise the real ``control_authorized`` function with a
stub handler; no network or server process is needed.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ATTACKER_APP = os.path.join(ROOT, "attacker_server", "app.py")
HTML_TEMPLATE = os.path.join(ROOT, "attacker_server", "templates", "attacker.html")


def _load_attacker_module():
    spec = importlib.util.spec_from_file_location("attacker_server_app", ATTACKER_APP)
    module = importlib.util.module_from_spec(spec)
    sys.modules["attacker_server_app"] = module
    spec.loader.exec_module(module)
    return module


class _StubHandler:
    """Minimal stand-in exposing what control_authorized() reads."""

    def __init__(self, peer_address, headers=None):
        self.client_address = (peer_address, 40000)
        self.headers = headers or {}


class ControlAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = _load_attacker_module()

    def test_session_token_is_generated_and_not_a_placeholder(self):
        token = self.app.control_token()
        self.assertTrue(token)
        self.assertFalse(token.startswith("__"))
        self.assertGreaterEqual(len(token), 16)

    def test_loopback_ipv4_allowed(self):
        self.assertTrue(self.app.control_authorized(_StubHandler("127.0.0.1")))

    def test_loopback_ipv6_allowed(self):
        self.assertTrue(self.app.control_authorized(_StubHandler("::1")))

    def test_remote_peer_without_token_denied(self):
        self.assertFalse(self.app.control_authorized(_StubHandler("203.0.113.9")))

    def test_remote_peer_with_session_token_allowed(self):
        handler = _StubHandler(
            "203.0.113.9",
            {"Authorization": f"Bearer {self.app.control_token()}"},
        )
        self.assertTrue(self.app.control_authorized(handler))

    def test_remote_peer_with_wrong_token_denied(self):
        handler = _StubHandler(
            "203.0.113.9", {"Authorization": "Bearer not-the-token"}
        )
        self.assertFalse(self.app.control_authorized(handler))

    def test_missing_peer_address_denied(self):
        handler = _StubHandler("not-an-ip")
        self.assertFalse(self.app.control_authorized(handler))

    def test_same_site_browser_request_allowed(self):
        """The launch button works through a preview proxy: the page's own
        Origin matches the Host the request was served on."""
        handler = _StubHandler(
            "10.12.0.172",
            {
                "Host": "8001-demo.e2b.app",
                "Origin": "https://8001-demo.e2b.app",
            },
        )
        self.assertTrue(self.app.control_authorized(handler))

    def test_same_site_via_referer_allowed(self):
        handler = _StubHandler(
            "10.12.0.172",
            {
                "Host": "8001-demo.e2b.app",
                "Referer": "https://8001-demo.e2b.app/index.html",
            },
        )
        self.assertTrue(self.app.control_authorized(handler))

    def test_foreign_origin_denied(self):
        handler = _StubHandler(
            "10.12.0.172",
            {"Host": "8001-demo.e2b.app", "Origin": "https://evil.example"},
        )
        self.assertFalse(self.app.control_authorized(handler))

    def test_origin_without_host_header_denied(self):
        handler = _StubHandler("10.12.0.172", {"Origin": "https://8001-demo.e2b.app"})
        self.assertFalse(self.app.control_authorized(handler))

    def test_forwarded_host_counts_as_served_host(self):
        handler = _StubHandler(
            "10.12.0.172",
            {
                "Host": "internal:8001",
                "X-Forwarded-Host": "8001-demo.e2b.app",
                "Origin": "https://8001-demo.e2b.app",
            },
        )
        self.assertTrue(self.app.control_authorized(handler))

    def test_console_page_template_has_token_slot(self):
        with open(HTML_TEMPLATE, "r", encoding="utf-8") as handle:
            template = handle.read()
        self.assertIn("__CONTROL_TOKEN__", template)
        self.assertIn('const CONTROL_TOKEN = "__CONTROL_TOKEN__";', template)

    def test_configured_token_overrides_generated_one(self):
        """A pinned ENTROPY_CONTROL_TOKEN must be what the gate accepts."""
        import config

        if config.CONTROL_TOKEN:
            self.assertEqual(self.app.control_token(), config.CONTROL_TOKEN)
        else:
            self.assertTrue(self.app.control_token_is_generated())


if __name__ == "__main__":
    unittest.main()
