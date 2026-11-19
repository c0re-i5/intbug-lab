"""Offline tests for cleanup_overcredit tuning + Status.INCONCLUSIVE."""
import unittest
from pathlib import Path

from ours.oracle import Status
from ours.targets import TARGETS, get_target

_REPO = Path(__file__).resolve().parents[2]
_OPENRESTY_DIGEST = (
    "sha256:2cb90d64192934c26b3749cf744f47edd59277787fe761bd109eeebdc3e2214a"
)
_NODE_DIGEST = (
    "sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a"
)
_HAPROXY_DIGEST = (
    "sha256:7430e63d3052198b18a40665b59a5826bc428e8bceb0c561d82258149ef855ee"
)
_OLS_DIGEST = (
    "sha256:48bc2719f24c4a451f13c379f499e9822f00aeae9ed248fea6d934d4a4231d50"
)


class StatusTests(unittest.TestCase):
    def test_inconclusive_exists(self):
        self.assertEqual(Status.INCONCLUSIVE.value, "INCONCLUSIVE")


class CleanupTuningTests(unittest.TestCase):
    def test_nginx_vuln_keeps_full_pressure_no_fallback(self):
        t = get_target("nginx-1.31.8")
        self.assertIsNone(t.key_updates)  # library default = full KU
        self.assertIsNone(t.fallback_key_updates)

    def test_nginx_patched_no_fallback(self):
        t = get_target("nginx-1.31.9")
        self.assertIsNone(t.fallback_key_updates)

    def test_openresty_full_pressure_digest_lockstep(self):
        t = get_target("openresty-1.31.8.1")
        self.assertEqual(t.role, "nginx-family")
        self.assertTrue(t.supports_h2)
        self.assertEqual(t.url, "https://127.0.0.1:19452/")
        self.assertIsNone(t.key_updates)
        self.assertIsNone(t.carrier_app_bytes)
        self.assertIsNone(t.fallback_key_updates)
        self.assertIsNone(t.fallback_carrier_app_bytes)
        self.assertIn(_OPENRESTY_DIGEST, t.image)
        for rel in (
            "ours/targets.py",
            "docker-compose.yml",
            "scripts/lab-up-targets.sh",
        ):
            blob = (_REPO / rel).read_text()
            self.assertEqual(blob.count(_OPENRESTY_DIGEST), 1, rel)
        compose = (_REPO / "docker-compose.yml").read_text()
        self.assertIn("127.0.0.1:19452:443", compose)
        self.assertNotIn("0.0.0.0:19452", compose)

    def test_node_http2_soft_profile_digest_lockstep(self):
        t = get_target("node-http2")
        self.assertEqual(t.role, "cross-impl")
        self.assertTrue(t.supports_h2)
        self.assertEqual(t.url, "https://127.0.0.1:19454/")
        self.assertEqual(t.key_updates, 0)
        self.assertEqual(t.carrier_app_bytes, 200_000)
        self.assertIsNone(t.fallback_key_updates)
        self.assertIsNone(t.fallback_carrier_app_bytes)
        self.assertIn(_NODE_DIGEST, t.image)
        for rel in (
            "ours/targets.py",
            "docker-compose.yml",
            "scripts/lab-up-targets.sh",
        ):
            blob = (_REPO / rel).read_text()
            self.assertEqual(blob.count(_NODE_DIGEST), 1, rel)
        compose = (_REPO / "docker-compose.yml").read_text()
        self.assertIn("integer-lab-node:pinned", compose)
        self.assertIn("127.0.0.1:19454:443", compose)
        self.assertNotIn("0.0.0.0:19454", compose)
        self.assertNotIn("0.0.0.0:19453", compose)

    def test_haproxy_soft_profile_digest_lockstep(self):
        t = get_target("haproxy-3.0")
        self.assertEqual(t.role, "cross-impl")
        self.assertTrue(t.supports_h2)
        self.assertEqual(t.url, "https://127.0.0.1:19453/")
        self.assertEqual(t.key_updates, 0)
        self.assertEqual(t.carrier_app_bytes, 200_000)
        self.assertIsNone(t.fallback_key_updates)
        self.assertIsNone(t.fallback_carrier_app_bytes)
        self.assertIn(_HAPROXY_DIGEST, t.image)
        self.assertIn("return", t.notes)
        for rel in (
            "ours/targets.py",
            "docker-compose.yml",
            "scripts/lab-up-targets.sh",
        ):
            blob = (_REPO / rel).read_text()
            self.assertEqual(blob.count(_HAPROXY_DIGEST), 1, rel)
        compose = (_REPO / "docker-compose.yml").read_text()
        self.assertIn("127.0.0.1:19453:443", compose)
        self.assertNotIn("0.0.0.0:19453", compose)
        up = (_REPO / "scripts/lab-up-targets.sh").read_text()
        self.assertIn("127.0.0.1:19453:443", up)
        self.assertNotIn("0.0.0.0:19453", up)

    def test_openlitespeed_soft_profile_digest_lockstep(self):
        t = get_target("openlitespeed-1.9.4")
        self.assertEqual(t.role, "cross-impl")
        self.assertTrue(t.supports_h2)
        self.assertEqual(t.url, "https://127.0.0.1:19451/")
        self.assertEqual(t.key_updates, 0)
        self.assertEqual(t.carrier_app_bytes, 200_000)
        self.assertIsNone(t.fallback_key_updates)
        self.assertIsNone(t.fallback_carrier_app_bytes)
        self.assertIn(_OLS_DIGEST, t.image)
        self.assertIn("LSWS Enterprise", t.notes)
        for rel in (
            "ours/targets.py",
            "docker-compose.yml",
            "scripts/lab-up-targets.sh",
        ):
            blob = (_REPO / rel).read_text()
            self.assertEqual(blob.count(_OLS_DIGEST), 1, rel)
        compose = (_REPO / "docker-compose.yml").read_text()
        self.assertIn("127.0.0.1:19451:443", compose)
        self.assertNotIn("0.0.0.0:19451", compose)
        self.assertNotIn("7080:7080", compose)
        self.assertNotIn("127.0.0.1:7080", compose)
        up = (_REPO / "scripts/lab-up-targets.sh").read_text()
        self.assertIn("127.0.0.1:19451:443", up)
        self.assertNotIn("0.0.0.0:19451", up)
        self.assertNotIn("7080:7080", up)

    def test_soft_stacks_use_ku0(self):
        for tid in (
            "caddy-2.10",
            "envoy-1.32",
            "go-nethttp",
            "nghttpd",
            "node-http2",
            "haproxy-3.0",
            "openlitespeed-1.9.4",
        ):
            t = get_target(tid)
            self.assertEqual(t.key_updates, 0, tid)
            self.assertEqual(t.carrier_app_bytes, 200_000, tid)

    def test_envoy_restart_hook(self):
        self.assertEqual(get_target("envoy-1.32").restart_container, "integer-lab-envoy")

    def test_all_still_loopback(self):
        for t in TARGETS.values():
            self.assertTrue(t.url.startswith("https://127.0.0.1:"))


if __name__ == "__main__":
    unittest.main()
