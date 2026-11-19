"""Offline tests for cleanup_overcredit tuning + Status.INCONCLUSIVE."""
import unittest

from ours.oracle import Status
from ours.targets import TARGETS, get_target


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

    def test_soft_stacks_use_ku0(self):
        for tid in ("caddy-2.10", "envoy-1.32", "go-nethttp", "nghttpd"):
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
