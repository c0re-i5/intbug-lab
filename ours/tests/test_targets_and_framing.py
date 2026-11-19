"""Offline tests: target registry, framing, loopback guard. No network."""
import unittest

from ours import framing as F
from ours.battery import _assert_loopback
from ours.targets import TARGETS, get_target, list_targets


class TargetRegistryTests(unittest.TestCase):
    def test_required_ids_present(self):
        for tid in (
            "nginx-1.31.8",
            "nginx-http2-off",
            "httpd-2.4.71",
            "nginx-1.31.9",
            "caddy-2.10",
            "envoy-1.32",
            "go-nethttp",
            "nghttpd",
            "openresty-1.31.8.1",
            "node-http2",
        ):
            self.assertIn(tid, TARGETS)

    def test_all_urls_loopback_https(self):
        for t in list_targets():
            self.assertTrue(t.url.startswith("https://127.0.0.1:"), t.id)
            host, port, _path = _assert_loopback(t.url)
            self.assertEqual(host, "127.0.0.1")
            self.assertGreaterEqual(port, 19443)
            self.assertLessEqual(port, 19454)

    def test_http2_off_does_not_claim_h2(self):
        self.assertFalse(get_target("nginx-http2-off").supports_h2)

    def test_unknown_raises(self):
        with self.assertRaises(KeyError):
            get_target("no-such-target")


class LoopbackGuardTests(unittest.TestCase):
    def test_rejects_non_loopback(self):
        with self.assertRaises(ValueError):
            _assert_loopback("https://example.com/")
        with self.assertRaises(ValueError):
            _assert_loopback("https://8.8.8.8/")

    def test_rejects_http(self):
        with self.assertRaises(ValueError):
            _assert_loopback("http://127.0.0.1:19443/")

    def test_accepts_localhost(self):
        host, port, path = _assert_loopback("https://localhost:19443/index.html")
        self.assertEqual(host, "localhost")
        self.assertEqual(port, 19443)
        self.assertEqual(path, "/index.html")


class FramingTests(unittest.TestCase):
    def test_window_update_rejects_zero(self):
        with self.assertRaises(ValueError):
            F.window_update(0, 0)

    def test_window_update_raw_zero(self):
        frame = F.window_update_raw(0, 0)
        self.assertEqual(len(frame), 13)  # 9-byte hdr + 4-byte payload
        self.assertEqual(frame[3], F.WINDOW_UPDATE)

    def test_max_window_constant(self):
        self.assertEqual(F.MAX_WINDOW, 0x7FFFFFFF)

    def test_parse_roundtrip(self):
        blob = F.ping(b"INTBUG01") + F.settings_ack()
        frames, rem = F.parse_frames(blob)
        self.assertEqual(len(frames), 2)
        self.assertEqual(rem, b"")
        self.assertEqual(frames[0][0], F.PING)
        self.assertEqual(frames[1][0], F.SETTINGS)


if __name__ == "__main__":
    unittest.main()


class ZeroWUFramingTests(unittest.TestCase):
    def test_wu_zero_stream_bytes(self):
        # Exact 13-byte WINDOW_UPDATE(stream=1, incr=0) used in captures.
        frame = F.window_update_raw(1, 0)
        self.assertEqual(frame, bytes.fromhex("00000408000000000100000000"))

    def test_open_stream_headers_no_end_stream(self):
        # h2spec-aligned: END_HEADERS set, END_STREAM clear.
        block = F.request_headers("127.0.0.1:19443", "/index.html")
        frame = F.headers_frame(1, block, end_stream=False)
        self.assertEqual(frame[3], F.HEADERS)
        self.assertEqual(frame[4] & F.END_HEADERS, F.END_HEADERS)
        self.assertEqual(frame[4] & F.END_STREAM, 0)
