import unittest
from ours.driver import fill_wave
from ours.oracle import (
    FlowControlObservation,
    Verdict,
    evaluate_connection_window_invariant,
)


class FillWaveTests(unittest.TestCase):
    def test_896(self):
        self.assertEqual(fill_wave(896), (71, 126))

    def test_equation(self):
        body = 896
        additional, range_end = fill_wave(body)
        total = 2 * body + additional * body + (range_end + 1)
        self.assertEqual(total, 65535)


class OracleTests(unittest.TestCase):
    def test_vulnerable_signal(self):
        obs = FlowControlObservation(
            expected_fc_reset_streams=(149, 151),
            rst_errors={149: 3, 151: 3},
            canary_body=b"0123456789",
            expected_canary_body=b"0123456789",
            post_refund_ping_acked=True,
            negotiated_h2=True,
        )
        report = evaluate_connection_window_invariant(obs)
        self.assertEqual(report.verdict, Verdict.VULNERABLE)
        self.assertTrue(report.all_passed)

    def test_missing_ping(self):
        obs = FlowControlObservation(
            expected_fc_reset_streams=(149, 151),
            rst_errors={149: 3, 151: 3},
            canary_body=b"0123456789",
            expected_canary_body=b"0123456789",
            post_refund_ping_acked=False,
            negotiated_h2=True,
        )
        report = evaluate_connection_window_invariant(obs)
        self.assertEqual(report.verdict, Verdict.NOT_PROVEN)

    def test_no_h2(self):
        obs = FlowControlObservation(
            expected_fc_reset_streams=(),
            rst_errors={},
            canary_body=b"",
            expected_canary_body=b"",
            post_refund_ping_acked=False,
            negotiated_h2=False,
        )
        report = evaluate_connection_window_invariant(obs)
        self.assertEqual(report.verdict, Verdict.NOT_PROVEN)


if __name__ == "__main__":
    unittest.main()
