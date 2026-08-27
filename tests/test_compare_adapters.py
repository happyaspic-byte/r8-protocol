import unittest
from unittest import mock
from bench.compare import mptcp_runner, quic_runner


class TestCompareAdapters(unittest.TestCase):
    def setUp(self):
        self.quic_plan = {
            "trial_id": "t-quic", "comparison": "mobility", "seed": 0,
            "mechanism": "quic-migration", "warmup": True, "block": 0,
            "execution_ordinal": 0,
        }
        self.mptcp_plan = {
            "trial_id": "t-mptcp", "comparison": "redundancy", "seed": 0,
            "mechanism": "linux-mptcp", "warmup": True, "block": 0,
            "execution_ordinal": 0,
        }

    def test_adapters_expose_uniform_trial_contract(self):
        self.assertTrue(callable(quic_runner.run_quic_trial))
        self.assertTrue(callable(mptcp_runner.run_mptcp_trial))

    def test_quic_adapter_fails_closed_without_aioquic(self):
        with mock.patch.object(quic_runner, "aioquic_available", return_value=False):
            trial, packets = quic_runner.run_quic_trial(self.quic_plan, None)
        self.assertEqual(trial["status"], "prerequisite_failed")
        self.assertEqual(trial["failure_reason"], "aioquic_unavailable")
        self.assertEqual(packets, [])

    def test_mptcp_adapter_fails_closed_without_kernel_support(self):
        with mock.patch.object(mptcp_runner, "mptcp_available", return_value=False):
            trial, packets = mptcp_runner.run_mptcp_trial(self.mptcp_plan, None)
        self.assertEqual(trial["status"], "prerequisite_failed")
        self.assertEqual(trial["failure_reason"], "mptcp_unavailable")
        self.assertEqual(packets, [])

    def test_adapters_never_emit_synthetic_success(self):
        with mock.patch.object(quic_runner, "aioquic_available", return_value=True):
            trial, packets = quic_runner.run_quic_trial(self.quic_plan, None)
        self.assertEqual(trial["status"], "not_implemented")
        self.assertEqual(packets, [])
        with mock.patch.object(mptcp_runner, "mptcp_available", return_value=True):
            trial, packets = mptcp_runner.run_mptcp_trial(self.mptcp_plan, None)
        self.assertEqual(trial["status"], "not_implemented")
        self.assertEqual(packets, [])
