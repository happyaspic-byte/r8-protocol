import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bench.compare import lisp_runner, mptcp_runner, quic_runner, run, validate


class ObservedTopology:
    def cut_primary(self):
        return {
            "observed": True,
            "event_ns": 1,
            "control_bytes": 8,
            "subflows": 2,
            "path_bytes": {"primary": 64, "secondary": 64},
            "packets": [],
        }


class TestComparisonAdapters(unittest.TestCase):
    def test_adapters_require_isolated_topology(self):
        with mock.patch.object(quic_runner, "aioquic_available", return_value=True):
            trial, _ = quic_runner.run_quic_trial({"mechanism": "quic-migration"}, None)
        self.assertEqual(trial["status"], "prerequisite_failed")
        self.assertEqual(trial["failure_reason"], "isolated_topology_required")

        with mock.patch.object(mptcp_runner, "mptcp_available", return_value=True):
            trial, _ = mptcp_runner.run_mptcp_trial({"mechanism": "linux-mptcp"}, None)
        self.assertEqual(trial["status"], "prerequisite_failed")
        self.assertEqual(trial["failure_reason"], "isolated_topology_required")

    def test_mptcp_requires_two_observed_subflows(self):
        topo = ObservedTopology()
        with mock.patch.object(mptcp_runner, "mptcp_available", return_value=True), mock.patch.object(
            mptcp_runner.socket, "socket"
        ):
            trial, _ = mptcp_runner.run_mptcp_trial({"mechanism": "linux-mptcp"}, topo)
        self.assertEqual(trial["status"], "completed")
        self.assertEqual(trial["subflows"], 2)

    def test_lisp_preflight_fails_closed(self):
        with mock.patch.object(lisp_runner, "_which", return_value=None):
            trial, _ = lisp_runner.run_lisp_trial({"mechanism": "lisp-xtr"})
        self.assertEqual(trial["status"], "prerequisite_failed")
        self.assertEqual(trial["failure_reason"], "oor_unavailable")

    def test_lisp_config_uses_only_closed_lab_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = lisp_runner.write_local_config(Path(tmp))
            text = path.read_text()
        self.assertIn("10.8.0.1", text)
        self.assertNotIn("0.0.0.0", text)

    def test_unprivileged_smoke_is_never_publication_eligible(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            self.assertEqual(run.run_package(output, smoke=True), 0)
            self.assertEqual(validate.validate_package(output), [])
            self.assertEqual((output / "publication_eligible.json").read_text(), "false\n")
