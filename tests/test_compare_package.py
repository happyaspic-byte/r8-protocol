import json
import pathlib
import tempfile
import unittest
from unittest import mock
from bench.compare import run, validate


class TestComparePackage(unittest.TestCase):
    def test_smoke_package_creation_retains_ineligible_prerequisites(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            out = pathlib.Path(temp_dir) / "pkg"
            with mock.patch("bench.compare.quic_runner.aioquic_available", return_value=False), \
                 mock.patch("bench.compare.mptcp_runner.mptcp_available", return_value=False):
                code = run.run_package(out, smoke=True)
            self.assertEqual(code, 0)
            self.assertTrue((out / "manifest.json").exists())
            self.assertTrue((out / "trial.jsonl").exists())
            self.assertEqual(json.loads((out / "publication_eligible.json").read_text()), False)
            errors = validate.validate_package(out)
            self.assertEqual(errors, [])

    def test_validator_rejects_tampered_bound_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            out = pathlib.Path(temp_dir) / "pkg"
            with mock.patch("bench.compare.quic_runner.aioquic_available", return_value=False), \
                 mock.patch("bench.compare.mptcp_runner.mptcp_available", return_value=False):
                run.run_package(out, smoke=True)
            (out / "trial.jsonl").write_text("tampered\n")
            self.assertIn("sha mismatch on trial.jsonl", validate.validate_package(out))
