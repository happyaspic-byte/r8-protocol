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

    def test_manifest_binds_publication_eligible_hash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            out = pathlib.Path(temp_dir) / "pkg"
            with mock.patch("bench.compare.quic_runner.aioquic_available", return_value=False), \
                 mock.patch("bench.compare.mptcp_runner.mptcp_available", return_value=False):
                run.run_package(out, smoke=True)
            manifest = json.loads((out / "manifest.json").read_text())
            self.assertIn("publication_eligible.json", manifest["files"])

    def test_validator_rejects_forged_publication_eligible(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            out = pathlib.Path(temp_dir) / "pkg"
            with mock.patch("bench.compare.quic_runner.aioquic_available", return_value=False), \
                 mock.patch("bench.compare.mptcp_runner.mptcp_available", return_value=False):
                run.run_package(out, smoke=True)
            (out / "publication_eligible.json").write_text("true\n")
            errors = validate.validate_package(out)
            self.assertTrue(errors)
            self.assertTrue(any("eligib" in error for error in errors))

    def test_validator_rejects_completed_trial_without_transfer_evidence(self):
        from bench.compare import model

        with tempfile.TemporaryDirectory() as temp_dir:
            out = pathlib.Path(temp_dir) / "pkg"
            out.mkdir()
            trial = {
                "trial_id": "a" * 64,
                "comparison": "mobility",
                "seed": 0,
                "mechanism": "quic-migration",
                "warmup": True,
                "block": 0,
                "execution_ordinal": 0,
                "status": "completed",
                "failure_reason": None,
                "cleanup_status": "passed",
            }
            (out / "trial.jsonl").write_text(model.canonical_json(trial) + "\n")
            (out / "packet.jsonl").write_text("")
            (out / "publication_eligible.json").write_text(model.canonical_json(True) + "\n")
            files = {
                "trial.jsonl": model.sha256_hex((out / "trial.jsonl").read_bytes()),
                "packet.jsonl": model.sha256_hex((out / "packet.jsonl").read_bytes()),
                "publication_eligible.json": model.sha256_hex((out / "publication_eligible.json").read_bytes()),
            }
            manifest = {
                "series": "r8-external-comparison-v1",
                "smoke": True,
                "privileged": False,
                "row_counts": {"trials": 1, "packets": 0},
                "files": files,
                "limitations": ["Isolated Linux network-namespace comparison only."],
            }
            (out / "manifest.json").write_text(model.canonical_json(manifest) + "\n")
            errors = validate.validate_package(out)
            self.assertTrue(any("transfer" in error for error in errors))
