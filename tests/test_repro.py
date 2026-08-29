import os
import unittest
from unittest import mock

from bench import repro


class TestReproducibilityBundle(unittest.TestCase):
    def test_ci_cannot_self_claim_independence(self):
        with mock.patch.dict(os.environ, {"CI": "true"}, clear=False), mock.patch.object(
            repro, "_git", side_effect=["a" * 40, "b" * 40, ""]
        ):
            bundle = repro.build_bundle(
                mock.Mock(), reproducer_identity="project-ci", evidence_path="evidence.json"
            )
        self.assertFalse(bundle["attestation"]["independent_reproducer"])
        self.assertIsNone(bundle["attestation"]["reproducer_identity"])

    def test_independent_claim_requires_identity_and_evidence(self):
        bundle = {
            "schema": repro.SCHEMA_VERSION,
            "commit": "a" * 40,
            "tree": "b" * 40,
            "environment": {"ci": False},
            "attestation": {"independent_reproducer": True},
        }
        errors = repro.validate_bundle(bundle)
        self.assertIn("independent_reproducer requires identity", errors)
        self.assertIn("independent_reproducer requires evidence", errors)

    def test_nonexistent_evidence_cannot_claim_independence(self):
        env = {key: value for key, value in os.environ.items() if key not in {"CI", "GITHUB_ACTIONS"}}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
            repro, "_git", side_effect=["a" * 40, "b" * 40, ""]
        ):
            bundle = repro.build_bundle(
                mock.Mock(),
                reproducer_identity="external-lab",
                evidence_path="/no/such/r8-evidence.json",
            )
        self.assertFalse(bundle["attestation"]["independent_reproducer"])
        self.assertIsNone(bundle["attestation"].get("evidence_sha256"))

    def test_project_ci_identity_cannot_claim_independence(self):
        import tempfile
        from pathlib import Path

        env = {key: value for key, value in os.environ.items() if key not in {"CI", "GITHUB_ACTIONS"}}
        with tempfile.TemporaryDirectory() as temp_dir:
            evidence = Path(temp_dir) / "evidence.json"
            evidence.write_text("{}\n")
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
                repro, "_git", side_effect=["a" * 40, "b" * 40, ""]
            ):
                bundle = repro.build_bundle(
                    mock.Mock(),
                    reproducer_identity="project-ci",
                    evidence_path=str(evidence),
                )
        self.assertFalse(bundle["attestation"]["independent_reproducer"])

    def test_third_party_evidence_binds_sha256(self):
        import tempfile
        from pathlib import Path

        env = {key: value for key, value in os.environ.items() if key not in {"CI", "GITHUB_ACTIONS"}}
        with tempfile.TemporaryDirectory() as temp_dir:
            evidence = Path(temp_dir) / "evidence.json"
            evidence.write_text('{"lab":"external"}\n')
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
                repro, "_git", side_effect=["a" * 40, "b" * 40, ""]
            ):
                bundle = repro.build_bundle(
                    mock.Mock(),
                    reproducer_identity="external-lab",
                    evidence_path=str(evidence),
                )
            self.assertFalse(bundle["attestation"]["independent_reproducer"])
            self.assertEqual(bundle["attestation"]["evidence_sha256"], repro.sha256_hex(evidence.read_bytes()))
            self.assertEqual(repro.validate_bundle(bundle), [])
