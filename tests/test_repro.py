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
