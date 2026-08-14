import hashlib
import json
from pathlib import Path
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parents[1]
VECTOR_ROOT = REPO_ROOT / "tests" / "vectors"
WIRE_ERRORS = {
    "TRUNCATED", "TRAILING_BYTES", "PACKET_CAP", "BINDING_BUDGET",
    "LENGTH_OVERFLOW", "VERSION", "PROFILE", "TRAFFIC_CLASS",
    "NEXT_HEADER", "HOP_LIMIT", "FLAGS", "PATH_SLOT", "SCID",
    "NONE_PAYLOAD", "CTL_SHORT", "CTL_TYPE", "CTL_CODE", "CTL_BODY",
    "CTL_CHECKSUM", "DGRAM_SHORT", "DGRAM_LENGTH", "DGRAM_CHECKSUM",
}
PREREGISTRATION_HASHES = {
    "Q1": "048557f2d2a0058400eb3b72c3932f392960edf21bcdc775217e5201f370b73c",
    "Q2": "12f678e6af04b1377bb977cf17da7f3a08bd2f0f9b3b30c43d4e6f072dbd840d",
    "Q3": "86de498d4690d9de98333d8a99b74c985e8561e57f060b7c6bb68a833ba58cbf",
}
COMPUTED_ZERO_PACKETS = {
    "ctl-computed-zero-encoded-ffff": "8000000801400000000000000000000000112233445566778899aabbccddeeffffeeddccbbaa998877665544332211000100ffff1234ecc2",
    "dgram-computed-zero-encoded-ffff": "8000000b02400000000000000000000000112233445566778899aabbccddeeffffeeddccbbaa9988776655443322110012345678000bffff5a3b3d",
}
SES_PRECEDENCE_CONFLICTS = {
    "ses-conflict-scid-bad-profile": "SCID",
    "ses-conflict-scid-short": "SCID",
    "ses-conflict-short-bad-profile": "TRUNCATED",
    "ses-conflict-version-profile": "VERSION",
    "ses-conflict-profile-traffic-class": "PROFILE",
    "ses-conflict-traffic-class-hop": "TRAFFIC_CLASS",
    "ses-conflict-hop-flags": "HOP_LIMIT",
    "ses-conflict-flags-slot": "FLAGS",
}
CARRIER_EXPECTATIONS = {
    "ses-binding-budget-before-version": {
        "udp4": "BINDING_BUDGET",
        "udp6": "BINDING_BUDGET",
        "native": "SCID",
    },
}
OUTER_DISPATCH_CONFLICTS = {
    "dispatch-unknown-next-header-before-header-fields": "NEXT_HEADER",
    "dispatch-version-before-unknown-next-header": "VERSION",
}
MOBILITY_NEGATIVE_OPERATIONS = {
    "parse_control", "validate_update", "submit_update", "receive_probe",
    "receive_response", "receive_result", "replay_control", "validate_roles",
}
SESSION_ERRORS = {
    "AUTH_FAILED", "COOKIE_INVALID", "PIN_MISMATCH", "ROLE_MISMATCH",
    "SERVICE_MISMATCH", "EID_KEY_MISMATCH", "COUNTER_RANGE",
    "COUNTER_EXHAUSTED", "REPLAY", "CAPACITY", "RESTART_REQUIRED",
    "UNEXPECTED_MESSAGE", "SCID_COLLISION", "TRUNCATED", "TRAILING_BYTES",
    "TIMEOUT", "BUDGET", "BINDING_INVALID", "CONFIG_ERROR", "RNG_FAILURE",
    "E-CANDIDATE", "E-CAPACITY", "E-TIMEOUT", "E-REPLAY",
}
T0_SERVER_KEY_OFFSET = (
    len(b"R8 session transcript v1") + 1 + 1 + 8 + 1 + 1 + 4 + 16 + 32 + 16
)


def load(path):
    return json.loads(path.read_text())


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def assert_canonical_binding(test_case, value):
    encoded = bytes.fromhex(value)
    if encoded[0] == 1:
        test_case.assertIn(encoded[1], {4, 6})
        test_case.assertEqual(len(encoded), 25 if encoded[1] == 4 else 37)
    elif encoded[0] == 2:
        test_case.assertEqual(len(encoded), 11)
    else:
        test_case.fail("unknown binding type")



class VectorContractsTest(unittest.TestCase):
    def test_manifest_strictly_validates(self):
        schema = load(VECTOR_ROOT / "schema.json")
        manifest = load(VECTOR_ROOT / "manifest.json")
        errors = list(Draft202012Validator(schema).iter_errors(manifest))
        self.assertEqual(errors, [])

    def test_wire_manifest_exactly_bijects_real_corpus_cases(self):
        manifest = load(VECTOR_ROOT / "manifest.json")
        corpus_path = VECTOR_ROOT / "wire-v0.2.json"
        corpus = load(corpus_path)
        corpus_cases = {
            case["id"]: case
            for group in ("positive_cases", "negative_cases", "binding_boundary_cases")
            for case in corpus[group]
        }
        real = [
            fixture for fixture in manifest["fixtures"]
            if fixture["status"] == "real"
            and fixture["artifact"]["path"] == "tests/vectors/wire-v0.2.json"
        ]
        mapped = [case_id for fixture in real for case_id in fixture["case_ids"]]
        self.assertEqual(len(mapped), len(set(mapped)))
        self.assertEqual(set(mapped), set(corpus_cases))
        artifact_hash = sha256(corpus_path)
        for fixture in real:
            self.assertEqual(fixture["artifact"]["sha256"], artifact_hash)
            case = corpus_cases[fixture["case_ids"][0]]
            if fixture["kind"] == "positive-bytes":
                self.assertEqual(fixture["expected_bytes"], case["packet_hex"])
            else:
                self.assertEqual(fixture["expected_error_category"], case["expected_error"])

    def test_error_categories_and_planned_fixtures(self):
        manifest = load(VECTOR_ROOT / "manifest.json")
        corpus = load(VECTOR_ROOT / "wire-v0.2.json")
        self.assertTrue(all(case["expected_error"] in WIRE_ERRORS for case in corpus["negative_cases"]))
        for fixture in manifest["fixtures"]:
            if fixture["status"] == "planned":
                self.assertFalse({"expected_bytes", "expected_error_category", "artifact", "case_ids"} & fixture.keys())

    def test_independently_fixed_computed_zero_packets(self):
        corpus = load(VECTOR_ROOT / "wire-v0.2.json")
        by_id = {case["id"]: case for case in corpus["positive_cases"]}
        for case_id, expected_hex in COMPUTED_ZERO_PACKETS.items():
            self.assertEqual(by_id[case_id]["packet_hex"], expected_hex)
            self.assertIn("ffff", expected_hex)
            self.assertEqual(by_id[case_id]["checksum"], "ones-complement-pseudo-header-computed-zero-ffff")
    def test_ses_precedence_conflicts(self):
        corpus = load(VECTOR_ROOT / "wire-v0.2.json")
        by_id = {case["id"]: case for case in corpus["negative_cases"]}
        self.assertEqual(corpus["ses_outer_envelope_conflict_cases"], list(SES_PRECEDENCE_CONFLICTS))
        self.assertEqual(
            {case_id: by_id[case_id]["expected_error"] for case_id in SES_PRECEDENCE_CONFLICTS},
            SES_PRECEDENCE_CONFLICTS,
        )
    def test_complete_finite_carrier_expectations(self):
        corpus = load(VECTOR_ROOT / "wire-v0.2.json")
        by_id = {case["id"]: case for case in corpus["negative_cases"]}
        for case_id, expected in CARRIER_EXPECTATIONS.items():
            actual = by_id[case_id]["carrier_expectations"]
            self.assertEqual(set(actual), {"udp4", "udp6", "native"})
            self.assertTrue(set(actual.values()) <= WIRE_ERRORS)
            self.assertEqual(actual, expected)
    def test_outer_dispatch_conflicts(self):
        corpus = load(VECTOR_ROOT / "wire-v0.2.json")
        by_id = {case["id"]: case for case in corpus["negative_cases"]}
        self.assertEqual(corpus["outer_dispatch_conflict_cases"], list(OUTER_DISPATCH_CONFLICTS))
        self.assertEqual(
            {case_id: by_id[case_id]["expected_error"] for case_id in OUTER_DISPATCH_CONFLICTS},
            OUTER_DISPATCH_CONFLICTS,
        )
    def test_session_corpus_and_manifest_bijection(self):
        manifest = load(VECTOR_ROOT / "manifest.json")
        corpus_path = VECTOR_ROOT / "session-v0.1.json"
        corpus = load(corpus_path)
        self.assertTrue(corpus["synthetic_only"])
        self.assertEqual(
            corpus["synthetic_material_notice"],
            "SYNTHETIC-NON-OPERATIONAL: fixed test-only material; never a runtime default or deployable credential.",
        )
        cases = {
            case["id"]: case
            for group in ("positive_cases", "negative_cases")
            for case in corpus[group]
        }
        fixtures = [
            fixture for fixture in manifest["fixtures"]
            if fixture["status"] == "real"
            and fixture["artifact"]["path"] == "tests/vectors/session-v0.1.json"
        ]
        mapped = [case_id for fixture in fixtures for case_id in fixture["case_ids"]]
        self.assertEqual(set(mapped), set(cases))
        self.assertEqual(len(mapped), len(set(mapped)))
        digest = sha256(corpus_path)
        for fixture in fixtures:
            self.assertEqual(fixture["artifact"]["sha256"], digest)
            case = cases[fixture["case_ids"][0]]
            if fixture["kind"] == "positive-bytes":
                expected = case.get("payload_hex") or case["protected"]["packet_hex"]
                self.assertEqual(fixture["expected_bytes"], expected)
                self.assertEqual(
                    case["exact_size"],
                    len(bytes.fromhex(expected)),
                )
            else:
                self.assertIn(case["expected_error"], SESSION_ERRORS)
                self.assertEqual(fixture["expected_error_category"], case["expected_error"])
        self.assertEqual(
            set(corpus["finite_state_cli_categories"]),
            {case["expected_error"] for case in corpus["negative_cases"]},
        )
        for case in corpus["negative_cases"]:
            if case["expected_error"] in {
                "TIMEOUT", "BUDGET", "BINDING_INVALID", "CONFIG_ERROR", "RNG_FAILURE",
            }:
                self.assertEqual(
                    set(case["contract_reference"]),
                    {"document", "section"},
                )
        mobility_corpus = load(VECTOR_ROOT / "mobility-v0.1.json")
        mobility_cases = {
            case["id"]: case
            for group in ("positive_cases", "negative_cases")
            for case in mobility_corpus[group]
        }
        mobility_fixtures = [
            fixture for fixture in manifest["fixtures"]
            if fixture["status"] == "real"
            and fixture["artifact"]["path"] == "tests/vectors/mobility-v0.1.json"
        ]
        mobility_mapped = [
            case_id for fixture in mobility_fixtures for case_id in fixture["case_ids"]
        ]
        self.assertTrue(mobility_corpus["synthetic_only"])
        self.assertEqual(set(mobility_mapped), set(mobility_cases))
        self.assertEqual(len(mobility_mapped), len(set(mobility_mapped)))
        mobility_digest = sha256(VECTOR_ROOT / "mobility-v0.1.json")
        for fixture in mobility_fixtures:
            self.assertEqual(fixture["artifact"]["sha256"], mobility_digest)
            case = mobility_cases[fixture["case_ids"][0]]
            self.assertIn(case["expected_error"], SESSION_ERRORS) if fixture["kind"] == "negative-error" else self.assertEqual(fixture["expected_bytes"], case["plaintext_hex"])
            self.assertEqual(
                set(case["contract_reference"]),
                {"document", "section"},
            ) if fixture["kind"] == "negative-error" else None
        schema = load(VECTOR_ROOT / "schema.json")
        mobility_case_schema = schema["$defs"]["mobilityNegativeCase"]
        for case in mobility_corpus["negative_cases"]:
            self.assertIn(case["operation"], MOBILITY_NEGATIVE_OPERATIONS)
            self.assertRegex(case["input_hex"], r"^(?:[0-9a-f]{2})+$")
            self.assertTrue(case["setup"])
            self.assertEqual(
                list(Draft202012Validator(mobility_case_schema).iter_errors(case)),
                [],
            )
        self.assertEqual(
            len({case["id"] for case in mobility_corpus["negative_cases"]}),
            len(mobility_corpus["negative_cases"]),
        )
        self.assertEqual(len(mobility_corpus["negative_cases"]), 43)
        def audit_bindings(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key.endswith("binding_hex"):
                        assert_canonical_binding(self, item)
                    audit_bindings(item)
            elif isinstance(value, list):
                for item in value:
                    audit_bindings(item)

        for case in mobility_corpus["negative_cases"]:
            audit_bindings(case["setup"])
            retry = case["setup"].get("retry") or case["setup"].get("same_id_retry")
            if retry and retry.get("byte_identical") is False:
                self.assertNotEqual(
                    retry["prior_input_hex"],
                    retry["submitted_input_hex"],
                )
        context_schema = schema["$defs"]["mobilityContext"]
        self.assertEqual(
            list(Draft202012Validator(context_schema).iter_errors(mobility_corpus["context"])),
            [],
        )
        context = mobility_corpus["context"]
        client_public_key = bytes.fromhex(context["client_public_key_hex"])
        server_public_key = bytes.fromhex(context["server_public_key_hex"])
        self.assertEqual(
            hashlib.sha256(b"R8 EID v1" + client_public_key).digest()[:16].hex(),
            context["client_eid_hex"],
        )
        self.assertEqual(
            hashlib.sha256(b"R8 EID v1" + server_public_key).digest()[:16].hex(),
            context["server_eid_hex"],
        )
        loc_update = next(
            case for case in mobility_corpus["positive_cases"]
            if case["id"] == "mobility-loc-update"
        )
        Ed25519PublicKey.from_public_bytes(client_public_key).verify(
            bytes.fromhex(loc_update["signature_hex"]),
            bytes.fromhex(loc_update["signature_input_hex"]),
        )
        wire_corpus = load(VECTOR_ROOT / "wire-v0.2.json")
        wire_cases = {
            case["id"]
            for group in ("positive_cases", "negative_cases", "binding_boundary_cases")
            for case in wire_corpus[group]
        }
        all_real = [
            fixture for fixture in manifest["fixtures"] if fixture["status"] == "real"
        ]
        all_mapped = [case_id for fixture in all_real for case_id in fixture["case_ids"]]
        self.assertEqual(
            len(all_mapped),
            len(wire_cases) + len(cases) + len(mobility_cases),
        )
        self.assertEqual(
            {
                (fixture["artifact"]["path"], case_id)
                for fixture in all_real
                for case_id in fixture["case_ids"]
            },
            {("tests/vectors/wire-v0.2.json", case_id) for case_id in wire_cases}
            | {("tests/vectors/session-v0.1.json", case_id) for case_id in cases}
            | {("tests/vectors/mobility-v0.1.json", case_id) for case_id in mobility_cases},
        )
    def test_placeholder_transcript_uses_zero_server_key(self):
        corpus = load(VECTOR_ROOT / "session-v0.1.json")
        placeholder = bytes.fromhex(corpus["transcript"]["placeholder_t0_hex"])
        actual = bytes.fromhex(corpus["transcript"]["actual_t0_hex"])
        pinned_server_key = bytes.fromhex(corpus["identities"]["server_public_key_hex"])
        key_slice = slice(T0_SERVER_KEY_OFFSET, T0_SERVER_KEY_OFFSET + 32)
        self.assertEqual(placeholder[key_slice], b"\0" * 32)
        self.assertEqual(actual[key_slice], pinned_server_key)
    def test_verify_cookie_prevalidation_amplification_bound(self):
        corpus = load(VECTOR_ROOT / "session-v0.1.json")
        bound = corpus["prevalidation_amplification"]
        self.assertEqual(bound["open_payload_bytes"], 122)
        self.assertEqual(bound["verify_cookie_payload_bytes"], 122)
        self.assertEqual(bound["open_serialized_r8_bytes"], 170)
        self.assertEqual(bound["verify_cookie_serialized_r8_bytes"], 170)
        self.assertLessEqual(
            bound["verify_cookie_serialized_r8_bytes"],
            bound["open_serialized_r8_bytes"],
        )

    def test_preregistration_hashes(self):
        manifest = load(REPO_ROOT / "bench" / "protocols" / "manifest.json")
        by_id = {entry["protocol_id"]: entry for entry in manifest["preregistrations"]}
        for protocol_id, expected_hash in PREREGISTRATION_HASHES.items():
            entry = by_id[protocol_id]
            path = REPO_ROOT / entry["path"]
            self.assertEqual(entry["sha256"], expected_hash)
            self.assertEqual(sha256(path), expected_hash)
            self.assertEqual(load(path)["protocol_id"], protocol_id)
        q1_superseded = by_id["Q1"]["superseded"]
        self.assertIn(
            {
                "contract_version": "r8-benchmark-preregistration-v1",
                "sha256": "a63788866da7a7b0cfbb8af0b07f96a0ddc041b2926d04debe8ee48e83cd5960",
                "status": "superseded-no-results",
            },
            q1_superseded,
        )


if __name__ == "__main__":
    unittest.main()
