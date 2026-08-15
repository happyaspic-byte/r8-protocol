import hashlib
import json
import re
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
    "Q1": "3f8511b1eb19a87ad385890fd591d97dd30a8713f08dafa836492610062e4296",
    "Q2": "f2afa5030d460b3bf82fc22d91bae88631269fc59b9c640e15dd8c2578fdaea0",
    "Q3": "e5a7f57a2f9ec152edad127c84ad6a9a80b8f5b3c9e4b7299e44fd815a677e1b",
}
SESSION_CORPUS_SHA256 = "3dc2c622eab5dc4cb8477c7e75678980366ed4253e369e83db207220f34cf740"
REDUNDANT_CORPUS_SHA256 = "3e1c8cdee7d5857344cb8ea764e05e1dbfff9fa71dec54ab2457495e5b1510b0"
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
PARAMETER_VALUES = {
    "P-OPEN-TOTAL-TIMEOUT": "`5 seconds` from initial `OPEN` send through `SESSION_ACCEPT` send",
    "P-POST-COOKIE-PENDING-TIMEOUT": "`5 seconds` from server `PENDING` allocation",
    "P-SESSION-IDLE-TIMEOUT": "`120 seconds` after the last first-accepted authenticated protected packet",
    "P-HANDSHAKE-RETRY-SCHEDULE": "at most `3` retransmissions with sequential waits of `0.5 seconds`, `1 second`, then `2 seconds` (cumulative elapsed offsets `0.5`, `1.5`, and `3.5 seconds` after the initial `OPEN`)",
    "P-PREVALIDATION-CUMULATIVE-RATIO": "cumulative emitted response bytes `<=` cumulative triggering request bytes per exact observed source binding in fixed `20-second` accounting windows",
    "P-PREVALIDATION-SOURCE-TABLE-MAX": "`4096` exact-observed-source-binding accounting entries; an entry expires `20 seconds` after its last triggering request or response, and new entries are reject-new while full",
    "P-PREVALIDATION-GLOBAL-BURST": "`2000` `VERIFY_COOKIE` response tokens; consume one token per emitted response",
    "P-PREVALIDATION-GLOBAL-REFILL": "`1000` `VERIFY_COOKIE` response tokens per elapsed second; fractional tokens do not exist",
    "P-PENDING-SESSIONS-MAX": "`256` server `PENDING` sessions; reject-new while full",
    "P-ESTABLISHED-SESSIONS-MAX": "`1024` sessions in `ESTABLISHED` or `CLOSING`; reject-new while full",
    "P-Q1-BOUNDARY-SKEW-NS": "`100000000 nanoseconds`",
    "P-PROFILE3-ADMISSION-OWNER": "exactly one opaque, non-cloneable owner capability issued per Profile-3 session for one SCID and policy; only a committed mobility result may move it into a one-shot slot-one admission",
    "P-REDUNDANT-RECEIVE-PREVIEWS-MAX": "exactly `1` outstanding transactional authenticated receive preview per Profile-3 redundant session; reject-new while occupied",
    "P-DELIVERY-ID": "atomically increasing `u64` in exactly `1..u64::MAX - 1`, inclusive; zero invalid, `u64::MAX` reserved, no wrap",
    "P-DELIVERY-IDENTITY-WINDOW": "sliding numeric window containing at most the latest `4096` delivery IDs relative to the delivery high-water mark; each present ID retains a full SHA-256 digest and byte length",
}
PARAMETER_ALIASES = {
    "P-COUNTER-RESERVED": "exactly `u64::MAX`",
    "P-COUNTER-USABLE-RANGE": "exactly `1..u64::MAX - 1`, inclusive",
    "P-REPLAY-FORWARD-JUMP-MAX": "alias of `P-REPLAY-FORWARD-GAP-MAX`, exactly `65,536` counters",
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
    def test_parameter_registry_is_complete_and_exact(self):
        parameters = (REPO_ROOT / "spec" / "parameters-v0.1.md").read_text()
        entries = re.findall(r"^\| `(P-[A-Z0-9-]+)` \| (.+) \|$", parameters, re.MULTILINE)
        by_id = {}
        for parameter_id, value in entries:
            self.assertNotIn(parameter_id, by_id, parameter_id)
            by_id[parameter_id] = value
        for parameter_id, value in PARAMETER_VALUES.items():
            self.assertEqual(by_id.get(parameter_id), value)
        for parameter_id, value in PARAMETER_ALIASES.items():
            self.assertEqual(by_id.get(parameter_id), value)

        referenced = set()
        for spec in (REPO_ROOT / "spec").glob("*.md"):
            if spec.name != "parameters-v0.1.md":
                referenced.update(re.findall(r"\bP-[A-Z0-9-]+\b", spec.read_text()))
        self.assertTrue(referenced <= set(by_id), sorted(referenced - set(by_id)))

    def test_redundant_identity_window_semantics_are_normative(self):
        redundant = (REPO_ROOT / "spec" / "0008-redundant-v0.1.md").read_text()
        for required in (
            "full-plaintext cache",
            "expiry erases only plaintext, never an identity still inside the window",
            "Equal delayed copies suppress after plaintext expiry while their ID remains",
            "a divergent delayed copy closes the session",
            "an older evicted ID fails closed without redelivery",
            "session release erases identity window and plaintext cache",
            "another session or policy fails without slot mutation",
        ):
            self.assertIn(required, redundant)
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
        self.assertEqual(digest, SESSION_CORPUS_SHA256)
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
        redundant_corpus = load(VECTOR_ROOT / "redundant-v0.1.json")
        redundant_cases = {
            case["id"]
            for group in ("positive_cases", "negative_cases")
            for case in redundant_corpus[group]
        }
        all_real = [
            fixture for fixture in manifest["fixtures"] if fixture["status"] == "real"
        ]
        all_mapped = [case_id for fixture in all_real for case_id in fixture["case_ids"]]
        self.assertEqual(
            len(all_mapped),
            len(wire_cases) + len(cases) + len(mobility_cases) + len(redundant_cases),
        )
        self.assertEqual(
            {
                (fixture["artifact"]["path"], case_id)
                for fixture in all_real
                for case_id in fixture["case_ids"]
            },
            {("tests/vectors/wire-v0.2.json", case_id) for case_id in wire_cases}
            | {("tests/vectors/session-v0.1.json", case_id) for case_id in cases}
            | {("tests/vectors/mobility-v0.1.json", case_id) for case_id in mobility_cases}
            | {("tests/vectors/redundant-v0.1.json", case_id) for case_id in redundant_cases},
        )
    def test_redundant_corpus_schema_manifest_and_hash_bijection(self):
        manifest = load(VECTOR_ROOT / "manifest.json")
        corpus_path = VECTOR_ROOT / "redundant-v0.1.json"
        corpus = load(corpus_path)
        schema = load(VECTOR_ROOT / "redundant-v0.1.schema.json")
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(corpus)), [])
        self.assertTrue(corpus["synthetic_only"])
        self.assertEqual(
            corpus["synthetic_material_notice"],
            "SYNTHETIC TEST-ONLY: fixed non-operational material; never a runtime default, credential, or deployment input.",
        )
        cases = {
            case["id"]: case
            for group in ("positive_cases", "negative_cases")
            for case in corpus[group]
        }
        fixtures = [
            fixture for fixture in manifest["fixtures"]
            if fixture["status"] == "real"
            and fixture["artifact"]["path"] == "tests/vectors/redundant-v0.1.json"
        ]
        mapped = [case_id for fixture in fixtures for case_id in fixture["case_ids"]]
        self.assertEqual(len(mapped), len(set(mapped)))
        self.assertEqual(set(mapped), set(cases))
        digest = sha256(corpus_path)
        self.assertEqual(digest, REDUNDANT_CORPUS_SHA256)
        for fixture in fixtures:
            self.assertEqual(fixture["artifact"]["sha256"], digest)
            case = cases[fixture["case_ids"][0]]
            if fixture["kind"] == "positive-bytes":
                self.assertEqual(fixture["expected_bytes"], case["full_packet_hex"])
            elif fixture["kind"] == "negative-error":
                self.assertEqual(fixture["expected_error_category"], case["expected_error"])
            elif fixture["kind"] == "state-transition":
                self.assertEqual(fixture["expected_outcome"], case["expected_outcome"])
            else:
                self.fail(f"unsupported redundant fixture kind: {fixture['kind']}")
        self.assertFalse(any(
            fixture["status"] == "planned"
            and fixture.get("artifact", {}).get("path") == "tests/vectors/redundant-v0.1.json"
            for fixture in manifest["fixtures"]
        ))
        self.assertEqual(
            len({case["id"] for case in corpus["negative_cases"]}),
            len(corpus["negative_cases"]),
        )
        state_ids = [trace["id"] for trace in corpus["state_traces"]]
        self.assertEqual(len(state_ids), len(set(state_ids)))
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
        self.assertEqual(by_id["Q1"]["contract_version"], "r8-benchmark-preregistration-v5")
        self.assertEqual(by_id["Q1"]["size_bytes"], 14317)
        q1_v4 = next(item for item in q1_superseded if item["contract_version"] == "r8-benchmark-preregistration-v4")
        self.assertEqual((q1_v4["run"], q1_v4["row_count"], q1_v4["pre_runtime_setup_failures"],
                          q1_v4["complete_diagnostic_rows"], q1_v4["publication_eligible"]),
                         ("31835854041", 1320, 63, 1257, False))
        q2 = by_id["Q2"]
        self.assertEqual(q2["contract_version"], "r8-benchmark-preregistration-v5")
        self.assertEqual(q2["size_bytes"], 20050)
        self.assertEqual(
            q2["schema_bindings"],
            [
                {"path": "bench/protocols/q2-trial-v5.schema.json", "sha256": "02f4a204840f216e6b453103696f0ea8bfc0bc6272b92b87e5fdddea93bbe30c", "size_bytes": 5508},
                {"path": "bench/protocols/q2-packet-v5.schema.json", "sha256": "6db0bf37dead1602d6ff67d0278e484356cf1a68dd89c9c4e65e1ab9038a6594", "size_bytes": 3699},
                {"path": "bench/protocols/q2-evidence-v5.schema.json", "sha256": "649d4368dcab8305f9db7479537d4e2c896e50b94cf7fad0737379306f696771", "size_bytes": 8898},
            ],
        )
        self.assertEqual(
            [(item["contract_version"], item["sha256"], item["size_bytes"]) for item in q2["superseded"]],
            [
                ("r8-benchmark-preregistration-v1", "12f678e6af04b1377bb977cf17da7f3a08bd2f0f9b3b30c43d4e6f072dbd840d", 3367),
                ("r8-benchmark-preregistration-v2", "376a944a155f40690acc5016db7d00cb8a0e12e249204ec5e3233471cdb9f545", 6939),
                ("r8-benchmark-preregistration-v3", "2e624e5801c2a42e7176204ba3f945e507e694273b85edb688b1e532a15f3e1f", 12704),
                ("r8-benchmark-preregistration-v4", "739021d7abf34ee8921de112e368aa41511116a426ab9d71a808d52a4836197b", 8711),
            ],
        )
        for binding in q2["schema_bindings"]:
            path = REPO_ROOT / binding["path"]
            self.assertEqual(binding["sha256"], sha256(path))
            self.assertEqual(binding["size_bytes"], path.stat().st_size)
        self.assertEqual(manifest["status"], "frozen-preregistrations-with-evidence-history")
        q3 = by_id["Q3"]
        self.assertEqual(q3["status"], "frozen-preregistered-no-current-source-results")
        self.assertEqual(q3["size_bytes"], 4353)
        self.assertEqual(len(q3["prior_source_evidence"]), 1)
        evidence = q3["prior_source_evidence"][0]
        self.assertEqual(evidence["status"], "historical-prior-source-evidence-not-current-contract")
        self.assertEqual((evidence["workflow_run"], evidence["git_commit"], evidence["row_count"],
                          evidence["warmup_count"], evidence["failure_count"]),
                         ("31835193766", "881826bb64bc38bbbbffe7ab9cdcedecc98a82e2",
                          4200, 200, 0))
        package = REPO_ROOT / evidence["retained_package_path"]
        for name, field in (("environment.json", "environment_sha256"),
                            ("raw.jsonl", "raw_sha256"),
                            ("run-manifest.json", "run_manifest_sha256"),
                            ("summary.json", "summary_sha256")):
            self.assertEqual(sha256(package / name), evidence[field])


if __name__ == "__main__":
    unittest.main()
