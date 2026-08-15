import copy
import hashlib
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
from bench import q2


def digest(value="fixed"):
    return hashlib.sha256(value.encode()).hexdigest()


def identity(row, field):
    value = dict(row)
    value.pop(field, None)
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def valid_rows():
    plan = next(row for row in q2.plan_rows() if row["seed"] == 0 and row["condition"] == "no-flap" and row["mechanism"] == "REDUNDANT")
    trial = {**{key: plan[key] for key in plan if key != "warmup"}, "status": "completed", "failure_retained": True,
             "failure_reason": None, "t_origin_relative_ns": 0, "readiness_relative_ns": -10_000_000,
             "flap_start_actual_relative_ns": None, "flap_end_actual_relative_ns": None, "recovery_relative_ns": None,
             "recovery_censored": False, "recovery_eligible": False, "sent_packets": 400, "delivered_packets": 400,
             "lost_packets": 0, "duplicates": 0, "reorder_displacement_count": 0, "max_consecutive_loss_burst": 0,
             "degraded_interval_ns": 0, "wire_bytes": 0, "wire_packets": 0, "cpu_user_ns": 0, "cpu_system_ns": 0,
             "queue_high_water_packets": 0, "queue_overflow_packets": 0, "setup_status": "passed", "cleanup_status": "passed"}
    d = digest()
    ordinal = [{"ordinal": i, "digest": d} for i in range(8)]
    environment = {"namespace_count": 4, "isolated_namespace_count": 4, "clock": "CLOCK_MONOTONIC_RAW", "kernel_digest": d,
                   "cpu_digest": d, "release_binary_digest": d, "source_digest": d, "offload_digests": ordinal,
                   "raw_identifiers_prohibited": True}
    environment["environment_id"] = identity(environment, "environment_id")
    topology = {"seed": 0, "interface_count": 8, "veth_pair_count": 4, "path_count": 2, "manifest_digest": d,
                "route_digests": [{"path": x, "digest": d} for x in "AB"], "source_policy_digests": [{"path": x, "digest": d} for x in "AB"],
                "hop_digests": [{"path": x, "digest": d} for x in "AB"], "interface_digests": ordinal,
                "locator_digests": [{"role": x, "digest": d} for x in q2.LOCATOR_TOKENS], "mac_digests": ordinal,
                "raw_identifiers_prohibited": True}
    topology["topology_id"] = identity(topology, "topology_id")
    trial["environment_id"], trial["topology_id"] = environment["environment_id"], topology["topology_id"]
    packets = [{"trial_id": trial["trial_id"], "packet_index": i, "scheduled_relative_ns": -1_000_000_000 + i * 10_000_000,
                "send_relative_ns": -1_000_000_000 + i * 10_000_000, "mechanism_active_path_count": 2,
                "authenticated_delivery": True, "suppression": "none", "outcome": "delivered",
                "path_A_received_relative_ns": -1_000_000_000 + i * 10_000_000, "path_B_received_relative_ns": None,
                "path_A_receive_count": 1, "path_B_receive_count": 0,
                "first_authenticated_receive_relative_ns": -1_000_000_000 + i * 10_000_000, "on_schedule": True} for i in range(400)]
    metrics = {key: trial[key] for key in ("sent_packets", "delivered_packets", "lost_packets", "duplicates", "reorder_displacement_count", "max_consecutive_loss_burst", "degraded_interval_ns", "wire_bytes", "wire_packets", "cpu_user_ns", "cpu_system_ns", "queue_high_water_packets", "queue_overflow_packets")}
    evidence = {"trial_id": trial["trial_id"], "condition": "no-flap", "lifecycle": {key: trial[key] for key in ("status", "failure_reason", "setup_status", "cleanup_status", "failure_retained")},
                "readiness": {"relative_ns": -10_000_000, "consecutive_authenticated_on_schedule_deliveries": 10},
                "recovery": {"eligible": False, "censored": False, "event_relative_ns": None, "observed_followup_ns": 0}, "metrics": metrics,
                "environment": environment, "topology": topology, "pre_state_digests": ordinal, "post_state_digests": ordinal,
                "cleanup_digests": ordinal, "qdisc_observations": [], "failure_retained": True, "raw_identifiers_prohibited": True}
    evidence["evidence_id"] = identity(evidence, "evidence_id")
    trial["evidence_id"] = evidence["evidence_id"]
    return [trial], packets, [evidence]


def flap_rows():
    trials, packets, evidence = valid_rows()
    plan = next(row for row in q2.plan_rows() if row["seed"] == 0 and row["condition"] == "flap-A" and row["mechanism"] == "REDUNDANT")
    trial, item = trials[0], evidence[0]
    for key, value in plan.items():
        if key != "warmup":
            trial[key] = value
    for packet in packets:
        packet["trial_id"] = trial["trial_id"]
    trial.update({
        "flap_start_actual_relative_ns": 0,
        "flap_end_actual_relative_ns": 1_000_000_000,
        "recovery_relative_ns": 100_000_000,
        "recovery_censored": False,
        "recovery_eligible": True,
        "degraded_interval_ns": 1_000_000_000,
    })
    item["trial_id"], item["condition"] = trial["trial_id"], "flap-A"
    item["metrics"]["degraded_interval_ns"] = 1_000_000_000
    item["qdisc_observations"] = [
        {"ordinal": 0, "start_actual_relative_ns": 0, "end_actual_relative_ns": 1_000_000_000},
        {"ordinal": 3, "start_actual_relative_ns": 0, "end_actual_relative_ns": 1_000_000_000},
    ]
    item["recovery"] = {"eligible": True, "censored": False, "event_relative_ns": 100_000_000,
                        "observed_followup_ns": 100_000_000}
    item["evidence_id"] = identity(item, "evidence_id")
    trial["evidence_id"] = item["evidence_id"]
    return trials, packets, evidence


class Q2ContractTest(unittest.TestCase):
    def test_fixed_point_and_v5_plan(self):
        self.assertEqual(q2.verify_contract(), [])
        self.assertEqual(q2.plan_digest(), q2.PLAN_SHA256)
        self.assertEqual(len(list(q2.plan_rows())), 1980)

    def test_accepts_v5_partial(self):
        self.assertEqual(q2.validate(*valid_rows(), require_complete=False), [])

    def test_rejects_packet_and_identity_tampering(self):
        trials, packets, evidence = valid_rows()
        packets[0]["scheduled_relative_ns"] += 1
        evidence[0]["topology"]["seed"] = 1
        errors = q2.validate(trials, packets, evidence, require_complete=False)
        self.assertTrue(any("scheduled_relative_ns" in error for error in errors))
        self.assertTrue(any("topology identity" in error for error in errors))

    def test_rejects_duplicate_primary_key(self):
        trials, packets, evidence = valid_rows()
        packets.append(dict(packets[0]))
        self.assertTrue(any("duplicate packet_index" in error for error in q2.validate(trials, packets, evidence, require_complete=False)))

    def test_accepts_completed_and_retained_failed_flap(self):
        self.assertEqual(q2.validate(*flap_rows(), require_complete=False), [])
        trials, packets, evidence = flap_rows()
        trial, item = trials[0], evidence[0]
        trial.update({"status": "failed", "failure_reason": "flap-timing",
                      "flap_start_actual_relative_ns": None, "flap_end_actual_relative_ns": None,
                      "recovery_relative_ns": None, "recovery_censored": True,
                      "recovery_eligible": False, "degraded_interval_ns": None})
        item["lifecycle"].update({"status": "failed", "failure_reason": "flap-timing"})
        item["metrics"]["degraded_interval_ns"] = None
        item["qdisc_observations"] = []
        item["recovery"] = {"eligible": False, "censored": True, "event_relative_ns": None,
                            "observed_followup_ns": 0}
        item["evidence_id"] = identity(item, "evidence_id")
        trial["evidence_id"] = item["evidence_id"]
        self.assertEqual(q2.validate(trials, packets, evidence, require_complete=False), [])

    def test_packet_state_machine_mutations_fail(self):
        mutations = (
            lambda rows: rows[1][0].__setitem__("send_relative_ns", rows[1][0]["scheduled_relative_ns"] - 1),
            lambda rows: rows[1][0].__setitem__("first_authenticated_receive_relative_ns", 1),
            lambda rows: rows[1][0].__setitem__("mechanism_active_path_count", 1),
            lambda rows: rows[1][0].__setitem__("outcome", "late"),
            lambda rows: rows[1][0].__setitem__("suppression", "duplicate"),
            lambda rows: rows[0][0].__setitem__("delivered_packets", 399),
        )
        for mutate in mutations:
            rows = [copy.deepcopy(part) for part in valid_rows()]
            mutate(rows)
            self.assertTrue(q2.validate(*rows, require_complete=False))

    def test_duplicate_copy_and_aggregate_are_derived(self):
        trials, packets, evidence = valid_rows()
        packets[0]["path_B_receive_count"] = 1
        packets[0]["path_B_received_relative_ns"] = packets[0]["path_A_received_relative_ns"] + 1
        packets[0]["suppression"] = "duplicate"
        errors = q2.validate(trials, packets, evidence, require_complete=False)
        self.assertTrue(any("aggregates disagree" in error for error in errors))

    def test_flap_skew_timing_and_recovery_tamper_fail(self):
        trials, packets, evidence = flap_rows()
        evidence[0]["qdisc_observations"][0]["start_actual_relative_ns"] = -100_000_000
        evidence[0]["qdisc_observations"][1]["start_actual_relative_ns"] = 1
        evidence[0]["evidence_id"] = identity(evidence[0], "evidence_id")
        trials[0]["evidence_id"] = evidence[0]["evidence_id"]
        errors = q2.validate(trials, packets, evidence, require_complete=False)
        self.assertTrue(any("valid qdisc" in error or "fault" in error for error in errors))

        trials, packets, evidence = flap_rows()
        trials[0]["recovery_relative_ns"] += 1
        errors = q2.validate(trials, packets, evidence, require_complete=False)
        self.assertTrue(any("recovery" in error for error in errors))

    def test_cross_mechanism_configuration_state_must_match(self):
        first = valid_rows()
        second = [copy.deepcopy(part) for part in valid_rows()]
        trial, packets, evidence = second[0][0], second[1], second[2][0]
        plan = next(row for row in q2.plan_rows()
                    if row["seed"] == 0 and row["condition"] == "no-flap" and row["mechanism"] == "single-A")
        for key, value in plan.items():
            if key != "warmup":
                trial[key] = value
        for packet in packets:
            packet["trial_id"] = trial["trial_id"]
            packet["mechanism_active_path_count"] = 1
        evidence["trial_id"] = trial["trial_id"]
        evidence["pre_state_digests"][0]["digest"] = digest("selective-configuration")
        evidence["evidence_id"] = identity(evidence, "evidence_id")
        trial["evidence_id"] = evidence["evidence_id"]
        errors = q2.validate(first[0] + second[0], first[1] + second[1],
                             first[2] + second[2], require_complete=False)
        self.assertTrue(any("configuration state is not stable" in error for error in errors))

    def test_readiness_and_evidence_metric_tamper_fail(self):
        trials, packets, evidence = valid_rows()
        packets[99].update({"authenticated_delivery": False, "suppression": "not_received",
                            "outcome": "lost", "path_A_received_relative_ns": None,
                            "path_A_receive_count": 0, "first_authenticated_receive_relative_ns": None,
                            "on_schedule": None})
        evidence[0]["metrics"]["wire_bytes"] = 1
        errors = q2.validate(trials, packets, evidence, require_complete=False)
        self.assertTrue(any("readiness" in error for error in errors))
        self.assertTrue(any("metrics disagree" in error for error in errors))

    def test_strict_json_error_cap_and_cli_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            q2._strict_loads('{"a":1,"a":2}')
        errors = q2.validate([{} for _ in range(300)], [], [], require_complete=False)
        self.assertLessEqual(len(errors), q2.MAX_ERRORS)
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(q2.main(["validate", "--input", directory]), 2)
            self.assertIn('"error_category":"input-invalid"', output.getvalue())

    def test_contract_byte_drift_fails_closed(self):
        original = q2.PROTOCOL
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "q2.json"
            path.write_bytes(original.read_bytes() + b"\n")
            q2.PROTOCOL = path
            try:
                self.assertIn("q2-contract-drift", q2.verify_contract())
            finally:
                q2.PROTOCOL = original


if __name__ == "__main__":
    unittest.main()
