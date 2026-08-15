#!/usr/bin/env python3
"""Q2 v5 preregistration contract validator (no measurement execution)."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "bench" / "protocols" / "q2.json"
SCHEMA_DIR = PROTOCOL.parent
CONDITIONS = {"no-flap": 0, "flap-A": 1, "flap-B": 2}
MECHANISMS = ("REDUNDANT", "single-A", "single-B")
LOCATOR_TOKENS = ("source-slot-0", "destination-slot-0", "source-slot-1", "destination-slot-1")
MAC_TOKENS = ("source-A-egress", "hop-A-ingress", "hop-A-egress", "destination-A-ingress", "source-B-egress", "hop-B-ingress", "hop-B-egress", "destination-B-ingress")
IMPLEMENTATION_FILES = (
    ".github/workflows/ci.yml", ".github/workflows/native-full.yml", ".github/workflows/q2-full.yml",
    "bench/q2.py", "bench/q2_run.py", "requirements-dev.txt",
    "spec/0004-wire-format-v0.2.md", "spec/0005-session-security-v0.1.md",
    "spec/0006-mobility-v0.1.md", "spec/0007-native-binding-v0.1.md",
    "spec/0008-redundant-v0.1.md", "spec/parameters-v0.1.md",
    "reference/r8ref.py", "reference/r8session.py", "reference/r8mobility.py",
    "reference/r8redundant.py", "tests/native_netns.py", "tests/redundant_netns.py",
    "rust/Cargo.toml", "rust/Cargo.lock", "rust/crates/r8-proto/Cargo.toml",
    "rust/crates/r8-proto/src/lib.rs", "rust/crates/r8-session/Cargo.toml",
    "rust/crates/r8-session/src/lib.rs", "rust/crates/r8-mobility/Cargo.toml",
    "rust/crates/r8-mobility/src/lib.rs", "rust/crates/r8-redundant/Cargo.toml",
    "rust/crates/r8-redundant/src/lib.rs",
    "rust/crates/r8-redundant/src/bin/r8-redundant-native.rs",
    "rust/crates/r8d/Cargo.toml", "rust/crates/r8d/src/lib.rs",
    "rust/crates/r8d/src/forward.rs", "rust/crates/r8d/src/linux.rs",
    "rust/crates/r8d/src/manifest.rs", "rust/crates/r8d/src/native.rs",
    "rust/crates/r8d/src/bin/r8-native.rs",
)
PLAN_SHA256 = "477db21557cd9ff0349c8e9630261d35ea6dda42a53f1fcf50c7936ba7a70f75"
SCHEMA_BINDINGS = (
    ("bench/protocols/q2-trial-v5.schema.json", "02f4a204840f216e6b453103696f0ea8bfc0bc6272b92b87e5fdddea93bbe30c", 5508),
    ("bench/protocols/q2-packet-v5.schema.json", "6db0bf37dead1602d6ff67d0278e484356cf1a68dd89c9c4e65e1ab9038a6594", 3699),
    ("bench/protocols/q2-evidence-v5.schema.json", "649d4368dcab8305f9db7479537d4e2c896e50b94cf7fad0737379306f696771", 8898),
)
HISTORY = (("r8-benchmark-preregistration-v1", "12f678e6af04b1377bb977cf17da7f3a08bd2f0f9b3b30c43d4e6f072dbd840d", 3367), ("r8-benchmark-preregistration-v2", "376a944a155f40690acc5016db7d00cb8a0e12e249204ec5e3233471cdb9f545", 6939), ("r8-benchmark-preregistration-v3", "2e624e5801c2a42e7176204ba3f945e507e694273b85edb688b1e532a15f3e1f", 12704), ("r8-benchmark-preregistration-v4", "739021d7abf34ee8921de112e368aa41511116a426ab9d71a808d52a4836197b", 8711))
MAX_ERRORS = 256


def _sha_size(path):
    value = Path(path).read_bytes()
    return hashlib.sha256(value).hexdigest(), len(value)

def implementation_sources():
    return {path: _sha_size(ROOT / path)[0] for path in IMPLEMENTATION_FILES}


def implementation_source_digest(sources=None):
    value = implementation_sources() if sources is None else sources
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _strict_loads(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonstandard JSON constant")))


def verify_contract():
    errors = []
    contract_sha, contract_size = _sha_size(PROTOCOL)
    contract = _strict_loads(PROTOCOL.read_text())
    bindings = tuple((x.get("path"), x.get("sha256"), _sha_size(ROOT / x.get("path", ""))[1]) for x in contract.get("schemas", {}).values())
    if bindings != SCHEMA_BINDINGS: errors.append("q2-contract-schema-drift")
    for path, digest, size in SCHEMA_BINDINGS:
        if _sha_size(ROOT / path) != (digest, size): errors.append("q2-schema-drift")
    if contract.get("execution_order", {}).get("plan_row", {}).get("digest") != PLAN_SHA256 or plan_digest() != PLAN_SHA256: errors.append("q2-plan-drift")
    frozen = contract.get("implementation_binding", {}).get("source_map")
    if not isinstance(frozen, dict) or tuple(sorted(frozen)) != tuple(sorted(IMPLEMENTATION_FILES)):
        errors.append("q2-implementation-map")
    elif implementation_sources() != frozen:
        errors.append("q2-implementation-drift")
    elif contract.get("implementation_binding", {}).get("source_map_sha256") != implementation_source_digest(frozen):
        errors.append("q2-implementation-digest")
    manifest = _strict_loads((SCHEMA_DIR / "manifest.json").read_text())
    entry = next((x for x in manifest.get("preregistrations", []) if x.get("protocol_id") == "Q2"), None)
    if entry is None:
        errors.append("q2-manifest-drift")
    elif (entry.get("sha256"), entry.get("size_bytes")) != (contract_sha, contract_size):
        errors.append("q2-contract-drift")
    elif tuple(entry.get(k) for k in ("contract_version", "status", "execution_plan_sha256")) != (
            "r8-benchmark-preregistration-v5", "frozen-preregistered-no-results-v5", PLAN_SHA256):
        errors.append("q2-manifest-drift")
    elif tuple((x.get("path"), x.get("sha256"), x.get("size_bytes")) for x in entry.get("schema_bindings", [])) != SCHEMA_BINDINGS: errors.append("q2-manifest-schema-drift")
    elif tuple((x.get("contract_version"), x.get("sha256"), x.get("size_bytes")) for x in entry.get("superseded", [])) != HISTORY or any(x.get("status") != "superseded-no-results" for x in entry["superseded"]): errors.append("q2-history-drift")
    return errors


def _digest(domain, seed, value=b""):
    return hashlib.sha256(domain + seed.to_bytes(4, "big") + value).digest()
def trial_id(seed, condition, mechanism): return _digest(b"r8-q2-v4-trial-id", seed, bytes([CONDITIONS[condition]]) + mechanism.encode()).hex()
def mechanism_plan(seed, condition):
    prefix = b"r8-q2-v3-mechanism-order" + seed.to_bytes(4, "big") + bytes([CONDITIONS[condition]])
    return sorted((hashlib.sha256(prefix + m.encode()).digest(), m) for m in MECHANISMS)
def mechanism_order(seed, condition): return [m for _, m in mechanism_plan(seed, condition)]
def locator_id(seed, token):
    if token not in LOCATOR_TOKENS: raise ValueError("unknown locator token")
    return _digest(b"r8-q2-v4-locator-id", seed, token.encode())[:16].hex()
def mac_address(seed, token):
    if token not in MAC_TOKENS: raise ValueError("unknown interface MAC token")
    value = bytearray(_digest(b"r8-q2-v4-mac", seed, token.encode())[:6]); value[0] = (value[0] | 2) & 0xfe
    return value.hex(":")
def block_draw(resample, position):
    if not 0 <= resample <= 9999 or not 0 <= position <= 9: raise ValueError("block draw is outside the frozen range")
    digest = hashlib.sha256(b"r8-q2-v4-block-draw" + resample.to_bytes(4, "big") + bytes([position])).digest()
    return digest.hex(), 1 + int.from_bytes(digest[:8], "big") % 10

def plan_rows():
    for seed in range(220):
        for condition, code in CONDITIONS.items():
            for rank, (digest, mechanism) in enumerate(mechanism_plan(seed, condition)):
                yield {"trial_id": trial_id(seed, condition, mechanism), "seed": seed, "block": seed // 20, "warmup": seed < 20, "condition": condition, "condition_code": code, "mechanism": mechanism, "mechanism_digest": digest.hex(), "execution_rank": rank, "execution_ordinal": seed * 9 + code * 3 + rank}
def plan_digest():
    return hashlib.sha256(b"".join(json.dumps(x, sort_keys=True, separators=(",", ":")).encode() + b"\n" for x in plan_rows())).hexdigest()
def _schema(name): return Draft202012Validator(_strict_loads((SCHEMA_DIR / name).read_text()))
def _canonical_id(row, field):
    payload = dict(row); payload.pop(field, None)
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
def _raw_rows(path):
    with Path(path).open() as source:
        for n, line in enumerate(source, 1):
            if line.strip():
                try: yield n, _strict_loads(line)
                except (ValueError, json.JSONDecodeError) as exc: raise ValueError(f"{path} line {n}: invalid JSON: {exc}") from exc


def validate(trials, packets, evidence, *, require_complete=True):
    errors, trial_rows, states, evidence_rows, evidence_ids = [], {}, {}, {}, set()
    validators = {x: _schema(f"q2-{x}-v5.schema.json") for x in ("trial", "packet", "evidence")}
    canonical_plan = {row["execution_ordinal"]: row for row in plan_rows()}
    def add(message):
        if len(errors) < MAX_ERRORS: errors.append(message)
    def numbered(rows):
        for n, row in enumerate(rows, 1): yield row if isinstance(row, tuple) and len(row) == 2 and isinstance(row[0], int) else (n, row)
    def schema(row, table, n):
        for error in validators[table].iter_errors(row): add(f"{table} row {n}: {error.message}")
    for n, row in numbered(trials):
        schema(row, "trial", n)
        if not isinstance(row, dict): continue
        key = row.get("trial_id")
        if key in trial_rows: add(f"trial row {n}: duplicate trial_id {key}"); continue
        trial_rows[key] = row; states[key] = {"indexes": set(), "rows": {}}
        try:
            expected = canonical_plan[row["execution_ordinal"]]
            # `warmup` is not a row field: it is uniquely derived from the canonical seed (`seed < 20`).
            if any(row.get(k) != v for k, v in expected.items() if k != "warmup"): add(f"trial row {n}: row does not equal canonical plan")
        except (KeyError, StopIteration, TypeError): add(f"trial row {n}: invalid canonical execution ordinal")
    for n, row in numbered(packets):
        schema(row, "packet", n)
        if not isinstance(row, dict): continue
        key, index = row.get("trial_id"), row.get("packet_index"); state = states.get(key)
        if state is None: add(f"packet row {n}: unknown trial_id {key}"); continue
        if index in state["indexes"]: add(f"packet row {n}: duplicate packet_index for {key}"); continue
        state["indexes"].add(index); state["rows"][index] = row
        try:
            schedule, send = -1_000_000_000 + index * 10_000_000, row["send_relative_ns"]
            if row["scheduled_relative_ns"] != schedule: add(f"packet row {n}: scheduled_relative_ns is not frozen schedule")
            if (send is None) != (row["outcome"] == "not_sent") or (send is not None and send < schedule): add(f"packet row {n}: send/outcome disagrees with schedule")
            counts = row["path_A_receive_count"] + row["path_B_receive_count"]
            for path in ("A", "B"):
                if (row[f"path_{path}_receive_count"] == 0) != (row[f"path_{path}_received_relative_ns"] is None): add(f"packet row {n}: path {path} count/timestamp disagree")
                stamp = row[f"path_{path}_received_relative_ns"]
                if stamp is not None and (send is None or stamp < send or stamp >= 3_000_000_000): add(f"packet row {n}: path {path} timestamp outside send/deadline")
            first = min(x for x in (row["path_A_received_relative_ns"], row["path_B_received_relative_ns"]) if x is not None) if counts else None
            if row["authenticated_delivery"] != (counts > 0) or row["first_authenticated_receive_relative_ns"] != first: add(f"packet row {n}: authentication/first receive disagrees with paths")
            active = 2 if trial_rows[key].get("mechanism") == "REDUNDANT" else 1
            if row["mechanism_active_path_count"] != active or (trial_rows[key].get("mechanism") == "single-A" and row["path_B_receive_count"] != 0) or (trial_rows[key].get("mechanism") == "single-B" and row["path_A_receive_count"] != 0): add(f"packet row {n}: mechanism path state disagrees")
            if counts:
                on = schedule <= first <= schedule + 20_000_000
                if row["on_schedule"] != on or row["outcome"] != ("delivered" if on else "late") or row["suppression"] != ("duplicate" if counts > 1 else "none"): add(f"packet row {n}: delivery outcome/suppression disagrees")
            elif row["outcome"] != ("not_sent" if send is None else "lost") or row["suppression"] != ("trial_failure" if send is None else "not_received"): add(f"packet row {n}: loss outcome/suppression disagrees")
        except (KeyError, TypeError, ValueError): add(f"packet row {n}: unusable packet fields")
    for key, state in states.items():
        trial, rows = trial_rows[key], state["rows"]
        if state["indexes"] != set(range(400)): add(f"trial {key}: packet table must contain indexes 0..399 exactly once")
        if len(rows) != 400: continue
        delivered = sum(r["authenticated_delivery"] for r in rows.values()); sent = sum(r["send_relative_ns"] is not None for r in rows.values())
        duplicates = sum(max(r["path_A_receive_count"] + r["path_B_receive_count"] - 1, 0) for r in rows.values())
        received = sorted((r["first_authenticated_receive_relative_ns"], i) for i, r in rows.items() if r["authenticated_delivery"])
        reorder = 0
        high_index = -1
        for _, index in received:
            reorder += index < high_index
            high_index = max(high_index, index)
        burst = best = 0
        for i in range(400): burst = burst + 1 if not rows[i]["authenticated_delivery"] else 0; best = max(best, burst)
        metrics = {"sent_packets": sent, "delivered_packets": delivered, "lost_packets": 400 - delivered, "duplicates": duplicates, "reorder_displacement_count": reorder, "max_consecutive_loss_burst": best}
        if any(trial.get(k) != v for k, v in metrics.items()): add(f"trial {key}: retained packet aggregates disagree")
        ready_flags = [
            rows[i]["authenticated_delivery"]
            and rows[i]["on_schedule"]
            and rows[i]["first_authenticated_receive_relative_ns"] <= 0
            for i in range(90, 100)
        ]
        longest = run = 0
        for good in ready_flags:
            run = run + 1 if good else 0
            longest = max(longest, run)
        ready = longest == 10
        readiness = max(rows[i]["first_authenticated_receive_relative_ns"] for i in range(90, 100)) if ready else None
        state["readiness_count"] = longest
        if trial.get("readiness_relative_ns") != readiness: add(f"trial {key}: readiness disagrees with packets")
        if trial.get("status") == "completed" and not ready: add(f"trial {key}: completed trial lacks readiness")
        if trial.get("failure_reason") == "readiness_not_reached" and ready: add(f"trial {key}: readiness failure reason contradicts packets")
        if trial.get("status") == "completed" and any(trial.get(k) is None for k in ("degraded_interval_ns", "wire_bytes", "wire_packets", "cpu_user_ns", "cpu_system_ns", "queue_high_water_packets", "queue_overflow_packets")):
            add(f"trial {key}: completed trial has null host metrics")
    env_bytes, topology_bytes, config_by_seed_condition = None, {}, {}
    for n, row in numbered(evidence):
        schema(row, "evidence", n)
        if not isinstance(row, dict): continue
        key = row.get("trial_id")
        if key in evidence_rows: add(f"evidence row {n}: duplicate trial_id {key}"); continue
        evidence_rows[key] = row
        if row.get("evidence_id") in evidence_ids: add(f"evidence row {n}: duplicate evidence_id")
        evidence_ids.add(row.get("evidence_id")); trial = trial_rows.get(key)
        if trial is None: add(f"evidence row {n}: unknown trial_id {key}"); continue
        if row.get("evidence_id") != trial.get("evidence_id") or row.get("evidence_id") != _canonical_id(row, "evidence_id"): add(f"evidence row {n}: evidence identity disagrees")
        env, topology = row.get("environment", {}), row.get("topology", {})
        if env.get("environment_id") != trial.get("environment_id") or env.get("environment_id") != _canonical_id(env, "environment_id"): add(f"evidence row {n}: environment identity disagrees")
        if topology.get("topology_id") != trial.get("topology_id") or topology.get("topology_id") != _canonical_id(topology, "topology_id") or topology.get("seed") != trial.get("seed"): add(f"evidence row {n}: topology identity disagrees")
        try: eb, tb = json.dumps(env, sort_keys=True, separators=(",", ":")), json.dumps(topology, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError): eb = tb = None
        if env_bytes is None: env_bytes = eb
        elif env_bytes != eb: add(f"evidence row {n}: environment is not stable")
        seed = trial.get("seed")
        if seed in topology_bytes and topology_bytes[seed] != tb: add(f"evidence row {n}: topology is not stable per seed")
        topology_bytes[seed] = tb
        config_key = (seed, trial.get("condition"))
        try:
            pre_state = json.dumps(row.get("pre_state_digests"), sort_keys=True, separators=(",", ":"))
            post_state = json.dumps(row.get("post_state_digests"), sort_keys=True, separators=(",", ":"))
            cleanup_state = json.dumps(row.get("cleanup_digests"), sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            pre_state = post_state = cleanup_state = None
        if config_key in config_by_seed_condition and config_by_seed_condition[config_key] != pre_state:
            add(f"evidence row {n}: configuration state is not stable across paired mechanisms")
        config_by_seed_condition[config_key] = pre_state
        if trial.get("status") == "completed" and post_state != pre_state:
            add(f"evidence row {n}: completed post-state does not match pre-state")
        if trial.get("cleanup_status") == "passed" and cleanup_state != pre_state:
            add(f"evidence row {n}: passed cleanup state does not match pre-state")
        lifecycle = row.get("lifecycle", {}); metrics = row.get("metrics", {}); readiness_data = row.get("readiness", {})
        if row.get("condition") != trial.get("condition") or any(lifecycle.get(k) != trial.get(k) for k in ("status", "failure_reason", "setup_status", "cleanup_status", "failure_retained")): add(f"evidence row {n}: lifecycle disagrees with trial")
        if any(metrics.get(k) != trial.get(k) for k in metrics): add(f"evidence row {n}: metrics disagree with trial")
        if readiness_data.get("relative_ns") != trial.get("readiness_relative_ns") or readiness_data.get("consecutive_authenticated_on_schedule_deliveries") != states[key].get("readiness_count", 0): add(f"evidence row {n}: readiness disagrees with trial")
        observations = row.get("qdisc_observations", []); expected = [] if trial.get("condition") == "no-flap" else ([0, 3] if trial.get("condition") == "flap-A" else [4, 7])
        valid = len(observations) == 2 and [x.get("ordinal") for x in observations] == expected and all(isinstance(x.get("start_actual_relative_ns"), int) and isinstance(x.get("end_actual_relative_ns"), int) and abs(x["start_actual_relative_ns"]) <= 100_000_000 and abs(x["end_actual_relative_ns"] - 1_000_000_000) <= 100_000_000 for x in observations)
        if observations and (not valid or max(x["start_actual_relative_ns"] for x in observations) - min(x["start_actual_relative_ns"] for x in observations) > 100_000_000 or max(x["end_actual_relative_ns"] for x in observations) - min(x["end_actual_relative_ns"] for x in observations) > 100_000_000): valid = False
        if trial.get("condition") != "no-flap" and trial.get("status") == "completed" and not valid: add(f"evidence row {n}: completed flap lacks valid qdisc observations")
        if (not valid and trial.get("condition") != "no-flap" and trial.get("status") != "completed"
                and trial.get("setup_status") == "passed"
                and trial.get("failure_reason") not in ("flap-timing", "fault_not_applied",
                                                        "cleanup_failed", "trial_timeout",
                                                        "supervisor_timeout")):
            add(f"evidence row {n}: invalid fault lacks retained failure reason")
        if trial.get("condition") == "no-flap" and observations: add(f"evidence row {n}: no-flap has qdisc observations")
        if valid and trial.get("condition") != "no-flap":
            starts = [item["start_actual_relative_ns"] for item in observations]
            ends = [item["end_actual_relative_ns"] for item in observations]
            expected_start, origin = max(starts), max(ends)
            degraded = origin - min(starts)
            if trial.get("flap_start_actual_relative_ns") != expected_start or trial.get("flap_end_actual_relative_ns") != origin:
                add(f"trial {key}: flap timing disagrees with qdisc evidence")
            if trial.get("degraded_interval_ns") != degraded or row.get("metrics", {}).get("degraded_interval_ns") != degraded:
                add(f"trial {key}: degraded interval disagrees with qdisc evidence")
        elif trial.get("condition") == "no-flap":
            if trial.get("degraded_interval_ns") != 0 or row.get("metrics", {}).get("degraded_interval_ns") != 0:
                add(f"trial {key}: no-flap degraded interval is not zero")
        recovery = row.get("recovery", {})
        if any(recovery.get(k) != trial.get({"eligible": "recovery_eligible", "censored": "recovery_censored", "event_relative_ns": "recovery_relative_ns"}[k]) for k in ("eligible", "censored", "event_relative_ns")):
            add(f"evidence row {n}: recovery disagrees with trial")
        if valid and trial.get("condition") != "no-flap" and len(states[key]["rows"]) == 400:
            origin = max(x["end_actual_relative_ns"] for x in observations)
            run = 0
            event = None
            for index in range(400):
                packet = states[key]["rows"][index]
                good = packet["scheduled_relative_ns"] > origin and packet["authenticated_delivery"] and packet["on_schedule"]
                run = run + 1 if good else 0
                if run == 10:
                    candidate = packet["first_authenticated_receive_relative_ns"] - origin
                    if candidate <= 2_000_000_000:
                        event = candidate
                    break
            if trial.get("recovery_eligible") is not True or trial.get("recovery_relative_ns") != event or trial.get("recovery_censored") != (event is None):
                add(f"trial {key}: recovery disagrees with valid fault and packets")
            if trial.get("status") == "completed":
                expected_followup = event if event is not None else max(0, min(2_000_000_000, 3_000_000_000 - origin))
                if recovery.get("observed_followup_ns") != expected_followup:
                    add(f"trial {key}: recovery follow-up disagrees with completed observation")
        elif trial.get("condition") != "no-flap" and not valid:
            if trial.get("recovery_eligible") or not trial.get("recovery_censored") or trial.get("recovery_relative_ns") is not None or recovery.get("observed_followup_ns") != 0:
                add(f"trial {key}: invalid fault must retain noneligible zero-followup censored recovery")
    if require_complete:
        expected = list(plan_rows())
        if len(trial_rows) != 1980 or [x.get("trial_id") for x in trial_rows.values()] != [x["trial_id"] for x in expected]: add("trial table is not the exact canonical 220 × 3 × 3 order")
        if len(evidence_rows) != 1980 or set(evidence_rows) != set(trial_rows): add("evidence table must contain exactly one row per trial_id")
        if sum(len(x["indexes"]) for x in states.values()) != 792000: add("logical packet table cardinality is not 792000")
    return errors

def validate_files(trial_path, packet_path, evidence_path): return validate(_raw_rows(trial_path), _raw_rows(packet_path), _raw_rows(evidence_path))
validate_streams = validate

def main(argv=None):
    parser = argparse.ArgumentParser(description="validate the frozen Q2 v5 contract")
    commands = parser.add_subparsers(dest="command", required=True); commands.add_parser("plan-digest")
    command = commands.add_parser("validate"); command.add_argument("--input", required=True, type=Path)
    try:
        args = parser.parse_args(argv); drift = verify_contract()
        if drift: print(json.dumps({"error_category":"contract-drift","error_count":len(drift),"ok":False}, separators=(",", ":"), sort_keys=True)); return 2
        if args.command == "plan-digest": print(json.dumps({"ok":True,"plan_digest":plan_digest(),"rows":1980}, separators=(",", ":"), sort_keys=True)); return 0
        errors = validate_files(args.input / "trial.jsonl", args.input / "logical-packet.jsonl", args.input / "evidence.jsonl")
        if errors: print(json.dumps({"error_category":"contract-invalid","error_count":len(errors),"ok":False}, separators=(",", ":"), sort_keys=True)); return 1
        print('{"ok":true}'); return 0
    except (Exception, SystemExit):
        print('{"error_category":"input-invalid","ok":false}'); return 2
if __name__ == "__main__": raise SystemExit(main())
