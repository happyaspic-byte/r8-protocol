#!/usr/bin/env python3
"""Q1 v4-ready runner.  It deliberately has no unprivileged/simulated mode."""
import argparse, hashlib, ipaddress, json, os, platform, random, re, shutil, signal, struct, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL, MANIFEST = ROOT / "bench/protocols/q1.json", ROOT / "bench/protocols/manifest.json"
MECHANISMS = ("R8", "TCP-reconnect", "GARP-VIP")
ARMS = ("abrupt-break", "make-before-break")
PAIR_ORDER = tuple((m, a) for m in MECHANISMS for a in ARMS)
WARMUPS, MEASURED, BLOCK_SIZE, RESAMPLES = 20, 200, 20, 10000
ORDER_SEED, BOOTSTRAP_SEED = "r8-q1-block-order-v4", "r8-q1-block-bootstrap-v2"
SOCKET_BUFFER = 262144
RAW_FIELDS = ("protocol_id", "contract_version", "trial_id", "block_id", "host_epoch", "mechanism", "arm", "randomization_position", "setup_status", "exclusion_reason", "error_category", "t_minus_3_ns", "activation_ns", "activation_start_ns", "activation_complete_ns", "cutover_ns", "observation_end_ns", "readiness_ns", "censored", "failure", "scheduled_payloads", "attempted_payloads", "sent_payloads", "received_payloads", "lost_payloads", "duplicate_payloads", "reordered_payloads", "outage_ns", "interface_counter_by_ordinal", "interface_counter_timestamp_ns_by_ordinal", "counter_complete", "process_user_cpu_ns", "process_system_cpu_ns", "process_cpu_timestamp_ns_by_ordinal", "cpu_complete", "cleanup_complete", "evidence_complete", "environment_complete", "topology_complete", "namespace_count", "interface_count", "non_loopback_interface_count", "veth_pair_count", "configuration_sha256")
ERROR_CATEGORIES = frozenset(("namespace_create", "forwarding_config", "veth_create", "namespace_move", "bridge_create", "address_config", "link_activate", "route_client_default", "route_server_main", "route_old_policy", "route_candidate_policy", "route_vip_policy", "neighbor_config", "candidate_deactivate", "environment_setup", "environment_verify", "counter_read", "endpoint_setup", "endpoint_ready", "endpoint_exit", "timeline", "authenticated_events", "garp_announce", "endpoint_runtime", "r8_move_timeout", "r8_move_io", "r8_move_protocol", "worker_internal", "worker_timeout", "worker_exit", "worker_output", "cleanup_delete", "cleanup_reap", "cleanup_residual", "control_parse"))
SOURCE_FILES = tuple(ROOT / path for path in ("bench/q1.py", "reference/r8mobility.py", "reference/r8move.py", "reference/r8ref.py", "reference/r8session.py", "requirements-dev.txt", "tests/mobility_netns.py"))

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def stable_sha(value): return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def contract():
    data = json.loads(PROTOCOL.read_text())
    manifest = json.loads(MANIFEST.read_text())
    entry = next((x for x in manifest["preregistrations"] if x["protocol_id"] == "Q1"), None)
    if not entry or entry["sha256"] != sha(PROTOCOL) or entry["contract_version"] != data["contract_version"]:
        raise RuntimeError("Q1 preregistration/manifest hash mismatch")
    if data["contract_version"] != "r8-benchmark-preregistration-v4": raise RuntimeError("wrong Q1 contract")
    binding = data.get("implementation_binding", {})
    frozen = binding.get("source_map")
    if not isinstance(frozen, dict) or tuple(sorted(frozen)) != tuple(sorted(str(path.relative_to(ROOT)) for path in SOURCE_FILES)):
        raise RuntimeError("Q1 implementation source map invalid")
    if binding.get("source_map_sha256") != stable_sha(frozen):
        raise RuntimeError("Q1 implementation source map digest mismatch")
    if implementation_sources() != frozen:
        raise RuntimeError("Q1 implementation source drift")
    return data

def schedule(smoke=False):
    """Deterministic balanced v4 order: 66 independently balanced 20-trial blocks."""
    if smoke:
        return [{"trial_id": i, "block_id": 0, "randomization_position": i, "mechanism": m, "arm": a, "exclusion_reason": "smoke_non_result"} for i, (m,a) in enumerate(PAIR_ORDER)]
    rng = random.Random(ORDER_SEED)
    result, seen = [], {pair: 0 for pair in PAIR_ORDER}
    # Two four-count pairs per block.  Cycling adjacent pair indices gives
    # every pair exactly 22 four-count blocks; a seeded permutation hides it.
    blocks = list(range(66)); rng.shuffle(blocks)
    extra = {block: {PAIR_ORDER[index % 6], PAIR_ORDER[(index + 1) % 6]}
             for index, block in enumerate(blocks)}
    for block in range(66):
        entries = [pair for pair in PAIR_ORDER for _ in range(3 + (pair in extra[block]))]
        rng.shuffle(entries)
        for position, pair in enumerate(entries):
            ordinal = seen[pair]; seen[pair] += 1
            result.append({"trial_id": len(result), "block_id": block,
                           "randomization_position": position, "mechanism": pair[0], "arm": pair[1],
                           "exclusion_reason": "warmup" if ordinal < WARMUPS else None})
    assert len(result) == 1320 and all(seen[pair] == 220 for pair in PAIR_ORDER)
    return result

def capabilities():
    try:
        text = Path("/proc/self/status").read_text()
        capeff = int(next(x.split()[1] for x in text.splitlines() if x.startswith("CapEff:")), 16)
    except (OSError, StopIteration, ValueError): return False
    return os.geteuid() == 0 and bool(capeff & (1 << 12)) and bool(capeff & (1 << 13))

def preflight():
    contract()
    missing = [x for x in ("ip", "tc", "arping", "ethtool") if shutil.which(x) is None]
    if os.geteuid() != 0: raise RuntimeError("Q1 requires uid 0")
    if not capabilities(): raise RuntimeError("Q1 requires effective CAP_NET_ADMIN and CAP_NET_RAW")
    if missing: raise RuntimeError("Q1 missing required setup binary: " + ",".join(missing))
    return {"capabilities": ["CAP_NET_ADMIN", "CAP_NET_RAW"], "required_binaries": ["ip", "tc", "arping", "ethtool"]}

def percentile(values, q):
    values = sorted(values)
    return values[int((len(values)-1)*q)] if values else None
def summary(rows, configuration_sha256):
    planned = {item["trial_id"]: item for item in schedule()}
    answer = []
    for mechanism, arm in PAIR_ORDER:
        measured = [r for r in rows if (p:=planned.get(r["trial_id"])) and p["mechanism"] == mechanism and p["arm"] == arm and p["exclusion_reason"] is None]
        outcomes = [r for r in measured if r["setup_status"] != "failed"]
        blocks = [[r for r in outcomes if r["block_id"] == b] for b in range(66)]
        def estimate(sample):
            allrows=[r for block in sample for r in block]
            values=[r["outage_ns"] for r in allrows if not r["failure"] and r["outage_ns"] is not None]
            return {"failure_rate":sum(bool(r["failure"]) for r in allrows)/len(allrows) if allrows else None,"outage_p50_ns":percentile(values,.5),"outage_p95_ns":percentile(values,.95)}
        point=estimate(blocks); rng=random.Random(BOOTSTRAP_SEED+mechanism+arm)
        samples=[estimate([rng.choice(blocks) for _ in blocks]) for _ in range(RESAMPLES)]
        ci={}
        for key in ("failure_rate","outage_p50_ns","outage_p95_ns"):
            values=[x[key] for x in samples if x[key] is not None]
            ci[key]=[percentile(values,.025),percentile(values,.975)] if values else None
        answer.append({"protocol_id":"Q1","contract_version":contract()["contract_version"],"mechanism":mechanism,"arm":arm,"measured_trial_count":len(measured),"setup_failure_count":sum(r["setup_status"] == "failed" for r in measured),**point,"block_bootstrap_95_percent_ci":ci,"configuration_sha256":configuration_sha256})
    return answer


def _control(path, phase, **timeline):
    if not path: return
    record = _control_record(path) if Path(path).exists() else {}
    if record.get("_parse_failure"): record = {}
    record.update({"phase": phase, **{key: value for key, value in timeline.items() if key in {"t_minus_3_ns", "activation_ns", "activation_start_ns", "activation_complete_ns", "cutover_ns", "observation_end_ns"} and isinstance(value, int)}})
    temporary = Path(path).with_suffix(".tmp")
    temporary.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")))
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
def _control_record(path):
    try:
        record = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return {"_parse_failure": True}
    if record.get("phase") not in {"setup", "runtime", "terminal"}:
        return {"_parse_failure": True}
    return record
def _evidence_events(directory):
    streams = {}
    try:
        for name in ("scheduled", "attempted", "sent", "received"):
            raw = (Path(directory) / (name + ".bin")).read_bytes()
            if len(raw) % 16: raise ValueError(name)
            streams[name] = list(struct.iter_unpack("!QQ", raw))
    except (OSError, ValueError):
        return None
    return streams
def _reduce_evidence(control, evidence):
    streams = _evidence_events(evidence)
    start, cut, end = (control.get(key) for key in ("t_minus_3_ns", "cutover_ns", "observation_end_ns"))
    if streams is None or not all(isinstance(value, int) for value in (start, cut, end)):
        return None
    scheduled, attempted, sent = streams["scheduled"], streams["attempted"], streams["sent"]
    if (len(scheduled) != 800 or {sequence for sequence, _ in scheduled} != set(range(800))
            or any(stamp != start + sequence * 10_000_000 for sequence, stamp in scheduled)):
        return None
    schedule = dict(scheduled)
    def unique_subset(records, previous):
        values = dict(records)
        return len(values) == len(records) and set(values) <= set(previous) and all(previous[sequence] <= stamp for sequence, stamp in values.items()), values
    attempts_valid, attempts = unique_subset(attempted, schedule)
    sent_valid, sent_values = unique_subset(sent, attempts)
    if not attempts_valid or not sent_valid or any(attempts[sequence] > stamp for sequence, stamp in sent_values.items()):
        return None
    received = sorted((item for item in streams["received"] if item[1] < end), key=lambda item: item[1])
    if any(sequence not in sent_values or sent_values[sequence] > stamp for sequence, stamp in received): return None
    seen, duplicate, reordered, high, streak, readiness = set(), 0, 0, -1, [], None
    for sequence, stamp in received:
        duplicate += sequence in seen
        if sequence not in seen:
            reordered += sequence < high
            high = max(high, sequence)
        due = schedule.get(sequence)
        qualifying = due is not None and cut <= stamp < end and due <= stamp < due + 10_000_000 and sequence not in seen
        if not qualifying: streak = []
        elif streak and sequence == streak[-1][0] + 1: streak.append((sequence, stamp))
        else: streak = [(sequence, stamp)]
        if len(streak) == 10 and readiness is None: readiness = stamp
        seen.add(sequence)
    on_schedule = [(sequence, stamp) for sequence, stamp in received if sequence in schedule and schedule[sequence] <= stamp < schedule[sequence] + 10_000_000]
    pre = [item for item in on_schedule if item[1] < cut]
    failure = not pre or readiness is None
    return {"readiness_ns": readiness, "censored": failure, "failure": failure,
            "scheduled_payloads": 800, "attempted_payloads": len(attempted), "sent_payloads": len(sent), "received_payloads": len(received),
            "lost_payloads": len(set(schedule) - seen), "duplicate_payloads": duplicate, "reordered_payloads": reordered,
            "outage_ns": None if failure else readiness - max(stamp for _, stamp in pre), "evidence_complete": True}
def _supervisor_outcome(category, control, evidence=None):
    if control.get("_parse_failure"): category = "control_parse"
    runtime = control.get("phase") == "runtime" or (control.get("phase") == "terminal" and all(isinstance(control.get(key), int) for key in ("t_minus_3_ns", "activation_ns", "cutover_ns", "observation_end_ns")))
    row = {"setup_status": "complete" if runtime else "failed", "failure": True, "censored": True,
           "error_category": category, "scheduled_payloads": None, "attempted_payloads": None, "sent_payloads": None,
           "received_payloads": None, "lost_payloads": None, "duplicate_payloads": None,
           "reordered_payloads": None, "outage_ns": None, "interface_counter_by_ordinal": {}, "evidence_complete": False}
    if runtime:
        row.update({key: control.get(key) for key in ("t_minus_3_ns", "activation_ns", "activation_start_ns", "activation_complete_ns", "cutover_ns", "observation_end_ns")})
        reduced = _reduce_evidence(control, evidence) if evidence else None
        if reduced is not None:
            row.update(reduced)
            row["failure"] = row["censored"] = True
    return row
def _worker_payload(text):
    try:
        payload = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return None
    required = {"setup_status", "error_category", "failure", "censored", "scheduled_payloads", "attempted_payloads", "sent_payloads", "received_payloads", "evidence_complete"}
    if not isinstance(payload, dict) or not required <= set(payload):
        return None
    counts = [payload[key] for key in ("scheduled_payloads", "attempted_payloads", "sent_payloads", "received_payloads")]
    if (payload["setup_status"] not in {"complete", "failed"} or not isinstance(payload["failure"], bool)
            or not isinstance(payload["censored"], bool) or not isinstance(payload["evidence_complete"], bool)):
        return None
    if any(value is None for value in counts):
        return payload if payload["failure"] and payload["censored"] and not payload["evidence_complete"] else None
    if any(not isinstance(value, int) or value < 0 for value in counts) or not (counts[2] <= counts[1] <= counts[0]):
        return None
    return payload

def _cleanup_worker_namespaces(suffix):
    names = tuple("r8q1-" + role + "-" + suffix for role in ("client", "server", "router"))
    failures = []
    for name in names:
        try:
            pids = subprocess.run(("ip", "netns", "pids", name), check=False, text=True, capture_output=True)
            if pids.returncode == 0:
                values = pids.stdout.split()
                if any(not value.isdigit() for value in values): failures.append("cleanup_reap"); continue
                for value in values:
                    try: os.kill(int(value), signal.SIGTERM); os.kill(int(value), signal.SIGKILL)
                    except ProcessLookupError: pass
                deadline = time.monotonic() + 1
                while True:
                    check = subprocess.run(("ip", "netns", "pids", name), check=False, text=True, capture_output=True)
                    if check.returncode == 0 and not check.stdout.split(): break
                    listed = {line.split()[0] for line in subprocess.run(("ip","netns","list"),check=False,text=True,capture_output=True).stdout.splitlines() if line.split()}
                    if check.returncode and name not in listed: break
                    if check.returncode or time.monotonic() >= deadline or any(not value.isdigit() for value in check.stdout.split()): failures.append("cleanup_reap"); break
                    time.sleep(.01)
                if failures and failures[-1] == "cleanup_reap": continue
            elif pids.returncode != 1: failures.append("cleanup_reap"); continue
            elif name in {line.split()[0] for line in subprocess.run(("ip","netns","list"),check=False,text=True,capture_output=True).stdout.splitlines() if line.split()}: failures.append("cleanup_reap"); continue
            subprocess.run(("ip", "netns", "del", name), check=False, text=True, capture_output=True)
        except OSError: failures.append("cleanup_reap")
    try: remaining = {line.split()[0] for line in subprocess.run(("ip", "netns", "list"), check=False, text=True, capture_output=True).stdout.splitlines() if line.split()}
    except OSError: return "cleanup_residual"
    return "cleanup_residual" if set(names) & remaining else failures[0] if failures else None
def invoke_worker(plan, config_sha):
    with tempfile.TemporaryDirectory() as directory:
        evidence = Path(directory) / "evidence"; evidence.mkdir(mode=0o700)
        control = evidence / "control.json"
        suffix = stable_sha({"trial_id": plan["trial_id"], "config_sha": config_sha})[:10]
        command = [sys.executable, str(ROOT / "tests/mobility_netns.py"), "worker", "--mechanism", plan["mechanism"], "--arm", plan["arm"], "--control-path", str(control), "--evidence-dir", str(evidence), "--suffix", suffix]
        try:
            process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            stdout, stderr = process.communicate(timeout=40)
            payload = _worker_payload(stdout) if process.returncode == 0 else None
            if payload is None: payload = _supervisor_outcome("worker_exit", _control_record(control), evidence)
            else:
                reduced = _reduce_evidence(_control_record(control), evidence)
                if reduced is None: payload.update({"scheduled_payloads":None,"attempted_payloads":None,"sent_payloads":None,"received_payloads":None,"lost_payloads":None,"duplicate_payloads":None,"reordered_payloads":None,"outage_ns":None,"evidence_complete":False,"failure":True,"censored":True})
                else:
                    reduced["failure"] = payload["failure"] or reduced["failure"]
                    reduced["censored"] = payload["censored"] or reduced["censored"]
                    payload.update(reduced)
        except subprocess.TimeoutExpired:
            graceful = False
            try:
                os.killpg(process.pid, signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=5)
                payload = _worker_payload(stdout)
                graceful = payload is not None
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                process.communicate()
                payload = None
            if graceful:
                reduced = _reduce_evidence(_control_record(control), evidence)
                if reduced is None: payload.update({"scheduled_payloads":None,"attempted_payloads":None,"sent_payloads":None,"received_payloads":None,"lost_payloads":None,"duplicate_payloads":None,"reordered_payloads":None,"outage_ns":None,"evidence_complete":False,"failure":True,"censored":True})
                else:
                    reduced["failure"] = payload["failure"] or reduced["failure"]
                    reduced["censored"] = payload["censored"] or reduced["censored"]
                    payload.update(reduced)
            if not graceful:
                payload = _supervisor_outcome("worker_timeout", _control_record(control), evidence)
        except OSError:
            payload = _supervisor_outcome("worker_exit", _control_record(control), evidence)
        except json.JSONDecodeError:
            payload = _supervisor_outcome("worker_exit", _control_record(control), evidence)
        finally:
            cleanup = _cleanup_worker_namespaces(suffix)
            payload["cleanup_complete"] = cleanup is None
            if cleanup:
                payload["error_category"] = cleanup
                payload["failure"] = payload["censored"] = True
    row = {k: None for k in RAW_FIELDS}
    row.update({"protocol_id":"Q1", "contract_version":contract()["contract_version"], "host_epoch":None,
      "setup_status":"complete", "exclusion_reason":plan["exclusion_reason"], "error_category":None, "censored":True, "failure":True,
      "scheduled_payloads":None,"attempted_payloads":None,"sent_payloads":None,"received_payloads":None,"lost_payloads":None,"duplicate_payloads":None,"reordered_payloads":None,"outage_ns":None,
      "interface_counter_by_ordinal":{}, "process_user_cpu_ns":None,"process_system_cpu_ns":None,"cpu_complete":False,"cleanup_complete":None,"evidence_complete":False,"environment_complete":False,"topology_complete":False,"configuration_sha256":config_sha})
    row.update({k:v for k,v in payload.items() if k in row})
    row["_command_sha256"] = payload.get("command_sha256")
    row.update({k:v for k,v in plan.items() if k in row})
    if row["error_category"] not in ERROR_CATEGORIES and row["error_category"] is not None:
        row["error_category"] = "worker_output"
    if row["setup_status"] == "failed":
        row["exclusion_reason"] = "setup_failure"
        if row["error_category"] is None: row["error_category"] = "worker_output"
    elif row["failure"] and row["error_category"] is None:
        row["error_category"] = "authenticated_events"
    elif not row["failure"]:
        row["error_category"] = None
    return row

def implementation_sources():
    return {str(path.relative_to(ROOT)): sha(path) for path in sorted(SOURCE_FILES)}
def source_identity():
    return "sha256:" + stable_sha(implementation_sources())
def source_digest():
    return source_identity()
def topology_digest():
    return stable_sha(contract()["topology"])
def environment(source_identity, git_commit, host_epoch, config_sha, command_sha, topology=None):
    return {"source_identity":source_identity, "implementation_sources":implementation_sources(), "git_commit":git_commit, "host_epoch":host_epoch, "kernel_release":platform.release(), "distribution":platform.platform(),
      "cpu_model":"redacted", "cpu_governor":"redacted", "nic_driver":"redacted", "topology_sha256":topology_digest(), "command_sha256":command_sha,
      "binary_sha256":source_digest(), "configuration_sha256":config_sha, "capabilities":["CAP_NET_ADMIN","CAP_NET_RAW"], "clock_source":"monotonic",
      "mtu":1500, "socket_buffer":SOCKET_BUFFER, "qdisc":"fq_codel", "offloads":"disabled",
      "environment_checks":{"mtu":1500,"socket_buffer":SOCKET_BUFFER,"qdisc":"fq_codel","offloads":"disabled"},
      **(topology or {field: None for field in ("namespace_count", "interface_count", "non_loopback_interface_count", "veth_pair_count")})}

def package(output, supplied_source_identity, host_epoch, smoke=False, git_commit=None):
    computed_source_identity = source_identity()
    if supplied_source_identity != computed_source_identity:
        raise RuntimeError("source identity mismatch")
    if not isinstance(host_epoch, str) or not (re.fullmatch(r"[A-Za-z0-9_-]{1,64}", host_epoch) if smoke else re.fullmatch(r"closed-lab-epoch-[0-9]{3,}", host_epoch)):
        raise RuntimeError("invalid host epoch")
    if git_commit is None: git_commit = os.environ.get("GITHUB_SHA")
    if not isinstance(git_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", git_commit):
        raise RuntimeError("git commit required")
    if not smoke:
        head = subprocess.run(("git","rev-parse","HEAD"),check=False,text=True,capture_output=True,cwd=ROOT)
        status = subprocess.run(("git","status","--porcelain","--untracked-files=all"),check=False,text=True,capture_output=True,cwd=ROOT)
        if head.returncode or status.returncode or head.stdout.strip()!=git_commit or os.environ.get("GITHUB_SHA")!=git_commit or status.stdout or os.environ.get("Q1_CLEAN_TREE")!="true":
            raise RuntimeError("trusted commit/clean-tree attestation required")
    elif os.environ.get("GITHUB_SHA") and git_commit != os.environ["GITHUB_SHA"]:
        raise RuntimeError("git commit mismatch")
    c = contract(); pf = preflight(); plans = schedule(smoke); config_sha = stable_sha({"protocol":sha(PROTOCOL), "sources":source_digest(), "seed":ORDER_SEED, "host_epoch":host_epoch})
    rows, command_digests = [], []
    for plan in plans:
        row = invoke_worker(plan, config_sha); row["host_epoch"] = host_epoch
        command_digests.append(row.pop("_command_sha256", None)); rows.append(row)
    command_sha=stable_sha(sorted(x for x in command_digests if x))
    topology_fields = ("namespace_count", "interface_count", "non_loopback_interface_count", "veth_pair_count")
    observed = [tuple(row.get(field) for field in topology_fields) for row in rows]
    unanimous = bool(observed) and all(row.get("topology_complete") and row.get("environment_complete") for row in rows) and len(set(observed)) == 1 and observed[0] == (3, 10, 7, 3)
    topology_observation = dict(zip(topology_fields, observed[0])) if unanimous else {field: None for field in topology_fields}
    eligible = unanimous and all(row.get("cleanup_complete") is True and row.get("evidence_complete") is True and row.get("cpu_complete") is True and row.get("counter_complete") is True and row.get("environment_complete") is True and row.get("topology_complete") is True and not str(row.get("error_category") or "").startswith("cleanup_") for row in rows)
    data = {"environment":environment(supplied_source_identity,git_commit,host_epoch,config_sha,command_sha,topology_observation), "topology":{"address_family":"IPv4-only","topology_sha256":topology_digest(),"command_sha256":command_sha,"configuration_sha256":config_sha,**topology_observation,"topology_complete":unanimous,"dns_disabled":True,"neighbor_flush_prohibited":True}, "raw":rows, "summary":[] if smoke or not eligible else summary(rows,config_sha), "publication_eligible":eligible, "smoke_non_result":smoke, "preflight":pf}
    def forbidden(value):
        if isinstance(value,list): return any(forbidden(item) for item in value)
        if isinstance(value,dict): return any(forbidden(item) for item in value.values())
        if not isinstance(value,str): return False
        if value.startswith("--") or value.startswith(("r8q1-","qc","qr","qso","qsn","qbo","qbn")): return True
        try: ipaddress.ip_address(value); return True
        except ValueError: return False
    if forbidden(data): raise RuntimeError("identifier redaction violation")
    output=Path(output); output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temp:
        temp=Path(temp)
        for name,value in data.items(): (temp/(name+".json")).write_text(json.dumps(value,sort_keys=True,separators=(",",":")))
        hashes={p.name:sha(p) for p in temp.iterdir()}
        (temp/"manifest.json").write_text(json.dumps({"protocol_sha256":sha(PROTOCOL),"source_identity":supplied_source_identity,"implementation_sources":implementation_sources(),"git_commit":git_commit,"host_epoch":host_epoch,"row_count":len(rows),"files":hashes},sort_keys=True))
        if output.exists(): raise RuntimeError("refusing to overwrite result package")
        os.replace(temp,output)

def regenerate(output):
    output=Path(output); manifest=json.loads((output/"manifest.json").read_text())
    if manifest.get("protocol_sha256") != sha(PROTOCOL): raise RuntimeError("preregistration hash mismatch")
    if os.environ.get("GITHUB_SHA") and manifest.get("git_commit") != os.environ["GITHUB_SHA"]: raise RuntimeError("git commit mismatch")
    for name, expected in manifest.get("files",{}).items():
        if sha(output/name) != expected: raise RuntimeError("package hash mismatch")
    raw=json.loads((output/"raw.json").read_text()); environment=json.loads((output/"environment.json").read_text()); topology=json.loads((output/"topology.json").read_text()); smoke=json.loads((output/"smoke_non_result.json").read_text()); published=json.loads((output/"publication_eligible.json").read_text())
    if len(raw) != manifest.get("row_count") or any(r.get("host_epoch") != manifest.get("host_epoch") for r in raw): raise RuntimeError("row binding mismatch")
    expected_config=stable_sha({"protocol":sha(PROTOCOL),"sources":source_digest(),"seed":ORDER_SEED,"host_epoch":manifest["host_epoch"]})
    topology_fields=("namespace_count","interface_count","non_loopback_interface_count","veth_pair_count")
    observed=[tuple(row.get(field) for field in topology_fields) for row in raw]
    unanimous=bool(observed) and all(row.get("topology_complete") and row.get("environment_complete") for row in raw) and len(set(observed))==1 and observed[0]==(3,10,7,3)
    expected_topology=dict(zip(topology_fields,observed[0])) if unanimous else {field:None for field in topology_fields}
    eligible=unanimous and all(row.get("cleanup_complete") is True and row.get("evidence_complete") is True and row.get("cpu_complete") is True and row.get("counter_complete") is True and row.get("environment_complete") is True and row.get("topology_complete") is True and not str(row.get("error_category") or "").startswith("cleanup_") for row in raw)
    if published is not eligible: raise RuntimeError("publication binding mismatch")
    common=(environment.get("source_identity") != manifest.get("source_identity") or environment.get("implementation_sources") != implementation_sources() or manifest.get("implementation_sources") != implementation_sources() or (not smoke and environment.get("source_identity") != source_identity()) or environment.get("git_commit") != manifest.get("git_commit") or environment.get("host_epoch") != manifest.get("host_epoch") or environment.get("configuration_sha256") != expected_config or environment.get("binary_sha256") != source_digest() or topology.get("topology_sha256") != topology_digest() or topology.get("configuration_sha256") != expected_config or topology.get("topology_complete") is not unanimous)
    if common or any(environment.get(field)!=value or topology.get(field)!=value for field,value in expected_topology.items()): raise RuntimeError("environment binding mismatch")
    rebuilt=summary(raw,expected_config) if not smoke and eligible else []
    existing=json.loads((output/"summary.json").read_text())
    if stable_sha(rebuilt) != stable_sha(existing): raise RuntimeError("summary regeneration mismatch")
    temporary=output/"summary.json.tmp"; temporary.write_text(json.dumps(rebuilt,sort_keys=True,separators=(",",":"))); os.replace(temporary,output/"summary.json")
    return 0
def main(argv=None):
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="command",required=True)
    sub.add_parser("preflight")
    identity=sub.add_parser("source-identity")
    regen=sub.add_parser("regenerate"); regen.add_argument("--output",required=True)
    run=sub.add_parser("run"); run.add_argument("--output",required=True); run.add_argument("--source-identity",required=True); run.add_argument("--git-commit",required=True); run.add_argument("--host-epoch",required=True); run.add_argument("--smoke",action="store_true")
    a=p.parse_args(argv)
    try:
        if a.command == "preflight": print(json.dumps(preflight(),sort_keys=True)); return 0
        if a.command == "source-identity": print(source_identity()); return 0
        if a.command == "regenerate": return regenerate(a.output)
        package(a.output,a.source_identity,a.host_epoch,a.smoke,a.git_commit); return 0
    except RuntimeError as error:
        print(json.dumps({"status":"failed","error":"preflight_or_package_failure","category":str(error).split(":")[0]},sort_keys=True),file=sys.stderr)
        return 2
if __name__ == "__main__": raise SystemExit(main())
