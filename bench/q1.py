#!/usr/bin/env python3
"""Frozen Q1 v3 runner.  It deliberately has no unprivileged/simulated mode."""
import argparse, hashlib, ipaddress, json, os, platform, random, shutil, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL, MANIFEST = ROOT / "bench/protocols/q1.json", ROOT / "bench/protocols/manifest.json"
MECHANISMS = ("R8", "TCP-reconnect", "GARP-VIP")
ARMS = ("abrupt-break", "make-before-break")
PAIR_ORDER = tuple((m, a) for m in MECHANISMS for a in ARMS)
WARMUPS, MEASURED, BLOCK_SIZE, RESAMPLES = 20, 200, 20, 10000
ORDER_SEED, BOOTSTRAP_SEED = "r8-q1-block-order-v2", "r8-q1-block-bootstrap-v2"
RAW_FIELDS = ("protocol_id", "contract_version", "trial_id", "block_id", "host_epoch", "mechanism", "arm", "randomization_position", "setup_status", "exclusion_reason", "error_category", "t_minus_3_ns", "activation_ns", "cutover_ns", "observation_end_ns", "readiness_ns", "censored", "failure", "sent_payloads", "received_payloads", "lost_payloads", "duplicate_payloads", "reordered_payloads", "outage_ns", "interface_counter_by_ordinal", "process_user_cpu_ns", "process_system_cpu_ns", "configuration_sha256")
ERROR_CATEGORIES = frozenset(("namespace_create", "forwarding_config", "veth_create", "namespace_move", "bridge_create", "address_config", "link_activate", "route_client_default", "route_server_main", "route_old_policy", "route_candidate_policy", "route_vip_policy", "candidate_deactivate", "counter_read", "endpoint_setup", "endpoint_exit", "timeline", "authenticated_events", "worker_internal", "worker_timeout", "worker_exit", "worker_output"))
SOURCE_FILES = (ROOT / "reference/r8ref.py", ROOT / "reference/r8session.py", ROOT / "reference/r8mobility.py", ROOT / "reference/r8move.py", ROOT / "bench/q1.py", PROTOCOL, ROOT / "tests/mobility_netns.py", ROOT / "requirements-dev.txt")

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def stable_sha(value): return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def contract():
    data = json.loads(PROTOCOL.read_text())
    manifest = json.loads(MANIFEST.read_text())
    entry = next((x for x in manifest["preregistrations"] if x["protocol_id"] == "Q1"), None)
    if not entry or entry["sha256"] != sha(PROTOCOL) or entry["contract_version"] != data["contract_version"]:
        raise RuntimeError("Q1 preregistration/manifest hash mismatch")
    if data["contract_version"] != "r8-benchmark-preregistration-v3": raise RuntimeError("wrong Q1 contract")
    return data

def schedule(smoke=False):
    """The sole global randomization. Smoke is explicitly not a result schedule."""
    if smoke:
        return [{"trial_id": i, "block_id": 0, "randomization_position": i, "mechanism": m, "arm": a, "exclusion_reason": "smoke_non_result"} for i, (m,a) in enumerate(PAIR_ORDER)]
    items = list(PAIR_ORDER) * 220
    random.Random(ORDER_SEED).shuffle(items)
    seen, result = {p: 0 for p in PAIR_ORDER}, []
    for i, (mechanism, arm) in enumerate(items):
        ordinal = seen[(mechanism, arm)]; seen[(mechanism, arm)] += 1
        result.append({"trial_id": i, "block_id": i // BLOCK_SIZE, "randomization_position": i % BLOCK_SIZE,
                       "mechanism": mechanism, "arm": arm,
                       "exclusion_reason": "warmup" if ordinal < WARMUPS else None})
    assert len(result) == 1320 and len({x["block_id"] for x in result}) == 66
    return result

def capabilities():
    try:
        text = Path("/proc/self/status").read_text()
        capeff = int(next(x.split()[1] for x in text.splitlines() if x.startswith("CapEff:")), 16)
    except (OSError, StopIteration, ValueError): return False
    return os.geteuid() == 0 and bool(capeff & (1 << 12)) and bool(capeff & (1 << 13))

def preflight():
    contract()
    missing = [x for x in ("ip", "tc", "arping") if shutil.which(x) is None]
    if os.geteuid() != 0: raise RuntimeError("Q1 requires uid 0")
    if not capabilities(): raise RuntimeError("Q1 requires effective CAP_NET_ADMIN and CAP_NET_RAW")
    if missing: raise RuntimeError("Q1 missing required setup binary: " + ",".join(missing))
    return {"capabilities": ["CAP_NET_ADMIN", "CAP_NET_RAW"], "required_binaries": ["ip", "tc", "arping"]}

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
        answer.append({"protocol_id":"Q1","contract_version":"r8-benchmark-preregistration-v3","mechanism":mechanism,"arm":arm,"measured_trial_count":len(measured),"setup_failure_count":sum(r["setup_status"] == "failed" for r in measured),**point,"block_bootstrap_95_percent_ci":ci,"configuration_sha256":configuration_sha256})
    return answer


def invoke_worker(plan, config_sha):
    command = [sys.executable, str(ROOT / "tests/mobility_netns.py"), "worker", "--mechanism", plan["mechanism"], "--arm", plan["arm"]]
    try:
        run = subprocess.run(command, text=True, capture_output=True, timeout=40, check=False)
        payload = json.loads(run.stdout) if run.returncode == 0 else {"setup_status":"failed", "failure":True, "censored":True, "error_category":"worker_exit"}
    except subprocess.TimeoutExpired:
        payload = {"setup_status":"failed", "failure":True, "censored":True, "error_category":"worker_timeout"}
    except (json.JSONDecodeError, OSError):
        payload = {"setup_status":"failed", "failure":True, "censored":True, "error_category":"worker_output"}
    row = {k: None for k in RAW_FIELDS}
    row.update({"protocol_id":"Q1", "contract_version":"r8-benchmark-preregistration-v3", "host_epoch":None,
      "setup_status":"complete", "exclusion_reason":plan["exclusion_reason"], "error_category":None, "censored":True, "failure":True,
      "sent_payloads":0,"received_payloads":0,"lost_payloads":0,"duplicate_payloads":0,"reordered_payloads":0,"outage_ns":None,
      "interface_counter_by_ordinal":{}, "process_user_cpu_ns":0,"process_system_cpu_ns":0,"configuration_sha256":config_sha})
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

def source_digest():
    return stable_sha({str(path.relative_to(ROOT)): sha(path) for path in SOURCE_FILES})
def topology_digest():
    return stable_sha(contract()["topology"])
def environment(source_identity, host_epoch, config_sha, command_sha):
    return {"source_identity":source_identity, "host_epoch":host_epoch, "kernel_release":platform.release(), "distribution":platform.platform(),
      "cpu_model":"redacted", "cpu_governor":"redacted", "nic_driver":"redacted", "topology_sha256":topology_digest(), "command_sha256":command_sha,
      "binary_sha256":source_digest(), "configuration_sha256":config_sha, "capabilities":["CAP_NET_ADMIN","CAP_NET_RAW"], "clock_source":"monotonic",
      "namespace_count":3,"interface_count":10,"non_loopback_interface_count":7,"veth_pair_count":3}

def package(output, source_identity, host_epoch, smoke=False):
    c = contract(); pf = preflight(); plans = schedule(smoke); config_sha = stable_sha({"protocol":sha(PROTOCOL), "sources":source_digest(), "seed":ORDER_SEED, "host_epoch":host_epoch})
    rows, command_digests = [], []
    for plan in plans:
        row = invoke_worker(plan, config_sha); row["host_epoch"] = host_epoch
        command_digests.append(row.pop("_command_sha256", None)); rows.append(row)
    command_sha=stable_sha(sorted(x for x in command_digests if x))
    data = {"environment":environment(source_identity,host_epoch,config_sha,command_sha), "topology":{"address_family":"IPv4-only","topology_sha256":topology_digest(),"command_sha256":command_sha,"configuration_sha256":config_sha,"namespace_count":3,"interface_count":10,"non_loopback_interface_count":7,"veth_pair_count":3,"dns_disabled":True,"neighbor_flush_prohibited":True}, "raw":rows, "summary":[] if smoke else summary(rows,config_sha), "smoke_non_result":smoke, "preflight":pf}
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
        (temp/"manifest.json").write_text(json.dumps({"protocol_sha256":sha(PROTOCOL),"source_identity":source_identity,"host_epoch":host_epoch,"row_count":len(rows),"files":hashes},sort_keys=True))
        if output.exists(): raise RuntimeError("refusing to overwrite result package")
        os.replace(temp,output)

def regenerate(output):
    output=Path(output); manifest=json.loads((output/"manifest.json").read_text())
    if manifest.get("protocol_sha256") != sha(PROTOCOL): raise RuntimeError("preregistration hash mismatch")
    for name, expected in manifest.get("files",{}).items():
        if sha(output/name) != expected: raise RuntimeError("package hash mismatch")
    raw=json.loads((output/"raw.json").read_text()); environment=json.loads((output/"environment.json").read_text()); topology=json.loads((output/"topology.json").read_text())
    if len(raw) != manifest.get("row_count") or any(r.get("host_epoch") != manifest.get("host_epoch") for r in raw): raise RuntimeError("row binding mismatch")
    expected_config=stable_sha({"protocol":sha(PROTOCOL),"sources":source_digest(),"seed":ORDER_SEED,"host_epoch":manifest["host_epoch"]})
    if environment.get("source_identity") != manifest.get("source_identity") or environment.get("host_epoch") != manifest.get("host_epoch") or environment.get("configuration_sha256") != expected_config or environment.get("binary_sha256") != source_digest() or environment.get("interface_count") != 10 or environment.get("non_loopback_interface_count") != 7 or environment.get("veth_pair_count") != 3 or topology.get("topology_sha256") != topology_digest() or topology.get("configuration_sha256") != expected_config or topology.get("interface_count") != 10 or topology.get("non_loopback_interface_count") != 7 or topology.get("veth_pair_count") != 3: raise RuntimeError("environment binding mismatch")
    rebuilt=summary(raw,expected_config) if not json.loads((output/"smoke_non_result.json").read_text()) else []
    existing=json.loads((output/"summary.json").read_text())
    if stable_sha(rebuilt) != stable_sha(existing): raise RuntimeError("summary regeneration mismatch")
    temporary=output/"summary.json.tmp"; temporary.write_text(json.dumps(rebuilt,sort_keys=True,separators=(",",":"))); os.replace(temporary,output/"summary.json")
    return 0
def main(argv=None):
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="command",required=True)
    sub.add_parser("preflight")
    regen=sub.add_parser("regenerate"); regen.add_argument("--output",required=True)
    run=sub.add_parser("run"); run.add_argument("--output",required=True); run.add_argument("--source-identity",required=True); run.add_argument("--host-epoch",required=True); run.add_argument("--smoke",action="store_true")
    a=p.parse_args(argv)
    try:
        if a.command == "preflight": print(json.dumps(preflight(),sort_keys=True)); return 0
        if a.command == "regenerate": return regenerate(a.output)
        package(a.output,a.source_identity,a.host_epoch,a.smoke); return 0
    except RuntimeError as error:
        print(json.dumps({"status":"failed","error":"preflight_or_package_failure","category":str(error).split(":")[0]},sort_keys=True),file=sys.stderr)
        return 2
if __name__ == "__main__": raise SystemExit(main())
