#!/usr/bin/env python3
"""Frozen Q3 closed-lab benchmark; output contains measurements, never secrets."""
import argparse
import hashlib
import importlib.metadata
import fcntl
import json
import os
import random
import shutil
import signal
import socket
import ssl
import statistics
import subprocess
import sys
import platform
import tempfile
import threading
import time
import struct
from datetime import datetime, timezone
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import r8session as r8

PROTOCOL = ROOT / "bench/protocols/q3.json"
CERT = ROOT / "bench/fixtures/q3-cert.pem"
KEY = ROOT / "bench/fixtures/q3-key.pem"
MECHANISMS = ("R8-cookie-pinned-full-handshake", "TLS-1.3-full-handshake")
WARMUPS, MEASURED, BLOCK_SIZE, TIMEOUT = 50, 1000, 20, 5.0
ORDER_SEED, BOOTSTRAP_SEED = "r8-q3-block-order-v1", "r8-q3-block-bootstrap-v1"
R8_BINDING_BUDGET = 1252
LO_COUNTERS = ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets")
SMOKE_STATUS = "smoke-non-result"
FULL_EPOCH = re.compile(r"closed-lab-epoch-[0-9]{3,}\Z")
SAFE_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
SOURCE_LABEL = re.compile(r"(?:sha256:[0-9a-f]{64}|[A-Za-z0-9][A-Za-z0-9_-]{0,127})\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
SOURCE_INPUTS = {
    "bench/fixtures/q3-cert.pem": CERT,
    "bench/fixtures/q3-key.pem": KEY,
    "bench/protocols/q3.json": PROTOCOL,
    "bench/q3.py": Path(__file__).resolve(),
    "reference/r8session.py": ROOT / "reference/r8session.py",
    "requirements-dev.txt": ROOT / "requirements-dev.txt",
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def source_hashes():
    return {path: digest(source) for path, source in sorted(SOURCE_INPUTS.items())}


def source_identity():
    encoded = json.dumps(source_hashes(), sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()



def _proc_net_dev():
    lines = Path("/proc/net/dev").read_text().splitlines()
    headers = [line.split("|") for line in lines[:2]]
    expected_rx = ["bytes", "packets", "errs", "drop", "fifo", "frame", "compressed", "multicast"]
    expected_tx = ["bytes", "packets", "errs", "drop", "fifo", "colls", "carrier", "compressed"]
    if (
        len(lines) < 3
        or len(headers[0]) != 3
        or [part.strip() for part in headers[0]] != ["Inter-", "Receive", "Transmit"]
        or len(headers[1]) != 3
        or headers[1][0].strip() != "face"
        or headers[1][1].split() != expected_rx
        or headers[1][2].split() != expected_tx
    ):
        raise ValueError("malformed /proc/net/dev")
    interfaces = {}
    for line in lines[2:]:
        if not line.strip() or ":" not in line:
            raise ValueError("malformed /proc/net/dev")
        name, values = line.split(":", 1)
        name = name.strip()
        fields = values.split()
        if not name or len(fields) != 16 or any(not field.isdecimal() for field in fields):
            raise ValueError("malformed /proc/net/dev")
        if name in interfaces:
            raise ValueError("duplicate interface in /proc/net/dev")
        interfaces[name] = [int(field) for field in fields]
    if "lo" not in interfaces:
        raise ValueError("/proc/net/dev missing lo")
    values = interfaces["lo"]
    counters = {
        "rx_bytes": values[0],
        "tx_bytes": values[8],
        "rx_packets": values[1],
        "tx_packets": values[9],
    }
    return set(interfaces), counters

def _loopback_counters():
    return _proc_net_dev()[1]

def net():
    return _loopback_counters()

def _loopback_flags_mtu():
    name = b"lo"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        flags = struct.unpack("16sH", fcntl.ioctl(control.fileno(), 0x8913, struct.pack("16sH", name, 0))[:18])[1]
        mtu = struct.unpack("16si", fcntl.ioctl(control.fileno(), 0x8921, struct.pack("16si", name, 0))[:20])[1]
    return flags, mtu

def isolated_netns_proof():
    try:
        own = os.stat("/proc/self/ns/net").st_ino
        init = os.stat("/proc/1/ns/net").st_ino
        flags, mtu = _loopback_flags_mtu()
        interfaces, _ = _proc_net_dev()
        return os.environ.get("Q3_ISOLATED_NETNS") == "1" and own != init and interfaces == {"lo"} and bool(flags & 1) and mtu == 65536
    except (OSError, ValueError, struct.error):
        return False

def require_isolated_netns():
    if not isolated_netns_proof():
        raise ValueError("Q3 evidence run requires a dedicated loopback-only network namespace")

def require_loopback_delta(delta):
    if set(delta) != set(LO_COUNTERS) or delta["rx_bytes"] != delta["tx_bytes"] or delta["rx_packets"] != delta["tx_packets"]:
        raise ValueError("loopback receive/transmit counters differ")
def _fixture_spki_pin():
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    certificate = x509.load_pem_x509_certificate(CERT.read_bytes())
    return hashlib.sha256(
        certificate.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest()






def _r8_id(label):
    return r8.Identity.from_seed(hashlib.sha256(b"r8-q3 identity " + label).digest())
def cookie_bucket(clock):
    return int(clock() // 10)



def _random_scid():
    while True:
        scid = int.from_bytes(r8._random(8), "big")
        if scid:
            return scid

def _r8_server_ready():
    client_id, server_id = _r8_id(b"client"), _r8_id(b"server")
    client_pin = r8.PeerPin(2, server_id.eid, server_id.public)
    server_pin = r8.PeerPin(1, client_id.eid, client_id.public)
    local, peer = __import__("ipaddress").IPv6Address("::1"), __import__("ipaddress").IPv6Address("::2")
    clock = time.monotonic
    config = r8.ServerConfig(server_id, server_pin, 1, 1, 0, peer, local, R8_BINDING_BUDGET, 4, 4)
    server = r8.ServerMachine(config, r8._random(16), r8._random(32), None, 0, clock,
                              r8.PrevalidationLimiter(clock, r8._random(32)))
    binding_selector = r8._random(16)
    ready = threading.Event()
    port = []
    error = []

    def serve():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.bind(("127.0.0.1", 0)); s.settimeout(TIMEOUT); port.append(s.getsockname()[1]); ready.set()
                while True:
                    packet, addr = s.recvfrom(R8_BINDING_BUDGET)
                    header, payload = r8.parse_packet(packet)
                    binding = r8.UdpBinding.from_endpoint(addr[0], addr[1], 1, binding_selector)
                    typ = r8.decode(payload)[0]
                    if typ == 1: reply = server.receive_open_packet(packet, binding, cookie_bucket(clock))
                    elif typ == 3: reply = server.receive_open_auth(packet, binding, cookie_bucket(clock), r8._random(32), r8._random(32))
                    elif typ == 5: server.receive_protected(packet); continue
                    elif typ == 6:
                        if server.receive_protected(packet) != b"x": raise ValueError("application byte mismatch")
                        reply = server.send_data(header.scid, b"x")
                    else: raise ValueError("unexpected R8 packet")
                    s.sendto(reply, addr)
                    if typ == 6: return
        except Exception as exc: error.append(type(exc).__name__)

    thread = threading.Thread(target=serve, daemon=True); thread.start()
    if not ready.wait(TIMEOUT): raise TimeoutError("R8 server readiness")

    machine = r8.ClientMachine(client_id, client_pin, 1, 0, local, peer, clock, R8_BINDING_BUDGET)

    def client():
        captured = None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(TIMEOUT)
                packet = machine.start(_random_scid(), r8._random(32), r8._random(32)); s.sendto(packet, ("127.0.0.1", port[0]))
                packet = machine.receive_verify(s.recv(R8_BINDING_BUDGET)); s.sendto(packet, ("127.0.0.1", port[0]))
                packet = machine.receive_ack(s.recv(R8_BINDING_BUDGET)); s.sendto(packet, ("127.0.0.1", port[0]))
                packet = machine.send_data(b"x"); s.sendto(packet, ("127.0.0.1", port[0]))
                if machine.receive_protected(s.recv(R8_BINDING_BUDGET)) != b"x": raise ValueError("application response mismatch")
                captured = _measurement_end()
                client.snapshot = captured
        finally:
            thread.join(TIMEOUT)
        if thread.is_alive(): raise TimeoutError("R8 server completion")
        if error: raise RuntimeError(error[0])
        return captured
    return client

def r8_trial():
    _r8_server_ready()()


def _disable_tickets(context):
    if getattr(ssl, "OP_NO_TICKET", None) is None:
        raise RuntimeError("ssl.OP_NO_TICKET is required for Q3")
    context.options |= ssl.OP_NO_TICKET
    if not context.options & ssl.OP_NO_TICKET:
        raise RuntimeError("unable to disable TLS session tickets")
def _disable_server_tickets(context):
    if not hasattr(context, "num_tickets"):
        raise RuntimeError("ssl server num_tickets is required for Q3")
    context.num_tickets = 0
    if context.num_tickets != 0:
        raise RuntimeError("unable to disable TLS server session tickets")


def _tls_server_ready():
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    expected_pin = _fixture_spki_pin()
    ready, release, port, error = threading.Event(), threading.Event(), [], []

    def serve():
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            _disable_tickets(context)
            _disable_server_tickets(context)
            context.load_cert_chain(CERT, KEY)
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); listener.bind(("127.0.0.1", 0)); listener.listen(1); listener.settimeout(TIMEOUT)
                port.append(listener.getsockname()[1]); ready.set()
                with context.wrap_socket(listener.accept()[0], server_side=True) as conn:
                    conn.settimeout(TIMEOUT)
                    if conn.recv(1) != b"x": raise ValueError("application byte mismatch")
                    conn.sendall(b"x")
                    if not release.wait(TIMEOUT):
                        raise TimeoutError("TLS client release")
        except Exception as exc: error.append(type(exc).__name__)

    thread = threading.Thread(target=serve, daemon=True); thread.start()
    if not ready.wait(TIMEOUT): raise TimeoutError("TLS server readiness")

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CERT))
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    _disable_tickets(context)

    def client():
        captured = None
        try:
            with socket.create_connection(("127.0.0.1", port[0]), TIMEOUT) as raw:
                with context.wrap_socket(raw, server_hostname="localhost") as conn:
                    try:
                        actual = hashlib.sha256(x509.load_der_x509_certificate(conn.getpeercert(binary_form=True)).public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
                        if actual != expected_pin: raise ssl.SSLError("SPKI pin mismatch")
                        conn.settimeout(TIMEOUT); conn.sendall(b"x")
                        if conn.recv(1) != b"x": raise ValueError("application response mismatch")
                        captured = _measurement_end()
                        client.snapshot = captured
                    finally:
                        release.set()
        finally:
            release.set()
            thread.join(TIMEOUT)
        if thread.is_alive(): raise TimeoutError("TLS server completion")
        if error: raise RuntimeError(error[0])
        return captured
    return client

def tls_trial():
    _tls_server_ready()()


def _measurement_start():
    return net(), time.process_time_ns(), time.monotonic_ns()
def _measurement_end():
    return net(), time.process_time_ns(), time.monotonic_ns()

def trial(mechanism):
    status, category = "success", None
    start_net = cpu = started = snapshot = client = None
    previous = None
    timer_started = False
    try:
        client = (_r8_server_ready if mechanism == MECHANISMS[0] else _tls_server_ready)()
        start_net, cpu, started = _measurement_start()
        previous = signal.getsignal(signal.SIGALRM)
        def expired(_signum, _frame): raise TimeoutError("Q3 trial timeout")
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, TIMEOUT)
        timer_started = True
        snapshot = client()
    except TimeoutError as exc:
        status, category = "timeout", type(exc).__name__
        snapshot = getattr(client, "snapshot", None)
    except Exception as exc:
        status, category = "failure", type(exc).__name__
        snapshot = getattr(client, "snapshot", None)
    finally:
        if timer_started:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
    if start_net is None or snapshot is None:
        return {"status": status, "error_category": category, "latency_ns": 0, "cpu_ns": 0, "network": {key: 0 for key in net()}}
    end_net, end_cpu, ended = snapshot
    return {"status": status, "error_category": category, "latency_ns": ended - started, "cpu_ns": end_cpu - cpu, "network": {k: end_net[k] - start_net[k] for k in start_net}}


def order(per_mechanism_count):
    rng, result = random.Random(ORDER_SEED), []
    remaining = per_mechanism_count
    block = 0
    while remaining:
        each = min(BLOCK_SIZE // len(MECHANISMS), remaining)
        items = [mechanism for mechanism in MECHANISMS for _ in range(each)]
        rng.shuffle(items)
        result.extend((block, position, mechanism) for position, mechanism in enumerate(items))
        remaining -= each
        block += 1
    return result
def planned_trials(per_mechanism_count, smoke):
    ordinals = {mechanism: 0 for mechanism in MECHANISMS}
    for block, position, mechanism in order(per_mechanism_count):
        ordinal = ordinals[mechanism]
        ordinals[mechanism] += 1
        yield block, position, mechanism, ordinal, not smoke and ordinal < WARMUPS


def worker(args):
    print(json.dumps(trial(args.mechanism), sort_keys=True)); return 0


def invoke_worker(mechanism):
    try:
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "worker", "--mechanism", mechanism], text=True, capture_output=True, timeout=TIMEOUT + 3, check=False)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error_category": "worker_timeout", "latency_ns": int(TIMEOUT * 1_000_000_000), "cpu_ns": 0, "network": {k: 0 for k in net()}}
    if result.returncode:
        return {"status": "failure", "error_category": "worker_exit", "latency_ns": 0, "cpu_ns": 0, "network": {k: 0 for k in net()}}
    try: return json.loads(result.stdout)
    except json.JSONDecodeError: return {"status": "failure", "error_category": "worker_output", "latency_ns": 0, "cpu_ns": 0, "network": {k: 0 for k in net()}}


def percentile(values, q):
    if not values: return None
    return sorted(values)[min(len(values) - 1, int((len(values) - 1) * q))]

def summary(rows):
    output = {"contract_version": json.loads(PROTOCOL.read_text())["contract_version"], "series": {}}
    for series in ("cold-process-primary", "warm-process"):
        output["series"][series] = {}
        for mechanism in MECHANISMS:
            selected = [r for r in rows if r["series"] == series and r["mechanism"] == mechanism and not r["excluded"]]
            success = [r["latency_ns"] for r in selected if r["status"] == "success"]
            blocks = [[r["latency_ns"] for r in selected if r["block"] == b and r["status"] == "success"] for b in sorted({r["block"] for r in selected})]
            rng = random.Random(BOOTSTRAP_SEED + series + mechanism)
            ci = {}
            bootstrap_ready = bool(blocks) and all(blocks) and len(success) >= 100
            for name, q in (("p50", .5), ("p90", .9), ("p99", .99)):
                samples = [percentile([v for group in (rng.choice(blocks) for _ in blocks) for v in group], q) for _ in range(10000)] if bootstrap_ready else []
                ci[name] = None if not samples else [percentile(samples, .025), percentile(samples, .975)]
            p99_supported = bootstrap_ready and ci["p99"][1] < int(TIMEOUT * 1_000_000_000)
            metrics = {"failure_rate": (sum(r["status"] != "success" for r in selected) / len(selected)) if selected else None,
                "latency_ns": {"p50": percentile(success, .5), "p90": percentile(success, .9), "p99": percentile(success, .99) if p99_supported else "unsupported", "confidence_intervals_95": ci},
                "p99_supported": p99_supported,
                "mean_cpu_ns": statistics.fmean([r["cpu_ns"] for r in selected]) if selected else None,
                "mean_network": {k: statistics.fmean([r["network"][k] for r in selected]) if selected else None for k in net()}}
            output["series"][series][mechanism] = metrics
    return output

def provenance():
    return {
        "cryptography": importlib.metadata.version("cryptography"),
        "requirements_dev_sha256": digest(ROOT / "requirements-dev.txt"),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
    }


def environment(source_label):
    sources = source_hashes()
    return {
        "source_identity": source_label,
        "implementation_source_identity": source_identity(),
        "implementation_sources": sources,
        "protocol_sha256": sources["bench/protocols/q3.json"],
        "fixture_certificate_sha256": sources["bench/fixtures/q3-cert.pem"],
        "fixture_key_sha256": sources["bench/fixtures/q3-key.pem"],
        "reference_sha256": sources["reference/r8session.py"],
        "requirements_dev_sha256": sources["requirements-dev.txt"],
        "loopback_interface": "lo",
        "loopback_mtu": int(Path("/sys/class/net/lo/mtu").read_text()),
        "cpu_policy": "process CPU clock; no affinity or governor modification",
        "toolchain": {"python": sys.version.split()[0], "openssl": ssl.OPENSSL_VERSION, "cryptography": provenance()["cryptography"]},
        "os": {"platform": platform.platform(), "kernel": platform.release(), "arch": platform.machine()},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "isolated_netns_proof": isolated_netns_proof(),
    }


def manifest(args, rows, directory):
    group_counts = []
    for series in ("cold-process-primary", "warm-process"):
        for mechanism in MECHANISMS:
            group = [row for row in rows if row["series"] == series and row["mechanism"] == mechanism]
            group_counts.append({
                "series": series,
                "mechanism": mechanism,
                "warmups": 0 if args.smoke else WARMUPS,
                "measured": 2 if args.smoke else MEASURED,
                "rows": len(group),
                "failures": sum(row["status"] != "success" for row in group),
            })
    return {
        "schema": "q3-run-manifest-v1",
        "status": SMOKE_STATUS if args.smoke else "completed",
        "source_identity": args.source_identity,
        "implementation_source_identity": source_identity(),
        "implementation_sources": source_hashes(),
        "host_epoch": args.host_epoch,
        "git_commit": args.git_commit,
        "isolated_netns_proof": True,
        "group_counts": group_counts,
        "row_count": len(rows),
        "failures": sum(row["status"] != "success" for row in rows),
        "post_hoc_exclusions": 0,
        "command_template": "python3 bench/q3.py run --output OUTPUT_DIR --source-identity SOURCE_ID --host-epoch HOST_EPOCH" + (" --smoke" if args.smoke else ""),
        "sha256": {name: digest(directory / name) for name in ("raw.jsonl", "environment.json", "summary.json")},
        "limitations": [
            "Closed-lab loopback measurements require a dedicated loopback-only network namespace.",
            "Smoke output is explicitly non-result and does not satisfy preregistered trial counts.",
        ],
        "toolchain_provenance": provenance(),
    }

def _git(command):
    return subprocess.run(["git", *command], cwd=ROOT, text=True, capture_output=True, check=True).stdout.strip()

def require_labels(args):
    if not SOURCE_LABEL.fullmatch(args.source_identity) or not SAFE_LABEL.fullmatch(args.host_epoch):
        raise ValueError("source identity and host epoch must be safe labels")
    if args.smoke:
        return
    if args.source_identity != source_identity():
        raise ValueError("full run source identity must match current Q3 implementation")
    if not FULL_EPOCH.fullmatch(args.host_epoch):
        raise ValueError("full run host epoch must be closed-lab-epoch-NNN")
    if not args.git_commit or not COMMIT.fullmatch(args.git_commit):
        raise ValueError("full run git commit must be an exact lowercase 40-character SHA")
    if _git(["rev-parse", "HEAD"]) != args.git_commit:
        raise ValueError("full run git commit must match HEAD")
    if os.environ.get("GITHUB_SHA") != args.git_commit:
        raise ValueError("full run git commit must match GITHUB_SHA")
    if _git(["status", "--porcelain"]):
        raise ValueError("full run requires a clean repository")

def run(args):
    require_isolated_netns()
    require_labels(args)
    per_mechanism_count = 2 if args.smoke else WARMUPS + MEASURED
    destination = Path(args.output)
    if destination.exists(): raise FileExistsError("output directory already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".q3-", dir=destination.parent))
    rows = []
    try:
        for series in ("cold-process-primary", "warm-process"):
            for block, position, mechanism, ordinal, excluded in planned_trials(per_mechanism_count, args.smoke):
                measurement = invoke_worker(mechanism) if series == "cold-process-primary" else trial(mechanism)
                require_loopback_delta(measurement["network"])
                measurement.update({"schema": "q3-raw-v1", "source_identity": args.source_identity, "series": series, "mechanism": mechanism, "host_epoch": args.host_epoch, "block": block, "order": position, "trial": ordinal, "excluded": excluded, "smoke_non_result": bool(args.smoke)})
                rows.append(measurement)
        (staging / "raw.jsonl").write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))
        saved_environment = environment(args.source_identity)
        if saved_environment["isolated_netns_proof"] is not True:
            raise ValueError("network namespace proof changed during run")
        (staging / "environment.json").write_text(json.dumps(saved_environment, sort_keys=True, indent=2) + "\n")
        (staging / "summary.json").write_text(json.dumps(summary(rows), sort_keys=True, indent=2) + "\n")
        (staging / "run-manifest.json").write_text(json.dumps(manifest(args, rows, staging), sort_keys=True, indent=2) + "\n")
        os.replace(staging, destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True); raise

def _validate_rows(manifest_data, saved, rows):
    smoke = manifest_data["status"] == SMOKE_STATUS
    if manifest_data["status"] not in {SMOKE_STATUS, "completed"}:
        raise ValueError("invalid run status")
    if manifest_data.get("isolated_netns_proof") is not True or saved.get("isolated_netns_proof") is not True:
        raise ValueError("missing isolated network namespace proof")
    if saved.get("source_identity") != manifest_data["source_identity"] or saved.get("loopback_interface") != "lo" or saved.get("loopback_mtu") != 65536:
        raise ValueError("environment consistency verification failed")
    labels = type("Args", (), {"smoke": smoke, "source_identity": manifest_data["source_identity"], "host_epoch": manifest_data["host_epoch"], "git_commit": manifest_data.get("git_commit")})()
    require_labels(labels)
    expected = []
    per_mechanism_count = 2 if smoke else WARMUPS + MEASURED
    for series in ("cold-process-primary", "warm-process"):
        for block, position, mechanism, ordinal, excluded in planned_trials(per_mechanism_count, smoke):
            expected.append((series, block, position, mechanism, ordinal, excluded))
    if len(rows) != len(expected) or manifest_data.get("row_count") != len(expected):
        raise ValueError("row count verification failed")
    groups = []
    for series in ("cold-process-primary", "warm-process"):
        for mechanism in MECHANISMS:
            group = [row for row in rows if row.get("series") == series and row.get("mechanism") == mechanism]
            groups.append({"series": series, "mechanism": mechanism, "warmups": 0 if smoke else WARMUPS, "measured": 2 if smoke else MEASURED, "rows": len(group), "failures": sum(row.get("status") != "success" for row in group)})
    if manifest_data.get("group_counts") != groups or manifest_data.get("failures") != sum(group["failures"] for group in groups):
        raise ValueError("group/failure verification failed")
    if manifest_data.get("post_hoc_exclusions") != 0:
        raise ValueError("post-hoc exclusions verification failed")
    if not smoke and manifest_data["failures"] != 0:
        raise ValueError("full run contains failures")
    fields = {"schema", "source_identity", "series", "mechanism", "host_epoch", "block", "order", "trial", "excluded", "smoke_non_result", "status", "error_category", "latency_ns", "cpu_ns", "network"}
    for row, (series, block, position, mechanism, ordinal, excluded) in zip(rows, expected):
        if set(row) != fields or row["schema"] != "q3-raw-v1" or row["source_identity"] != manifest_data["source_identity"] or row["host_epoch"] != manifest_data["host_epoch"] or (row["series"], row["block"], row["order"], row["mechanism"], row["trial"], row["excluded"]) != (series, block, position, mechanism, ordinal, excluded) or row["smoke_non_result"] is not smoke or row["status"] not in {"success", "failure", "timeout"} or (row["status"] == "success") != (row["error_category"] is None):
            raise ValueError("raw row consistency verification failed")
        if type(row["network"]) is not dict:
            raise ValueError("raw network verification failed")
        numeric = [row["latency_ns"], row["cpu_ns"], *row["network"].values()]
        if any(type(value) is not int or value < 0 for value in numeric):
            raise ValueError("raw numeric verification failed")
        require_loopback_delta(row["network"])

def regenerate(args):
    directory = Path(args.output)
    manifest_data = json.loads((directory / "run-manifest.json").read_text())
    if manifest_data.get("schema") != "q3-run-manifest-v1":
        raise ValueError("invalid run manifest")
    hashes = manifest_data.get("sha256")
    if set(hashes or ()) != {"raw.jsonl", "environment.json", "summary.json"}:
        raise ValueError("invalid manifest file hashes")
    for name, expected_hash in hashes.items():
        if expected_hash != digest(directory / name):
            raise ValueError("manifest hash verification failed: " + name)
    saved = json.loads((directory / "environment.json").read_text())
    current_sources = source_hashes()
    current_identity = source_identity()
    for recorded in (saved, manifest_data):
        if recorded.get("implementation_sources") != current_sources:
            raise ValueError("source/toolchain hash verification failed")
        if recorded.get("implementation_source_identity") != current_identity:
            raise ValueError("implementation source identity verification failed")
    if manifest_data.get("toolchain_provenance", {}).get("requirements_dev_sha256") != current_sources["requirements-dev.txt"]:
        raise ValueError("requirements toolchain hash verification failed")
    for key, expected in (("protocol_sha256", current_sources["bench/protocols/q3.json"]), ("fixture_certificate_sha256", current_sources["bench/fixtures/q3-cert.pem"]), ("fixture_key_sha256", current_sources["bench/fixtures/q3-key.pem"]), ("reference_sha256", current_sources["reference/r8session.py"]), ("requirements_dev_sha256", current_sources["requirements-dev.txt"])):
        if saved.get(key) != expected:
            raise ValueError("hash verification failed: " + key)
    rows = [json.loads(line) for line in (directory / "raw.jsonl").read_text().splitlines()]
    _validate_rows(manifest_data, saved, rows)
    rendered = json.dumps(summary(rows), sort_keys=True, indent=2) + "\n"
    if hashlib.sha256(rendered.encode()).hexdigest() != hashes["summary.json"]:
        raise ValueError("manifest summary verification failed")
    temporary = directory / ".summary.json.tmp"
    temporary.write_text(rendered)
    os.replace(temporary, directory / "summary.json")

def main():
    parser = argparse.ArgumentParser(); commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run"); run_parser.add_argument("--output", required=True); run_parser.add_argument("--source-identity", required=True); run_parser.add_argument("--host-epoch", required=True); run_parser.add_argument("--git-commit"); run_parser.add_argument("--smoke", action="store_true")
    work = commands.add_parser("worker"); work.add_argument("--mechanism", choices=MECHANISMS, required=True)
    regen = commands.add_parser("regenerate"); regen.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "worker": return worker(args)
    if args.command == "regenerate": return regenerate(args)
    return run(args)
if __name__ == "__main__": main()
