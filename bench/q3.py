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
import select
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import r8session as r8

PROTOCOL = ROOT / "bench/protocols/q3.json"
MANIFEST = ROOT / "bench/protocols/manifest.json"
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
    ".github/workflows/q3-full.yml": ROOT / ".github/workflows/q3-full.yml",
    "bench/fixtures/q3-cert.pem": CERT,
    "bench/fixtures/q3-key.pem": KEY,
    "bench/protocols/q3.json": PROTOCOL,
    "bench/protocols/manifest.json": MANIFEST,
    "bench/q3.py": Path(__file__).resolve(),
    "reference/r8ref.py": ROOT / "reference/r8ref.py",
    "reference/r8session.py": ROOT / "reference/r8session.py",
    "requirements-dev.txt": ROOT / "requirements-dev.txt",
    "spec/0004-wire-format-v0.2.md": ROOT / "spec/0004-wire-format-v0.2.md",
    "spec/0005-session-security-v0.1.md": ROOT / "spec/0005-session-security-v0.1.md",
    "spec/parameters-v0.1.md": ROOT / "spec/parameters-v0.1.md",
}



def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def source_hashes():
    return {path: digest(source) for path, source in sorted(SOURCE_INPUTS.items())}


def implementation_source_identity(sources):
    encoded = json.dumps(sources, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
def strict_json(text):
    def object_without_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON object key: " + key)
            value[key] = item
        return value
    return json.loads(text, object_pairs_hook=object_without_duplicates)


def source_identity():
    return implementation_source_identity(source_hashes())
def require_frozen_protocol():
    manifest_data = strict_json(MANIFEST.read_text())
    if (
        manifest_data.get("contract_version") != "r8-benchmark-preregistration-manifest-v1"
        or manifest_data.get("status") != "frozen-preregistrations-with-evidence-history"
        or manifest_data.get("scope") != "private-experimental-closed-lab"
    ):
        raise ValueError("invalid preregistration manifest")
    entries = [
        item for item in manifest_data.get("preregistrations", ())
        if isinstance(item, dict) and item.get("protocol_id") == "Q3"
    ]
    if len(entries) != 1:
        raise ValueError("missing unique Q3 preregistration")
    protocol_bytes = PROTOCOL.read_bytes()
    protocol_data = strict_json(protocol_bytes.decode())
    expected = {
        "path": "bench/protocols/q3.json",
        "size_bytes": len(protocol_bytes),
        "sha256": hashlib.sha256(protocol_bytes).hexdigest(),
        "status": "frozen-preregistered-no-current-source-results",
    }
    if any(entries[0].get(key) != value for key, value in expected.items()):
        raise ValueError("Q3 preregistration drift")
    if (
        protocol_data.get("protocol_id") != "Q3"
        or protocol_data.get("contract_version") != "r8-benchmark-preregistration-v1"
        or protocol_data.get("status") != "preregistered-no-results"
        or protocol_data.get("scope") != "private-experimental-closed-lab"
    ):
        raise ValueError("invalid Q3 protocol contract")



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
    binding_selector, ready, stop, port, error, sockets = r8._random(16), threading.Event(), threading.Event(), [], [], []

    def serve():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                sockets.append(s)
                s.bind(("127.0.0.1", 0)); s.settimeout(.1); port.append(s.getsockname()[1]); ready.set()
                while not stop.is_set():
                    try:
                        packet, addr = s.recvfrom(R8_BINDING_BUDGET)
                    except socket.timeout:
                        continue
                    header, payload = r8.parse_packet(packet)
                    binding = r8.UdpBinding.from_endpoint(addr[0], addr[1], 1, binding_selector)
                    typ = r8.decode(payload)[0]
                    if typ == 1: reply = server.receive_open_packet(packet, binding, cookie_bucket(clock))
                    elif typ == 3: reply = server.receive_open_auth(packet, binding, cookie_bucket(clock))
                    elif typ == 5: server.receive_protected(packet); continue
                    elif typ == 6:
                        if server.receive_protected(packet) != b"x": raise ValueError("application byte mismatch")
                        reply = server.send_data(header.scid, b"x")
                    else: raise ValueError("unexpected R8 packet")
                    s.sendto(reply, addr)
                    if typ == 6: return
        except OSError:
            if not stop.is_set(): error.append("OSError")
        except Exception as exc:
            error.append(type(exc).__name__)

    thread = threading.Thread(target=serve)

    def close():
        stop.set()
        for active in sockets:
            try: active.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            try: active.close()
            except OSError: pass
    started = False
    try:
        thread.start()
        started = True
        if not ready.wait(TIMEOUT): raise TimeoutError("R8 server readiness")
        machine = r8.ClientMachine(client_id, client_pin, 1, 0, local, peer, clock, R8_BINDING_BUDGET)
    except BaseException:
        close()
        if started: thread.join(TIMEOUT)
        raise

    def client():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            sockets.append(s)
            s.settimeout(TIMEOUT)
            packet = machine.start(_random_scid()); s.sendto(packet, ("127.0.0.1", port[0]))
            packet = machine.receive_verify(s.recv(R8_BINDING_BUDGET)); s.sendto(packet, ("127.0.0.1", port[0]))
            packet = machine.receive_ack(s.recv(R8_BINDING_BUDGET)); s.sendto(packet, ("127.0.0.1", port[0]))
            packet = machine.send_data(b"x"); s.sendto(packet, ("127.0.0.1", port[0]))
            if machine.receive_protected(s.recv(R8_BINDING_BUDGET)) != b"x": raise ValueError("application response mismatch")
            captured = _measurement_end()
        if error: raise RuntimeError(error[0])
        return captured

    client.close, client.join = close, lambda: thread.join(TIMEOUT)
    return client

def r8_trial():
    client = _r8_server_ready()
    try: client()
    finally: client.close(); client.join()


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
    ready, release, stop, port, error, sockets = threading.Event(), threading.Event(), threading.Event(), [], [], []

    def serve():
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            _disable_tickets(context); _disable_server_tickets(context); context.load_cert_chain(CERT, KEY)
            with socket.socket() as listener:
                sockets.append(listener)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); listener.bind(("127.0.0.1", 0)); listener.listen(1); listener.settimeout(.1)
                port.append(listener.getsockname()[1]); ready.set()
                while not stop.is_set():
                    try: raw = listener.accept()[0]
                    except socket.timeout: continue
                    sockets.append(raw)
                    with context.wrap_socket(raw, server_side=True) as conn:
                        sockets.append(conn); conn.settimeout(TIMEOUT)
                        if conn.recv(1) != b"x": raise ValueError("application byte mismatch")
                        conn.sendall(b"x")
                        release.wait()
                        return
        except OSError:
            if not stop.is_set(): error.append("OSError")
        except Exception as exc:
            error.append(type(exc).__name__)

    thread = threading.Thread(target=serve)

    def close():
        stop.set(); release.set()
        for active in sockets:
            try: active.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            try: active.close()
            except OSError: pass
    started = False
    try:
        thread.start()
        started = True
        if not ready.wait(TIMEOUT): raise TimeoutError("TLS server readiness")
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CERT))
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        _disable_tickets(context)
    except BaseException:
        close()
        if started: thread.join(TIMEOUT)
        raise

    def client():
        try:
            with socket.create_connection(("127.0.0.1", port[0]), TIMEOUT) as raw:
                sockets.append(raw)
                with context.wrap_socket(raw, server_hostname="localhost") as conn:
                    sockets.append(conn)
                    actual = hashlib.sha256(x509.load_der_x509_certificate(conn.getpeercert(binary_form=True)).public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
                    if actual != expected_pin: raise ssl.SSLError("SPKI pin mismatch")
                    conn.settimeout(TIMEOUT); conn.sendall(b"x")
                    if conn.recv(1) != b"x": raise ValueError("application response mismatch")
                    captured = _measurement_end()
            if error: raise RuntimeError(error[0])
            return captured
        finally:
            release.set()

    client.close, client.join = close, lambda: thread.join(TIMEOUT)
    return client

def tls_trial():
    client = _tls_server_ready()
    try: client()
    finally: client.close(); client.join()


def _measurement_start():
    return net(), time.process_time_ns(), time.monotonic_ns()
def _measurement_end():
    return net(), time.process_time_ns(), time.monotonic_ns()

def _zero_network():
    return {key: 0 for key in net()}

def _measurement_result(status, category, start_net, cpu, started, snapshot=None):
    if start_net is None:
        return {"status": status, "error_category": "setup:" + category, "latency_ns": 0, "cpu_ns": 0, "network": _zero_network()}
    end_net, end_cpu, ended = snapshot or _measurement_end()
    return {"status": status, "error_category": category, "latency_ns": ended - started, "cpu_ns": end_cpu - cpu, "network": {k: end_net[k] - start_net[k] for k in start_net}}

def _attempt(client, start):
    status, category, snapshot = "success", None, None
    previous = signal.getsignal(signal.SIGALRM)
    try:
        def expired(_signum, _frame): raise TimeoutError("Q3 trial timeout")
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, TIMEOUT)
        snapshot = client()
    except TimeoutError as exc:
        status, category, snapshot = "timeout", type(exc).__name__, _measurement_end()
    except Exception as exc:
        status, category, snapshot = "failure", type(exc).__name__, _measurement_end()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        client.close()
        client.join()
    return _measurement_result(status, category, *start, snapshot)

def trial(mechanism):
    try:
        client = (_r8_server_ready if mechanism == MECHANISMS[0] else _tls_server_ready)()
    except Exception as exc:
        return _measurement_result("failure", type(exc).__name__, None, None, None)
    return _attempt(client, _measurement_start())

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
    try:
        client = (_r8_server_ready if args.mechanism == MECHANISMS[0] else _tls_server_ready)()
    except Exception as exc:
        print(json.dumps(_measurement_result("failure", type(exc).__name__, None, None, None), sort_keys=True))
        return 0
    start = _measurement_start()
    if args.marker_fd is not None:
        with socket.socket(fileno=args.marker_fd) as marker:
            marker.sendall(json.dumps({"network": start[0], "cpu_ns": start[1], "started_ns": start[2]}, sort_keys=True).encode())
    print(json.dumps(_attempt(client, start), sort_keys=True))
    return 0

def _reap_worker(process, deadline_ns):
    while time.monotonic_ns() < deadline_ns:
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if pid:
            return status, usage, False
        time.sleep(.001)
    os.kill(process.pid, signal.SIGKILL)
    _pid, status, usage = os.wait4(process.pid, 0)
    return status, usage, True

def invoke_worker(mechanism):
    parent, child = socket.socketpair()
    try:
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "worker", "--mechanism", mechanism, "--marker-fd", str(child.fileno())],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(child.fileno(),),
        )
    finally:
        child.close()
    try:
        readable, _, _ = select.select([parent], [], [], TIMEOUT)
        if not readable:
            os.kill(process.pid, signal.SIGKILL)
            os.wait4(process.pid, 0)
            return _measurement_result("failure", "worker_marker_timeout", None, None, None)
        try:
            marker = strict_json(parent.recv(4096).decode())
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            try: os.kill(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            os.wait4(process.pid, 0)
            return _measurement_result("failure", "worker_marker_invalid", None, None, None)
        if set(marker) != {"network", "cpu_ns", "started_ns"} or type(marker["cpu_ns"]) is not int or type(marker["started_ns"]) is not int or type(marker["network"]) is not dict:
            os.kill(process.pid, signal.SIGKILL)
            os.wait4(process.pid, 0)
            return _measurement_result("failure", "worker_marker_invalid", None, None, None)
        start_net, child_cpu, started = marker["network"], marker["cpu_ns"], marker["started_ns"]
        if set(start_net) != set(LO_COUNTERS):
            os.kill(process.pid, signal.SIGKILL)
            os.wait4(process.pid, 0)
            return _measurement_result("failure", "worker_marker_invalid", None, None, None)
        status, usage, killed = _reap_worker(process, started + int(TIMEOUT * 1_000_000_000))
        def fallback(status, category):
            end_net, _supervisor_cpu, ended = _measurement_end()
            child_end_cpu = int((usage.ru_utime + usage.ru_stime) * 1_000_000_000)
            observed = {"latency_ns": max(0, ended - started), "cpu_ns": max(0, child_end_cpu - child_cpu), "network": {k: end_net[k] - start_net[k] for k in start_net}}
            return {"status": status, "error_category": category, **observed}

        if killed:
            return fallback("timeout", "worker_timeout")
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status):
            return fallback("failure", "worker_exit")
        output = process.stdout.read()
        try:
            result = strict_json(output)
            numeric = [result["latency_ns"], result["cpu_ns"], *result["network"].values()]
        except (AttributeError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return fallback("failure", "worker_output")
        if set(result) != {"status", "error_category", "latency_ns", "cpu_ns", "network"} or result["status"] not in {"success", "failure", "timeout"} or (result["status"] == "success") != (result["error_category"] is None) or (result["status"] != "success" and type(result["error_category"]) is not str) or type(result["network"]) is not dict or set(result["network"]) != set(LO_COUNTERS) or any(type(value) is not int or value < 0 for value in numeric):
            return fallback("failure", "worker_output")
        return result
    finally:
        parent.close()


def percentile(values, q):
    if not values: return None
    return sorted(values)[min(len(values) - 1, int((len(values) - 1) * q))]

def censored_quantile(rows, q):
    """Kaplan-Meier quantile; non-success rows are right-censored observations."""
    if not rows:
        return None
    observations = {}
    for row in rows:
        elapsed = row["latency_ns"]
        events, censored = observations.get(elapsed, (0, 0))
        observations[elapsed] = (events + (row["status"] == "success"), censored + (row["status"] != "success"))
    at_risk, survival = len(rows), 1.0
    for elapsed in sorted(observations):
        events, censored = observations[elapsed]
        survival *= (at_risk - events) / at_risk
        if 1.0 - survival >= q:
            return elapsed
        at_risk -= events + censored
    return None

def censored_bootstrap(blocks, q):
    if not blocks:
        return None
    rng = random.Random(BOOTSTRAP_SEED + repr(q))
    samples = []
    for _ in range(10000):
        sample = [row for _ in blocks for row in rng.choice(blocks)]
        estimate = censored_quantile(sample, q)
        if estimate is None:
            return None
        samples.append(estimate)
    return [percentile(samples, .025), percentile(samples, .975)]

def summary(rows):
    output = {"contract_version": strict_json(PROTOCOL.read_text())["contract_version"], "series": {}}
    for series in ("cold-process-primary", "warm-process"):
        output["series"][series] = {}
        for mechanism in MECHANISMS:
            selected = [r for r in rows if r["series"] == series and r["mechanism"] == mechanism and not r["excluded"]]
            blocks = [[r for r in selected if r["block"] == b] for b in sorted({r["block"] for r in selected})]
            ci = {name: censored_bootstrap(blocks, q) for name, q in (("p50", .5), ("p90", .9))}
            metrics = {"failure_rate": (sum(r["status"] != "success" for r in selected) / len(selected)) if selected else None,
                "latency_ns": {"estimator": "kaplan-meier-right-censored", "p50": censored_quantile(selected, .5), "p90": censored_quantile(selected, .9), "confidence_intervals_95": ci},
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
        "preregistration_manifest_sha256": sources["bench/protocols/manifest.json"],
        "fixture_certificate_sha256": sources["bench/fixtures/q3-cert.pem"],
        "fixture_key_sha256": sources["bench/fixtures/q3-key.pem"],
        "reference_sha256": sources["reference/r8session.py"],
        "requirements_dev_sha256": sources["requirements-dev.txt"],
        "workflow_sha256": sources[".github/workflows/q3-full.yml"],
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
    failures = sum(row["status"] != "success" for row in rows)
    complete_evidence = not args.smoke and len(rows) == 2 * len(MECHANISMS) * (WARMUPS + MEASURED) and all(group["rows"] == WARMUPS + MEASURED for group in group_counts)
    return {
        "schema": "q3-run-manifest-v1",
        "status": SMOKE_STATUS if args.smoke else "completed-evidence",
        "runtime_outcome": "smoke-non-result" if args.smoke else ("success" if failures == 0 else "failures-retained"),
        "publication_eligible": bool(not args.smoke and complete_evidence),
        "source_identity": args.source_identity,
        "implementation_source_identity": source_identity(),
        "implementation_sources": source_hashes(),
        "host_epoch": args.host_epoch,
        "git_commit": args.git_commit,
        "isolated_netns_proof": True,
        "group_counts": group_counts,
        "row_count": len(rows),
        "failures": failures,
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
def require_clean_repository(error):
    if _git(["status", "--porcelain", "--untracked-files=all"]):
        raise ValueError(error)

def require_labels(args):
    require_frozen_protocol()
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
    require_clean_repository("full run requires a clean repository")

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
    if manifest_data["status"] not in {SMOKE_STATUS, "completed", "completed-evidence"}:
        raise ValueError("invalid run status")
    if manifest_data.get("isolated_netns_proof") is not True or saved.get("isolated_netns_proof") is not True:
        raise ValueError("missing isolated network namespace proof")
    if saved.get("source_identity") != manifest_data["source_identity"] or saved.get("loopback_interface") != "lo" or saved.get("loopback_mtu") != 65536:
        raise ValueError("environment consistency verification failed")
    if not SOURCE_LABEL.fullmatch(manifest_data["source_identity"]) or not SAFE_LABEL.fullmatch(manifest_data["host_epoch"]):
        raise ValueError("manifest label verification failed")
    if not smoke and (not FULL_EPOCH.fullmatch(manifest_data["host_epoch"]) or not COMMIT.fullmatch(manifest_data.get("git_commit", ""))):
        raise ValueError("full manifest label verification failed")
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
    if manifest_data["status"] == "completed-evidence":
        expected_outcome = "success" if manifest_data["failures"] == 0 else "failures-retained"
        if manifest_data.get("publication_eligible") is not True or manifest_data.get("runtime_outcome") != expected_outcome:
            raise ValueError("completed evidence status verification failed")
    if manifest_data["status"] == SMOKE_STATUS and (manifest_data.get("publication_eligible", False) or manifest_data.get("runtime_outcome") != SMOKE_STATUS):
        raise ValueError("smoke status verification failed")
    fields = {"schema", "source_identity", "series", "mechanism", "host_epoch", "block", "order", "trial", "excluded", "smoke_non_result", "status", "error_category", "latency_ns", "cpu_ns", "network"}
    for row, (series, block, position, mechanism, ordinal, excluded) in zip(rows, expected):
        if set(row) != fields or row["schema"] != "q3-raw-v1" or row["source_identity"] != manifest_data["source_identity"] or row["host_epoch"] != manifest_data["host_epoch"] or (row["series"], row["block"], row["order"], row["mechanism"], row["trial"], row["excluded"]) != (series, block, position, mechanism, ordinal, excluded) or row["smoke_non_result"] is not smoke or row["status"] not in {"success", "failure", "timeout"} or (row["status"] == "success") != (row["error_category"] is None):
            raise ValueError("raw row consistency verification failed")
        if type(row["network"]) is not dict:
            raise ValueError("raw network verification failed")
        numeric = [row["latency_ns"], row["cpu_ns"], *row["network"].values()]
        if any(type(value) is not int or value < 0 for value in numeric):
            raise ValueError("raw numeric verification failed")
        if row["status"] != "success":
            setup_failure = row["error_category"].startswith("setup:")
            if setup_failure and any(numeric):
                raise ValueError("setup failure measurement verification failed")
            if not setup_failure and row["latency_ns"] == 0:
                raise ValueError("post-start failure elapsed verification failed")
        require_loopback_delta(row["network"])

def regenerate(args):
    require_frozen_protocol()
    directory = Path(args.output)
    manifest_data = strict_json((directory / "run-manifest.json").read_text())
    if manifest_data.get("schema") != "q3-run-manifest-v1":
        raise ValueError("invalid run manifest")
    hashes = manifest_data.get("sha256")
    if set(hashes or ()) != {"raw.jsonl", "environment.json", "summary.json"}:
        raise ValueError("invalid manifest file hashes")
    for name, expected_hash in hashes.items():
        if expected_hash != digest(directory / name):
            raise ValueError("manifest hash verification failed: " + name)
    saved = strict_json((directory / "environment.json").read_text())
    current_sources = source_hashes()
    current_identity = source_identity()
    recorded_sources = manifest_data.get("implementation_sources")
    recorded_identity = manifest_data.get("implementation_source_identity")
    if type(recorded_sources) is not dict or any(type(path) is not str or type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value) for path, value in recorded_sources.items()):
        raise ValueError("recorded implementation sources verification failed")
    recorded_keys = set(recorded_sources)
    if recorded_keys != set(SOURCE_INPUTS):
        raise ValueError("recorded implementation source key-set verification failed")
    if saved.get("implementation_sources") != recorded_sources or saved.get("implementation_source_identity") != recorded_identity:
        raise ValueError("recorded implementation source binding verification failed")
    if implementation_source_identity(recorded_sources) != recorded_identity:
        raise ValueError("recorded implementation source identity verification failed")
    if recorded_sources != current_sources or recorded_identity != current_identity:
        raise ValueError("package is not bound to the current implementation")
    smoke = manifest_data.get("status") == SMOKE_STATUS
    if not smoke and (manifest_data.get("source_identity") != recorded_identity or saved.get("source_identity") != recorded_identity):
        raise ValueError("full package public source identity binding verification failed")
    if not smoke:
        component_fields = {
            "protocol_sha256": "bench/protocols/q3.json",
            "preregistration_manifest_sha256": "bench/protocols/manifest.json",
            "fixture_certificate_sha256": "bench/fixtures/q3-cert.pem",
            "fixture_key_sha256": "bench/fixtures/q3-key.pem",
            "reference_sha256": "reference/r8session.py",
            "requirements_dev_sha256": "requirements-dev.txt",
        }
        if "workflow_sha256" in saved or ".github/workflows/q3-full.yml" in recorded_sources:
            component_fields["workflow_sha256"] = ".github/workflows/q3-full.yml"
        for field, path in component_fields.items():
            if path not in recorded_sources or saved.get(field) != recorded_sources[path]:
                raise ValueError("recorded component hash verification failed: " + field)
        if manifest_data.get("toolchain_provenance", {}).get("requirements_dev_sha256") != recorded_sources["requirements-dev.txt"]:
            raise ValueError("requirements toolchain hash verification failed")
        if manifest_data.get("git_commit") != _git(["rev-parse", "HEAD"]):
            raise ValueError("full package git commit does not match current HEAD")
        require_clean_repository(
            "full package regeneration requires a clean repository")
        github_sha = os.environ.get("GITHUB_SHA")
        if github_sha is not None and manifest_data.get("git_commit") != github_sha:
            raise ValueError("full package git commit does not match GITHUB_SHA")
    rows = [strict_json(line) for line in (directory / "raw.jsonl").read_text().splitlines()]
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
    work = commands.add_parser("worker"); work.add_argument("--mechanism", choices=MECHANISMS, required=True); work.add_argument("--marker-fd", type=int)
    regen = commands.add_parser("regenerate"); regen.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "worker": return worker(args)
    if args.command == "regenerate": return regenerate(args)
    return run(args)
if __name__ == "__main__": main()
