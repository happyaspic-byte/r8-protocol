#!/usr/bin/env python3
"""Root-only, fail-not-skip AF_PACKET proof for r8-native."""
import argparse
import hashlib
import ipaddress
import json
import os
import selectors
import shutil
import signal
import socket
import subprocess
import struct
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
_WORKER_PROCESS = len(sys.argv) > 1 and sys.argv[1] == "worker"
if _WORKER_PROCESS:
    print("r8-native-worker stage=bootstrap", file=sys.stderr, flush=True)
import r8ref
if _WORKER_PROCESS:
    print("r8-native-worker stage=import-ref", file=sys.stderr, flush=True)
import r8session
if _WORKER_PROCESS:
    print("r8-native-worker stage=import-session", file=sys.stderr, flush=True)

ETHERTYPE = 0x88B5
PACKET_IGNORE_OUTGOING = 23
SOL_PACKET = 263
UID = GID = 65534
READY = "r8-native ready descriptors="


def sha(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()


def canonical_frame(domain, records):
    out = bytearray()
    domain = domain.encode()
    out.extend(len(domain).to_bytes(8, "big"))
    out.extend(domain)
    for path, ordinal, value in sorted(records, key=lambda item: (item[0], item[1])):
        path = path.encode()
        out.extend(len(path).to_bytes(8, "big"))
        out.extend(path)
        out.extend(ordinal.to_bytes(8, "big"))
        out.extend(len(value).to_bytes(8, "big"))
        out.extend(value)
    return bytes(out)


def aggregate_hash(domain, records):
    return sha(canonical_frame(domain, records))


def mac(n): return bytes((2, 0x52, 0x38, 0, n >> 8, n & 255))
def loc(n): return ipaddress.IPv6Address((0x20010db800000000 << 64) | n)
def eth(dst, src, packet): return dst + src + ETHERTYPE.to_bytes(2, "big") + packet


def parse_frame(value):
    if len(value) < 14 or value[12:14] != ETHERTYPE.to_bytes(2, "big"):
        raise ValueError("frame")
    return value[:6], value[6:12], r8ref.Header.unpack(value[14:])
def forwarded_packet(packet, hops):
    expected = bytearray(packet)
    expected[5] -= hops
    return bytes(expected)


def ctl(source, destination, hop=8):
    h = r8ref.Header(r8ref.NH_CTL, loc(source), loc(destination), hop=hop)
    return r8ref.build_ctl(h, r8ref.CTL_ECHO_REQUEST, 0, b"native")


def dgram(source, destination, data_len, hop=8):
    h = r8ref.Header(r8ref.NH_DGRAM, loc(source), loc(destination), hop=hop)
    return r8ref.build_dgram(h, 7, 9, b"d" * data_len)
def oversized_dgram(source, destination, hop=8):
    """Build an internally consistent 1,281-byte R8 DGRAM for ingress-budget proof."""
    header = r8ref.Header(r8ref.NH_DGRAM, loc(source), loc(destination), hop=hop)
    data = b"d" * 1225
    length = r8ref.DGRAM_HDR.size + len(data)
    zeroed = r8ref.DGRAM_HDR.pack(7, 9, length, 0) + data
    checksum = r8ref.checksum16(
        r8ref.pseudo_header(header, length, r8ref.NH_DGRAM), zeroed
    ) or 0xffff
    payload = r8ref.DGRAM_HDR.pack(7, 9, length, checksum) + data
    fixed = struct.pack(
        "!BBHBBBBQ",
        (r8ref.VERSION << 4) | header.profile,
        header.tc,
        len(payload),
        header.nh,
        header.hop,
        header.flags,
        header.pslot,
        header.scid,
    )
    packet = fixed + header.src.packed + header.dst.packed + payload
    if len(packet) != 1281:
        raise RuntimeError("oversized fixture")
    return packet


def ses_packet():
    v = json.loads((ROOT / "tests/vectors/session-v0.1.json").read_text())
    return bytes.fromhex(v["positive_cases"][4]["protected"]["packet_hex"]), bytes.fromhex(v["key_schedule"]["c2s_slot0_key_hex"])


def manifest(ifaces, routes, local_locs=()):
    return {"local_locs": [list(loc(x).packed) for x in local_locs], "interfaces": [
        {"descriptor_id": i, "interface_name": name, "allowed_source_macs": [list(mac(peer))],
         "local_delivery": False, "transit": True} for i, name, peer in ifaces], "routes": [
        {"destination_prefix": {"network": list(destination.packed), "prefix_length": 128},
         "egress_descriptor_id": egress, "next_hop_mac": list(next_hop)} for destination, egress, next_hop in routes]}


def _run(command, check=True):
    return subprocess.run(command, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
def ip(*args, ns=None, check=True):
    prefix = ["ip", "netns", "exec", ns, "ip"] if ns is not None else ["ip"]
    return _run(prefix + list(args), check)
ERROR_CATEGORIES = {
    "READY": "ready",
    "PRIVILEGE": "privilege",
    "FORWARD": "forward",
    "NEGATIVE": "negative",
    "BUDGET": "budget",
    "REVOCATION": "revocation",
    "SETUP": "setup",
    "TIMEOUT": "timeout",
    "FORWARD_WORKER_SOCKET": "forward-worker-socket",
    "FORWARD_WORKER_SEND": "forward-worker-send",
    "FORWARD_WORKER_REPLY": "forward-worker-reply",
    "FORWARD_WORKER_BOOTSTRAP": "forward-worker-bootstrap",
    "FORWARD_WORKER_IMPORT_REF": "forward-worker-import-ref",
    "FORWARD_WORKER_IMPORT_SESSION": "forward-worker-import-session",
    "FORWARD_WORKER_RECEIVE": "forward-worker-receive",
}
LAB_STAGES = frozenset(("setup", "launch", "proof-ctl", "proof-dgram", "proof-ses", "proof-negative", "revoke", "cleanup"))
def emit_stage(value):
    if value not in LAB_STAGES:
        raise RuntimeError("SETUP")
    print(f"r8-native-lab stage={value}", file=sys.stderr, flush=True)
WORKER_STAGES = frozenset(("bootstrap", "import-ref", "import-session", "socket", "send", "reply", "receive"))
def emit_worker_stage(value):
    if value not in WORKER_STAGES:
        raise RuntimeError("SETUP")
    print(f"r8-native-worker stage={value}", file=sys.stderr, flush=True)
def worker_error(stderr):
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", "replace")
    stage = None
    for line in (stderr or "").splitlines():
        value = line.removeprefix("r8-native-worker stage=")
        if value in WORKER_STAGES:
            stage = value
    key = f"FORWARD_WORKER_{stage.upper().replace('-', '_')}" if stage else "FORWARD"
    return key if key in ERROR_CATEGORIES else "FORWARD"
def worker_process_error(process):
    stage = getattr(process, "_r8_worker_stage", None)
    key = f"FORWARD_WORKER_{stage.upper().replace('-', '_')}" if stage else "FORWARD"
    return key if key in ERROR_CATEGORIES else "FORWARD"
def wait_worker_stage(process, expected, timeout=10):
    if expected not in WORKER_STAGES:
        return False
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    selector.register(process.stderr, selectors.EVENT_READ)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            events = selector.select(remaining if process.poll() is None else 0)
            if not events:
                return False
            line = process.stderr.readline()
            if not line:
                return False
            if isinstance(line, bytes):
                line = line.decode("utf-8", "replace")
            value = line.strip().removeprefix("r8-native-worker stage=")
            if value in WORKER_STAGES:
                process._r8_worker_stage = value
            if value == expected:
                return True
            if line.startswith("r8-native-worker stage=") and value not in WORKER_STAGES:
                return False
    finally:
        selector.close()
SETUP_STAGES = frozenset(("namespace-create", "ipv6-disable", "loopback-down", "veth-create", "veth-move", "interface-rename", "link-activate"))
STARTUP_STAGES = frozenset(("arguments", "manifest", "isolation", "descriptors", "watch", "privilege", "runtime"))
ERROR_CATEGORIES.update({f"STARTUP_{stage.upper()}": f"startup-{stage}" for stage in STARTUP_STAGES})
ISOLATION_STAGES = frozenset(("namespace", "network", "default-route-v4", "address", "interface", "internal"))
ERROR_CATEGORIES.update({f"STARTUP_ISOLATION_{stage.upper().replace('-', '_')}": f"startup-isolation-{stage}" for stage in ISOLATION_STAGES})


def error_category(error):
    if isinstance(error, RuntimeError):
        return ERROR_CATEGORIES.get(str(error), "setup")
    return "setup"
def setup_error_category(error, stage):
    category = error_category(error)
    return f"setup-{stage}" if category == "setup" and stage in SETUP_STAGES else category
def startup_error(stderr):
    stage = isolation = None
    for line in stderr.splitlines():
        if line.startswith("r8-native startup=") and line.removeprefix("r8-native startup=") in STARTUP_STAGES:
            stage = line.removeprefix("r8-native startup=")
        if line.startswith("r8-native isolation=") and line.removeprefix("r8-native isolation=") in ISOLATION_STAGES:
            isolation = line.removeprefix("r8-native isolation=")
    if isolation is not None:
        return f"STARTUP_ISOLATION_{isolation.upper().replace('-', '_')}"
    return f"STARTUP_{stage.upper()}" if stage is not None else "READY"


def descriptor_ids(hops):
    return list(range(2, 2 * hops + 2))


def source_records():
    paths = (
        "tests/native_netns.py", "tests/vectors/session-v0.1.json", "requirements-dev.txt",
        "spec/0004-wire-format-v0.2.md", "spec/0005-session-security-v0.1.md",
        "spec/0007-native-binding-v0.1.md", "spec/parameters-v0.1.md",
        "reference/r8ref.py", "reference/r8session.py",
        "rust/Cargo.toml", "rust/Cargo.lock",
        "rust/crates/r8d/Cargo.toml", "rust/crates/r8d/src/bin/r8-native.rs",
        "rust/crates/r8d/src/lib.rs", "rust/crates/r8d/src/native.rs",
        "rust/crates/r8d/src/linux.rs", "rust/crates/r8d/src/manifest.rs",
        "rust/crates/r8d/src/forward.rs",
        "rust/crates/r8-proto/Cargo.toml", "rust/crates/r8-proto/src/lib.rs",
        "rust/crates/r8-session/Cargo.toml", "rust/crates/r8-session/src/lib.rs",
        ".github/workflows/native-full.yml", ".github/workflows/ci.yml",
    )
    return [(path, ordinal, (ROOT / path).read_bytes()) for ordinal, path in enumerate(paths)]


def result_json(lab, binary, hops):
    binary_bytes = Path(binary).read_bytes() if Path(binary).is_file() else b""
    return {
        "ok": lab.error_category is None and not lab.counts["cleanup_failures"],
        "error_category": lab.error_category,
        "counts": lab.counts,
        "source_hash": aggregate_hash("r8-native-source-v1", source_records()),
        "binary_hash": sha(binary_bytes),
        "manifest_hash": aggregate_hash("r8-native-manifest-v1",
                                        [("manifest", ordinal, doc.encode())
                                         for ordinal, doc in enumerate(lab.docs)]),
        "filter_hash": aggregate_hash("r8-native-filter-v1",
                                      [("rust/crates/r8d/src/linux.rs", 0,
                                        (ROOT / "rust/crates/r8d/src/linux.rs").read_bytes())]),
        "interface_ordinals": descriptor_ids(hops),
    }


def emit_result(lab, binary, hops):
    result = result_json(lab, binary, hops)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["ok"] else 1


def socket_for(interface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE))
    s.setsockopt(SOL_PACKET, PACKET_IGNORE_OUTGOING, 1)
    s.bind((interface, ETHERTYPE)); s.setblocking(False)
    return s


def receive(s, timeout):
    sel = selectors.DefaultSelector(); sel.register(s, selectors.EVENT_READ)
    events = sel.select(timeout); sel.close()
    if not events: return None
    return s.recv(2048)


def status(pid):
    wanted = {"Uid", "Gid", "Groups", "CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd", "NoNewPrivs"}; out = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in wanted: out[key] = value.split()
    return out


class Lab:
    def __init__(self, hops, binary):
        self.hops, self.binary = hops, binary; self.token = os.urandom(5).hex()
        self.names = []; self.procs = []; self.workers = []; self.docs = []; self.temp = Path(tempfile.mkdtemp(prefix="r8-native-"))
        self.counts = {"frames_sent": 0, "frames_received": 0, "negative_timeouts": 0,
                       "local_budget_rejects": 0, "daemon_exits": 0, "cleanup_failures": 0}
        self.error_category = self.setup_stage = None

    def name(self, n): return f"r8n{self.token}{n}"
    def iface(self, n, side): return f"e{n - 1}" if side == "left" else f"e{n}"

    def setup(self):
        for n in range(self.hops + 2):
            self.setup_stage = "namespace-create"
            name = self.name(n); ip("netns", "add", name); self.names.append(name)
            self.setup_stage = "ipv6-disable"
            _run(["ip", "netns", "exec", name, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1"])
            _run(["ip", "netns", "exec", name, "sysctl", "-qw", "net.ipv6.conf.default.disable_ipv6=1"])
            self.setup_stage = "loopback-down"
            ip("link", "set", "lo", "down", ns=name)
        self.setup_stage = "veth-create"
        for n in range(self.hops + 1):
            a, b = f"x{n}a", f"x{n}b"; ip("link", "add", a, "type", "veth", "peer", "name", b)
            self.setup_stage = "veth-move"
            ip("link", "set", a, "netns", self.name(n)); ip("link", "set", b, "netns", self.name(n + 1))
            self.setup_stage = "interface-rename"
            ip("link", "set", a, "name", f"e{n}", ns=self.name(n)); ip("link", "set", b, "name", f"e{n}", ns=self.name(n + 1))
        self.setup_stage = "link-activate"
        for n, namespace in enumerate(self.names):
            for e in (["e0"] if n == 0 else [f"e{self.hops}"] if n == self.hops + 1 else [f"e{n - 1}", f"e{n}"]):
                ip("link", "set", e, "address", mac(n).hex(":"), ns=namespace); ip("link", "set", e, "up", ns=namespace)
        self.setup_stage = None
    def launch(self):
        for n in range(1, self.hops + 1):
            left, right = n * 2, n * 2 + 1
            destinations = [loc(0), loc(self.hops + 1)]
            packet, _ = ses_packet(); ses_dst = r8ref.Header.unpack(packet)[0].dst
            doc = manifest([(left, f"e{n - 1}", n - 1), (right, f"e{n}", n + 1)],
                [(destinations[0], left, mac(n - 1)), (destinations[1], right, mac(n + 1)),
                 (ses_dst, right, mac(n + 1))])
            self.docs.append(json.dumps(doc, sort_keys=True, separators=(",", ":")))
            path = self.temp / f"m{n}.json"; path.write_text(self.docs[-1])
            command = ["ip", "netns", "exec", self.name(n), self.binary, "--manifest", str(path),
                       "--interface", f"e{n - 1}", "--interface", f"e{n}", "--uid", str(UID), "--gid", str(GID)]
            p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True); self.procs.append(p)
            sel = selectors.DefaultSelector(); sel.register(p.stdout, selectors.EVENT_READ)
            ready = bool(sel.select(5)) and p.stdout.readline().startswith(READY)
            sel.close()
            if not ready:
                if p.poll() is None:
                    try: p.wait(timeout=.2)
                    except subprocess.TimeoutExpired: pass
                category = startup_error(p.stderr.read()) if p.poll() is not None else "READY"
                raise RuntimeError(category)
            snap = status(p.pid)
            zero = ["0000000000000000"]
            if snap.get("Uid") != [str(UID)] * 4 or snap.get("Gid") != [str(GID)] * 4 or snap.get("Groups") != [] or any(snap.get(key) != zero for key in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd")) or snap.get("NoNewPrivs") != ["1"]: raise RuntimeError("PRIVILEGE")
    def assert_live(self):
        if any(process.poll() is not None for process in self.procs):
            raise RuntimeError("NEGATIVE")

    def health_probe(self):
        watcher = subprocess.Popen(["ip", "netns", "exec", self.name(self.hops + 1), sys.executable, str(Path(__file__).resolve()), "worker", "watch", "--interface", f"e{self.hops}", "--kind", "ctl", "--hops", str(self.hops), "--reply"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self.workers.append(watcher)
        if not wait_worker_stage(watcher, "receive"):
            raise RuntimeError(worker_process_error(watcher))
        probe = _run(["ip", "netns", "exec", self.name(0), sys.executable, str(Path(__file__).resolve()), "worker", "send", "--interface", "e0", "--packet", ctl(0, self.hops + 1).hex(), "--reply", "--hops", str(self.hops)], check=False)
        if probe.returncode or watcher.wait(timeout=4):
            raise RuntimeError("NEGATIVE")
        self.assert_live()


    def proof(self):
        # Endpoint workers send and observe each packet over real Ethernet; no local parse is evidence.
        for kind, packet in (("ctl", ctl(0, self.hops + 1)), ("dgram", dgram(0, self.hops + 1, 1224)), ("ses", ses_packet()[0])):
            emit_stage(f"proof-{kind}")
            self.assert_live()
            watcher = subprocess.Popen(["ip", "netns", "exec", self.name(self.hops + 1), sys.executable, str(Path(__file__).resolve()), "worker", "watch", "--interface", f"e{self.hops}", "--kind", kind, "--hops", str(self.hops), "--reply" if kind == "ctl" else "--no-reply"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            self.workers.append(watcher)
            if not wait_worker_stage(watcher, "receive"):
                raise RuntimeError(worker_process_error(watcher))
            try:
                sender = _run(["ip", "netns", "exec", self.name(0), sys.executable, str(Path(__file__).resolve()), "worker", "send", "--interface", "e0", "--packet", packet.hex(), "--reply" if kind == "ctl" else "--no-reply", "--hops", str(self.hops)], check=False)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError(worker_error(error.stderr)) from error
            if sender.returncode:
                raise RuntimeError(worker_error(sender.stderr))
            if watcher.wait(timeout=4):
                raise RuntimeError("FORWARD")
            self.assert_live()
            self.counts["frames_sent"] += 1; self.counts["frames_received"] += 1
        # Every negative is sent and B's independent watcher must time out.
        negatives = [b"\0", eth(mac(1), b"\x02\0\0\0\0\xff", ctl(0, self.hops + 1)), ctl(0, self.hops + 1, 1), ctl(0, 0xffff), dgram(0, self.hops + 1, 10) + b"\0"]
        for packet in negatives:
            emit_stage("proof-negative")
            self.assert_live()
            watcher = subprocess.Popen(["ip", "netns", "exec", self.name(self.hops + 1), sys.executable, str(Path(__file__).resolve()), "worker", "absent", "--interface", f"e{self.hops}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            self.workers.append(watcher)
            if not wait_worker_stage(watcher, "receive"):
                raise RuntimeError(worker_process_error(watcher))
            raw = packet if len(packet) >= 14 and packet[12:14] == ETHERTYPE.to_bytes(2, "big") else eth(mac(1), mac(0), packet)
            if _run(["ip", "netns", "exec", self.name(0), sys.executable, str(Path(__file__).resolve()), "worker", "send", "--interface", "e0", "--frame", raw.hex()], check=False).returncode or watcher.wait(timeout=3):
                raise RuntimeError("NEGATIVE")
            self.assert_live()
            self.health_probe()
            self.counts["negative_timeouts"] += 1
        over_budget = oversized_dgram(0, self.hops + 1)
        watcher = subprocess.Popen(["ip", "netns", "exec", self.name(self.hops + 1), sys.executable, str(Path(__file__).resolve()), "worker", "absent", "--interface", f"e{self.hops}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self.workers.append(watcher)
        if not wait_worker_stage(watcher, "receive"):
            raise RuntimeError(worker_process_error(watcher))
        result = _run(["ip", "netns", "exec", self.name(0), sys.executable, str(Path(__file__).resolve()), "worker", "send", "--interface", "e0", "--frame", eth(mac(1), mac(0), over_budget).hex()], check=False)
        if result.returncode or watcher.wait(timeout=3):
            raise RuntimeError("BUDGET")
        self.assert_live()
        self.health_probe()
        self.counts["local_budget_rejects"] += 1

    def revoke(self):
        self.assert_live()
        for n, process in enumerate(self.procs, 1):
            if process.poll() is not None:
                raise RuntimeError("REVOCATION")
            ip("link", "set", f"e{n - 1}", "down", ns=self.name(n))
            if process.wait(timeout=5) == 0:
                raise RuntimeError("REVOCATION")
            if any(remaining.poll() is not None for remaining in self.procs[n:]):
                raise RuntimeError("REVOCATION")
            self.counts["daemon_exits"] += 1

    def cleanup(self):
        for process in self.procs + self.workers:
            if process.poll() is None:
                try: process.terminate()
                except ProcessLookupError: pass
        for process in self.procs + self.workers:
            try: process.wait(timeout=.5)
            except subprocess.TimeoutExpired:
                try: process.kill(); process.wait(timeout=.5)
                except (ProcessLookupError, subprocess.TimeoutExpired): self.counts["cleanup_failures"] += 1
        for namespace in reversed(self.names):
            first = ip("netns", "pids", namespace, check=False).stdout.split()
            for value in first:
                try: os.kill(int(value), signal.SIGTERM)
                except ProcessLookupError: pass
            time.sleep(.1)
            for value in ip("netns", "pids", namespace, check=False).stdout.split():
                try: os.kill(int(value), signal.SIGKILL)
                except ProcessLookupError: pass
            if ip("netns", "pids", namespace, check=False).stdout.split() or ip("netns", "del", namespace, check=False).returncode: self.counts["cleanup_failures"] += 1
        if any(n in ip("netns", "list", check=False).stdout for n in self.names): self.counts["cleanup_failures"] += 1
        try:
            shutil.rmtree(self.temp)
        except OSError:
            self.counts["cleanup_failures"] += 1
        if self.temp.exists():
            self.counts["cleanup_failures"] += 1


def worker(args):
    emit_worker_stage("socket")
    s = socket_for(args.interface)
    if args.mode == "send":
        emit_worker_stage("send")
        wire = bytes.fromhex(args.frame) if args.frame else eth(mac(1), mac(0), bytes.fromhex(args.packet))
        s.send(wire)
        if not args.reply: return 0
        emit_worker_stage("reply")
        data = receive(s, 2)
        if data is None:
            return 1
        request_header, request_payload = r8ref.Header.unpack(bytes.fromhex(args.packet))
        reply = r8ref.Header(r8ref.NH_CTL, request_header.dst, request_header.src, hop=8)
        expected = eth(mac(0), mac(1), forwarded_packet(r8ref.build_ctl(reply, r8ref.CTL_ECHO_REPLY, 0, r8ref.parse_ctl(request_header, request_payload)[2]), args.hops))
        return 0 if data == expected else 1
    emit_worker_stage("receive")
    data = receive(s, 1.5)
    if args.mode == "absent":
        return 0 if data is None else 1
    if data is None:
        return 1
    expected_packet = {
        "ctl": ctl(0, args.hops + 1),
        "dgram": dgram(0, args.hops + 1, 1224),
        "ses": ses_packet()[0],
    }[args.kind]
    if data != eth(mac(args.hops + 1), mac(args.hops), forwarded_packet(expected_packet, args.hops)):
        return 1
    _, _, (h, payload) = parse_frame(data)
    if args.kind == "ctl":
        if r8ref.parse_ctl(h, payload)[0] != r8ref.CTL_ECHO_REQUEST:
            return 1
        if args.reply:
            reply = r8ref.Header(r8ref.NH_CTL, h.dst, h.src, hop=8)
            s.send(eth(data[6:12], data[:6], r8ref.build_ctl(reply, r8ref.CTL_ECHO_REPLY, 0, r8ref.parse_ctl(h, payload)[2])))
    elif args.kind == "dgram":
        r8ref.parse_dgram(h, payload)
    else:
        key = ses_packet()[1]; prefix = payload[:4]; counter = int.from_bytes(payload[4:12], "big")
        canonical = bytearray(data[14:62]); canonical[5] = 0
        r8session.Session(key).decrypt(bytes(canonical), prefix, counter, payload[12:])
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="command")
    w = sub.add_parser("worker"); w.add_argument("mode", choices=("send", "watch", "absent")); w.add_argument("--interface", required=True); w.add_argument("--packet"); w.add_argument("--frame"); w.add_argument("--kind", choices=("ctl", "dgram", "ses")); w.add_argument("--hops", type=int, default=0); w.add_argument("--reply", action="store_true"); w.add_argument("--no-reply", action="store_false", dest="reply")
    p.add_argument("--binary", default=os.environ.get("R8_NATIVE_BINARY", str(ROOT / "rust/target/release/r8-native"))); p.add_argument("--hops", type=int, choices=(1, 2), default=2); p.add_argument("--smoke", action="store_true")
    a = p.parse_args(argv)
    if a.command == "worker": return worker(a)
    if os.geteuid() != 0:
        return 1
    lab = Lab(a.hops, a.binary)
    if not shutil.which("ip") or not os.path.isfile(a.binary) or not os.access(a.binary, os.X_OK):
        lab.error_category = "setup"
        try:
            lab.cleanup()
        except Exception:
            lab.counts["cleanup_failures"] += 1
        return emit_result(lab, a.binary, a.hops)
    previous_alarm = signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(RuntimeError("TIMEOUT")))
    signal.alarm(30)
    try:
        emit_stage("setup"); lab.setup()
        emit_stage("launch"); lab.launch()
        lab.proof()
        emit_stage("revoke"); lab.revoke()
    except Exception as error:
        lab.error_category = setup_error_category(error, lab.setup_stage)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_alarm)
        emit_stage("cleanup")
        try:
            lab.cleanup()
        except Exception:
            lab.counts["cleanup_failures"] += 1
    return emit_result(lab, a.binary, a.hops)

if __name__ == "__main__": raise SystemExit(main())
