#!/usr/bin/env python3
"""Q2 v5 root-only native two-path measurement; no simulation or fallback."""
import argparse
import hashlib
import ipaddress
import json
import math
import os
import multiprocessing
import platform
import re
import resource
import select
import selectors
import shutil
import signal
import socket
import struct
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "reference"))
from bench import q2
import r8mobility as mobility
import r8redundant as redundant
import r8session as session
from tests import native_netns as gate4_native
from tests import redundant_netns as gate5_native

ETHERTYPE = 0x88B5
SOL_PACKET = 263
PACKET_IGNORE_OUTGOING = 23
UID = GID = 65534
READY = "r8-native ready descriptors="
CLOCK = getattr(time, "CLOCK_MONOTONIC_RAW", None)
SAFE_EPOCH = re.compile(r"closed-lab-epoch-[0-9]{3,}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
SOURCE_FILES = q2.IMPLEMENTATION_FILES
MISSING_TIME = -(1 << 63)
INTERFACES = (
    (0, 0, "p0"), (1, 0, "p0"), (1, 1, "p1"), (3, 1, "p1"),
    (0, 2, "p2"), (2, 2, "p2"), (2, 3, "p3"), (3, 3, "p3"),
)
LINKS = ((0, 1), (1, 3), (0, 2), (2, 3))
METRIC_FIELDS = (
    "sent_packets", "delivered_packets", "lost_packets", "duplicates",
    "reorder_displacement_count", "max_consecutive_loss_burst", "degraded_interval_ns",
    "wire_bytes", "wire_packets", "cpu_user_ns", "cpu_system_ns",
    "queue_high_water_packets", "queue_overflow_packets",
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def digest_value(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_hashes():
    return {path: file_sha(ROOT / path) for path in SOURCE_FILES}


def source_identity():
    return "sha256:" + digest_value(source_hashes())


def raw_ns():
    return time.clock_gettime_ns(CLOCK)


def fail(category):
    raise RuntimeError(category)


def command(args, *, namespace=None, check=True, timeout=10):
    argv = tuple(str(x) for x in args)
    if namespace is not None:
        argv = ("ip", "netns", "exec", namespace, *argv)
    try:
        result = subprocess.run(argv, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        fail("native-command")
    if check and result.returncode:
        fail("native-command")
    return result


def capabilities():
    try:
        line = next(item for item in Path("/proc/self/status").read_text().splitlines()
                    if item.startswith("CapEff:"))
        value = int(line.split()[1], 16)
        return os.geteuid() == 0 and bool(value & (1 << 12)) and bool(value & (1 << 13))
    except (OSError, StopIteration, ValueError):
        return False


def clean_head(expected):
    if not isinstance(expected, str) or not COMMIT.fullmatch(expected):
        fail("source-identity")
    head = command(("git", "rev-parse", "HEAD")).stdout.strip()
    status = command(("git", "status", "--porcelain", "--untracked-files=all")).stdout
    if head != expected or os.environ.get("GITHUB_SHA") != expected or status or os.environ.get("Q2_CLEAN_TREE") != "true":
        fail("source-identity")
    return head


def _expected_filter_hash():
    path = "rust/crates/r8d/src/linux.rs"
    return gate4_native.aggregate_hash(
        "r8-native-filter-v1", [(path, 0, (ROOT / path).read_bytes())])


def _expected_gate4_manifest_hash(hops):
    packet, _ = gate4_native.ses_packet()
    session_destination = gate4_native.r8ref.Header.unpack(packet)[0].dst
    destinations = (gate4_native.loc(0), gate4_native.loc(hops + 1))
    documents = []
    for hop in range(1, hops + 1):
        left, right = hop * 2, hop * 2 + 1
        document = gate4_native.manifest(
            [(left, f"e{hop - 1}", hop - 1), (right, f"e{hop}", hop + 1)],
            [(destinations[0], left, gate4_native.mac(hop - 1)),
             (destinations[1], right, gate4_native.mac(hop + 1)),
             (session_destination, right, gate4_native.mac(hop + 1))],
        )
        documents.append(canonical(document).encode())
    return gate4_native.aggregate_hash(
        "r8-native-manifest-v1",
        [("manifest", ordinal, document) for ordinal, document in enumerate(documents)])


def _expected_gate5_manifest_hash():
    locations = (ipaddress.IPv6Address("11:2233:4455:6677:8899:aabb:ccdd:eeff"),
                 ipaddress.IPv6Address("ffee:ddcc:bbaa:9988:7766:5544:3322:1100"))
    documents = []
    for hop, descriptors, links, peers in ((1, (2, 3), (0, 1), (0, 3)),
                                           (2, (4, 5), (2, 3), (0, 3))):
        interfaces = list(zip(
            descriptors, [f"p{link}" for link in links],
            [link * 4 + peer for link, peer in zip(links, peers)]))
        routes = [(location, descriptor, gate5_native.mac(link * 4 + peer))
                  for location, descriptor, link, peer
                  in zip(locations, descriptors, links, peers)]
        if hop == 2:
            # The deployed hop-2 manifest also routes the session destination
            # 8::3 back over path one (tests/redundant_netns.py launch());
            # mirror it exactly or valid gate evidence is rejected.
            routes.append((ipaddress.IPv6Address("8::3"),
                           descriptors[0],
                           gate5_native.mac(links[0] * 4 + peers[0])))
        documents.append(canonical(gate5_native.manifest(interfaces, routes)).encode())
    return gate5_native.aggregate_hash(
        "r8-redundant-manifest-v1",
        [("manifest", ordinal, document) for ordinal, document in enumerate(documents)])


def gate(path, binary_hash, kind, endpoint_hash=None):
    try:
        raw = Path(path).read_text()
        value = q2._strict_loads(raw)
    except (OSError, ValueError):
        fail("gate-evidence")
    gate4_counts = {"frames_sent", "frames_received", "negative_timeouts",
                    "local_budget_rejects", "daemon_exits", "cleanup_failures"}
    gate5_counts = {"frames_sent", "frames_received", "application_deliveries", "suppressions",
                    "rust_endpoint_authentications", "cached_retries", "degraded_events",
                    "path_removals", "negative_drops", "budget_rejects", "daemon_exits",
                    "cleanup_failures"}
    gate4_fields = {"ok", "error_category", "counts", "source_hash", "binary_hash",
                    "manifest_hash", "filter_hash", "interface_ordinals"}
    gate5_fields = gate4_fields | {"endpoint_binary_hash", "privilege_dropped",
                                  "revocation_verified", "cleanup_verified"}
    expected_fields = gate5_fields if kind == "gate5" else gate4_fields
    expected_counts = gate5_counts if kind == "gate5" else gate4_counts
    counts = value.get("counts")
    hashes = ("source_hash", "binary_hash", "manifest_hash", "filter_hash")
    if (raw != canonical(value) + "\n" or set(value) != expected_fields
            or value.get("ok") is not True or value.get("error_category") is not None
            or value.get("binary_hash") != binary_hash
            or not isinstance(counts, dict) or set(counts) != expected_counts
            or any(type(item) is not int or item < 0 for item in counts.values())
            or any(not isinstance(value.get(name), str) or len(value[name]) != 64 for name in hashes)):
        fail("gate-evidence")
    if kind == "gate5":
        expected_source = gate5_native.aggregate_hash("r8-redundant-source-v1", gate5_native.source_records())
        expected_manifest = _expected_gate5_manifest_hash()
        successful_counts = {"frames_sent": 27, "frames_received": 27,
                             "application_deliveries": 6, "suppressions": 5,
                             "rust_endpoint_authentications": 1, "cached_retries": 1,
                             "degraded_events": 2, "path_removals": 2,
                             "negative_drops": 4, "budget_rejects": 1,
                             "daemon_exits": 2, "cleanup_failures": 0}
        if (value.get("source_hash") != expected_source
                or not isinstance(value.get("endpoint_binary_hash"), str)
                or len(value["endpoint_binary_hash"]) != 64
                or value.get("endpoint_binary_hash") != endpoint_hash
                or value.get("interface_ordinals") != [2, 3, 4, 5]
                or counts != successful_counts
                or value.get("manifest_hash") != expected_manifest
                or value.get("filter_hash") != _expected_filter_hash()
                or value.get("privilege_dropped") is not True
                or value.get("revocation_verified") is not True
                or value.get("cleanup_verified") is not True):
            fail("gate-evidence")
    else:
        expected_source = gate4_native.aggregate_hash("r8-native-source-v1", gate4_native.source_records())
        expected_hops = 1 if kind == "gate4-one" else 2
        expected_manifest = _expected_gate4_manifest_hash(expected_hops)
        if (value.get("source_hash") != expected_source
                or value.get("interface_ordinals") != list(range(2, 2 * expected_hops + 2))
                or value.get("manifest_hash") != expected_manifest
                or value.get("filter_hash") != _expected_filter_hash()
                or counts.get("daemon_exits") != expected_hops
                or counts.get("cleanup_failures") != 0):
            fail("gate-evidence")
    return file_sha(path)


def preflight(binary, endpoint_binary, gate4_one=None, gate4_two=None, gate5=None, *, smoke=False, commit=None):
    errors = q2.verify_contract()
    if errors:
        fail("contract-drift")
    if CLOCK is None:
        fail("clock")
    if not capabilities():
        fail("privilege")
    for name in ("ip", "tc", "ethtool", "sysctl"):
        if shutil.which(name) is None:
            fail("environment")
    for value in (binary, endpoint_binary):
        if not value or not Path(value).is_file() or not os.access(value, os.X_OK):
            fail("binary")
    binary_hash, endpoint_hash = file_sha(binary), file_sha(endpoint_binary)
    gates = {}
    if not smoke:
        clean_head(commit)
        for kind, value in (("gate4-one", gate4_one), ("gate4-two", gate4_two), ("gate5", gate5)):
            if not value:
                fail("gate-evidence")
            gates[kind] = gate(value, binary_hash, kind, endpoint_hash)
    return {"binary_hash": binary_hash, "endpoint_binary_hash": endpoint_hash, "gates": gates}


def _mac(seed, ordinal):
    return bytes.fromhex(q2.mac_address(seed, q2.MAC_TOKENS[ordinal]).replace(":", ""))


def _loc(seed, token):
    return ipaddress.IPv6Address(int(q2.locator_id(seed, token), 16))


def _binding(identifier, peer_mac):
    return session.NativeBinding(identifier, peer_mac)


def _material(seed, trial_id, label, length=32):
    material = hashlib.sha256(b"r8-q2-v5-runtime" + seed.to_bytes(4, "big") + bytes.fromhex(trial_id) + label.encode()).digest()
    return material[:length]
def _secret(length=32):
    value = secrets.token_bytes(length)
    if not isinstance(value, bytes) or len(value) != length:
        fail("rng")
    return value


def _nonzero_secret(length):
    for _ in range(4):
        value = _secret(length)
        if any(value):
            return value
    fail("rng")


def _delivery_seed():
    return secrets.randbelow((1 << 64) - 513) + 1




def _control_specs(seed):
    return {
        "update": ("source-A", "destination-A", 0, 3, 1, 2, 4),
        "probe": ("source-B", "destination-B", 4, 7, 5, 6, 8),
        "challenge": ("destination-B", "source-B", 7, 4, 6, 5, 5),
        "response": ("source-B", "destination-B", 4, 7, 5, 6, 8),
        "result": ("destination-B", "source-B", 7, 4, 6, 5, 5),
    }


class _SocketControlTransport:
    def __init__(self, sockets, seed, deadline):
        self.sockets, self.seed, self.deadline = sockets, seed, deadline

    def transfer(self, name, packet):
        sender, receiver, sender_ordinal, receiver_ordinal, next_hop, peer, descriptor = _control_specs(self.seed)[name]
        frame = _frame(_mac(self.seed, sender_ordinal), _mac(self.seed, next_hop), packet)
        while True:
            if raw_ns() >= self.deadline:
                fail("admission-timeout")
            try:
                sent = self.sockets[sender].send(frame)
                if sent != len(frame):
                    fail("binding-mismatch")
                break
            except BlockingIOError:
                select.select([], [self.sockets[sender]], [], max(0, min(.02, (self.deadline - raw_ns()) / 1_000_000_000)))
        selector = selectors.DefaultSelector()
        try:
            selector.register(self.sockets[receiver], selectors.EVENT_READ)
            while raw_ns() < self.deadline:
                for selected, _ in selector.select(max(0, min(.02, (self.deadline - raw_ns()) / 1_000_000_000))):
                    received = selected.fileobj.recv(2048)
                    if (len(received) != len(packet) + 14
                            or received[:6] != _mac(self.seed, receiver_ordinal)
                            or received[6:12] != _mac(self.seed, peer)
                            or received[12:14] != ETHERTYPE.to_bytes(2, "big")):
                        fail("binding-mismatch")
                    return received[14:], _binding(descriptor, received[6:12])
            fail("admission-timeout")
        finally:
            selector.close()


def _states(plan, control_transport=None):
    seed, trial_id, mechanism = plan["seed"], plan["trial_id"], plan["mechanism"]
    if mechanism == "REDUNDANT" and control_transport is None:
        fail("admission-transport")
    source0, destination0 = _loc(seed, "source-slot-0"), _loc(seed, "destination-slot-0")
    source1, destination1 = _loc(seed, "source-slot-1"), _loc(seed, "destination-slot-1")
    client_identity = session.Identity.from_seed(_material(seed, trial_id, "client-ed25519"))
    server_identity = session.Identity.from_seed(_material(seed, trial_id, "server-ed25519"))
    service = int.from_bytes(_material(seed, trial_id, "service", 4), "big") or 1
    scid = int.from_bytes(_nonzero_secret(8), "big")
    now = [100]
    client = session.ClientMachine(client_identity, session.PeerPin(2, server_identity.eid, server_identity.public),
                                   service, 3, source0, destination0, lambda: now[0])
    server = session.ServerMachine(session.ServerConfig(
        server_identity, session.PeerPin(1, client_identity.eid, client_identity.public), service,
        int.from_bytes(_material(seed, trial_id, "context", 4), "big") or 1, 3,
        destination0, source0, 1280, 4, 4), _secret(16),
        _secret(), None, 0, lambda: now[0],
        session.PrevalidationLimiter(lambda: now[0], _secret()))
    path_a_source = _binding(1, _mac(seed, 1))
    path_a_destination = _binding(4, _mac(seed, 2))
    path_b_source = _binding(5, _mac(seed, 5))
    path_b_destination = _binding(8, _mac(seed, 6))
    observed = path_a_destination if mechanism != "single-B" else path_b_destination
    opening = client.start(scid)
    auth = client.receive_verify(server.receive_open_packet(opening, observed, 1))
    ack = server.receive_open_auth(auth, observed, 1)
    server.receive_protected(client.receive_ack(ack))
    source_binding = path_b_source if mechanism == "single-B" else path_a_source
    destination_binding = path_b_destination if mechanism == "single-B" else path_a_destination
    source = redundant.RedundantSession(client.take_profile3(), source_binding, 1280,
                                        _delivery_seed(), lambda: now[0])
    destination = redundant.RedundantSession(server.take_profile3(scid), destination_binding, 1280,
                                             _delivery_seed(), lambda: now[0])
    mapping = {0: (1 if mechanism == "single-B" else 0)}
    bindings = {0: destination_binding}
    if mechanism == "REDUNDANT":
        mover = mobility.MobilityManager(client_identity, session.PeerPin(2, server_identity.eid, server_identity.public),
                                         1, 3, scid, 9, str(source0), str(destination1), path_a_source,
                                         _nonzero_secret(32), lambda: now[0],
                                         session_commit=source.commit_receive,
                                         profile3_admission_owner=source.issue_profile3_admission_owner(9))
        receiver = mobility.MobilityManager(server_identity, session.PeerPin(1, client_identity.eid, client_identity.public),
                                            2, 3, scid, 9, str(destination1), str(source0), path_a_destination,
                                            _nonzero_secret(32), lambda: now[0],
                                            session_commit=destination.commit_receive,
                                            profile3_admission_owner=destination.issue_profile3_admission_owner(9))
        def protected_control(sender, receiver_state, manager, control, name):
            outbound = sender.send(control)
            packet = outbound.packets[0]
            if packet is None:
                fail("profile3-control")
            control_packet, binding = control_transport.transfer(name, packet)
            sender.confirm(0, packet)
            preview = receiver_state.preview_mobility(manager, 0, binding, control_packet)
            return receiver_state.commit_mobility(preview)
        candidate_id = _nonzero_secret(16)
        update = mover.propose_local(str(source1), 1, candidate_id, slot=1, carrier=path_b_source)
        protected_control(source, destination, receiver, update, "update")
        probe = mover.make_probe(candidate_id, path_b_source, _secret(16))
        challenge = protected_control(source, destination, receiver, probe, "probe")
        response = protected_control(destination, source, mover, challenge, "challenge")
        protected_control(source, destination, receiver, response, "response")
        result = receiver.take_results()[0]
        protected_control(destination, source, mover, result, "result")
        source.activate_slot1(mover.take_profile3_admissions()[0], path_b_source, 1280)
        destination.activate_slot1(receiver.take_profile3_admissions()[0], path_b_destination, 1280)
        mapping[1], bindings[1] = 1, path_b_destination
    return source, destination, mapping, bindings


def _payload(seed, index):
    prefix = struct.pack("!I", index)
    body = hashlib.sha512(b"r8-q2-v5-payload" + seed.to_bytes(4, "big") + index.to_bytes(4, "big")).digest()
    return prefix + body[:60]


def _frame(local_mac, peer_mac, packet):
    return peer_mac + local_mac + ETHERTYPE.to_bytes(2, "big") + packet


def _socket_in_namespace(namespace, interface):
    current = os.open("/proc/self/ns/net", os.O_RDONLY)
    target = os.open(f"/var/run/netns/{namespace}", os.O_RDONLY)
    try:
        os.setns(target, 0)
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE))
        sock.setsockopt(SOL_PACKET, PACKET_IGNORE_OUTGOING, 1)
        sock.bind((interface, ETHERTYPE))
        sock.setblocking(False)
        return sock
    finally:
        os.setns(current, 0)
        os.close(target)
        os.close(current)


def _status(pid):
    wanted = {"Uid", "Gid", "Groups", "CapEff", "NoNewPrivs"}
    result = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in wanted:
            result[key] = value.split()
    return result


class Lab:
    def __init__(self, seed, binary):
        self.seed, self.binary = seed, str(Path(binary).resolve())
        self.token = os.urandom(5).hex()
        self.names = [f"r8q2{self.token}{index}" for index in range(4)]
        self.temp = Path(tempfile.mkdtemp(prefix="r8-q2-native-"))
        self.processes, self.documents, self.sockets = [], [], {}
        self.privilege_dropped = False

    def ns(self, node):
        return self.names[node]

    @staticmethod
    def iface(link):
        return f"p{link}"

    def setup(self):
        for namespace in self.names:
            command(("ip", "netns", "add", namespace))
            command(("sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1"), namespace=namespace)
            command(("sysctl", "-qw", "net.ipv6.conf.default.disable_ipv6=1"), namespace=namespace)
            command(("ip", "link", "set", "lo", "down"), namespace=namespace)
        for link, (left, right) in enumerate(LINKS):
            a, b = f"q{link}a{self.token}", f"q{link}b{self.token}"
            command(("ip", "link", "add", a, "type", "veth", "peer", "name", b))
            command(("ip", "link", "set", a, "netns", self.ns(left)))
            command(("ip", "link", "set", b, "netns", self.ns(right)))
            command(("ip", "link", "set", a, "name", self.iface(link)), namespace=self.ns(left))
            command(("ip", "link", "set", b, "name", self.iface(link)), namespace=self.ns(right))
        for ordinal, (node, link, interface) in enumerate(INTERFACES):
            mac = _mac(self.seed, ordinal).hex(":")
            command(("ip", "link", "set", interface, "address", mac), namespace=self.ns(node))
            command(("ip", "link", "set", interface, "mtu", "1500"), namespace=self.ns(node))
            command(("ethtool", "-K", interface, "gro", "off", "gso", "off", "tso", "off"), namespace=self.ns(node))
            features = command(("ethtool", "-k", interface), namespace=self.ns(node)).stdout
            required_off = ("generic-receive-offload: off", "generic-segmentation-offload: off",
                            "tcp-segmentation-offload: off")
            if not all(feature in features for feature in required_off):
                fail("native-command")
            command(("ip", "link", "set", interface, "up"), namespace=self.ns(node))
            observed = json.loads(command(("ip", "-j", "address", "show", "dev", interface),
                                          namespace=self.ns(node)).stdout)
            if (len(observed) != 1 or observed[0].get("mtu") != 1500
                    or observed[0].get("address", "").lower() != mac
                    or observed[0].get("addr_info")):
                fail("native-command")
        for node in range(4):
            links = json.loads(command(("ip", "-j", "link", "show"), namespace=self.ns(node)).stdout)
            routes = json.loads(command(("ip", "-j", "route", "show", "table", "all"),
                                       namespace=self.ns(node)).stdout)
            if len([item for item in links if item.get("ifname") != "lo"]) != 2 or routes:
                fail("native-command")
        self.launch()
        self.sockets = {
            "source-A": _socket_in_namespace(self.ns(0), "p0"),
            "source-B": _socket_in_namespace(self.ns(0), "p2"),
            "destination-A": _socket_in_namespace(self.ns(3), "p1"),
            "destination-B": _socket_in_namespace(self.ns(3), "p3"),
        }

    def _manifest(self, path):
        source0, destination0 = _loc(self.seed, "source-slot-0"), _loc(self.seed, "destination-slot-0")
        source1, destination1 = _loc(self.seed, "source-slot-1"), _loc(self.seed, "destination-slot-1")
        if path == "A":
            interfaces = ((2, "p0", 0), (3, "p1", 3))
            routes = ((source0, 2, 0), (destination0, 3, 3))
        else:
            interfaces = ((6, "p2", 4), (7, "p3", 7))
            routes = ((source0, 6, 4), (source1, 6, 4), (destination0, 7, 7), (destination1, 7, 7))
        return {
            "local_locs": [],
            "interfaces": [{"descriptor_id": descriptor, "interface_name": interface,
                             "allowed_source_macs": [list(_mac(self.seed, peer))],
                             "local_delivery": False, "transit": True}
                            for descriptor, interface, peer in interfaces],
            "routes": [{"destination_prefix": {"network": list(loc.packed), "prefix_length": 128},
                        "egress_descriptor_id": descriptor, "next_hop_mac": list(_mac(self.seed, peer))}
                       for loc, descriptor, peer in routes],
        }

    def launch(self):
        for node, path, interfaces in ((1, "A", ("p0", "p1")), (2, "B", ("p2", "p3"))):
            document = self._manifest(path)
            text = canonical(document)
            self.documents.append(text)
            manifest = self.temp / f"manifest-{path}.json"
            manifest.write_text(text)
            process = subprocess.Popen(("ip", "netns", "exec", self.ns(node), self.binary,
                                        "--manifest", str(manifest), "--interface", interfaces[0],
                                        "--interface", interfaces[1], "--uid", str(UID), "--gid", str(GID)),
                                       cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.processes.append(process)
            ready = selectors.DefaultSelector()
            ready.register(process.stdout, selectors.EVENT_READ)
            if not ready.select(5) or not process.stdout.readline().startswith(READY):
                ready.close()
                fail("native-ready")
            ready.close()
            status = _status(process.pid)
            if (status.get("Uid", ["0"])[0] != str(UID) or status.get("Gid", ["0"])[0] != str(GID)
                    or status.get("Groups") != [] or status.get("CapEff") != ["0000000000000000"]
                    or status.get("NoNewPrivs") != ["1"]):
                fail("native-privilege")
        self.privilege_dropped = True

    def drain(self, deadline=None):
        for sock in self.sockets.values():
            while True:
                if deadline is not None and raw_ns() >= deadline:
                    fail("supervisor-timeout")
                try:
                    sock.recv(2048)
                except BlockingIOError:
                    break

    def counters(self, deadline=None):
        values = {"bytes": 0, "packets": 0}
        for _, (node, _, interface) in enumerate(INTERFACES):
            for key, filename in (("bytes", "tx_bytes"), ("packets", "tx_packets")):
                result = command(("cat", f"/sys/class/net/{interface}/statistics/{filename}"),
                                 namespace=self.ns(node), timeout=self._deadline_timeout(deadline))
                values[key] += int(result.stdout.strip())
        return values
    def state_digests(self, deadline=None):
        result = []
        for ordinal, (node, _, interface) in enumerate(INTERFACES):
            observed = json.loads(command(("ip", "-j", "address", "show", "dev", interface),
                                          namespace=self.ns(node),
                                          timeout=self._deadline_timeout(deadline)).stdout)
            qdiscs = json.loads(command(("tc", "-j", "qdisc", "show", "dev", interface),
                                        namespace=self.ns(node),
                                        timeout=self._deadline_timeout(deadline)).stdout)
            if len(observed) != 1:
                fail("native-command")
            link = observed[0]
            try:
                address_digest = hashlib.sha256(bytes.fromhex(link["address"].replace(":", ""))).hexdigest()
            except (KeyError, ValueError):
                fail("native-command")
            state = {"ordinal": ordinal, "up": "UP" in link.get("flags", []),
                     "mtu": link.get("mtu"), "address_digest": address_digest,
                     "address_count": len(link.get("addr_info", [])),
                     "qdisc_kinds": sorted(str(item.get("kind", "unknown")) for item in qdiscs)}
            result.append({"ordinal": ordinal, "digest": digest_value(state)})
        return result

    @staticmethod
    def _deadline_timeout(deadline):
        if deadline is None:
            return 10
        remaining = (deadline - raw_ns()) / 1_000_000_000
        if remaining <= 0:
            fail("supervisor-timeout")
        return max(.05, min(10, remaining))

    def clean_qdisc(self, deadline=None):
        ok = True
        for node, interface in ((0, "p0"), (3, "p1"), (0, "p2"), (3, "p3")):
            try:
                command(("tc", "qdisc", "del", "dev", interface, "root"),
                        namespace=self.ns(node), check=False,
                        timeout=self._deadline_timeout(deadline))
                shown = command(("tc", "-j", "qdisc", "show", "dev", interface),
                                namespace=self.ns(node), check=False,
                                timeout=self._deadline_timeout(deadline))
                values = json.loads(shown.stdout or "[]")
                ok &= shown.returncode == 0 and all(item.get("kind") != "netem" for item in values)
            except (RuntimeError, ValueError):
                ok = False
                break
        return ok

    def qdisc(self, condition, origin, deadline):
        if condition == "no-flap":
            return [], True
        entries = ((0, 0, "p0"), (3, 3, "p1")) if condition == "flap-A" else ((4, 0, "p2"), (7, 3, "p3"))
        observations = [{"ordinal": ordinal, "start_actual_relative_ns": None, "end_actual_relative_ns": None}
                        for ordinal, _, _ in entries]
        while True:
            remaining = (origin - raw_ns()) / 1_000_000_000
            if remaining <= 0:
                break
            if raw_ns() >= deadline:
                return observations, False
            time.sleep(min(remaining, .001))
        try:
            for item, (_, node, interface) in zip(observations, entries):
                command(("tc", "qdisc", "replace", "dev", interface, "root", "netem", "loss", "100%"),
                        namespace=self.ns(node), timeout=self._deadline_timeout(deadline))
                shown = command(("tc", "qdisc", "show", "dev", interface),
                                namespace=self.ns(node), timeout=self._deadline_timeout(deadline))
                if not re.search(r"\bnetem\b.*\bloss 100(?:\.0+)?%", shown.stdout):
                    fail("fault-not-applied")
                item["start_actual_relative_ns"] = raw_ns() - origin
            target = origin + 1_000_000_000
            while True:
                remaining = (target - raw_ns()) / 1_000_000_000
                if remaining <= 0:
                    break
                if raw_ns() >= deadline:
                    return observations, False
                time.sleep(min(remaining, .001))
            for item, (_, node, interface) in zip(observations, entries):
                command(("tc", "qdisc", "del", "dev", interface, "root"),
                        namespace=self.ns(node), timeout=self._deadline_timeout(deadline))
                shown = command(("tc", "qdisc", "show", "dev", interface),
                                namespace=self.ns(node), timeout=self._deadline_timeout(deadline))
                if re.search(r"\bnetem\b", shown.stdout):
                    fail("fault-not-applied")
                item["end_actual_relative_ns"] = raw_ns() - origin
        except Exception:
            return observations, False
        starts = [item["start_actual_relative_ns"] for item in observations]
        ends = [item["end_actual_relative_ns"] for item in observations]
        valid = (all(value is not None for value in starts + ends)
                 and all(abs(value) <= 100_000_000 for value in starts)
                 and all(abs(value - 1_000_000_000) <= 100_000_000 for value in ends)
                 and max(starts) - min(starts) <= 100_000_000
                 and max(ends) - min(ends) <= 100_000_000)
        return observations, valid

    def topology(self):
        route_digests = [{"path": path, "digest": digest_value({"seed": self.seed, "path": path, "routes": self._manifest(path)["routes"]})}
                         for path in ("A", "B")]
        path_digests = [{"path": path, "digest": digest_value({"policy": "static-ip-free", "path": path})}
                        for path in ("A", "B")]
        ordinal = lambda domain: [{"ordinal": index, "digest": digest_value({"domain": domain, "seed": self.seed, "ordinal": index})}
                                  for index in range(8)]
        value = {
            "seed": self.seed, "interface_count": 8, "veth_pair_count": 4, "path_count": 2,
            "manifest_digest": digest_value(self.documents), "route_digests": route_digests,
            "source_policy_digests": path_digests,
            "hop_digests": [{"path": path, "digest": digest_value({"path": path, "hop_decrement": 1})}
                            for path in ("A", "B")],
            "interface_digests": ordinal("interface-mtu1500-offloads-disabled"),
            "locator_digests": [{"role": token, "digest": hashlib.sha256(_loc(self.seed, token).packed).hexdigest()}
                                for token in q2.LOCATOR_TOKENS],
            "mac_digests": [{"ordinal": index, "digest": hashlib.sha256(_mac(self.seed, index)).hexdigest()}
                            for index in range(8)],
            "raw_identifiers_prohibited": True,
        }
        value["topology_id"] = digest_value(value)
        return value

    def cleanup(self):
        for sock in self.sockets.values():
            sock.close()
        self.sockets.clear()
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
        failures = 0
        for namespace in reversed(self.names):
            pids = command(("ip", "netns", "pids", namespace), check=False).stdout.split()
            for pid in pids:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if command(("ip", "netns", "del", namespace), check=False).returncode:
                failures += 1
        shutil.rmtree(self.temp, ignore_errors=True)
        return failures == 0


def _process_cpu_ns(pid):
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
        fields = text[text.rfind(")") + 2:].split()
        ticks = os.sysconf("SC_CLK_TCK")
        return int(fields[11]) * 1_000_000_000 // ticks, int(fields[12]) * 1_000_000_000 // ticks
    except (OSError, ValueError, IndexError):
        fail("native-command")


def _resource_snapshot(lab):
    own = resource.getrusage(resource.RUSAGE_SELF)
    user = int(own.ru_utime * 1_000_000_000)
    system = int(own.ru_stime * 1_000_000_000)
    for process in lab.processes:
        daemon_user, daemon_system = _process_cpu_ns(process.pid)
        user += daemon_user
        system += daemon_system
    return user, system


def _mark_error(error_code, code):
    with error_code.get_lock():
        if error_code.value == 0:
            error_code.value = code


def _send_worker(plan, state, mapping, sockets, origin, send_times, error_code,
                 queue_high_water, queue_overflow):
    physical = {0: "source-A", 1: "source-B"}
    local_macs = {0: _mac(plan["seed"], 0), 1: _mac(plan["seed"], 4)}
    peer_macs = {0: _mac(plan["seed"], 1), 1: _mac(plan["seed"], 5)}
    try:
        for index in range(400):
            due = origin - 1_000_000_000 + index * 10_000_000
            while True:
                remaining = (due - raw_ns()) / 1_000_000_000
                if remaining <= 0:
                    break
                time.sleep(min(remaining, .001))
            try:
                outbound = state.send(_payload(plan["seed"], index))
            finally:
                queue = state.queue_metrics()
                with queue_high_water.get_lock():
                    queue_high_water.value = max(queue_high_water.value, queue["queued_packets"])
                with queue_overflow.get_lock():
                    queue_overflow.value = max(queue_overflow.value, queue["overflow_packets"])
            stamp = None
            sent_slots = 0
            for slot, packet in enumerate(outbound.packets):
                if packet is None:
                    continue
                path = mapping[slot]
                frame = _frame(local_macs[path], peer_macs[path], packet)
                sent = sockets[physical[path]].send(frame)
                if sent != len(frame):
                    fail("binding-mismatch")
                state.confirm(slot, packet)
                if stamp is None:
                    stamp = raw_ns() - origin
                    send_times[index] = stamp
                sent_slots += 1
            if not sent_slots:
                fail("binding-mismatch")
    except Exception:
        _mark_error(error_code, 1)


def _receive_worker(plan, state, mapping, bindings, sockets, origin, receive_times,
                    receive_counts, error_code):
    selector = selectors.DefaultSelector()
    reverse = {physical: slot for slot, physical in mapping.items()}
    for physical, key in ((0, "destination-A"), (1, "destination-B")):
        if physical in reverse:
            selector.register(sockets[key], selectors.EVENT_READ, physical)
    deadline = origin + 3_000_000_000
    try:
        while raw_ns() < deadline:
            timeout = max(0, min((deadline - raw_ns()) / 1_000_000_000, .02))
            for selected, _ in selector.select(timeout):
                physical = selected.data
                slot = reverse[physical]
                try:
                    frame = selected.fileobj.recv(2048)
                except BlockingIOError:
                    continue
                local = _mac(plan["seed"], 3 if physical == 0 else 7)
                peer = _mac(plan["seed"], 2 if physical == 0 else 6)
                if len(frame) < 14 or frame[:6] != local or frame[6:12] != peer or frame[12:14] != ETHERTYPE.to_bytes(2, "big"):
                    continue
                inbound = state.receive(slot, bindings[slot], frame[14:])
                if len(inbound.plaintext) != 64:
                    fail("binding-mismatch")
                index = struct.unpack("!I", inbound.plaintext[:4])[0]
                if index >= 400 or inbound.plaintext != _payload(plan["seed"], index):
                    fail("binding-mismatch")
                stamp = raw_ns() - origin
                offset = physical * 400 + index
                if receive_counts[offset] == 0:
                    receive_times[offset] = stamp
                receive_counts[offset] += 1
    except Exception:
        _mark_error(error_code, 1)
    finally:
        selector.close()


def _trial_endpoint_process(plan, sockets, started, supervisor_deadline, ready, gate,
                            setup_state, origin, child_cpu, send_times, receive_times,
                            receive_counts, error_code, queue_high_water, queue_overflow):
    source = destination = None
    try:
        transport = _SocketControlTransport(
            sockets, plan["seed"], min(supervisor_deadline, raw_ns() + 10_000_000_000))
        source, destination, mapping, bindings = _states(
            plan, transport if plan["mechanism"] == "REDUNDANT" else None)
        with setup_state.get_lock():
            setup_state.value = 1
        ready.set()
        if not gate.wait(max(0, (supervisor_deadline - raw_ns()) / 1_000_000_000)):
            _mark_error(error_code, 2)
            return
        child_before = _process_cpu_ns(os.getpid())
        origin = origin.value
        sender = threading.Thread(
            target=_send_worker,
            args=(plan, source, mapping, sockets, origin, send_times, error_code,
                  queue_high_water, queue_overflow),
            daemon=True,
        )
        receiver = threading.Thread(
            target=_receive_worker,
            args=(plan, destination, mapping, bindings, sockets, origin, receive_times,
                  receive_counts, error_code),
            daemon=True,
        )
        receiver.start()
        sender.start()
        absolute = min(supervisor_deadline, started + 10_000_000_000)
        for thread in (sender, receiver):
            thread.join(max(0, (absolute - raw_ns()) / 1_000_000_000))
        if sender.is_alive() or receiver.is_alive():
            _mark_error(error_code, 2)
        child_after = _process_cpu_ns(os.getpid())
        with child_cpu.get_lock():
            child_cpu[0] = max(0, child_after[0] - child_before[0])
            child_cpu[1] = max(0, child_after[1] - child_before[1])
    except Exception:
        with setup_state.get_lock():
            if setup_state.value == 0:
                setup_state.value = 2
        ready.set()
        _mark_error(error_code, 1)
    finally:
        if source is not None:
            source.close()
        if destination is not None:
            destination.close()


def _packet_rows(plan, send_times, receive_times, receive_counts):
    rows = []
    active = 2 if plan["mechanism"] == "REDUNDANT" else 1
    for index in range(400):
        schedule = -1_000_000_000 + index * 10_000_000
        send = None if send_times[index] == MISSING_TIME else send_times[index]
        counts_a, counts_b = receive_counts[index], receive_counts[400 + index]
        first_a = None if receive_times[index] == MISSING_TIME else receive_times[index]
        first_b = None if receive_times[400 + index] == MISSING_TIME else receive_times[400 + index]
        counts = counts_a + counts_b
        first = min(value for value in (first_a, first_b) if value is not None) if counts else None
        authenticated = counts > 0
        on_schedule = schedule <= first <= schedule + 20_000_000 if authenticated else None
        if authenticated:
            outcome = "delivered" if on_schedule else "late"
            suppression = "duplicate" if counts > 1 else "none"
        else:
            outcome = "not_sent" if send is None else "lost"
            suppression = "trial_failure" if send is None else "not_received"
        rows.append({
            "trial_id": plan["trial_id"], "packet_index": index,
            "scheduled_relative_ns": schedule, "send_relative_ns": send,
            "mechanism_active_path_count": active, "authenticated_delivery": authenticated,
            "suppression": suppression, "outcome": outcome,
            "path_A_received_relative_ns": first_a, "path_B_received_relative_ns": first_b,
            "path_A_receive_count": counts_a, "path_B_receive_count": counts_b,
            "first_authenticated_receive_relative_ns": first, "on_schedule": on_schedule,
        })
    return rows


def _aggregates(rows):
    sent = sum(row["send_relative_ns"] is not None for row in rows)
    delivered = sum(row["authenticated_delivery"] for row in rows)
    duplicates = sum(max(row["path_A_receive_count"] + row["path_B_receive_count"] - 1, 0) for row in rows)
    arrivals = sorted((row["first_authenticated_receive_relative_ns"], row["packet_index"])
                      for row in rows if row["authenticated_delivery"])
    high, reorder = -1, 0
    for _, index in arrivals:
        reorder += index < high
        high = max(high, index)
    run = maximum = 0
    for row in rows:
        run = 0 if row["authenticated_delivery"] else run + 1
        maximum = max(maximum, run)
    return {"sent_packets": sent, "delivered_packets": delivered, "lost_packets": 400 - delivered,
            "duplicates": duplicates, "reorder_displacement_count": reorder,
            "max_consecutive_loss_burst": maximum}


def _readiness(rows):
    flags = [rows[index]["authenticated_delivery"] and rows[index]["on_schedule"]
             and rows[index]["first_authenticated_receive_relative_ns"] <= 0 for index in range(90, 100)]
    run = longest = 0
    for good in flags:
        run = run + 1 if good else 0
        longest = max(longest, run)
    return (max(rows[index]["first_authenticated_receive_relative_ns"] for index in range(90, 100))
            if longest == 10 else None), longest


def _recovery(rows, observations, valid):
    if not valid:
        return {"eligible": False, "censored": True, "event_relative_ns": None, "observed_followup_ns": 0}
    origin = max(item["end_actual_relative_ns"] for item in observations)
    run = 0
    event = None
    for row in rows:
        good = (row["scheduled_relative_ns"] > origin and row["authenticated_delivery"] and row["on_schedule"])
        run = run + 1 if good else 0
        if run == 10:
            candidate = row["first_authenticated_receive_relative_ns"] - origin
            if candidate <= 2_000_000_000:
                event = candidate
            break
    return {"eligible": True, "censored": event is None, "event_relative_ns": event,
            "observed_followup_ns": event if event is not None else max(0, min(2_000_000_000, 3_000_000_000 - origin))}


def _identity(value, field):
    copy = dict(value)
    copy.pop(field, None)
    return digest_value(copy)


def environment(preflight_value):
    offloads = [{"ordinal": index, "digest": digest_value({"ordinal": index, "gro": False, "gso": False, "tso": False})}
                for index in range(8)]
    value = {"namespace_count": 4, "isolated_namespace_count": 4, "clock": "CLOCK_MONOTONIC_RAW",
             "kernel_digest": hashlib.sha256(platform.release().encode()).hexdigest(),
             "cpu_digest": hashlib.sha256((platform.processor() or "redacted").encode()).hexdigest(),
             "release_binary_digest": preflight_value["binary_hash"],
             "source_digest": source_identity().split(":", 1)[1], "offload_digests": offloads,
             "raw_identifiers_prohibited": True}
    value["environment_id"] = _identity(value, "environment_id")
    return value


def execute_trial(lab, plan, environment_value, topology):
    started = raw_ns()
    supervisor_deadline = started + 20_000_000_000
    context = multiprocessing.get_context("fork")
    send_times = context.Array("q", [MISSING_TIME] * 400, lock=False)
    receive_times = context.Array("q", [MISSING_TIME] * 800, lock=False)
    receive_counts = context.Array("B", 800, lock=False)
    error_code = context.Value("i", 0)
    queue_high_water = context.Value("i", 0)
    queue_overflow = context.Value("i", 0)
    setup_state = context.Value("i", 0)
    origin = context.Value("q", 0)
    child_cpu = context.Array("q", [0, 0])
    ready, gate = context.Event(), context.Event()
    observations, valid_fault = [], plan["condition"] == "no-flap"
    state_before = [{"ordinal": index, "digest": None} for index in range(8)]
    state_after = [{"ordinal": index, "digest": None} for index in range(8)]
    cleanup_state = [{"ordinal": index, "digest": None} for index in range(8)]
    pre_counters = post_counters = None
    user_before = system_before = user_after = system_after = None
    admitted = supervisor_timeout = post_start_failure = False
    cleanup_ok = True
    emergency_deadline = None

    # Persistent packet sockets survive trials, so stale frames must be discarded before
    # the child can complete a new admission exchange.
    lab.drain(supervisor_deadline)
    endpoint = context.Process(
        target=_trial_endpoint_process,
        args=(plan, lab.sockets, started, supervisor_deadline, ready, gate, setup_state,
              origin, child_cpu, send_times, receive_times, receive_counts, error_code,
              queue_high_water, queue_overflow),
    )
    endpoint.start()
    try:
        ready.wait(max(0, (supervisor_deadline - raw_ns()) / 1_000_000_000))
        admitted = setup_state.value == 1 and ready.is_set()
        if admitted:
            # Admission traffic is also excluded from the measurement counter baseline.
            lab.drain(supervisor_deadline)
            if not lab.clean_qdisc(supervisor_deadline):
                fail("cleanup-failed")
            state_before = lab.state_digests(supervisor_deadline)
            pre_counters = lab.counters(supervisor_deadline)
            origin.value = raw_ns() + 1_250_000_000
            gate.set()
            # The child samples after this same gate; do not charge origin/gate setup.
            user_before, system_before = _resource_snapshot(lab)
            observations, valid_fault = lab.qdisc(plan["condition"], origin.value, supervisor_deadline)
        else:
            state_before = lab.state_digests(supervisor_deadline)
        endpoint.join(max(0, (supervisor_deadline - raw_ns()) / 1_000_000_000))
        supervisor_timeout = endpoint.is_alive() or raw_ns() >= supervisor_deadline
        if endpoint.exitcode not in (0, None) and error_code.value == 0:
            _mark_error(error_code, 1)
        if not supervisor_timeout and admitted:
            state_after = lab.state_digests(supervisor_deadline)
            post_counters = lab.counters(supervisor_deadline)
    except Exception:
        post_start_failure = True
        _mark_error(error_code, 1)
    finally:
        # No post-start failure may leave a child blocked on the shared gate.
        gate.set()
        try:
            endpoint.join(max(0, (supervisor_deadline - raw_ns()) / 1_000_000_000))
        except Exception:
            post_start_failure = True
        if endpoint.is_alive():
            supervisor_timeout = True
            emergency_deadline = raw_ns() + 3_000_000_000
            try:
                endpoint.terminate()
                endpoint.join(max(0, min(1, (emergency_deadline - raw_ns()) / 1_000_000_000)))
                if endpoint.is_alive():
                    endpoint.kill()
                    endpoint.join(max(0, (emergency_deadline - raw_ns()) / 1_000_000_000))
            except Exception:
                post_start_failure = True
        if endpoint.is_alive():
            post_start_failure = True
            cleanup_ok = False
        try:
            endpoint.close()
        except Exception:
            post_start_failure = True
            cleanup_ok = False

    if pre_counters is not None and post_counters is not None:
        wire_bytes = max(0, post_counters["bytes"] - pre_counters["bytes"])
        wire_packets = max(0, post_counters["packets"] - pre_counters["packets"])
    else:
        wire_bytes = wire_packets = None
    try:
        cleanup_deadline = emergency_deadline or supervisor_deadline
        cleanup_ok = lab.clean_qdisc(cleanup_deadline) and cleanup_ok
        cleanup_state = lab.state_digests(cleanup_deadline)
    except Exception:
        cleanup_ok = False
    try:
        user_after, system_after = _resource_snapshot(lab)
    except Exception:
        post_start_failure = True
    supervisor_timeout = supervisor_timeout or raw_ns() >= supervisor_deadline
    cleanup_ok = cleanup_ok and (not admitted or cleanup_state == state_before)

    rows = _packet_rows(plan, send_times, receive_times, receive_counts)
    metrics = _aggregates(rows)
    readiness, readiness_count = _readiness(rows)
    if plan["condition"] == "no-flap":
        recovery = {"eligible": False, "censored": False, "event_relative_ns": None, "observed_followup_ns": 0}
        flap_start = flap_end = None
        degraded = 0
    elif valid_fault:
        recovery = _recovery(rows, observations, True)
        starts = [item["start_actual_relative_ns"] for item in observations]
        ends = [item["end_actual_relative_ns"] for item in observations]
        flap_start, flap_end, degraded = max(starts), max(ends), max(ends) - min(starts)
    else:
        recovery = _recovery(rows, observations, False)
        flap_start = flap_end = degraded = None
    status, reason = "completed", None
    if not cleanup_ok:
        status, reason = "failed", "cleanup_failed"
    elif supervisor_timeout:
        status, reason = "timeout", "supervisor_timeout"
    elif not admitted:
        status, reason = "failed", "binding_mismatch"
    elif error_code.value == 2:
        status, reason = "timeout", "trial_timeout"
    elif plan["condition"] != "no-flap" and not valid_fault:
        status, reason = "failed", "flap-timing" if len(observations) == 2 else "fault_not_applied"
    elif error_code.value == 1 or post_start_failure:
        status, reason = "failed", "evidence_missing"
    elif state_after != state_before:
        status, reason = "failed", "evidence_missing"
    elif readiness is None:
        status, reason = "failed", "readiness_not_reached"
    measured_cpu = admitted and all(value is not None for value in
                                    (user_before, system_before, user_after, system_after))
    metrics.update({
        "degraded_interval_ns": degraded, "wire_bytes": wire_bytes, "wire_packets": wire_packets,
        "cpu_user_ns": (max(0, user_after - user_before) + child_cpu[0]) if measured_cpu else None,
        "cpu_system_ns": (max(0, system_after - system_before) + child_cpu[1]) if measured_cpu else None,
        "queue_high_water_packets": queue_high_water.value if admitted else None,
        "queue_overflow_packets": queue_overflow.value if admitted else None,
    })
    trial = {key: value for key, value in plan.items() if key != "warmup"}
    trial.update({"status": status, "failure_retained": True, "failure_reason": reason,
                  "t_origin_relative_ns": 0, "readiness_relative_ns": readiness,
                  "flap_start_actual_relative_ns": flap_start, "flap_end_actual_relative_ns": flap_end,
                  "recovery_relative_ns": recovery["event_relative_ns"],
                  "recovery_censored": recovery["censored"], "recovery_eligible": recovery["eligible"],
                  **metrics, "setup_status": "passed" if admitted else "failed",
                  "cleanup_status": "passed" if cleanup_ok else "failed",
                  "environment_id": environment_value["environment_id"], "topology_id": topology["topology_id"]})
    lifecycle = {key: trial[key] for key in ("status", "failure_reason", "setup_status", "cleanup_status", "failure_retained")}
    evidence = {"trial_id": plan["trial_id"], "condition": plan["condition"], "lifecycle": lifecycle,
                "readiness": {"relative_ns": readiness, "consecutive_authenticated_on_schedule_deliveries": readiness_count},
                "recovery": recovery, "metrics": {key: trial[key] for key in METRIC_FIELDS},
                "environment": environment_value, "topology": topology,
                "pre_state_digests": state_before, "post_state_digests": state_after,
                "cleanup_digests": cleanup_state, "qdisc_observations": observations,
                "failure_retained": True, "raw_identifiers_prohibited": True}
    evidence["evidence_id"] = _identity(evidence, "evidence_id")
    trial["evidence_id"] = evidence["evidence_id"]
    return trial, rows, evidence


def failure_trial(plan, environment_value, topology, cleanup_ok):
    send_times = [MISSING_TIME] * 400
    receive_times = [MISSING_TIME] * 800
    receive_counts = [0] * 800
    rows = _packet_rows(plan, send_times, receive_times, receive_counts)
    metrics = {**_aggregates(rows), "degraded_interval_ns": 0 if plan["condition"] == "no-flap" else None,
               "wire_bytes": None, "wire_packets": None, "cpu_user_ns": None, "cpu_system_ns": None,
               "queue_high_water_packets": None, "queue_overflow_packets": None}
    recovery = ({"eligible": False, "censored": False, "event_relative_ns": None, "observed_followup_ns": 0}
                if plan["condition"] == "no-flap" else
                {"eligible": False, "censored": True, "event_relative_ns": None, "observed_followup_ns": 0})
    reason = "evidence_missing" if cleanup_ok else "cleanup_failed"
    trial = {key: value for key, value in plan.items() if key != "warmup"}
    trial.update({"status": "failed", "failure_retained": True, "failure_reason": reason,
                  "t_origin_relative_ns": 0, "readiness_relative_ns": None,
                  "flap_start_actual_relative_ns": None, "flap_end_actual_relative_ns": None,
                  "recovery_relative_ns": None, "recovery_censored": recovery["censored"],
                  "recovery_eligible": False, **metrics, "setup_status": "failed",
                  "cleanup_status": "passed" if cleanup_ok else "failed",
                  "environment_id": environment_value["environment_id"], "topology_id": topology["topology_id"]})
    empty = [{"ordinal": index, "digest": None} for index in range(8)]
    lifecycle = {key: trial[key] for key in ("status", "failure_reason", "setup_status", "cleanup_status", "failure_retained")}
    evidence = {"trial_id": plan["trial_id"], "condition": plan["condition"], "lifecycle": lifecycle,
                "readiness": {"relative_ns": None, "consecutive_authenticated_on_schedule_deliveries": 0},
                "recovery": recovery, "metrics": {key: trial[key] for key in METRIC_FIELDS},
                "environment": environment_value, "topology": topology, "pre_state_digests": empty,
                "post_state_digests": empty, "cleanup_digests": empty,
                "qdisc_observations": [], "failure_retained": True, "raw_identifiers_prohibited": True}
    evidence["evidence_id"] = _identity(evidence, "evidence_id")
    trial["evidence_id"] = evidence["evidence_id"]
    return trial, rows, evidence


def type7(values, quantile):
    values = sorted(values)
    if not values:
        return None
    location = (len(values) - 1) * quantile
    low, high = math.floor(location), math.ceil(location)
    return values[low] + (values[high] - values[low]) * (location - low)


def _recovery_observations(trials, evidence_by_id):
    observations = []
    for trial in trials:
        if not trial["recovery_eligible"]:
            continue
        recovery = evidence_by_id[trial["trial_id"]]["recovery"]
        moment = (trial["recovery_relative_ns"] if trial["recovery_relative_ns"] is not None
                  else recovery["observed_followup_ns"])
        observations.append((min(2_000_000_000, moment),
                             trial["recovery_relative_ns"] is not None))
    return observations


def _recovery_quantile(trials, evidence_by_id, quantile):
    observations = _recovery_observations(trials, evidence_by_id)
    if not observations or any(not event for _, event in observations):
        return None
    return type7([moment for moment, _ in observations], quantile)


def _rmst(trials, evidence_by_id):
    observations = _recovery_observations(trials, evidence_by_id)
    if not observations:
        return None
    at_risk, survival, prior, area = len(observations), 1.0, 0, 0.0
    grouped = {}
    for moment, event in observations:
        grouped.setdefault(moment, [0, 0])[0 if event else 1] += 1
    for moment in sorted(grouped):
        area += survival * (moment - prior)
        events, censored = grouped[moment]
        if at_risk:
            survival *= (at_risk - events) / at_risk
        at_risk -= events + censored
        prior = moment
    return area + survival * (2_000_000_000 - prior)


def _estimate(trials, evidence_by_id):
    denominator = len(trials)
    failures = sum(trial["status"] != "completed" for trial in trials)
    losses = sum(trial["lost_packets"] for trial in trials)
    return {"failure_rate": failures / denominator if denominator else None,
            "loss_rate": losses / (denominator * 400) if denominator else None,
            "recovery_rmst_2s_ns": _rmst(trials, evidence_by_id),
            "recovery_p50_ns": _recovery_quantile(trials, evidence_by_id, .5),
            "recovery_p95_ns": _recovery_quantile(trials, evidence_by_id, .95)}


def _percentile(values):
    if not values or any(value is None for value in values):
        return None
    values = sorted(values)
    return [values[math.floor(.025 * (len(values) - 1))], values[math.ceil(.975 * (len(values) - 1))]]


def summary(trials, evidence, bootstrap_resamples=10_000):
    measured = [trial for trial in trials if trial["seed"] >= 20]
    evidence_by_id = {item["trial_id"]: item for item in evidence}
    result = []
    for condition in q2.CONDITIONS:
        groups = {mechanism: [trial for trial in measured if trial["condition"] == condition and trial["mechanism"] == mechanism]
                  for mechanism in q2.MECHANISMS}
        for mechanism, values in groups.items():
            estimate = _estimate(values, evidence_by_id)
            bootstrap = {key: [] for key in ("failure_rate", "loss_rate", "recovery_rmst_2s_ns",
                                              "recovery_p50_ns", "recovery_p95_ns")}
            by_block = {block: [trial for trial in values if trial["block"] == block] for block in range(1, 11)}
            for draw in range(bootstrap_resamples):
                sample = []
                for position in range(10):
                    _, block = q2.block_draw(draw, position)
                    sample.extend(by_block[block])
                candidate = _estimate(sample, evidence_by_id)
                for key in bootstrap:
                    bootstrap[key].append(candidate[key])
            result.append({"condition": condition, "mechanism": mechanism,
                           "trial_denominator": len(values), "logical_packet_denominator": len(values) * 400,
                           **estimate, "block_bootstrap_95_percent_ci": {key: _percentile(value) for key, value in bootstrap.items()}})
        for control in ("single-A", "single-B"):
            pairs = []
            for seed in range(20, 220):
                redundant_row = next((trial for trial in groups["REDUNDANT"] if trial["seed"] == seed), None)
                control_row = next((trial for trial in groups[control] if trial["seed"] == seed), None)
                if redundant_row is not None and control_row is not None:
                    pairs.append((redundant_row, control_row))
            failure = [(left["status"] != "completed") - (right["status"] != "completed") for left, right in pairs]
            loss = [(left["lost_packets"] - right["lost_packets"]) / 400 for left, right in pairs]
            bootstrap_failure, bootstrap_loss = [], []
            pairs_by_block = {block: [pair for pair in pairs if pair[0]["block"] == block]
                              for block in range(1, 11)}
            for draw in range(bootstrap_resamples):
                sample = []
                for position in range(10):
                    _, block = q2.block_draw(draw, position)
                    sample.extend(pairs_by_block[block])
                if sample:
                    bootstrap_failure.append(sum(
                        (left["status"] != "completed") - (right["status"] != "completed")
                        for left, right in sample) / len(sample))
                    bootstrap_loss.append(sum(
                        (left["lost_packets"] - right["lost_packets"]) / 400
                        for left, right in sample) / len(sample))
            result.append({"condition": condition, "contrast": "REDUNDANT-minus-" + control,
                           "paired_denominator": len(pairs),
                           "failure_difference": sum(failure) / len(failure) if failure else None,
                           "loss_difference": sum(loss) / len(loss) if loss else None,
                           "block_bootstrap_95_percent_ci": {
                               "failure_difference": _percentile(bootstrap_failure),
                               "loss_difference": _percentile(bootstrap_loss)}})
    return result


def _read_jsonl(path):
    with Path(path).open() as handle:
        return [q2._strict_loads(line) for line in handle if line.strip()]


def validate_package(output):
    output = Path(output)
    manifest = q2._strict_loads((output / "manifest.json").read_text())
    smoke = q2._strict_loads((output / "smoke_non_result.json").read_text())
    for name, expected in manifest["files"].items():
        if file_sha(output / name) != expected:
            fail("package-hash")
    if manifest.get("implementation_sources") != source_hashes() or manifest.get("source_identity") != source_identity():
        fail("source-identity")
    contract_sha, contract_size = q2._sha_size(q2.PROTOCOL)
    if (manifest.get("contract_sha256"), manifest.get("contract_size_bytes"), manifest.get("plan_sha256")) != (
            contract_sha, contract_size, q2.PLAN_SHA256):
        fail("package-hash")
    if manifest.get("schema_bindings") != [list(item) for item in q2.SCHEMA_BINDINGS]:
        fail("package-hash")
    if manifest.get("external_binding_required") != "GitHub Actions artifact-digest SHA-256":
        fail("package-hash")
    if not smoke:
        head = command(("git", "rev-parse", "HEAD")).stdout.strip()
        status = command(("git", "status", "--porcelain", "--untracked-files=all")).stdout
        if head != manifest.get("git_commit") or status:
            fail("source-identity")
        expected_gates = {"gate4-one": "gate4-one.json", "gate4-two": "gate4-two.json", "gate5": "gate5.json"}
        if set(manifest.get("gate_evidence", {})) != set(expected_gates):
            fail("gate-evidence")
        for kind, name in expected_gates.items():
            observed = gate(output / name, manifest.get("native_binary_hash"), kind,
                            manifest.get("endpoint_binary_hash"))
            if observed != manifest["gate_evidence"][kind]:
                fail("gate-evidence")
    elif manifest.get("gate_evidence") != {}:
        fail("gate-evidence")
    trials = _read_jsonl(output / "trial.jsonl")
    packets = _read_jsonl(output / "logical-packet.jsonl")
    evidence = _read_jsonl(output / "evidence.jsonl")
    environment_file = q2._strict_loads((output / "environment.json").read_text())
    if not evidence or environment_file != evidence[0].get("environment"):
        fail("package-hash")
    errors = q2.validate(trials, packets, evidence, require_complete=not smoke)
    eligible = not smoke and not errors and manifest.get("seed_cleanup_failures") == 0
    existing_summary = q2._strict_loads((output / "summary.json").read_text())
    rebuilt = summary(trials, evidence) if eligible else []
    if existing_summary != rebuilt or q2._strict_loads((output / "publication_eligible.json").read_text()) is not eligible:
        fail("package-summary")
    if manifest.get("row_counts") != {"trial": len(trials), "packet": len(packets), "evidence": len(evidence)}:
        fail("package-count")
    return eligible


def atomic_output(output, writer):
    output = Path(output)
    if output.exists():
        fail("output-exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".q2-package-", dir=output.parent))
    try:
        writer(temporary)
        os.replace(temporary, output)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def run_measurement(args):
    if not SAFE_EPOCH.fullmatch(args.host_epoch):
        fail("host-epoch")
    supplied_identity = args.source_identity or source_identity()
    if supplied_identity != source_identity():
        fail("source-identity")
    commit = args.git_commit or os.environ.get("GITHUB_SHA")
    preflight_value = preflight(args.binary, args.endpoint_binary, args.gate4_one, args.gate4_two,
                                args.gate5, smoke=args.smoke, commit=commit)
    environment_value = environment(preflight_value)
    plans = [plan for plan in q2.plan_rows() if not args.smoke or plan["seed"] == 0]
    result = {"eligible": False}

    def write_package(directory):
        trial_path, packet_path, evidence_path = (directory / "trial.jsonl", directory / "logical-packet.jsonl", directory / "evidence.jsonl")
        trials, evidence_rows = [], []
        seed_cleanup_failures = 0
        with trial_path.open("w") as trial_file, packet_path.open("w") as packet_file, evidence_path.open("w") as evidence_file:
            for seed in sorted({plan["seed"] for plan in plans}):
                seed_plans = [plan for plan in plans if plan["seed"] == seed]
                lab = Lab(seed, args.binary)
                topology = None
                setup_error = False
                cleanup_ok = True
                try:
                    lab.setup()
                    topology = lab.topology()
                    for plan in seed_plans:
                        trial, packets, evidence = execute_trial(lab, plan, environment_value, topology)
                        trials.append(trial); evidence_rows.append(evidence)
                        trial_file.write(canonical(trial) + "\n")
                        for packet in packets:
                            packet_file.write(canonical(packet) + "\n")
                        evidence_file.write(canonical(evidence) + "\n")
                        if trial["cleanup_status"] != "passed":
                            fail("cleanup-failed")
                except Exception:
                    setup_error = True
                finally:
                    try:
                        cleanup_ok = lab.cleanup()
                    except Exception:
                        cleanup_ok = False
                if not cleanup_ok:
                    seed_cleanup_failures += 1
                if setup_error:
                    if topology is None:
                        # Intended, digest-only topology is retained; no raw runtime name is claimed.
                        lab.documents = [canonical(lab._manifest("A")), canonical(lab._manifest("B"))]
                        topology = lab.topology()
                    for plan in seed_plans:
                        if any(item["trial_id"] == plan["trial_id"] for item in trials):
                            continue
                        trial, packets, evidence = failure_trial(plan, environment_value, topology, cleanup_ok)
                        trials.append(trial); evidence_rows.append(evidence)
                        trial_file.write(canonical(trial) + "\n")
                        for packet in packets:
                            packet_file.write(canonical(packet) + "\n")
                        evidence_file.write(canonical(evidence) + "\n")
        (directory / "environment.json").write_text(canonical(environment_value) + "\n")
        smoke = bool(args.smoke)
        if not smoke:
            for name, path in (("gate4-one.json", args.gate4_one),
                               ("gate4-two.json", args.gate4_two),
                               ("gate5.json", args.gate5)):
                (directory / name).write_bytes(Path(path).read_bytes())
        errors = q2.validate(trials, _read_jsonl(packet_path), evidence_rows, require_complete=not smoke)
        eligible = not smoke and not errors and seed_cleanup_failures == 0
        (directory / "summary.json").write_text(canonical(summary(trials, evidence_rows) if eligible else []) + "\n")
        (directory / "publication_eligible.json").write_text(canonical(eligible) + "\n")
        (directory / "smoke_non_result.json").write_text(canonical(smoke) + "\n")
        files = {path.name: file_sha(path) for path in directory.iterdir() if path.is_file()}
        manifest = {"protocol_id": "Q2", "contract_version": "r8-benchmark-preregistration-v5",
                    "source_identity": supplied_identity, "implementation_sources": source_hashes(),
                    "git_commit": commit, "host_epoch": args.host_epoch, "plan_sha256": q2.PLAN_SHA256,
                    "contract_sha256": q2._sha_size(q2.PROTOCOL)[0],
                    "contract_size_bytes": q2._sha_size(q2.PROTOCOL)[1],
                    "schema_bindings": [list(item) for item in q2.SCHEMA_BINDINGS],
                    "native_binary_hash": preflight_value["binary_hash"],
                    "endpoint_binary_hash": preflight_value["endpoint_binary_hash"],
                    "external_binding_required": "GitHub Actions artifact-digest SHA-256",
                    "gate_evidence": preflight_value["gates"],
                    "row_counts": {"trial": len(trials), "packet": sum(1 for _ in packet_path.open()), "evidence": len(evidence_rows)},
                    "seed_cleanup_failures": seed_cleanup_failures,
                    "status": "smoke-non-result" if smoke else ("completed" if eligible else "invalid-diagnostic"),
                    "files": files, "limitations": ["Private isolated same-host namespace evidence only.",
                                                       "No Internet, public-network, or standardized IPv8 claim."]}
        (directory / "manifest.json").write_text(canonical(manifest) + "\n")
        result["eligible"] = eligible

    atomic_output(args.output, write_package)
    validate_package(args.output)
    return 0 if args.smoke or result["eligible"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="Q2 v5 native closed-lab measurement")
    commands = parser.add_subparsers(dest="command_name", required=True)
    commands.add_parser("source-identity")
    pre = commands.add_parser("preflight")
    run_parser = commands.add_parser("run")
    regenerate = commands.add_parser("regenerate")
    regenerate.add_argument("--output", required=True, type=Path)
    for target in (pre, run_parser):
        target.add_argument("--binary", required=True)
        target.add_argument("--endpoint-binary", required=True)
        target.add_argument("--gate4-one")
        target.add_argument("--gate4-two")
        target.add_argument("--gate5")
        target.add_argument("--smoke", action="store_true")
    run_parser.add_argument("--output", required=True, type=Path)
    run_parser.add_argument("--host-epoch", required=True)
    run_parser.add_argument("--source-identity")
    run_parser.add_argument("--git-commit")
    args = parser.parse_args(argv)
    try:
        if args.command_name == "source-identity":
            print(source_identity())
            return 0
        if args.command_name == "preflight":
            print(canonical(preflight(args.binary, args.endpoint_binary, args.gate4_one, args.gate4_two,
                                      args.gate5, smoke=args.smoke, commit=os.environ.get("GITHUB_SHA"))))
            return 0
        if args.command_name == "regenerate":
            validate_package(args.output)
            return 0
        return run_measurement(args)
    except (RuntimeError, ValueError, OSError, json.JSONDecodeError) as error:
        category = str(error)
        if category not in {"contract-drift", "clock", "privilege", "environment", "binary", "source-identity",
                            "gate-evidence", "host-epoch", "output-exists", "package-hash", "package-summary",
                            "package-count", "native-command", "native-ready", "native-privilege"}:
            category = "runtime"
        print(canonical({"error_category": category, "ok": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
