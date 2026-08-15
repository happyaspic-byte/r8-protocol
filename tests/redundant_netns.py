#!/usr/bin/env python3
"""Root-only, fail-not-skip redundant native Ethernet proof.

The endpoints own Profile-3 state; r8-native only sees opaque Ethernet payloads.
Diagnostics deliberately expose only finite counters and framed digests.
"""
import argparse, hashlib, json, os, selectors, shutil, signal, socket, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import r8mobility as mobility
import r8redundant as redundant
import r8session as session

ETHERTYPE = 0x88B5
SOL_PACKET = 263
PACKET_IGNORE_OUTGOING = 23
UID = GID = 65534
READY = "r8-native ready descriptors="


def sha(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()


def canonical_frame(domain, records):
    out = bytearray(); domain = domain.encode(); out += len(domain).to_bytes(8, "big") + domain
    for path, ordinal, value in sorted(records, key=lambda r: (r[0], r[1])):
        path = path.encode(); out += len(path).to_bytes(8, "big") + path + ordinal.to_bytes(8, "big") + len(value).to_bytes(8, "big") + value
    return bytes(out)


def aggregate_hash(domain, records): return sha(canonical_frame(domain, records))
def endpoint_frame_counts(before, after):
    expected = {(0, 0), (0, 2), (3, 1), (3, 3)}
    if set(before) != expected or set(after) != expected:
        raise RuntimeError("rust-frame-count")
    sent = sum(after[key][0] - before[key][0] for key in expected)
    received = sum(after[key][1] - before[key][1] for key in expected)
    path0 = sum(after[key][0] - before[key][0] for key in ((0, 0), (3, 1)))
    path1 = sum(after[key][0] - before[key][0] for key in ((0, 2), (3, 3)))
    return sent, received, path0, path1
def mac(n): return bytes((2, 0x52, 0x38, 0, n >> 8, n & 255))
def eth(dst, src, packet): return dst + src + ETHERTYPE.to_bytes(2, "big") + packet

def manifest(ifaces, routes):
    return {"local_locs": [], "interfaces": [{"descriptor_id": ident, "interface_name": name,
        "allowed_source_macs": [list(mac(peer))], "local_delivery": False, "transit": True}
        for ident, name, peer in ifaces], "routes": [{"destination_prefix": {"network": list(destination.packed), "prefix_length": 128},
        "egress_descriptor_id": ident, "next_hop_mac": list(next_hop)} for destination, ident, next_hop in routes]}

def socket_for(interface):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE))
    sock.setsockopt(SOL_PACKET, PACKET_IGNORE_OUTGOING, 1); sock.bind((interface, ETHERTYPE)); sock.setblocking(False)
    return sock

def receive(sock, timeout=2):
    poll = selectors.DefaultSelector(); poll.register(sock, selectors.EVENT_READ)
    events = poll.select(timeout); poll.close()
    return sock.recv(2048) if events else None

def run(command, check=True): return subprocess.run(command, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
def ip(*args, ns=None, check=True):
    prefix = ["ip", "netns", "exec", ns, "ip"] if ns is not None else ["ip"]
    return run(prefix + list(args), check)
STARTUP_STAGES = frozenset(("arguments", "manifest", "isolation", "descriptors", "watch", "privilege", "runtime"))
ISOLATION_STAGES = frozenset(("namespace", "network", "default-route-v4", "address", "interface", "internal"))
def startup_error(stderr):
    stage = isolation = None
    for line in stderr.splitlines():
        if line.startswith("r8-native startup=") and line.removeprefix("r8-native startup=") in STARTUP_STAGES:
            stage = line.removeprefix("r8-native startup=")
        if line.startswith("r8-native isolation=") and line.removeprefix("r8-native isolation=") in ISOLATION_STAGES:
            isolation = line.removeprefix("r8-native isolation=")
    if isolation is not None:
        return f"startup-isolation-{isolation}"
    return f"startup-{stage}" if stage is not None else "ready"
def proc_status(pid):
    wanted = {"Uid", "Gid", "Groups", "CapEff", "NoNewPrivs"}; result = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in wanted: result[key] = value.split()
    return result

def source_records():
    paths = (
        "tests/redundant_netns.py", "tests/vectors/session-v0.1.json", "requirements-dev.txt",
        "spec/0004-wire-format-v0.2.md", "spec/0005-session-security-v0.1.md",
        "spec/0006-mobility-v0.1.md", "spec/0007-native-binding-v0.1.md",
        "spec/0008-redundant-v0.1.md", "spec/parameters-v0.1.md",
        "reference/r8ref.py", "reference/r8session.py", "reference/r8mobility.py",
        "reference/r8redundant.py",
        "rust/Cargo.toml", "rust/Cargo.lock",
        "rust/crates/r8d/Cargo.toml", "rust/crates/r8d/src/bin/r8-native.rs",
        "rust/crates/r8d/src/lib.rs", "rust/crates/r8d/src/native.rs",
        "rust/crates/r8d/src/linux.rs", "rust/crates/r8d/src/manifest.rs",
        "rust/crates/r8d/src/forward.rs",
        "rust/crates/r8-proto/Cargo.toml", "rust/crates/r8-proto/src/lib.rs",
        "rust/crates/r8-session/Cargo.toml", "rust/crates/r8-session/src/lib.rs",
        "rust/crates/r8-redundant/Cargo.toml", "rust/crates/r8-redundant/src/lib.rs",
        "rust/crates/r8-redundant/src/bin/r8-redundant-native.rs",
        "rust/crates/r8-mobility/Cargo.toml", "rust/crates/r8-mobility/src/lib.rs",
        ".github/workflows/native-full.yml", ".github/workflows/ci.yml",
    )
    return [(path, n, (ROOT / path).read_bytes()) for n, path in enumerate(paths)]

class Lab:
    # Link order is source-hopA, hopA-destination, source-hopB, hopB-destination.
    links = ((0, 1), (1, 3), (0, 2), (2, 3))
    def __init__(self, binary, endpoint_binary):
        self.binary, self.endpoint_binary = binary, endpoint_binary
        self.token = os.urandom(5).hex(); self.names = []; self.procs = []; self.docs = []
        self.temp = Path(tempfile.mkdtemp(prefix="r8-redundant-")); self.error_category = None; self.router_privilege_dropped = self.endpoint_privilege_dropped = False
        self.counts = {"frames_sent": 0, "frames_received": 0, "application_deliveries": 0,
                       "suppressions": 0, "rust_endpoint_authentications": 0, "cached_retries": 0,
                       "degraded_events": 0, "path_removals": 0, "negative_drops": 0,
                       "budget_rejects": 0, "daemon_exits": 0, "cleanup_failures": 0}
    def ns(self, n): return f"r8r{self.token}{n}"
    def iface(self, node, link): return f"p{link}"  # unique inside each namespace
    def setup(self):
        for n in range(4):
            name = self.ns(n); ip("netns", "add", name); self.names.append(name)
            run(["ip", "netns", "exec", name, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1"]); run(["ip", "netns", "exec", name, "sysctl", "-qw", "net.ipv6.conf.default.disable_ipv6=1"]); ip("link", "set", "lo", "down", ns=name)
        for link, (left, right) in enumerate(self.links):
            a, b = f"v{link}a", f"v{link}b"; ip("link", "add", a, "type", "veth", "peer", "name", b)
            ip("link", "set", a, "netns", self.ns(left)); ip("link", "set", b, "netns", self.ns(right))
            ip("link", "set", a, "name", self.iface(left, link), ns=self.ns(left)); ip("link", "set", b, "name", self.iface(right, link), ns=self.ns(right))
        for link, (left, right) in enumerate(self.links):
            for node in (left, right):
                iface = self.iface(node, link); ip("link", "set", iface, "address", mac(link * 4 + node).hex(":"), ns=self.ns(node)); ip("link", "set", iface, "mtu", "1500", ns=self.ns(node)); ip("link", "set", iface, "up", ns=self.ns(node))
    def launch(self):
        # Each strict daemon has precisely its two path-facing descriptors.
        for hop, descriptors, links, peers in ((1, (2, 3), (0, 1), (0, 3)), (2, (4, 5), (2, 3), (0, 3))):
            local = [self.iface(hop, link) for link in links]
            peer_macs = [mac(link * 4 + peer) for link, peer in zip(links, peers)]
            # Routes cover both endpoint locations; opaque Profile-3 packets are routed by destination LOC.
            locs = (session.ipaddress.IPv6Address("11:2233:4455:6677:8899:aabb:ccdd:eeff"), session.ipaddress.IPv6Address("ffee:ddcc:bbaa:9988:7766:5544:3322:1100"))
            routes = [(locs[0], descriptors[0], peer_macs[0]), (locs[1], descriptors[1], peer_macs[1])]
            if hop == 2:
                routes.append((
                    session.ipaddress.IPv6Address("8::3"),
                    descriptors[0], peer_macs[0]))
            doc = manifest(list(zip(descriptors, local, [link * 4 + peer for link, peer in zip(links, peers)])), routes)
            text = json.dumps(doc, sort_keys=True, separators=(",", ":")); self.docs.append(text); path = self.temp / f"hop{hop}.json"; path.write_text(text)
            command = ["ip", "netns", "exec", self.ns(hop), self.binary, "--manifest", str(path), "--interface", local[0], "--interface", local[1], "--uid", str(UID), "--gid", str(GID)]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True); self.procs.append(process)
            select = selectors.DefaultSelector(); select.register(process.stdout, selectors.EVENT_READ)
            ready = bool(select.select(5)) and process.stdout.readline().startswith(READY)
            select.close()
            if not ready:
                if process.poll() is None:
                    try: process.wait(timeout=.2)
                    except subprocess.TimeoutExpired: pass
                raise RuntimeError(startup_error(process.stderr.read()) if process.poll() is not None else "ready")
            status = proc_status(process.pid)
            if status.get("Uid", ["0"])[0] != str(UID) or status.get("Gid", ["0"])[0] != str(GID) or status.get("Groups") != [] or status.get("CapEff") != ["0000000000000000"] or status.get("NoNewPrivs") != ["1"]: raise RuntimeError("privilege")
        self.router_privilege_dropped = True
    def endpoints(self):
        vectors = json.loads((ROOT / "tests/vectors/session-v0.1.json").read_text()); ids, context = vectors["identities"], vectors["context"]; now = [100]
        ci, si = session.Identity.from_seed(bytes.fromhex(ids["client_ed25519_seed_hex"])), session.Identity.from_seed(bytes.fromhex(ids["server_ed25519_seed_hex"]))
        cl, sl = session.ipaddress.IPv6Address("11:2233:4455:6677:8899:aabb:ccdd:eeff"), session.ipaddress.IPv6Address("ffee:ddcc:bbaa:9988:7766:5544:3322:1100")
        source_bindings = (session.NativeBinding(2, mac(1)), session.NativeBinding(3, mac(10)))
        destination_bindings = (session.NativeBinding(4, mac(5)), session.NativeBinding(5, mac(14)))
        client = session.ClientMachine(ci, session.PeerPin(2, si.eid, si.public), context["service_context"], 3, cl, sl, lambda: now[0])
        server = session.ServerMachine(session.ServerConfig(si, session.PeerPin(1, ci.eid, ci.public), context["service_context"], context["server_context_id"], 3, sl, cl, 1280, 2, 2), bytes.fromhex(context["server_boot_instance_hex"]), bytes.fromhex(context["cookie_key_hex"]), None, 0, lambda: now[0], session.PrevalidationLimiter(lambda: now[0], b"a" * 32))
        opening = client.start(context["scid"])
        auth = client.receive_verify(server.receive_open_packet(opening, destination_bindings[0], context["cookie_bucket"]))
        ack = server.receive_open_auth(auth, destination_bindings[0], context["cookie_bucket"])
        server.receive_protected(client.receive_ack(ack))
        source = redundant.RedundantSession(client.take_profile3(), source_bindings[0], 1280, 1, lambda: now[0])
        destination = redundant.RedundantSession(server.take_profile3(context["scid"]), destination_bindings[0], 1280, 9, lambda: now[0])
        # Each role runs its own signed mobility exchange.  The vector SCID is public
        # test context; no bootstrap/session internals are inspected.
        a = mobility.MobilityManager(
            ci, session.PeerPin(2, si.eid, si.public), 1, 3, context["scid"], 3,
            str(cl), str(sl), source_bindings[0], b"c" * 32, lambda: now[0],
            session_commit=source.commit_receive,
            profile3_admission_owner=source.issue_profile3_admission_owner(3))
        b = mobility.MobilityManager(
            si, session.PeerPin(1, ci.eid, ci.public), 2, 3, context["scid"], 3,
            str(sl), str(cl), destination_bindings[0], b"d" * 32, lambda: now[0],
            session_commit=destination.commit_receive,
            profile3_admission_owner=destination.issue_profile3_admission_owner(3))
        def protected_control(sender, receiver_state, manager, control,
                              sender_node, receiver_node, physical_slot):
            outbound = sender.send(control); packet = outbound.packets[0]
            if packet is None: raise RuntimeError("control")
            received, observed_binding = self.transit(
                sender_node, receiver_node, physical_slot, packet, admission=True)
            preview = receiver_state.preview_mobility(
                manager, 0, observed_binding, received)
            result = receiver_state.commit_mobility(preview)
            sender.confirm(0, packet)
            return result
        candidate = b"z" * 16
        update = a.propose_local("8::3", 1, candidate, slot=1, carrier=source_bindings[1])
        protected_control(
            source, destination, b, update, 0, 3, 0)
        challenge = protected_control(
            source, destination, b,
            a.make_probe(candidate, source_bindings[1], b"n" * 16), 0, 3, 1)
        response = protected_control(
            destination, source, a, challenge, 3, 0, 1)
        protected_control(
            source, destination, b, response, 0, 3, 1)
        protected_control(
            destination, source, a, b.take_results()[0], 3, 0, 1)
        source.activate_slot1(a.take_profile3_admissions()[0], source_bindings[1], 1280)
        destination.activate_slot1(b.take_profile3_admissions()[0], destination_bindings[1], 1280)
        return source, destination, source_bindings, destination_bindings

    def transit(self, sender_node, receiver_node, slot, packet, admission=False):
        header, _ = session.parse_packet(packet)
        expected_destination = (
            bytes.fromhex("00080000000000000000000000000003")
            if receiver_node == 0 and header.pslot == 1 else
            bytes.fromhex("00112233445566778899aabbccddeeff")
            if receiver_node == 0 else
            bytes.fromhex("ffeeddccbbaa99887766554433221100"))
        if packet[32:48] != expected_destination:
            raise RuntimeError("forward-destination")
        first_link, last_link = ((0, 1), (2, 3))[slot] if sender_node == 0 else ((1, 0), (3, 2))[slot]
        watcher = subprocess.Popen(["ip", "netns", "exec", self.ns(receiver_node), sys.executable, str(Path(__file__).resolve()), "--worker", "watch", "--interface", self.iface(receiver_node, last_link)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(.05)
        hop_node = 1 if slot == 0 else 2
        frame = eth(mac(first_link * 4 + hop_node), mac(first_link * 4 + sender_node), packet)
        sender = run(["ip", "netns", "exec", self.ns(sender_node), sys.executable, str(Path(__file__).resolve()), "--worker", "send", "--interface", self.iface(sender_node, first_link), "--frame", frame.hex()], check=False)
        if sender.returncode:
            raise RuntimeError("forward-send")
        try:
            watched = watcher.wait(timeout=4)
        except subprocess.TimeoutExpired as error:
            daemon = self.procs[0 if hop_node == 1 else 1]
            raise RuntimeError(
                "forward-daemon" if daemon.poll() is not None
                else "forward-timeout") from error
        if watched:
            raise RuntimeError("forward-watch")
        received = bytes.fromhex(watcher.stdout.read().strip())
        expected_src = mac(last_link * 4 + (1 if last_link < 2 else 2))
        expected_dst = mac(last_link * 4 + receiver_node)
        if (len(received) != len(packet) + 14 or received[:6] != expected_dst
                or received[6:12] != expected_src or received[12:14] != ETHERTYPE.to_bytes(2, "big")
                or received[14:19] != packet[:5] or received[19] != packet[5] - 1
                or received[20:] != packet[6:]):
            raise RuntimeError("forward-frame")
        self.counts["frames_sent"] += 1; self.counts["frames_received"] += 1
        payload = received[14:]
        if admission:
            descriptor = (4, 5)[slot] if receiver_node == 3 else (2, 3)[slot]
            return payload, session.NativeBinding(descriptor, received[6:12])
        return payload
    def expect_drop(self, sender_node, receiver_node, slot, packet, source_mac=None):
        first_link, last_link = ((0, 1), (2, 3))[slot] if sender_node == 0 else ((1, 0), (3, 2))[slot]
        watcher = subprocess.Popen(["ip", "netns", "exec", self.ns(receiver_node), sys.executable, str(Path(__file__).resolve()), "--worker", "watch", "--interface", self.iface(receiver_node, last_link)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(.05)
        hop_node = 1 if slot == 0 else 2
        frame = eth(mac(first_link * 4 + hop_node),
                    mac(first_link * 4 + sender_node) if source_mac is None else source_mac, packet)
        sent = run(["ip", "netns", "exec", self.ns(sender_node), sys.executable, str(Path(__file__).resolve()), "--worker", "send", "--interface", self.iface(sender_node, first_link), "--frame", frame.hex()], check=False)
        if sent.returncode or watcher.wait(timeout=4) == 0:
            raise RuntimeError("negative")
        self.counts["negative_drops"] += 1


    def endpoint_counters(self):
        counters = {}
        for node, links in ((0, (0, 2)), (3, (1, 3))):
            for link in links:
                details = json.loads(ip("-j", "-s", "link", "show", "dev", self.iface(node, link), ns=self.ns(node)).stdout)[0]
                stats = details["stats64"] if "stats64" in details else details["stats"]
                counters[(node, link)] = (stats["tx"]["packets"], stats["rx"]["packets"])
        return counters

    def endpoint_process(self, command, seed, peer_public):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, seed + peer_public)
        finally:
            os.close(write_fd)
        saved_fd = os.dup(3)
        try:
            os.dup2(read_fd, 3, inheritable=True)
            return subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, pass_fds=(3,))
        finally:
            os.dup2(saved_fd, 3)
            os.close(saved_fd)
            os.close(read_fd)

    def rust_endpoint_proof(self):
        sender_seed, receiver_seed = os.urandom(32), os.urandom(32)
        sender_public = session.Identity.from_seed(sender_seed).public
        receiver_public = session.Identity.from_seed(receiver_seed).public
        receiver_command = [
            "ip", "netns", "exec", self.ns(3), self.endpoint_binary, "receive",
            self.iface(3, 1), self.iface(3, 3),
            mac(7).hex(":"), mac(5).hex(":"), mac(15).hex(":"), mac(14).hex(":"),
        ]
        receiver = self.endpoint_process(receiver_command, receiver_seed, sender_public)
        try:
            listening = selectors.DefaultSelector(); listening.register(receiver.stdout, selectors.EVENT_READ)
            if (not listening.select(5)
                    or receiver.stdout.readline().strip() != "R8-ENDPOINT-LISTENING"):
                raise RuntimeError("rust-endpoint")
            listening.close()
            status = proc_status(receiver.pid)
            if (status.get("Uid", ["0"])[0] != str(UID)
                    or status.get("Gid", ["0"])[0] != str(GID)
                    or status.get("Groups") != []
                    or status.get("CapEff") != ["0000000000000000"]
                    or status.get("NoNewPrivs") != ["1"]):
                raise RuntimeError("rust-endpoint")
            self.endpoint_privilege_dropped = True
            before = self.endpoint_counters()
            sender_command = [
                "ip", "netns", "exec", self.ns(0), self.endpoint_binary, "send",
                self.iface(0, 0), self.iface(0, 2),
                mac(0).hex(":"), mac(1).hex(":"), mac(8).hex(":"), mac(10).hex(":"),
            ]
            sender = self.endpoint_process(sender_command, sender_seed, receiver_public)
            sender_output, sender_error = sender.communicate(timeout=8)
            output, error = receiver.communicate(timeout=8)
            after = self.endpoint_counters()
            if (sender.returncode or sender_error or sender_output.splitlines()
                    != ["R8-ENDPOINT-READY handshake=5 candidate=5 application=2 total=12",
                        "R8-ENDPOINT-SENT copies=2 handshake=5 candidate=5 application=2 total=12"]
                    or receiver.returncode or error
                    or output.splitlines() != ["R8-ENDPOINT-READY handshake=5 candidate=5 application=2 total=12",
                                               "R8-ENDPOINT-PASS delivered=1 suppressed=1 handshake=5 candidate=5 application=2 total=12"]):
                raise RuntimeError("rust-endpoint")
            sent, received, path0, path1 = endpoint_frame_counts(before, after)
            if (sent, received, path0, path1) != (12, 12, 7, 5):
                raise RuntimeError("rust-frame-count")
        except Exception:
            if receiver.poll() is None:
                receiver.kill()
            receiver.wait(timeout=2)
            raise
        self.counts["frames_sent"] += sent
        self.counts["frames_received"] += received
        self.counts["application_deliveries"] += 1
        self.counts["suppressions"] += 1
        self.counts["rust_endpoint_authentications"] += 1
    def proof(self):
        self.rust_endpoint_proof()
        source, destination, source_bindings, destination_bindings = self.endpoints()
        for direction, (sender, receiver, sender_node, receiver_node, bindings) in enumerate((
            (source, destination, 0, 3, destination_bindings),
            (destination, source, 3, 0, source_bindings),
        )):
            try:
                outbound = sender.send(b"redundant proof")
            except Exception as error:
                raise RuntimeError(f"application-{direction}-send") from error
            for slot in (1, 0):
                try:
                    packet = self.transit(
                        sender_node, receiver_node, slot, outbound.packets[slot])
                except Exception as error:
                    suffix = str(error) if str(error) in {
                        "forward-destination", "forward-send", "forward-daemon",
                        "forward-timeout", "forward-watch", "forward-frame",
                    } else "internal"
                    raise RuntimeError(
                        f"application-{direction}-{slot}-transit-{suffix}") from error
                try:
                    result = receiver.receive(slot, bindings[slot], packet)
                except Exception as error:
                    raise RuntimeError(
                        f"application-{direction}-{slot}-receive") from error
                if result.delivered: self.counts["application_deliveries"] += 1
                else: self.counts["suppressions"] += 1
                try:
                    sender.confirm(slot, outbound.packets[slot])
                except Exception as error:
                    raise RuntimeError(
                        f"application-{direction}-{slot}-confirm") from error
        retry_outbound = source.send(b"retry")
        retry = retry_outbound.packets[0]
        delivered = destination.receive(0, destination_bindings[0], self.transit(0, 3, 0, retry))
        if not delivered.delivered: raise RuntimeError("replay")
        self.counts["application_deliveries"] += 1
        try:
            destination.receive(0, destination_bindings[0], self.transit(0, 3, 0, retry))
        except redundant.RedundantError as error:
            if str(error) != "E-REPLAY": raise
            self.counts["cached_retries"] += 1
        source.confirm(0, retry)
        second = destination.receive(1, destination_bindings[1],
                                     self.transit(0, 3, 1, retry_outbound.packets[1]))
        if second.delivered: raise RuntimeError("replay")
        self.counts["suppressions"] += 1
        source.confirm(1, retry_outbound.packets[1])
        # These are Ethernet observations only: no endpoint state is invoked for
        # malformed, spoofed, unroutable, or exhausted-hop traffic.
        self.expect_drop(0, 3, 0, b"\0")
        self.expect_drop(0, 3, 0, retry, source_mac=mac(99))
        route_miss = bytearray(retry); route_miss[32:48] = bytes.fromhex("20010db8000000000000000000000001")
        self.expect_drop(0, 3, 0, bytes(route_miss))
        hop_one = bytearray(retry); hop_one[5] = 1
        self.expect_drop(0, 3, 0, bytes(hop_one))
        exact = source.send(b"x" * 1196)
        exact_deliveries = 0
        for slot in (0, 1):
            packet = self.transit(0, 3, slot, exact.packets[slot])
            result = destination.receive(slot, destination_bindings[slot], packet)
            exact_deliveries += int(result.delivered)
            self.counts["application_deliveries"] += int(result.delivered)
            self.counts["suppressions"] += int(not result.delivered)
            source.confirm(slot, exact.packets[slot])
        if exact_deliveries != 1: raise RuntimeError("budget")
        try:
            source.send(b"x" * 1197)
        except redundant.RedundantError as error:
            if str(error) != "E-BUDGET": raise
            self.counts["budget_rejects"] += 1
        ip("link", "set", self.iface(2, 3), "down", ns=self.ns(2))
        source.remove_path(1); destination.remove_path(1); source.remove_path(1); destination.remove_path(1)
        self.counts["path_removals"] += 2
        if source.events[-1].kind == "degraded" and destination.events[-1].kind == "degraded": self.counts["degraded_events"] += 2
        remaining = source.send(b"remaining")
        if remaining.packets[1] is not None: raise RuntimeError("fault")
        delivered = destination.receive(0, destination_bindings[0], self.transit(0, 3, 0, remaining.packets[0]))
        if not delivered.delivered: raise RuntimeError("fault")
        self.counts["application_deliveries"] += 1
        source.confirm(0, remaining.packets[0])
        source.remove_path(0); destination.remove_path(0)
    def revoke(self):
        for hop, process in zip((1, 2), self.procs):
            ip("link", "set", self.iface(hop, 0 if hop == 1 else 2), "down", ns=self.ns(hop))
            if process.wait(timeout=5) == 0: raise RuntimeError("revocation")
            self.counts["daemon_exits"] += 1
    def cleanup(self):
        for process in self.procs:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=2)
        for namespace in reversed(self.names):
            pids = ip("netns", "pids", namespace, check=False).stdout.split()
            for pid in pids:
                try: os.kill(int(pid), signal.SIGTERM)
                except ProcessLookupError: pass
            time.sleep(.05)
            for pid in ip("netns", "pids", namespace, check=False).stdout.split():
                try: os.kill(int(pid), signal.SIGKILL)
                except ProcessLookupError: pass
            if ip("netns", "pids", namespace, check=False).stdout.split() or ip("netns", "del", namespace, check=False).returncode:
                self.counts["cleanup_failures"] += 1
        shutil.rmtree(self.temp, ignore_errors=True)

def worker(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("send", "watch")); parser.add_argument("--interface", required=True); parser.add_argument("--frame")
    args = parser.parse_args(argv); sock = socket_for(args.interface)
    if args.mode == "send":
        sock.send(bytes.fromhex(args.frame)); return 0
    frame = receive(sock)
    if frame is None or len(frame) < 14 or frame[12:14] != ETHERTYPE.to_bytes(2, "big"):
        return 1
    print(frame.hex())
    return 0


def result_json(lab, binary, endpoint_binary):
    binary_data = Path(binary).read_bytes() if Path(binary).is_file() else b""
    endpoint_data = Path(endpoint_binary).read_bytes() if Path(endpoint_binary).is_file() else b""
    return {"ok": lab.error_category is None and not lab.counts["cleanup_failures"],
            "error_category": lab.error_category, "counts": lab.counts,
            "source_hash": aggregate_hash("r8-redundant-source-v1", source_records()),
            "binary_hash": sha(binary_data), "endpoint_binary_hash": sha(endpoint_data),
            "manifest_hash": aggregate_hash("r8-redundant-manifest-v1", [("manifest", n, value.encode()) for n, value in enumerate(lab.docs)]),
            "filter_hash": aggregate_hash("r8-native-filter-v1", [("rust/crates/r8d/src/linux.rs", 0, (ROOT / "rust/crates/r8d/src/linux.rs").read_bytes())]),
            "interface_ordinals": [2, 3, 4, 5], "privilege_dropped": (getattr(lab, "router_privilege_dropped", False) and getattr(lab, "endpoint_privilege_dropped", False)),
            "revocation_verified": lab.counts["daemon_exits"] == 2,
            "cleanup_verified": lab.counts["cleanup_failures"] == 0}

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=os.environ.get("R8_NATIVE_BINARY", str(ROOT / "rust/target/release/r8-native")))
    parser.add_argument("--endpoint-binary", default=os.environ.get("R8_REDUNDANT_ENDPOINT_BINARY", str(ROOT / "rust/target/release/r8-redundant-native")))
    parser.add_argument("--worker", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.worker: return worker(args.worker)
    if os.geteuid() != 0: return 1
    lab = Lab(args.binary, args.endpoint_binary)
    try:
        if (not shutil.which("ip") or not os.path.isfile(args.binary) or not os.access(args.binary, os.X_OK)
                or not os.path.isfile(args.endpoint_binary) or not os.access(args.endpoint_binary, os.X_OK)):
            raise RuntimeError("setup")
        lab.setup(); lab.launch(); lab.proof(); lab.revoke()
    except Exception as error:
        allowed = ({"setup", "ready", "privilege", "revocation", "rust-endpoint"}
                   | {f"startup-{stage}" for stage in STARTUP_STAGES}
                   | {f"startup-isolation-{stage}" for stage in ISOLATION_STAGES}
                   | {f"application-{direction}-{slot}-transit-{reason}"
                      for direction in range(2) for slot in range(2)
                      for reason in ("forward-destination", "forward-send",
                                     "forward-daemon", "forward-timeout",
                                     "forward-watch", "forward-frame", "internal")}
                   | {f"application-{direction}-{slot}-{operation}"
                      for direction in range(2) for slot in range(2)
                      for operation in ("receive", "confirm")}
                   | {f"application-{direction}-send" for direction in range(2)})
        lab.error_category = str(error) if str(error) in allowed else "proof"
    finally:
        try: lab.cleanup()
        except Exception: lab.counts["cleanup_failures"] += 1
    print(json.dumps(result_json(lab, args.binary, args.endpoint_binary), sort_keys=True, separators=(",", ":")))
    return 0 if lab.error_category is None and not lab.counts["cleanup_failures"] else 1

if __name__ == "__main__": raise SystemExit(main())
