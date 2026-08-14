#!/usr/bin/env python3
"""Strict R8 v0.2 UDP reference wire implementation (closed lab only)."""
import argparse
import errno
import ipaddress
import socket
import struct
import sys
import threading
import time

R8_UDP_PORT = 52808
R8_ETHERTYPE = 0x88B5
VERSION = 8
HEADER_LEN = 48
SERIALIZED_MAX = 1280
NH_CTL, NH_DGRAM, NH_SES, NH_NONE = 1, 2, 3, 59
CTL_ECHO_REQUEST, CTL_ECHO_REPLY = 1, 2
CTL_DEST_UNREACHABLE, CTL_TIME_EXCEEDED, CTL_PACKET_TOO_BIG = 128, 129, 130
DGRAM_HDR = struct.Struct("!HHHH")

ERROR_CATEGORIES = frozenset((
    "TRUNCATED", "TRAILING_BYTES", "PACKET_CAP", "BINDING_BUDGET",
    "LENGTH_OVERFLOW", "VERSION", "PROFILE", "TRAFFIC_CLASS", "NEXT_HEADER",
    "HOP_LIMIT", "FLAGS", "PATH_SLOT", "SCID", "NONE_PAYLOAD", "CTL_SHORT",
    "CTL_TYPE", "CTL_CODE", "CTL_BODY", "CTL_CHECKSUM", "DGRAM_SHORT",
    "DGRAM_LENGTH", "DGRAM_CHECKSUM",
))


class WireError(ValueError):
    """A finite, fail-closed R8 wire error."""
    __slots__ = ("category",)

    def __init__(self, category):
        if category not in ERROR_CATEGORIES:
            raise ValueError("invalid WireError category")
        self.category = category
        super().__init__(category)


def _fail(category):
    raise WireError(category)


def parse_loc(text):
    return ipaddress.IPv6Address(text)


def _sum16(data):
    total = 0
    pairs = len(data) - (len(data) % 2)
    for offset in range(0, pairs, 2):
        total += (data[offset] << 8) | data[offset + 1]
        total = (total & 0xffff) + (total >> 16)
    if len(data) % 2:
        total += data[-1] << 8
        total = (total & 0xffff) + (total >> 16)
    return total


def checksum16(pseudo, body):
    total = _sum16(pseudo + body)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def pseudo_header(hdr, plen, nh):
    return hdr.src.packed + hdr.dst.packed + struct.pack("!II", plen, nh)

def _wire_view(data):
    try:
        view = memoryview(data)
    except TypeError:
        _fail("TRUNCATED")
    if not view.contiguous:
        _fail("TRUNCATED")
    try:
        return view.cast("B")
    except TypeError:
        _fail("TRUNCATED")


def _checked_binding_budget(binding_budget):
    if not isinstance(binding_budget, int) or not 48 <= binding_budget <= SERIALIZED_MAX:
        _fail("BINDING_BUDGET")



def _checked_packet_size(payload_len, binding_budget):
    if payload_len > 0xffff:
        _fail("LENGTH_OVERFLOW")
    total = HEADER_LEN + payload_len
    if total > SERIALIZED_MAX:
        _fail("PACKET_CAP")
    _checked_binding_budget(binding_budget)
    if total > binding_budget:
        _fail("BINDING_BUDGET")


def _u8(value, category):
    if not isinstance(value, int) or value < 0 or value > 0xff:
        _fail(category)


def _u64(value):
    if not isinstance(value, int) or value < 0 or value > 0xffffffffffffffff:
        _fail("SCID")


class Header:
    """The exact 48-byte R8 v0.2 header."""
    __slots__ = ("profile", "tc", "nh", "hop", "flags", "pslot", "scid", "src", "dst")

    def __init__(self, nh, src, dst, profile=0, tc=0, hop=64, flags=0, pslot=0, scid=0):
        self.profile, self.tc, self.nh, self.hop = profile, tc, nh, hop
        self.flags, self.pslot, self.scid = flags, pslot, scid
        self.src = src if isinstance(src, ipaddress.IPv6Address) else ipaddress.IPv6Address(src)
        self.dst = dst if isinstance(dst, ipaddress.IPv6Address) else ipaddress.IPv6Address(dst)

    def _validate_fixed(self, payload):
        _u8(self.nh, "NEXT_HEADER")
        if self.nh not in (NH_CTL, NH_DGRAM, NH_SES, NH_NONE):
            _fail("NEXT_HEADER")
        if self.nh == NH_SES:
            self._validate_ses(payload)
            return
        _u8(self.profile, "PROFILE")
        if self.profile > 3:
            _fail("PROFILE")
        _u8(self.tc, "TRAFFIC_CLASS")
        if self.tc != 0:
            _fail("TRAFFIC_CLASS")
        _u8(self.hop, "HOP_LIMIT")
        if self.hop == 0:
            _fail("HOP_LIMIT")
        _u8(self.flags, "FLAGS")
        if self.flags & ~0x03:
            _fail("FLAGS")
        _u8(self.pslot, "PATH_SLOT")
        _u64(self.scid)
        if self.profile != 0:
            _fail("PROFILE")
        if self.flags != 0:
            _fail("FLAGS")
        if self.pslot != 0:
            _fail("PATH_SLOT")
        if self.scid != 0:
            _fail("SCID")
        if self.nh == NH_NONE and payload:
            _fail("NONE_PAYLOAD")

    def _validate_ses(self, payload):
        _u64(self.scid)
        if self.scid == 0:
            _fail("SCID")
        if len(payload) < 4:
            _fail("TRUNCATED")
        stype, session_version, ses_profile, ses_flags = payload[:4]
        if stype not in (1, 2, 3, 4, 5, 6, 7) or session_version != 1:
            _fail("NEXT_HEADER")
        _u8(self.profile, "PROFILE")
        if self.profile > 3 or ses_profile > 3 or ses_profile != self.profile:
            _fail("PROFILE")
        _u8(self.tc, "TRAFFIC_CLASS")
        if self.tc != 0:
            _fail("TRAFFIC_CLASS")
        _u8(self.hop, "HOP_LIMIT")
        if self.hop == 0:
            _fail("HOP_LIMIT")
        if ses_flags != 0:
            _fail("FLAGS")
        _u8(self.flags, "FLAGS")
        if self.flags & ~0x03:
            _fail("FLAGS")
        _u8(self.pslot, "PATH_SLOT")
        if stype <= 4:
            wanted_flags, wanted_slot = 0, 0
        elif stype == 5:
            wanted_flags, wanted_slot = 1, 0
        elif self.profile == 3:
            if self.flags not in (1, 3):
                _fail("FLAGS")
            wanted_slot = 0 if self.flags == 1 else 1
            if self.pslot != wanted_slot:
                _fail("PATH_SLOT")
            return
        else:
            wanted_flags, wanted_slot = 1, 0
        if self.flags != wanted_flags:
            _fail("FLAGS")
        if self.pslot != wanted_slot:
            _fail("PATH_SLOT")

    def pack(self, payload=b"", binding_budget=1280):
        view = _wire_view(payload)
        _checked_packet_size(view.nbytes, binding_budget)
        payload = view.tobytes()
        self._validate_fixed(payload)
        if self.nh == NH_CTL:
            parse_ctl(self, payload)
        elif self.nh == NH_DGRAM:
            parse_dgram(self, payload)
        fixed = struct.pack("!BBHBBBBQ", (VERSION << 4) | self.profile, self.tc,
                            len(payload), self.nh, self.hop, self.flags,
                            self.pslot, self.scid)
        return fixed + self.src.packed + self.dst.packed + payload

    @classmethod
    def unpack(cls, data, binding_budget=1280):
        _checked_binding_budget(binding_budget)
        view = _wire_view(data)
        if view.nbytes > SERIALIZED_MAX:
            _fail("PACKET_CAP")
        if view.nbytes > binding_budget:
            _fail("BINDING_BUDGET")
        if view.nbytes < HEADER_LEN:
            _fail("TRUNCATED")
        b0, tc, plen, nh, hop, flags, pslot, scid = struct.unpack("!BBHBBBBQ", view[:16])
        if b0 >> 4 != VERSION:
            _fail("VERSION")
        expected = HEADER_LEN + plen
        if expected > SERIALIZED_MAX:
            _fail("PACKET_CAP")
        if expected > binding_budget:
            _fail("BINDING_BUDGET")
        if view.nbytes < expected:
            _fail("TRUNCATED")
        if view.nbytes > expected:
            _fail("TRAILING_BYTES")
        hdr = cls(nh, ipaddress.IPv6Address(view[16:32].tobytes()), ipaddress.IPv6Address(view[32:48].tobytes()),
                  profile=b0 & 0x0f, tc=tc, hop=hop, flags=flags, pslot=pslot, scid=scid)
        payload = view[HEADER_LEN:].tobytes()
        hdr._validate_fixed(payload)
        if nh == NH_CTL:
            parse_ctl(hdr, payload)
        elif nh == NH_DGRAM:
            parse_dgram(hdr, payload)
        return hdr, payload


def _ctl_shape(ctype, code, body):
    if not isinstance(ctype, int) or ctype not in (1, 2, 128, 129, 130):
        _fail("CTL_TYPE")
    allowed_codes = {1: (0,), 2: (0,), 128: (0, 1, 3, 4), 129: (0,), 130: (0,)}
    if not isinstance(code, int) or code not in allowed_codes[ctype]:
        _fail("CTL_CODE")
    minimum = 4 if ctype in (1, 2, 130) else 0
    if len(body) < minimum:
        _fail("CTL_BODY")
    quote = body[4:] if ctype == 130 else (body if ctype >= 128 else b"")
    if len(quote) > 512:
        _fail("CTL_BODY")


def build_ctl(hdr, ctype, code, body, binding_budget=1280):
    view = _wire_view(body)
    _checked_packet_size(4 + view.nbytes, binding_budget)
    body = view.tobytes()
    _ctl_shape(ctype, code, body)
    if not isinstance(hdr, Header) or hdr.nh != NH_CTL:
        _fail("NEXT_HEADER")
    msg = struct.pack("!BBH", ctype, code, 0) + body
    hdr._validate_fixed(msg)
    checksum = checksum16(pseudo_header(hdr, len(msg), NH_CTL), msg) or 0xffff
    return hdr.pack(struct.pack("!BBH", ctype, code, checksum) + body, binding_budget)


def parse_ctl(hdr, payload):
    if len(payload) < 4:
        _fail("CTL_SHORT")
    ctype, code, received = struct.unpack("!BBH", payload[:4])
    body = payload[4:]
    _ctl_shape(ctype, code, body)
    if received == 0:
        _fail("CTL_CHECKSUM")
    zeroed = payload[:2] + b"\0\0" + body
    if (checksum16(pseudo_header(hdr, len(payload), NH_CTL), zeroed) or 0xffff) != received:
        _fail("CTL_CHECKSUM")
    return ctype, code, body


def build_dgram(hdr, sport, dport, data, binding_budget=1280):
    view = _wire_view(data)
    if not isinstance(hdr, Header) or hdr.nh != NH_DGRAM:
        _fail("NEXT_HEADER")
    if not isinstance(sport, int) or not 0 <= sport <= 0xffff:
        _fail("DGRAM_LENGTH")
    if not isinstance(dport, int) or not 0 <= dport <= 0xffff:
        _fail("DGRAM_LENGTH")
    length = DGRAM_HDR.size + view.nbytes
    if length > 0xffff:
        _fail("LENGTH_OVERFLOW")
    _checked_packet_size(length, binding_budget)
    data = view.tobytes()
    msg = DGRAM_HDR.pack(sport, dport, length, 0) + data
    hdr._validate_fixed(msg)
    checksum = checksum16(pseudo_header(hdr, length, NH_DGRAM), msg) or 0xffff
    return hdr.pack(DGRAM_HDR.pack(sport, dport, length, checksum) + data, binding_budget)


def parse_dgram(hdr, payload):
    if len(payload) < DGRAM_HDR.size:
        _fail("DGRAM_SHORT")
    sport, dport, length, received = DGRAM_HDR.unpack(payload[:DGRAM_HDR.size])
    if length != len(payload):
        _fail("DGRAM_LENGTH")
    if received == 0:
        _fail("DGRAM_CHECKSUM")
    zeroed = payload[:6] + b"\0\0" + payload[8:]
    if (checksum16(pseudo_header(hdr, len(payload), NH_DGRAM), zeroed) or 0xffff) != received:
        _fail("DGRAM_CHECKSUM")
    return sport, dport, payload[DGRAM_HDR.size:]


def _validate_port(port):
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("invalid port")
    return port


def _underlay_endpoint(host, port, allow_isolated_underlay=False):
    _validate_port(port)
    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise ValueError("invalid underlay endpoint") from error
    if (address.is_unspecified or address.is_multicast or address.is_reserved
            or address == ipaddress.ip_address("255.255.255.255")):
        raise ValueError("unsafe underlay destination")
    if address.is_loopback:
        return str(address), port
    allowed_isolated = (address.version == 4 and address in ipaddress.ip_network("10.0.0.0/8")
                        or address.version == 4 and address in ipaddress.ip_network("172.16.0.0/12")
                        or address.version == 4 and address in ipaddress.ip_network("192.168.0.0/16")
                        or address.is_link_local)
    if allow_isolated_underlay and allowed_isolated:
        return str(address), port
    raise ValueError("underlay destination rejected")


def parse_peers(entries, allow_isolated_underlay=False):
    peers = {}
    for entry in entries or []:
        loc, sep, destination = entry.partition("=")
        host, colon, port = destination.rpartition(":")
        if not sep or not colon:
            raise ValueError("invalid peer")
        peers[parse_loc(loc.strip())] = _underlay_endpoint(
            host.strip(), int(port), allow_isolated_underlay)
    return peers


def _configure_pmtu(sock):
    if not sys.platform.startswith("linux"):
        raise RuntimeError("PMTU/DF unavailable on this platform")
    sock.setsockopt(socket.IPPROTO_IP, 10, 2)


def _send_packet(sock, packet, endpoint):
    try:
        sent = sock.sendto(packet, endpoint)
    except OSError as error:
        if error.errno == errno.EMSGSIZE:
            _fail("BINDING_BUDGET")
        raise
    if sent != len(packet):
        raise OSError(errno.EIO, "short datagram send")


def run_echo_server(sock, me, stop, binding_budget=1252):
    sock.settimeout(0.2)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(binding_budget + 1)
        except socket.timeout:
            continue
        try:
            if len(data) > binding_budget:
                _fail("BINDING_BUDGET")
            hdr, payload = Header.unpack(data, binding_budget)
            if hdr.dst != me:
                print("[drop] direction length=" + str(len(data)), flush=True)
                continue
            if hdr.nh == NH_CTL:
                ctype, code, body = parse_ctl(hdr, payload)
                if ctype == CTL_ECHO_REQUEST and code == 0:
                    reply = Header(NH_CTL, me, hdr.src)
                    _send_packet(sock, build_ctl(reply, CTL_ECHO_REPLY, 0, body, binding_budget), addr)
                    print("[echo] outbound length=" + str(len(data)), flush=True)
            elif hdr.nh == NH_DGRAM:
                parse_dgram(hdr, payload)
                print("[dgram] inbound length=" + str(len(data)), flush=True)
        except WireError as error:
            print("[drop] " + error.category + " length=" + str(min(len(data), binding_budget + 1)), flush=True)


def _validate_cli_args(args, require_peer=False):
    _checked_binding_budget(getattr(args, "binding_budget", 1252))
    port = getattr(args, "port", R8_UDP_PORT)
    _validate_port(port)
    _underlay_endpoint(args.bind, port, getattr(args, "allow_isolated_underlay", False))
    if require_peer:
        if (hasattr(args, "count")
                and (args.count <= 0 or args.timeout <= 0 or args.interval < 0)):
            raise ValueError("invalid ping timing")
        if hasattr(args, "sport"):
            _validate_port(args.sport)
        if hasattr(args, "dport"):
            _validate_port(args.dport)


def cmd_listen(args):
    _validate_cli_args(args)
    me = parse_loc(args.address)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _configure_pmtu(sock)
    sock.bind((args.bind, args.port))
    print("[r8ref] listen", flush=True)
    run_echo_server(sock, me, threading.Event(), args.binding_budget)


def cmd_ping(args):
    _validate_cli_args(args, require_peer=True)
    me, target = parse_loc(args.address), parse_loc(args.loc)
    binding_budget = getattr(args, "binding_budget", 1252)
    allow_isolated = getattr(args, "allow_isolated_underlay", False)
    peers = parse_peers(args.peer, allow_isolated)
    if target not in peers:
        raise ValueError("missing peer")
    endpoint = peers[target]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _configure_pmtu(sock)
    sock.bind((args.bind, 0))
    ident = int(time.time()) & 0xffff
    sent = received = invalid = attempts = 0
    for sequence in range(1, args.count + 1):
        attempts += 1
        body = struct.pack("!HH", ident, sequence)
        started = time.monotonic()
        try:
            _send_packet(sock, build_ctl(Header(NH_CTL, me, target), CTL_ECHO_REQUEST, 0,
                                         body, binding_budget), endpoint)
        except WireError:
            invalid += 1
            print("R8-ECHO send-failed sequence=" + str(sequence))
            continue
        sent += 1
        deadline = started + args.timeout
        matched = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, source = sock.recvfrom(binding_budget + 1)
                if len(data) > binding_budget or source != endpoint:
                    invalid += 1
                    continue
                hdr, payload = Header.unpack(data, binding_budget)
                ctype, code, reply = parse_ctl(hdr, payload)
                if (ctype == CTL_ECHO_REPLY and code == 0 and reply == body
                        and hdr.src == target and hdr.dst == me):
                    received += 1
                    matched = True
                    print("R8-ECHO reply sequence=" + str(sequence))
                    break
                invalid += 1
            except socket.timeout:
                break
            except WireError:
                invalid += 1
        if not matched:
            print("R8-ECHO invalid-or-timeout sequence=" + str(sequence))
        time.sleep(args.interval)
    loss = 100 * (attempts - received) / attempts
    print(f"{sent} sent, {received} received, {loss:.0f}% loss, {invalid} invalid")
    if received != attempts or invalid:
        raise SystemExit(1)


def cmd_send(args):
    _validate_cli_args(args, require_peer=True)
    me, target = parse_loc(args.address), parse_loc(args.loc)
    binding_budget = getattr(args, "binding_budget", 1252)
    allow_isolated = getattr(args, "allow_isolated_underlay", False)
    peers = parse_peers(args.peer, allow_isolated)
    if target not in peers:
        raise ValueError("missing peer")
    packet = build_dgram(Header(NH_DGRAM, me, target), args.sport, args.dport,
                         args.message.encode(), binding_budget)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _configure_pmtu(sock)
    sock.bind((args.bind, 0))
    try:
        _send_packet(sock, packet, peers[target])
    except WireError:
        raise SystemExit(1)
    print("[r8ref] dgram outbound length=" + str(len(packet)))


def main():
    parser = argparse.ArgumentParser(prog="r8ref")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("listen", "ping", "send"):
        command = sub.add_parser(name)
        command.add_argument("--address", required=True)
        command.add_argument("--peer", action="append")
        command.add_argument("--binding-budget", type=int, default=1252)
        command.add_argument("--allow-isolated-underlay", action="store_true")
        if name == "listen":
            command.add_argument("--bind", default="127.0.0.1")
            command.add_argument("--port", type=int, default=R8_UDP_PORT)
            command.set_defaults(fn=cmd_listen)
        elif name == "ping":
            command.add_argument("loc")
            command.add_argument("--bind", default="127.0.0.1")
            command.add_argument("--count", type=int, default=4)
            command.add_argument("--timeout", type=float, default=1.0)
            command.add_argument("--interval", type=float, default=0.2)
            command.set_defaults(fn=cmd_ping)
        else:
            command.add_argument("loc")
            command.add_argument("message")
            command.add_argument("--bind", default="127.0.0.1")
            command.add_argument("--sport", type=int, default=1000)
            command.add_argument("--dport", type=int, default=9000)
            command.set_defaults(fn=cmd_send)
    args = parser.parse_args()
    try:
        args.fn(args)
    except (ValueError, WireError) as error:
        parser.error(error.category if isinstance(error, WireError) else "invalid arguments")


if __name__ == "__main__":
    main()
