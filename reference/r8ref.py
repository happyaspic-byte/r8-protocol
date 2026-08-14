#!/usr/bin/env python3
"""R8 reference implementation (udp-binding) — wire format v0.1.

Source of truth for the format: spec/0001-wire-format-v0.1.md
Stdlib only. Lab use only; NOT an Internet standard.

Usage:
  r8ref.py selftest
  r8ref.py listen --address 8:1::10 --bind 127.0.0.1 --port 52808
  r8ref.py ping   --address 8:1::20 --peer 8:1::10=127.0.0.1:52808 8:1::10
  r8ref.py send   --address 8:1::20 --peer 8:1::10=127.0.0.1:52808 8:1::10 "hello"
"""
import argparse
import ipaddress
import socket
import struct
import sys
import threading
import time

R8_UDP_PORT = 52808        # dynamic/private range (RFC 6335); lab use only
R8_ETHERTYPE = 0x88B5      # IEEE local experimental; eth-binding is M4, not here
VERSION = 8
HEADER_LEN = 48

NH_CTL, NH_DGRAM, NH_SES, NH_NONE = 1, 2, 3, 59

CTL_ECHO_REQUEST = 1
CTL_ECHO_REPLY = 2
CTL_DEST_UNREACHABLE = 128
CTL_TIME_EXCEEDED = 129
CTL_PACKET_TOO_BIG = 130

DGRAM_HDR = struct.Struct("!HHHH")
SES_HDR = struct.Struct("!BBH")


def parse_loc(text):
    """Parse an R8 locator (RFC 4291 textual form, e.g. '8:1::10')."""
    return ipaddress.IPv6Address(text)


def _sum16(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return s


def checksum16(pseudo, body):
    s = _sum16(pseudo + body)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def pseudo_header(hdr, plen, nh):
    return hdr.src.packed + hdr.dst.packed + struct.pack("!I", plen) + struct.pack("!I", nh)


class Header:
    """R8 base header, 48 bytes. See spec section 2."""

    __slots__ = ("profile", "tc", "nh", "hop", "flags", "pslot", "scid", "src", "dst")

    def __init__(self, nh, src, dst, profile=0, tc=0, hop=64, flags=0, pslot=0, scid=0):
        self.profile, self.tc, self.nh, self.hop = profile, tc, nh, hop
        self.flags, self.pslot, self.scid = flags, pslot, scid
        self.src, self.dst = src, dst

    def pack(self, payload=b""):
        b0 = (VERSION << 4) | (self.profile & 0xF)
        fixed = struct.pack(
            "!BBHBBBBQ", b0, self.tc, len(payload), self.nh,
            self.hop, self.flags, self.pslot, self.scid,
        )
        return fixed + self.src.packed + self.dst.packed + payload

    @classmethod
    def unpack(cls, data):
        if len(data) < HEADER_LEN:
            raise ValueError(f"short packet: {len(data)} < {HEADER_LEN}")
        b0, tc, plen, nh, hop, flags, pslot, scid = struct.unpack("!BBHBBBBQ", data[:16])
        version = b0 >> 4
        if version != VERSION:
            raise ValueError(f"bad version: {version}")
        if len(data) < HEADER_LEN + plen:
            raise ValueError("truncated payload")
        hdr = cls(nh, ipaddress.IPv6Address(data[16:32]), ipaddress.IPv6Address(data[32:48]),
                  profile=b0 & 0xF, tc=tc, hop=hop, flags=flags, pslot=pslot, scid=scid)
        return hdr, data[HEADER_LEN:HEADER_LEN + plen]


# --- CTL ---

def build_ctl(hdr, ctype, code, body, with_checksum=True):
    msg = struct.pack("!BBH", ctype, code, 0) + body
    if with_checksum:
        c = checksum16(pseudo_header(hdr, len(msg), NH_CTL), msg)
        msg = struct.pack("!BBH", ctype, code, c) + body
    return hdr.pack(msg)


def parse_ctl(hdr, payload):
    if len(payload) < 4:
        raise ValueError("short ctl")
    ctype, code, csum = struct.unpack("!BBH", payload[:4])
    ok = True
    if csum != 0:
        ok = checksum16(pseudo_header(hdr, len(payload), NH_CTL), payload) == 0
    return ctype, code, csum, payload[4:], ok


# --- DGRAM ---

def build_dgram(hdr, sport, dport, data, with_checksum=True):
    msg = DGRAM_HDR.pack(sport, dport, DGRAM_HDR.size + len(data), 0) + data
    if with_checksum:
        c = checksum16(pseudo_header(hdr, len(msg), NH_DGRAM), msg)
        msg = DGRAM_HDR.pack(sport, dport, DGRAM_HDR.size + len(data), c) + data
    return hdr.pack(msg)


def parse_dgram(hdr, payload):
    if len(payload) < DGRAM_HDR.size:
        raise ValueError("short dgram")
    sport, dport, length, csum = DGRAM_HDR.unpack(payload[:DGRAM_HDR.size])
    ok = True
    if csum != 0:
        ok = checksum16(pseudo_header(hdr, len(payload), NH_DGRAM), payload) == 0
    return sport, dport, payload[DGRAM_HDR.size:length], ok


# --- peers / io ---

def parse_peers(entries):
    """['8:1::10=127.0.0.1:52808', ...] -> {IPv6Address: (host, port)}"""
    peers = {}
    for e in entries or []:
        loc, _, dest = e.partition("=")
        host, _, port = dest.rpartition(":")
        peers[parse_loc(loc.strip())] = (host.strip(), int(port))
    return peers


def run_echo_server(sock, me, stop):
    sock.settimeout(0.2)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        try:
            hdr, payload = Header.unpack(data)
        except ValueError as e:
            print(f"[drop] {e}", flush=True)
            continue
        if hdr.dst != me:
            print(f"[drop] dst {hdr.dst} != me {me}", flush=True)
            continue
        if hdr.nh == NH_CTL:
            ctype, code, _c, body, ok = parse_ctl(hdr, payload)
            if not ok:
                print(f"[drop] bad ctl checksum from {hdr.src}", flush=True)
                continue
            if ctype == CTL_ECHO_REQUEST:
                ident, seq = struct.unpack("!HH", body[:4])
                rh = Header(NH_CTL, src=me, dst=hdr.src, scid=hdr.scid)
                sock.sendto(build_ctl(rh, CTL_ECHO_REPLY, 0, body), addr)
                print(f"[echo] reply -> {hdr.src} seq={seq}", flush=True)
        elif hdr.nh == NH_DGRAM:
            sport, dport, data, ok = parse_dgram(hdr, payload)
            if ok:
                print(f"[dgram] {hdr.src}:{sport} -> :{dport} {data!r}", flush=True)
            else:
                print(f"[drop] bad dgram checksum from {hdr.src}", flush=True)


def cmd_listen(args):
    me = parse_loc(args.address)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    print(f"[r8ref] listen {me} on {args.bind}:{args.port} (udp-binding)", flush=True)
    run_echo_server(sock, me, threading.Event())


def cmd_ping(args):
    me = parse_loc(args.address)
    target = parse_loc(args.loc)
    peers = parse_peers(args.peer)
    if target not in peers:
        sys.exit(f"no udp-binding peer for {target} (use --peer {target}=host:port)")
    dest = peers[target]
    ident = int(time.time()) & 0xFFFF
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, 0))
    sock.settimeout(args.timeout)
    sent = rcvd = 0
    t_start = time.time()
    for seq in range(1, args.count + 1):
        hdr = Header(NH_CTL, src=me, dst=target)
        body = struct.pack("!HH", ident, seq)
        t0 = time.time()
        sock.sendto(build_ctl(hdr, CTL_ECHO_REQUEST, 0, body), dest)
        sent += 1
        try:
            data, _ = sock.recvfrom(65535)
            rh, payload = Header.unpack(data)
            ctype, _c, _s, rbody, ok = parse_ctl(rh, payload)
            if ok and ctype == CTL_ECHO_REPLY and rbody[:4] == body:
                rcvd += 1
                ms = (time.time() - t0) * 1000
                print(f"R8-ECHO reply from {rh.src} sequence={seq} latency={ms:.2f} ms", flush=True)
        except socket.timeout:
            print(f"R8-ECHO timeout sequence={seq}", flush=True)
        time.sleep(args.interval)
    loss = 100.0 * (sent - rcvd) / sent
    print(f"--- {target} r8ping statistics ---")
    print(f"{sent} sent, {rcvd} received, {loss:.0f}% loss, time {int((time.time()-t_start)*1000)} ms")


def cmd_send(args):
    me = parse_loc(args.address)
    target = parse_loc(args.loc)
    peers = parse_peers(args.peer)
    if target not in peers:
        sys.exit(f"no udp-binding peer for {target}")
    hdr = Header(NH_DGRAM, src=me, dst=target)
    pkt = build_dgram(hdr, args.sport, args.dport, args.message.encode())
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(pkt, peers[target])
    print(f"[r8ref] dgram {me} -> {target} ({len(pkt)} bytes on wire)")


def selftest():
    assert str(parse_loc("8:1::10")) == "8:1::10"

    h = Header(NH_CTL, src=parse_loc("8:1::10"), dst=parse_loc("8:1::20"),
               scid=0x1122334455667788, hop=64)
    raw = h.pack(b"hello")
    assert len(raw) == HEADER_LEN + 5
    h2, pl = Header.unpack(raw)
    assert pl == b"hello" and h2.scid == h.scid and h2.src == h.src and h2.hop == 64

    body = struct.pack("!HH", 7, 42)
    pkt = build_ctl(h, CTL_ECHO_REQUEST, 0, body)
    h3, p3 = Header.unpack(pkt)
    t, c, _s, b3, ok = parse_ctl(h3, p3)
    assert ok and t == CTL_ECHO_REQUEST and b3 == body
    bad = bytearray(pkt)
    bad[-1] ^= 0xFF
    hb, pb = Header.unpack(bytes(bad))
    assert not parse_ctl(hb, pb)[4]

    dpkt = build_dgram(h, 1000, 9000, b"ping")
    hd, pd = Header.unpack(dpkt)
    sp, dp, data, ok = parse_dgram(hd, pd)
    assert ok and (sp, dp, data) == (1000, 9000, b"ping")

    # loopback echo
    me, you = parse_loc("8:1::10"), parse_loc("8:1::20")
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    stop = threading.Event()
    th = threading.Thread(target=run_echo_server, args=(srv, me, stop), daemon=True)
    th.start()
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.settimeout(2.0)
    ch = Header(NH_CTL, src=you, dst=me)
    ebody = struct.pack("!HH", 1, 1)
    cli.sendto(build_ctl(ch, CTL_ECHO_REQUEST, 0, ebody), ("127.0.0.1", port))
    data, _ = cli.recvfrom(65535)
    stop.set()
    rh, rp = Header.unpack(data)
    t, _c, _s, rb, ok = parse_ctl(rh, rp)
    assert ok and t == CTL_ECHO_REPLY and rb == ebody and rh.src == me and rh.dst == you

    print("selftest OK: addr/header/ctl/dgram/loopback-echo")


def main():
    p = argparse.ArgumentParser(prog="r8ref", description="R8 reference implementation (udp-binding)")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("listen", "ping", "send"):
        sp = sub.add_parser(name)
        sp.add_argument("--address", required=True, help="my R8 locator, e.g. 8:1::10")
        sp.add_argument("--peer", action="append", help="loc=host:port (repeatable)")
        if name == "listen":
            sp.add_argument("--bind", default="0.0.0.0")
            sp.add_argument("--port", type=int, default=R8_UDP_PORT)
            sp.set_defaults(fn=cmd_listen)
        elif name == "ping":
            sp.add_argument("loc")
            sp.add_argument("--bind", default="0.0.0.0")
            sp.add_argument("--count", type=int, default=4)
            sp.add_argument("--timeout", type=float, default=1.0)
            sp.add_argument("--interval", type=float, default=0.2)
            sp.set_defaults(fn=cmd_ping)
        else:
            sp.add_argument("loc")
            sp.add_argument("message")
            sp.add_argument("--sport", type=int, default=1000)
            sp.add_argument("--dport", type=int, default=9000)
            sp.set_defaults(fn=cmd_send)
    sub.add_parser("selftest").set_defaults(fn=lambda a: selftest())
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
