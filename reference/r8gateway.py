#!/usr/bin/env python3
"""Bounded UDP-to-R8 DGRAM compatibility gateway for isolated labs."""
import argparse
from dataclasses import dataclass
import ipaddress
import selectors
import socket

import r8ref


@dataclass(frozen=True)
class GatewayConfig:
    local_loc: str
    peer_loc: str
    sport: int
    dport: int
    binding_budget: int = 1252

    def __post_init__(self):
        ipaddress.IPv6Address(self.local_loc)
        ipaddress.IPv6Address(self.peer_loc)
        if not 1 <= self.sport <= 65535 or not 1 <= self.dport <= 65535:
            raise ValueError("invalid gateway port")
        if not 56 <= self.binding_budget <= 1280:
            raise ValueError("invalid binding budget")


def validate_underlay(host: str, allow_isolated: bool):
    address = ipaddress.ip_address(host)
    if address.is_loopback:
        return str(address)
    if allow_isolated and (address.is_private or address.is_link_local):
        return str(address)
    if address.is_private or address.is_link_local:
        raise ValueError("isolated underlay requires explicit authorization")
    raise ValueError("public underlay is rejected")


def encapsulate(config: GatewayConfig, payload: bytes):
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if len(payload) > config.binding_budget - 56:
        raise ValueError("payload budget exceeded")
    header = r8ref.Header(r8ref.NH_DGRAM, config.local_loc, config.peer_loc)
    return r8ref.build_dgram(
        header, config.sport, config.dport, payload, config.binding_budget
    )


def decapsulate(config: GatewayConfig, packet: bytes):
    header, payload = r8ref.Header.unpack(packet, config.binding_budget)
    if header.src != ipaddress.IPv6Address(config.peer_loc):
        raise ValueError("unexpected source LOC")
    if header.dst != ipaddress.IPv6Address(config.local_loc):
        raise ValueError("unexpected destination LOC")
    return r8ref.parse_dgram(header, payload)


def forward_once(legacy_socket, r8_socket, r8_peer, config: GatewayConfig):
    payload, _ = legacy_socket.recvfrom(config.binding_budget - 55)
    packet = encapsulate(config, payload)
    sent = r8_socket.sendto(packet, r8_peer)
    if sent != len(packet):
        raise OSError("short R8 datagram send")
    return len(payload)


def deliver_once(r8_socket, legacy_socket, legacy_peer, config: GatewayConfig):
    packet, _ = r8_socket.recvfrom(config.binding_budget + 1)
    if len(packet) > config.binding_budget:
        raise ValueError("R8 packet exceeds binding budget")
    _, _, payload = decapsulate(config, packet)
    sent = legacy_socket.sendto(payload, legacy_peer)
    if sent != len(payload):
        raise OSError("short legacy UDP send")
    return len(payload)


def _endpoint(text, allow_isolated=False):
    host, port_text = text.rsplit(":", 1)
    host = validate_underlay(host, allow_isolated)
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("invalid UDP endpoint port")
    return host, port


def bridge(args):
    legacy_bind = _endpoint(args.legacy_bind)
    r8_bind = _endpoint(args.r8_bind, args.allow_isolated_underlay)
    r8_peer = _endpoint(args.r8_peer, args.allow_isolated_underlay)
    legacy_peer = _endpoint(args.legacy_peer)
    config = GatewayConfig(
        args.local_loc, args.peer_loc, args.sport, args.dport, args.binding_budget
    )
    legacy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    r8_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    legacy_socket.bind(legacy_bind)
    r8_socket.bind(r8_bind)
    selected = selectors.DefaultSelector()
    selected.register(legacy_socket, selectors.EVENT_READ, "legacy")
    selected.register(r8_socket, selectors.EVENT_READ, "r8")
    try:
        while True:
            for event, _ in selected.select():
                if event.data == "legacy":
                    forward_once(legacy_socket, r8_socket, r8_peer, config)
                else:
                    deliver_once(r8_socket, legacy_socket, legacy_peer, config)
    finally:
        selected.close()
        legacy_socket.close()
        r8_socket.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="R8 isolated-lab UDP compatibility gateway")
    parser.add_argument("--legacy-bind", required=True)
    parser.add_argument("--legacy-peer", required=True)
    parser.add_argument("--r8-bind", required=True)
    parser.add_argument("--r8-peer", required=True)
    parser.add_argument("--local-loc", required=True)
    parser.add_argument("--peer-loc", required=True)
    parser.add_argument("--sport", type=int, required=True)
    parser.add_argument("--dport", type=int, required=True)
    parser.add_argument("--binding-budget", type=int, default=1252)
    parser.add_argument("--allow-isolated-underlay", action="store_true")
    bridge(parser.parse_args(argv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
