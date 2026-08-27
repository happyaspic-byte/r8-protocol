"""Small public SDK for strict R8 DGRAM applications."""
import ipaddress
import socket

import r8ref


class DgramCodec:
    def __init__(self, local_loc, peer_loc, sport, dport, binding_budget=1280):
        self.local_loc = ipaddress.IPv6Address(local_loc)
        self.peer_loc = ipaddress.IPv6Address(peer_loc)
        if not 1 <= sport <= 65535 or not 1 <= dport <= 65535:
            raise ValueError("invalid DGRAM port")
        if not 56 <= binding_budget <= 1280:
            raise ValueError("invalid binding budget")
        self.sport = sport
        self.dport = dport
        self.binding_budget = binding_budget

    def encode(self, payload):
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        header = r8ref.Header(r8ref.NH_DGRAM, self.local_loc, self.peer_loc)
        return r8ref.build_dgram(
            header, self.sport, self.dport, payload, self.binding_budget
        )

    def decode(self, packet):
        header, payload = r8ref.Header.unpack(packet, self.binding_budget)
        if header.src != self.peer_loc or header.dst != self.local_loc:
            raise ValueError("packet LOCs do not match codec peers")
        sport, dport, data = r8ref.parse_dgram(header, payload)
        if sport != self.dport or dport != self.sport:
            raise ValueError("packet ports do not match codec peers")
        return data


class UdpClient:
    def __init__(self, local_loc, peer_loc, peer_endpoint, sport, dport, binding_budget=1280):
        host, port = peer_endpoint
        address = ipaddress.ip_address(host)
        if not address.is_loopback:
            raise ValueError("SDK client defaults to loopback underlay only")
        self.codec = DgramCodec(local_loc, peer_loc, sport, dport, binding_budget)
        self.peer_endpoint = str(address), int(port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))

    def send(self, payload):
        packet = self.codec.encode(payload)
        sent = self.socket.sendto(packet, self.peer_endpoint)
        if sent != len(packet):
            raise OSError("short UDP send")
        return len(payload)

    def close(self):
        self.socket.close()
