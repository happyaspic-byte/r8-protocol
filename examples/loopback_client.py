#!/usr/bin/env python3
import pathlib, socket, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "reference"))
from r8sdk import DgramCodec, UdpClient

receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receiver.bind(("127.0.0.1", 0))
client = UdpClient("8:1::10", "8:2::20", receiver.getsockname(), 12000, 13000)
try:
    client.send(b"hello from R8 SDK")
    packet, _ = receiver.recvfrom(1281)
    codec = DgramCodec("8:2::20", "8:1::10", 13000, 12000)
    print(codec.decode(packet).decode())
finally:
    client.close()
    receiver.close()
