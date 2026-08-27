import pathlib
import socket
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import r8sdk


class SdkTests(unittest.TestCase):
    def test_dgram_codec_round_trip(self):
        codec = r8sdk.DgramCodec("8:1::10", "8:2::20", 12000, 13000)
        packet = codec.encode(b"hello")
        reverse = r8sdk.DgramCodec("8:2::20", "8:1::10", 13000, 12000)
        self.assertEqual(reverse.decode(packet), b"hello")

    def test_udp_client_sends_encoded_packet(self):
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(1)
        client = r8sdk.UdpClient(
            local_loc="8:1::10", peer_loc="8:2::20",
            peer_endpoint=receiver.getsockname(), sport=12000, dport=13000,
        )
        try:
            client.send(b"hello")
            packet, _ = receiver.recvfrom(1281)
            reverse = r8sdk.DgramCodec("8:2::20", "8:1::10", 13000, 12000)
            self.assertEqual(reverse.decode(packet), b"hello")
        finally:
            client.close()
            receiver.close()

    def test_three_examples_exist(self):
        examples = ROOT / "examples"
        for name in ("encode_dgram.py", "decode_dgram.py", "loopback_client.py"):
            self.assertTrue((examples / name).is_file(), name)
