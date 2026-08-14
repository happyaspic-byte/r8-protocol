"""Execute shared wire vectors through the public R8 Wireshark dissector."""

import json
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LUA = ROOT / "tools" / "wireshark" / "r8.lua"
VECTORS = ROOT / "tests" / "vectors" / "wire-v0.2.json"
TSHARK_VERSION = "TShark (Wireshark) 4.6.4"
CARRIERS = ("udp4", "udp6", "native")


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(int.from_bytes(data[index : index + 2], "big") for index in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def udp(payload: bytes, source: bytes, destination: bytes) -> bytes:
    length = 8 + len(payload)
    bare = struct.pack("!HHHH", 52808, 52808, length, 0) + payload
    if len(source) == 16:
        pseudo = source + destination + struct.pack("!I", length) + b"\0\0\0" + bytes((17,))
    else:
        pseudo = source + destination + bytes((0, 17)) + struct.pack("!H", length)
    return struct.pack("!HHHH", 52808, 52808, length, internet_checksum(pseudo + bare) or 0xFFFF) + payload


def udp4_frame(payload: bytes) -> bytes:
    source, destination = bytes((192, 0, 2, 1)), bytes((192, 0, 2, 2))
    segment = udp(payload, source, destination)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0, 0, 64, 17, 0, source, destination)
    header = header[:10] + struct.pack("!H", internet_checksum(header)) + header[12:]
    return bytes.fromhex("0200000000020200000000010800") + header + segment


def udp6_frame(payload: bytes) -> bytes:
    source = bytes.fromhex("20010db8000000000000000000000001")
    destination = bytes.fromhex("20010db8000000000000000000000002")
    segment = udp(payload, source, destination)
    header = struct.pack("!IHBB16s16s", 6 << 28, len(segment), 17, 64, source, destination)
    return bytes.fromhex("02000000000202000000000186dd") + header + segment


def native_frame(payload: bytes) -> bytes:
    return bytes.fromhex("02000000000202000000000188b5") + payload


def pcap(frame: bytes) -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    return header + struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame


def carrier_frame(carrier: str, payload: bytes) -> bytes:
    return {"udp4": udp4_frame, "udp6": udp6_frame, "native": native_frame}[carrier](payload)


def binding_outcome(case: dict, carrier: str) -> str | None:
    if case.get("kind") != "binding-boundary":
        return None
    length = len(bytes.fromhex(case["packet_hex"]))
    limit = {"udp4": 1252, "udp6": 1232, "native": 1280}[carrier]
    return "accept" if length <= limit else "BINDING_BUDGET"


class TsharkCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(VECTORS.read_text(encoding="utf-8"))
        required = os.environ.get("R8_REQUIRE_TSHARK") == "1"
        cls.tshark = shutil.which("tshark")
        if not cls.tshark:
            if required:
                raise AssertionError("R8_REQUIRE_TSHARK=1 but tshark is unavailable")
            raise unittest.SkipTest(json.dumps({"status": "skipped", "reason": "tshark unavailable"}))
        version = subprocess.run([cls.tshark, "--version"], check=True, capture_output=True, text=True).stdout
        if TSHARK_VERSION not in version:
            if required:
                raise AssertionError(f"R8_REQUIRE_TSHARK=1 requires {TSHARK_VERSION}; got {version.splitlines()[0]!r}")
            raise unittest.SkipTest(json.dumps({"status": "skipped", "reason": "tshark version mismatch", "found": version.splitlines()[0]}))

    def run_vector(self, capture: Path) -> list[str]:
        result = subprocess.run(
            [self.tshark, "-n", "-o", "udp.check_checksum:TRUE", "-X", f"lua_script:{LUA}", "-r", str(capture), "-T", "fields", "-E", "occurrence=f", "-E", "separator=\t", "-e", "r8.version", "-e", "r8.nh", "-e", "r8.ctl.type", "-e", "r8.dgram.length", "-e", "r8.ses.type", "-e", "r8.error", "-e", "udp.checksum.status"],
            check=True, capture_output=True, text=True,
        )
        return result.stdout.rstrip("\n").split("\t") if result.stdout else []

    def assert_accept(self, payload: bytes, fields: list[str], carrier: str) -> None:
        self.assertEqual(len(fields), 7, fields)
        self.assertEqual(fields[0], "8", fields)
        self.assertEqual(fields[1], str(payload[4]), fields)
        self.assertEqual(fields[5], "", fields)
        if carrier == "udp6":
            self.assertEqual(fields[6], "1", fields)
        if payload[4] == 1:
            self.assertEqual(fields[2], str(payload[48]), fields)
        elif payload[4] == 2:
            self.assertEqual(fields[3], str(int.from_bytes(payload[52:54], "big")), fields)
        elif payload[4] == 3:
            self.assertEqual(fields[4], str(payload[48]), fields)

    def test_shared_corpus_on_all_carriers(self):
        cases = self.corpus["positive_cases"] + self.corpus["negative_cases"] + self.corpus["binding_boundary_cases"]
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            for case in cases:
                payload = bytes.fromhex(case["packet_hex"])
                for carrier in CARRIERS:
                    with self.subTest(case=case["id"], carrier=carrier):
                        capture = temporary / f"{case['id']}-{carrier}.pcap"
                        capture.write_bytes(pcap(carrier_frame(carrier, payload)))
                        fields = self.run_vector(capture)
                        outcome = binding_outcome(case, carrier)
                        if outcome == "accept" or (outcome is None and case["expectation"] in ("accept", "outer-envelope-accept")):
                            self.assert_accept(payload, fields, carrier)
                        elif not case["packet_hex"] and carrier.startswith("udp") and len(fields) == 7 and all(field == "" for field in fields[:6]):
                            self.assertEqual(case["expected_error"], "TRUNCATED")
                            self.assertTrue(all(field == "" for field in fields[:6]), "zero-byte UDP payload must not decode R8 fields")
                        else:
                            self.assertEqual(len(fields), 7, fields)
                            carrier_errors = case.get("carrier_expectations", {})
                            if carrier in carrier_errors:
                                expected = carrier_errors[carrier]
                            elif outcome is not None:
                                expected = outcome
                            else:
                                expected = case["expected_error"]
                            self.assertEqual(fields[5], expected, fields)

    def test_computed_zero_checksum_vectors_are_accepted(self):
        cases = {case["id"]: case for case in self.corpus["positive_cases"]}
        for case_id in self.corpus["checksum_method"]["computed_zero_cases"]:
            payload = bytes.fromhex(cases[case_id]["packet_hex"])
            for carrier in CARRIERS:
                with self.subTest(case=case_id, carrier=carrier), tempfile.TemporaryDirectory() as directory:
                    capture = Path(directory) / "computed-zero.pcap"
                    capture.write_bytes(pcap(carrier_frame(carrier, payload)))
                    self.assert_accept(payload, self.run_vector(capture), carrier)


if __name__ == "__main__":
    unittest.main()
