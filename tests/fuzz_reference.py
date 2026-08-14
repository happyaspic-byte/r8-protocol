"""Deterministic parser fuzz-smoke for the strict Python R8 reference.

Run directly with Python; it deliberately has no external fuzzing dependency.
"""
import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import r8ref  # noqa: E402


def _valid_packet():
    header = r8ref.Header(r8ref.NH_DGRAM, r8ref.parse_loc("8:1::1"), r8ref.parse_loc("8:1::2"))
    return r8ref.build_dgram(header, 1, 2, b"fuzz")


def run(seed=0x52385632, samples=4096):
    rng = random.Random(seed)
    valid = _valid_packet()
    corpus = [valid]
    # Include every receive length through the serialized cap and one byte beyond it.
    corpus.extend(rng.randbytes(length) for length in range(1282))
    for _ in range(samples):
        source = bytearray(rng.choice(corpus))
        if source:
            source[rng.randrange(len(source))] ^= 1 << rng.randrange(8)
        else:
            source.append(rng.randrange(256))
        corpus.append(bytes(source))
    for index, packet in enumerate(corpus):
        try:
            header, payload = r8ref.Header.unpack(packet)
            # Successful parses are canonical bounded packets, never attacker-sized allocations.
            assert len(packet) <= r8ref.SERIALIZED_MAX
            assert len(payload) <= r8ref.SERIALIZED_MAX - r8ref.HEADER_LEN
            assert header.pack(payload) == packet
        except r8ref.WireError as error:
            assert error.category in r8ref.ERROR_CATEGORIES
        except Exception as error:
            raise AssertionError(f"uncategorized parser exception at sample {index}: {error!r}") from error
    # Every one-bit corruption either remains a defined valid packet or gets a finite wire error.
    for offset in range(len(valid)):
        corrupted = bytearray(valid)
        corrupted[offset] ^= 1
        try:
            header, payload = r8ref.Header.unpack(bytes(corrupted))
            assert header.pack(payload) == bytes(corrupted)
        except r8ref.WireError as error:
            assert error.category in r8ref.ERROR_CATEGORIES


if __name__ == "__main__":
    run()
    print("reference fuzz smoke OK")
