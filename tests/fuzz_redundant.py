#!/usr/bin/env python3
"""Bounded malformed-input exerciser for the Profile-3 DATA codec."""
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import r8session as s


def run(iterations=4096):
    session = s.Session(b"f" * 32)
    for _ in range(iterations):
        size = int.from_bytes(os.urandom(2), "big") % 1282
        if not 0 <= size <= 1281:
            raise AssertionError("fuzz packet size escaped bound")
        try:
            s.preview_profile3_data(session, os.urandom(size))
        except s.SessionError as error:
            if error.category not in s.ERRORS:
                raise AssertionError("non-finite session error")
        if session._previews:
            raise AssertionError("malformed packet left a preview")
        if (session.replay.highest != 0 or session.replay.bits != 0
                or session.replay.generation != 0):
            raise AssertionError("malformed packet changed replay state")
        if session.send_counter != 1:
            raise AssertionError("receive fuzzing changed send counter")


if __name__ == "__main__":
    run()
