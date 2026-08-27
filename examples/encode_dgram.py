#!/usr/bin/env python3
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "reference"))
from r8sdk import DgramCodec

codec = DgramCodec("8:1::10", "8:2::20", 12000, 13000)
print(codec.encode(b"hello from R8 SDK").hex())
