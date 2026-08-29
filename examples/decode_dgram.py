#!/usr/bin/env python3
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "reference"))
from r8sdk import DgramCodec

sender = DgramCodec("8:1::10", "8:2::20", 12000, 13000)
receiver = DgramCodec("8:2::20", "8:1::10", 13000, 12000)
print(receiver.decode(sender.encode(b"hello from R8 SDK")).decode())
