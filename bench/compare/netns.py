"""Isolated network-namespace topology lifecycle for external comparisons."""
import os
import shutil
import subprocess
import tempfile


class CompareTopology:
    def __init__(self, seed: int):
        if not isinstance(seed, int) or not 0 <= seed <= 99_999:
            raise ValueError(f"seed {seed} is out of bounds (0..99999)")
        self.seed = seed
        self.prefix = f"r8cmp-{seed}"
        self.client_ns = f"{self.prefix}-cli"
        self.server_ns = f"{self.prefix}-srv"
        self.router_a_ns = f"{self.prefix}-ra"
        self.router_b_ns = f"{self.prefix}-rb"
        self.namespaces = [
            self.client_ns,
            self.server_ns,
            self.router_a_ns,
            self.router_b_ns,
        ]
        self.temp_dir = None

    def setup(self):
        self.temp_dir = tempfile.mkdtemp(prefix=f"{self.prefix}-")
        for ns in self.namespaces:
            subprocess.run(
                ["ip", "netns", "add", ns], check=True, capture_output=True
            )
        return {
            "seed": self.seed,
            "namespaces": list(self.namespaces),
            "temp_dir": self.temp_dir,
        }

    def cleanup(self):
        failures = 0
        for ns in reversed(self.namespaces):
            res = subprocess.run(
                ["ip", "netns", "del", ns], capture_output=True
            )
            if res.returncode != 0:
                failures += 1
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = None
        return failures == 0
