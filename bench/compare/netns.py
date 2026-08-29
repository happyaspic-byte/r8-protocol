"""Isolated network-namespace topology lifecycle for external comparisons."""
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


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
        self._ready = False
        self._created_namespaces = []

    def _ip(self, *args, netns=None):
        cmd = ["ip"]
        if netns:
            cmd.extend(["netns", "exec", netns, "ip"])
        cmd.extend(args)
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"ip failed: {cmd} -> {res.stderr.strip()}")
        return res.stdout

    def _sysctl_in_ns(self, netns, setting):
        res = subprocess.run(
            ["ip", "netns", "exec", netns, "sysctl", "-w", setting],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            raise RuntimeError(f"sysctl failed: {netns} {setting} -> {res.stderr.strip()}")
        return res.stdout

    def setup(self):
        self.temp_dir = tempfile.mkdtemp(prefix=f"{self.prefix}-")
        try:
            for ns in self.namespaces:
                subprocess.run(["ip", "netns", "add", ns], check=True, capture_output=True)
                self._created_namespaces.append(ns)
                self._ip("link", "set", "lo", "up", netns=ns)

            self._ip("link", "add", "v-ca", "type", "veth", "peer", "name", "v-ac")
            self._ip("link", "add", "v-as", "type", "veth", "peer", "name", "v-sa")
            self._ip("link", "add", "v-cb", "type", "veth", "peer", "name", "v-bc")
            self._ip("link", "add", "v-bs", "type", "veth", "peer", "name", "v-sb")

            self._ip("link", "set", "v-ca", "netns", self.client_ns)
            self._ip("link", "set", "v-ac", "netns", self.router_a_ns)
            self._ip("link", "set", "v-as", "netns", self.router_a_ns)
            self._ip("link", "set", "v-sa", "netns", self.server_ns)

            self._ip("link", "set", "v-cb", "netns", self.client_ns)
            self._ip("link", "set", "v-bc", "netns", self.router_b_ns)
            self._ip("link", "set", "v-bs", "netns", self.router_b_ns)
            self._ip("link", "set", "v-sb", "netns", self.server_ns)

            self._ip("addr", "add", "10.8.1.10/24", "dev", "v-ca", netns=self.client_ns)
            self._ip("addr", "add", "10.8.1.1/24", "dev", "v-ac", netns=self.router_a_ns)
            self._ip("addr", "add", "10.8.2.1/24", "dev", "v-as", netns=self.router_a_ns)
            self._ip("addr", "add", "10.8.2.20/24", "dev", "v-sa", netns=self.server_ns)

            self._ip("addr", "add", "10.8.3.10/24", "dev", "v-cb", netns=self.client_ns)
            self._ip("addr", "add", "10.8.3.1/24", "dev", "v-bc", netns=self.router_b_ns)
            self._ip("addr", "add", "10.8.4.1/24", "dev", "v-bs", netns=self.router_b_ns)
            self._ip("addr", "add", "10.8.4.20/24", "dev", "v-sb", netns=self.server_ns)

            for dev in ("v-ca", "v-cb"):
                self._ip("link", "set", dev, "up", netns=self.client_ns)
            for dev in ("v-ac", "v-as"):
                self._ip("link", "set", dev, "up", netns=self.router_a_ns)
            for dev in ("v-bc", "v-bs"):
                self._ip("link", "set", dev, "up", netns=self.router_b_ns)
            for dev in ("v-sa", "v-sb"):
                self._ip("link", "set", dev, "up", netns=self.server_ns)

            for router_ns in (self.router_a_ns, self.router_b_ns):
                self._sysctl_in_ns(router_ns, "net.ipv4.ip_forward=1")

            for ns, ifaces in (
                (self.client_ns, ("v-ca", "v-cb")),
                (self.server_ns, ("v-sa", "v-sb")),
                (self.router_a_ns, ("v-ac", "v-as")),
                (self.router_b_ns, ("v-bc", "v-bs")),
            ):
                for scope in ("all", "default") + ifaces:
                    self._sysctl_in_ns(ns, f"net.ipv4.conf.{scope}.rp_filter=0")

            self._ip("route", "add", "10.8.2.0/24", "via", "10.8.1.1", "dev", "v-ca", netns=self.client_ns)
            self._ip("route", "add", "10.8.4.0/24", "via", "10.8.3.1", "dev", "v-cb", netns=self.client_ns)
            self._ip("route", "add", "10.8.1.0/24", "via", "10.8.2.1", "dev", "v-sa", netns=self.server_ns)
            self._ip("route", "add", "10.8.3.0/24", "via", "10.8.4.1", "dev", "v-sb", netns=self.server_ns)

            try:
                self._sysctl_in_ns(self.client_ns, "net.mptcp.enabled=1")
                self._sysctl_in_ns(self.server_ns, "net.mptcp.enabled=1")
                self._ip("mptcp", "endpoint", "add", "10.8.3.10", "dev", "v-cb", "subflow", netns=self.client_ns)
                self._ip("mptcp", "limits", "set", "subflows", "2", "add_addr_accepted", "2", netns=self.client_ns)
                self._ip("mptcp", "endpoint", "add", "10.8.4.20", "dev", "v-sb", "subflow", netns=self.server_ns)
                self._ip("mptcp", "limits", "set", "subflows", "2", "add_addr_accepted", "2", netns=self.server_ns)
            except RuntimeError:
                pass
        except Exception:
            self.cleanup()
            raise

        self._ready = True
        return {
            "seed": self.seed,
            "namespaces": list(self.namespaces),
            "temp_dir": self.temp_dir,
        }

    def cut_primary(self):
        event_ns = time.monotonic_ns()
        if not self._ready:
            return {
                "observed": False,
                "event_ns": event_ns,
                "control_bytes": 0,
                "subflows": 0,
                "path_bytes": {},
                "packets": [],
            }
        try:
            self._ip("link", "set", "v-ca", "down", netns=self.client_ns)
            observed = True
        except Exception:
            observed = False
        if not observed:
            return {
                "observed": False,
                "event_ns": event_ns,
                "control_bytes": 0,
                "subflows": 0,
                "path_bytes": {},
                "packets": [],
            }
        path_bytes = {}
        try:
            for iface in json.loads(self._ip("-j", "-s", "link", netns=self.client_ns)):
                stats64 = iface.get("stats64") or {}
                tx = (stats64.get("tx") or {}).get("bytes") or 0
                rx = (stats64.get("rx") or {}).get("bytes") or 0
                if iface.get("ifname") == "v-ca":
                    path_bytes["primary"] = tx + rx
                elif iface.get("ifname") == "v-cb":
                    path_bytes["secondary"] = tx + rx
        except Exception:
            path_bytes = {}
        subflows = 0
        try:
            shown = subprocess.run(
                ["ip", "netns", "exec", self.client_ns, "ss", "-Mn"],
                capture_output=True,
                text=True,
            )
            if shown.returncode == 0:
                subflows = sum(1 for line in shown.stdout.splitlines() if "tcp-mptcp" in line)
        except Exception:
            subflows = 0
        return {
            "observed": True,
            "event_ns": event_ns,
            "control_bytes": 0,
            "subflows": subflows,
            "path_bytes": path_bytes,
            "packets": [],
        }

    def cleanup(self):
        failures = 0
        self._ready = False
        for ns in reversed(self._created_namespaces):
            res = subprocess.run(["ip", "netns", "del", ns], capture_output=True)
            if res.returncode != 0:
                failures += 1
        self._created_namespaces = []
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = None
        return failures == 0
