import unittest
from bench.compare import netns


class TestCompareNetns(unittest.TestCase):
    def test_topology_names_are_seed_scoped_and_deterministic(self):
        topo = netns.CompareTopology(seed=42)
        self.assertEqual(topo.client_ns, "r8cmp-42-cli")
        self.assertEqual(topo.server_ns, "r8cmp-42-srv")
        self.assertEqual(topo.router_a_ns, "r8cmp-42-ra")
        self.assertEqual(topo.router_b_ns, "r8cmp-42-rb")
        self.assertEqual(
            topo.namespaces,
            ["r8cmp-42-cli", "r8cmp-42-srv", "r8cmp-42-ra", "r8cmp-42-rb"],
        )

    def test_seed_must_fit_namespace_name_budget(self):
        with self.assertRaisesRegex(ValueError, "seed"):
            netns.CompareTopology(seed=-1)
        with self.assertRaisesRegex(ValueError, "seed"):
            netns.CompareTopology(seed=1_000_000)

    def test_cut_primary_does_not_fabricate_observations(self):
        topo = netns.CompareTopology(seed=1)
        cut = topo.cut_primary()
        self.assertFalse(cut["observed"])
        self.assertEqual(cut["packets"], [])

    def test_setup_failure_deletes_already_created_namespaces(self):
        import subprocess
        from unittest import mock

        topo = netns.CompareTopology(seed=7)
        created = []
        deleted = []

        def fake_run(cmd, **kwargs):
            if cmd[:3] == ["ip", "netns", "add"]:
                ns = cmd[3]
                if ns.endswith("-ra"):
                    raise subprocess.CalledProcessError(1, cmd)
                created.append(ns)
                return mock.Mock(returncode=0, stdout="", stderr="")
            if cmd[:3] == ["ip", "netns", "del"]:
                deleted.append(cmd[3])
                return mock.Mock(returncode=0, stdout="", stderr="")
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(netns.subprocess, "run", side_effect=fake_run):
            with self.assertRaises(subprocess.CalledProcessError):
                topo.setup()
        self.assertEqual(created, ["r8cmp-7-cli", "r8cmp-7-srv"])
        self.assertEqual(deleted, ["r8cmp-7-srv", "r8cmp-7-cli"])
        self.assertFalse(topo._ready)

    def test_setup_configures_namespace_local_routes_forwarding_and_mptcp(self):
        from unittest import mock

        topo = netns.CompareTopology(seed=3)
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(tuple(cmd))
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(netns.subprocess, "run", side_effect=fake_run):
            topo.setup()
            topo.cleanup()

        self.assertIn(
            ("ip", "netns", "exec", "r8cmp-3-ra", "sysctl", "-w", "net.ipv4.ip_forward=1"),
            calls,
        )
        self.assertIn(
            ("ip", "netns", "exec", "r8cmp-3-rb", "sysctl", "-w", "net.ipv4.ip_forward=1"),
            calls,
        )
        self.assertEqual([c for c in calls if c and c[0] == "sysctl"], [])
        self.assertFalse(any("sysctl" in c and c[:3] != ("ip", "netns", "exec") for c in calls))

        self.assertIn(
            ("ip", "netns", "exec", "r8cmp-3-cli", "ip", "route", "add", "10.8.2.0/24", "via", "10.8.1.1", "dev", "v-ca"),
            calls,
        )
        self.assertIn(
            ("ip", "netns", "exec", "r8cmp-3-cli", "ip", "route", "add", "10.8.4.0/24", "via", "10.8.3.1", "dev", "v-cb"),
            calls,
        )
        self.assertIn(
            ("ip", "netns", "exec", "r8cmp-3-srv", "ip", "route", "add", "10.8.1.0/24", "via", "10.8.2.1", "dev", "v-sa"),
            calls,
        )
        self.assertIn(
            ("ip", "netns", "exec", "r8cmp-3-srv", "ip", "route", "add", "10.8.3.0/24", "via", "10.8.4.1", "dev", "v-sb"),
            calls,
        )
        self.assertIn(
            ("ip", "netns", "exec", "r8cmp-3-cli", "ip", "mptcp", "endpoint", "add", "10.8.3.10", "dev", "v-cb", "subflow"),
            calls,
        )
        self.assertTrue(any("mptcp" in c and "limits" in c for c in calls))

    def test_cut_primary_reports_observed_state_not_hardcoded_zeros(self):
        import json
        from unittest import mock

        topo = netns.CompareTopology(seed=1)
        topo._ready = True

        def fake_run(cmd, **kwargs):
            if cmd[:6] == ("ip", "netns", "exec", "r8cmp-1-cli", "ip", "link") and "down" in cmd:
                return mock.Mock(returncode=0, stdout="", stderr="")
            if "-j" in cmd and "-s" in cmd and "link" in cmd:
                payload = [
                    {
                        "ifname": "v-ca",
                        "stats64": {"tx": {"bytes": 128}, "rx": {"bytes": 64}},
                    },
                    {
                        "ifname": "v-cb",
                        "stats64": {"tx": {"bytes": 256}, "rx": {"bytes": 32}},
                    },
                ]
                return mock.Mock(returncode=0, stdout=json.dumps(payload), stderr="")
            if "ss" in cmd:
                return mock.Mock(returncode=0, stdout="Netid State Recv-Q Send-Q\n[0:0] tcp-mptcp 0 0\n[1:0] tcp-mptcp 0 0\n", stderr="")
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(netns.subprocess, "run", side_effect=fake_run):
            cut = topo.cut_primary()
        self.assertTrue(cut["observed"])
        self.assertEqual(cut["subflows"], 2)
        self.assertEqual(cut["path_bytes"]["primary"], 192)
        self.assertEqual(cut["path_bytes"]["secondary"], 288)
        self.assertEqual(cut["packets"], [])
