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
