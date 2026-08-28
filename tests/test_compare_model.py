import unittest
from bench.compare import model


class TestCompareModel(unittest.TestCase):
    def test_canonical_json_is_sorted_and_compact(self):
        data = {"b": 2, "a": 1}
        self.assertEqual(model.canonical_json(data), '{"a":1,"b":2}')

    def test_plan_rows_have_exact_mechanisms_and_blocks(self):
        rows = list(model.plan_rows())
        self.assertEqual(len(rows), 550)
        mechanisms = {row["mechanism"] for row in rows}
        self.assertEqual(
            mechanisms,
            {"r8-mobility", "quic-migration", "lisp-xtr", "r8-redundant", "linux-mptcp"},
        )
        self.assertEqual(model.validate_plan_invariants(rows), [])
