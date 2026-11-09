"""Regression tests for exact OSV range boundaries and conservative fallback."""
import unittest
from test_patchgate import Harness, VM, ADVISORY

RANGE = {"type": "SEMVER",
         "events": [{"introduced": "0"}, {"fixed": "4.17.12"}]}


class OsvBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.h.advisory(ranges=[RANGE])

    def evaluate(self, version):
        idx = self.h.open(version)
        decision = self.h.gate.evaluate_release(idx)
        return decision, self.h.gate.get_release(idx)

    def test_exact_fixed_version_is_not_affected(self):
        decision, raw = self.evaluate("4.17.12")
        self.assertEqual(decision, "ALLOW")
        self.assertIn('"status":"NOT_AFFECTED"', raw)
        self.assertEqual(self.h.prompts, [])

    def test_one_version_below_is_affected(self):
        decision, raw = self.evaluate("4.17.11")
        self.assertEqual(decision, "BLOCK")
        self.assertIn('"status":"AFFECTED"', raw)

    def test_numeric_version_order_not_lexical(self):
        self.assertEqual(self.evaluate("4.17.9")[0], "BLOCK")
        self.assertEqual(self.evaluate("4.17.20")[0], "ALLOW")

    def test_fixed_boundary_is_exclusive(self):
        result = self.h.mod.simple_npm_osv_range(RANGE, "4.17.12")
        self.assertEqual(result, "NOT_AFFECTED")

    def test_last_affected_boundary_is_inclusive(self):
        rng = {"type": "SEMVER",
               "events": [{"introduced": "1.0.0"},
                          {"last_affected": "2.0.0"}]}
        self.assertEqual(self.h.mod.simple_npm_osv_range(rng, "2.0.0"), "AFFECTED")
        self.assertEqual(self.h.mod.simple_npm_osv_range(rng, "2.0.1"), "NOT_AFFECTED")
        self.assertEqual(self.h.mod.simple_npm_osv_range(rng, "0.9.9"), "NOT_AFFECTED")

    def test_limit_is_exclusive(self):
        rng = {"type": "SEMVER",
               "events": [{"introduced": "1.0.0"}, {"limit": "2.0.0"}]}
        self.assertEqual(self.h.mod.simple_npm_osv_range(rng, "1.9.9"), "AFFECTED")
        self.assertEqual(self.h.mod.simple_npm_osv_range(rng, "2.0.0"), "NOT_AFFECTED")

    def test_multiple_intervals(self):
        rng = {"type": "SEMVER",
               "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"},
                          {"introduced": "3.0.0"}, {"fixed": "4.0.0"}]}
        m = self.h.mod.simple_npm_osv_range
        self.assertEqual(m(rng, "1.5.0"), "AFFECTED")
        self.assertEqual(m(rng, "2.5.0"), "NOT_AFFECTED")
        self.assertEqual(m(rng, "3.5.0"), "AFFECTED")
        self.assertEqual(m(rng, "4.0.0"), "NOT_AFFECTED")

    def test_prerelease_cannot_be_cleared_using_stable_order(self):
        m = self.h.mod.simple_npm_osv_range
        self.assertEqual(m(RANGE, "4.17.12-beta.1"), "REVIEW_REQUIRED")

    def test_malformed_or_reversed_events_cannot_clear(self):
        m = self.h.mod.simple_npm_osv_range
        self.assertEqual(m({"type": "SEMVER",
                             "events": [{"fixed": "4.17.12"}]}, "4.17.12"),
                         "REVIEW_REQUIRED")
        self.assertEqual(m({"type": "SEMVER",
                             "events": [{"introduced": "5.0.0"},
                                        {"fixed": "4.0.0"}]}, "4.17.12"),
                         "REVIEW_REQUIRED")

    def test_complex_ecosystem_range_does_not_use_stable_parser(self):
        m = self.h.mod.simple_npm_osv_range
        self.assertEqual(m({"type": "ECOSYSTEM",
                             "events": [{"introduced": "0"}, {"fixed": "4.17.12"}]},
                            "4.17.12"), "REVIEW_REQUIRED")


if __name__ == "__main__":
    unittest.main()
