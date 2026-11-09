"""Offline contract logic tests. Mock GenLayer VM: no claim of Studio execution."""
import importlib.util
import json
import pathlib
import sys
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ADVISORY = "GHSA-jf85-cpcp-j695"
CLIENT = "0x" + "11" * 20
OTHER = "0x" + "22" * 20


class VM:
    class UserError(Exception):
        pass

    class Return:
        def __init__(self, calldata):
            self.calldata = calldata

    def run_nondet_unsafe(self, leader, validator):
        result = leader()
        if not validator(self.Return(result)):
            raise self.UserError("consensus mismatch")
        return result


class TreeMap(dict):
    @classmethod
    def __class_getitem__(cls, _):
        return cls


class Public:
    @staticmethod
    def write(fn):
        return fn

    @staticmethod
    def view(fn):
        return fn


class Harness:
    def __init__(self):
        self.sources = {}
        self.prompts = []
        self.gl = types.SimpleNamespace(
            Contract=object, public=Public(), vm=VM(),
            message=types.SimpleNamespace(
                sender_address=types.SimpleNamespace(as_hex=CLIENT)),
            nondet=types.SimpleNamespace(
                web=types.SimpleNamespace(get=self.get),
                exec_prompt=self.prompt))
        fake = types.ModuleType("genlayer")
        fake.gl = self.gl
        fake.TreeMap = TreeMap
        fake.u256 = int
        sys.modules["genlayer"] = fake
        spec = importlib.util.spec_from_file_location("patchgate_under_test",
                  ROOT / "contracts" / "patchgate.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.mod = mod
        self.gate = mod.PatchGate()
        self.gate.releases = TreeMap()

    def get(self, url):
        if url not in self.sources:
            raise LookupError("missing simulated OSV record")
        return types.SimpleNamespace(body=json.dumps(self.sources[url]).encode())

    def prompt(self, _):
        return self.prompts.pop(0)

    def actor(self, address):
        self.gl.message.sender_address.as_hex = address

    def advisory(self, *, package="lodash", ecosystem="npm", versions=None,
                 ranges=None):
        item = {"package": {"ecosystem": ecosystem, "name": package}}
        if versions is not None:
            item["versions"] = versions
        if ranges is not None:
            item["ranges"] = ranges
        self.sources["https://api.osv.dev/v1/vulns/" + ADVISORY] = {
            "id": ADVISORY, "modified": "2026-11-09T00:00:00Z",
            "affected": [item]
        }

    def open(self, version="4.17.11"):
        return self.gate.open_release("npm", "lodash", version,
                                      json.dumps([ADVISORY]))


class PatchGateTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()

    def test_explicitly_affected_version_is_blocked(self):
        self.h.advisory(versions=["4.17.11", "4.17.10"])
        idx = self.h.open()
        self.assertEqual(self.h.gate.evaluate_release(idx), "BLOCK")
        record = json.loads(self.h.gate.get_release(idx))
        self.assertEqual(record["evidence"][0]["status"], "AFFECTED")
        self.assertEqual(len(record["evidence"][0]["source_sha256"]), 64)
        with self.assertRaises(VM.UserError):
            self.h.gate.authorize_release(idx)

    def test_unlisted_package_is_advisory_scoped_allow(self):
        self.h.advisory(package="unrelated", versions=["4.17.11"])
        idx = self.h.open()
        self.assertEqual(self.h.gate.evaluate_release(idx), "ALLOW")
        self.h.gate.authorize_release(idx)
        self.assertTrue(json.loads(self.h.gate.get_release(idx))["authorized"])

    def test_explicit_version_not_in_list_allows_only_this_advisory(self):
        self.h.advisory(versions=["1.0.0"])
        idx = self.h.open()
        self.assertEqual(self.h.gate.evaluate_release(idx), "ALLOW")

    def test_range_requires_independently_matching_consensus(self):
        self.h.advisory(ranges=[{"type": "SEMVER",
                  "events": [{"introduced": "0"}, {"fixed": "4.17.12"}]}])
        self.h.prompts = ["AFFECTED", "AFFECTED"]
        idx = self.h.open()
        self.assertEqual(self.h.gate.evaluate_release(idx), "BLOCK")

    def test_ambiguous_range_validator_detects_disagreement(self):
        # Unsupported ecosystem-defined ordering uses independently compared AI.
        self.h.advisory(ranges=[{"type": "ECOSYSTEM",
                  "events": [{"introduced": "0"}, {"fixed": "4.17.12"}]}])
        self.h.prompts = ["AFFECTED", "NOT_AFFECTED"]
        idx = self.h.open()
        with self.assertRaises(VM.UserError):
            self.h.gate.evaluate_release(idx)
        self.assertEqual(json.loads(self.h.gate.get_release(idx))["stage"], "OPEN")

    def test_source_missing_fails_closed(self):
        idx = self.h.open()
        self.assertEqual(self.h.gate.evaluate_release(idx), "REVIEW_REQUIRED")
        with self.assertRaises(VM.UserError):
            self.h.gate.authorize_release(idx)

    def test_source_id_mismatch_fails_closed(self):
        self.h.advisory(versions=["4.17.11"])
        url = "https://api.osv.dev/v1/vulns/" + ADVISORY
        self.h.sources[url]["id"] = "GHSA-other-entry"
        idx = self.h.open()
        self.assertEqual(self.h.gate.evaluate_release(idx), "REVIEW_REQUIRED")

    def test_owner_only_authorization_and_revocation(self):
        self.h.advisory(package="other", versions=["4.17.11"])
        idx = self.h.open()
        self.h.gate.evaluate_release(idx)
        self.h.actor(OTHER)
        with self.assertRaises(VM.UserError):
            self.h.gate.authorize_release(idx)
        self.h.actor(CLIENT)
        self.h.gate.authorize_release(idx)
        self.h.gate.revoke_release(idx)
        record = json.loads(self.h.gate.get_release(idx))
        self.assertEqual(record["stage"], "REVOKED")
        self.assertFalse(record["authorized"])

    def test_no_repeat_authorization_or_re_evaluation(self):
        self.h.advisory(package="other", versions=["4.17.11"])
        idx = self.h.open()
        self.h.gate.evaluate_release(idx)
        with self.assertRaises(VM.UserError):
            self.h.gate.evaluate_release(idx)
        self.h.gate.authorize_release(idx)
        with self.assertRaises(VM.UserError):
            self.h.gate.authorize_release(idx)

    def test_reject_duplicate_advisory_ids(self):
        with self.assertRaises(VM.UserError):
            self.h.gate.open_release("npm", "lodash", "4.17.11",
                                     json.dumps([ADVISORY, ADVISORY]))

    def test_reject_unsupported_ecosystem(self):
        with self.assertRaises(VM.UserError):
            self.h.gate.open_release("unknown", "lodash", "4.17.11",
                                     json.dumps([ADVISORY]))


if __name__ == "__main__":
    unittest.main()
