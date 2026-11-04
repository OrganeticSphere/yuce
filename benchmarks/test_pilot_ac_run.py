"""Run artifact regressions with dependency mocks; no model, server or pilot is executed."""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import run_pilot_ac as R


class RunEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.raw = b"# Snapshot\r\nA known limitation remains.\r\n"
        (self.root / "one.md").write_bytes(self.raw)
        self.manifest = self.root / "manifest.json"
        self.manifest.write_bytes(b'{"snapshot":"original"}')
        self.out = self.root / "out"
        self.model = SimpleNamespace(name="dependency-mock-only")

    def run_mocked(self):
        return R.run(self.manifest, self.root, ["one.md"], self.out, self.model, 1, None)

    def test_existing_output_is_rejected_without_changing_prior_evidence(self):
        self.out.mkdir()
        sentinel = self.out / "calls.jsonl"
        sentinel.write_bytes(b"previous run\n")
        with mock.patch.object(R.P, "run_arm_c") as arm:
            with self.assertRaises(FileExistsError):
                self.run_mocked()
        arm.assert_not_called()
        self.assertEqual(sentinel.read_bytes(), b"previous run\n")

    def test_completed_c_calls_survive_a_failure(self):
        c = {"calls": [{"call_id": "completed-C", "ok": True}], "events": []}
        with mock.patch.object(R.P, "run_arm_c", return_value=c), mock.patch.object(
                R.P, "run_arm_a", side_effect=RuntimeError("later arm failed")):
            with self.assertRaisesRegex(RuntimeError, "later arm failed"):
                self.run_mocked()
        self.assertIn("completed-C", (self.out / "calls.jsonl").read_text())
        self.assertEqual(json.loads((self.out / "arm_c.json").read_text()), c)
        status = json.loads((self.out / "status.json").read_text())
        self.assertEqual((status["status"], status["stage"]), ("FAILED", "arm_a"))

    def test_call_and_context_are_durable_before_an_arm_returns(self):
        def fail(*args, evidence, **kwargs):
            evidence("context", {"call_id": "C-in-flight", "prompt": "captured context"})
            evidence("call_started", {"call_id": "C-in-flight"})
            evidence("call", {"call_id": "C-in-flight", "ok": True})
            self.assertIn("C-in-flight", (self.out / "calls.jsonl").read_text())
            raise RuntimeError("after completed call")

        with mock.patch.object(R.P, "run_arm_c", side_effect=fail):
            with self.assertRaisesRegex(RuntimeError, "after completed call"):
                self.run_mocked()
        records = [json.loads(x) for x in (self.out / "journal.jsonl").read_text().splitlines()]
        self.assertEqual([x["kind"] for x in records], ["context", "call_started", "call"])
        self.assertEqual([x["sequence"] for x in records], [1, 2, 3])

    def test_both_arm_inputs_bind_raw_source_and_original_manifest_bytes(self):
        original_manifest = self.manifest.read_bytes()

        def c(*args, **kwargs):
            pinned, repo, docs = args[3], args[4], args[6]
            self.assertEqual(pinned.read_bytes(), original_manifest)
            self.assertEqual((repo / "one.md").read_bytes(), self.raw)
            self.assertEqual(docs["one.md"].encode(), self.raw)
            self.manifest.write_bytes(b'{"snapshot":"replacement"}')
            (self.root / "one.md").write_bytes(b"replacement source")
            self.assertEqual(pinned.read_bytes(), original_manifest)
            self.assertEqual((repo / "one.md").read_bytes(), self.raw)
            return {"calls": [], "events": []}

        def a(model, docs, *args, **kwargs):
            self.assertEqual(docs["one.md"].encode(), self.raw)
            return {"calls": [], "events": []}

        with mock.patch.object(R.P, "run_arm_c", side_effect=c), mock.patch.object(R.P, "run_arm_a", side_effect=a), \
                mock.patch.object(R.P, "measures", return_value={}), mock.patch.object(R.P, "answers_md", return_value=("", {})):
            summary = self.run_mocked()
        self.assertEqual(summary["corpus"]["manifest_sha256"], hashlib.sha256(original_manifest).hexdigest())
        self.assertEqual(summary["corpus"]["source_bytes"]["one.md"]["raw_sha256"], hashlib.sha256(self.raw).hexdigest())

    def test_reconcile_does_not_duplicate_streamed_calls_or_drop_equal_events(self):
        self.out.mkdir()
        evidence = R.Evidence(self.out)
        event = {"outcome": "WAIT"}
        call = {"call_id": "C1"}
        evidence("call", call)
        evidence("event", event)
        evidence.reconcile({"calls": [call], "events": [event, event]})
        self.assertEqual(len((self.out / "calls.jsonl").read_text().splitlines()), 1)
        self.assertEqual(len((self.out / "events.jsonl").read_text().splitlines()), 2)

    def test_invalid_withdrawal_fails_before_either_arm(self):
        with mock.patch.object(R.P, "run_arm_c") as c:
            with self.assertRaisesRegex(ValueError, "withdrawal must name"):
                R.run(self.manifest, self.root, ["one.md"], self.out, self.model, 1,
                      {"quote": "limitation", "report": "other.md"})
        c.assert_not_called()

    def test_equal_nonstreamed_events_from_two_arms_are_both_preserved(self):
        self.out.mkdir()
        evidence = R.Evidence(self.out)
        event = {"outcome": "WAIT"}
        for _ in range(2):
            before = evidence.mark()
            evidence.reconcile({"events": [event]}, before)
        self.assertEqual(len((self.out / "events.jsonl").read_text().splitlines()), 2)

    def test_noncanonical_report_cannot_escape_frozen_repository(self):
        with mock.patch.object(R.P, "run_arm_c") as c:
            with self.assertRaisesRegex(ValueError, "unsafe report path"):
                R.run(self.manifest, self.root, ["../one.md"], self.out, self.model, 1, None)
        c.assert_not_called()


if __name__ == "__main__":
    unittest.main()
