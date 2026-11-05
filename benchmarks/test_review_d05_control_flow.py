"""D05 control-flow regressions: scripted calls and in-process RPC only."""
from __future__ import annotations

import json
import pathlib
import sys
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P

OBSERVE = {"kind": "observe", "local_id": "t1_o", "doc_id": "d", "exact_quote": "a retained exact quote"}
OP = {"op": "map_term", "record": "@o", "term": "topic", "concept": "Topic"}


class FakeRpc:
    def __init__(self, role, stop, replies, kind):
        self.role, self.stop, self.replies, self.kind = role, stop, list(replies or []), kind
        self.calls, self.polled, self.closed = [], False, 0

    def call(self, tool, **args):
        self.calls.append((tool, args))
        if tool in ("audit_acquire", "audit_next_card"):
            if self.polled:
                self.stop.set()
                return {"status": "COMPLETE" if self.role == "worker" else "IDLE"}
            self.polled = True
            if self.role == "worker":
                return {"status": "DIRECTIVE", "kind": self.kind, "prompt": "synthetic directive",
                        "task_id": "T1", "key": "rq:RQ1" if self.kind == "SUMMARIZE" else "doc:d#0",
                        "local_id_prefix": "t1_"}
            return {"status": "CARD", "card_id": "C1", "prompt": "synthetic builder",
                    "records": [{"id": "@o", "kind": "observe", "quote": "a retained exact quote", "terms": ["topic"]}],
                    "candidates": {}, "max_ops": 8}
        if tool in ("audit_submit", "audit_submit_ops"):
            return self.replies.pop(0) if self.replies else {
                "status": "COMMITTED" if self.role == "worker" else "CARD_DONE",
                "accepted": [], "accepted_locals": {}}
        if tool == "audit_release":
            return {"status": "RELEASED"}
        raise AssertionError(tool)

    def close(self):
        self.closed += 1

    @property
    def submissions(self):
        field = "lines" if self.role == "worker" else "ops"
        return [args[field] for tool, args in self.calls if tool in ("audit_submit", "audit_submit_ops")]


class D05ControlFlow(unittest.TestCase):
    def flow(self, role, outputs, *, replies=None, kind="EXTEND", max_calls=20):
        stop, prompts, emitted = threading.Event(), [], []
        rpc = FakeRpc(role, stop, replies, kind)
        kernel = SimpleNamespace(connect=lambda agent: rpc)
        log = P.Log(max_calls=max_calls, evidence=lambda kind, record: emitted.append((kind, record)))
        remaining = iter(outputs)

        def scripted(unused, prompt, **fields):
            prompts.append(prompt)
            return P.Call(**fields, prompt_chars=len(prompt), text=next(remaining), model="in-process-script")

        forbidden = AssertionError("external dependency forbidden in D05 control-flow tests")
        with mock.patch.object(P, "call_model", side_effect=scripted), \
                mock.patch.object(P.socket, "create_connection", side_effect=forbidden), \
                mock.patch.object(P.urllib.request, "urlopen", side_effect=forbidden), \
                mock.patch.object(P.subprocess, "Popen", side_effect=forbidden), \
                mock.patch.object(P.subprocess, "run", side_effect=forbidden):
            model = SimpleNamespace(name="script-only")
            if role == "worker":
                P.c_worker(kernel, "w1", model, log, [1], stop)
            else:
                P.c_builder(kernel, model, log, [1], stop)
        self.assertEqual(rpc.closed, 1)
        self.assertFalse(log.in_flight)
        self.assertEqual(len([k for k, _ in emitted if k == "call"]), len(log.calls))
        return rpc, log, prompts

    def assert_parse_stop(self, rpc, log):
        self.assertTrue(log.stopped and log.stopped.startswith("PARSE_FAILURE"), log.stopped)
        events = [e for e in log.events if e.get("parse_failure")]
        self.assertTrue(events, log.events)
        self.assertFalse(any(e.get("outcome") in ("COMMITTED", "CARD_DONE") for e in log.events))
        self.assertFalse(any(e.get("first_try") for e in events))

    def test_invalid_shape_or_prose_never_becomes_an_empty_success(self):
        for role in ("worker", "builder"):
            for text in ('[{"op":"map_term"}]', "No relevant findings.", "", "null"):
                with self.subTest(role=role, text=text):
                    rpc, log, _ = self.flow(role, [text] * 3)
                    self.assertEqual(rpc.submissions, [])
                    self.assert_parse_stop(rpc, log)
                    self.assertEqual(len(log.calls), 3)

    def test_last_malformed_repair_never_submits_its_valid_subset(self):
        for role in ("worker", "builder"):
            valid = OBSERVE if role == "worker" else OP
            bad = json.dumps(valid) + '\n{"broken":'
            with self.subTest(role=role):
                rpc, log, _ = self.flow(role, [bad] * 3)
                self.assertEqual(rpc.submissions, [])
                self.assert_parse_stop(rpc, log)

    def test_invalid_then_valid_submits_only_the_repaired_answer(self):
        for role in ("worker", "builder"):
            valid = OBSERVE if role == "worker" else OP
            with self.subTest(role=role):
                rpc, log, _ = self.flow(role, ["unexpected prose", json.dumps(valid)])
                self.assertEqual(rpc.submissions, [[valid]])
                self.assertIsNone(log.stopped)
                event = log.events[-1]
                self.assertEqual(event["repairs"], 1)
                self.assertFalse(event["parse_failure"])

    def test_an_explicit_empty_result_is_recorded_separately(self):
        for role, kind in (("worker", "EXTEND"), ("worker", "INVESTIGATE"), ("builder", "EXTEND")):
            with self.subTest(role=role, kind=kind):
                rpc, log, _ = self.flow(role, ["[]"], kind=kind)
                self.assertEqual(rpc.submissions, [[]])
                self.assertIsNone(log.stopped)
                self.assertTrue(log.events[-1]["explicit_empty"])
                self.assertFalse(log.events[-1]["parse_failure"])

    def test_empty_summary_or_link_answer_is_not_intentional_closure(self):
        for kind in ("SUMMARIZE", "VERIFY_LINK", "RESOLVE_CONFLICT"):
            with self.subTest(kind=kind):
                # a summary has four repairs (live run 10A-3), the other tasks two
                rpc, log, _ = self.flow("worker", ["[]"] * (1 + (P.SUMMARY_REPAIRS if kind == "SUMMARIZE" else P.REPAIRS)), kind=kind)
                self.assertEqual(rpc.submissions, [])
                self.assert_parse_stop(rpc, log)

    def test_previously_accepted_observe_survives_failed_format_repairs(self):
        refusal = {"status": "REPAIR_REQUIRED", "failed_index": 1, "accepted": ["@kept"],
                   "accepted_locals": {"t1_o": "@kept"}, "error": {"code": "BAD_FIELD"}}
        rpc, log, _ = self.flow("worker", [json.dumps(OBSERVE), '{"broken":', '{"broken":'], replies=[refusal])
        self.assertEqual(rpc.submissions, [[OBSERVE]])
        self.assertEqual(log.observes, {"@kept": {"quote": OBSERVE["exact_quote"], "doc_id": "d"}})
        self.assert_parse_stop(rpc, log)

    def test_builder_committed_prefix_is_not_empty_closed_after_bad_repairs(self):
        refusal = {"status": "REPAIR_REQUIRED", "accepted": 1, "refused": [{"index": 1, "error": {"code": "BAD_FIELD"}}]}
        refused_op = {"op": "no_such_op"}
        initial = json.dumps(OP) + "\n" + json.dumps(refused_op)
        rpc, log, _ = self.flow("builder", [initial, '{"broken":', '{"broken":'], replies=[refusal])
        self.assertEqual(rpc.submissions, [[OP, refused_op]])
        self.assert_parse_stop(rpc, log)

    def test_call_cap_during_format_repair_preserves_the_cap_and_no_fallback(self):
        for role in ("worker", "builder"):
            with self.subTest(role=role):
                rpc, log, _ = self.flow(role, ['{"broken":'], max_calls=1)
                self.assertEqual(rpc.submissions, [])
                self.assertTrue(log.stopped.startswith("CALL_CAP"), log.stopped)
                self.assertTrue(any(e.get("parse_failure") for e in log.events))
                self.assertEqual(len(log.calls), 1)

    def test_valid_json_server_refusals_keep_the_existing_fallback(self):
        for role in ("worker", "builder"):
            valid = OBSERVE if role == "worker" else OP
            refusal = {"status": "REPAIR_REQUIRED", "failed_index": 0, "accepted_locals": {}, "error": {"code": "BAD_FIELD"}}
            with self.subTest(role=role):
                rpc, log, _ = self.flow(role, [json.dumps(valid)] * 3, replies=[refusal] * 3)
                self.assertEqual(rpc.submissions, [[valid], [valid], [valid], []])
                self.assertIsNone(log.stopped)
                self.assertTrue(log.events[-1]["abandoned"])
                self.assertFalse(log.events[-1]["parse_failure"])


if __name__ == "__main__":
    unittest.main()
