"""Codex's analysis of live run 10A-4, F01/F02: a run that stops before it is terminal first lets the work already sent finish against a
running kernel, then exports what the store accepted (marked partial), and only then closes the kernel. In-process fakes only."""
from __future__ import annotations

import pathlib
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P


class FakeKernel:
    def __init__(self, *args, **kwargs):
        self.hello, self.order, self.stopped = {"status": "listening"}, [], False
        self.owner = FakeOwner(self)

    def connect(self, agent):
        return self.owner if agent == "own" else FakeWire(self, agent)

    def stop(self):
        self.order.append("kernel_stopped")
        self.stopped = True


class FakeWire:
    def __init__(self, kernel, agent):
        self.kernel, self.agent = kernel, agent

    def call(self, tool, **args):
        if self.kernel.stopped:
            raise OSError("the kernel is closed")
        self.kernel.order.append(f"{self.agent}:{tool}")
        return {"status": "COMMITTED", "accepted": []}

    def close(self):
        pass


class FakeOwner(FakeWire):
    def __init__(self, kernel):
        super().__init__(kernel, "own")

    def call(self, tool, **args):
        if self.kernel.stopped:
            raise OSError("the kernel is closed")
        self.kernel.order.append(f"own:{tool}")
        if tool == "audit_terminal_receipt":
            return {"status": "NOT_COMPLETE", "accepted_outcomes": {"RQ1": {"outcome": "answered", "done": "@d", "answer_ids": ["@c"], "partial": True}}}
        return {}

    def close(self):
        self.kernel.order.append("owner_closed")


class StopBeforeTerminal(unittest.TestCase):
    def test_paid_work_finishes_against_a_running_kernel_and_the_accepted_answer_is_exported_as_partial(self):
        kernels, sent = [], threading.Event()

        def make_kernel(*args, **kwargs):
            kernels.append(FakeKernel())
            return kernels[-1]

        def in_flight_worker(k, agent, model, log, phase, stop):
            # a model answer already on its way when the run stops: it is submitted after the stop
            sent.set()
            stop.wait(5)
            k.connect(agent).call("audit_submit", task_id="T1", lines=[])

        def stopped(own, log, timeout_s):
            sent.wait(5)
            return {"status": "STOPPED", "reason": "BUDGET_CAP: $2.0"}

        exported = {}

        def answers(own, receipt, docs, paths=None):
            exported["receipt"] = receipt
            return {rq: {"outcome": o["outcome"], "claims": []} for rq, o in (receipt.get("outcomes") or {}).items()}

        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(P, "Kernel", side_effect=make_kernel), \
                mock.patch.object(P, "source_document_paths", return_value={}), \
                mock.patch.object(P, "c_worker", side_effect=in_flight_worker), \
                mock.patch.object(P, "c_builder", side_effect=lambda *a, **k: None), \
                mock.patch.object(P, "c_until_terminal", side_effect=stopped), \
                mock.patch.object(P, "c_answers", side_effect=answers):
            manifest = pathlib.Path(d) / "manifest.json"
            manifest.write_text("{}", encoding="utf-8")
            res = P.run_arm_c(P.StubModel(), P.StubModel(), pathlib.Path(d) / "work", manifest, pathlib.Path(d), [], {}, {"quote": "q", "report": "r"},
                              workers=1, timeout_s=60)
        order = kernels[0].order
        self.assertIn("w1:audit_submit", order, "the paid answer reached the kernel")
        self.assertLess(order.index("w1:audit_submit"), order.index("kernel_stopped"), f"submitted before the kernel closed: {order}")
        self.assertLess(order.index("own:audit_terminal_receipt"), order.index("kernel_stopped"), f"exported before the kernel closed: {order}")
        self.assertEqual(res["phase1"]["receipt"]["status"], "STOPPED", "the run is still reported as stopped")
        self.assertEqual(list(res["phase1"]["answers"]), ["RQ1"], "the accepted answer is exported")
        self.assertIn("not terminal", res["phase1"]["answers_partial"])
        self.assertEqual(res["phase2"]["reason"], "PREVIOUS_PHASE_NOT_TERMINAL")

    def test_an_answer_that_was_not_exported_counts_as_unknown_not_as_zero_reports(self):
        docs = {"r.md": "a retained exact quote of the report"}
        c = {"events": [], "calls": [], "phase1": {"answers": {"RQ1": {"claims": [{"quotes": [{"quote": "a retained exact quote"}]}]}}}}
        a = {"events": [], "calls": [], "phase1": {"answers": {}}}
        cited = P.measures(a, c, docs)["reports_cited"]
        self.assertEqual(cited["C"]["phase1"]["RQ1"], 1)
        self.assertIsNone(cited["C"]["phase1"]["RQ2"], "no answer exported: null, not 0")
        self.assertIsNone(cited["A"]["phase1"]["RQ1"])



class OwnersMeasure(unittest.TestCase):
    def test_a_task_reports_the_lines_it_offered_and_the_lines_the_graph_got(self):
        import json
        import test_review_d05_control_flow as D
        answer = "\n".join(json.dumps(x) for x in [
            dict(D.OBSERVE, local_id="t1_o"), dict(D.OBSERVE, local_id="t1_p"), dict(D.OBSERVE, local_id="t1_q")])
        partial = {"status": "REPAIR_REQUIRED", "failed_index": 2, "accepted": ["@o", "@p"], "accepted_locals": {"t1_o": "@o", "t1_p": "@p"},
                   "error": {"code": "QUOTE_NOT_FOUND_IN_BYTES"}}
        done = {"status": "COMMITTED", "accepted": [], "accepted_locals": {}}
        rpc, log, _ = D.D05ControlFlow().flow("worker", [answer, answer], replies=[partial, done])
        event = [e for e in log.events if e.get("task")][0]
        self.assertEqual((event["lines_offered"], event["lines_stored"]), (3, 2), event)
        measured = P.measures({"events": [], "calls": []}, {"events": log.events, "calls": []}, {})["lines_stored"]
        self.assertEqual(measured, {"EXTEND": {"offered": 3, "stored": 2}})


if __name__ == "__main__":
    unittest.main()
