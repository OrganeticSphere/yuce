"""Codex's review of 77a803e (2026-10-23), his runner probes: a withdrawal phase that stops exports what the store still accepts, marked
partial, and keeps its own STOPPED receipt (R01); a submission whose answer is lost after the stop gets an explicit task outcome
(R02); the reservation takes the peak rate of a peak window inside a long call life whose ends are both off-peak (R05). In-process
fakes only: no provider, no kernel process, no network."""
from __future__ import annotations

import calendar
import json
import pathlib
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P


class Owner:
    def __init__(self, kernel):
        self.kernel = kernel

    def call(self, tool, **kw):
        if self.kernel.stopped:
            raise OSError("kernel is stopped")
        self.kernel.order.append(tool)
        if tool == "audit_revoke":
            return {"status": "REVOKED"}
        if tool == "audit_terminal_receipt":
            return {"status": "NOT_COMPLETE", "accepted_outcomes": self.kernel.accepted_outcomes}
        return {}

    def close(self):
        self.kernel.order.append("owner_closed")


class Kernel:
    def __init__(self):
        self.order, self.stopped, self.hello = [], False, {"status": "listening"}
        self.accepted_outcomes = {"RQ1": {"outcome": "answered", "done": "@partial2", "answer_ids": ["@c2"], "partial": True}}
        self.owner = Owner(self)

    def connect(self, role):
        return self.owner

    def stop(self):
        self.order.append("kernel_stopped")
        self.stopped = True


class WithdrawalPhaseStops(unittest.TestCase):
    def test_the_accepted_partial_answer_of_a_stopped_withdrawal_phase_is_exported(self):
        kernel = Kernel()
        receipts = iter([
            {"status": "TERMINAL", "outcomes": {"RQ1": {"outcome": "answered", "done": "@initial", "answer_ids": ["@c1"]}}},
            {"status": "STOPPED", "reason": "BUDGET_CAP"},
        ])

        def terminal(own, log, timeout):
            receipt = next(receipts)
            if receipt["status"] == "STOPPED":
                log.stopped = "BUDGET_CAP"
            return receipt

        exports = []

        def answers(own, receipt, *args):
            exports.append(receipt)
            return {q: {"outcome": v["outcome"], "done": v.get("done"), "claims": []} for q, v in receipt.get("outcomes", {}).items()}

        with tempfile.TemporaryDirectory() as name, \
             mock.patch.object(P, "Kernel", return_value=kernel), \
             mock.patch.object(P, "source_document_paths", return_value={}), \
             mock.patch.object(P, "c_worker", return_value=None), \
             mock.patch.object(P, "c_builder", return_value=None), \
             mock.patch.object(P, "c_until_terminal", side_effect=terminal), \
             mock.patch.object(P, "c_answers", side_effect=answers), \
             mock.patch.object(P, "choose_candidate", return_value=({"quote": "q"}, ["@o"], "test")):
            manifest = pathlib.Path(name) / "manifest.json"
            manifest.write_text("{}", encoding="utf-8")
            steps = {"steps": [{"name": "withdraw", "report": "r", "candidates": [{"quote": "q"}]}]}
            result = P.run_arm_c(SimpleNamespace(), SimpleNamespace(), pathlib.Path(name) / "work", manifest, pathlib.Path(name), [], {},
                                 steps, workers=1)
        self.assertEqual(result["phase2"]["receipt"], {"status": "STOPPED", "reason": "BUDGET_CAP"}, "the phase keeps its own receipt")
        self.assertEqual(result["phase2"]["answers"]["RQ1"]["done"], "@partial2", "the answer accepted after the withdrawal, not the old one")
        self.assertEqual(result["phase2"]["answers_partial"], P.PARTIAL_ANSWERS)
        self.assertNotIn("answers_partial", result["phase1"])
        # drained, then exported, then closed
        self.assertEqual(kernel.order[-3:], ["audit_status", "owner_closed", "kernel_stopped"])
        self.assertLess(kernel.order.index("audit_terminal_receipt"), kernel.order.index("owner_closed"))


class SubmitLostAfterStop(unittest.TestCase):
    def test_a_lost_submission_answer_is_an_explicit_task_outcome_and_keeps_the_stop_reason(self):
        stop, emitted = threading.Event(), []
        log = P.Log(evidence=lambda kind, row: emitted.append({"kind": kind, "row": row}))

        class Wire:
            def call(self, tool, **kw):
                if tool == "audit_acquire":
                    return {"status": "DIRECTIVE", "kind": "EXTEND", "task_id": "T1", "key": "doc:d#0", "prompt": "test", "max_lines": 32}
                if tool == "audit_submit":
                    raise TimeoutError("submit timed out while draining a paid answer")
                raise AssertionError(tool)

            def close(self):
                pass

        def call_model(unused, prompt, **kw):
            stop.set()
            line = {"kind": "observe", "local_id": "t1_o", "doc_id": "d", "exact_quote": "retained quote"}
            return P.Call(**kw, prompt_chars=len(prompt), text=json.dumps(line), model="in-process-only")

        kernel = SimpleNamespace(connect=lambda agent: Wire())
        with mock.patch.object(P, "call_model", side_effect=call_model):
            P.guarded_worker(lambda: P.c_worker(kernel, "w1", SimpleNamespace(), log, [1], stop), log, stop, arm="C", agent="w1")
        tasks = [e for e in log.events if e.get("task")]
        self.assertEqual([(e["outcome"], e["call_id"], e["lines_submitted"], e["after_stop"]) for e in tasks],
                         [("ACK_UNKNOWN", "C1-T1-0", 1, True)])
        self.assertIn("TimeoutError", tasks[0]["error"])
        self.assertEqual([e["outcome"] for e in log.events if not e.get("task")], ["ERROR_AFTER_STOP"])
        self.assertIsNone(log.stopped, "an error after the stop does not become its reason")
        self.assertEqual(log.in_flight, {})
        self.assertIn("event", [e["kind"] for e in emitted])


class PeakInsideALongLife(unittest.TestCase):
    def test_a_peak_window_between_two_off_peak_ends_is_reserved_at_the_peak_rate(self):
        begin = calendar.timegm((2026, 10, 23, 4, 30, 0))  # a Friday: 04:30 and 10:31 UTC are off-peak, 06-10 is peak
        model = P.DeepSeekModel(key="offline-placeholder", timeout_s=3600)
        end = begin + model.longest_s()
        self.assertEqual((P.deepseek_price_factor(begin), P.deepseek_price_factor(end)), (0.5, 0.5))
        with mock.patch.object(P.time, "time", return_value=begin):
            estimate = model.estimate("p")
        self.assertAlmostEqual(estimate, (1 * P.DEEPSEEK_RATES[0] + model.max_tokens * P.DEEPSEEK_RATES[2]) / 1e6)
        self.assertEqual(P.deepseek_price_factor_over(begin, begin + 3600), 0.5, "04:30 to 05:30 holds no peak hour")
        self.assertEqual(P.deepseek_price_factor_over(begin, calendar.timegm((2026, 10, 23, 6, 0, 0))), 1.0, "the peak's first second counts")


if __name__ == "__main__":
    unittest.main()
