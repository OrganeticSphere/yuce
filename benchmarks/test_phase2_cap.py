"""The cap of model calls of each withdrawal phase is a flag (run MCPpair_r1: arm A's map-reduce answer over the 22 MCP pages takes 46
calls a withdrawal phase before any repair; at the fixed cap of 30 it stopped in 2A, and 2B was skipped). No model, pilot or
provider is executed."""
from __future__ import annotations

import pathlib
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import run_pilot_ac as R  # noqa: E402
from sbgk_bench import pilot_ac as P  # noqa: E402


def completed(unused_model, prompt, **fields):
    return P.Call(**fields, prompt_chars=len(prompt), text="{}", model="dependency-intercept")


class Phase2Cap(unittest.TestCase):
    def main(self, *flags, read=lambda: P.PHASE2_MAX_CALLS):
        saved = {k: v for k, v in vars(P).items() if k.isupper()}  # main sets module settings before it exits
        try:
            with mock.patch.object(sys, "argv", ["run_pilot_ac.py", "--model", "stub", *flags]):
                with self.assertRaises(SystemExit) as stop:
                    R.main()
            return str(stop.exception), read()
        finally:
            vars(P).update(saved)

    def test_the_flag_sets_the_cap_and_its_default_keeps_the_old_one(self):
        self.assertEqual(self.main("--phase2-max-calls", "150")[1], 150)
        self.assertEqual(self.main()[1], 30)
        for refused in ("0", "-5", "many"):
            self.assertIn("--phase2-max-calls", self.main("--phase2-max-calls", refused)[0], refused)

    def test_the_acquire_wait_is_a_flag_up_to_the_kernel_cap(self):
        # agents wait inside the kernel for a signal instead of asking every 500 ms
        wait = lambda: P.ACQUIRE_WAIT_MS  # noqa: E731
        self.assertEqual(self.main(read=wait)[1], 10000)
        self.assertEqual(self.main("--acquire-wait-ms", "500", read=wait)[1], 500)
        for refused in ("-1", "30001"):
            self.assertIn("--acquire-wait-ms", self.main("--acquire-wait-ms", refused)[0], refused)

    def test_auto_needs_arm_a_answer_calls_to_count(self):
        for alone in (["--freeze-arm-a"], ["--whole-reader", "--workers", "1"]):
            self.assertIn("auto is taken from arm A's answer calls", self.main("--phase2-max-calls", "auto", *alone)[0], alone[0])

    def test_the_repair_rounds_are_flags_with_the_old_defaults(self):
        rounds = lambda: (P.REPAIRS, P.SUMMARY_REPAIRS)
        self.assertEqual(self.main(read=rounds)[1], (2, 4))
        self.assertEqual(self.main("--repairs", "0", "--summary-repairs", "7", read=rounds)[1], (0, 7))
        for flag, refused in (("--repairs", "-1"), ("--summary-repairs", "21")):
            self.assertIn("must be 0..20", self.main(flag, refused)[0], flag)

    def test_a_withdrawal_phase_takes_calls_up_to_the_cap_and_stops_at_it(self):
        for cap in (30, 46):
            log = P.Log(max_calls=3000)
            with mock.patch.object(P, "PHASE2_MAX_CALLS", cap), mock.patch.object(P, "call_model", side_effect=completed) as model:
                made = [log.invoke(SimpleNamespace(name="unused"), "p", call_id=f"c{i}", arm="A", role="LEAD", phase=2) for i in range(cap + 1)]
            self.assertEqual(model.call_count, cap)
            self.assertIsNone(made[-1])
            self.assertIn(f"per withdrawal phase={cap}", log.stopped)


class ScaleCheckBeforeAnyModelCall(unittest.TestCase):
    """A cap too small for arm A's map-reduce over the corpus is refused before any work starts."""

    def main(self, reports: int, *flags, answer: str = "map-reduce"):
        saved = {k: v for k, v in vars(P).items() if k.isupper()}
        seen = []
        steps = {"steps": [{"name": "2A", "report": "r", "candidates": [{"quote": "q"}]}]}
        argv = ["run_pilot_ac.py", "--manifest", "m", "--repo", "r", "--model", "stub", "--team-models", "stub,stub,stub",
                "--arm-a-answer", answer, *flags]
        try:
            with mock.patch.object(sys, "argv", argv), mock.patch.object(R.C, "BIN", pathlib.Path(__file__)), \
                 mock.patch.object(R, "corpus_choice", return_value=([f"r{i}.md" for i in range(reports)], steps, {})), \
                 mock.patch.object(P, "make_model", return_value=P.StubModel()), \
                 mock.patch.object(R, "run", side_effect=lambda *a, **k: seen.append((P.PHASE2_MAX_CALLS, P.PHASE2_CAP_RULE)) or {"measures": {}}), \
                 mock.patch("builtins.print"):
                try:
                    R.main()
                except SystemExit as stop:
                    return str(stop), seen
            return None, seen
        finally:
            vars(P).update(saved)

    def test_the_mcp_corpus_needs_a_larger_cap_than_30(self):
        refused, seen = self.main(22)
        self.assertIn("--phase2-max-calls 30 is below the 46 calls", refused)
        self.assertEqual(seen, [], "no work started")
        self.assertEqual(self.main(22, "--phase2-max-calls", "150"), (None, [(150, "fixed")]))
        self.assertEqual(self.main(5), (None, [(30, "fixed")]), "five pages fit the old cap (12 calls)")

    def test_the_tree_reduction_needs_a_merge_per_report_beyond_the_last_two(self):
        refused, seen = self.main(22, "--phase2-max-calls", "46", "--arm-a-reduce", "tree")
        self.assertIn("--phase2-max-calls 46 is below the 86 calls", refused)  # (22 maps + 20 merges + 1 reduction) x 2 questions
        self.assertEqual(seen, [])

    def test_auto_gives_every_answer_call_all_its_repair_rounds_and_their_timeout_retries(self):
        refused, seen = self.main(22, "--phase2-max-calls", "auto")
        self.assertIsNone(refused)
        self.assertEqual(seen[0][0], 46 * 5 * 2)
        self.assertIn("auto: 46 answer calls of arm A (22 reports, 2 questions, map-reduce/single) x 5 attempts x 2 tries each", seen[0][1])
        self.assertEqual(self.main(22, "--phase2-max-calls", "auto", "--summary-repairs", "2")[1][0][0], 46 * 3 * 2)
        self.assertEqual(self.main(22, "--phase2-max-calls", "auto", "--arm-a-reduce", "tree")[1][0][0], 86 * 5 * 2)

    def test_auto_lets_every_answer_time_out_once_in_each_repair_round(self):
        # Codex review of 729eda8, BATCH-01: invoke_answer asks an answer again after a timeout, beside the repair rounds; with the
        # cap auto chose, every round of both direct answers timed out once and needed a repair, and the second answer was cut
        text = ('{"kind":"claim","local_id":"a","text":"The port is 9090.","quotes":[{"report":"r.md","exact_quote":"The port is 9090."}]}\n'
                '{"kind":"done","text":"Nothing else."}')
        for repairs in (0, 4):
            refused, seen = self.main(1, "--phase2-max-calls", "auto", "--summary-repairs", str(repairs), answer="direct")
            self.assertIsNone(refused)
            cap = seen[0][0]
            calls = []

            def wire(unused_model, prompt, **fields):
                calls.append(fields["call_id"])
                retry = fields["call_id"].endswith("-timeout-retry-1")
                attempt = int(fields["call_id"].removesuffix("-timeout-retry-1").split("-")[-1])
                return P.Call(**fields, prompt_chars=len(prompt), ok=retry, error=None if retry else "TimeoutError: synthetic deadline",
                              text=(text if attempt == repairs else "not a JSON answer") if retry else "", model="dependency-intercept")

            log = P.Log(max_calls=1000)
            with mock.patch.object(P, "SUMMARY_REPAIRS", repairs), mock.patch.object(P, "PHASE2_MAX_CALLS", cap),                  mock.patch.object(P, "call_model", side_effect=wire):
                done = [P.single_answer(log, SimpleNamespace(name="unused"), "answer", {"r.md": "The port is 9090."}, [], phase=2,
                                        rq=q["id"], role="UPDATE") for q in P.QUESTIONS]
            self.assertEqual([d is not None and d["complete"] for d in done], [True] * len(P.QUESTIONS), (repairs, cap, log.stopped))
            self.assertIsNone(log.stopped)
            self.assertEqual(len(calls), cap, "the worst case of the protocol is the cap itself")


class AnswerRecordsOnce(unittest.TestCase):
    def test_a_record_named_twice_by_a_summary_is_exported_once_in_its_first_place(self):
        class Own:
            def call(self, tool, record=None, **kw):
                assert tool == "audit_record", tool
                if record == "@d":
                    return {"kind": "done", "body": {"text": "nothing else"}}
                return {"kind": "claim", "short": record, "text": f"claim {record}", "based_on": []}

        receipt = {"outcomes": {"RQ2": {"outcome": "answered", "done": "@d", "answer_ids": ["@a", "@b", "@a", "@c", "@b"]}}}
        out = P.c_answers(Own(), receipt, {})
        self.assertEqual([c["id"] for c in out["RQ2"]["claims"]], ["@a", "@b", "@c"])



class WithdrawalsAfterAGap(unittest.TestCase):
    def test_an_answer_with_a_refused_line_is_still_updated_after_a_withdrawal(self):
        # run MCPpair2_r1: one quote still refused after its repairs in two of 44 partial answers made arm A's phase 1 INCOMPLETE,
        # and both withdrawals were skipped; arm C goes on from a TERMINAL phase with unsettled questions, so arm A does too
        good = ('{"kind":"claim","local_id":"a","text":"The port is 9090.","quotes":[{"report":"r.md","exact_quote":"The port is 9090."}]}\n'
                '{"kind":"done","text":"Nothing else."}')
        bad =('{"kind":"claim","local_id":"a","text":"The port is 8080.","quotes":[{"report":"r.md","exact_quote":"The port is 8080."}]}\n'
               '{"kind":"done","text":"Nothing else."}')

        def wire(unused_model, prompt, **fields):
            text = bad if fields["call_id"].startswith("A1-") and "-RQ1-" in fields["call_id"] else good
            return P.Call(**fields, prompt_chars=len(prompt), text=text, model="dependency-intercept")

        withdraw = {"steps": [{"name": "2A", "report": "r.md", "candidates": [{"quote": "Valve B is open."}]}]}
        res = {"phase1": {"answers": {}}}
        log = P.Log(max_calls=1000)
        with (mock.patch.object(P, "SUMMARY_REPAIRS", 1), mock.patch.object(P, "PHASE2_MAX_CALLS", 1000),
              mock.patch.object(P, "call_model", side_effect=wire)):
            P.answer_phases(log, SimpleNamespace(name="unused"), {"r.md": "The port is 9090. Valve B is open."}, withdraw, "corpus",
                            P.SINGLE_RULES, res, 0.0, 600.0, None, name="single", role="SINGLE")
        self.assertEqual(res["phase1"]["status"], "INCOMPLETE", "the gap stays in the record")
        self.assertEqual(sorted(res["phase2"]["answers"]), sorted(q["id"] for q in P.QUESTIONS), "the withdrawal still ran")
        self.assertEqual(res["phase2"]["status"], "COMPLETE")


if __name__ == "__main__":
    unittest.main()
