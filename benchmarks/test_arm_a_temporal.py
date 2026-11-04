"""Arm A as a Temporal-native team (the owner, 2026-10-30: the same as the LangGraph-native team for Temporal before its run): the
stub team on the synthetic corpus, on the test's own local dev server. No provider is called; skipped without temporalio or the
Temporal CLI (the system Python), run in the baselines venv."""
from __future__ import annotations

import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import run_pilot_ac as R  # noqa: E402
from sbgk_bench import pilot_ac as P  # noqa: E402

try:
    import temporalio  # noqa: F401

    from sbgk_bench import arm_a_temporal as T  # noqa: E402
except ImportError:
    T = None
CLI = shutil.which("temporal") or os.path.join(os.path.expanduser("~"), ".local", "bin", "temporal.exe")

GONE = "The earlier warning rule is superseded: a version mismatch is now blocking."
WITHDRAW = {"quote": GONE, "report": "reports/later.md"}


class Failing(P.StubModel):
    """The stub that fails the first `fails` calls whose prompt starts with `prefix`."""

    def __init__(self, prefix: str, fails: int):
        super().__init__()
        self.prefix, self.fails = prefix, fails

    def complete(self, prompt: str):
        if prompt.startswith(self.prefix) and self.fails > 0:
            self.fails -= 1
            raise RuntimeError("provider down")
        return super().complete(prompt)


@unittest.skipIf(T is None or not os.path.exists(CLI), "temporalio or the Temporal CLI is missing (run in the baselines venv)")
class TemporalNativeTeam(unittest.TestCase):
    def setUp(self):
        self.saved = {k: v for k, v in vars(P).items() if k.isupper()}
        self.saved_t = {k: v for k, v in vars(T).items() if k.isupper()}
        P.ARM_A_ANSWER = "map-reduce"

    def tearDown(self):
        vars(P).update(self.saved)
        vars(T).update(self.saved_t)

    def run_team(self, team=None):
        return T.run(team or [P.StubModel(), P.StubModel(), P.StubModel()], dict(R.SYNTH), WITHDRAW, timeout_s=120)

    def test_the_workflow_answers_every_stage_and_keeps_its_history_on_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            T.TEMPORAL_DB = str(pathlib.Path(tmp) / "arm_a_temporal.db")
            res = self.run_team()
            self.assertTrue(pathlib.Path(T.TEMPORAL_DB).is_file(), "the dev server's SQLite history")
        self.assertIsNone(res["stopped"])
        for phase in ("phase1", "phase2"):
            self.assertEqual(res[phase]["status"], "COMPLETE", res[phase])
        cited = lambda ph: {q["quote"] for a in res[ph]["answers"].values() for c in a["claims"] for q in c["quotes"]}  # noqa: E731
        self.assertIn(GONE, cited("phase1"))
        self.assertNotIn(GONE, cited("phase2"), "the withdrawn quote is dropped")
        o = res["orchestration"]
        self.assertEqual((o["kind"], o["history"], o["max_concurrent_activities"]), ("temporal-native", "sqlite file", 3))
        self.assertGreater(o["history_events"], 20)
        # only later.md's partials are made again: earlier.md's are the workflow's state
        self.assertEqual(res["phase2"]["partials_reused"], len(P.QUESTIONS) * (len(R.SYNTH) - 1))
        self.assertEqual(sum(c["role"] == "UPDATE" for c in res["calls"]), 2 * len(P.QUESTIONS))

    def test_temporal_retries_a_failed_reading_and_counts_every_attempt(self):
        res = self.run_team([Failing("ARM A WORKER", 1), P.StubModel(), P.StubModel()])
        self.assertIsNone(res["stopped"])
        workers = [c for c in res["calls"] if c["role"] == "WORKER"]
        self.assertEqual(sum(not c["ok"] for c in workers), 1)
        self.assertTrue(any("-tmp-retry-1" in c["call_id"] and c["ok"] for c in workers), [c["call_id"] for c in workers])

    def test_a_reading_that_fails_on_its_last_attempt_stops_the_arm_visibly(self):
        res = self.run_team([Failing("ARM A WORKER", 10), P.StubModel(), P.StubModel()])
        self.assertTrue(res["stopped"].startswith("MODEL_ERROR"), res["stopped"])
        self.assertEqual((res["phase1"]["status"], res["phase2"]["status"]), ("STOPPED", "SKIPPED"))

    def test_a_partial_that_fails_on_its_last_attempt_is_incomplete_and_the_arm_goes_on(self):
        res = self.run_team([P.StubModel(), Failing("ARM A TEAM", 100), P.StubModel()])
        self.assertIsNone(res["stopped"])
        rows = [r for rows in res["phase1"]["partials"].values() for r in rows]
        self.assertTrue(any(r["status"] != "COMPLETE" and r["temporal_attempts"] == T.RETRY_ATTEMPTS for r in rows), rows)
        self.assertEqual(res["phase1"]["status"], "INCOMPLETE")
        self.assertIn(res["phase2"]["status"], ("COMPLETE", "INCOMPLETE"), "the withdrawal still runs")

    def test_overrun_partials_are_incomplete_without_timeout_or_native_retries(self):
        class Overrun(P.StubModel):
            def complete(self, prompt):
                if prompt.startswith("ARM A TEAM"):
                    raise P.CallFailed(P.OUTPUT_OVERRUN + ": synthetic multi-turn result", 0.0)
                return super().complete(prompt)
        res = self.run_team([Overrun(), Overrun(), Overrun()])
        self.assertIsNone(res["stopped"])
        self.assertEqual(res["phase1"]["status"], "INCOMPLETE")
        failed = [c for c in res["calls"] if not c["ok"]]
        self.assertTrue(failed)
        self.assertTrue(all("retry" not in c["call_id"] for c in failed), [c["call_id"] for c in failed])
        rows = [r for rows in res["phase1"]["partials"].values() for r in rows]
        self.assertTrue(all(r["temporal_attempts"] == 1 and r["status"] == "INCOMPLETE" for r in rows))

    def test_a_partial_that_failed_is_made_again_in_the_next_stage(self):
        # Codex review of 6baf2ae, NATIVE-01: a failed partial was kept as done work; a new activity makes it again
        from test_arm_a_langgraph import Flaky

        outage = {"fails": T.RETRY_ATTEMPTS}
        res = self.run_team([Flaky(outage, "reports/early.md") for _ in range(3)])
        early = [r for rows in res["phase2"]["partials"].values() for r in rows if r["report"] == "reports/early.md"]
        self.assertEqual((res["phase1"]["status"], res["phase2"]["status"]), ("INCOMPLETE", "COMPLETE"), res["phase2"])
        self.assertTrue(any(r["made_in_stage"] == 2 and r["status"] == "COMPLETE" for r in early), early)

    def test_each_reduction_counts_its_own_calls_and_an_agent_does_one_piece_at_a_time(self):
        from test_arm_a_langgraph import Busy

        team = [Busy(), Busy(), Busy()]
        res = self.run_team(team)
        self.assertIsNone(res["stopped"])
        self.assertEqual([m.peak for m in team], [1, 1, 1])
        for e in (e for e in res["events"] if e.get("kind") == "ANSWER_REDUCE"):
            self.assertEqual(e["calls"], sum(1 for c in res["calls"] if c["phase"] == e["phase"] and f"-reduce-{e['rq_id']}-" in c["call_id"]), e)

    def test_a_worker_that_dies_after_its_start_stops_the_arm_instead_of_waiting(self):
        # Codex review of 6baf2ae, NATIVE-03: a stage waited for ever on an update no worker would run any more
        import concurrent.futures

        start = T._Runtime.__init__

        def dying(rt, team_size):
            start(rt, team_size)
            dead = concurrent.futures.Future()
            dead.set_exception(RuntimeError("SYNTH_POST_START_WORKER_FATAL"))
            rt.running = dead

        with mock.patch.object(T._Runtime, "__init__", dying):
            res = self.run_team()
        self.assertIn("TEMPORAL_WORKER_STOPPED", res["stopped"])
        self.assertIn("SYNTH_POST_START_WORKER_FATAL", res["stopped"])
        self.assertEqual((res["phase1"]["status"], res["phase2"]["status"]), ("STOPPED", "SKIPPED"))

    def test_a_worker_that_dies_while_a_stage_waits_stops_the_arm(self):
        # NATIVE-03 as Codex met it: the worker dies after the stage's update was sent, while its activities run
        import concurrent.futures
        import threading

        class Slow(P.StubModel):
            def complete(self, prompt: str):
                __import__("time").sleep(0.4)
                return super().complete(prompt)

        start = T._Runtime.__init__

        def dying_later(rt, team_size):
            start(rt, team_size)
            dead = concurrent.futures.Future()
            rt.running = dead
            threading.Timer(1.0, lambda: dead.set_exception(RuntimeError("SYNTH_WORKER_FATAL_DURING_STAGE"))).start()

        with mock.patch.object(T._Runtime, "__init__", dying_later):
            res = self.run_team([Slow(), Slow(), Slow()])
        self.assertIn("SYNTH_WORKER_FATAL_DURING_STAGE", res["stopped"])
        self.assertEqual(res["phase1"]["status"], "STOPPED")

    def test_the_runner_hands_the_team_to_the_workflow_only_under_the_flag(self):
        with mock.patch.object(T, "run", return_value={"arm": "A", "orchestration": {"kind": "temporal-native"}}) as native:
            P.ARM_A_ORCHESTRATION = "temporal-native"
            self.assertEqual(P.run_arm_team([P.StubModel()], dict(R.SYNTH), WITHDRAW, timeout_s=60)["orchestration"]["kind"], "temporal-native")
            native.assert_called_once()


class Flags(unittest.TestCase):
    def test_temporal_native_is_the_teams_single_map_reduce_answer(self):
        saved = {k: v for k, v in vars(P).items() if k.isupper()}
        try:
            with mock.patch.object(sys, "argv", ["run_pilot_ac.py", "--model", "stub", "--arm-a-orchestration", "temporal-native"]):
                with self.assertRaises(SystemExit) as stop:
                    R.main()
            self.assertIn("temporal-native is the team's map-reduce answer", str(stop.exception))
        finally:
            vars(P).update(saved)


if __name__ == "__main__":
    unittest.main()
