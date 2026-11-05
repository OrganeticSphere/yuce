"""Arm A as a LangGraph-native team (a run with LangGraph's own checkpoints and native means, for a real
comparison with LangGraph): the stub team on the synthetic corpus. No provider is called; skipped without langgraph (the system
Python), run in the baselines venv."""
from __future__ import annotations

import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import run_pilot_ac as R  # noqa: E402
from sbgk_bench import pilot_ac as P  # noqa: E402

try:
    import langgraph  # noqa: F401

    from sbgk_bench import arm_a_langgraph as L  # noqa: E402
except ImportError:
    L = None

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


class Flaky(P.StubModel):
    """The team's models sharing one outage: the first `fails` partial answers of `report` to RQ1 fail, whichever agent sends them."""

    def __init__(self, outage: dict, report: str):
        super().__init__()
        self.outage, self.report = outage, report

    def complete(self, prompt: str):
        if (prompt.startswith("ARM A TEAM") and f"  {self.report}\n" in prompt and "\nQUESTION RQ1:" in prompt
                and self.outage["fails"] > 0):
            self.outage["fails"] -= 1
            raise RuntimeError("provider down")
        return super().complete(prompt)


class Busy(P.StubModel):
    """A stub that records how many calls it serves at once (an agent should do one piece of work at a time)."""

    def __init__(self):
        super().__init__()
        self.now = self.peak = 0
        self.guard = __import__("threading").Lock()

    def complete(self, prompt: str):
        with self.guard:
            self.now += 1
            self.peak = max(self.peak, self.now)
        try:
            __import__("time").sleep(0.02)
            return super().complete(prompt)
        finally:
            with self.guard:
                self.now -= 1


@unittest.skipIf(L is None, "langgraph is not installed (run in the baselines venv)")
class LangGraphNativeTeam(unittest.TestCase):
    def setUp(self):
        self.saved = {k: v for k, v in vars(P).items() if k.isupper()}
        self.saved_l = {k: v for k, v in vars(L).items() if k.isupper()}
        P.ARM_A_ANSWER = "map-reduce"

    def tearDown(self):
        vars(P).update(self.saved)
        vars(L).update(self.saved_l)

    def run_team(self, team=None, withdraw=WITHDRAW):
        return L.run(team or [P.StubModel(), P.StubModel(), P.StubModel()], dict(R.SYNTH), withdraw, timeout_s=120)

    def test_the_team_answers_every_stage_from_its_checkpointed_graph(self):
        res = self.run_team()
        self.assertIsNone(res["stopped"])
        for phase in ("phase1", "phase2"):
            self.assertEqual(res[phase]["status"], "COMPLETE", res[phase])
            self.assertEqual(set(res[phase]["answers"]), {q["id"] for q in P.QUESTIONS})
        cited = lambda ph: {q["quote"] for a in res[ph]["answers"].values() for c in a["claims"] for q in c["quotes"]}  # noqa: E731
        self.assertIn(GONE, cited("phase1"))
        self.assertNotIn(GONE, cited("phase2"), "the withdrawn quote is dropped")
        o = res["orchestration"]
        self.assertEqual((o["kind"], o["checkpointer"], o["max_concurrency"]), ("langgraph-native", "memory", 3))
        self.assertGreater(o["checkpoints"], 5, "a checkpoint after every superstep")
        self.assertGreater(res["phase1"]["notes_lines"], 0)

    def test_the_sqlite_checkpointer_keeps_every_checkpoint_on_disk(self):
        try:
            import langgraph.checkpoint.sqlite  # noqa: F401
        except ImportError:
            self.skipTest("langgraph-checkpoint-sqlite is not installed")
        import sqlite3
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            L.CHECKPOINTER, L.CHECKPOINT_DB = "sqlite", str(pathlib.Path(tmp) / "arm_a_langgraph.sqlite")
            res = self.run_team()
            self.assertEqual((res["phase2"]["status"], res["orchestration"]["checkpointer"]), ("COMPLETE", "sqlite"))
            conn = sqlite3.connect(L.CHECKPOINT_DB)
            try:
                stored = conn.execute("SELECT COUNT(*) FROM checkpoints WHERE thread_id = ?", (L.THREAD_ID,)).fetchone()[0]
            finally:
                conn.close()
            self.assertEqual(stored, res["orchestration"]["checkpoints"], "every checkpoint of the run is on disk")

    def test_a_withdrawal_remakes_only_the_partials_it_changes(self):
        res = self.run_team()
        reports = list(R.SYNTH)
        self.assertEqual(res["phase1"]["partials_reused"], 0)
        # the withdrawal changes the prompt of later.md's partials only: earlier.md's come from the checkpointed state
        self.assertEqual(res["phase2"]["partials_reused"], len(P.QUESTIONS) * (len(reports) - 1))
        for rows in res["phase2"]["partials"].values():
            made = {r["report"]: r["made_in_stage"] for r in rows}
            self.assertEqual(made["reports/later.md"], 2)
            self.assertTrue(all(stage == 1 for report, stage in made.items() if report != "reports/later.md"), made)
        update = [c for c in res["calls"] if c["role"] == "UPDATE"]
        self.assertEqual(len(update), 2 * len(P.QUESTIONS), "one partial and one reduction per question")

    def test_langgraph_retries_a_failed_reading_and_counts_every_attempt(self):
        res = self.run_team([Failing("ARM A WORKER", 1), P.StubModel(), P.StubModel()])
        self.assertIsNone(res["stopped"])
        self.assertEqual(res["phase1"]["status"], "COMPLETE")
        workers = [c for c in res["calls"] if c["role"] == "WORKER"]
        self.assertEqual(sum(not c["ok"] for c in workers), 1)
        self.assertTrue(any("-lg-retry-1" in c["call_id"] and c["ok"] for c in workers), [c["call_id"] for c in workers])

    def test_a_reading_that_fails_past_its_retries_stops_the_arm_visibly(self):
        res = self.run_team([Failing("ARM A WORKER", 10), P.StubModel(), P.StubModel()])
        self.assertTrue(res["stopped"].startswith("MODEL_ERROR"), res["stopped"])
        self.assertEqual(res["phase1"]["status"], "STOPPED")
        self.assertEqual(res["phase2"]["status"], "SKIPPED")

    def test_a_partial_that_fails_past_its_retries_is_incomplete_and_the_arm_goes_on(self):
        res = self.run_team([P.StubModel(), Failing("ARM A TEAM", 100), P.StubModel()])
        self.assertIsNone(res["stopped"])
        rows = [r for rows in res["phase1"]["partials"].values() for r in rows]
        self.assertTrue(any(r["status"] != "COMPLETE" and r["lg_attempts"] == L.RETRY_ATTEMPTS for r in rows), rows)
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
        self.assertTrue(all(r["lg_attempts"] == 1 and r["status"] == "INCOMPLETE" for r in rows))

    def test_a_partial_that_failed_is_made_again_in_the_next_stage(self):
        # Codex review of 70e8d31, NATIVE-01: early.md's partial failed twice in stage 1, the provider recovered, and stage 2 kept
        # the failure as done work; only a COMPLETE partial is kept, the other is made again with a fresh budget of attempts
        outage = {"fails": L.RETRY_ATTEMPTS}
        res = self.run_team([Flaky(outage, "reports/early.md") for _ in range(3)])
        early = lambda ph: [r for rows in res[ph]["partials"].values() for r in rows if r["report"] == "reports/early.md"]  # noqa: E731
        self.assertEqual(res["phase1"]["status"], "INCOMPLETE")
        self.assertTrue(any(r["status"] != "COMPLETE" for r in early("phase1")))
        self.assertEqual(res["phase2"]["status"], "COMPLETE", res["phase2"])
        self.assertTrue(all(r["status"] == "COMPLETE" and r["made_in_stage"] == 2 for r in early("phase2")
                            if r["made_in_stage"] == 2) and any(r["made_in_stage"] == 2 for r in early("phase2")), early("phase2"))

    def test_each_reduction_counts_its_own_calls(self):
        # Codex review of 70e8d31, NATIVE-02: two reductions at once counted each other's calls
        res = self.run_team()
        for e in (e for e in res["events"] if e.get("kind") == "ANSWER_REDUCE"):
            own = sum(1 for c in res["calls"] if c["phase"] == e["phase"] and f"-reduce-{e['rq_id']}-" in c["call_id"])
            self.assertEqual(e["calls"], own, e)

    def test_an_agent_does_one_piece_of_work_at_a_time(self):
        team = [Busy(), Busy(), Busy()]
        res = self.run_team(team)
        self.assertIsNone(res["stopped"])
        self.assertEqual([m.peak for m in team], [1, 1, 1])

    def test_the_runner_hands_the_team_to_the_graph_only_under_the_flag(self):
        with mock.patch.object(L, "run", return_value={"arm": "A", "orchestration": {"kind": "langgraph-native"}}) as native:
            P.ARM_A_ORCHESTRATION = "langgraph-native"
            self.assertEqual(P.run_arm_team([P.StubModel()], dict(R.SYNTH), WITHDRAW, timeout_s=60)["orchestration"]["kind"],
                             "langgraph-native")
            native.assert_called_once()
            P.ARM_A_ORCHESTRATION = "runner"
            self.assertNotIn("orchestration", P.run_arm_team([P.StubModel()], dict(R.SYNTH), WITHDRAW, timeout_s=60))
            native.assert_called_once()


class Flags(unittest.TestCase):
    def main(self, *flags):
        saved = {k: v for k, v in vars(P).items() if k.isupper()}
        try:
            with mock.patch.object(sys, "argv", ["run_pilot_ac.py", "--model", "stub", *flags]):
                with self.assertRaises(SystemExit) as stop:
                    R.main()
            return str(stop.exception)
        finally:
            vars(P).update(saved)

    def test_langgraph_native_is_the_teams_single_map_reduce_answer(self):
        for flags in ([], ["--team-models", "stub,stub,stub"], ["--team-models", "stub,stub,stub", "--arm-a-answer", "map-reduce",
                                                                 "--arm-a-reduce", "tree"]):
            self.assertIn("is the team's map-reduce answer", self.main("--arm-a-orchestration", "langgraph-native", *flags), flags)
        self.assertIn("goes with --arm-a-orchestration langgraph-native", self.main("--lg-checkpointer", "sqlite"))


if __name__ == "__main__":
    unittest.main()
