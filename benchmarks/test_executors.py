"""The executors that drive an agent's steps (sbgk_bench/executors.py): the runner's threads, LangGraph and Temporal stop at the
same points and give a step's own error back. LangGraph and Temporal are checked where they are installed (the baselines venv);
no model, pilot or provider is executed."""
from __future__ import annotations

import importlib.util
import pathlib
import shutil
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import executors as E  # noqa: E402

HAS_LANGGRAPH = importlib.util.find_spec("langgraph") is not None
HAS_TEMPORAL = importlib.util.find_spec("temporalio") is not None and (
    shutil.which("temporal") or (pathlib.Path.home() / ".local" / "bin" / "temporal.exe").exists())


class Log:
    def __init__(self, active: bool = True):
        self.on = active

    def active(self) -> bool:
        return self.on


def counter(last: int, stop: threading.Event | None = None, stop_at: int | None = None):
    n = [0]

    def step() -> bool:
        n[0] += 1
        if stop is not None and n[0] == stop_at:
            stop.set()
        return n[0] < last

    return n, step


class Drive(unittest.TestCase):
    def check(self, executor: str, last: int = 300) -> None:
        with mock.patch.object(E, "EXECUTOR", executor):
            n, step = counter(last)
            E.drive("w1", step, threading.Event(), Log())
            self.assertEqual(n[0], last, "a step that returns False ends the agent")
            stop = threading.Event()
            n, step = counter(10**6, stop, 7)
            E.drive("w1", step, stop, Log())
            self.assertEqual(n[0], 7, "the run's stop ends it before the next step")
            n, step = counter(5)
            E.drive("w1", step, threading.Event(), Log(active=False))
            self.assertEqual(n[0], 0, "no step once the log is no longer active")
            ran = []
            stop = threading.Event()
            stop.set()
            E.once("lead", lambda: ran.append(1))
            self.assertEqual(ran, [1], "the lead's one step runs whatever the stop state")

            def broken() -> bool:
                raise KeyError("the step's own error")

            with self.assertRaises(KeyError):
                E.drive("w1", broken, threading.Event(), Log())

    def test_threads(self):
        self.check("threads")

    def test_an_unknown_executor_is_refused(self):
        with mock.patch.object(E, "EXECUTOR", "cron"), self.assertRaises(ValueError):
            E.drive("w1", lambda: False, threading.Event(), Log())

    @unittest.skipUnless(HAS_LANGGRAPH, "langgraph is in the baselines venv")
    def test_langgraph_runs_past_its_default_recursion_limit(self):
        self.check("langgraph", last=300)

    @unittest.skipUnless(HAS_TEMPORAL, "temporalio and the Temporal CLI are in the baselines venv")
    def test_temporal_continues_its_history_as_new(self):
        try:
            with mock.patch.object(E, "CONTINUE_EVERY", 100):
                self.check("temporal", last=250)
        finally:
            E.close()
        self.assertEqual(E._runtime, {}, "the worker and the dev server are stopped")


class Steps(unittest.TestCase):
    def test_the_steps_and_their_time_are_counted_per_agent(self):
        with mock.patch.object(E, "EXECUTOR", "threads"), mock.patch.dict(E.STATS, clear=True):
            n, step = counter(4)
            E.drive("C-w1", step, threading.Event(), Log())
            self.assertEqual(E.STATS["C-w1"]["steps"], 4)
            self.assertGreaterEqual(E.STATS["C-w1"]["drive_s"], E.STATS["C-w1"]["step_s"])
            self.assertEqual(E.describe()["agents"]["C-w1"]["steps"], 4)


class StepTimeout(unittest.TestCase):
    def test_the_runner_lets_a_step_last_the_whole_run(self):
        # Codex review of 0dc2164 and 628adb3, EXEC-02: arm A's lead answers every phase in one step, each phase may take its
        # deadline, and the last call sent in it its whole life
        import run_pilot_ac as R
        from sbgk_bench import pilot_ac as P
        saved = {k: v for k, v in vars(P).items() if k.isupper()}
        saved_executor = {k: v for k, v in vars(E).items() if k.isupper()}  # main sets the executor of the run
        seen = []
        steps = {"steps": [{"name": n, "report": "r", "candidates": [{"quote": "q"}]} for n in ("2A", "2B")]}

        def cap(model, *flags):
            seen.clear()
            argv = ["run_pilot_ac.py", "--manifest", "m", "--repo", "r", "--model", "stub", "--team-models", "stub,stub,stub",
                    "--phase-timeout-s", "100", "--executor", "temporal", *flags]
            with (mock.patch.object(sys, "argv", argv), mock.patch.object(R.C, "BIN", pathlib.Path(__file__)),
                  mock.patch.object(R, "corpus_choice", return_value=(["r0.md"], steps, {})),
                  mock.patch.object(P, "make_model", return_value=model),
                  mock.patch.object(R, "run", side_effect=lambda *a, **k: seen.append(E.STEP_TIMEOUT_S) or {"measures": {}}),
                  mock.patch("builtins.print")):
                R.main()
            return seen[0]

        claude = P.ClaudeCliModel(model=P.CLAUDE_HAIKU)  # no call is made
        pauses = sum(2 ** (n + 1) for n in range(P.RETRIES))
        tail = P.ACQUIRE_WAIT_MS / 1000 + P.CYCLE_RPCS * P.RPC_TIMEOUT_S  # an acquire's whole wait and the kernel calls after it
        try:
            # three phases, each with its deadline and then what a step begun before it may still do: the whole life of the last call
            # sent (every attempt at the longest timeout), an acquire's wait, the step's last kernel calls
            self.assertEqual(cap(claude), 3 * (100 + (P.RETRIES + 1) * 900 + pauses + tail), "the default answer timeout, 900 s")
            # Codex review of 628adb3: an answer timeout longer than the drain budget is the life that counts
            self.assertEqual(cap(claude, "--answer-timeout-s", "1800"), 3 * (100 + (P.RETRIES + 1) * 1800 + pauses + tail))
            # Codex review of d80910c, ACQUIRE-01: a stub answers at once, and an acquire begun before a short phase's end still waits
            self.assertEqual(cap(P.StubModel(), "--phase-timeout-s", "0.3"), 3 * (0.3 + 10 + P.CYCLE_RPCS * P.RPC_TIMEOUT_S))
            self.assertEqual(cap(P.StubModel(), "--phase-timeout-s", "0.3", "--acquire-wait-ms", "500"),
                             3 * (0.3 + 0.5 + P.CYCLE_RPCS * P.RPC_TIMEOUT_S), "the shorter wait, the shorter bound")

            class Unknown:
                name, timeout_s = "unknown", 10.0

            with self.assertRaises(SystemExit) as stop:
                cap(Unknown())
            self.assertIn("declares no longest call life", str(stop.exception))
            self.assertEqual(seen, [], "refused before any work")
        finally:
            vars(P).update(saved)
            vars(E).update(saved_executor)

    def test_a_team_of_several_makers_can_run_under_temporal(self):
        # the side on Temporal could not start with a Codex or an Antigravity seat: neither declared its longest call
        from sbgk_bench import pilot_ac as P

        codex, agy = P.CodexModel("gpt-x", "medium", timeout_s=900.0), P.AgyModel("m", timeout_s=240.0)
        self.assertEqual(P.call_life_s([codex], 0.1), 900.0)
        self.assertEqual(P.call_life_s([agy], 0.1), 240.0)
        self.assertEqual(P.call_life_s([codex, agy], 1000.0), 1000.0)

    def test_the_money_brake_counts_the_paid_seats_of_a_mixed_team(self):
        from sbgk_bench import pilot_ac as P

        paid = P.DeepSeekModel.__new__(P.DeepSeekModel)
        codex, agy = P.CodexModel("gpt-x"), P.AgyModel("m")
        self.assertTrue(P.priced_by_the_brake([paid, codex, agy]))
        self.assertFalse(P.priced_by_the_brake([codex, agy]))

    def test_each_adapter_counts_its_own_pauses(self):
        # Codex review of c24763f, EXEC-03: the Gemini CLI pauses 4, 8, ... s between attempts, Claude and DeepSeek 2, 4, ... s
        # (the Gemini CLI is the closed layer's: an adapter with its pauses stands for it here)
        from sbgk_bench import pilot_ac as P

        class SlowPauses:
            def longest_s(self, timeout_s=None):
                return (P.RETRIES + 1) * (self.timeout_s if timeout_s is None else timeout_s) + sum(2 ** (a + 2) for a in range(P.RETRIES))

        gemini = SlowPauses()
        gemini.name, gemini.timeout_s = "gemini", 300.0
        deepseek = P.DeepSeekModel.__new__(P.DeepSeekModel)
        deepseek.name, deepseek.timeout_s = "deepseek", 180.0
        attempts = P.RETRIES + 1
        self.assertEqual(P.call_life_s([gemini], 0.1, 0.1), attempts * 300 + sum(2 ** (n + 2) for n in range(P.RETRIES)))
        self.assertEqual(P.call_life_s([deepseek], 0.1), attempts * 180 + sum(2 ** (n + 1) for n in range(P.RETRIES)))
        self.assertEqual(P.call_life_s([deepseek, gemini], 900.0), attempts * 900 + sum(2 ** (n + 2) for n in range(P.RETRIES)),
                         "the longest timeout in play, at the slowest adapter")

    @unittest.skipUnless(HAS_TEMPORAL, "temporalio and the Temporal CLI are in the baselines venv")
    def test_temporal_stops_a_step_only_past_the_step_timeout(self):
        import time

        def slow() -> bool:
            time.sleep(1.0)
            return False

        try:
            with mock.patch.object(E, "EXECUTOR", "temporal"), mock.patch.object(E, "STEP_TIMEOUT_S", 10.0):
                E.drive("A-lead", slow, threading.Event(), Log())
            with (mock.patch.object(E, "EXECUTOR", "temporal"), mock.patch.object(E, "STEP_TIMEOUT_S", 0.3),
                  self.assertRaises(Exception)):
                E.drive("A-lead", slow, threading.Event(), Log())
        finally:
            E.close()


@unittest.skipUnless(importlib.util.find_spec("temporalio") is not None, "temporalio is in the baselines venv")
class WorkerFailure(unittest.TestCase):
    """Codex review of 0dc2164, EXEC-01: a worker that stops with a fatal error must not leave the agents waiting."""

    def run_with(self, fail_after_start: bool):
        import asyncio

        class Client:
            async def execute_workflow(self, *a, **k):
                await asyncio.Event().wait()  # the workflow never ends by itself

        class Worker:
            def __init__(self, *a, **k):
                self.running = False

            @property
            def is_running(self):
                return self.running

            async def run(self):
                if fail_after_start:
                    self.running = True
                    await asyncio.sleep(0.3)
                raise RuntimeError("synthetic fatal Worker.run failure")

            async def shutdown(self):
                self.running = False

        async def connect(*a, **k):
            return Client()

        with (mock.patch("temporalio.client.Client.connect", side_effect=connect), mock.patch("temporalio.worker.Worker", Worker),
              mock.patch.object(E, "TEMPORAL_ADDRESS", "127.0.0.1:1"), mock.patch.object(E, "EXECUTOR", "temporal")):
            try:
                E.drive("C-w1", lambda: True, threading.Event(), Log())
            finally:
                E.close()

    def test_a_fatal_error_after_the_start_reaches_the_waiting_agent(self):
        with self.assertRaisesRegex(RuntimeError, "TEMPORAL_WORKER_STOPPED.*synthetic fatal"):
            self.run_with(fail_after_start=True)
        self.assertEqual(E._runtime, {})

    def test_a_worker_that_never_runs_is_not_reported_ready(self):
        with self.assertRaisesRegex(RuntimeError, "synthetic fatal"):
            self.run_with(fail_after_start=False)
        self.assertEqual(E._runtime, {})


if __name__ == "__main__":
    unittest.main()
