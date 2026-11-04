"""The owner's export window after a terminal phase (run MCPpair_r1: with 2 850 records every acquire re-planned the circle, 8 s of
the kernel's lock each, and four agents polling every 0.2 s left the owner's hundreds of small reads waiting behind them; the
stalled export also counted against the phase-1 deadline). While the window is open the idle agents poll once in EXPORT_POLL_S
and stay present; the next withdrawal wakes them at once; a stop ends a pause at once; the export runs without the finished
phase's deadline. In-process fakes only: no provider, no kernel process, no network."""
from __future__ import annotations

import pathlib
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P  # noqa: E402


class Idle:
    """A kernel with nothing to hand out: every poll answers `status`, and its time is kept."""

    def __init__(self, tool, status):
        self.tool, self.status, self.times = tool, status, []

    def call(self, tool, **kw):
        assert tool == self.tool, tool
        self.times.append(time.monotonic())
        return {"status": self.status}

    def close(self):
        pass


def polling(fn, wire, log, stop):
    agent = ("w1",) if fn in (P.c_worker, P.c_whole_worker) else ()
    whole = ({},) if fn is P.c_whole_worker else ()
    thread = threading.Thread(target=fn, args=(SimpleNamespace(connect=lambda a: wire), *agent, SimpleNamespace(name="unused"), log, [1],
                                               stop, *whole), daemon=True)
    thread.start()
    return thread


def closed_after_choosing(first_only: bool = True):
    """idle_pause as the owner may interleave it: the long export pause is chosen, then the window closes before the wait."""
    real, calls = P.idle_pause, []

    def pause(log, usual):
        seconds = real(log, usual)
        calls.append(seconds)
        if log.exporting.is_set() and (len(calls) == 1 or not first_only):
            log.exporting.clear()
            with log.lock:
                log.wake_gen += 1
        return seconds

    return pause, calls


class IdleAgentsDuringExport(unittest.TestCase):
    def check(self, fn, tool, status, usual):
        with mock.patch.object(P, "EXPORT_POLL_S", 0.8):
            # outside the window: the usual pause
            wire, log, stop = Idle(tool, status), P.Log(), threading.Event()
            thread = polling(fn, wire, log, stop)
            time.sleep(1.0)
            stop.set()
            thread.join(1.0)
            self.assertGreaterEqual(len(wire.times), int(0.8 / usual), "the usual pace outside an export window")
            # inside it: one poll in EXPORT_POLL_S
            wire, log, stop = Idle(tool, status), P.Log(), threading.Event()
            log.exporting.set()
            thread = polling(fn, wire, log, stop)
            time.sleep(2.0)
            self.assertLessEqual(len(wire.times), 3, wire.times)
            gaps = [b - a for a, b in zip(wire.times, wire.times[1:])]
            self.assertTrue(gaps and all(0.7 < g < 1.1 for g in gaps), gaps)
            # the next phase begins: the agent polls at once and at the usual pace again
            log.exporting.clear()
            with log.lock:
                log.wake_gen += 1
            woke = time.monotonic()
            time.sleep(0.6)
            after = [t for t in wire.times if t > woke]
            self.assertTrue(after and after[0] - woke < 0.35, (woke, wire.times[-4:]))
            self.assertGreaterEqual(len(after), 2, "the usual pace after the window")
            stop.set()
            thread.join(1.0)
            self.assertFalse(thread.is_alive())

    def test_a_reader_polls_rarely_while_the_owner_exports_and_wakes_at_the_next_phase(self):
        self.check(P.c_worker, "audit_acquire", "COMPLETE", 0.2)

    def test_the_graph_builder_polls_rarely_while_the_owner_exports(self):
        self.check(P.c_builder, "audit_next_card", "CAUGHT_UP", 0.1)

    def test_the_pause_stays_below_half_the_kernels_readiness_timeout(self):
        log = P.Log()
        log.exporting.set()
        self.assertLessEqual(P.idle_pause(log, 0.2), P.AGENT_TIMEOUT_S / 2)
        with mock.patch.object(P, "AGENT_TIMEOUT_S", 100.0):
            self.assertEqual(P.idle_pause(log, 0.2), 40.0)
        log.exporting.clear()
        self.assertEqual(P.idle_pause(log, 0.2), 0.2)

    def test_a_stop_ends_a_long_pause_at_once(self):
        wire, log, stop = Idle("audit_acquire", "COMPLETE"), P.Log(), threading.Event()
        log.exporting.set()
        thread = polling(P.c_worker, wire, log, stop)
        time.sleep(0.5)  # now in a pause of EXPORT_POLL_S (120 s)
        stopped = time.monotonic()
        stop.set()
        thread.join(2.0)
        self.assertFalse(thread.is_alive())
        self.assertLess(time.monotonic() - stopped, 0.5)
        self.assertEqual(len(wire.times), 1)


class WindowClosedBetweenPauseAndWait(unittest.TestCase):
    """Codex review EXPORT-01 of 7284c65: the long pause was chosen in the window, the owner closed it and moved the generation,
    and only then did the wait read the generation, sleeping the whole pause into the next phase."""

    def test_the_wait_ends_at_once(self):
        log, stop = P.Log(), threading.Event()
        log.exporting.set()
        pause, calls = closed_after_choosing()
        with mock.patch.object(P, "EXPORT_POLL_S", 5.0), mock.patch.object(P, "idle_pause", side_effect=pause):
            started = time.monotonic()
            P.idle_wait(log, stop, 0.2)
        self.assertEqual(calls, [5.0], "the export pause was chosen")
        self.assertLess(time.monotonic() - started, 0.35)

    def check(self, fn, tool, status):
        wire, log, stop = Idle(tool, status), P.Log(), threading.Event()
        log.exporting.set()
        pause, calls = closed_after_choosing()
        with mock.patch.object(P, "EXPORT_POLL_S", 5.0), mock.patch.object(P, "idle_pause", side_effect=pause):
            thread = polling(fn, wire, log, stop)
            time.sleep(0.6)
            stop.set()
            thread.join(1.0)
        self.assertFalse(thread.is_alive())
        self.assertEqual(calls[0], 5.0)
        self.assertGreaterEqual(len(wire.times), 2, "the next poll must come at once, not after the export pause")
        self.assertLess(wire.times[1] - wire.times[0], 0.35, wire.times)

    def test_a_reader(self):
        self.check(P.c_worker, "audit_acquire", "COMPLETE")

    def test_the_whole_reader(self):
        self.check(P.c_whole_worker, "audit_acquire", "COMPLETE")

    def test_the_graph_builder(self):
        self.check(P.c_builder, "audit_next_card", "CAUGHT_UP")


class OwnerOpensAndClosesTheWindow(unittest.TestCase):
    def run_c(self, revoked: dict, export_s: float = 0.0, timeout_s: float = 1800) -> tuple[list, list, P.Log]:
        seen, logs = [], []

        class Owner:
            def call(self, tool, **kw):
                return revoked if tool == "audit_revoke" else {}

            def close(self):
                pass

        kernel = SimpleNamespace(connect=lambda role: Owner(), hello={"status": "listening"}, stop=lambda: None)

        def terminal(own, log, timeout):
            logs.append(log)
            seen.append(("wait", log.exporting.is_set(), log.wake_gen))
            # as c_until_terminal: a log no longer active ends the phase STOPPED
            return {"status": "TERMINAL", "outcomes": {}} if log.active() else {"status": "STOPPED", "reason": log.stopped}

        def answers(own, receipt, *args):
            seen.append(("export", logs[-1].exporting.is_set(), logs[-1].wake_gen))
            time.sleep(export_s)
            logs[-1].active()  # as a polling agent would ask meanwhile
            return {}

        steps = {"steps": [{"name": "2A", "report": "r", "candidates": [{"quote": "q"}]},
                           {"name": "2B", "report": "r", "candidates": [{"quote": "q"}]}]}
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
            P.run_arm_c(SimpleNamespace(), SimpleNamespace(), pathlib.Path(name) / "work", manifest, pathlib.Path(name), [], {}, steps,
                        workers=1, timeout_s=timeout_s)
        windows = [(e["phase"], e["outcome"]) for e in logs[-1].events if e.get("kind") == "EXPORT_WINDOW"]
        return seen, windows, logs[-1]

    def test_the_window_covers_each_export_but_the_last_and_closes_before_each_withdrawal_is_waited_for(self):
        seen, windows, _ = self.run_c({"status": "REVOKED"})
        self.assertEqual(seen, [("wait", False, 0), ("export", True, 0),
                                ("wait", False, 1), ("export", True, 1),
                                ("wait", False, 2), ("export", False, 2)])
        self.assertEqual(windows, [(1, "OPEN"), (2, "CLOSED"), (2, "OPEN"), (3, "CLOSED")], "the windows are in the run's events")

    def test_an_export_longer_than_the_phase_deadline_does_not_stop_the_run(self):
        seen, _, log = self.run_c({"status": "REVOKED"}, export_s=0.5, timeout_s=0.3)
        self.assertIsNone(log.stopped)
        self.assertEqual([s[0] for s in seen], ["wait", "export"] * 3, "both withdrawals ran")

    def test_a_refused_withdrawal_closes_the_window_with_the_run(self):
        seen, windows, log = self.run_c({"status": "error", "error": {"code": "REFUSED"}})
        self.assertEqual(seen, [("wait", False, 0), ("export", True, 0)])
        self.assertEqual(windows, [(1, "OPEN"), (2, "CLOSED")])
        self.assertFalse(log.exporting.is_set())
        self.assertIn("WITHDRAWAL_REFUSED", log.stopped)


if __name__ == "__main__":
    unittest.main()
