"""Arm A as a Temporal-native team (the owner, 2026-10-30, on the LangGraph-native team: the same for Temporal before its run). The
same agents, models, prompt templates and checks as the runner's team arm with --arm-a-answer map-reduce (the prompts actually sent
differ where the orchestration does; every call keeps its context and prompt hash), built the way a Temporal application is built:

- the team is one workflow (temporal_team.ArmATeam); its state, the shared notes, each report's notes and the partial answers, lives
  in the workflow, and its history is the durable record: the run's own dev server keeps it in a SQLite file (TEMPORAL_DB). The
  activities use the run's log and models in this process, so this runner does not resume a team after a process restart;
- every model call is an activity with Temporal's RetryPolicy (RETRY_ATTEMPTS attempts, each one counted by the run's log, call cap
  and budget, its call id marked with the attempt); a reading or a reduction that fails on its last attempt stops the arm visibly
  through an activity, a partial answer that does is recorded INCOMPLETE, as in the runner's team arm;
- reading: the workflow runs the next sections as parallel activities, one per agent, each with the notes so far; answering: one
  activity per (question, report), each taken by a free agent of the team, and the lead's reductions one after another; the worker
  runs at most len(team) activities at a time, and the stage's wait watches the worker, so a worker that dies stops the arm;
- each stage is a workflow update: the first reads and answers, each withdrawal step sends the withdrawn quotes and gets the new
  answers back; a COMPLETE partial whose prompt the withdrawal leaves unchanged is the workflow's own state, every other partial is
  made again by a new activity.

The kernel is not used: this is the team without the kernel, orchestrated by Temporal alone."""
from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import os
import queue
import shutil
import subprocess
import threading
import time
import uuid

from . import answer_map_reduce as M
from . import executors as E
from . import pilot_ac as P

RETRY_ATTEMPTS = 2
TEMPORAL_DB: str | None = None  # the dev server's SQLite file (durable history); None: an in-memory dev server
TASK_QUEUE = "r2r-arm-a-team"


class TeamRun:
    """The activities' side of one team: the run's log, models and reports (activities run in this process's worker)."""

    def __init__(self, log: "P.Log", team: list, docs: dict[str, str], secs: list):
        self.log, self.team, self.docs, self.secs = log, team, docs, secs
        # the team's agents as a pool: a partial takes a free agent, so an agent does one piece of work at a time; the lead reduces
        # alone (Codex review of 70e8d31/6baf2ae: round-robin names let one agent run several pieces at once)
        self.agents: queue.Queue = queue.Queue()
        for w in range(1, len(team) + 1):
            self.agents.put(w)
        self.lead = threading.Lock()

    def read(self, i: int, w: int, notes: list[str], attempt: int) -> dict:
        path, rng = self.secs[i]
        prompt, context, call_id = P.worker_call(w, notes, self.docs, path, rng)
        c = self.log.invoke(self.team[w - 1], prompt, call_id=call_id if attempt == 1 else f"{call_id}-tmp-retry-{attempt - 1}", arm="A",
                            role="WORKER", phase=1, context=dict(context, temporal_attempt=attempt))
        if c is None:
            return {"report": path, "lines": [], "inactive": True}
        if not c.ok:
            if attempt < RETRY_ATTEMPTS and self.log.active():
                raise RuntimeError(f"MODEL_ERROR: {c.error}")  # Temporal retries the activity
            return {"report": path, "lines": [], "failed": f"MODEL_ERROR: {c.error}"}
        return {"report": path, "lines": [ln for ln in c.text.splitlines() if ln.strip()]}

    def partial(self, payload: dict, attempt: int) -> dict:
        q, report, stage = payload["q"], payload["report"], payload["stage"]
        w = self.agents.get()
        try:
            name = f"w{w}" if attempt == 1 else f"w{w}-tmp-retry-{attempt - 1}"
            row, part = M.partial(self.log, self.team[w - 1], self.docs, payload["withdrawn"], q, stage, P.TEAM_RULES, name,
                                  "LEAD" if stage == 1 else "UPDATE", dict(payload["context"], agent=f"w{w}", temporal_attempt=attempt),
                                  {report: payload["notes"]}, report)
        finally:
            self.agents.put(w)
        if (row.get("answer") or {}).get("outcome") == "not_answered" and attempt < RETRY_ATTEMPTS and self.log.active():
            raise RuntimeError(f"MODEL_ERROR: {row['answer'].get('error')}")
        # the row counts the calls of its last attempt; every attempt of this stage is counted here (Codex review of 70e8d31)
        digest = hashlib.sha256(report.encode()).hexdigest()[:16]
        row["calls_all_attempts"] = sum(1 for c in list(self.log.calls) if c.call_id.startswith(f"A{stage}-")
                                        and f"-map-{digest}-{q['id']}-" in c.call_id)
        return {"row": row, "part": part, "attempts": attempt}

    def reduce(self, payload: dict, attempt: int) -> dict:
        q, stage = payload["q"], payload["stage"]
        name = "lead" if attempt == 1 else f"lead-tmp-retry-{attempt - 1}"
        with self.lead:
            ans = M.reduce(self.log, self.team[0], self.docs, payload["withdrawn"], q, stage, name, "LEAD" if stage == 1 else "UPDATE",
                           dict(payload["context"], temporal_attempt=attempt), payload["parts"], payload["rows"], stop_on_model_error=False)
        if ans is not None and ans.get("outcome") == "not_answered":
            if attempt < RETRY_ATTEMPTS and self.log.active():
                raise RuntimeError(f"MODEL_ERROR: {ans.get('error')}")
            return {"failed": f"MODEL_ERROR: {ans.get('error')}"}
        return {"answer": ans}

    def stop(self, reason: str) -> None:
        if not self.log.stopped:
            self.log.fail(reason, arm="A")


class _Runtime:
    """This team's own dev server (with its SQLite history file when TEMPORAL_DB is set), client and worker."""

    def __init__(self, team_size: int):
        from concurrent.futures import ThreadPoolExecutor

        from temporalio.client import Client
        from temporalio.worker import UnsandboxedWorkflowRunner, Worker

        from .temporal_team import ArmATeam, partial_activity, read_activity, reduce_activity, stop_activity

        self.server = self.loop = self.worker = self.pool = self.running = None
        try:
            exe = shutil.which("temporal") or os.path.join(os.path.expanduser("~"), ".local", "bin", "temporal.exe")
            port, ui = E._free_port(), E._free_port()
            args = [exe, "server", "start-dev", "--ip", "127.0.0.1", "--port", str(port), "--ui-port", str(ui), "--headless", "--log-level", "warn"]
            if TEMPORAL_DB:
                args += ["--db-filename", TEMPORAL_DB]
            self.server = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.loop = asyncio.new_event_loop()
            threading.Thread(target=self.loop.run_forever, name="temporal-team-loop", daemon=True).start()

            async def connect():
                deadline = time.monotonic() + 60
                while True:
                    try:
                        return await Client.connect(f"127.0.0.1:{port}")
                    except Exception:
                        if time.monotonic() > deadline:
                            raise
                        await asyncio.sleep(0.5)

            self.client = self.call(connect(), 90)
            self.pool = ThreadPoolExecutor(max_workers=team_size + 2, thread_name_prefix="temporal-team")
            self.worker = Worker(self.client, task_queue=TASK_QUEUE, workflows=[ArmATeam],
                                 activities=[read_activity, partial_activity, reduce_activity, stop_activity], activity_executor=self.pool,
                                 workflow_runner=UnsandboxedWorkflowRunner(), max_concurrent_activities=team_size)
            self.running = asyncio.run_coroutine_threadsafe(self.worker.run(), self.loop)
            deadline = time.monotonic() + 60
            while not self.worker.is_running:
                if self.running.done():
                    self.running.result()
                    raise RuntimeError("TEMPORAL_WORKER_NOT_STARTED: run() returned before the worker ran")
                if time.monotonic() > deadline:
                    raise RuntimeError("TEMPORAL_WORKER_NOT_STARTED: no start within 60 s")
                time.sleep(0.05)
        except BaseException:
            self.close()
            raise

    def call(self, coro, timeout: float | None = None):
        """Run `coro` on the team's loop and wait for it, or for the worker to stop: a worker that dies after its start runs no
        update and no activity any more, so a stage waiting on it gets the worker's error instead of waiting for ever (Codex review
        of 6baf2ae, NATIVE-03); the pending call is cancelled."""
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        watched = [future] + ([self.running] if getattr(self, "running", None) is not None else [])
        done, _ = concurrent.futures.wait(watched, timeout=timeout, return_when=concurrent.futures.FIRST_COMPLETED)
        if future in done:
            return future.result()
        future.cancel()
        if not done:
            raise TimeoutError(f"no answer within {timeout} s")
        cause = self.running.exception() if not self.running.cancelled() else None
        raise RuntimeError(f"TEMPORAL_WORKER_STOPPED: {type(cause).__name__ if cause else 'stopped'}: {cause}") from cause

    def close(self) -> None:
        if self.loop is not None and self.worker is not None:
            try:
                self.call(self.worker.shutdown(), 60)
            except Exception:
                pass
        if self.pool is not None:
            # a model call an activity began finishes (each one is bounded by its adapter) before the run's log is read: a worker
            # that died leaves its activity threads running, and the log refuses to report unfinished invocations
            self.pool.shutdown(wait=True)
        if self.loop is not None:
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self.server is not None:
            self.server.terminate()
            try:
                self.server.wait(30)
            except subprocess.TimeoutExpired:
                self.server.kill()


def _record(out: dict, stage: int, log: "P.Log", t0: float) -> dict:
    answers = out.get("answers") or {}
    partials = {rq: [dict(r["row"], made_in_stage=r["stage"], temporal_attempts=r["attempts"]) for r in rows]
                for rq, rows in (out.get("partials") or {}).items()}
    status, reason = P.answers_status(answers, log)
    return {"answers": answers, "partials": partials, "partials_reused": sum(r["made_in_stage"] != stage for rows in partials.values() for r in rows),
            "wall_s": time.monotonic() - t0, "status": status, "reason": reason}


def run(team: list, docs: dict[str, str], withdraw: dict, timeout_s: float = 1800, *, evidence=None, max_calls: int = P.MAX_CALLS,
        budget=None, chosen: list[dict] | None = None) -> dict:
    """Arm A as the Temporal-native team: phase 1 and each withdrawal step, recorded as the runner's team arm records them."""
    import importlib.metadata

    from . import temporal_team as T

    if not team or timeout_s <= 0:
        raise ValueError("a team and a positive phase timeout are needed")
    log = P.Log(max_calls, evidence, time.monotonic() + timeout_s)
    log.budget = budget
    secs = [(path, rng) for path, text in docs.items() for rng in P.sections(text, P.SECTION_BYTES)]
    key = f"arm-a-{uuid.uuid4().hex}"
    T.RUNS[key] = TeamRun(log, team, docs, secs)
    # an activity may last as long as its phase lets a call sent before the deadline live, its repairs and timeout retries included
    activity_timeout_s = timeout_s + (P.SUMMARY_REPAIRS + 1) * (P.ANSWER_TIMEOUT_RETRIES + 1) * P.call_life_s(team, P.ANSWER_TIMEOUT_S)
    res = {"arm": "A", "mode": "team", "team": [m.name for m in team], "answer_strategy": "map-reduce", "phase1": {"answers": {}},
           "orchestration": {"kind": "temporal-native", "temporalio": importlib.metadata.version("temporalio"),
                             "history": "sqlite file" if TEMPORAL_DB else "in memory", "max_concurrent_activities": len(team),
                             "retry_attempts": RETRY_ATTEMPTS, "sections": len(secs), "activity_timeout_s": activity_timeout_s}}
    rt = None
    try:
        rt = _Runtime(len(team))
        cfg = {"key": key, "sections": len(secs), "team_size": len(team), "questions": P.QUESTIONS, "reports": list(docs),
               "retry_attempts": RETRY_ATTEMPTS, "activity_timeout_s": activity_timeout_s}
        try:
            handle = rt.call(rt.client.start_workflow("R2RArmATeam", cfg, id=f"r2r-{key}", task_queue=TASK_QUEUE), 60)
        except Exception as e:  # the worker died before the team's workflow could start: the same visible stop
            handle = None
            log.fail(f"TEMPORAL_ERROR: {type(e).__name__}: {e}", arm="A")

        def stage(req: dict) -> dict | None:
            if handle is None:
                return None
            try:
                return rt.call(handle.execute_update("stage", req))
            except Exception as e:  # an activity failed past its last attempt: a visible stop
                if not log.stopped:
                    log.fail(f"TEMPORAL_ERROR: {type(e).__name__}: {e}", arm="A")
                return None

        t0 = time.monotonic()
        out = stage({"stage": 1, "withdrawn": []}) or {}
        res["phase1"] = dict(_record(out, 1, log, t0), notes_lines=out.get("notes_lines", 0))
        if res["phase1"]["status"] == "STOPPED":
            res["phase2"] = P.skipped_phase("PHASE1_STOPPED")
        elif withdraw:
            steps = P.withdrawal_steps(withdraw)
            texts = chosen or [{"step": s["name"], "report": s["report"], **s["candidates"][0]} for s in steps]
            so_far: list[dict] = []
            for n, (step, text) in enumerate(zip(steps, texts), start=2):
                k = f"phase{n}"
                if res[f"phase{n - 1}"].get("status") == "STOPPED":
                    res[k] = P.skipped_phase("PREVIOUS_PHASE_STOPPED")
                    continue
                log.deadline = time.monotonic() + timeout_s
                t1 = time.monotonic()
                so_far.append({"report": text["report"], "quote": text["quote"]})
                out = stage({"stage": n, "withdrawn": list(so_far)}) or {}
                res[k] = dict(_record(out, n, log, t1), step=step["name"])
        else:
            res["phase2"] = P.skipped_phase("NO_WITHDRAWAL")
        try:
            if handle is None:
                raise RuntimeError("no workflow was started")
            rt.call(handle.signal("finish"), 60)
            rt.call(handle.result(), 120)
            res["orchestration"]["history_events"] = len(rt.call(handle.fetch_history(), 120).events)
        except Exception as e:  # a worker that stopped cannot close the workflow: the arm already stopped visibly in its stage
            res["orchestration"]["finish_error"] = f"{type(e).__name__}: {e}"
            if not log.stopped:
                log.fail(f"TEMPORAL_ERROR: {type(e).__name__}: {e}", arm="A")
    finally:
        if rt is not None:
            rt.close()
        T.RUNS.pop(key, None)
    res.update(log.result())
    return res
