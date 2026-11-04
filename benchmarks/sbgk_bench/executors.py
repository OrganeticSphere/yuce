"""Who drives an agent's loop: the runner's own threads, LangGraph or Temporal (the orchestration baselines of the v0.1 release
plan: the executor x the kernel on or off, the same corpus, agents, prompts and checks).

An agent is a step function, one acquire of the agent and the task it got (`c_worker`'s `cycle`), that returns False when the agent
is done. `drive` runs it until then, or until the run stops:

- threads: a plain loop in the agent's thread, as before;
- langgraph: a LangGraph StateGraph of one node, the step, whose conditional edge loops back to it until the step returns False;
  LangGraph runs every step as a superstep of the agent's graph (no checkpointer: an in-memory run);
- temporal: a Temporal workflow per agent that runs the step as an activity and loops on its result, on a local dev server
  (`temporal server start-dev`, in memory) and an in-process worker; the history is continued as new every CONTINUE_EVERY steps
  (an idle agent polls thousands of times a phase). The workflow code only sequences activities, so it runs unsandboxed.

The kernel arm's coordination stays the kernel's: the executor only decides when the agent's next step runs. The steps, prompts,
models and the log are the same in all three."""
from __future__ import annotations

import asyncio
import atexit
import concurrent.futures
import os
import shutil
import socket
import subprocess
import threading
import time
import uuid
from typing import Callable, TypedDict

EXECUTOR = "threads"
EXECUTORS = ("threads", "langgraph", "temporal")
TEMPORAL_ADDRESS: str | None = None  # None: start a local dev server for the run
TEMPORAL_QUEUE = "r2r-agents"
CONTINUE_EVERY = 2000
# A Temporal step may last as long as the runner lets the whole run last (every phase with its deadline and then the whole life of
# the last call sent, pilot_ac.call_life_s): Temporal's own timeout must never stop a step the runner's threads would let finish
# (Codex review of 0dc2164 and 628adb3, EXEC-02: one 6 h activity held all of arm A's lead phases, each of which may take 6 h,
# and a call's life may exceed the drain budget). The runner sets it from its flags and models.
STEP_TIMEOUT_S = 6 * 3600.0
# The agents the executor drives (the kernel arm's dynamic-role workers, arm A's readers and team lead), not the dedicated builder
# or refiner, the whole reader or the single agent, which keep their threads
DRIVEN = "kernel arm: c_worker (dynamic roles); arm A: read_notes readers, team lead (one step)"
# per agent: the steps, the time inside them and the time the executor held the agent (drive_s - step_s: the executor's own share)
STATS: dict[str, dict] = {}

_lock = threading.Lock()
_runtime: dict = {}
_steps: dict[str, Callable[[], bool]] = {}
_errors: dict[str, BaseException] = {}


def drive(agent: str, step: Callable[[], bool], stop: threading.Event, log) -> None:
    """Run `step` until it returns False or the run stops (`stop`, or the log no longer active), with the chosen executor."""
    if EXECUTOR not in EXECUTORS:
        raise ValueError(f"unknown executor {EXECUTOR!r}")
    stats = STATS.setdefault(agent, {"steps": 0, "step_s": 0.0, "drive_s": 0.0})

    def go() -> bool:
        if stop.is_set() or not log.active():
            return False
        started = time.monotonic()
        try:
            return step()
        finally:
            stats["steps"] += 1
            stats["step_s"] += time.monotonic() - started

    started = time.monotonic()
    try:
        if EXECUTOR == "threads":
            while go():
                pass
        elif EXECUTOR == "langgraph":
            _langgraph(go)
        else:
            _temporal(agent, go)
    finally:
        stats["drive_s"] += time.monotonic() - started


def once(agent: str, fn: Callable[[], None]) -> None:
    """Run `fn` as a single step of the executor, whatever the stop state (arm A's lead: one agent that answers question after
    question and checks the log itself)."""
    class Always:
        def active(self) -> bool:
            return True

    def step() -> bool:
        fn()
        return False

    drive(agent, step, threading.Event(), Always())


class _State(TypedDict):
    go: bool
    steps: int


def _langgraph(go: Callable[[], bool]) -> None:
    from langgraph.graph import END, START, StateGraph

    graph = StateGraph(_State)
    graph.add_node("step", lambda s: {"go": go(), "steps": s["steps"] + 1})
    graph.add_edge(START, "step")
    graph.add_conditional_edges("step", lambda s: "step" if s["go"] else END, ["step", END])
    # a superstep per agent step: the limit only guards a runaway graph, the run's own stop ends the agent
    graph.compile().invoke({"go": True, "steps": 0}, {"recursion_limit": 10**9})


def _temporal(agent: str, go: Callable[[], bool]) -> None:
    rt = start()
    key = f"{agent}-{uuid.uuid4().hex}"
    _steps[key] = go
    try:
        future = asyncio.run_coroutine_threadsafe(
            rt["client"].execute_workflow("R2RAgentLoop", args=[key, 0, STEP_TIMEOUT_S], id=f"r2r-{key}", task_queue=TEMPORAL_QUEUE),
            rt["loop"])
        # the worker that runs the steps may stop with a fatal error while the agent's workflow waits: the agent gets that error
        # instead of waiting for ever (Codex review of 0dc2164, EXEC-01)
        concurrent.futures.wait([future, rt["running"]], return_when=concurrent.futures.FIRST_COMPLETED)
        if not future.done():
            future.cancel()
            cause = rt["running"].exception()
            raise RuntimeError(f"TEMPORAL_WORKER_STOPPED: {type(cause).__name__ if cause else 'stopped'}: {cause}") from cause
        future.result()
    except Exception:
        # the step's own error, not Temporal's wrapping of it, is the agent's error (guarded_worker logs it as before)
        if key in _errors:
            raise _errors.pop(key) from None
        raise
    finally:
        _steps.pop(key, None)
        _errors.pop(key, None)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start() -> dict:
    """The Temporal client and worker of this process (started once): a local dev server unless TEMPORAL_ADDRESS names one."""
    with _lock:
        if _runtime:
            return _runtime
        from concurrent.futures import ThreadPoolExecutor

        from temporalio.client import Client
        from temporalio.worker import UnsandboxedWorkflowRunner, Worker

        from .temporal_loop import AgentLoop, step_activity

        rt: dict = {}
        atexit.register(close)  # a selftest or a failed run returns before the runner's own close
        try:
            address = TEMPORAL_ADDRESS
            if address is None:
                exe = shutil.which("temporal") or os.path.join(os.path.expanduser("~"), ".local", "bin", "temporal.exe")
                port, ui = _free_port(), _free_port()
                rt["server"] = subprocess.Popen([exe, "server", "start-dev", "--ip", "127.0.0.1", "--port", str(port), "--ui-port", str(ui),
                                                 "--headless", "--log-level", "warn"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                address = f"127.0.0.1:{port}"
            rt["loop"] = loop = asyncio.new_event_loop()
            threading.Thread(target=loop.run_forever, name="temporal-loop", daemon=True).start()

            async def connect():
                deadline = time.monotonic() + 60
                while True:
                    try:
                        return await Client.connect(address)
                    except Exception:
                        if time.monotonic() > deadline:
                            raise
                        await asyncio.sleep(0.5)

            client = asyncio.run_coroutine_threadsafe(connect(), loop).result(90)
            rt["pool"] = pool = ThreadPoolExecutor(max_workers=64, thread_name_prefix="temporal-step")
            worker = Worker(client, task_queue=TEMPORAL_QUEUE, workflows=[AgentLoop], activities=[step_activity], activity_executor=pool,
                            workflow_runner=UnsandboxedWorkflowRunner(), max_concurrent_activities=64)
            rt.update(client=client, worker=worker, address=address)
            rt["running"] = running = asyncio.run_coroutine_threadsafe(worker.run(), loop)
            # ready only once the worker runs: its namespace and task queue are checked inside run(), after the constructor
            # (Codex review of 0dc2164, EXEC-01)
            deadline = time.monotonic() + 60
            while not worker.is_running:
                if running.done():
                    running.result()
                    raise RuntimeError("TEMPORAL_WORKER_NOT_STARTED: run() returned before the worker ran")
                if time.monotonic() > deadline:
                    raise RuntimeError("TEMPORAL_WORKER_NOT_STARTED: no start within 60 s")
                time.sleep(0.05)
        except BaseException:
            _shutdown(rt)
            raise
        _runtime.update(rt)
        return _runtime


def _shutdown(rt: dict) -> None:
    loop = rt.get("loop")
    if loop is not None and rt.get("worker") is not None:
        try:
            asyncio.run_coroutine_threadsafe(rt["worker"].shutdown(), loop).result(60)
        except Exception:
            pass
    if rt.get("pool") is not None:
        rt["pool"].shutdown(wait=False)
    if loop is not None:
        loop.call_soon_threadsafe(loop.stop)
    proc = rt.get("server")
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(30)
        except subprocess.TimeoutExpired:
            proc.kill()


def close() -> None:
    """Stop the worker and the dev server this process started (by its own handle)."""
    with _lock:
        _shutdown(_runtime)
        _runtime.clear()


def describe() -> dict:
    """The executor of the run and the library versions behind it, for the provenance."""
    from importlib.metadata import PackageNotFoundError, version

    def ver(name: str) -> str | None:
        try:
            return version(name)
        except PackageNotFoundError:
            return None

    out = {"executor": EXECUTOR, "driven": DRIVEN,
           "agents": {a: {"steps": s["steps"], "step_s": round(s["step_s"], 3), "drive_s": round(s["drive_s"], 3),
                          "executor_s": round(s["drive_s"] - s["step_s"], 3)} for a, s in sorted(STATS.items())}}
    if EXECUTOR == "langgraph":
        out["langgraph"] = ver("langgraph")
    if EXECUTOR == "temporal":
        out.update(temporalio=ver("temporalio"), server="local dev server" if TEMPORAL_ADDRESS is None else TEMPORAL_ADDRESS,
                   continue_every=CONTINUE_EVERY, step_timeout_s=STEP_TIMEOUT_S)
    return out
