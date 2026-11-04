"""Arm A as a LangGraph-native team (the owner, 2026-10-30: such a run is needed with LangGraph's own checkpoints and native means, so
that we can claim a real comparison with LangGraph). The same agents, models, prompt templates and checks as the runner's team arm
with --arm-a-answer map-reduce (the prompts actually sent differ where the orchestration does: which agent reads which section with
which notes; every call keeps its context and prompt hash), built the way a LangGraph application is built:

- one StateGraph for the whole team; its state holds the team's shared notes, and a reducer merges what readers write in the same
  superstep;
- reading: a dispatcher sends the next sections to the readers with Send, one section per agent per superstep, each reader with the
  notes so far; the graph loops until the sections run out;
- answering: one Send per (question, report) makes the partial answers in parallel, bounded by max_concurrency = the team's size;
  each partial is taken by a free agent of the team, so an agent does one piece of work at a time; the lead reduces the questions
  one after another;
- a checkpointer saves the state after every superstep (InMemorySaver, or SqliteSaver on disk with langgraph-checkpoint-sqlite);
  after each answer the graph interrupts (langgraph.types.interrupt), and a withdrawal resumes it from the checkpoint with
  Command(resume=...): a COMPLETE partial whose prompt the withdrawal leaves unchanged is read from the checkpointed state, as the
  kernel's arm keeps its records across a withdrawal; every other partial (changed, or not complete) is made again, with a fresh
  budget of attempts;
- RetryPolicy on the model nodes: a failed model call is retried by LangGraph (RETRY_ATTEMPTS attempts in all, each one counted by
  the run's log, its call cap and its budget); a reading or a reduction that still fails stops the arm visibly, a partial answer that
  still fails is recorded INCOMPLETE, as in the runner's team arm.

The kernel is not used: this is the team without the kernel, orchestrated by LangGraph alone. The checkpoints are written to disk
with the SQLite checkpointer; this runner resumes a team only inside its own process (the attempt counters and the run's log live
there), not after a process restart."""
from __future__ import annotations

import hashlib
import json
import operator
import queue
import threading
import time
from typing import Annotated, TypedDict

from . import answer_map_reduce as M
from . import pilot_ac as P

RETRY_ATTEMPTS = 2  # attempts in all of a model node: the first and one LangGraph retry
CHECKPOINTER = "memory"  # memory (InMemorySaver) or sqlite (SqliteSaver on CHECKPOINT_DB)
CHECKPOINT_DB: str | None = None
THREAD_ID = "arm-a"


class ModelCallError(RuntimeError):
    """A model call that failed, raised so that LangGraph's RetryPolicy runs the node again."""


def _merge(a: dict | None, b: dict | None) -> dict:
    return {**(a or {}), **(b or {})}


def _merge_by_report(a: dict | None, b: dict | None) -> dict:
    out = {k: list(v) for k, v in (a or {}).items()}
    for k, v in (b or {}).items():
        out.setdefault(k, []).extend(v)
    return out


def _merge_answers(a: dict | None, b: dict | None) -> dict:
    out = {k: dict(v) for k, v in (a or {}).items()}
    for k, v in (b or {}).items():
        out.setdefault(k, {}).update(v)
    return out


class TeamState(TypedDict, total=False):
    cursor: Annotated[int, operator.add]  # sections read so far
    notes: Annotated[list, operator.add]  # the team's shared notes, in the order the readers' writes are applied
    by_report: Annotated[dict, _merge_by_report]  # report -> its notes
    partials: Annotated[dict, _merge]  # partial key -> {stage, row, part, attempts}
    answers: Annotated[dict, _merge_answers]  # stage -> question id -> answer
    stage: int  # 1, then each withdrawal step's phase number; 0 ends the graph
    withdrawn: list  # the quotes withdrawn so far


def partial_key(rq: str, report: str, withdrawn: list[dict]) -> str:
    """A partial answer's identity: its question, its report and the withdrawals of that report, all its prompt depends on besides
    the report's notes (a withdrawal of another report leaves it as it was)."""
    return json.dumps([rq, report, sorted(w["quote"] for w in withdrawn if w["report"] == report)], ensure_ascii=False)


def _saver():
    if CHECKPOINTER == "sqlite":
        import sqlite3

        from langgraph.checkpoint.sqlite import SqliteSaver

        if not CHECKPOINT_DB:
            raise ValueError("the sqlite checkpointer needs CHECKPOINT_DB")
        conn = sqlite3.connect(CHECKPOINT_DB, check_same_thread=False)
        return SqliteSaver(conn), conn.close
    if CHECKPOINTER != "memory":
        raise ValueError(f"unknown checkpointer {CHECKPOINTER!r}")
    from langgraph.checkpoint.memory import InMemorySaver

    return InMemorySaver(), (lambda: None)


def build(log: "P.Log", team: list, docs: dict[str, str], secs: list[tuple[str, tuple[int, int]]]):
    """The team's StateGraph (not compiled)."""
    from langgraph.graph import END, START, StateGraph
    from langgraph.types import RetryPolicy, Send, interrupt

    attempts: dict = {}
    lock = threading.Lock()
    # the team's agents as a pool: a partial takes a free agent and gives it back, so an agent does one piece of work at a time
    # (Codex review of 70e8d31: round-robin names let w1 run two partials and both reductions at once); the lead reduces alone
    agents: queue.Queue = queue.Queue()
    for w in range(1, len(team) + 1):
        agents.put(w)
    lead = threading.Lock()

    def attempt(key) -> int:
        with lock:
            attempts[key] = attempts.get(key, 0) + 1
            return attempts[key]

    def role(stage: int) -> str:
        return "LEAD" if stage == 1 else "UPDATE"

    def dispatch(state: TeamState) -> dict:
        return {}

    def route_read(state: TeamState):
        if not log.active():
            return END
        cur = state.get("cursor", 0)
        if cur >= len(secs):
            return "answer"
        notes = list(state.get("notes", []))
        return [Send("read", {"i": cur + k, "w": k + 1, "notes": notes}) for k in range(min(len(team), len(secs) - cur))]

    def read(payload: dict) -> dict:
        i, w = payload["i"], payload["w"]
        path, rng = secs[i]
        prompt, context, call_id = P.worker_call(w, payload["notes"], docs, path, rng)
        n = attempt(("read", i))
        c = log.invoke(team[w - 1], prompt, call_id=call_id if n == 1 else f"{call_id}-lg-retry-{n - 1}", arm="A", role="WORKER",
                       phase=1, context=dict(context, lg_attempt=n))
        if c is None:
            return {"cursor": 1}
        if not c.ok:
            if n < RETRY_ATTEMPTS and log.active():
                raise ModelCallError(c.error)
            log.fail(f"MODEL_ERROR: {c.error}", arm="A", phase=1, agent=f"w{w}")
            return {"cursor": 1}
        lines = [ln for ln in c.text.splitlines() if ln.strip()]
        return {"cursor": 1, "notes": lines, "by_report": {path: lines}}

    def answer(state: TeamState) -> dict:
        return {}

    def route_map(state: TeamState):
        if not log.active():
            return END
        stage, withdrawn = state.get("stage", 1), state.get("withdrawn", [])
        done = state.get("partials", {})
        context = {k: v for k, v in P.notes_context(state.get("notes", [])).items() if k != "notes"}
        sends = []
        for q in P.QUESTIONS:
            for report in docs:
                key = partial_key(q["id"], report, withdrawn)
                # only a usable result is kept: a partial that failed, or ended incomplete, is made again (Codex review of
                # 70e8d31, NATIVE-01: a transport failure of stage 1 was taken as done work after the provider recovered)
                if done.get(key, {}).get("row", {}).get("status") == "COMPLETE":
                    continue
                sends.append(Send("partial", {"key": key, "q": q, "report": report, "stage": stage, "withdrawn": withdrawn,
                                              "notes": state.get("by_report", {}).get(report, []), "context": context}))
        return sends or "gather"

    def partial(payload: dict) -> dict:
        q, report, stage, key = payload["q"], payload["report"], payload["stage"], payload["key"]
        n = attempt(("partial", stage, key))  # a fresh budget of attempts in each stage
        w = agents.get()
        try:
            name = f"w{w}" if n == 1 else f"w{w}-lg-retry-{n - 1}"
            row, part = M.partial(log, team[w - 1], docs, payload["withdrawn"], q, stage, P.TEAM_RULES, name, role(stage),
                                  dict(payload["context"], agent=f"w{w}", lg_attempt=n), {report: payload["notes"]}, report)
        finally:
            agents.put(w)
        a = row.get("answer") or {}
        if a.get("outcome") == "not_answered" and n < RETRY_ATTEMPTS and log.active():
            raise ModelCallError(a.get("error"))
        # the row counts the calls of its last attempt; every attempt of this stage is counted here (Codex review of 70e8d31)
        digest = hashlib.sha256(report.encode()).hexdigest()[:16]
        row["calls_all_attempts"] = sum(1 for c in list(log.calls) if c.call_id.startswith(f"A{stage}-")
                                        and f"-map-{digest}-{q['id']}-" in c.call_id)
        return {"partials": {key: {"stage": stage, "row": row, "part": part, "attempts": n}}}

    def gather(state: TeamState) -> dict:
        return {}

    def route_reduce(state: TeamState):
        if not log.active():
            return END
        stage, withdrawn = state.get("stage", 1), state.get("withdrawn", [])
        context = {k: v for k, v in P.notes_context(state.get("notes", [])).items() if k != "notes"}
        sends = []
        for q in P.QUESTIONS:
            recs = [state.get("partials", {}).get(partial_key(q["id"], report, withdrawn)) for report in docs]
            sends.append(Send("reduce", {"q": q, "stage": stage, "withdrawn": withdrawn, "context": context,
                                         "rows": [r["row"] for r in recs if r], "parts": [r["part"] for r in recs if r and r["part"]]}))
        return sends

    def reduce(payload: dict) -> dict:
        q, stage = payload["q"], payload["stage"]
        n = attempt(("reduce", stage, q["id"]))
        name = "lead" if n == 1 else f"lead-lg-retry-{n - 1}"
        with lead:
            ans = M.reduce(log, team[0], docs, payload["withdrawn"], q, stage, name, role(stage), dict(payload["context"], lg_attempt=n),
                           payload["parts"], payload["rows"], stop_on_model_error=False)
        if ans is None:
            return {}
        if ans.get("outcome") == "not_answered":
            if n < RETRY_ATTEMPTS and log.active():
                raise ModelCallError(ans.get("error"))
            log.fail(f"MODEL_ERROR: {ans.get('error')}", arm="A", phase=stage, rq_id=q["id"])
            return {}
        return {"answers": {str(stage): {q["id"]: ans}}}

    def wait(state: TeamState) -> dict:
        command = interrupt({"answered_stage": state.get("stage", 1)})
        if command.get("done"):
            return {"stage": 0}
        return {"stage": command["stage"], "withdrawn": command["withdrawn"]}

    def route_wait(state: TeamState):
        return END if state.get("stage") == 0 else "answer"

    retry = RetryPolicy(max_attempts=RETRY_ATTEMPTS, retry_on=ModelCallError, initial_interval=1.0, jitter=False)
    g = StateGraph(TeamState)
    g.add_node("dispatch", dispatch)
    g.add_node("read", read, retry_policy=retry)
    g.add_node("answer", answer)
    g.add_node("partial", partial, retry_policy=retry)
    g.add_node("gather", gather)
    g.add_node("reduce", reduce, retry_policy=retry)
    g.add_node("wait", wait)
    g.add_edge(START, "dispatch")
    g.add_conditional_edges("dispatch", route_read, ["read", "answer", END])
    g.add_edge("read", "dispatch")
    g.add_conditional_edges("answer", route_map, ["partial", "gather", END])
    g.add_edge("partial", "gather")
    g.add_conditional_edges("gather", route_reduce, ["reduce", END])
    g.add_edge("reduce", "wait")
    g.add_conditional_edges("wait", route_wait, ["answer", END])
    return g


def _stage_record(state: dict, stage: int, log: "P.Log", t0: float, reports: list[str]) -> dict:
    """A phase of arm A as the runner's team arm records it, from the checkpointed state."""
    withdrawn = state.get("withdrawn", []) if stage > 1 else []
    answers = dict(state.get("answers", {}).get(str(stage), {}))
    partials, reused = {}, 0
    for q in P.QUESTIONS:
        rows = []
        for report in reports:
            rec = state.get("partials", {}).get(partial_key(q["id"], report, withdrawn))
            if rec:
                rows.append(dict(rec["row"], made_in_stage=rec["stage"], lg_attempts=rec["attempts"]))
                reused += rec["stage"] != stage
        partials[q["id"]] = rows
    status, reason = P.answers_status(answers, log)
    return {"answers": answers, "partials": partials, "partials_reused": reused, "wall_s": time.monotonic() - t0, "status": status,
            "reason": reason}


def run(team: list, docs: dict[str, str], withdraw: dict, timeout_s: float = 1800, *, evidence=None, max_calls: int = P.MAX_CALLS,
        budget=None, chosen: list[dict] | None = None) -> dict:
    """Arm A as the LangGraph-native team: phase 1 and each withdrawal step, recorded as the runner's team arm records them."""
    import importlib.metadata

    from langgraph.types import Command

    if not team or timeout_s <= 0:
        raise ValueError("a team and a positive phase timeout are needed")
    log = P.Log(max_calls, evidence, time.monotonic() + timeout_s)
    log.budget = budget
    secs = [(path, rng) for path, text in docs.items() for rng in P.sections(text, P.SECTION_BYTES)]
    saver, close = _saver()
    graph = build(log, team, docs, secs).compile(checkpointer=saver)
    config = {"configurable": {"thread_id": THREAD_ID}, "max_concurrency": len(team), "recursion_limit": 100000}
    res = {"arm": "A", "mode": "team", "team": [m.name for m in team], "answer_strategy": "map-reduce", "phase1": {"answers": {}},
           "orchestration": {"kind": "langgraph-native", "langgraph": importlib.metadata.version("langgraph"), "checkpointer": CHECKPOINTER,
                             "max_concurrency": len(team), "retry_attempts": RETRY_ATTEMPTS, "sections": len(secs)}}

    def invoke(value) -> bool:
        """One run of the graph up to its next interrupt; False when it ended without one (the log stopped it, or it failed)."""
        try:
            out = graph.invoke(value, config)
        except Exception as e:  # a node failed past its retries: a visible stop, as a failed call stops the runner's arm
            if not log.stopped:
                log.fail(f"LANGGRAPH_ERROR: {type(e).__name__}: {e}", arm="A")
            return False
        return "__interrupt__" in out

    try:
        t0 = time.monotonic()
        waiting = invoke({"cursor": 0, "notes": [], "by_report": {}, "partials": {}, "answers": {}, "stage": 1, "withdrawn": []})
        state = graph.get_state(config).values
        res["phase1"] = dict(_stage_record(state, 1, log, t0, list(docs)), notes_lines=len(state.get("notes", [])))
        if res["phase1"]["status"] == "STOPPED":
            res["phase2"] = P.skipped_phase("PHASE1_STOPPED")
        elif withdraw:
            steps = P.withdrawal_steps(withdraw)
            texts = chosen or [{"step": s["name"], "report": s["report"], **s["candidates"][0]} for s in steps]
            so_far: list[dict] = []
            for n, (step, text) in enumerate(zip(steps, texts), start=2):
                key = f"phase{n}"
                if res[f"phase{n - 1}"].get("status") == "STOPPED" or not waiting:
                    res[key] = P.skipped_phase("PREVIOUS_PHASE_STOPPED")
                    continue
                log.deadline = time.monotonic() + timeout_s
                t1 = time.monotonic()
                so_far.append(text)
                waiting = invoke(Command(resume={"stage": n, "withdrawn": [{"report": w["report"], "quote": w["quote"]} for w in so_far]}))
                state = graph.get_state(config).values
                res[key] = dict(_stage_record(state, n, log, t1, list(docs)), step=step["name"])
        else:
            res["phase2"] = P.skipped_phase("NO_WITHDRAWAL")
        if waiting:
            invoke(Command(resume={"done": True}))
        res["orchestration"]["checkpoints"] = sum(1 for _ in graph.get_state_history(config))
    finally:
        close()
    res.update(log.result())
    return res
