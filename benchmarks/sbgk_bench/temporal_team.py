"""The Temporal side of arm_a_temporal.py: arm A's team as one workflow and its model calls as activities. Imported only with
--arm-a-orchestration temporal-native (the module needs temporalio); a workflow class has to be at module level, and the workflow
runs unsandboxed (it only sequences activities and keeps the team's state; every model call and every effect on the run's log is an
activity)."""
from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import timedelta

from temporalio import activity, workflow
from temporalio.common import RetryPolicy

# the run objects (log, team, docs) of each running team, by run key: activities run in this process's worker
RUNS: dict[str, object] = {}


def _run(key: str):
    return RUNS[key]


@activity.defn(name="arm_a_read")
def read_activity(key: str, i: int, w: int, notes: list[str]) -> dict:
    return _run(key).read(i, w, notes, activity.info().attempt)


@activity.defn(name="arm_a_partial")
def partial_activity(key: str, payload: dict) -> dict:
    return _run(key).partial(payload, activity.info().attempt)


@activity.defn(name="arm_a_reduce")
def reduce_activity(key: str, payload: dict) -> dict:
    return _run(key).reduce(payload, activity.info().attempt)


@activity.defn(name="arm_a_stop")
def stop_activity(key: str, reason: str) -> None:
    _run(key).stop(reason)


def partial_key(rq: str, report: str, withdrawn: list[dict]) -> str:
    """A partial answer's identity: its question, its report and the withdrawals of that report (see arm_a_langgraph)."""
    return json.dumps([rq, report, sorted(w["quote"] for w in withdrawn if w["report"] == report)], ensure_ascii=False)


@workflow.defn(name="R2RArmATeam")
class ArmATeam:
    """The team's state lives in the workflow (its history is the checkpoint): the notes, each report's notes, the partial answers by
    key. A stage is a workflow update: the first reads every section and answers, each later one takes the withdrawn quotes and
    answers again, keeping only the COMPLETE partials whose prompt they leave unchanged."""

    # the configuration comes with the workflow's start, before any update can run (an update may reach a new workflow before its run
    # method: the stub smoke on a SQLite history met a stage without its configuration)
    @workflow.init
    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg
        self.notes: list[str] = []
        self.by_report: dict[str, list[str]] = {}
        self.partials: dict[str, dict] = {}
        self.finished = False
        self.stopped: str | None = None

    @workflow.run
    async def run(self, cfg: dict) -> dict:
        await workflow.wait_condition(lambda: self.finished)
        return {"notes_lines": len(self.notes), "partials": len(self.partials), "stopped": self.stopped}

    @workflow.signal
    def finish(self) -> None:
        self.finished = True

    def _options(self) -> dict:
        return {"start_to_close_timeout": timedelta(seconds=self.cfg["activity_timeout_s"]),
                "retry_policy": RetryPolicy(maximum_attempts=self.cfg["retry_attempts"], initial_interval=timedelta(seconds=1),
                                            backoff_coefficient=2.0)}

    async def _stop(self, reason: str) -> None:
        self.stopped = self.stopped or reason
        await workflow.execute_activity("arm_a_stop", args=[self.cfg["key"], reason], **self._options())

    async def _read_all(self) -> None:
        n, team = self.cfg["sections"], self.cfg["team_size"]
        cursor = 0
        while cursor < n and not self.stopped:
            batch = list(range(cursor, min(n, cursor + team)))
            snapshot = list(self.notes)
            results = await asyncio.gather(*[workflow.execute_activity("arm_a_read", args=[self.cfg["key"], i, k + 1, snapshot], **self._options())
                                             for k, i in enumerate(batch)])
            for r in results:
                if r.get("failed"):
                    await self._stop(r["failed"])
                    continue
                self.notes.extend(r["lines"])
                if r["lines"]:
                    self.by_report.setdefault(r["report"], []).extend(r["lines"])
                if r.get("inactive"):
                    self.stopped = self.stopped or "LOG_INACTIVE"
            cursor += len(batch)

    @workflow.update
    async def stage(self, req: dict) -> dict:
        stage, withdrawn = req["stage"], req.get("withdrawn", [])
        if stage == 1:
            await self._read_all()
        if self.stopped:
            return {"answers": {}, "partials": {}, "notes_lines": len(self.notes), "stopped": self.stopped}
        # the context of the team's answer calls, as pilot_ac.notes_context gives it without the notes themselves
        digest = hashlib.sha256("\n".join(self.notes).encode("utf-8")).hexdigest()
        context = {"notes_revision": f"{len(self.notes)}:{digest}", "notes_sha256": digest, "notes_lines": len(self.notes)}
        jobs = []
        for q in self.cfg["questions"]:
            for report in self.cfg["reports"]:
                key = partial_key(q["id"], report, withdrawn)
                # only a usable result is kept: a partial that failed, or ended incomplete, is made again with a new activity and
                # so a fresh budget of attempts (Codex review of 6baf2ae, NATIVE-01)
                if self.partials.get(key, {}).get("row", {}).get("status") == "COMPLETE":
                    continue
                payload = {"key": key, "q": q, "report": report, "stage": stage, "withdrawn": withdrawn, "notes": self.by_report.get(report, []),
                           "context": context}
                jobs.append((key, workflow.execute_activity("arm_a_partial", args=[self.cfg["key"], payload], **self._options())))
        made = await asyncio.gather(*[job for _, job in jobs])
        for (key, _), rec in zip(jobs, made):
            self.partials[key] = dict(rec, stage=stage)
        reduces = []
        for q in self.cfg["questions"]:
            recs = [self.partials.get(partial_key(q["id"], report, withdrawn)) for report in self.cfg["reports"]]
            payload = {"q": q, "stage": stage, "withdrawn": withdrawn, "context": context, "rows": [r["row"] for r in recs if r],
                       "parts": [r["part"] for r in recs if r and r["part"]]}
            reduces.append(workflow.execute_activity("arm_a_reduce", args=[self.cfg["key"], payload], **self._options()))
        answers = {}
        for q, r in zip(self.cfg["questions"], await asyncio.gather(*reduces)):
            if r.get("failed"):
                await self._stop(r["failed"])
            elif r.get("answer") is not None:
                answers[q["id"]] = r["answer"]
        partials = {q["id"]: [dict(self.partials[partial_key(q["id"], report, withdrawn)]) for report in self.cfg["reports"]
                              if partial_key(q["id"], report, withdrawn) in self.partials] for q in self.cfg["questions"]}
        return {"answers": answers, "partials": partials, "notes_lines": len(self.notes), "stopped": self.stopped}
