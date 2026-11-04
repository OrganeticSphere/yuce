"""The Temporal side of executors.py: the workflow that loops an agent's step and the activity that runs one step. Imported only
with --executor temporal (the module needs temporalio); a workflow class has to be at module level."""
from __future__ import annotations

from datetime import timedelta

from temporalio import activity, workflow
from temporalio.common import RetryPolicy

from . import executors as E


@activity.defn(name="r2r_step")
def step_activity(key: str) -> bool:
    try:
        return E._steps[key]()
    except BaseException as exc:
        E._errors[key] = exc
        raise


@workflow.defn(name="R2RAgentLoop")
class AgentLoop:
    @workflow.run
    async def run(self, key: str, done: int, timeout_s: float) -> int:
        n = done
        while True:
            go = await workflow.execute_activity("r2r_step", key, start_to_close_timeout=timedelta(seconds=timeout_s),
                                                 retry_policy=RetryPolicy(maximum_attempts=1))
            n += 1
            if not go:
                return n
            # an idle agent polls thousands of times a phase: the history starts anew before it grows past Temporal's bounds
            if n - done >= E.CONTINUE_EVERY or workflow.info().is_continue_as_new_suggested():
                workflow.continue_as_new(args=[key, n, timeout_s])
