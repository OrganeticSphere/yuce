"""A run's plain steps: the model of each call and the work around a builder card. `pilot_ac.RUN_HOOK` holds the run's `RunHook`."""
from __future__ import annotations

# the roles of an answer call: its deadline is the run's --answer-timeout-s, not the model's
ANSWER_ROLES = ("SUMMARIZE", "LEAD", "UPDATE", "ANSWER", "RESTATE", "SINGLE", "WHOLE")


class PlainPolicy:
    def select(self, model, arm, role, phase, context, answer_timeout_s):
        """The model of a call and the fields of its record; an answer call runs under the answer deadline."""
        chosen = model.for_role(None, timeout_s=answer_timeout_s) if role in ANSWER_ROLES and hasattr(model, "for_role") else model
        return chosen, {"model_family": getattr(chosen, "model_family", getattr(model, "name", "unknown"))}

    def after_call(self, arm, role, phase, context, call=None, reply=None):
        """Called with a finished call or with a reply that asks for another call; returns the events to record."""
        return ()


class RunHook:
    def policy(self):
        """The policy of one Log."""
        return PlainPolicy()

    def before(self, card, ctx):
        """Before the builder's call: its prompt and more fields of the card's last event, or None to stop the card."""
        return ctx.render(card), {}

    def after(self, card, operations, submit, ctx):
        """On a valid answer: the operations submitted, the reply and the text a repair shows (None: the answer's own)."""
        return operations, submit(operations), None

    def measures(self, cards):
        """More measures of the builder's finished cards."""
        return {}

    def summary(self, summary):
        """Called with a run's summary before it is saved."""

    def metrics(self, metrics, events):
        """The metrics of a run's circles."""
        return metrics

    def markdown(self, row):
        """More lines of a circle in the model matrix."""
        return []
