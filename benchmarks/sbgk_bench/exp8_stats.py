"""EXP-8 statistics: per-mode aggregates and exact paired sign tests (same case = same task, team and speaking order in every mode)."""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict

MODES = ["iso", "prose", "raw", "graph", "graphopen"]
PAIRS = [("graph", "iso"), ("graph", "prose"), ("graph", "raw"), ("graphopen", "graph"), ("graphopen", "raw"), ("graphopen", "prose"), ("prose", "raw")]


def sign_p(wins: int, losses: int) -> float:
    """Exact two-sided sign test (ties dropped)."""
    n = wins + losses
    if n == 0:
        return 1.0
    k = min(wins, losses)
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(0, k + 1)) / 2 ** n)


def normalize(data: dict) -> dict:
    """Recompute net input tokens (prompt tokens minus the measured per-call runtime overhead) from the stored raw counts."""
    ov = data.get("overhead_in_tokens", {})
    for r in data["results"]:
        if r.get("error"):
            continue
        tot = 0
        for s in r["step_log"]:
            for rec in s["recs"]:
                rec["in_net"] = max(0, rec["in_tokens"] - ov.get(rec["backend"], 0)) if rec["in_tokens"] else 0
                tot += rec["in_net"]
        r["in_net"] = tot
    return data


def usable(runs: list[dict]) -> list[dict]:
    return [r for r in runs if not r.get("error") and not r.get("call_errors", 0)]


def reps(r: dict) -> int:
    return r["repeat_partner"] + r["repeat_self"]


def rate(r: dict) -> float:
    return reps(r) / r["accepted"] if r["accepted"] else 0.0


def avoidable(r: dict) -> int:
    return reps(r) - r["repeat_unavoidable"]


def avoidable_rate(r: dict) -> float:
    return avoidable(r) / r["accepted"] if r["accepted"] else 0.0


def defects(r: dict) -> int:
    """Wrong things standing at the end: stale or false conclusions, missing ones, withdrawn clauses still active."""
    return r["false_final"] + r["missing_final"] + r["withdrawn_active_final"]


def steps_to_goal(r: dict, cap: int) -> int:
    return r["goal_step"] if r["completed"] else cap


# metric key -> (label, function(run, cap) -> float); lower is better for every metric
METRICS = {
    "rate": ("repeat share", lambda r, cap: rate(r)),
    "reps": ("repeats", lambda r, cap: reps(r)),
    "avoid": ("avoidable repeats", lambda r, cap: avoidable(r)),
    "steps": ("turns/rounds to goal", lambda r, cap: steps_to_goal(r, cap)),
    "defects": ("defects at the end", lambda r, cap: defects(r)),
    "rejected": ("kernel rejections", lambda r, cap: r["rejected"]),
    "in_net": ("input, tokens", lambda r, cap: r["in_net"]),
}


def agg(runs: list[dict], cap: int) -> dict:
    ok = usable(runs)
    A = lambda k: sum(r.get(k, 0) or 0 for r in ok)  # noqa: E731
    acc = A("accepted")
    rp, rs, un = A("repeat_partner"), A("repeat_self"), A("repeat_unavoidable")
    return {
        "runs": len(runs), "failed": len(runs) - len(ok), "completed": sum(1 for r in ok if r["completed"]), "n": len(ok),
        "steps_mean": statistics.fmean(steps_to_goal(r, cap) for r in ok) if ok else float("nan"),
        "steps_done_mean": statistics.fmean(r["goal_step"] for r in ok if r["completed"]) if any(r["completed"] for r in ok) else float("nan"),
        "targets_done": A("targets_done"), "targets": A("targets"),
        "accepted": acc, "new": A("new"), "rp": rp, "rs": rs, "unavoidable": un, "avoidable": rp + rs - un, "repair": A("repair"),
        "rate": (rp + rs) / acc if acc else 0.0, "rate_partner": rp / acc if acc else 0.0, "rate_avoidable": (rp + rs - un) / acc if acc else 0.0,
        "rejected": A("rejected"), "reject_codes": dict(sum((Counter(r.get("reject_codes", {})) for r in ok), Counter())), "unsent": A("unsent"),
        "wrong_facts": A("wrong_facts"), "false_final": A("false_final"), "stale_final": A("stale_final"), "under_conflict_final": A("under_conflict_final"),
        "missing_final": A("missing_final"), "withdrawn_active_final": A("withdrawn_active_final"), "wrong_revokes": A("wrong_revokes"),
        "revokes": A("revokes"), "dropped_plain": A("dropped_plain"), "repeat_after_notice": A("repeat_after_notice"),
        "x_ok": sum(1 for r in ok if r.get("x_ok")), "p_ok": sum(1 for r in ok if r.get("p_ok")), "rederive": A("rederive_after_notice"),
        "clean": sum(1 for r in ok if defects(r) == 0 and r["completed"]),
        "wasted_steps": A("wasted_steps"), "empty_steps": A("empty_steps"), "calls": A("calls"),
        "in_net": A("in_net"), "out": A("out_tokens"), "cost": sum(r.get("cost_usd", 0.0) or 0.0 for r in ok), "seconds": A("seconds"),
        "wall": A("wall_s"), "raw_hidden_share": statistics.fmean(r["raw_hidden_share"] for r in ok) if ok else 0.0,
        "compact_calls": A("compact_calls"), "max_cmdlen": max((r.get("max_cmdlen", 0) for r in ok), default=0),
        "call_errors": sum(r.get("call_errors", 0) for r in runs if not r.get("error")), "tools": A("tool_items"), "from_cache": A("from_cache"),
    }


def paired(by: dict, a: str, b: str, key: str, cap: int) -> dict | None:
    """A against B on one metric over the cases that have a usable run in both modes. 'win' = A strictly lower (better)."""
    if a not in by or b not in by:
        return None
    ra = {r["case"]: r for r in usable(by[a])}
    rb = {r["case"]: r for r in usable(by[b])}
    cases = sorted(set(ra) & set(rb))
    if not cases:
        return None
    fn = METRICS[key][1]
    d = [fn(ra[c], cap) - fn(rb[c], cap) for c in cases]
    w = sum(1 for x in d if x < -1e-12)
    l = sum(1 for x in d if x > 1e-12)
    return {"n": len(cases), "win": w, "tie": len(cases) - w - l, "loss": l, "mean_diff": statistics.fmean(d), "median_diff": statistics.median(d), "p": sign_p(w, l)}


def split_by_mode(results: list[dict]) -> dict[str, list[dict]]:
    by: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        by[r["mode"]].append(r)
    return by


def history_buckets(runs: list[dict], edges=(0, 20, 40, 60, 10 ** 9)) -> list[dict]:
    """Repeat rate and prompt size as a function of how many events the team had accepted before the turn."""
    out = [{"lo": edges[i], "hi": edges[i + 1], "acc": 0, "rep": 0, "calls": 0, "in_net": 0, "hidden": 0, "raw_total": 0} for i in range(len(edges) - 1)]
    for r in usable(runs):
        before = 0
        for s in r["step_log"]:
            for rec in s["recs"]:
                for b in out:
                    if b["lo"] <= before < b["hi"]:
                        b["acc"] += rec["accepted"]
                        b["rep"] += rec["repeat_partner"] + rec["repeat_self"]
                        b["calls"] += 1
                        b["in_net"] += rec["in_net"]
                        b["hidden"] += rec.get("raw_hidden", 0)
                        b["raw_total"] += rec.get("raw_total", 0)
                        break
            before += sum(rec["accepted"] for rec in s["recs"])
    return out


def round_table(runs: list[dict], max_round: int = 4) -> list[dict]:
    """Parallel scenario: per round index (the last bucket pools the later rounds), repeats split into unavoidable / avoidable."""
    out = [{"round": i + 1, "acc": 0, "new": 0, "rep": 0, "unavoid": 0, "calls": 0, "runs": 0} for i in range(max_round)]
    for r in usable(runs):
        for s in r["step_log"]:
            b = out[min(s["step"], max_round) - 1]
            b["runs"] += 1
            for rec in s["recs"]:
                b["acc"] += rec["accepted"]
                b["new"] += rec["new"]
                b["rep"] += rec["repeat_partner"] + rec["repeat_self"]
                b["unavoid"] += rec["repeat_unavoidable"]
                b["calls"] += 1
    return out


def direction_matrix(runs: list[dict]) -> Counter:
    c: Counter = Counter()
    for r in usable(runs):
        c.update(r.get("repeat_matrix", {}))
    return c


def agent_table(runs: list[dict]) -> dict[str, dict]:
    t: dict[str, dict] = defaultdict(lambda: Counter())
    for r in usable(runs):
        for s in r["step_log"]:
            for rec in s["recs"]:
                a = t[rec["label"]]
                a["calls"] += 1
                a["accepted"] += rec["accepted"]
                a["new"] += rec["new"]
                a["repeats"] += rec["repeat_partner"] + rec["repeat_self"]
                a["rejected"] += rec["rejected"]
                a["over_budget"] += rec["over_budget"]
                a["empty"] += 1 if rec["accepted"] == 0 else 0
                a["call_errors"] += 1 if rec["call_error"] else 0
                for code in rec["reject_codes"]:
                    a["code:" + str(code)] += 1
    return t


def case_pick(by: dict, cap: int) -> int | None:
    """The case with the largest spread of steps-to-goal across modes (used for the worked example)."""
    cases = sorted({r["case"] for rs in by.values() for r in rs})
    best, spread = None, -1
    for c in cases:
        v = [steps_to_goal(r, cap) for rs in by.values() for r in rs if r["case"] == c and not r.get("error")]
        if len(v) >= 3 and max(v) - min(v) > spread:
            best, spread = c, max(v) - min(v)
    return best
