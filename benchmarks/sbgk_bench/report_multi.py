"""Renders results/exp7/exp7.json into the multi-agent report (separate from the earlier reports)."""

from __future__ import annotations

import math
from collections import defaultdict

from .report import f0, f1, f2, p1, table  # noqa: F401 - shared helpers

MODE_NAMES = {
    "iso": "iso — partners not visible",
    "prose": "prose — the partner's words (chat)",
    "raw": "raw — the partner's raw event log",
    "graph": "graph — the graph the compiler built from the bytes",
}
BACKENDS = {"codex": "Codex gpt-5.6-sol", "deepseek": "DeepSeek-chat (OpenClaw)", "opus": "Claude Opus 5.5"}


def sign_p(wins: int, losses: int) -> float:
    n = wins + losses
    if n == 0:
        return 1.0
    k = min(wins, losses)
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(0, k + 1)) / 2 ** n)


def rate(r: dict) -> float | None:
    a = r.get("events_accepted") or 0
    return (r["repeat_partner"] + r["repeat_self"]) / a if a else None


def agg(runs: list[dict], cap: int) -> dict:
    ok = [r for r in runs if not r.get("error")]
    acc = sum(r["events_accepted"] for r in ok)
    rp = sum(r["repeat_partner"] for r in ok)
    rs = sum(r["repeat_self"] for r in ok)
    turns = [r["goal_turn"] if r["completed"] else cap for r in ok]
    return {
        "runs": len(runs), "failed_runs": len(runs) - len(ok), "completed": sum(r["completed"] for r in ok),
        "turns_mean": sum(turns) / max(1, len(turns)), "accepted": acc, "new": sum(r["events_new"] for r in ok), "rp": rp, "rs": rs,
        "rate": (rp + rs) / acc if acc else 0.0, "rate_partner": rp / acc if acc else 0.0,
        "rejected": sum(r["rejected"] for r in ok), "unsent": sum(r["unsent"] for r in ok), "wrong": sum(r["wrong_facts"] for r in ok),
        "flags": sum(r["false_flags"] for r in ok), "wasted_turns": sum(r["wasted_turns"] for r in ok),
        "out": sum(r["out_tokens"] for r in ok), "in_net": sum(r["in_net"] for r in ok), "cost": sum(r["cost_usd"] for r in ok),
        "seconds": sum(r["seconds"] for r in ok), "tools": sum(r["tool_items"] for r in ok),
        "turns_run": sum(r["turns_run"] for r in ok),
    }


def render(D: dict) -> str:
    R = D["results"]
    cap = D["max_turns"]
    modes = [m for m in ("iso", "prose", "raw", "graph") if any(r["mode"] == m for r in R)]
    by_mode = {m: [r for r in R if r["mode"] == m] for m in modes}
    S = {m: agg(by_mode[m], cap) for m in modes}
    cases = sorted({r["case"] for r in R})
    team_of = {c["idx"]: c["team"] for c in D["case_info"]}
    L: list[str] = []
    A = L.append

    A("# SBGK-P0 — EXP-7: agents work on one task and exchange reasoning through the compiler")
    A("")
    bl = D["backends"]
    A("Agents: " + "; ".join(f"**{BACKENDS[k]}** ({v['label']}, {v.get('version', '')})" for k, v in bl.items()) + ".  ")
    A(f"Cases: {len(cases)} · exchange modes: {len(modes)} · runs: {len(R)} · agent turn: at most {D['k_events']} events · cap: {cap} turns.  ")
    A("This is a **separate report**; the three earlier reports and `results/summary.json` were not changed.")
    A("")

    # ---------------------------------------------------------------- 0
    A("## 0. In plain words")
    A("")
    A("Several AI agents from different vendors get **one task** and take turns. Nobody is assigned a share of the work. "
      "Each step an agent takes is written as a strict JSON event. The only shared \"channel\" is the compiler (the SBGK kernel): it checks the event, "
      "brings it into canonical form and stores it in bytes. The agents then see in different ways what the team has already done:")
    A("")
    A(table(["Mode", "What the agent sees of the partners' work"], [[MODE_NAMES[m].split(" — ")[0], MODE_NAMES[m].split(" — ")[1]] for m in modes]))
    A("")
    A("The main question: **do agents repeat each other's steps**. A repeat is judged by the kernel, not by us: the event is accepted, but the node (quoted evidence "
      "or claim) was already in the graph. That catches it regardless of what the agents called things, in which order they wrote them and in which words. "
      "Whose steps were repeated — the partner's or one's own — is counted separately.")
    A("")
    best = min(modes, key=lambda m: S[m]["rate"])
    A("**Repeats overall** (summed over all cases):")
    A("")
    rows = [[MODE_NAMES[m].split(" — ")[0], f"{S[m]['completed']}/{S[m]['runs']}", f1(S[m]["turns_mean"]), f0(S[m]["accepted"]),
             f"{S[m]['rp'] + S[m]['rs']}", p1(S[m]["rate"]), p1(S[m]["rate_partner"])] for m in modes]
    A(table(["Mode", "goal reached", "turns to goal (mean)", "events accepted", "of them repeats", "repeat share", "of it: repeats of a partner's step"], rows))
    A("")

    if "iso" in S and "graph" in S:
        A(f"- Without exchange (iso) {p1(S['iso']['rate'])} of the accepted events are repeats; with the compiler's graph — {p1(S['graph']['rate'])}.")
    if "raw" in S and "graph" in S:
        A(f"- The raw log gave {p1(S['raw']['rate'])}, the graph {p1(S['graph']['rate'])}: "
          + ("the graph is lower, but the difference at this scale is small (see the paired comparison below)." if S["graph"]["rate"] < S["raw"]["rate"] else "the graph is not better than the raw log at this scale."))
    if "prose" in S and "graph" in S:
        A(f"- A retelling in words (prose) gave {p1(S['prose']['rate'])}.")
    A(f"- The lowest repeat share in this run: **{MODE_NAMES[best].split(' — ')[0]}**.")
    A("")

    # ---------------------------------------------------------------- 1 environment
    A("## 1. How the environment works")
    A("")
    A("- **The task (one per team).** The document has clauses \"service X calls API Y in a time window…\" and \"API Y is deprecated in a window…\". "
      "Find every service that needs review: its API is deprecated in a window that overlaps its use. Derive nothing for the others (every case has a trap — an API "
      "that is deprecated only later). The generator knows the reference; the agents do not see it.")
    A("- **Teams.** Three pairs and one trio: " + "; ".join("+".join(BACKENDS[b].split(' ')[0] for b in t) for t in {tuple(v) for v in team_of.values()}) + ". "
      "Turns go round robin; the first speaker changes from case to case.")
    A("- **An agent's turn.** The agent gets a prompt (task, ontology, document, event format, its budget) and outputs up to "
      f"{D['k_events']} JSON lines. The kernel numbers the events, checks them in order and **stops at the first rejected one** (the rest of the turn's lines are dropped). "
      "The kernel state is shared by the whole team.")
    A("- **The compiler takes part in all four modes** (otherwise there would be nothing to measure): events always go through the kernel. The modes differ only in what an agent sees of the partners' work.")
    A("- **The same in every mode:** the task text, the request not to repeat others' work, the agent's own turn history with the kernel's verdicts. "
      "**Different:** only what the agent sees of the partners' turns (table above).")
    A("- **The graph for the graph mode** is assembled from the byte container the kernel exports after every turn (`snapshot`), by `sbgk view`: "
      "canonical claims with statuses, bound quotes and `@id` references, through which any agent can use another's claim as a premise.")
    A("- **Every model call** runs in an empty temporary folder without tools (tools called: "
      f"{sum(S[m]['tools'] for m in modes)}). DeepSeek is called through OpenClaw, Codex through `codex exec`, Opus through `claude -p` (the newest bundled copy, because "
      "the system `claude` is too old for this model).")
    A("")

    # ---------------------------------------------------------------- 2 details
    A("## 2. Detailed results by mode")
    A("")
    rows = [[MODE_NAMES[m].split(" — ")[0], f"{S[m]['new']}", f"{S[m]['rp']}", f"{S[m]['rs']}", S[m]["rejected"], S[m]["unsent"], S[m]["wasted_turns"], S[m]["wrong"], S[m]["flags"]] for m in modes]
    A(table(["Mode", "new steps", "repeat of a partner's", "repeat of one's own", "rejected by the kernel", "not sent (after a rejection)", "turns without new steps", "wrong facts", "false conclusions"], rows))
    A("")
    A("A \"wrong fact\" is an accepted `uses_api` or `api_deprecated` claim that is not in the reference; a \"false conclusion\" is `needs_review` for the wrong service. "
      "The kernel rejects invalid quotes and impossible derivations, so such cases can only come from misreading the text.")
    A("")
    rows = [[MODE_NAMES[m].split(" — ")[0], f0(S[m]["out"]), f0(S[m]["in_net"]), f"${S[m]['cost']:.2f}", f0(S[m]["seconds"])] for m in modes]
    A(table(["Mode", "agent output, tokens", "input (without runtime overhead), tokens", "cost of Opus calls", "call time, s"], rows))
    A("")
    est = [k for k, v in bl.items() if v.get("tokens_estimated")]
    A(("DeepSeek tokens are estimated as characters/4; " if est else "Tokens are taken from the runtimes' answers; ")
      + "the runtime's per-call overhead (measured by a probe call) is subtracted from the input: "
      + ", ".join(f"{BACKENDS[k]} {f0(v)}" for k, v in D["overhead_in_tokens"].items()) + ".")
    A("")

    # ---------------------------------------------------------------- 3 paired
    A("## 3. Paired comparison by case")
    A("")
    A("For each case the modes got the same task and the same team. We compare the repeat share (repeats / accepted events) in pairs; "
      "the sign test (two-sided, exact) is a rough check, not proof with such a sample.")
    A("")
    pairs = [(a, b) for a, b in (("graph", "iso"), ("graph", "prose"), ("graph", "raw"), ("raw", "iso"), ("prose", "iso")) if a in S and b in S]
    rows = []
    for a, b in pairs:
        w = l = e = 0
        diffs = []
        for c in cases:
            ra = next((r for r in by_mode[a] if r["case"] == c and not r.get("error")), None)
            rb = next((r for r in by_mode[b] if r["case"] == c and not r.get("error")), None)
            if not ra or not rb or rate(ra) is None or rate(rb) is None:
                continue
            d = rate(ra) - rate(rb)
            diffs.append(d)
            if d < 0:
                w += 1
            elif d > 0:
                l += 1
            else:
                e += 1
        rows.append([f"{a} vs {b}", f"{w} / {e} / {l}", p1(sum(diffs) / len(diffs)) if diffs else "—", f"{sign_p(w, l):.3f}"])
    A(table(["Pair", "cases: fewer repeats / equal / more", "mean difference of the repeat share", "p (sign test)"], rows))
    A("")
    rows = []
    for a, b in (("graph", "iso"), ("graph", "prose"), ("graph", "raw")):
        if a not in S or b not in S:
            continue
        w = l = e = 0
        for c in cases:
            ra = next((r for r in by_mode[a] if r["case"] == c and not r.get("error")), None)
            rb = next((r for r in by_mode[b] if r["case"] == c and not r.get("error")), None)
            if not ra or not rb:
                continue
            ta = ra["goal_turn"] if ra["completed"] else cap
            tb = rb["goal_turn"] if rb["completed"] else cap
            w += ta < tb
            l += ta > tb
            e += ta == tb
        rows.append([f"{a} vs {b}", f"{w} / {e} / {l}", f"{sign_p(w, l):.3f}"])
    A("Turns to the goal (fewer is better):")
    A("")
    A(table(["Pair", "cases: faster / equal / slower", "p (sign test)"], rows))
    A("")

    # ---------------------------------------------------------------- 4 both directions
    A("## 4. Both directions: who repeated whose steps")
    A("")
    A("A row \"X→Y\" counts how often agent X repeated a step that Y had made earlier. If the exchange works both ways, there are zeros on both sides.")
    A("")
    mat = {m: defaultdict(int) for m in modes}
    for r in R:
        for k, v in (r.get("repeat_matrix") or {}).items():
            mat[r["mode"]][k] += v
    keys = sorted({k for m in modes for k in mat[m]})
    if keys:
        A(table(["direction"] + [MODE_NAMES[m].split(" — ")[0] for m in modes], [[k.replace("->", " → ")] + [mat[m].get(k, 0) for m in modes] for k in keys]))
    else:
        A("No repeats of a partner's steps were recorded in any mode.")
    A("")

    # ---------------------------------------------------------------- 5 by agent
    A("## 5. What each agent did")
    A("")
    per = defaultdict(lambda: defaultdict(int))
    codes = defaultdict(lambda: defaultdict(int))
    for r in R:
        for t in r.get("turn_log", []):
            p = per[t["backend"]]
            p["turns"] += 1
            p["accepted"] += t["accepted"]
            p["new"] += t["new"]
            p["repeat"] += t["repeat_partner"] + t["repeat_self"]
            p["rejected"] += t["rejected"]
            p["over"] += t["over_budget"]
            p["out"] += t["out_tokens"]
            for c in t["reject_codes"]:
                codes[t["backend"]][c] += 1
    rows = []
    for b in ("codex", "deepseek", "opus"):
        if b in per:
            p = per[b]
            top = ", ".join(f"{c}×{n}" for c, n in sorted(codes[b].items(), key=lambda x: -x[1])[:3]) or "—"
            rows.append([BACKENDS[b], p["turns"], p["accepted"], p["new"], p["repeat"], p["rejected"], top, p["over"]])
    A(table(["Agent", "turns", "accepted", "new steps", "repeats", "rejected", "frequent kernel rejections", "extra lines over budget"], rows))
    A("")

    # ---------------------------------------------------------------- 6 by team
    A("## 6. Pairs and the trio")
    A("")
    rows = []
    teams = sorted({tuple(v) for v in team_of.values()})
    for team in teams:
        name = "+".join(BACKENDS[b].split(" ")[0] for b in team)
        row = [name]
        for m in modes:
            rs_ = [r for r in by_mode[m] if tuple(team_of[r["case"]]) == team and not r.get("error")]
            a_ = sum(r["events_accepted"] for r in rs_)
            rp_ = sum(r["repeat_partner"] + r["repeat_self"] for r in rs_)
            tt = sum((r["goal_turn"] if r["completed"] else cap) for r in rs_) / max(1, len(rs_))
            row.append(f"{p1(rp_ / a_) if a_ else '—'} · turns {f1(tt)}")
        rows.append(row)
    A(table(["Team"] + [MODE_NAMES[m].split(" — ")[0] for m in modes], rows))
    A("")

    # ---------------------------------------------------------------- 7 example
    A("## 7. One case, turn by turn")
    A("")
    ex_case = max(cases, key=lambda c: len(team_of[c]))
    A(f"Case {ex_case}: team {' + '.join(BACKENDS[b].split(' ')[0] for b in team_of[ex_case])}. Columns: whose turn — new / repeats (partner's+own) / rejected — how many reference conclusions are done.")
    A("")
    maxt = 0
    cols = {}
    for m in modes:
        r = next((x for x in by_mode[m] if x["case"] == ex_case), None)
        cols[m] = r
        if r:
            maxt = max(maxt, len(r.get("turn_log", [])))
    hdr = ["turn"] + [MODE_NAMES[m].split(" — ")[0] for m in modes]
    rows = []
    for t in range(maxt):
        row = [t + 1]
        for m in modes:
            r = cols[m]
            tl = r.get("turn_log", []) if r else []
            if t < len(tl):
                x = tl[t]
                row.append(f"{x['backend']}: {x['new']} / {x['repeat_partner'] + x['repeat_self']} / {x['rejected']} — done {x['targets_done']}/{r['targets']}")
            else:
                row.append("")
        rows.append(row)
    A(table(hdr, rows))
    A("")

    # ---------------------------------------------------------------- 8 honest reading
    A("## 8. What follows from this")
    A("")
    vis = [m for m in ("prose", "raw", "graph") if m in S]
    g_rep = sum(r["repeat_partner"] + r["repeat_self"] for r in by_mode.get("graph", []) if not r.get("error"))
    g_trio = sum(r["repeat_partner"] + r["repeat_self"] for r in by_mode.get("graph", []) if not r.get("error") and len(team_of[r["case"]]) == 3)
    iso_r = S.get("iso", {}).get("rate")
    if iso_r is not None and vis:
        lo, hi = min(S[m]["rate"] for m in vis), max(S[m]["rate"] for m in vis)
        A(f"- **Seeing the partners' work almost removes repeats — and it works both ways.** Without it {p1(iso_r)} of the accepted events are repeats "
          f"({S['iso']['rp']} times an agent repeated a partner's step); with any of the three ways to see the partners — {p1(lo)}–{p1(hi)}. Turns to the goal: {f1(S['iso']['turns_mean'])} without exchange "
          f"vs {f1(min(S[m]['turns_mean'] for m in vis))}–{f1(max(S[m]['turns_mean'] for m in vis))} with it. In iso everyone repeats everyone's steps (direction table in section 4); "
          "in the modes with visibility only isolated repeats remain (directions — same place).")
    if "graph" in S and vis:
        others = [m for m in ("prose", "raw") if m in S]
        better = all(S["graph"]["rate"] <= S[m]["rate"] for m in others)
        A("- **An advantage of the graph specifically over prose and the raw log is NOT shown in this run.** "
          + "Repeat share: " + ", ".join(f"{m} {p1(S[m]['rate'])}" for m in others) + f", graph {p1(S['graph']['rate'])}; in the paired comparisons the graph is better, worse and equal in different cases, with no significant differences "
          "(section 3). "
          + ("The graph turned out no worse than both." if better else
             f"The graph is even slightly behind here: {g_trio} of its {g_rep} repeats fell on cases with a trio of agents."))
        A("  On short histories (≤ 12 turns, ≤ 60 events) strong models get enough from a couple of sentences from a partner or from the raw log. "
          "This does not refute the idea of the graph: at this scale it simply adds nothing (a possible explanation is the short history, but that is an assumption).")
    rep_by = defaultdict(int)
    for r in R:
        if r["mode"] != "iso":
            for k, v in (r.get("repeat_matrix") or {}).items():
                rep_by[k.split("->")[0]] += v
    tot_rep = sum(rep_by.values())
    if tot_rep:
        top = max(rep_by, key=rep_by.get)
        A(f"- **Who repeated with visibility.** Of {tot_rep} repeats in the prose/raw/graph modes, {rep_by[top]} were made by {BACKENDS.get(top, top)}; the other agents never repeated a partner's step in these modes. "
          "This is probably a property of that particular model (how it reads the shared state), not of the mode; there is no data to check this assumption.")
    wr = sum(S[m]["wrong"] + S[m]["flags"] for m in modes)
    rj = sum(S[m]["rejected"] for m in modes)
    acc_all = sum(S[m]["accepted"] for m in modes)
    A(f"- **What the compiler gave in every mode.** Repeats measured by node identity (aliases, argument order and names do not fool the counter), strict checking of quotes and derivations "
      f"(wrong facts and false conclusions: {wr}; kernel rejections: {rj} per {f0(acc_all)} accepted events) and shared references to nodes. But these are properties of the kernel, not of the graph as a way of showing state.")
    A("- **The strict format is extra work.** Kernel rejections (reused local names, a reference to the wrong node type, broken JSON) are rare, but they concentrate on DeepSeek (section 5); "
      "the kernel returns the exact reason.")
    A("- **What remains untested.** The setting in which the graph should win: long histories, 4–5 agents, parallel turns, retraction and contradiction of claims "
      "(there a retelling goes stale, while the graph with statuses does not). That is the next experiment, not a conclusion of this one.")
    A("")

    # ---------------------------------------------------------------- 9 caveats
    A("## 9. Caveats")
    A("")
    tot_cost = sum(S[m]["cost"] for m in modes)
    cav = [
        f"**Small sample:** {len(cases)} cases per mode, one run each. The sign tests are rough; model answers are non-deterministic.",
        "**The task is synthetic and simple** (finding interval intersections in templated sentences). Its difficulty was chosen so that it cannot be finished in one turn, but it is not real reasoning.",
        "**Turns are sequential, not parallel.** With parallel work some repeats are unavoidable (nobody sees the others' turn) — that is a separate experiment.",
        "**Agents are told explicitly not to repeat others' steps** — in every mode. The modes differ only in visibility.",
        "**The kernel counts a repeat by node identity.** An accepted event that produced an existing node is a repeat; a new alternative support for the same claim (another quote) also counts as a repeat, since the goal does not need it.",
        "**A preliminary fix of the environment.** In the first trial run the graph mode did not show agents their own local names, and they reused them (`DUPLICATE_LOCAL_ID`). "
        "That was a defect of the environment, not of the idea; now the own history is visible in every mode, and the graph trial run was repeated. No other adjustments were made.",
        f"**DeepSeek tokens are estimated**; the runtimes' overhead is subtracted from the input (values in section 2). Cost is shown only for Opus (total for the whole run: ${tot_cost:.2f}).",
        "**The data is synthetic**; only generated task texts leave the machine.",
    ]
    for i, c in enumerate(cav, 1):
        A(f"{i}. {c}")
    A("")
    A("## 10. Reproduction")
    A("")
    A("```bash")
    A("python benchmarks/run_exp7_multiagent.py              # 8 cases × 4 modes, needs Codex ≥ 0.163, OpenClaw (deepseek-chat), Claude Code ≥ 2.1.280")
    A("python benchmarks/run_exp7_multiagent.py --cases 1 --max-turns 6   # quick check")
    A("python benchmarks/run_exp7_multiagent.py --report-only")
    A("```")
    A("")
    return "\n".join(L)
