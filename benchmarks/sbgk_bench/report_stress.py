"""Renders results/exp8/*.json into the EXP-8 report (separate from the earlier reports)."""

from __future__ import annotations

from collections import Counter  # noqa: F401 - kept for callers that extend the report

from . import exp8_stats as S
from .report import f0, f1, f2, p1, table  # noqa: F401 - shared helpers

MODE_SHORT = {"iso": "iso", "prose": "prose", "raw": "raw", "graph": "graph", "graphopen": "graph+open"}
MODE_DESC = {
    "iso": "partners not visible (baseline: how many repeats happen without exchange)",
    "prose": "the partner's words: a message of up to 60 words after each of its turns",
    "raw": "the partners' raw event log (JSONL as is, with the kernel's verdict at that time)",
    "graph": "the graph the kernel assembled from the byte container (current statuses, retractions, conflicts)",
    "graphopen": "graph + a list of \"open obligations\" (supported facts not yet used in any derivation) — "
                 "extra intelligence computed from the graph, not part of the byte format",
}
SCN_TITLE = {
    "retractp": "Scenario 1b — the same, but only one agent receives the erratum (the others learn of it through their channel)",
    "retract": "Scenario 1 — retraction of a claim and contradicting sources",
    "scale": "Scenario 2 — scale: 5 agents, 22 services, two-level inference, a long history",
    "parallel": "Scenario 3 — parallel rounds: all agents act at once on the same snapshot",
}
SCN_NO = {"retract": 2, "retractp": 3, "scale": 4, "parallel": 5}
UNIT = {"retract": "turns", "retractp": "turns", "scale": "turns", "parallel": "rounds"}
BACKENDS = {"codex": "Codex gpt-5.6-sol", "deepseek": "DeepSeek-chat (OpenClaw)", "opus": "Claude Opus 5.5", "sonnet": "Claude Sonnet 5.5"}
CODES_TEXT = {"PREMISE_CONFLICTING": "derive from a conflicting fact", "PREMISE_UNSUPPORTED": "premise lost its support", "EVIDENCE_REVOKED": "quote already revoked",
              "ALREADY_REVOKED": "repeated revocation", "EVIDENCE_NOT_ACTIVE": "quote not active", "DUPLICATE_LOCAL_ID": "reused local name",
              "EMPTY_INTERVAL_INTERSECTION": "windows do not overlap", "UNKNOWN_LOCAL_ID": "unknown name", "BAD_JSON": "broken JSON"}


def mn(m: str) -> str:
    return MODE_SHORT[m]


def pstr(p: float) -> str:
    return f"{p:.3f}" if p >= 0.001 else "<0.001"


def mode_list(by: dict) -> list[str]:
    return [m for m in S.MODES if m in by]


def pair_row(by, a, b, key, cap, pct=False):
    r = S.paired(by, a, b, key, cap)
    if not r:
        return None
    md = f"{100 * r['mean_diff']:+.1f} pp" if pct else f"{r['mean_diff']:+.2f}"
    return [f"{mn(a)} vs {mn(b)}", r["n"], f"{r['win']} / {r['tie']} / {r['loss']}", md, pstr(r["p"])]


def verdict_word(r):
    """Plain-language reading of one paired comparison (lower is better)."""
    if not r:
        return "no data"
    w, l = r["win"], r["loss"]
    if w + l == 0:
        return "equal"
    if r["p"] < 0.05:
        return "significantly better" if w > l else "significantly worse"
    if w > l and r["p"] < 0.3:
        return "slightly better (not significant)"
    if l > w and r["p"] < 0.3:
        return "slightly worse (not significant)"
    return "no difference"


def scenario_block(name: str, D: dict) -> tuple[list[str], dict]:
    spec = D["spec"]
    cap = spec["cap"]
    unit = UNIT[name]
    by = S.split_by_mode(D["results"])
    modes = mode_list(by)
    agg = {m: S.agg(by[m], cap) for m in modes}
    out: list[str] = []
    a = out.append
    a(f"## {SCN_NO[name]}. {SCN_TITLE[name]}")
    a("")
    nc = len(D["case_info"])
    ci = D["case_info"][0]
    team = " + ".join(BACKENDS[b].split(" ")[0] for b in spec["team"])
    kept = f" (of {D['all_cases']} launched, only the cases where all five modes ran without a single call failure are kept)" if D.get("all_cases") else ""
    a(f"Cases: **{nc}**{kept} · modes: {len(modes)} · runs: {len(D['results'])} · team: {len(spec['team'])} agents ({team}) · "
      f"at most {spec['k']} events per turn · cap {cap} {unit} · an ideal team needs at least ≈{ci['min_events']} events "
      f"(≈{-(-ci['min_events'] // (spec['k'] * (len(spec['team']) if spec['parallel'] else 1)))} {unit} without a single repeat).")
    a("")
    # --- main table
    rows = []
    for m in modes:
        g = agg[m]
        rows.append([mn(m), f"{g['completed']}/{g['n']}", f1(g["steps_mean"]), f0(g["accepted"]), f"{g['rp'] + g['rs']} ({p1(g['rate'])})",
                     f"{g['avoidable']} ({p1(g['rate_avoidable'])})", g["rejected"], g["wrong_facts"], g["false_final"] + g["missing_final"] + g["withdrawn_active_final"],
                     f0(g["in_net"]), f"${g['cost']:.2f}", f0(g["seconds"])])
    a(table(["Mode", "goal reached", f"{unit} to goal (mean; cap on failure)", "events accepted", "repeats (share)", "of them avoidable",
             "kernel rejections", "wrong facts", "defects at the end", "input without overhead, tokens", "Claude, $", "call time, s"], rows))
    a("")
    if any(agg[m]["failed"] for m in modes):
        a("Excluded runs with a launch error or three or more model call failures: " + ", ".join(f"{mn(m)} — {agg[m]['failed']}" for m in modes if agg[m]["failed"]) + ".")
        a("")
    a("\"Defects at the end\" is the sum of: false/stale conclusions in the kernel + missing reference conclusions + quotes withdrawn by the erratum but still active. "
      "An \"avoidable\" repeat is one where the partner's step was already in the state the agent saw at the start of its turn/round (a step made in the same round cannot be seen — that is an unavoidable repeat).")
    a("")
    # --- paired
    a(f"### Paired comparisons by case ({nc} cases; exact two-sided sign test; \"better\" = lower)")
    a("")
    for key, label, pct in (("rate", "Repeat share", True), ("steps", f"{unit.capitalize()} to goal", False), ("defects", "Defects at the end", False), ("rejected", "Kernel rejections", False)):
        if key == "defects" and name not in ("retract", "retractp"):
            continue
        rows = [x for x in (pair_row(by, p, q, key, cap, pct) for p, q in S.PAIRS) if x]
        if rows:
            a(f"**{label}**")
            a("")
            a(table(["pair", "n", "better / equal / worse", "mean difference", "p"], rows))
            a("")
    # --- scenario specific
    if name in ("retract", "retractp"):
        a("### What happened to the retraction and the contradiction")
        a("")
        rows = []
        for m in modes:
            g = agg[m]
            rows.append([mn(m), f"{g['clean']}/{g['n']}", g["stale_final"], g["under_conflict_final"], g["missing_final"], g["withdrawn_active_final"],
                         g["wrong_revokes"], g["dropped_plain"], g["repeat_after_notice"], g["rederive"], f"{g['x_ok']}/{g['n']}", f"{g['p_ok']}/{g['n']}",
                         g["reject_codes"].get("PREMISE_CONFLICTING", 0), g["reject_codes"].get("ALREADY_REVOKED", 0) + g["reject_codes"].get("EVIDENCE_REVOKED", 0)])
        a(table(["Mode", "clean final state", "stale conclusions left", "conclusion over an unresolved conflict", "missing conclusions", "withdrawn quotes still active",
                 "wrong revocations", "conclusions lost by mistake", "repeats after the erratum", "x restored", "d kept", "\"derive from conflict\" rejections", "\"already revoked\" rejections"], rows))
        a("")
        a("Roles in each case: **w** — the clause the erratum withdraws (its conclusion must disappear); **d** — a clause withdrawn but restated by another clause "
          "(the fact must survive — that is DRed's job); **x** — a contradiction the erratum resolves (the conclusion for x must come back); **y** — a contradiction that is never resolved "
          "(there must be no conclusion). \"Conclusions lost by mistake\" — reference conclusions (other than x and d) that were supported and then disappeared.")
        a("")
    if name == "scale":
        a("### How the cost of history grows")
        a("")
        edges = ["0–19", "20–39", "40–59", "60+"]
        hb = {m: S.history_buckets(by[m]) for m in modes}
        rows = []
        for i, e in enumerate(edges):
            row = [f"{e}"]
            for m in modes:
                b = hb[m][i]
                row.append(f"{p1(b['rep'] / b['acc'])} ({b['acc']})" if b["acc"] else "—")
            rows.append(row)
        a("Repeat share among accepted events depending on how many events the team had already accepted at the start of the turn (in brackets — accepted events in the bucket):")
        a("")
        a(table(["accepted at the start of the turn"] + [mn(m) for m in modes], rows))
        a("")
        rows = []
        for i, e in enumerate(edges):
            row = [f"{e}"]
            for m in modes:
                b = hb[m][i]
                row.append(f"{b['in_net'] // b['calls']:,}".replace(",", " ") if b["calls"] else "—")
            rows.append(row)
        a("Mean input of one call (tokens without runtime overhead) in the same split:")
        a("")
        a(table(["accepted at the start of the turn"] + [mn(m) for m in modes], rows))
        a("")
        a("Share of the partners' log that did not fit into the prompt (raw mode) and number of calls where the graph had to be compacted to clause labels: " +
          ", ".join(f"{mn(m)} — {p1(agg[m]['raw_hidden_share'])}" for m in modes if m == "raw") + "; " +
          ", ".join(f"{mn(m)} — {agg[m]['compact_calls']} of {agg[m]['calls']}" for m in modes if m in ("graph", "graphopen")) + ". "
          f"The prompt budget is 27500 characters of command line.")
        a("")
    if name == "parallel":
        a("### Unavoidable and avoidable repeats by round")
        a("")
        rt = {m: S.round_table(by[m]) for m in modes}
        rows = []
        for i in range(4):
            lab = f"round {i + 1}" if i < 3 else "rounds 4+"
            row = [lab]
            for m in modes:
                b = rt[m][i]
                if not b["acc"]:
                    row.append("—")
                else:
                    row.append(f"{b['unavoid']} / {b['rep'] - b['unavoid']} of {b['acc']}")
            rows.append(row)
        a("Each cell: unavoidable repeats / avoidable repeats out of the round's accepted events (summed over cases). "
          "Unavoidable — a step a partner made in the same round; avoidable — a step that was already in the shared state at the start of the round.")
        a("")
        a(table(["round"] + [mn(m) for m in modes], rows))
        a("")
    return out, agg


# ------------------------------------------------------------------ cross-scenario parts

def claude_spend() -> dict[str, tuple[float, int]]:
    """Money actually spent on the Claude seat, per model: every call ever cached in results/exp8/calls
    (smoke runs, calibration probes, the Opus pilot and discarded runs included)."""
    import json
    from . import exp8_env as E
    out: dict[str, list] = {}
    for f in (E.OUT / "calls").glob("*.json"):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if d.get("backend") in ("opus", "sonnet"):
            v = out.setdefault(d["backend"], [0.0, 0])
            v[0] += d.get("cost_usd") or 0.0
            v[1] += 1
    return {k: (v[0], v[1]) for k, v in out.items()}


def scoreboard(an: dict) -> tuple[list[str], dict]:
    """Rows: scenario x comparison. Columns: repeat rate, turns/rounds to goal (and defects for the retraction scenario)."""
    rows, summary = [], {}
    for name, (by, cap) in an.items():
        for a, b in (("graph", "prose"), ("graph", "raw"), ("graph", "iso"), ("graphopen", "graph")):
            rr, rs = S.paired(by, a, b, "rate", cap), S.paired(by, a, b, "steps", cap)
            rd = S.paired(by, a, b, "defects", cap) if name == "retract" else None
            if not rr:
                continue
            rows.append([SCN_TITLE[name].split(" — ")[0], f"{mn(a)} vs {mn(b)}", rr["n"],
                         f"{rr['win']}/{rr['tie']}/{rr['loss']}; {100 * rr['mean_diff']:+.1f} pp; p={pstr(rr['p'])}",
                         f"{rs['win']}/{rs['tie']}/{rs['loss']}; {rs['mean_diff']:+.2f}; p={pstr(rs['p'])}",
                         (f"{rd['win']}/{rd['tie']}/{rd['loss']}; {rd['mean_diff']:+.2f}; p={pstr(rd['p'])}" if rd else "—")])
            summary[(name, a, b)] = {"rate": rr, "steps": rs, "defects": rd}
    return rows, summary


def example_table(name: str, D: dict, modes: list[str], cap: int) -> list[str]:
    by = S.split_by_mode(D["results"])
    c = S.case_pick(by, cap)
    if c is None:
        return []
    runs = {m: next((r for r in by[m] if r["case"] == c and not r.get("error")), None) for m in modes}
    n_steps = max((r["steps_run"] for r in runs.values() if r), default=0)
    rows = []
    for st in range(1, n_steps + 1):
        row = [st]
        for m in modes:
            r = runs[m]
            if not r or st > r["steps_run"]:
                row.append("")
                continue
            s = r["step_log"][st - 1]
            cell = "; ".join(f"{x['label']}: {x['new']}/{x['repeat_partner'] + x['repeat_self']}/{x['rejected']}" for x in s["recs"])
            extra = f" — done {s['done']}/{r['targets']}" + (f", conflicts {s['conflicting']}" if s["conflicting"] else "") + (" · **erratum**" if s.get("notice_issued") else "")
            row.append(cell + extra)
        rows.append(row)
    out = [f"Case {c}. In a cell: agent: new steps / repeats / kernel rejections — how many reference conclusions are done.", ""]
    out.append(table(["step"] + [mn(m) for m in modes], rows))
    return out


def render(data: dict, frozen: bool = False) -> str:
    L: list[str] = []
    A = L.append
    names = [n for n in ("retract", "retractp", "scale", "parallel") if n in data]
    first = data[names[0]]
    for n in names:
        S.normalize(data[n])
    A("# SBGK-P0 — EXP-8: does a shared compiled graph withstand stress — retraction, scale, parallel rounds"
      + (" (experiment frozen, incomplete sample)" if frozen else ""))
    A("")
    bl = first["backends"]
    A("Agents: " + "; ".join(f"**{BACKENDS[k]}** ({v['label']}, {v.get('version', '')})" for k, v in bl.items()) + ".  ")
    if frozen:
        A("")
        A("> **Status: EXP-8 is frozen and did not reach its planned size.** The first launch (Claude seat — Opus 5.5) hit the subscription session limit, and some turns "
          "got a refusal instead of a model answer; the relaunch with Sonnet 5.5 was stopped, and by the user's decision the experiment was frozen in favour of EXP-9. "
          "The report includes **only runs without a single call failure**, and only cases where such runs exist in all five modes: " +
          ", ".join(f"{SCN_TITLE[n].split(' — ')[0].lower()} — {len(data[n]['case_info'])} of {data[n].get('all_cases', len(data[n]['case_info']))}" for n in names) +
          ". This is pilot data: no comparison of modes here can be statistically significant; read them as observations.")
        A("")
    A("This is a **separate report** (a continuation of EXP-7): the earlier reports, `results/summary.json`, `results/exp3_llm`, `results/exp7` and the EXP-7 modules were not changed; "
      "the new files are `benchmarks/sbgk_bench/exp8_*.py`, `report_stress.py`, `benchmarks/run_exp8_stress.py`, `results/exp8/`. The kernel (Rust) was not touched.")
    A("")
    an = {n: (S.split_by_mode(data[n]["results"]), data[n]["spec"]["cap"]) for n in names}
    rows, summ = scoreboard(an)
    spend = claude_spend()
    A("## 0. In plain words")
    A("")
    A("In EXP-7 any visibility of the partners' work almost removed repeats, but **the compiled graph was not better than a retelling or the raw log** — the histories were too short "
      "(≤ 12 turns, ≤ 60 events, 2–3 agents). Here three situations are built in which unstructured exchange should break down, and each runs separately so that the effect can be "
      "attributed to its cause:")
    A("")
    A("1. **Retraction and contradiction.** Midway an erratum appears: it withdraws a usage clause (w), a deprecation clause of an API on which several conclusions rest "
      "(p; it is restated in another clause, so the fact can be re-supported — and the conclusions come back without being re-derived), and one side of a contradiction (x); the second contradiction (y) "
      "is never resolved. A retelling should go stale, while the graph shows `SUPPORTED / UNSUPPORTED / CONFLICTING_SOURCES`. "
      "**1b** — the same cases, but **only one agent** receives the erratum; the others learn of it only through their channel (message, log or graph).")
    A("2. **Scale.** 5 agents (two Codex, two DeepSeek, Claude), 26 services, 7 systems, two-level inference, up to 30 turns of 4 events; clauses are written in three ways "
      "(ids, aliases, another word order) — the history reaches ~100 events and the raw log no longer fits into the prompt.")
    A("3. **Parallel rounds.** 4 agents act at once on the same snapshot; the kernel merges the results after the round.")
    A("")
    A("Five modes: " + "; ".join(f"**{mn(m)}** — {MODE_DESC[m]}" for m in S.MODES) + ".")
    A("")
    A("**Summary of paired comparisons** (by case; \"better / equal / worse\" for the first mode of the pair; lower = better; exact two-sided sign test, p without correction for multiple comparisons):")
    A("")
    A(table(["scenario", "pair", "n cases", "repeat share", "turns/rounds to goal", "defects at the end"], rows))
    A("")
    A("**The verdict is in section 8**, details and caveats below. The samples are small (n is given in every table), so strong statements are allowed only where p < 0.05 "
      "and the direction is the same across metrics.")
    A("")
    # ---------------------------------------------------------------- 1
    A("## 1. How the environment works")
    A("")
    A("- **Shared with EXP-7:** the SBGK kernel as the only shared channel (agents write strict JSON events, the kernel checks quotes against the document bytes, computes derivations and intervals, "
      "canonicalizes aliases and erases local names); model calls in an empty temporary folder without tools; the kernel judges a repeat by node identity: an accepted event "
      "that produced an already existing active node (quote or claim) is a repeat, whoever made it, whatever it was called and in whatever order it was written.")
    A("- **What EXP-8 changes:** (a) repeating a node that lost its support (`UNSUPPORTED`) is a **restoration**, not a repeat; (b) in the parallel scenario repeating a step "
      "a partner made **in the same round** is **unavoidable**, the rest are **avoidable**; (c) agents prefix local names with \"tag+turn number\" so that names do not clash; "
      "(d) the kernel's verdict in the log includes the claim status (e.g. `CONFLICTING_SOURCES`) and the outcome of a revocation cascade.")
    A(f"- **Prompt budget.** DeepSeek takes the prompt as a Windows command-line argument, so for all agents alike the prompt is limited to {27500} characters "
      "of command line (tested up to 28.7 k). If it does not fit: the graph is first compacted to clause labels (`Clause U.12`), then the raw/prose/own-history modes "
      "keep the most recent entries and drop older ones with a note. The share of hidden log is given in scenario 2.")
    A("- **What counts as an error.** The kernel and the graph judge everything, not the harness: a false conclusion is a `needs_review`/`sys_flagged` in status `SUPPORTED` that is not in the reference; "
      "a wrong fact is an accepted `uses_api`/`api_deprecated`/`part_of` that is not in the document; a kernel rejection is an event refused by the check (after the first rejection the rest of the agent's turn "
      "is not sent).")
    if frozen:
        A("- **The Claude agent is Opus 5.5** (`claude-opus-5-5`) through the newest bundled copy of Claude Code (the system one is too old). The launch was interrupted by the subscription session limit; "
          "runs with failed calls are discarded entirely (the harness now aborts such a run and does not count it).")
    else:
        A("- **The Claude agent is Sonnet 5.5** (`claude-sonnet-5-5`) through the newest bundled copy of Claude Code (the system one is too old). The first EXP-8 launch ran with Opus 5.5, "
          "but hit the subscription session limit (some turns got a refusal instead of an answer); at the user's request the Claude seat went to Sonnet 5.5, and **all runs of the report were redone "
          "with Sonnet**. The Opus pilot data is in `results/exp8/opus_pilot/` and is not used in the conclusions (briefly — in the caveats).")
    A("- **Tokens and money.** Codex and Claude tokens are exact (from the runtime's report), DeepSeek's are estimated; the runtime's per-call overhead is measured with three probe calls "
      "and subtracted from the input; the cost in dollars is shown only for Claude. Claude Code's token report is noisy (prompt cache), so the prompt size in characters is given alongside.")
    A("")
    for n in names:
        blk, _ = scenario_block(n, data[n])
        L.extend(blk)
        L.extend(example_header(n, data[n]))
    # ---------------------------------------------------------------- tail sections
    tail(L, data, names, an, summ, spend, frozen)
    return "\n".join(L) + "\n"


def example_header(n: str, D: dict) -> list[str]:
    spec = D["spec"]
    by = S.split_by_mode(D["results"])
    modes = mode_list(by)
    out = ["", f"### One case, step by step ({SCN_TITLE[n].split(' — ')[0]})", ""]
    out += example_table(n, D, modes, spec["cap"])
    out.append("")
    return out


def tail(L, data, names, an, summ, spend, frozen=False):
    A = L.append
    A("## 6. Directions of repeats and agent behaviour")
    A("")
    for n in names:
        by = S.split_by_mode(data[n]["results"])
        modes = mode_list(by)
        mats = {m: S.direction_matrix(by[m]) for m in modes}
        keys = sorted({k for m in modes for k in mats[m]})
        A(f"**{SCN_TITLE[n].split(' — ')[0]}** — \"X→Y\": agent X repeated a step that Y had made earlier (all runs of the mode).")
        A("")
        if keys:
            A(table(["direction"] + [mn(m) for m in modes], [[k] + [mats[m].get(k, 0) for m in modes] for k in keys]))
        else:
            A("No repeats.")
        A("")
        at = S.agent_table([r for m in modes if m != "iso" for r in by[m]])
        rows = []
        for lab in sorted(at):
            a = at[lab]
            codes = ", ".join(f"{CODES_TEXT.get(k[5:], k[5:])}×{v}" for k, v in sorted(a.items()) if k.startswith("code:"))
            rows.append([lab, a["calls"], a["accepted"], a["new"], f"{a['repeats']} ({p1(a['repeats'] / a['accepted']) if a['accepted'] else '—'})", a["rejected"], codes or "—",
                         a["empty"], a["over_budget"], a["call_errors"]])
        A("Agents (modes other than iso):")
        A("")
        A(table(["agent", "calls", "accepted", "new", "repeats (share)", "kernel rejections", "rejection codes", "empty turns", "extra lines", "call failures"], rows))
        A("")
    A("## 7. Tokens, cost, time")
    A("")
    rows = []
    for n in names:
        by = S.split_by_mode(data[n]["results"])
        for m in mode_list(by):
            g = S.agg(by[m], data[n]["spec"]["cap"])
            ok = S.usable(by[m])
            chars = sum(x["cmdlen"] or 0 for r in ok for s in r["step_log"] for x in s["recs"])
            crit = sum(max((x["seconds"] for x in st["recs"]), default=0.0) for r in ok for st in r["step_log"])
            rows.append([SCN_TITLE[n].split(" — ")[0], mn(m), g["calls"], f"{chars / max(1, g['calls']):,.0f}".replace(",", " "), f0(g["in_net"]), f0(g["out"]), f"${g['cost']:.2f}",
                         f1(g["seconds"] / max(1, g["n"])), f1(crit / max(1, g["n"]))])
    A(table(["scenario", "mode", "calls", "mean prompt, characters", "input without overhead, tokens", "output, tokens", "Claude, $", "sum of call time per run, s", "critical-path time per run, s"], rows))
    A("")
    ov = data[names[0]]["overhead_in_tokens"]
    A("Runtime overhead per call (mean of three probe calls): " + ", ".join(f"{BACKENDS[k]} — {f0(v)}" for k, v in ov.items()) +
      ". DeepSeek tokens are estimated; Claude Code's token report fluctuates from call to call because of the prompt cache, so compare modes on Claude tokens only roughly.")
    A("")
    sv, op = spend.get("sonnet", (0.0, 0)), spend.get("opus", (0.0, 0))
    A(f"**Spending on Claude for the whole of EXP-8** (every call recorded in `results/exp8/calls`, including calibration and interrupted runs): "
      f"Sonnet 5.5 — **${sv[0]:.2f}** for {sv[1]} calls (main runs); Opus 5.5 — **${op[0]:.2f}** for {op[1]} calls (pilot, stopped by the subscription limit, not part of the analysis). "
      f"Total **${sv[0] + op[0]:.2f}**.")
    A("")
    if frozen:
        frozen_verdict(L, data, names, an, summ)
    else:
        verdict(L, data, names, an, summ)
    caveats(L, data, names, frozen)


def _cmp(summ, name, a, b, key):
    r = summ.get((name, a, b), {}).get(key)
    return r


def verdict(L, data, names, an, summ):
    A = L.append
    A("## 8. Verdict: what the graph won and what remains unproven")
    A("")
    lines = []
    for n in names:
        sc = SCN_TITLE[n].split(" — ")[0]
        res = {}
        for b in ("prose", "raw", "iso"):
            res[b] = (_cmp(summ, n, "graph", b, "rate"), _cmp(summ, n, "graph", b, "steps"), _cmp(summ, n, "graph", b, "defects"))
        lines.append((n, sc, res))
    for n, sc, res in lines:
        gp = res["prose"]
        gr = res["raw"]
        gi = res["iso"]
        A(f"- **{sc}.** Graph vs iso: repeats — {verdict_word(gi[0])}, {UNIT[n]} to goal — {verdict_word(gi[1])}. "
          f"Graph vs prose: repeats — {verdict_word(gp[0])}, {UNIT[n]} to goal — {verdict_word(gp[1])}" + (f", defects — {verdict_word(gp[2])}" if gp[2] else "") + ". "
          f"Graph vs raw: repeats — {verdict_word(gr[0])}, {UNIT[n]} to goal — {verdict_word(gr[1])}" + (f", defects — {verdict_word(gr[2])}" if gr[2] else "") + ".")
    for n in names:
        go = _cmp(summ, n, "graphopen", "graph", "rate")
        gos = _cmp(summ, n, "graphopen", "graph", "steps")
        if go:
            A(f"- **graph+open vs graph ({SCN_TITLE[n].split(' — ')[0]}):** repeats — {verdict_word(go)}, {UNIT[n]} to goal — {verdict_word(gos)}.")
    A("")


def frozen_verdict(L, data, names, an, summ):
    """Verdict of the frozen pilot: plain statements built from the measured aggregates, no claims beyond what n allows."""
    A = L.append
    G = {n: {m: S.agg(an[n][0][m], an[n][1]) for m in S.MODES if m in an[n][0]} for n in names}
    A("## 8. Verdict of the frozen pilot")
    A("")
    seq = [n for n in names if n != "parallel"]
    vis_seq = [G[n][m]["rate"] for n in seq for m in ("prose", "raw", "graph", "graphopen") if m in G[n]]
    iso = [G[n]["iso"]["rate"] for n in names if "iso" in G[n]]
    txt = (f"1. **Visibility of the shared state again removes repeats — this was reproduced in every scenario.** Without exchange (iso) the repeat share is {p1(min(iso))}–{p1(max(iso))}; "
           f"with sequential turns and any kind of exchange — {p1(min(vis_seq))}–{p1(max(vis_seq))}.")
    if "parallel" in G:
        g = G["parallel"]
        txt += (" In parallel rounds there are more repeats (" + ", ".join(f"{mn(m)} {p1(g[m]['rate'])}" for m in ("prose", "raw", "graph", "graphopen")) +
                "), but almost none of them are avoidable (" + ", ".join(f"{mn(m)} {p1(g[m]['rate_avoidable'])}" for m in ("prose", "raw", "graph", "graphopen")) +
                "): what remains are collisions inside one round that nobody could see.")
    A(txt)
    if "retract" in G:
        g = G["retract"]
        clean = ", ".join(f"{mn(m)} {g[m]['clean']}/{g[m]['n']}" for m in ("prose", "raw", "graph", "graphopen"))
        A(f"2. **With a shared erratum the graph did not win on retraction and contradiction.** Every mode with exchange finished the task without defects ({clean} cases in a clean final state); "
          f"turns to goal: prose {f1(g['prose']['steps_mean'])}, raw {f1(g['raw']['steps_mean'])}, graph {f1(g['graph']['steps_mean'])}, graph+open {f1(g['graphopen']['steps_mean'])}; "
          f"repeat share: prose {p1(g['prose']['rate'])}, raw {p1(g['raw']['rate'])}, graph {p1(g['graph']['rate'])}. The graph is slightly more economical on repeats than the retelling, but the difference on "
          f"{g['graph']['n']} cases proves nothing. The reason is clear: the erratum is visible to everyone, and the kernel itself runs the revocation cascade in every mode, so the agent does not have "
          "to track which conclusions went stale.")
    if "parallel" in G:
        g = G["parallel"]
        A(f"3. **In parallel rounds the graph was worse than the retelling.** Repeat share: prose {p1(g['prose']['rate'])}, raw {p1(g['raw']['rate'])}, graph {p1(g['graph']['rate'])}, "
          f"graph+open {p1(g['graphopen']['rate'])} (rounds to goal {f1(g['prose']['steps_mean'])} / {f1(g['raw']['steps_mean'])} / {f1(g['graph']['steps_mean'])} / {f1(g['graphopen']['steps_mean'])}). "
          "Almost all of these repeats are collisions inside a round: the agents see the same canonical state (and in graph+open the same sorted list of open "
          "obligations) and take the same top steps at the same time. A passive shared graph without work allocation amplifies the \"herd\" effect — the main concrete "
          "weakness found in EXP-8, and the direct motive for EXP-9 (handing out different directives to different seats).")
    extra = [n for n in ("scale", "retractp") if n in G]
    if extra:
        bits = []
        for n in extra:
            g = G[n]
            bits.append(f"{SCN_TITLE[n].split(' — ')[0].lower()} ({g['graph']['n']} case): " +
                        ", ".join(f"{mn(m)} — {'goal' if g[m]['completed'] else 'did not finish'} in {f1(g[m]['steps_mean'])} turns" for m in ('iso', 'prose', 'raw', 'graph', 'graphopen')))
        A("4. **Scale and the private erratum — one case each, that is an anecdote, not data:** " + "; ".join(bits) + ".")
    A("")
    A("**How far the user's thesis is supported** (agents exchange reasoning through the compiler and do not repeat each other's steps): the first half — *exchange through "
      "a shared verified state removes repeats* — is confirmed again. The second half — *a strict compiled graph beats unstructured exchange* — is "
      "**not shown** in this pilot: with sequential turns the graph is on par with the retelling and the raw log, and in parallel rounds it loses to them because everyone picks the same steps at once. "
      "The situations in which the graph should win (long history, private notice) were covered by one case in the pilot — there is no honest answer for them.")
    A("")


def caveats(L, data, names, frozen=False):
    A = L.append
    A("## 9. Caveats")
    A("")
    ncases = {n: len(data[n]["case_info"]) for n in names}
    A("1. **Small samples.** " + ", ".join(f"{SCN_TITLE[n].split(' — ')[0]} — {ncases[n]} cases" for n in names) +
      "; one run per (case, mode) pair. The sign test with n = 6 can give p < 0.05 only with 6 wins of 6 (p = 0.031); there is no correction for multiple "
      "comparisons. Everything below that threshold is an observation, not proof. Model answers are non-deterministic.")
    A("2. **The task is synthetic and templated** (interval intersection over uniform sentences; in the second scenario one more level of inference). It tests "
      "coordination and tracking of the shared state, not real reasoning.")
    A("3. **The kernel counts a repeat by node identity.** A new alternative support of an already established claim (another quote) is also a repeat; restoring "
      "a claim that lost its support is not a repeat. In every mode the agents are told alike not to repeat others' steps.")
    A("4. **The prompt budget is the same for every mode** (27,500 characters of command line, a DeepSeek/OpenClaw limit). With a long history it cuts the raw log and "
      "the retelling, while the graph is only compacted to clause labels; for large-context models (Codex, Claude) raw might look better without this limit. "
      "The share of hidden log is given in scenario 2.")
    A("5. **\"Open obligations\" (graph+open) are computed by the harness** from the graph read from the byte container; the kernel (Rust) was not changed. This is extra "
      "intelligence on top of the graph, so graph+open is compared with graph separately.")
    A("6. **Runtime failures.** The first launch with Opus 5.5 hit the subscription session limit; during the pilot OpenClaw sometimes answered \"database is locked\" with many "
      "parallel processes. Now a run with a failed call is aborted entirely and redone (successful calls come from the cache), DeepSeek calls "
      "are limited by cross-process slots; only runs without a single failure enter the analysis.")
    A("7. **Call cache.** A model answer is stored by the exact prompt text; if a Codex or DeepSeek prompt matched a pilot prompt (usually the first turns before Claude's first turn), "
      "the same answer is used. This does not change the distribution of answers, but makes runs reproducible.")
    A("8. **The team in a scenario is fixed**, the first speaker changes from case to case; in the parallel scenario the merge order of the round's events changes too. "
      "So \"who repeated whose step\" depends both on the model and on the place in the queue.")
    A("9. **The erratum in scenario 1 arrives after turn 3–5** (once the premise to be revoked is bound, otherwise after turn 5); in 1b only the agent of the next turn sees it.")
    A("10. **The data is synthetic**; only generated task texts leave the machine.")
    A("")
    A("## 10. Reproduction")
    A("")
    A("```bash")
    A("python benchmarks/run_exp8_stress.py --selftest                     # offline, scripted agent, no model calls")
    A("python benchmarks/run_exp8_stress.py --smoke                        # 2 cases × 3 scenarios × 5 modes")
    A("python benchmarks/run_exp8_stress.py                                # full run (cases: retract 7, scale 6, parallel 7)")
    A("python benchmarks/run_exp8_stress.py --report-only                  # rebuild the report from results/exp8/*.json")
    A("```")
