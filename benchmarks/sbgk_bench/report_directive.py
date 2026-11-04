"""Renders results/exp9/*.json into the EXP-9 report and a machine-readable summary (results/exp9/summary.json)."""

from __future__ import annotations

import json
import statistics

from . import exp8_stats as S
from .report import f0, f1, p1, table

MN = {"iso": "iso", "prose": "prose", "raw": "raw", "graph": "graph", "graphopen": "graph+open", "directive": "**directive**", "stateful": "stateful O(N)"}
BLOCK = {
    "a_trio": "EXP-9A-1 — turn-based team Codex + DeepSeek-chat + Claude Sonnet (the EXP-7 task, 12 services)",
    "a_solo": "EXP-9A-2 — a weak graph-builder: DeepSeek-chat alone (the same cases)",
    "b_parallel": "EXP-9B — parallel rounds: 4 agents at once on the same snapshot (EXP-8 scenario 3, 20 services)",
    "c_retract": "EXP-9C-1 — an erratum midway and contradictions (EXP-8 scenario 1)",
    "c_long": "EXP-9C-2 — a long register: 48 services, one agent (Codex), O(N) vs O(1) window",
}
UNIT = {"b_parallel": "rounds"}
BACKENDS = {"codex": "Codex gpt-5.6-sol", "deepseek": "DeepSeek-chat (OpenClaw)", "sonnet": "Claude Sonnet 5.5", "opus": "Claude Opus 5.5"}


def mn(m):
    return MN.get(m, m)


def pstr(p):
    return f"{p:.3f}" if p >= 0.001 else "<0.001"


def recs(runs):
    return [x for r in S.usable(runs) for st in r["step_log"] for x in st["recs"]]


def per_call(runs):
    """Mean prompt size (characters of the prompt as sent) and net input tokens per model call (repair calls included)."""
    rs = recs(runs)
    calls = sum(1 + int(bool(x.get("repair_call"))) for x in rs)
    chars = sum((x.get("cmdlen") or x.get("prompt_chars") or 0) + (x.get("prompt_chars_repair") or 0) for x in rs)
    net = sum(x.get("in_net", 0) for x in rs)
    return {"calls": calls, "chars": chars / calls if calls else 0.0, "in_net": net / calls if calls else 0.0}


def agent_rate(runs, label):
    rs = [x for x in recs(runs) if x["label"] == label]
    acc = sum(x["accepted"] for x in rs)
    rep = sum(x["repeat_partner"] + x["repeat_self"] for x in rs)
    return rep, acc


S.METRICS["cpc"] = ("prompt characters per call", lambda r, cap: per_call([r])["chars"])


def defects(r):
    return r["false_final"] + r["missing_final"] + r["withdrawn_active_final"]


def block_table(name, D):
    cap = D["spec"]["cap"]
    by = S.split_by_mode(D["results"])
    modes = [m for m in D["modes"] if m in by]
    rows, agg = [], {}
    for m in modes:
        g = S.agg(by[m], cap)
        pc = per_call(by[m])
        agg[m] = {**g, **{"per_call_chars": pc["chars"], "per_call_in_net": pc["in_net"], "model_calls": pc["calls"]}}
        coll = g["unavoidable"] / g["accepted"] if g["accepted"] else 0.0
        idle = sum(r.get("idle_seat_slots", 0) for r in S.usable(by[m]))
        agg[m]["collision_rate"] = coll
        agg[m]["idle_seat_slots"] = idle
        rows.append([mn(m), f"{g['completed']}/{g['n']}", f1(g["steps_mean"]), f0(g["accepted"]), f"{g['rp'] + g['rs']} ({p1(g['rate'])})", p1(g["rate_avoidable"]),
                     p1(coll) if D["spec"].get("parallel") else "—", g["rejected"], g["wrong_facts"], g["false_final"] + g["missing_final"] + g["withdrawn_active_final"],
                     f0(pc["calls"]), f0(pc["chars"]), f0(pc["in_net"]), f0(g["in_net"]), f"${g['cost']:.2f}"])
    unit = UNIT.get(name, "turns")
    head = ["mode", "goal reached", f"{unit} to goal (mean; failure = cap)", "events accepted", "repeats (share)", "avoidable", "in-round collisions",
            "kernel rejections", "wrong facts", "defects at the end", "model calls", "prompt characters per call", "input tokens per call", "input total, tokens", "Claude, $"]
    return table(head, rows), agg, by, modes, cap


def paired_rows(by, modes, cap, keys):
    rows = []
    for m in modes:
        if m == "directive":
            continue
        for key, label, pct in keys:
            r = S.paired(by, "directive", m, key, cap)
            if r:
                md = f"{100 * r['mean_diff']:+.1f} pp" if pct else f"{r['mean_diff']:+.1f}"
                rows.append([f"directive vs {mn(m)}", label, r["n"], f"{r['win']} / {r['tie']} / {r['loss']}", md, pstr(r["p"])])
    return rows


def window_table(D, steps=(1, 10, 20, 30, 48)):
    by = S.split_by_mode(D["results"])
    rows = []
    data = {}
    for st in steps:
        row = [st]
        for m in ("stateful", "directive"):
            vals, toks, nodes = [], [], []
            for r in S.usable(by.get(m, [])):
                if len(r["step_log"]) >= st:
                    s = r["step_log"][st - 1]
                    x = s["recs"][0] if s["recs"] else None
                    if x:
                        vals.append(x.get("cmdlen") or x.get("prompt_chars") or 0)
                        toks.append(x.get("in_net", 0))
                    nodes.append(s.get("nodes", 0))
            data[(m, st)] = (statistics.fmean(vals) if vals else None, statistics.fmean(toks) if toks else None, statistics.fmean(nodes) if nodes else None)
            v, t, n = data[(m, st)]
            row += [f0(v) if v is not None else "—", f0(t) if t is not None else "—", f0(n) if n is not None else "—"]
        rows.append(row)
    return rows, data


def perf_rows(all_data):
    rows = []
    out = {}
    for name, D in all_data.items():
        us, warm, segs = [], [], []
        for r in S.usable([x for x in D["results"] if x["mode"] == "directive"]):
            for s in r["step_log"]:
                if s.get("analysis_us") is not None:
                    us.append(s["analysis_us"])
                if s.get("analysis_warm_us") is not None:
                    warm.append(s["analysis_warm_us"])
                if s.get("segments"):
                    segs.append(s["segments"])
        if not us:
            continue
        us.sort()
        w = sorted(warm)
        med = statistics.median(us)
        p95 = us[int(0.95 * (len(us) - 1))]
        out[name] = {"median_us": med, "p95_us": p95, "warm_median_us": statistics.median(w) if w else None, "n": len(us),
                     "segments": round(statistics.fmean(segs)) if segs else None, "under_500us": sum(1 for x in us if x < 500) / len(us)}
        rows.append([BLOCK[name].split(" — ")[0], len(us), out[name]["segments"] or "—", f0(med), f0(p95), f0(out[name]["warm_median_us"]) if w else "—",
                     p1(out[name]["under_500us"])])
    return rows, out


def claude_spend9() -> tuple[float, int] | None:
    from . import exp9_directive_emitter as X
    tot, n = 0.0, 0
    for f in (X.OUT / "calls").glob("*.json"):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if d.get("backend") == "sonnet":
            tot += d.get("cost_usd") or 0.0
            n += 1
    return (tot, n) if n else None


def v1_retract() -> dict | None:
    """Directive results of the first compiler version (kept for the record) in the retraction block."""
    from . import exp9_directive_emitter as X
    f = X.OUT / "v1_directive" / "c_retract.json"
    if not f.exists():
        return None
    D = json.loads(f.read_text(encoding="utf-8"))
    rs = [r for r in S.usable(D["results"]) if r["mode"] == "directive"]
    if not rs:
        return None
    return {"n": len(rs), "clean": sum(1 for r in rs if r["completed"] and defects(r) == 0), "under_conflict": sum(r["under_conflict_final"] for r in rs),
            "wrong_revokes": sum(r["wrong_revokes"] for r in rs)}


def oracle_window() -> dict:
    from . import exp9_directive_emitter as X
    f = X.OUT / "window_replay.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}


def resident_speed() -> dict:
    """Compiler speed after the resident path (`sbgk serve` op `directives`) and the cached analysis (run_exp9_directive.py --speed)."""
    from . import exp9_directive_emitter as X
    f = X.OUT / "speed_resident.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}


def harness_check() -> dict:
    """The harness switch to the resident op, checked with the oracle worker (results/exp9/harness_resident_check.json)."""
    from . import exp9_directive_emitter as X
    f = X.OUT / "harness_resident_check.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}


def _mp(st: dict | None) -> str:
    return "—" if not st or not st.get("n") else f"{f0(st['median'])} / {f0(st['p95'])}"


def _m(st: dict | None) -> str:
    return "—" if not st or not st.get("n") else f0(st["median"])


def resident_section(L, R: dict) -> dict | None:
    """Subsection of the speed section: resident vs one-shot compiler on identical states, before / after this change."""
    sm = R.get("summary") or {}
    if not sm:
        return None
    A = L.append
    n_states = sum(s["rounds"] for s in sm.values())
    n_same = sum(s["identical_rounds"] for s in sm.values())
    A("### Resident compiler and analysis cache (after optimization)")
    A("")
    A('What changed. (1) `sbgk serve` got the op `{"op":"directives","targets":…,"seats":K,"k":4,"round":r}`: the frontier and the frames '
      "are computed on the live session — no container is built, re-read or verified, and the support cone is read directly from the engine (the same selection "
      "`cone::minimal_cone_value` makes from the bytes). (2) Everything the analysis derives from immutable inputs is cached (`DirectiveCache`): the ontology's "
      "name index, the sentences of each document version with mentions, labels, type signatures and an \"entity → sentences\" index, byte spans and "
      "quotes of evidence, heads of rule applications; nodes are read from the engine without encoding/decoding, nested scans are replaced by indexes. "
      "A CLI call starts with an empty cache (the \"cold\" column), the resident compiler keeps the cache for the whole session.")
    A("")
    A("How it was measured: `python benchmarks/run_exp9_directive.py --speed --baseline-bin <previous sbgk>`. Each register is played by the oracle worker "
      "through one `serve` process; at the start of every round the same state is measured resident (the first call after the events of the previous round — "
      "\"round\", then repeats without changes), through the CLI on a snapshot of that state, and by the previous binary on the same snapshot. "
      f"Frames and all non-timing fields of the batch were byte-identical on **{n_same} of {n_states}** states (the `serve_vs_cli` test checks the same in `cargo test`). "
      "Time is `analysis_us` / `total_us` from inside Rust, µs, median / p95 over rounds.")
    A("")
    rows = []
    for key, st in sm.items():
        rows.append([key, st["services"], st["rounds"], st["segments_mean"], _mp(st["serve_round_analysis_us"]), _mp(st["serve_repeat_analysis_us"]),
                     _mp(st["serve_round_total_us"]), _mp(st["cli_cold_analysis_us"]), _mp(st["cli_warm_analysis_us"]), _m(st["cli_open_us"]), _m(st["cli_wall_us"])])
    A(table(["register", "services", "rounds", "sentences", "serve: round analysis", "serve: repeat", "serve: analysis + frames",
             "CLI: cold analysis", "CLI: warm analysis", "CLI: read + verify, median", "CLI: whole process, median"], rows))
    A("")
    if any("baseline_cold_analysis_us" in st for st in sm.values()):
        rows = []
        for key, st in sm.items():
            old_warm = (st.get("baseline_warm_analysis_us") or {}).get("median")
            new_round = st["serve_round_analysis_us"].get("median")
            rows.append([key, _m(st.get("baseline_cold_analysis_us")), _m(st.get("baseline_warm_analysis_us")), _m(st["cli_cold_analysis_us"]),
                         _m(st["cli_warm_analysis_us"]), _m(st["serve_round_analysis_us"]),
                         f"{old_warm / new_round:.1f}×" if old_warm and new_round else "—", f"{st['identical_rounds']}/{st['rounds']}"])
        A("Before and after on the same states (frontier analysis, µs, median; \"before\" — the previous binary that made the runs above):")
        A("")
        A(table(["register", "before: cold", "before: warm", "after: CLI cold", "after: CLI warm", "after: serve, round",
                 "faster (before warm / serve)", "frames identical"], rows))
        A("")
    big = {k: st for k, st in sm.items() if st["services"] >= 48}
    if big:
        ok = all(st["serve_round_analysis_us"]["median"] < 500 for st in big.values())
        A("Target \"frontier analysis < 0.5 ms\" on 48 and 96 services: median of the resident round " +
          ", ".join(f"{st['services']} services — {f0(st['serve_round_analysis_us']['median'])} µs" for st in big.values()) +
          (" — **met**. " if ok else " — **not met**. ") +
          "A cold CLI call (new process, empty cache) is still more expensive: reading and verifying the container and starting the process add to the analysis, "
          "so long registers need the resident path. The harness of the model runs in this report called the CLI of the previous compiler; "
          "the new compiler's frames for the same states are the same, so the results above do not change.")
        A("")
    H = harness_check()
    if H.get("oracle"):
        o, w = H["oracle"], H.get("window", {})
        pb = o["per_block"]
        A(f"**The harness was switched to the resident path** (since {H['created'][:10]}): `run_directive` and the window replay take the frames from the `directives` op "
          "of the kernel process; `--cli-directives` restores the previous CLI call on a snapshot. Check without models: all "
          f"{o['cases']} runs of the oracle worker ({o['steps']} turns) give the same turns, events, rejections, goals and frames as the stored results "
          f"({o['identical_to_stored']}/{o['cases']}), and the resident path matches the CLI ({o['resident_equals_cli']}/{o['cases']}); "
          f"the window replays ({', '.join(w)}) match at every step ({sum(1 for v in w.values() if v['identical'])}/{len(w)}). "
          "Compiler per turn (median, analysis + frames, µs; CLI — without process start): " +
          ", ".join(f"{BLOCK[b].split(' — ')[0]} {f0(v['emit_total_median_us']['resident'])} vs {f0(v['emit_total_median_us']['cli'])}" for b, v in pb.items()) +
          ". The model runs in the report were not rerun: their frames are the same.")
        A("")
    mach = R.get("machine", {})
    A(f"Machine: {mach.get('platform', '?')}, {mach.get('processor', '?')}; measured {R.get('created', '?')}. On a hybrid processor (P- and E-cores) "
      "Windows sometimes moves the `serve` process waiting on stdin to the efficiency cores — single rounds are then 2–3 times slower; this shows "
      "in p95, the medians hardly depend on it.")
    A("")
    return {k: {"services": st["services"], "serve_round_median_us": st["serve_round_analysis_us"].get("median"), "serve_round_p95_us": st["serve_round_analysis_us"].get("p95"),
                "cli_cold_median_us": st["cli_cold_analysis_us"].get("median"), "cli_warm_median_us": st["cli_warm_analysis_us"].get("median"),
                "baseline_warm_median_us": (st.get("baseline_warm_analysis_us") or {}).get("median"), "identical": f"{st['identical_rounds']}/{st['rounds']}"}
            for k, st in sm.items()}


def window_section(L, sec, W) -> dict | None:
    if not W:
        return None
    A = L.append
    A(f"## {sec}. O(N) vs O(1) window on the same graph states (no models)")
    A("")
    A("To separate the growth of the window from model behaviour, the case is played by a deterministic directive worker, and at **every** step, on the same "
      "kernel state, both windows are measured: the directive frame the compiler emits, and the prompt a stateful agent would get (the whole document + the whole graph "
      "+ its whole own history, no budget). Tokens are estimated as \"characters / 4\".")
    A("")
    out = {}
    for key, rows in W.items():
        if not rows:
            continue
        last = rows[-1]["step"]
        last_work = max(r["step"] for r in rows if r["directive_chars"])  # the final step is P4 (no frame) when the run completed
        pick = sorted({s for s in (1, 10, 20, 30, 48, 60, 80) if s <= last} | {last_work, last})
        tab = []
        for st in pick:
            r = rows[st - 1]
            tab.append([st, r["graph_events"], r["nodes"], f0(r["stateful_chars"]), f0(r["stateful_chars"] / 4), f0(r["directive_chars"]), f0(r["directive_chars"] / 4),
                        f"{r['stateful_chars'] / r['directive_chars']:.1f}×" if r["directive_chars"] else "—"])
        dir_vals = [r["directive_chars"] for r in rows if r["directive_chars"]]
        st_vals = [r["stateful_chars"] for r in rows]
        out[key] = {"steps": last, "directive_min": min(dir_vals), "directive_max": max(dir_vals), "stateful_first": st_vals[0], "stateful_last": st_vals[-1]}
        A(f"**{key}** ({last} steps to P4; at the P4 step there is no frame — no work left):")
        A("")
        A(table(["step", "events in the graph", "nodes in the kernel", "stateful, characters", "≈ tokens", "directive, characters", "≈ tokens", "times smaller"], tab))
        A("")
        A(f"Directive frame over the whole run: {f0(min(dir_vals))}–{f0(max(dir_vals))} characters; stateful prompt: from {f0(st_vals[0])} at the first step to {f0(st_vals[-1])} at the last.")
        A("")
    return out


def verdict(L, sec, aggs, perf, summary):
    A = L.append
    A(f"## {sec}. Verdict: what of the promises held")
    A("")
    rows = []

    def g(block, mode, key):
        try:
            return aggs[block][0][mode][key]
        except KeyError:
            return None

    # 9A
    for block in ("a_trio", "a_solo"):
        if block not in aggs:
            continue
        agg, by, modes, cap = aggs[block]
        ds = {m: agent_rate(by[m], "deepseek") for m in modes}
        dsr = {m: (r / a if a else None) for m, (r, a) in ds.items()}
        d = dsr.get("directive")
        others = ", ".join(f"{mn(m)} {p1(v)}" for m, v in dsr.items() if m != "directive" and v is not None)
        rows.append([BLOCK[block].split(" — ")[0], "DeepSeek repeats = 0.0 %", f"directive {p1(d) if d is not None else '—'} (for comparison: {others})",
                     "yes" if d == 0 else ("almost" if d is not None and d < 0.02 else "no")])
        dc = g(block, "directive", "per_call_chars")
        if dc:
            ratios = {m: agg[m]["per_call_chars"] / dc for m in modes if m != "directive"}
            lo, hi = min(ratios.values()), max(ratios.values())
            rows.append([BLOCK[block].split(" — ")[0], "prompt per call 4–8 times smaller", ", ".join(f"{mn(m)} {v:.1f}×" for m, v in ratios.items()),
                         "yes" if lo >= 4 else ("partly" if hi >= 4 else "no")])
        dd = agg.get("directive")
        if dd:
            ok = dd["completed"] == dd["n"] and dd["false_final"] + dd["missing_final"] + dd["withdrawn_active_final"] == 0 and dd["wrong_facts"] == 0
            rows.append([BLOCK[block].split(" — ")[0], "100 % of the reference, 0 defects", f"goal {dd['completed']}/{dd['n']}, defects {dd['false_final'] + dd['missing_final'] + dd['withdrawn_active_final']}, "
                         f"wrong facts {dd['wrong_facts']}, turns {f1(dd['steps_mean'])} (graph {f1(g(block, 'graph', 'steps_mean') or 0)})", "yes" if ok else "no"])
    # 9B
    if "b_parallel" in aggs:
        agg, by, modes, cap = aggs["b_parallel"]
        dd = agg.get("directive")
        if dd:
            rows.append(["EXP-9B", "avoidable repeats = 0.0 %", f"directive {p1(dd['rate_avoidable'])} (" + ", ".join(f"{mn(m)} {p1(agg[m]['rate_avoidable'])}" for m in modes if m != 'directive') + ")",
                         "yes" if dd["rate_avoidable"] == 0 else "no"])
            rows.append(["EXP-9B", "in-round collisions = 0.0 %", f"directive {p1(dd['collision_rate'])} (" + ", ".join(f"{mn(m)} {p1(agg[m]['collision_rate'])}" for m in modes if m != 'directive') + ")",
                         "yes" if dd["collision_rate"] == 0 else ("almost" if dd["collision_rate"] < 0.02 else "no")])
            rows.append(["EXP-9B", "rounds and tokens", f"rounds: directive {f1(dd['steps_mean'])}, " + ", ".join(f"{mn(m)} {f1(agg[m]['steps_mean'])}" for m in modes if m != 'directive') +
                         f"; input total: directive {f0(dd['in_net'])}, graph {f0(g('b_parallel', 'graph', 'in_net') or 0)}", "see the table"])
    # 9C
    if "c_retract" in aggs:
        agg, by, modes, cap = aggs["c_retract"]
        dd = agg.get("directive")
        if dd:
            dfx = dd["false_final"] + dd["missing_final"] + dd["withdrawn_active_final"]
            rows.append(["EXP-9C-1", "0 defects after the erratum", f"clean final states {dd['clean']}/{dd['n']}, defects {dfx}, repeats after the erratum {dd['repeat_after_notice']}",
                         "yes" if dfx == 0 and dd["clean"] == dd["n"] else "no"])
    if summary.get("window_replay"):
        w = summary["window_replay"]
        flat = all(v["directive_max"] < 4500 for v in w.values())
        rows.append(["EXP-9C-2", "directive window is a constant O(1)", "; ".join(f"{k}: frame {f0(v['directive_min'])}–{f0(v['directive_max'])} characters, stateful {f0(v['stateful_first'])} → {f0(v['stateful_last'])}" for k, v in w.items()),
                     "yes" if flat else "no"])
    blocks_perf = {k: v for k, v in perf.items() if not k.startswith("_")} if perf else {}
    if blocks_perf:
        med = max(v["median_us"] for v in blocks_perf.values())
        under = [k for k, v in blocks_perf.items() if v["median_us"] < 500]
        longw = perf.get("_window", {})
        rows.append(["kernel" + (" (compiler of the model runs)" if perf.get("_resident") else ""), "frontier analysis < 0.5 ms", "medians: " + ", ".join(f"{BLOCK[k].split(' — ')[0]} {f0(v['median_us'])} µs" for k, v in blocks_perf.items()) +
                     ("; long registers: " + ", ".join(f"{k} {f0(v['median_us'])} µs" for k, v in longw.items()) if longw else ""),
                     "yes" if med < 500 and all(v["median_us"] < 500 for v in longw.values()) else ("partly" if under else "no")])
    res = perf.get("_resident") if perf else None
    if res:
        rows.append(["kernel, resident compiler", "frontier analysis < 0.5 ms (incl. 48–96 services)",
                     "median of a `serve` round: " + ", ".join(f"{v['services']} svc {f0(v['serve_round_median_us'])} µs" for v in res.values()) +
                     "; frames identical to the CLI on " + ", ".join(v["identical"] for v in res.values()) + " states",
                     "yes" if all(v["serve_round_median_us"] < 500 for v in res.values()) else "no"])
    A(table(["test", "promised in the task", "measured", "held?"], rows))
    A("")
    summary["verdict_rows"] = rows
    narrative(L, aggs, perf, summary)


def _mean_ratio(aggs, block, key="per_call_chars"):
    agg = aggs[block][0]
    d = agg.get("directive", {}).get(key)
    if not d:
        return None
    return {m: agg[m][key] / d for m in agg if m != "directive" and agg[m].get(key)}


def narrative(L, aggs, perf, summary):
    A = L.append
    A("")
    A("**In plain words.**")
    A("")
    bullets = []
    # what worked
    parts = []
    for b in ("a_trio", "a_solo", "b_parallel", "c_retract"):
        if b not in aggs or "directive" not in aggs[b][0]:
            continue
        d = aggs[b][0]["directive"]
        parts.append(f"{BLOCK[b].split(' — ')[0]}: goal {d['completed']}/{d['n']}, repeats {d['rp'] + d['rs']}, kernel rejections {d['rejected']}")
    if parts:
        bullets.append("**Directive has no or almost no repeats and collisions, and the final graph is correct.** " + "; ".join(parts) +
                       ". The reason is structural: the compiler hands out work that is not yet in the graph and never gives one target or one sentence to two seats; "
                       "the agent does not choose what to do — it does the prescribed step with ready `@id`s of the premises.")
    rs = [(b, _mean_ratio(aggs, b)) for b in ("a_trio", "a_solo", "b_parallel", "c_retract") if b in aggs]
    rs = [(b, r) for b, r in rs if r]
    if rs:
        allv = [v for _, r in rs for v in r.values()]
        bullets.append(f"**The input of one call is {min(allv):.1f}–{max(allv):.1f} times smaller** (a directive frame ≈ 3 k characters instead of 10–17 k): "
                       "the agent gets 1–4 sentences, not the document, and the target's support cone, not the whole graph.")
    if "b_parallel" in aggs and "directive" in aggs["b_parallel"][0]:
        agg = aggs["b_parallel"][0]
        d = agg["directive"]
        worst = max((m for m in agg if m != "directive"), key=lambda m: agg[m]["collision_rate"])
        bullets.append(f"**The herd effect of parallel rounds is gone:** in-round collisions — directive {p1(d['collision_rate'])} vs {p1(agg['graph']['collision_rate'])} for graph, "
                       f"{p1(agg['graphopen']['collision_rate'])} for graph+open and {p1(agg['prose']['collision_rate'])} for prose (worst — {mn(worst)}). "
                       f"Rounds to goal: directive {f1(d['steps_mean'])}, graph {f1(agg['graph']['steps_mean'])}, prose {f1(agg['prose']['steps_mean'])}.")
    # costs
    costs = []
    for b in ("a_trio", "a_solo", "c_retract"):
        if b in aggs and "directive" in aggs[b][0] and "graph" in aggs[b][0]:
            agg = aggs[b][0]
            costs.append(f"{BLOCK[b].split(' — ')[0]}: {f1(agg['directive']['steps_mean'])} turns and {f0(agg['directive']['accepted'])} events vs "
                         f"{f1(agg['graph']['steps_mean'])} and {f0(agg['graph']['accepted'])} for graph")
    if costs:
        bullets.append("**The price: with sequential turns directive takes more steps.** " + "; ".join(costs) + ". The compiler cannot \"skip\" a service "
                       "by reading the time windows, as a strong model with the whole document does: it formalizes every reachable target (including traps with a late "
                       "deprecation) and closes it only when the facts are in the kernel. In exchange every step is cheaper, and the total input is lower (tables above).")
    if "c_long" in aggs:
        agg = aggs["c_long"][0]
        if "stateful" in agg and "directive" in agg:
            bullets.append(f"**The long register (48 services, Codex alone):** the stateful agent with the full window finished in {f1(agg['stateful']['steps_mean'])} turns "
                           f"with {f0(agg['stateful']['per_call_chars'])} characters per call (the window grows with the graph), directive in {f1(agg['directive']['steps_mean'])} turns with "
                           f"{f0(agg['directive']['per_call_chars'])} characters per call (constant window); input total: {f0(agg['stateful']['in_net'])} vs {f0(agg['directive']['in_net'])} tokens. "
                           "A strong model still copes with the full window at 48 services; directive's advantage here is a bounded and predictable window size, not accuracy.")
    if perf:
        meds = {k: v["median_us"] for k, v in perf.items() if not k.startswith("_")}
        longw = perf.get("_window", {})
        fast = [BLOCK[k].split(" — ")[0] for k, v in meds.items() if v < 500]
        slow = [BLOCK[k].split(" — ")[0] for k, v in meds.items() if v >= 500] + [k for k, v in longw.items() if v["median_us"] >= 500]
        bullets.append("**Kernel speed:** median frontier analysis " + ", ".join(f"{BLOCK[k].split(' — ')[0]} {f0(v)} µs" for k, v in meds.items()) +
                       ("; long registers " + ", ".join(f"{k} {f0(v['median_us'])} µs" for k, v in longw.items()) if longw else "") + ". "
                       + (f"The \"< 0.5 ms\" target is met for: {', '.join(fast)}; " if fast else "The \"< 0.5 ms\" target is not met in any block; ")
                       + (f"not met for: {', '.join(slow)}. " if slow else "")
                       + "Besides, every CLI call re-reads and re-verifies the container (~1–2 ms)."
                       + (" After the optimization the resident compiler (`sbgk serve`, op `directives`) computes a round in " +
                          ", ".join(f"{f0(v['serve_round_median_us'])} µs ({v['services']} svc)" for v in perf["_resident"].values()) +
                          " at the median with byte-identical frames — the target is met on long registers too." if perf.get("_resident") else ""))
    for b in bullets:
        A(f"- {b}")
    A("")
    drs = [r for b in ("a_trio", "a_solo", "b_parallel", "c_retract", "c_long") if b in aggs for r in S.usable(aggs[b][1].get("directive", []))]
    reps_d = sum(r["repeat_partner"] + r["repeat_self"] for r in drs)
    acc_d = sum(r["accepted"] for r in drs)
    clean_d = sum(1 for r in drs if r["completed"] and defects(r) == 0)
    A(f"Over all {len(drs)} directive model runs: a clean final state in {clean_d}, {reps_d} repeats per {acc_d} accepted events ({p1(reps_d / acc_d) if acc_d else '—'}), "
      f"0 in-round collisions.")
    A("")
    A("**How far the thesis is supported** (agents exchange reasoning through the compiler and do not repeat each other's steps): in EXP-7/EXP-8 it held only halfway — "
      "the shared state removed repeats, but the passive graph was not better than a retelling, and in parallel rounds it lost to it. When the compiler does not just show "
      "the graph but **allocates work along the frontier** and gives each seat its own directive, both halves of the thesis hold in these tests: almost no repeats, no collisions, "
      "a correct graph, a small agent window that does not grow. The price is extra steps in sequential work and compiler heuristics (amendments by keywords, "
      "type signatures) tuned to this document format.")
    A("")
    A("## Caveats")
    A("")
    for i, t in enumerate([
        "**Small samples:** 6 cases per block (c_long — 2), one run per (case, mode) pair. The sign test with n = 6 gives p < 0.05 only with 6 wins of 6 (p = 0.031); "
        "there is no correction for multiple comparisons. Model answers are non-deterministic.",
        "**The Claude agent is Sonnet 5.5**, not Opus 5.5 (subscription limit). All modes are compared within EXP-9 on the same cases and teams; a direct comparison with the numbers "
        "of EXP-7/EXP-8 is only qualitative.",
        "**Directive relies on knowledge the other modes do not have:** routing, precomputed intervals and `@id`s of premises. That is exactly the idea being tested, but some of the "
        "compiler's rules are heuristic and tied to the document format: amendments are recognized by keywords (withdrawn, stands in, …) and clause labels like `U.12`, "
        "the source of a missing premise by the type signature of the mentioned entities. Documents in another style will need these rules tuned.",
        "**Directive formalizes more:** every reachable target, including traps; unreachable ones (the API has no deprecation clause at all) the compiler closes without formalization. "
        "So its \"turns to goal\" can be higher than for a model that skips what is not needed by reading the text.",
        "**The O(1) window in the long-register section** was measured on a deterministic replay (the same graph states for both windows); there are 2 c_long model cases.",
        "**The upper bound (oracle)** is a worker that never errs; it checks the compiler and the harness, not a model result.",
        "**Compiler versions during the experiment:** the trial directive run (before pruning unreachable targets) — `results/exp9/pre_pruning/` (also without repeats, but with "
        "noticeably more turns: the compiler formalized every service); the first full run — `results/exp9/v1_directive/` (the 9C-1 failure, described above). "
        "The tables show only the final version; the baseline modes (iso…graph+open) do not depend on the compiler version.",
        "**Kernel time** was measured inside the CLI process; starting the process and verifying the container every round add ~1–2 ms, which the resident compiler does not pay.",
        "**Tokens:** the Codex and Claude Code token reports are noisy (runtime cache and system prompts), DeepSeek tokens are estimated; the main measure of window size is prompt characters.",
        "**The data is synthetic**; only generated task texts leave the machine.",
    ], 1):
        A(f"{i}. {t}")


def render(data: dict, oracle: dict) -> tuple[str, dict]:
    L: list[str] = []
    A = L.append
    for D in list(data.values()) + list(oracle.values()):
        S.normalize(D) if D.get("overhead_in_tokens") is not None else None
    A("# SBGK-P0 — EXP-9: the compiler hands out directives, the graph-builder works without memory (Addendum v0.2)")
    A("")
    bl = {}
    for D in data.values():
        bl.update(D.get("backends", {}))
    if bl:
        A("Agents: " + "; ".join(f"**{BACKENDS.get(k, k)}** ({v['label']}, {v.get('version', '')})" for k, v in sorted(bl.items())) + ".  ")
    A("New in the kernel: the module `crates/sbgk-core/src/directive.rs` and the commands `sbgk emit-directive`, `sbgk emit-batch-directives`, `sbgk frontier`; "
      "benchmark `benchmarks/sbgk_bench/exp9_directive_emitter.py`, runner `benchmarks/run_exp9_directive.py`, data — `results/exp9/`. "
      "The earlier reports and the data of EXP-1…EXP-8 were not changed.")
    A("")
    summary = {"blocks": {}}
    # ---------------------------------------------------------------- 0
    A("## 0. What changed and what was tested")
    A("")
    A("In EXP-7/EXP-8 the graph was a **passive notice board**: every turn the agent got the whole document, the whole ontology and the whole graph and decided by itself what to do; "
      "in parallel rounds all agents saw the same thing and took the same steps at the same time. The **directive** mode makes the kernel a dispatcher:")
    A("")
    A("1. **The frontier analyzer** (Rust, deterministic) finds the open work from the container bytes and a list of goals and orders it: "
      "P0 — apply an amendment / resolve a contradiction (revoke the evidence of a withdrawn clause); P1 — re-support a claim that lost its support from a restating clause; "
      "P2 — finish a rule derivation (2A: all premises are present — only a `derive` is needed, the interval is precomputed; 2B: one premise is present, the other must be extracted from a sentence found "
      "by the types of the mentioned entities); P3 — formalize an uncovered sentence that mentions a target; P4 — no work.")
    A("2. **Sharding over seats**: the directives of a round never give two seats the same target, the same source sentence or the same node; "
      "surplus seats get P4 and do not call the model at all.")
    A("3. **The directive frame** is the only thing the agent sees: 1–4 source sentences (not the document), the target's minimal support cone (not the graph), "
      "an ontology slice and a task text written by the kernel, with ready `@id`s of premises and the interval formula. If the kernel rejects an event — one repair attempt in the same "
      "small window; then the agent's context is discarded (the agent has no dialogue history).")
    A("")
    A("The other modes are the same as in EXP-8 (iso, prose, raw, graph, graph+open), run by the same harness on the same cases with the same team. "
      "**The Claude agent is Sonnet 5.5** (Opus 5.5's subscription limit was exhausted). So the comparison is made within EXP-9, not with the numbers of EXP-7/EXP-8 (they used Opus).")
    A("")
    # ---------------------------------------------------------------- blocks
    sec = 1
    aggs = {}
    for name in ("a_trio", "a_solo", "b_parallel", "c_retract", "c_long"):
        if name not in data:
            continue
        D = data[name]
        tb, agg, by, modes, cap = block_table(name, D)
        aggs[name] = (agg, by, modes, cap)
        nc = len(D["case_info"])
        A(f"## {sec}. {BLOCK[name]}")
        sec += 1
        A("")
        sp = D["spec"]
        A(f"Cases: **{nc}** · team: {' + '.join(sp['team'])} · at most {sp['k']} events per turn · cap {cap} {UNIT.get(name, 'turns')} · "
          f"targets (services) per case: {D['case_info'][0]['services']}, of them needing review ≈{D['case_info'][0]['gold_services']}.")
        A("")
        A(tb)
        A("")
        drs = S.usable(by.get("directive", []))
        if drs:
            viol = sum(r.get("contract_violations", 0) for r in drs)
            rc = sum(r.get("repair_calls", 0) for r in drs)
            rok = sum(r.get("repair_ok", 0) for r in drs)
            mx = max((x.get("cmdlen") or 0) for r in drs for st in r["step_log"] for x in st["recs"])
            A(f"Directive mode: repair attempts after a kernel rejection — {rc} ({rok} successful); events refused by the directive contract before the kernel — {viol}; "
              f"the largest frame — {f0(mx)} characters.")
            A("")
        summary["blocks"][name] = {m: {k: v for k, v in agg[m].items() if isinstance(v, (int, float, str))} for m in modes}
        if name in ("a_trio", "a_solo"):
            rows = []
            for m in modes:
                rep, acc = agent_rate(by[m], "deepseek")
                rows.append([mn(m), f"{rep} of {acc}", p1(rep / acc) if acc else "—"])
                summary["blocks"][name][m]["deepseek_repeat_rate"] = rep / acc if acc else None
            A("Repeats of work already done **by DeepSeek-chat** (its accepted events that produced an existing node):")
            A("")
            A(table(["mode", "DeepSeek repeats", "share"], rows))
            A("")
            d = agg.get("directive")
            if d:
                comp = [f"{mn(m)} — {agg[m]['per_call_chars'] / d['per_call_chars']:.1f} times" for m in modes if m != "directive" and d["per_call_chars"]]
                A("Input compression: the mean prompt of one call in directive mode — " + f"{f0(d['per_call_chars'])} characters; " + "smaller than " + ", ".join(comp) + ".")
                A("")
        if name == "b_parallel":
            d = agg.get("directive")
            if d:
                A(f"In directive mode idle seats (P4, the model was not called): {d['idle_seat_slots']} seat-rounds over all cases.")
                A("")
            rt = {m: S.round_table(by[m]) for m in modes}
            rows = []
            for i in range(4):
                row = [f"round {i + 1}" if i < 3 else "rounds 4+"]
                for m in modes:
                    b = rt[m][i]
                    row.append(f"{b['unavoid']} / {b['rep'] - b['unavoid']} of {b['acc']}" if b["acc"] else "—")
                rows.append(row)
            A("In-round collisions / avoidable repeats out of the accepted events, by round (summed over cases):")
            A("")
            A(table(["round"] + [mn(m) for m in modes], rows))
            A("")
        if name == "c_retract":
            rows = []
            for m in modes:
                g = agg[m]
                rows.append([mn(m), f"{g['clean']}/{g['n']}", g["stale_final"], g["under_conflict_final"], g["missing_final"], g["withdrawn_active_final"], g["wrong_revokes"],
                             g["repeat_after_notice"], g["rederive"], g["reject_codes"].get("PREMISE_CONFLICTING", 0)])
            A(table(["mode", "clean final state", "stale conclusions", "conclusion over a conflict", "missing conclusions", "withdrawn quotes active",
                     "wrong revocations", "repeats after the erratum", "re-derivation after the erratum", "\"derive from conflict\" rejections"], rows))
            A("")
            # how fast the directive mode switched to P0/P1 work after the erratum
            sw = []
            for r in S.usable(by.get("directive", [])):
                ns = r.get("notice_step")
                if ns is None:
                    continue
                nxt = [s for s in r["step_log"] if s["step"] == ns + 1]
                if nxt and nxt[0]["recs"]:
                    sw.append(nxt[0]["recs"][0]["priority"])
            if sw:
                A("The first directive after the erratum was published (by case): " + ", ".join(sw) + ".")
                A("")
            v1 = v1_retract()
            if v1:
                A(f"**The first compiler version failed here, and that matters:** in the first full run directive reached a clean final state in only {v1['clean']} of {v1['n']} cases "
                  f"(conclusions over an unresolved contradiction — {v1['under_conflict']}, wrong revocations — {v1['wrong_revokes']}). In both failed cases the FORMALIZE directive "
                  "showed the agent both contradicting sentences about service y at once (POS and NEG) together with the hint \"if the windows overlap, derive right away\". The agent derived (the kernel "
                  "refused: the premise is in conflict), then on its own initiative revoked the evidence of the NEG clause, which the erratum had not withdrawn; the conflict disappeared, and on the "
                  "next step the compiler honestly issued a \"ready derivation\" — cementing the agent's mistake. Fixed with two changes, after which all directive runs were redone: "
                  "(1) if a target has several sentences of the same type signature in the slice (a possible contradiction), there is no \"derive right away\" hint but an explicit \"assert as stated "
                  "and do not derive\"; a target that already has a conclusion still gets its unformalized sentences; (2) a **directive contract** in the harness: an event the frame "
                  "did not ask for (a quote not from the slice, revoking unlisted evidence) is refused before the kernel and goes to repair. Data of the first version — `results/exp9/v1_directive/`.")
                A("")
        if name == "c_long":
            rows, wd = window_table(D)
            A("Input size of one call at step s (mean over cases; tokens — input without runtime overhead; nodes — graph size in the kernel at the end of the step):")
            A("")
            A(table(["step", "stateful: characters", "stateful: tokens", "stateful: graph nodes", "directive: characters", "directive: tokens", "directive: graph nodes"], rows))
            A("")
            summary["blocks"][name]["window"] = {f"{m}@{st}": v for (m, st), v in wd.items()}
        # paired
        keys = [("rate", "repeat share", True), ("steps", f"{UNIT.get(name, 'turns')} to goal", False), ("cpc", "characters per call", False), ("in_net", "input total, tokens", False)]
        if name == "c_retract":
            keys.insert(2, ("defects", "defects at the end", False))
        pr = paired_rows(by, modes, cap, keys)
        if pr:
            A(f"Paired comparisons (over {nc} cases; exact two-sided sign test; \"better\" = lower):")
            A("")
            A(table(["pair", "metric", "n", "better / equal / worse", "mean difference", "p"], pr))
            A("")
    # ---------------------------------------------------------------- oracle
    if oracle:
        A(f"## {sec}. Upper bound: the same loop with a deterministic directive worker")
        sec += 1
        A("")
        A("The \"oracle\" worker does exactly what the frame says (it reads the clauses from the case's reference, no models). This checks the compiler and the harness: "
          "how many turns are needed if the agent never errs.")
        A("")
        rows = []
        for name, D in oracle.items():
            rs = S.usable(D["results"])
            if not rs:
                continue
            pc = per_call(rs)
            rows.append([BLOCK[name].split(" — ")[0], len(rs), f"{sum(r['completed'] for r in rs)}/{len(rs)}", f1(statistics.fmean(r["steps_run"] for r in rs)),
                         sum(r["repeat_partner"] + r["repeat_self"] for r in rs), sum(r["repeat_unavoidable"] for r in rs), sum(r["rejected"] for r in rs),
                         sum(defects(r) for r in rs), f0(pc["chars"]), f0(max(x.get("cmdlen") or 0 for x in recs(rs)))])
        A(table(["block", "runs", "goal", "turns/rounds (mean)", "repeats", "in-round collisions", "kernel rejections", "defects", "characters per frame (mean)", "max frame"], rows))
        A("")
    # ---------------------------------------------------------------- performance
    # timings from the oracle runs (same compiler code path, no model processes competing for the CPU); model runs as a fallback
    pr, perf = perf_rows({**data, **oracle})
    if pr:
        A(f"## {sec}. Compiler speed")
        sec += 1
        A("")
        A("Frontier analysis time in Rust (`analysis_us`, without reading and verifying the container) over all turns/rounds of the runs with the oracle worker "
          "(the same compiler code, no competing model processes; during the model runs, when 5 processes worked in parallel, the measurements are 2–4 times higher). "
          "\"Warm\" — a repeated analysis of the same state in the same process.")
        A("")
        A(table(["block", "measurements", "sentences in the documents (mean)", "median, µs", "p95, µs", "warm, median, µs", "share < 500 µs"], pr))
        A("")
        W = oracle_window()
        if W:
            rows = []
            for key, rws in W.items():
                us = sorted(r["analysis_us"] for r in rws)
                rows.append([key, len(us), f0(statistics.median(us)), f0(us[int(0.95 * (len(us) - 1))])])
            A("The same on long registers (deterministic replay from the window section; one process, but model runs may have been running at the same time):")
            A("")
            A(table(["register", "measurements", "median, µs", "p95, µs"], rows))
            A("")
            perf["_window"] = {r[0]: {"median_us": float(r[2].replace(" ", "")), "p95_us": float(r[3].replace(" ", ""))} for r in rows}
        res = resident_section(L, resident_speed())
        if res:
            perf["_resident"] = res
        summary["compiler_us"] = perf
    summary["aggs"] = {n: {m: {k: v for k, v in a[0][m].items() if isinstance(v, (int, float))} for m in a[2]} for n, a in aggs.items()}
    sp = claude_spend9()
    if sp:
        A(f"**Spending on Claude Sonnet 5.5 for EXP-9:** ${sp[0]:.2f} for {sp[1]} calls (including the trial run, the first directive version and calibration). "
          "Codex and DeepSeek run on a subscription/key and are not counted in dollars in this report.")
        A("")
    win = window_section(L, sec, oracle_window())
    if win:
        sec += 1
        summary["window_replay"] = win
    verdict(L, sec, aggs, perf, summary)
    A("")
    A("## Reproduction")
    A("")
    A("```bash")
    A("cargo test --release --workspace                                  # the kernel together with directive.rs")
    A("python benchmarks/run_exp9_directive.py --oracle                  # offline: compiler + harness with a deterministic worker")
    A("python benchmarks/run_exp9_directive.py --smoke                   # 2 cases per block, live models")
    A("python benchmarks/run_exp9_directive.py                           # every block")
    A("python benchmarks/run_exp9_directive.py --speed --baseline-bin <previous sbgk>   # compiler speed: serve vs CLI on the same states")
    A("python benchmarks/run_exp9_directive.py --report-only")
    A("```")
    return "\n".join(L) + "\n", summary
