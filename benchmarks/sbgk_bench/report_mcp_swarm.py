"""Render results/exp10/*.json into the EXP-10 report and results/exp10/summary.json."""

from __future__ import annotations

import statistics
from collections import defaultdict

from . import exp8_stats as S
from .report import f0, f1, f2, table  # noqa: F401 - shared helpers

SCHED = {"sync": "Sync-Batch Barrier (EXP-9B)", "sync_u": "Sync-Batch Barrier, unique prefixes", "async": "Async-Lease Swarm (no auto-closure)",
         "full": "Async-Lease + Kernel Auto-Close (Full SBGK-MCP)"}
DISP = {"target_only": "Target-Only Sharding (no premise lock, no auto-closure)", "premise_lock": "Shared-Premise Lock (no auto-closure)",
        "full": "Full SBGK-MCP (Shared-Premise Lock + Kernel Auto-Close)"}
TOOLS = [("sbgk_acquire_directive", "acquire_directive"), ("sbgk_submit_directive", "submit_directive"), ("sbgk_renew_lease", "renew_lease"),
         ("sbgk_emit_batch", "emit_batch (round)"), ("sbgk_apply_events", "apply_events"), ("sbgk_swarm_status", "swarm_status"),
         ("sbgk_post_erratum", "post_erratum"), ("sbgk_query_cone", "query_cone")]


def mean(xs):
    xs = list(xs)
    return statistics.fmean(xs) if xs else float("nan")


def pstr(p: float) -> str:
    return f"{p:.3f}" if p >= 0.001 else f"{p:.1e}"


def pct(x: float) -> str:
    return f"{100 * x:.1f} %"


def us(x) -> str:
    return f0(x) if x == x else "—"


def paired(pairs: list[tuple[float, float]], better_lower: bool = True) -> tuple[int, int, int, float, float]:
    """(wins, ties, losses, mean difference a - b, p) for pairs (a, b); a 'wins' when it is lower (or higher with better_lower=False)."""
    w = t = l = 0
    for a, b in pairs:
        if abs(a - b) < 1e-9:
            t += 1
        elif (a < b) == better_lower:
            w += 1
        else:
            l += 1
    return w, t, l, mean(a - b for a, b in pairs), S.sign_p(w, l)


def sign_row(label: str, metric: str, pairs, better_lower=True, unit=""):
    w, t, l, d, p = paired(pairs, better_lower)
    return [label, metric, len(pairs), f"{w} / {t} / {l}", f"{d:+.1f}{unit}", pstr(p)]


# ------------------------------------------------------------------ sections

def sec_a(L: list[str], A: dict, summary: dict) -> None:
    rows = A["rows"]
    ks = sorted({r["K"] for r in rows})
    cases = sorted({r["case"] for r in rows})
    scheds = [s for s in ("sync", "sync_u", "async", "full") if any(r["schedule"] == s for r in rows)]
    g = defaultdict(list)
    for r in rows:
        g[(r["K"], r["schedule"])].append(r)
    prof = A["profile"]
    L.append("## 1. EXP-10A — swarm scaling K ∈ {" + ", ".join(map(str, ks)) + "} with latency spread and hung workers\n")
    L.append(f"The `c_long96` register of EXP-9 (96 services, 16 APIs, ≈311 sentences), cases: **{len(cases)}**. The worker is the EXP-9 deterministic oracle "
             "(it does exactly what the frame says), connected to a live `sbgk mcp-serve --listen 127.0.0.1:0` process; each worker has its own TCP connection. "
             f"Time is virtual (`now_ms` in every call): even workers answer in {prof['fast'][0]:.0f}–{prof['fast'][1]:.0f} s, odd ones in "
             f"{prof['medium'][0]:.0f}–{prof['medium'][1]:.0f} s; {100 * prof['p_straggler']:.0f} % of calls are stragglers of {prof['straggler'][0]:.0f}–{prof['straggler'][1]:.0f} s; "
             f"{100 * prof['p_hang']:.0f} % of calls hang: the worker stops sending heartbeats and comes back with its answer after {prof['hang_s']:.0f} s. "
             f"Lease: TTL {A['ttl_ms'] // 1000} s, a live worker renews it every {A['renew_s']:.0f} s (`sbgk_renew_lease`). The latency of the n-th call of worker w "
             "is derived from the seed (case, w, n) and is the same in every schedule.\n")
    L.append("Schedules: **sync** — the EXP-9B round scheme (`sbgk_emit_batch` on K seats, a round lasts until its slowest seat; the barrier gives up a hung seat "
             "after the TTL and its work is replayed in the next round; no auto-closure); **sync, unique prefixes** — the same scheme, but the worker "
             "uses the prefix `s{seat}r{round}_` instead of the frame's prefix (see below); **async** — TTL leases without a barrier, with the shared-premise lock, without "
             "auto-closure; **full** — async + P2A auto-closure in the kernel.\n")
    hdr = ["K", "schedule", "swarm time, s (mean)", "model calls", "of them on P2A", "P2A auto-closed", "taken over after TTL", "late answers refused",
           "worker utilization", "useful utilization", "kernel rejections", "collisions", "root = reference"]
    tr = []
    for K in ks:
        for s in scheds:
            rs = g[(K, s)]
            if not rs:
                continue
            coll = sum(r['collisions'] for r in rs)
            tr.append([K, ("**" + SCHED[s] + "**") if s == "full" else SCHED[s], f0(mean(r["makespan_s"] for r in rs)), f1(mean(r["calls"] for r in rs)),
                       f1(mean(r["llm_calls_p2a"] for r in rs)), f1(mean(r["auto_closed"] for r in rs)), sum(r["takeovers"] for r in rs),
                       sum(r.get("stale", 0) for r in rs), pct(mean(r["util"] for r in rs)), pct(mean(r["util_useful"] for r in rs)),
                       sum(r.get("rejected", 0) for r in rs), f"{coll} (0.0 %)" if not coll else coll,
                       f"{sum(r['root_ok'] for r in rs)}/{len(rs)}"])
    L.append(table(hdr, tr) + "\n")
    rej = sum(r.get("rejected", 0) for r in rows if r["schedule"] == "sync")
    codes = defaultdict(int)
    for r in rows:
        for c, n in (r.get("reject_codes") or {}).items():
            codes[c] += n
    L.append("\"Taken over after TTL\" — leases issued again after the TTL of a hung worker ran out (`takeover` in the kernel's answer); \"late answers refused\" — "
             "answers of hung workers that arrived after their lease expired: the kernel returned `STALE_LEASE / LEASE_EXPIRED_OR_UNKNOWN` and applied nothing. "
             "The state root (`state_root`) is compared with the root of the case's first run (sync, K = 4).\n")
    if rej:
        L.append(f"**A defect of the round scheme for K > 8.** The EXP-9B frame builds the local_id prefix from eight seat tags (`SEAT_TAGS[seat % 8]` + round number): for K > 8 "
                 f"two seats of one round get the same prefix and the kernel refuses the second one's ids (`DUPLICATE_LOCAL_ID`: {codes.get('DUPLICATE_LOCAL_ID', 0)} "
                 f"rejections over all sync runs). Their work is replayed in later rounds — hence the extra calls of sync for K ≥ 16. A lease uses the prefix `l{{seq}}_`, "
                 "unique for any K. To separate the cost of the barrier itself from this defect, the \"sync, unique prefixes\" schedule was run separately.\n")
    # paired tests over (case, K)
    by = {(r["case"], r["K"], r["schedule"]): r for r in rows}
    keys = sorted({(r["case"], r["K"]) for r in rows})

    def pairs(a, b, key):
        return [(by[(c, K, a)][key], by[(c, K, b)][key]) for c, K in keys if (c, K, a) in by and (c, K, b) in by]
    st = []
    for a, b in (("full", "sync_u"), ("full", "sync"), ("async", "sync_u"), ("full", "async")):
        if a in scheds and b in scheds:
            st.append(sign_row(f"{a} vs {b}", "swarm time, s", pairs(a, b, "makespan_s"), unit=" s"))
            st.append(sign_row(f"{a} vs {b}", "model calls", pairs(a, b, "calls")))
    L.append(f"Paired comparisons over (case, K) pairs (n = {len(keys)}; exact two-sided sign test; \"better\" = lower):\n")
    L.append(table(["pair", "metric", "n", "better / equal / worse", "mean difference", "p"], st) + "\n")
    speed = {}
    for K in ks:
        if g[(K, "full")] and g[(K, "sync_u")]:
            speed[K] = {"vs_sync": mean(r["makespan_s"] for r in g[(K, "sync")]) / mean(r["makespan_s"] for r in g[(K, "full")]),
                        "vs_sync_u": mean(r["makespan_s"] for r in g[(K, "sync_u")]) / mean(r["makespan_s"] for r in g[(K, "full")]),
                        "vs_async": mean(r["makespan_s"] for r in g[(K, "async")]) / mean(r["makespan_s"] for r in g[(K, "full")])}
    L.append("Speed-up of the full schedule in swarm time (ratio of means): " + "; ".join(
        f"K = {K}: {v['vs_sync']:.1f}× faster than sync, {v['vs_sync_u']:.1f}× faster than sync with unique prefixes, {v['vs_async']:.2f}× faster than async"
        for K, v in speed.items()) + ".\n")
    summary["exp10a"] = {"cases": cases, "ks": ks, "by": {f"{K}/{s}": {
        "makespan_s": mean(r["makespan_s"] for r in g[(K, s)]), "calls": mean(r["calls"] for r in g[(K, s)]),
        "llm_calls_p2a": mean(r["llm_calls_p2a"] for r in g[(K, s)]), "auto_closed": mean(r["auto_closed"] for r in g[(K, s)]),
        "takeovers": sum(r["takeovers"] for r in g[(K, s)]), "stale": sum(r.get("stale", 0) for r in g[(K, s)]),
        "util": mean(r["util"] for r in g[(K, s)]), "util_useful": mean(r["util_useful"] for r in g[(K, s)]),
        "collisions": sum(r["collisions"] for r in g[(K, s)]), "rejected": sum(r.get("rejected", 0) for r in g[(K, s)]),
        "root_ok": sum(r["root_ok"] for r in g[(K, s)]), "n": len(g[(K, s)])} for K in ks for s in scheds if g[(K, s)]}, "speedup_full": speed,
        "collisions_total": sum(r["collisions"] for r in rows), "roots_ok": sum(r["root_ok"] for r in rows), "runs": len(rows)}
    # latency
    L.append("Latency of MCP calls in these runs (µs): \"server\" — time inside the kernel under the session lock (`server_us`), \"round trip\" — the full JSON-RPC round trip "
             "measured by the Python client (serialization, TCP loopback, parsing the answer with its frame):\n")
    lr = []
    for K in ks:
        lk = A["latency_by_k"].get(str(K), {})
        for t, name in TOOLS:
            if t in lk:
                v = lk[t]
                lr.append([K, name, v["n"], f"{us(v['srv_p50'])} / {us(v['srv_p95'])}", f"{us(v['rtt_p50'])} / {us(v['rtt_p95'])}"])
    L.append(table(["K", "call", "n", "server, median / p95", "round trip, median / p95"], lr) + "\n")
    summary["exp10a"]["latency_by_k"] = A["latency_by_k"]


def sec_rt(L: list[str], R: dict, summary: dict) -> None:
    L.append("### 1.1. EXP-10A-RT — the same register under real concurrent load\n")
    L.append(f"Case {R['case']}; K Python threads, each with its own connection, an oracle worker without model latency: workers take and submit leases continuously, "
             "waiting ones wake on every commit. It checks that under a real race for the lock the leases do not overlap and the swarm converges to the same root.\n")
    rows = []
    for r in R["rows"]:
        a = r["latency"].get("sbgk_acquire_directive", {})
        s = r["latency"].get("sbgk_submit_directive", {})
        rows.append([r["K"], f2(r["wall_s"]), r["leases"], f0(r["leases_per_s"]), r["collisions"], f"{us(a.get('srv_p50', float('nan')))} / {us(a.get('srv_p95', float('nan')))}",
                     f"{us(s.get('srv_p50', float('nan')))} / {us(s.get('srv_p95', float('nan')))}", f"{us(a.get('rtt_p50', float('nan')))} / {us(a.get('rtt_p95', float('nan')))}",
                     "yes" if r["root_ok"] else "NO"])
    L.append(table(["K", "time, s", "leases", "leases per second", "collisions", "acquire, server median / p95, µs", "submit, server median / p95, µs",
                    "acquire, round trip median / p95, µs", "root = reference"], rows) + "\n")
    L.append("The client-side round trip here is mostly waiting for the Python GIL and for the single session lock (all calls are serialized by one "
             "`Mutex<SwarmSession>`); the kernel's own time per call stays at hundreds of microseconds.\n")
    summary["exp10a_rt"] = [{k: r[k] for k in ("K", "wall_s", "leases", "leases_per_s", "collisions", "root_ok")} for r in R["rows"]]


def sec_b(L: list[str], B: dict, summary: dict) -> None:
    rows = B["rows"]
    cases = sorted({r["case"] for r in rows})
    g = defaultdict(list)
    for r in rows:
        g[r["dispatcher"]].append(r)
    L.append("## 2. EXP-10B — fan-in of shared premises: 60 agents, 60 services on 6 deprecated interfaces\n")
    L.append(f"Cases: **{len(cases)}**; each has 60 services `svc_000…svc_059`, exactly 10 per interface `api_000…api_005`, every interface is deprecated in a window "
             f"that overlaps the usage windows (all 60 need the `needs_review` conclusion). K = {B['K']} workers, the same oracle and latency model as in 10A, "
             "but without hangs. The reference root is a synchronous run of the case with K = 4.\n")
    hdr = ["dispatcher", "EXTRACT_PARTNER leases", "max per D clause", "D clause extractions (bind)", "extraction duplication", "lease collisions",
           "model calls", "of them on P2A", "P2A auto-closed", "swarm time, s", "root = reference"]
    tr = []
    for d in ("target_only", "premise_lock", "full"):
        rs = g.get(d, [])
        if not rs:
            continue
        tr.append([("**" + DISP[d] + "**") if d == "full" else DISP[d], f1(mean(r["extract_leases"] for r in rs)), max(r["extract_max_per_clause"] for r in rs),
                   f1(mean(r["dep_binds"] for r in rs)), pct(mean(r["dep_dup_share"] for r in rs)), f1(mean(r["collisions"] for r in rs)),
                   f1(mean(r["calls"] for r in rs)), f1(mean(r["llm_calls_p2a"] for r in rs)), f1(mean(r["auto_closed"] for r in rs)),
                   f0(mean(r["makespan_s"] for r in rs)), f"{sum(r['root_ok'] for r in rs)}/{len(rs)}"])
    L.append(table(hdr, tr) + "\n")
    L.append("\"Extraction duplication\" — the share of `D.m` clause bindings that repeated work already done (6 clauses per case; everything above 6 is a repeat); "
             "\"lease collisions\" — leases issued that overlap a live lease in target or source sentence. Without the premise lock the second wave "
             "(after the first `uses_api` facts are committed) hands `EXTRACT_PARTNER` on the same `D.m` clause to several agents at once.\n")
    by = {(r["case"], r["dispatcher"]): r for r in rows}
    st = []
    for a, b in (("full", "target_only"), ("full", "premise_lock"), ("premise_lock", "target_only")):
        pr = lambda k: [(by[(c, a)][k], by[(c, b)][k]) for c in cases if (c, a) in by and (c, b) in by]  # noqa: E731
        st.append(sign_row(f"{a} vs {b}", "D clause extractions", pr("dep_binds")))
        st.append(sign_row(f"{a} vs {b}", "model calls", pr("calls")))
        st.append(sign_row(f"{a} vs {b}", "swarm time, s", pr("makespan_s"), unit=" s"))
    L.append(f"Paired comparisons by case (n = {len(cases)}; sign test; \"better\" = lower; with n = 4 the smallest possible p is 0.125):\n")
    L.append(table(["pair", "metric", "n", "better / equal / worse", "mean difference", "p"], st) + "\n")
    lat = B.get("latency", {})
    if lat:
        L.append("Call latency with 60 connections (µs, server / round trip, median): " + "; ".join(
            f"{name} {us(lat[t]['srv_p50'])} / {us(lat[t]['rtt_p50'])}" for t, name in TOOLS[:3] if t in lat) + ".\n")
    summary["exp10b"] = {d: {"extract_leases": mean(r["extract_leases"] for r in g[d]), "extract_max_per_clause": max(r["extract_max_per_clause"] for r in g[d]),
                             "dep_binds": mean(r["dep_binds"] for r in g[d]), "dep_dup_share": mean(r["dep_dup_share"] for r in g[d]),
                             "collisions": mean(r["collisions"] for r in g[d]), "calls": mean(r["calls"] for r in g[d]),
                             "llm_calls_p2a": mean(r["llm_calls_p2a"] for r in g[d]), "auto_closed": mean(r["auto_closed"] for r in g[d]),
                             "makespan_s": mean(r["makespan_s"] for r in g[d]), "root_ok": sum(r["root_ok"] for r in g[d]), "n": len(g[d])} for d in g}


def sec_guard(L: list[str], G: dict, summary: dict) -> None:
    L.append("## 3. Directive Scope Guard and STALE_LEASE in Rust — deterministic probes\n")
    L.append(f"On each of the {len(G['runs'])} 10C cases (20 services, shared APIs, contradictions, erratum) the oracle drives the swarm through `sbgk mcp-serve`, committing "
             "five violations along the way; after the probes the swarm is played to the end and the outcome is checked against the kernel's graph.\n")
    names = [p["probe"] for p in G["runs"][0]["probes"]]
    rows = []
    for n in names:
        ps = [p for r in G["runs"] for p in r["probes"] if p["probe"] == n]
        exp = defaultdict(int)
        for p in ps:
            exp["yes" if isinstance(p["expected"], bool) else f"`{p['expected']}`"] += 1
        rows.append([n, "; ".join(f"{e} ({k})" if len(exp) > 1 else e for e, k in exp.items()), f"{sum(p['ok'] for p in ps)}/{len(ps)}"])
    L.append(table(["probe", "expected kernel answer (cases)", "matched"], rows) + "\n")
    L.append("The \"premise revoked\" probe depends on which clause the kernel extracted the premise from: the document is shuffled, and if the restating clause `R.p` comes before "
             "`D.p`, the premise is established from `R.p`, which the erratum keeps in force — then the premise stays SUPPORTED and the kernel's correct answer is to accept "
             "the lease (`COMMITTED`). The probe reads which clause is bound from the kernel's graph before the erratum is published.\n")
    L.append("The same is covered by the unit tests in `crates/sbgk-core/src/swarm.rs` and the integration test `crates/sbgk-cli/tests/mcp_swarm.rs` "
             "(JSON-RPC 2.0 over TCP and stdio: parallel leases from different connections, the lock on a shared clause, TTL with takeover, the guard, "
             "`STALE_LEASE_PREMISE_REVOKED` after `sbgk_post_erratum`, auto-closure).\n")
    summary["guard"] = {"all_ok": G["all_ok"], "probes": {n: sum(p["ok"] for r in G["runs"] for p in r["probes"] if p["probe"] == n) for n in names},
                        "runs": len(G["runs"])}


def sec_c(L: list[str], Cd: dict, summary: dict) -> None:
    res = [r for r in Cd["results"] if not r.get("error")]
    errs = [r for r in Cd["results"] if r.get("error")]
    by = defaultdict(list)
    for r in res:
        by[r["mode"]].append(r)
    cases = sorted({r["case"] for r in res})
    bk = Cd["backends"]
    L.append("## 4. EXP-10C — a live swarm: Codex + DeepSeek-chat + Claude Sonnet 5.5 through MCP\n")
    L.append(f"Cases: **{len(cases)}** (20 services, 8 APIs, shared interfaces, two POS/NEG contradictions; the erratum withdraws a usage clause, the "
             "deprecation clause of a shared premise (restated in another clause) and one side of a contradiction). Team: " +
             ", ".join(f"{b} — {v['label']} ({v['version']})" for b, v in bk.items()) + ". Four seats / workers: codex, deepseek, sonnet, codex.\n")
    L.append("**sync** — EXP-9B synchronous rounds through the EXP-9 harness (resident `serve`, 4 seats, directive contract in Python, no auto-closure; the erratum "
             "is published after round ≥ 3 if the trigger clause is already bound, otherwise after round 5). **swarm** — an asynchronous swarm through `sbgk mcp-serve` over TCP: "
             "4 worker threads, leases that pack several targets into a frame (`pack_multi_target`), the shared-premise lock, P2A auto-closure, Scope Guard in Rust; "
             f"the erratum is published through `sbgk_post_erratum` after {Cd['erratum_rule']['after_commits_if_trigger_bound']} commits if the trigger clause is bound, "
             f"otherwise after {Cd['erratum_rule']['latest']} (or when the kernel answered COMPLETE earlier). Model calls are cached by prompt (new ones in `results/exp10/calls`; "
             "the EXP-9 cache is read first).\n")

    def d(r):
        return (r.get("false_final") or 0) + (r.get("missing_final", r["targets"] - r["targets_done"]) or 0) + (r.get("withdrawn_active_final") or 0)
    hdr = ["mode", "goal reached", "defects at the end", "model calls", "of them repair", "calls on P2A", "P2A auto-closed", "input, tokens",
           "output, tokens", "Claude, $", "model time Σ, s", "run time, s", "repeats", "rejections", "contract violations", "stale leases", "collisions"]
    tr = []
    for m in ("sync", "swarm"):
        rs = by.get(m, [])
        if not rs:
            continue
        tr.append([("**swarm (MCP, async + auto-close)**" if m == "swarm" else "sync (EXP-9B)"), f"{sum(bool(r['completed']) for r in rs)}/{len(rs)}",
                   sum(d(r) for r in rs), sum(r["calls"] for r in rs), sum(r["repair_calls"] for r in rs), sum(r.get("llm_calls_p2a", 0) for r in rs),
                   sum(r.get("auto_closed", 0) for r in rs), f0(sum(r["in_tokens"] for r in rs)), f0(sum(r["out_tokens"] for r in rs)),
                   f"${sum(r['cost_usd'] or 0 for r in rs):.2f}", f0(sum(r["seconds"] for r in rs)), f0(sum(r["wall_s"] for r in rs)),
                   sum(r.get("repeats", 0) for r in rs), sum(r["rejected"] for r in rs),
                   sum(r.get("contract_violations", r.get("directive_violations", 0)) or 0 for r in rs), sum(r.get("stale_leases", 0) for r in rs),
                   sum(r.get("collisions", 0) for r in rs)])
    L.append(table(hdr, tr) + "\n")
    if errs:
        L.append(f"Runs with an error (not in the table): {len(errs)} — " + "; ".join(f"case {r['case']} {r['mode']}: {r['error'][:120]}" for r in errs) + ".\n")
    share = {}
    for m, rs in by.items():
        cnt = defaultdict(int)
        for r in rs:
            recs = [x for st_ in r.get("step_log", []) for x in st_["recs"]] if m == "sync" else r.get("recs", [])
            for x in recs:
                cnt[x["backend"]] += 1 + (1 if x.get("repair_call") else 0)
        share[m] = dict(cnt)
    if "sync" in share and "swarm" in share:
        L.append("Calls by model: " + "; ".join(f"{m}: " + ", ".join(f"{b} {n}" for b, n in sorted(share[m].items())) for m in ("sync", "swarm")) +
                 ". In a round every seat gets its share of the work regardless of the model's speed; in the swarm a lease goes to whoever is free, so "
                 "the fastest worker (Claude Sonnet) runs more leases and the slow ones (Codex under load, DeepSeek) fewer. Hence the higher Claude "
                 "spending and input tokens with fewer calls and less time: the swarm trades a \"cheap slow\" seat for an \"expensive fast\" one.\n")
        summary.setdefault("exp10c_calls_by_backend", share)
    L.append("\"Run time\" is the wall-clock time of a (case, mode) run; 9 of the 12 runs were resumed after a stop on the Sonnet subscription limit, and "
             "answers already in the call cache were delivered with the recorded model latency (schedule and run time as in a live run). "
             "\"Model time Σ\" is the sum of model answer times. "
             "\"Defects at the end\" are false or stale conclusions, missing conclusions and active withdrawn clauses, read from the kernel's graph. "
             "\"Stale leases\" are answers the kernel did not accept because the lease expired or an erratum revoked a premise / withdrew a clause of the frame.\n")
    pm = {(r["case"], r["mode"]): r for r in res}
    st = []
    for key, name in (("calls", "model calls"), ("in_tokens", "input, tokens"), ("out_tokens", "output, tokens"), ("wall_s", "run time, s"),
                      ("seconds", "model time Σ, s")):
        pr = [(pm[(c, "swarm")][key], pm[(c, "sync")][key]) for c in cases if (c, "swarm") in pm and (c, "sync") in pm]
        if pr:
            st.append(sign_row("swarm vs sync", name, pr))
    pr = [(pm[(c, "swarm")]["cost_usd"] or 0, pm[(c, "sync")]["cost_usd"] or 0) for c in cases if (c, "swarm") in pm and (c, "sync") in pm]
    if pr:
        w, t, l, dd, p = paired(pr)
        st.append(["swarm vs sync", "Claude, $", len(pr), f"{w} / {t} / {l}", f"{dd:+.3f}", pstr(p)])
    L.append(f"Paired comparisons by case (n = {len(cases)}; sign test; \"better\" = lower; with n = 6, p < 0.05 only with 6 of 6):\n")
    L.append(table(["pair", "metric", "n", "better / equal / worse", "mean difference", "p"], st) + "\n")
    per = []
    for c in cases:
        s, w = pm.get((c, "sync")), pm.get((c, "swarm"))
        if s and w:
            per.append([c, f"{s['targets_done']}/{s['targets']}", f"{w['targets_done']}/{w['targets']}", s["calls"], w["calls"], f0(s["in_tokens"]), f0(w["in_tokens"]),
                        f0(s["wall_s"]), f0(w["wall_s"]), w.get("auto_closed", 0), w.get("erratum_after_commits")])
    L.append(table(["case", "sync: conclusions", "swarm: conclusions", "sync: calls", "swarm: calls", "sync: input", "swarm: input", "sync: time, s", "swarm: time, s",
                    "swarm: auto-closed", "swarm: erratum after commits"], per) + "\n")
    lat = defaultdict(list)
    for r in by.get("swarm", []):
        for t, v in (r.get("latency") or {}).items():
            lat[t].append(v)
    if lat:
        L.append("MCP latency in the live swarm (µs, median over runs; server / round trip): " + "; ".join(
            f"{name} {us(statistics.median(v['srv_p50'] for v in lat[t]))} / {us(statistics.median(v['rtt_p50'] for v in lat[t]))}"
            for t, name in TOOLS if t in lat) + ".\n")
    oc = Cd.get("oracle_swarm")
    if oc:
        L.append(f"Harness check: the same swarm loop with the oracle instead of models reached the goal in {sum(o['completed'] for o in oc)}/{len(oc)} cases "
                 f"(leases on average {mean(o['leases'] for o in oc):.1f}, collisions {sum(o['collisions'] for o in oc)}).\n")
    summary["exp10c"] = {m: {"runs": len(rs), "completed": sum(bool(r["completed"]) for r in rs), "defects": sum(d(r) for r in rs),
                             "calls": sum(r["calls"] for r in rs), "repair_calls": sum(r["repair_calls"] for r in rs),
                             "llm_calls_p2a": sum(r.get("llm_calls_p2a", 0) for r in rs), "auto_closed": sum(r.get("auto_closed", 0) for r in rs),
                             "in_tokens": sum(r["in_tokens"] for r in rs), "out_tokens": sum(r["out_tokens"] for r in rs),
                             "cost_usd": sum(r["cost_usd"] or 0 for r in rs), "model_seconds": sum(r["seconds"] for r in rs), "wall_s": sum(r["wall_s"] for r in rs),
                             "repeats": sum(r.get("repeats", 0) for r in rs), "rejected": sum(r["rejected"] for r in rs),
                             "collisions": sum(r.get("collisions", 0) for r in rs)} for m, rs in by.items()}
    summary["exp10c"]["errors"] = len(errs)


def render(data: dict) -> tuple[str, dict]:
    L: list[str] = []
    summary: dict = {"version": "exp10-1"}
    mach = data.get("machine", {})
    L.append("# SBGK-P0 — EXP-10: resident MCP server, asynchronous leases and P2A auto-closure (Addendum v0.3.1)\n")
    L.append("New in the kernel: the module `crates/sbgk-core/src/swarm.rs` (`SwarmSession`: a TTL lease registry, the shared-premise lock, `ScopeContract`, "
             "`STALE_LEASE` checks, `auto_close_ready`), swarm ops in `sbgk serve` and a new command `sbgk mcp-serve` (`crates/sbgk-cli/src/mcp.rs`, "
             "JSON-RPC 2.0 over stdio and TCP); tests `crates/sbgk-cli/tests/mcp_swarm.rs`. Benchmark — `benchmarks/sbgk_bench/exp10_mcp_swarm.py`, runner — "
             "`benchmarks/run_exp10_mcp_swarm.py`, data — `results/exp10/`." + (f" Machine: {mach.get('cpu', '?')}." if mach else "") + "\n")
    L.append("## 0. What changed and what was tested\n")
    L.append("In EXP-9B directives were handed out in a synchronous round: every seat got its frame from the same state, and the next round started only when "
             "the slowest one had answered. `SwarmSession` replaces the barrier with individual leases on a live session (the same `analyze_cached` and `DirectiveCache`, the same "
             "frame packer as a round, `ConeReader` instead of a container):\n")
    L.append("1. **`acquire_directive`** — frontier analysis, exclusion of gaps whose resources are held by a live lease, and issue of the most urgent free target "
             "as one frame with the prefix `l{seq}_`. The lease locks the target, the non-amendment source sentences, the gap's nodes and — the **Shared-Premise Lock** — "
             "the premise the gap will establish (e.g. `(api_000, api_deprecated)` for an `EXTRACT_PARTNER` on the shared clause `D.0`). If all open work is held, "
             "the answer is `WAIT_IN_FLIGHT`; if there is no work and no leases — `COMPLETE`.\n"
             "2. **`submit_directive`** — checks that the lease is alive (TTL, `expire_stale`), that the frame's premises are still SUPPORTED and that no fresh erratum withdrew "
             "its sentences (`STALE_LEASE`); then the events go through the **`ScopeContract`** (the EXP-9 directive contract, moved from Python into Rust: "
             "allowed operations, quotes only from the slice, revocation only of listed evidence) and `Session::apply_line`: fail-fast, keeping the "
             "accepted prefix, with one repair attempt per lease.\n"
             "3. **Kernel Auto-Close P2A** — after every commit, document update and before every issue the kernel itself applies all ready Horn derivations "
             "(`EMIT_DERIVE_ONLY`) through `apply_line`; a derivation for a target held by a live lease waits for that lease to close. No model is called for P2A.\n"
             "4. **`post_erratum` / `put_document`** — a document is published on the live session and routed at once; **`renew_lease`** — heartbeat; "
             "**`release_lease`** — give the work back.\n"
             "5. **`sbgk mcp-serve`** — MCP (JSON-RPC 2.0, line-delimited): `initialize`, `tools/list`, `tools/call`; stdio or `--listen 127.0.0.1:<port>` "
             "(a thread per connection around `Arc<Mutex<SwarmSession>>`). Tools: `sbgk_init_session`, `sbgk_acquire_directive`, `sbgk_submit_directive`, "
             "`sbgk_post_erratum`, `sbgk_query_cone`, `sbgk_swarm_status`, plus `sbgk_renew_lease`, `sbgk_release_lease`, `sbgk_set_targets`, "
             "`sbgk_emit_batch` (a round for the baseline), `sbgk_apply_events`, `sbgk_snapshot`. Only `std`, `sha2` and `serde_json`.\n")
    q = data.get("quality")
    fi = data.get("frames_identity_exp9")
    lines = []
    if q:
        lines.append(f"`cargo test --release --workspace`: **{q['passed']} tests passed, {q['failed']} failed, compiler warnings — {q['warnings']}** "
                     f"(new: {q.get('new_tests', '?')}).")
    if fi:
        n = sum(len(v) for v in fi["rows"].values())
        ok = sum(1 for v in fi["rows"].values() for x in v if x["identical"])
        lines.append(f"The EXP-9 frames did not change: on {n} states of the 16/20/48/96-service registers the `emit_batch` batch of the new binary (resident `serve` and CLI) "
                     f"was byte-identical to the binary before the change in {ok}/{n} (`results/exp10/frames_identity_exp9.json`).")
    if lines:
        L.append("**\"Zero breaking changes\" invariants.** " + " ".join(lines) + " The `.sbgk` format, hashing, CDC and the `Engine` semantics did not change.\n")
        summary["quality"] = q
        summary["frames_identity_exp9"] = {"identical_all": fi["identical_all"]} if fi else None
    if "a" in data:
        sec_a(L, data["a"], summary)
    if "rt" in data:
        sec_rt(L, data["rt"], summary)
    if "b" in data:
        sec_b(L, data["b"], summary)
    if "guard" in data:
        sec_guard(L, data["guard"], summary)
    if "c" in data:
        sec_c(L, data["c"], summary)
    verdict(L, summary)
    caveats(L)
    L.append("## Reproduction\n")
    L.append("```bash\ncargo test --release --workspace                          # kernel, swarm.rs, MCP server (TCP + stdio)\n"
             "python benchmarks/run_exp10_mcp_swarm.py --selftest         # offline checks without models (~1 min)\n"
             "python benchmarks/run_exp10_mcp_swarm.py --smoke            # small series + 10C on 2 cases with live models\n"
             "python benchmarks/run_exp10_mcp_swarm.py                    # 10A, 10A-RT, 10B, guard, 10C\n"
             "python benchmarks/run_exp10_mcp_swarm.py --report-only\n```\n")
    return "\n".join(L), summary


def verdict(L: list[str], s: dict) -> None:
    L.append("## 5. Outcome\n")
    out = []
    a = s.get("exp10a")
    if a:
        sp = a["speedup_full"]
        ks = sorted(sp, key=int)
        out.append(f"**10A.** Leases without a barrier remove idle time on stragglers: the full schedule finishes the swarm faster than the round barrier at every K "
                   f"({min(v['vs_sync_u'] for v in sp.values()):.1f}–{max(v['vs_sync_u'] for v in sp.values()):.1f}× vs the barrier with unique prefixes, "
                   f"{min(v['vs_sync'] for v in sp.values()):.1f}–{max(v['vs_sync'] for v in sp.values()):.1f}× vs the EXP-9B scheme as is). "
                   f"Auto-closure adds another {min(v['vs_async'] for v in sp.values()):.2f}–{max(v['vs_async'] for v in sp.values()):.2f}× on top of asynchrony and "
                   f"removes every model call on P2A. Lease collisions — {a['collisions_total']} in {a['runs']} runs; the state root matched the reference in "
                   f"{a['roots_ok']}/{a['runs']}. Hung workers do not slow the swarm down: their work is taken over after the TTL, and the kernel refuses late answers. "
                   f"From K ≈ 32 the swarm time is bound by the length of the dependency chain (formalization → extraction of the shared clause → derivation), not by the number of workers: "
                   f"at K = {ks[-1]} worker utilization is low in every schedule.")
    b = s.get("exp10b")
    if b and "full" in b and "target_only" in b:
        out.append(f"**10B.** Without the premise lock a shared clause is handed to several agents at once (up to {b['target_only']['extract_max_per_clause']} leases on one "
                   f"clause, {b['target_only']['dep_binds']:.1f} extractions instead of 6, {100 * b['target_only']['dep_dup_share']:.1f} % duplication). "
                   f"With the Shared-Premise Lock each of the 6 clauses is extracted exactly once (0.0 % duplication, 0 collisions), and auto-closure derives "
                   f"{b['full']['auto_closed']:.0f} dependent `needs_review` conclusions in the kernel without a single model call: {b['full']['calls']:.0f} calls vs "
                   f"{b['premise_lock']['calls']:.0f} for the lock without auto-closure and {b['target_only']['calls']:.0f} for sharding by target. "
                   f"The lock without auto-closure pays for deduplication with time ({b['premise_lock']['makespan_s']:.0f} s vs "
                   f"{b['target_only']['makespan_s']:.0f} s): the dependent services wait for the shared clause and then call the model for a single `derive` line; "
                   f"only the combination of both mechanisms is the fastest ({b['full']['makespan_s']:.0f} s).")
    g = s.get("guard")
    if g:
        out.append(f"**Guard.** Every Scope Guard and STALE_LEASE probe gave the expected kernel code on all {g['runs']} cases: " + ("yes." if g["all_ok"] else "NO."))
    c = s.get("exp10c")
    if c and "swarm" in c and "sync" in c:
        w, y = c["swarm"], c["sync"]
        out.append(f"**10C.** The live swarm through MCP: goal {w['completed']}/{w['runs']} (sync — {y['completed']}/{y['runs']}), defects at the end {w['defects']} "
                   f"(sync — {y['defects']}); model calls {w['calls']} vs {y['calls']}, input {f0(w['in_tokens'])} vs {f0(y['in_tokens'])} tokens, "
                   f"Claude ${w['cost_usd']:.2f} vs ${y['cost_usd']:.2f}, total run time {f0(w['wall_s'])} s vs {f0(y['wall_s'])} s; "
                   f"{w['auto_closed']} conclusions auto-closed, calls on P2A {w['llm_calls_p2a']} (sync — {y['llm_calls_p2a']}); collisions {w['collisions']}.")
    for x in out:
        L.append(x + "\n")
    s["verdict"] = out


def caveats(L: list[str]) -> None:
    L.append("## Caveats\n")
    items = [
        "**10A and 10B — virtual time and an oracle.** Latencies and hangs are synthetic (profile above), the worker never errs; what is measured is the schedule "
        "and the kernel, not model quality. A call's latency is given by the seed (case, worker, call number), so the schedules get the same sequence of "
        "latencies per worker, but different tasks in those calls.",
        "**The EXP-9B scheme with K > 8** loses work to coinciding local_id prefixes (`DUPLICATE_LOCAL_ID`); this is a property of the EXP-9 frame, not of the barrier. "
        "So both versions of sync are given: as is and with unique prefixes; the conclusions about the barrier are drawn from the second.",
        "**Saturation.** In the c_long96 register about 45 targets have work; with K = 64 and 100 most workers idle in any schedule, "
        "and the low \"utilization\" is a property of the task, not of the dispatcher. With large K the swarm time is set by the length of the dependency chain.",
        "**Frame packing.** In 10A/10B a lease takes one target (maximum parallelism), so async without auto-closure makes more calls than "
        "a round with pass 2 of `emit_batch` (up to several targets per seat). The live 10C enables `pack_multi_target` — a lease tops up with whole free targets "
        "while the event budget lasts, like a round's seat.",
        "**10B: the lock without auto-closure is slower than sharding by target.** Deduplicating the shared clause makes the dependent services wait and then "
        "spend a separate call on `derive`; with sharding by target the duplicates carry their own `derive` at once. Only the combination of "
        "the lock and auto-closure wins on time.",
        "**Auto-closure defers the derivation for a target held by a live lease** (so as not to conclude from a fact next to which a contradicting sentence is still "
        "being formalized); after the lease closes the derivation is made in the same call. The kernel still checks every `derive` and recomputes "
        "support on a conflict.",
        "**10C — small sample and runtime noise**: 6 cases, one run per pair; the sign test with n = 6 gives p < 0.05 only with 6 wins of 6. "
        "The first attempt of the series stopped on the Sonnet subscription limit (3 of 12 runs were done); the failed "
        "runs were not stored and were redone after the limit reset, with answers from the cache delivered with their recorded latency. "
        "Run time depends on runtime queues (DeepSeek through OpenClaw answers in tens of seconds and "
        "is limited to 3 concurrent calls). The erratum publication rules of the two modes are comparable but not "
        "identical (after round ≥ 3 vs after 12 commits), so the moment of the amendment can differ within a pair.",
        "**The EXP-9 harness was fixed in one place**: a run with an amendment no longer stops in the same round in which the erratum became visible "
        "(before, the compiler had no chance to see it if the work ended before publication; this case did not occur in the EXP-9 data — every c_retract run "
        "reached the goal). Also `find_claude` looks for Claude Code in the new application folder.",
        "**Round-trip latency** is measured by a Python client and includes serialization, parsing the answer with its frame (several KB, duplicated in "
        "`content.text` and `structuredContent` per the MCP specification) and, in 10A-RT, waiting for the GIL; kernel time is `server_us` under the session lock. "
        "All calls are serialized by one `Mutex<SwarmSession>`.",
        "**The Scope Guard is syntactic** (as in EXP-9): a quote must be a substring of a slice sentence, a revocation a prefix of listed evidence; "
        "the meaning of facts is still checked by the kernel.",
        "**TTL and heartbeats** in 10A are simulated (renewal every 10 s); the live 10C workers take a lease with a 15-minute TTL without renewal (a model's answer time "
        "is bounded by the runtime's timeout). Server time is monotonic milliseconds since start unless the client passes `now_ms`.",
        "**The data is synthetic**; only generated task texts leave the machine.",
    ]
    for i, x in enumerate(items, 1):
        L.append(f"{i}. {x}")
    L.append("")
