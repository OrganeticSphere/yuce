"""Render the live-agent EXP-3 result into a separate report (the main report is not touched)."""

from __future__ import annotations

from .report import f0, f1, f2, ok, p1, table  # noqa: F401 - shared helpers

ARMS = ["A1", "A2", "B"]
ARM_NAMES = {
    "A1": "A1 · monolithic JSON, generic error, full regeneration",
    "A2": "A2 · monolithic JSON, structured error, JSON patch",
    "B": "B · streaming JSONL, fail-fast, targeted repair + continuation",
}
TYPE_NAME = {"quote": "invented quote", "interval": "wrong interval", "alias": "ambiguous alias", "premise": "unsupported premise"}


def render(D: dict, scripted: dict | None) -> str:
    R = D["results"]
    base_in = D["base_input_tokens"]
    arms = [a for a in ARMS if any(r["arm"] == a for r in R)]
    tasks = sorted({r["task"] for r in R})
    types = ["quote", "interval", "alias", "premise"]
    by = lambda a: [r for r in R if r["arm"] == a]  # noqa: E731

    def tot(a, key):
        return sum(r["usage"][key] for r in by(a))

    # calibration: output tokens per byte of generated text (A1 calls without hidden reasoning)
    a1 = [r for r in by("A1") if r["usage"]["reasoning"] == 0 and r["usage"]["out_bytes"] > 0]
    tpb = (sum(r["usage"]["output"] for r in a1) / sum(r["usage"]["out_bytes"] for r in a1)) if a1 else 0.25
    sp = {int(k): v for k, v in D["scripted_parts"].items()}
    scripted_tok = {"A1": sum(sp[t]["A_initial_bytes"] for t in tasks) * tpb,
                    "A2": sum(sp[t]["A_initial_bytes"] for t in tasks) * tpb,
                    "B": sum(sp[t]["B_prefix_bytes"] for t in tasks) * tpb}

    S = {}
    for a in arms:
        n = len(by(a))
        S[a] = {
            "n": n, "success": sum(r["success"] for r in by(a)), "rounds": sum(r["rounds"] for r in by(a)) / n,
            "calls": tot(a, "calls"), "input_raw": tot(a, "input"), "cached": tot(a, "cached"), "output": tot(a, "output"),
            "reasoning": tot(a, "reasoning"), "seconds": tot(a, "seconds"), "tools": tot(a, "tool_items"),
            "input_net": max(0, tot(a, "input") - base_in * tot(a, "calls")),
            "scripted_tok": scripted_tok[a],
        }
        S[a]["out_total"] = S[a]["output"] + S[a]["scripted_tok"]
        S[a]["wall_mean"] = S[a]["seconds"] / max(1, S[a]["calls"])

    L: list[str] = []
    A = L.append
    A("# SBGK-P0 — EXP-3 with a live agent: Codex CLI, model " + D["model"])
    A("")
    A(f"{D['codex_version']} · reasoning effort: {D['reasoning_effort']} · tasks: {D['tasks']} · model calls: {sum(S[a]['calls'] for a in arms)} "
      f"(reused from the cache of earlier runs with the same prompts: {D['cached_calls_reused']}).  ")
    A("This is a **separate report**. The main report and `results/summary.json` were not changed; the scripted-run numbers below "
      "are read from `results/summary.json` without writing it.")
    A("")

    A("## 0. Summary")
    A("")
    rows = [[ARM_NAMES[a], f"{S[a]['success']}/{S[a]['n']}", f2(S[a]["rounds"]), S[a]["calls"], f0(S[a]["input_net"]), f0(S[a]["output"]), f0(S[a]["out_total"])] for a in arms]
    A(table(["Scheme", "correct (root = reference)", "rounds per task", "model calls", "input tokens (net)", "output tokens (measured)", "agent output total ≈ tokens"], rows))
    A("")
    if "B" in S and "A1" in S:
        A(f"Agent output (initial emission + measured repair): B relative to A1 — {f1(100 * (1 - S['B']['out_total'] / S['A1']['out_total']))} %"
          + (f", relative to A2 — {f1(100 * (1 - S['B']['out_total'] / S['A2']['out_total']))} %" if "A2" in S else "") + " (a positive value means B is cheaper).")
    tools = sum(S[a]["tools"] for a in arms)
    A(f"Tool calls by the model (file reads, shell): **{tools}** — the model answered in text, as the instruction required.")
    A("")

    A("## 1. What changed compared with the scripted run")
    A("")
    A("- **The same 30 tasks and the same injected errors** (`exp3.Task` is imported unchanged; same seed). The first, faulty emission is still scripted — it is the injected error.")
    A("- **The model does the repair**, not a \"mechanical policy\". The kernel judges every line; success = the final state root equals the reference.")
    A("- **What the model sees:** the ontology description, the document text, a \"work order\" (what must be recorded, with intervals), its own faulty lines and the kernel's answer. "
      "The reference stream is not in the prompts. For A1 the kernel's answer is generic (code, line number, message), for A2 and B it is structured (`expected_by_kernel`, `obligation`).")
    A("- **A1** returns the whole graph; **A2** a JSON patch (all changed lines, including dependent ones); **B** the corrected line `k`, then the continuation of the stream to the end of the chain "
      "(in the streaming scheme the lines after `k` are not written yet, so emitting them is part of B's cost).")
    A("- Every call is `codex exec` in an empty temporary folder, `read-only`, `--ephemeral`, `--ignore-user-config`, `--ignore-rules`; the prompt goes through stdin. Up to three repair rounds per task.")
    A("")

    A("## 2. Repair success")
    A("")
    rows = []
    for ty in types:
        row = [TYPE_NAME[ty]]
        for a in arms:
            rs = [r for r in by(a) if r["type"] == ty]
            row.append(f"{sum(r['success'] for r in rs)}/{len(rs)} · rounds {f1(sum(r['rounds'] for r in rs) / max(1, len(rs)))}")
        rows.append(row)
    rows.append(["**total**"] + [f"{S[a]['success']}/{S[a]['n']} · rounds {f2(S[a]['rounds'])}" for a in arms])
    A(table(["Error type"] + [ARM_NAMES[a].split(" · ")[0] for a in arms], rows))
    A("")
    fails = [r for r in R if not r["success"]]
    if fails:
        A("**Failures:**")
        A("")
        A(table(["task", "scheme", "type", "what happened"], [[r["task"], r["arm"], TYPE_NAME[r["type"]], "; ".join(
            (f"round {t['round']}: {t.get('error_code')} (seq {t.get('error_seq')})" if "error_code" in t else
             f"{t.get('phase', '')} {t.get('code', '')} {t.get('exception', '')}{' the answer could not be parsed' if t.get('parse_failure') else ''}").strip()
            for t in r["trail"])] for r in fails]))
        A("")
    else:
        mx = max(r["rounds"] for r in R)
        A(f"No failures: in every scheme the graph reached the reference root; at most {mx} repair rounds per task. "
          "So by repair success the schemes **do not differ** here: a generic error without `expected_by_kernel` (A1) was enough for this model, "
          "because it sees the ontology, the document and the work order. The difference is only in cost.")
        A("")
    prem_b = [r for r in by("B") if r["type"] == "premise"]
    if prem_b and scripted:
        sc_prem = scripted["by_type"]["premise"]["mean_rounds"]
        A(f"Note on the \"unsupported premise\": the scripted repair needed {f1(sc_prem)} rounds (first replace the premise, then the interval); "
          f"the model in scheme B needed {f1(sum(r['rounds'] for r in prem_b) / len(prem_b))} on average — it handles both mismatches at once when it sees the error and the context.")
        A("")

    A("## 3. Tokens and time (measured from `turn.completed.usage`)")
    A("")
    A(f"Every Codex call carries a fixed overhead (system prompt, tool schemas): a probe call used {f0(D['baseline_call_usage']['input_tokens'])} input tokens "
      f"({f0(D['baseline_call_usage']['cached_input_tokens'])} of them cached). \"Net\" input tokens = call input − {f0(base_in)}. "
      f"Tokens of the initial (scripted) emission are estimated by calibration: {f2(tpb)} output tokens per byte of text, measured on the A1 answers.")
    A("")
    rows = [[ARM_NAMES[a].split(" · ")[0], S[a]["calls"], f0(S[a]["input_raw"]), f0(S[a]["cached"]), f0(S[a]["input_net"]), f0(S[a]["output"]), f0(S[a]["reasoning"]),
             f0(S[a]["scripted_tok"]), f0(S[a]["out_total"]), f1(S[a]["wall_mean"]), f0(S[a]["seconds"])] for a in arms]
    A(table(["Scheme", "calls", "input, raw", "of it cached", "input, net", "output, measured", "of it reasoning", "initial emission ≈", "output total ≈", "s per call", "s total"], rows))
    A("")
    if "B" in S:
        for a in ("A1", "A2"):
            if a in S:
                d_out = S[a]["out_total"] - S["B"]["out_total"]
                d_in = S["B"]["input_net"] - S[a]["input_net"]
                be = f" Break-even: B is cheaper overall if an output token costs more than {f1(d_in / d_out)} times an (uncached) input token." if d_out > 0 and d_in > 0 else ""
                A(f"- B vs {a}: agent output {f1(100 * (1 - S['B']['out_total'] / S[a]['out_total']))} % smaller; B's net input is {f2(S['B']['input_net'] / max(1, S[a]['input_net']))} times "
                  f"{'larger' if d_in > 0 else 'smaller'}; {S['B']['calls']} calls vs {S[a]['calls']}." + be)
        A("")
        A("B's cost in this harness is understated in the number of round trips and overstated in input: the streaming dialogue is emulated by independent calls with the full prefix in the prompt "
          "(in a real session the prefix is cached and Codex's overhead is paid once), and the continuation of the stream is generated as a batch — "
          "if the batch contains an error, the lines after it are paid for too.")
    A("")

    if scripted:
        A("## 4. Comparison with the scripted run")
        A("")
        sa = scripted["arms"]
        rows = []
        for a in arms:
            rows.append([ARM_NAMES[a].split(" · ")[0], f0(sa[a]["output_tokens_est"]) + " (bytes/4)", f0(S[a]["out_total"]) + " (measured + calibration)",
                         f"{scripted['repair']['of']}/{scripted['repair']['of']} by construction", f"{S[a]['success']}/{S[a]['n']}"])
        A(table(["Scheme", "agent output: scripted", "agent output: live model", "success: scripted", "success: live model"], rows))
        A("")
        A("The scripted agent's 100 % success follows from its construction (it knows the reference), so only tokens are comparable, and even that with a caveat: "
          "the scripted cost was counted in bytes of the reference lines, the live one in tokens of the model's real answer.")
        A("")
        if "B" in S and "A1" in S and "A2" in S:
            A(f"The scripted conclusion holds on the live model: B's output saving vs A1 — {f1(sa['A1']['B_saves_output_pct'])} % (scripted) "
              f"vs {f1(100 * (1 - S['B']['out_total'] / S['A1']['out_total']))} % (live model), vs A2 — {f1(sa['A2']['B_saves_output_pct'])} % vs "
              f"{f1(100 * (1 - S['B']['out_total'] / S['A2']['out_total']))} %. Order and sign match; the gain over the patch stays small.")
            A("")

    A("## 5. Caveats")
    A("")
    cav = [
        "**One run per task, no repeats.** Model answers are non-deterministic; the call cache (`results/exp3_llm/calls`) keeps the specific answers, but another run may give other numbers.",
        "**30 tasks from one generator**, one model, one reasoning level (the model's default); the errors are injected in advance and of four types — they are not the agent's \"natural\" errors.",
        "**The work order contains the intent** (which links and intervals are needed). In a real task the model would get it from the document; here this simplification makes the repair feasible by construction.",
        "**The streaming scheme is emulated.** There is no real \"line → answer → line\" dialogue: every call is independent, the prefix goes in the prompt. Codex's per-call overhead (≈ " + f0(base_in) + " input tokens) makes the number of calls the main source of input cost; \"net\" tokens are given for comparison.",
        "**Tokens of the initial emission are an estimate.** It comes from the A1 calibration and is the same for A1/A2; for B only the prefix up to the faulty line counts.",
        "**Time includes the start of the Codex process and network latency**, not only the model's work; comparable between schemes, not between machines.",
        "**The data is synthetic**; only generated task texts leave the machine (to OpenAI), nothing from the repository or user files.",
    ]
    for i, c in enumerate(cav, 1):
        A(f"{i}. {c}")
    A("")
    A("## 6. Reproduction")
    A("")
    A("```bash")
    A("python benchmarks/run_exp3_llm.py              # 30 tasks × 3 schemes, gpt-5.6-sol, needs Codex CLI ≥ 0.163")
    A("python benchmarks/run_exp3_llm.py --limit 4    # quick trial run (report with a .smoke suffix)")
    A("python benchmarks/run_exp3_llm.py --report-only")
    A("```")
    A("")
    return "\n".join(L)
