"""EXP-9: Compiler-Driven Directive Emitter + Stateless O(1) graph-builders, against the EXP-7/EXP-8 visibility modes.

New mode `directive`: before every turn/round the harness asks the Rust compiler for the frontier of unfinished work - the
resident compiler of the kernel process itself (`sbgk serve` op `directives`, on the live session, no container), or with
RESIDENT = False the one-shot CLI (`sbgk emit-batch-directives`) on a snapshot of the same state, as in the model runs of the
report (the frames are byte-identical; only the compiler's cost differs). The compiler returns one self-contained frame per seat
(source slice + minimal support cone + ontology slice + its own instruction with precomputed ids and intervals); seats that get
no work are not called at all. A worker sees only its frame: no document, no graph, no history. If the kernel rejects an
event, the worker gets ONE repair attempt inside the same small window (its previous output + the kernel's obligation).
Then its context is discarded (context flush); the next call starts from a fresh frame.

Blocks (each run separately so effects are attributable):
  a_trio      EXP-7-like task (12 services), Codex + DeepSeek + Sonnet in turns; prose / raw / graph / directive
  a_solo      the same cases with DeepSeek-chat alone (the weak graph-builder); iso (own history) / graph / directive
  b_parallel  EXP-8 scenario 3 (20 services, 4 agents in the same round); iso / prose / raw / graph / graphopen / directive
  c_retract   EXP-8 scenario 1 (erratum mid-task, conflicts); prose / raw / graph / directive
  c_long      48 services, Codex alone, sequential; stateful (whole document + whole graph + own history, no prompt budget)
              against directive: how the input window grows with the size of the graph

The baselines are run by the EXP-8 harness (imported, unchanged); the Claude seat is Sonnet 5.5.
"""

from __future__ import annotations

import concurrent.futures as cf
import dataclasses
import json
import pathlib
import shutil
import subprocess
import threading
import time
from collections import Counter

from . import common as C
from . import exp8_env as E
from . import exp8_run as R8
from .exp7_multiagent import Kernel, parse_turn

OUT = C.RESULTS / "exp9"
R8.CALLS = OUT / "calls"  # EXP-9 keeps its own call cache (the EXP-8 cache is not touched)
RUNS = OUT / "runs"
VERSION = "exp9-2"

Spec = E.Spec
SPECS9 = {
    "a_trio": Spec("a_trio", services=12, apis=7, active=3, systems=0, team=("codex", "deepseek", "sonnet"), k=5, cap=16, parallel=False, gold=(5, 7)),
    "a_solo": Spec("a_solo", services=12, apis=7, active=3, systems=0, team=("deepseek",), k=5, cap=20, parallel=False, gold=(5, 7)),
    "b_parallel": E.SPECS["parallel"],
    # the EXP-8 retraction cases with a higher cap (the same for every mode): directive formalizes every service, not only the eligible ones
    "c_retract": dataclasses.replace(E.SPECS["retract"], cap=18),
    "c_long": Spec("c_long", services=48, apis=12, active=4, systems=0, team=("codex",), k=4, cap=70, parallel=False, gold=(14, 18)),
    # only for the deterministic window replay (no model calls): a register long enough to reach step 48 and beyond
    "c_long96": Spec("c_long96", services=96, apis=16, active=6, systems=0, team=("codex",), k=4, cap=200, parallel=False, gold=(34, 40)),
}
SEEDS9 = {"a_trio": 9000, "a_solo": 9000, "b_parallel": 8200, "c_retract": 8000, "c_long": 9300, "c_long96": 9400}
MODES9 = {
    "a_trio": ["prose", "raw", "graph", "directive"],
    "a_solo": ["iso", "graph", "directive"],
    "b_parallel": ["iso", "prose", "raw", "graph", "graphopen", "directive"],
    "c_retract": ["prose", "raw", "graph", "directive"],
    "c_long": ["stateful", "directive"],
}
REPAIR_NOTE = ("\n\nYOUR PREVIOUS OUTPUT:\n{prev}\n\nKERNEL FEEDBACK: your event #{n} was REJECTED: {err}\n"
               "Events before it were accepted and are in the kernel now; the events after it were not sent. Output only the corrected "
               "remaining events (one JSON object per line). Do not reuse local_ids that were already accepted.\n")


FACT_KINDS = {"FORMALIZE", "EXTRACT_PARTNER", "RESUPPORT_FROM_RESTATEMENT", "REPAIR_UNSUPPORTED"}


def contract_of(frame: dict) -> dict:
    """What a frame allows: the ops its gaps need, the slice sentences a quote must come from, the evidence ids it may revoke."""
    ops, revoke = set(), set()
    for g in frame["gaps"]:
        if g["kind"] in FACT_KINDS:
            ops |= {"bind_evidence", "assert_fact", "derive"}
        elif g["kind"] == "EMIT_DERIVE_ONLY":
            ops.add("derive")
        elif g["kind"] in ("REVOKE_WITHDRAWN", "RESOLVE_CONFLICT"):
            ops.add("revoke_evidence")
            revoke |= {e.lstrip("@") for e in g["evidence"]}
    texts = [c["text"] for c in frame["chunk_slice"] if not c.get("amendment")]
    return {"ops": ops, "texts": texts, "revoke": revoke}


def contract_violation(ev: dict, con: dict) -> str | None:
    """Harness-side directive contract: an event the frame did not ask for is refused before it reaches the kernel."""
    op = ev.get("op")
    if op not in con["ops"]:
        return f"this directive does not ask for '{op}' events"
    if op == "bind_evidence":
        q = ev.get("exact_quote") or ""
        if not q or not any(q in t for t in con["texts"]):
            return "the quote is not taken from the directive's source slice"
    if op == "revoke_evidence":
        tgt = str(ev.get("target_evidence") or "").lstrip("@")
        if len(tgt) < 8 or not any(r.startswith(tgt) or tgt.startswith(r) for r in con["revoke"]):
            return "this evidence is not listed for revocation by the directive"
    return None


def make_case(block: str, idx: int) -> E.Case8:
    return E.Case8(SPECS9[block], idx, seed=SEEDS9[block] + idx)


def targets_for(case: E.Case8, docs: list[str]) -> dict:
    svcs = [e["id"] for e in case.onto["entities"] if e["type"] == "Service"]
    return {"goals": [{"entity": s, "predicate": "needs_review"} for s in svcs], "docs": docs}


# where the per-round frames come from: True = the resident `directives` op of the kernel process; False = the one-shot CLI
RESIDENT = True


def emit(container: pathlib.Path, targets_file: pathlib.Path, seats: int, k: int, rnd: int) -> dict:
    return C.cli("emit-batch-directives", "--state", container, "--targets", targets_file, "--seats", seats, "--k", k, "--round", rnd)


class ResidentKernel(Kernel):
    """The EXP-7 kernel process plus the resident compiler of `sbgk serve` (frames from the live session)."""

    def directives(self, targets: dict, seats: int, k: int, rnd: int) -> dict:
        r = self._rt({"op": "directives", "targets": targets, "seats": seats, "k": k, "round": rnd})
        if r.get("status") != "directives":
            raise RuntimeError(f"sbgk serve refused the directives op: {str(r)[:300]}")
        return r


def batch_for(kernel: ResidentKernel, container: pathlib.Path, targets_file: pathlib.Path, targets: dict, seats: int, k: int, rnd: int) -> dict:
    """The round's batch for the current kernel state. The CLI path reads `container`, which must be a snapshot of that state."""
    if RESIDENT:
        return kernel.directives(targets, seats, k, rnd)
    targets_file.write_text(json.dumps(targets), encoding="utf-8")
    return emit(container, targets_file, seats, k, rnd)


# ------------------------------------------------------------------ deterministic worker (offline check of the whole loop)

class Oracle:
    """Executes a frame exactly as the compiler asks, using the case's ground truth to read clauses. No model involved."""
    exact_tokens = True
    label = "oracle"

    def __init__(self, case: E.Case8):
        self.case = case
        self.by_text = {v: k for k, v in case.quote.items()}

    def claim_of(self, label: str) -> dict | None:
        c = self.case
        kind, num = label.split(".")
        i = int(num)
        if kind == "U":
            return {"s": f"svc_{i:03d}", "p": "uses_api", "o": f"api_{c.api_of[i]:03d}", "polarity": "POS", "t": list(c.use_t[i])}
        if kind == "N":
            lo, hi = c.use_t[i]
            return {"s": f"svc_{i:03d}", "p": "uses_api", "o": f"api_{c.api_of[i]:03d}", "polarity": "NEG", "t": [lo + 20, hi + 10]}
        if kind in ("D", "R"):
            return {"s": f"api_{i:03d}", "p": "api_deprecated", "o": "true", "polarity": "POS", "t": list(c.dep_t[i])}
        if kind == "P":
            return {"s": f"svc_{i:03d}", "p": "part_of", "o": f"sys_{c.sys_of[i]:02d}", "polarity": "POS", "t": [0, 1000]}
        return None

    def overlap_for(self, svc: str) -> bool:
        i = int(svc.split("_")[1])
        a = self.case.api_of[i]
        if a not in self.case.dep_t:
            return False
        lo, hi = C.intersect(self.case.use_t[i], self.case.dep_t[a])
        return lo < hi

    def events(self, frame: dict) -> list[dict]:
        pre = frame["local_id_prefix"]
        out, n = [], 0
        for g in frame["gaps"]:
            kind = g["kind"]
            if kind in ("FORMALIZE", "EXTRACT_PARTNER", "RESUPPORT_FROM_RESTATEMENT", "REPAIR_UNSUPPORTED"):
                facts = []
                for text in g["segment_texts"]:
                    lab = self.by_text.get(text)
                    cl = g["resupport"] if kind in ("RESUPPORT_FROM_RESTATEMENT", "REPAIR_UNSUPPORTED") and g.get("resupport") else (self.claim_of(lab) if lab else None)
                    if not cl:
                        continue
                    n += 1
                    out.append({"op": "bind_evidence", "local_id": f"{pre}e{n}", "doc_id": "policy", "exact_quote": text})
                    out.append({"op": "assert_fact", "local_id": f"{pre}f{n}", "s": cl["s"], "p": cl["p"], "o": cl["o"], "polarity": cl["polarity"],
                                "ctx": "prod", "t": cl["t"], "evidence": [f"{pre}e{n}"]})
                    facts.append((f"{pre}f{n}", cl))
                if g.get("partner") and facts and kind in ("FORMALIZE", "EXTRACT_PARTNER"):
                    lid, cl = facts[0]
                    svc = cl["s"] if cl["p"] == "uses_api" else g["target"]
                    if cl["polarity"] == "POS" and self.overlap_for(svc):
                        n += 1
                        out.append({"op": "derive", "local_id": f"{pre}r{n}", "rule": g["partner"]["rule"], "premises": [lid, g["partner"]["id"]]})
            elif kind == "EMIT_DERIVE_ONLY":
                n += 1
                out.append({"op": "derive", "local_id": f"{pre}r{n}", "rule": g["derive"]["rule"], "premises": g["derive"]["premises"]})
            elif kind in ("REVOKE_WITHDRAWN", "RESOLVE_CONFLICT"):
                out += [{"op": "revoke_evidence", "target_evidence": e} for e in g["evidence"]]
        return out[: frame["max_events"]]

    def call_frame(self, frame: dict) -> dict:
        text = "\n".join(json.dumps(e, separators=(",", ":")) for e in self.events(frame)) or "\n"
        return {"text": text, "in_tokens": len(frame["prompt"]) // 4, "cached_tokens": 0, "out_tokens": len(text) // 4, "cost_usd": 0.0,
                "seconds": 0.0, "tokens_estimated": True, "tool_items": 0}


# ------------------------------------------------------------------ the directive session

def run_directive(case: E.Case8, backends: dict, overhead: dict, wd: pathlib.Path, first: int = 0, oracle: bool = False) -> dict:
    spec = case.spec
    team, n, k = spec.team, len(spec.team), spec.k
    labels = E.seat_labels(team)
    pos = [(i + first) % n for i in range(n)]
    agent_backend = [team[p] for p in pos]
    agent_label = [labels[p] for p in pos]
    seats = n if spec.parallel else 1
    rdir = wd / f"{spec.name}_c{case.idx}_directive"
    rdir.mkdir(parents=True, exist_ok=True)
    docs = {"policy": case.doc}
    if case.erratum:
        docs["erratum"] = case.erratum
    C.write_docs(rdir / "docs", docs)
    onto = rdir / "ontology.json"
    onto.write_text(json.dumps(case.onto), encoding="utf-8")
    container = rdir / "state.sbgk"
    tfile = rdir / "targets.json"
    kernel = ResidentKernel(onto, rdir / "docs")
    oracle_w = Oracle(case) if oracle else None
    t_start = time.time()
    visible = ["policy"]
    created: dict[str, tuple[int, int]] = {}
    status: dict[str, str] = {}
    full, snap = E.kernel_full(kernel, container, rdir)
    status = E.status_map(full)
    notice_step = None
    step_log: list[dict] = []
    goal_step = None
    revokes = wrong_revokes = 0
    matrix: Counter = Counter()
    emit_us: list[float] = []
    stop_reason = "cap"
    try:
        for step in range(1, spec.cap + 1):
            # the container is a snapshot of the current state (kernel_full at the end of every step), for the CLI path only
            batch = batch_for(kernel, container, tfile, targets_for(case, visible), seats, k, step)
            emit_us.append(batch["analysis_us"])
            frames = batch["frames"]
            if spec.parallel:
                seat_agent = [(s + step - 1) % n for s in range(seats)]
            else:
                seat_agent = [(step - 1) % n]
            work = [(s, frames[s]) for s in range(seats) if not frames[s]["noop"]]

            def do(item):
                s, fr = item
                a = seat_agent[s]
                if oracle_w:
                    return s, oracle_w.call_frame(fr), None
                try:
                    return s, backends[agent_backend[a]].call(fr["prompt"], f"{spec.name}-c{case.idx}-directive-s{step}-{agent_label[a]}"), None
                except Exception as e:  # noqa: BLE001
                    return s, None, str(e)[:300]

            if len(work) > 1:
                with cf.ThreadPoolExecutor(max_workers=len(work)) as ex:
                    results = list(ex.map(do, work))
            else:
                results = [do(w) for w in work]
            failed = [e for _, _, e in results if e]
            if failed:
                raise RuntimeError(f"model call failed at step {step}, run aborted: {failed[0]}")
            recs = []
            for (s, r, _), (_, fr) in zip(results, work):
                a = seat_agent[s]
                rec = {"step": step, "seat": s, "agent": a, "label": agent_label[a], "backend": agent_backend[a], "directive_id": fr["directive_id"],
                       "priority": fr["priority"], "kind": fr["kind"], "target": fr["target"], "accepted": 0, "new": 0, "repeat_partner": 0,
                       "repeat_self": 0, "repeat_unavoidable": 0, "repair": 0, "rejected": 0, "unsent": 0, "reject_codes": [], "revokes": 0,
                       "repeat_after_notice": 0, "rederive_after_notice": 0, "over_budget": 0, "repair_call": False, "repair_ok": None, "contract_violations": 0,
                       "prompt_chars": fr["prompt_chars"], "cmdlen": E.cmdlen(fr["prompt"]), "raw_hidden": 0, "raw_total": 0, "compact": False,
                       "call_error": None, "in_tokens": 0, "in_net": 0, "out_tokens": 0, "cost_usd": 0.0, "seconds": 0.0, "tokens_estimated": False,
                       "tool_items": 0, "from_cache": False, "message": None}
                rec["emitted"] = 0
                con = contract_of(fr)
                for attempt in range(2):
                    if attempt == 1:
                        if rec["rejected"] == 0 or oracle_w:
                            break
                        rec["repair_call"] = True
                        prompt2 = fr["prompt"] + REPAIR_NOTE.format(prev=r["text"].strip()[:2500], n=rej_at + 1, err=json.dumps(rej_resp, ensure_ascii=False)[:600])
                        try:
                            r = backends[agent_backend[a]].call(prompt2, f"{spec.name}-c{case.idx}-directive-s{step}-{agent_label[a]}-repair")
                        except Exception as e:  # noqa: BLE001
                            raise RuntimeError(f"model call failed at step {step} (repair), run aborted: {e}") from e
                        rec["prompt_chars_repair"] = len(prompt2)
                    rec["in_tokens"] += r["in_tokens"]
                    rec["in_net"] += max(0, r["in_tokens"] - overhead.get(agent_backend[a], 0)) if not oracle_w else r["in_tokens"]
                    rec["out_tokens"] += r["out_tokens"]
                    rec["cost_usd"] += r.get("cost_usd") or 0.0
                    rec["seconds"] += r.get("seconds", 0.0)
                    rec["tokens_estimated"] = r.get("tokens_estimated", False)
                    rec["tool_items"] += r.get("tool_items", 0)
                    rec["from_cache"] = rec["from_cache"] or bool(r.get("from_cache"))
                    events, _ = parse_turn(r["text"], False)
                    limit = fr["max_events"] if attempt == 0 else max(1, fr["max_events"] - rec["accepted"])
                    rec["over_budget"] += max(0, len(events) - limit)
                    events = events[:limit]
                    rec["emitted"] += len(events)
                    rej_at, rej_resp = None, None
                    for idx_ev, ev in enumerate(events):
                        if rej_at is not None:
                            rec["unsent"] += 1
                            continue
                        if not isinstance(ev, dict) or "__bad_json__" in ev:
                            resp = {"status": "error", "code": "BAD_JSON", "message": "the line is not valid JSON"}
                        elif ev.get("op") not in R8.VALID_OPS:
                            resp = {"status": "error", "code": "UNKNOWN_OP", "message": f"unknown op '{ev.get('op')}'"}
                        elif (why := contract_violation(ev, con)) is not None:
                            resp = {"status": "error", "code": "DIRECTIVE_VIOLATION", "message": why,
                                    "obligation": {"action": "emit only the events the directive asks for"}}
                            rec["contract_violations"] += 1
                        else:
                            resp = kernel.send(ev)
                        if resp.get("status") != "ok":
                            rec["rejected"] += 1
                            rec["reject_codes"].append(resp.get("code"))
                            rej_at, rej_resp = idx_ev, resp
                            continue
                        rec["accepted"] += 1
                        node, op = resp.get("node"), resp.get("op")
                        need_refresh = False
                        if op == "revoke_evidence":
                            rec["revokes"] += 1
                            revokes += 1
                            full, snap = E.kernel_full(kernel, container, rdir)
                            status = E.status_map(full)
                            quote = next((e["quote"] for e in full["evidence"] if e["id"] == node), "")
                            if spec.retract and quote not in case.withdrawn.values():
                                wrong_revokes += 1
                        elif resp.get("existed"):
                            cr = created.get(node)
                            if status.get(node) == "UNSUPPORTED":
                                rec["repair"] += 1
                                need_refresh = True
                            else:
                                if cr is not None and cr[0] == a:
                                    rec["repeat_self"] += 1
                                else:
                                    rec["repeat_partner"] += 1
                                    if cr is not None:
                                        matrix[f"{agent_label[a]}->{agent_label[cr[0]]}"] += 1
                                if spec.parallel and cr is not None and cr[1] == step and cr[0] != a:
                                    rec["repeat_unavoidable"] += 1
                                if notice_step is not None and step > notice_step:
                                    rec["repeat_after_notice"] += 1
                                    if op == "derive":
                                        rec["rederive_after_notice"] += 1
                        else:
                            rec["new"] += 1
                            if node is not None:
                                created.setdefault(node, (a, step))
                                status[node] = resp.get("claim_status") or "ACTIVE"
                        if resp.get("claim_status") not in (None, "SUPPORTED"):
                            need_refresh = True
                        if need_refresh:
                            full, snap = E.kernel_full(kernel, container, rdir)
                            status = E.status_map(full)
                    if attempt == 1:
                        rec["repair_ok"] = rej_at is None
                # context flush: nothing of this call is kept for the next one
                recs.append(rec)
            full, snap = E.kernel_full(kernel, container, rdir)
            status = E.status_map(full)
            ev_ = case.evaluate(full)
            if spec.retract and notice_step is None:
                bound = any(e["quote"] == case.trigger_quote for e in full["evidence"])
                if (step >= 3 and bound) or step >= 5:
                    notice_step = step
                    visible = ["erratum", "policy"]  # the erratum is published: from now on the compiler routes it
            step_log.append({"step": step, "recs": recs, "done": ev_["done"], "false": ev_["false"], "conflicting": ev_["conflicting"],
                             "unsupported": ev_["unsupported"], "withdrawn_active": ev_["withdrawn_active"], "nodes": snap.get("nodes", 0),
                             "notice_issued": notice_step == step, "idle_seats": seats - len(work), "gaps": batch["gaps_total"],
                             "gaps_by_priority": batch["gaps_by_priority"], "compiler_complete": batch["complete"],
                             "analysis_us": batch["analysis_us"], "analysis_warm_us": batch.get("analysis_warm_us"), "emit_total_us": batch.get("total_us"),
                             "open_us": batch.get("open_us"), "pack_us": batch.get("pack_us"), "segments": batch.get("segments"),
                             "emit_resident": bool(batch.get("resident"))})
            if ev_["goal"] and (not spec.retract or notice_step is not None):
                goal_step = step
                stop_reason = "goal"
                break
            # with a retraction, stop only once the compiler has seen the erratum (it becomes visible to the batch of the NEXT step)
            if batch["complete"] and not work and not (spec.retract and (notice_step is None or notice_step == step)):
                stop_reason = "compiler_complete_without_goal"
                break
        fin = case.evaluate(full)
    finally:
        kernel.close()
        shutil.rmtree(rdir, ignore_errors=True)

    R = [x for s in step_log for x in s["recs"]]
    sm = lambda key: sum(x.get(key, 0) or 0 for x in R)  # noqa: E731
    rej = Counter(c for x in R for c in x["reject_codes"])
    return {
        "scenario": spec.name, "case": case.idx, "mode": "directive", "seats": agent_label, "backends": agent_backend, "version": VERSION,
        "steps_run": len(step_log), "goal_step": goal_step, "completed": goal_step is not None, "stop_reason": stop_reason,
        "targets": case.targets, "targets_done": fin["done"], "missing_final": case.targets - fin["done"],
        "accepted": sm("accepted"), "new": sm("new"), "repeat_partner": sm("repeat_partner"), "repeat_self": sm("repeat_self"),
        "repeat_unavoidable": sm("repeat_unavoidable"), "repair": sm("repair"), "rejected": sm("rejected"), "reject_codes": dict(rej),
        "unsent": sm("unsent"), "over_budget": sm("over_budget"),
        "empty_steps": sum(1 for x in R if x["accepted"] == 0), "wasted_steps": sum(1 for x in R if x["new"] == 0),
        "wrong_facts": fin["wrong_facts"], "false_final": fin["false"], "stale_final": fin["stale"], "under_conflict_final": fin["under_conflict"],
        "withdrawn_active_final": fin["withdrawn_active"], "conflicting_final": fin["conflicting"], "x_ok": fin["x_ok"], "p_ok": fin["p_ok"],
        "revokes": revokes, "wrong_revokes": wrong_revokes, "dropped_plain": 0,
        "repeat_after_notice": sm("repeat_after_notice"), "rederive_after_notice": sm("rederive_after_notice"), "notice_step": notice_step,
        "in_tokens": sm("in_tokens"), "in_net": sm("in_net"), "out_tokens": sm("out_tokens"), "cost_usd": sm("cost_usd"), "seconds": sm("seconds"),
        "tool_items": sm("tool_items"), "from_cache": sum(1 for x in R if x["from_cache"]), "calls": len(R) + sum(1 for x in R if x["repair_call"]),
        "repair_calls": sum(1 for x in R if x["repair_call"]), "repair_ok": sum(1 for x in R if x["repair_ok"]), "call_errors": 0,
        "contract_violations": sum(x.get("contract_violations", 0) for x in R),
        "idle_seat_slots": sum(s["idle_seats"] for s in step_log), "raw_hidden_share": 0.0, "compact_calls": 0,
        "max_cmdlen": max((x["cmdlen"] for x in R), default=0), "repeat_matrix": dict(matrix), "emit_analysis_us": emit_us,
        "wall_s": time.time() - t_start, "step_log": step_log,
    }


# ------------------------------------------------------------------ window size on identical graph states (no model involved)

def window_replay(block: str = "c_long", idx: int = 0, k: int | None = None) -> list[dict]:
    """Play a case with the deterministic worker and, at every step, measure BOTH windows on the same kernel state:
    the directive frame the compiler emits, and the prompt a stateful agent would get (whole document + whole compiled graph
    + its whole own history, no budget). This isolates how the window grows with the graph from any model behaviour."""
    case = make_case(block, idx)
    if k is not None:  # same document, fewer events per step (to follow the growth over more steps)
        case = E.Case8(dataclasses.replace(SPECS9[block], k=k), idx, seed=SEEDS9[block] + idx)
    wd = OUT / f"work_window_{block}_{idx}_{k}"
    shutil.rmtree(wd, ignore_errors=True)
    wd.mkdir(parents=True, exist_ok=True)
    C.write_docs(wd / "docs", {"policy": case.doc})
    (wd / "o.json").write_text(json.dumps(case.onto), encoding="utf-8")
    kernel = ResidentKernel(wd / "o.json", wd / "docs")
    orc = Oracle(case)
    tf = wd / "t.json"
    targets = targets_for(case, ["policy"])
    cont = wd / "state.sbgk"
    own: list[dict] = []
    rows = []
    old = E.PROMPT_BUDGET
    E.PROMPT_BUDGET = 10 ** 9
    try:
        full, snap = E.kernel_full(kernel, cont, wd)
        for step in range(1, 200):
            batch = batch_for(kernel, cont, tf, targets, 1, case.spec.k, step)
            stateful, _ = E.build_prompt(case, "graph", 0, step, own, own, [], full if step > 1 else None, None)
            fr = batch["frames"][0]
            rows.append({"step": step, "nodes": snap.get("nodes", 0), "graph_events": len(own), "stateful_chars": len(stateful),
                         "directive_chars": fr["prompt_chars"] if not fr["noop"] else 0, "analysis_us": batch["analysis_us"],
                         "resident": bool(batch.get("resident"))})
            if batch["complete"] or fr["noop"]:
                break
            for ev in orc.events(fr):
                resp = kernel.send(ev)
                own.append({"step": step, "seat": 0, "ev": ev, "resp": resp, "cls": "new" if resp.get("status") == "ok" and not resp.get("existed") else ""})
            full, snap = E.kernel_full(kernel, cont, wd)
    finally:
        E.PROMPT_BUDGET = old
        kernel.close()
        shutil.rmtree(wd, ignore_errors=True)
    return rows


# ------------------------------------------------------------------ baselines through the EXP-8 harness

def run_baseline(case: E.Case8, mode: str, backends: dict, overhead: dict, wd: pathlib.Path, first: int) -> dict:
    if mode == "stateful":
        # O(N) window: the whole document, the whole compiled graph and the agent's own history, with NO prompt budget
        # (the solo agent of c_long is Codex, which reads its prompt from stdin)
        old = E.PROMPT_BUDGET
        E.PROMPT_BUDGET = 10 ** 9
        try:
            res = R8.run_session(case, "graph", backends, overhead, wd, first)
        finally:
            E.PROMPT_BUDGET = old
        res["mode"] = "stateful"
        return res
    return R8.run_session(case, mode, backends, overhead, wd, first)


_print_lock = threading.Lock()


def run_block(block: str, n_cases: int, modes: list[str] | None = None, workers: int = 4, fresh: bool = False, oracle: bool = False) -> dict:
    spec = SPECS9[block]
    modes = modes or MODES9[block]
    OUT.mkdir(parents=True, exist_ok=True)
    RUNS.mkdir(parents=True, exist_ok=True)
    backends = {} if oracle else {b: R8.make_backend(b) for b in sorted(set(spec.team))}
    overhead = {} if oracle else R8.calibrate(backends)
    cases = [make_case(block, i) for i in range(n_cases)]
    wd = OUT / f"work_{block}"
    n = len(spec.team)
    jobs = [(c, m, c.idx % n) for c in cases for m in modes]

    def job(j):
        c, m, first = j
        f = RUNS / f"{block}_c{c.idx}_{m}{'_oracle' if oracle else ''}.json"
        if f.exists() and not fresh:
            res = json.loads(f.read_text(encoding="utf-8"))
            if res.get("version") in (VERSION, R8.VERSION) and not res.get("error"):
                return res
        t0 = time.time()
        try:
            if m == "directive":
                res = run_directive(c, backends, overhead, wd, first, oracle=oracle)
            else:
                res = run_baseline(c, m, backends, overhead, wd, first)
            res["scenario"] = block
        except Exception as e:  # noqa: BLE001 - a failed run is reported and redone later from the call cache
            res = {"scenario": block, "case": c.idx, "mode": m, "error": str(e)[:400], "completed": False, "steps_run": 0, "version": VERSION}
        res["wall_s"] = res.get("wall_s", time.time() - t0)
        if not res.get("error"):
            f.write_text(json.dumps(res, ensure_ascii=False), encoding="utf-8")
        with _print_lock:
            print(f"  [{block}] case {c.idx} {m:<9}: completed={res.get('completed')} steps={res.get('steps_run')}/{spec.cap} done={res.get('targets_done')}/{c.targets} "
                  f"acc={res.get('accepted')} rep={((res.get('repeat_partner') or 0) + (res.get('repeat_self') or 0))} unav={res.get('repeat_unavoidable')} "
                  f"rej={res.get('rejected')} false={res.get('false_final')} ${res.get('cost_usd', 0) or 0:.2f} {res.get('wall_s', 0):.0f}s "
                  f"{('ERROR ' + res['error']) if res.get('error') else ''}", flush=True)
        return res

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(job, jobs))
    shutil.rmtree(wd, ignore_errors=True)
    return {
        "scenario": block, "spec": {k: (list(v) if isinstance(v, tuple) else v) for k, v in spec.__dict__.items()},
        "backends": {b: {"label": be.label, "version": getattr(be, "version", ""), "tokens_estimated": not be.exact_tokens} for b, be in backends.items()},
        "overhead_in_tokens": overhead, "modes": modes, "version": VERSION, "oracle": oracle,
        "case_info": [{"idx": c.idx, "targets": c.targets, "doc_bytes": len(c.doc), "seed": c.seed, "min_events": c.min_events,
                       "services": spec.services, "gold_services": len(c.gold_services)} for c in cases],
        "results": results,
    }
