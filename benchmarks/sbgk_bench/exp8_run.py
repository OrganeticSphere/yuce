"""EXP-8 runner: one team session per (scenario, case, visibility mode), plus the scenario driver.

Reuses the EXP-7 kernel session, strict-JSON turn parser and the three agent backends (imported, not modified). Differences from EXP-7:
  * its own call cache (results/exp8/calls) so EXP-7 data is never touched;
  * rounds: with spec.parallel all agents of a round are prompted from the SAME state and the kernel merges their events afterwards;
  * the environment may issue a binding notice (erratum) mid-task;
  * every judgement (repeat, repair, conflict, stale conclusion) is read from the kernel's answers and from the graph the kernel compiled.
"""

from __future__ import annotations

import concurrent.futures as cf
import json
import os
import random
import shutil
import threading
import time
from collections import Counter

from . import agents as AG
from . import common as C
from . import exp8_env as E
from .exp7_multiagent import Kernel, parse_turn

VERSION = "exp8-4"
CALLS = E.OUT / "calls"
RUNS = E.OUT / "runs"
_lock = threading.Lock()
SEM = {"codex": threading.Semaphore(int(os.environ.get("EXP8_CODEX", 4))),
       "deepseek": threading.Semaphore(int(os.environ.get("EXP8_DEEPSEEK", 6))),
       "opus": threading.Semaphore(int(os.environ.get("EXP8_OPUS", 4))),
       "sonnet": threading.Semaphore(int(os.environ.get("EXP8_SONNET", 4)))}
VALID_OPS = {"bind_evidence", "assert_fact", "derive", "revoke_evidence"}
QUOTA: dict[str, str] = {}  # backend -> the runtime's "limit reached" message; once set, no new calls go to that backend
QUOTA_MARKERS = ("session limit", "usage limit", "rate limit", "hit your", "quota")


class QuotaExceeded(RuntimeError):
    pass


class FileSlots:
    """Cross-process limit on concurrent calls (OpenClaw keeps a local state database that does not tolerate many parallel processes)."""

    def __init__(self, name: str, n: int):
        self.paths = [E.OUT / f".slot_{name}_{i}" for i in range(n)]
        self.fh = None

    def __enter__(self):
        if os.name != "nt":
            return self
        import msvcrt
        E.OUT.mkdir(parents=True, exist_ok=True)
        while True:
            for path in self.paths:
                fh = open(path, "a+b")
                try:
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    self.fh = fh
                    return self
                except OSError:
                    fh.close()
            time.sleep(0.3 + random.random())

    def __exit__(self, *exc):
        if self.fh is not None:
            import msvcrt
            self.fh.seek(0)
            msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
            self.fh.close()
            self.fh = None
        return False


GLOBAL_SLOTS = {"deepseek": int(os.environ.get("EXP8_DEEPSEEK_GLOBAL", 3))}


class _Cached:
    """Same call contract as agents.Backend.call, but cached under results/exp8/calls and rate limited per runtime."""

    def call(self, prompt: str, tag: str = "") -> dict:
        f = CALLS / f"{self._key(prompt)}.json"
        if f.exists():
            try:
                r = json.loads(f.read_text(encoding="utf-8"))
                r["from_cache"] = True
                return r
            except ValueError:
                pass  # half-written by a concurrent process: treat as a miss and overwrite
        if self.name in QUOTA:
            raise QuotaExceeded(f"{self.name}: {QUOTA[self.name]}")
        last = None
        attempts = 6 if self.name == "deepseek" else 3
        for attempt in range(attempts):
            try:
                slots = FileSlots(self.name, GLOBAL_SLOTS[self.name]) if self.name in GLOBAL_SLOTS else None
                with SEM[self.name]:
                    if slots:
                        slots.__enter__()
                    try:
                        t0 = time.time()
                        r = self._run(prompt)
                        r["seconds"] = time.time() - t0
                    finally:
                        if slots:
                            slots.__exit__(None, None, None)
                r.update({"backend": self.name, "model": self.label, "tag": tag, "attempts": attempt + 1, "prompt_chars": len(prompt)})
                if not r.get("text", "").strip():
                    raise RuntimeError("empty reply")
                with _lock:
                    CALLS.mkdir(parents=True, exist_ok=True)
                    tmp = f.with_name(f"{f.name}.{os.getpid()}.{threading.get_ident()}.tmp")
                    tmp.write_text(json.dumps({**r, "prompt": prompt}, ensure_ascii=False), encoding="utf-8")
                    os.replace(tmp, f)
                return r
            except Exception as e:  # noqa: BLE001 - any transport failure is retried, a quota message is not
                last = e
                if any(m in str(e).lower() for m in QUOTA_MARKERS):
                    QUOTA[self.name] = str(e)[:200]
                    raise QuotaExceeded(f"{self.name}: {QUOTA[self.name]}") from e
                time.sleep(2 + 3 * attempt + 4 * random.random())
        raise RuntimeError(f"{self.name} call failed ({tag}): {last}")


class SonnetBackend(AG.OpusBackend):
    """Claude Sonnet 5.5 through the same Claude Code runtime (the Opus backend's call, only another model id).
    EXP-8 was first launched with Opus 5.5; it hit the subscription session limit and, at the user's request, the Claude seat was switched to Sonnet 5.5."""
    name = "sonnet"
    label = "claude-sonnet-5-5"


def make_backend(name: str):
    cls = {"codex": AG.CodexBackend, "deepseek": AG.DeepSeekBackend, "opus": AG.OpusBackend, "sonnet": SonnetBackend}[name]
    return type(cls.__name__ + "8", (_Cached, cls), {})()


def calibrate(backends: dict) -> dict:
    """Fixed per-call input tokens that belong to the runtime, not to our prompt: mean of three trivial probes (the runtimes report slightly
    different totals from call to call, so one probe is too noisy)."""
    base = 'Reply with exactly one line of JSON: {"ok":1}. Do not use tools.'
    out = {}
    for n, b in backends.items():
        vals = [b.call(base + suffix, f"overhead-{n}")["in_tokens"] for suffix in ("", " Probe B.", " Probe C.")]
        out[n] = round(sum(vals) / len(vals))
    return out


# ------------------------------------------------------------------ one team session

def run_session(case: E.Case8, mode: str, backends: dict, overhead: dict, wd, first: int = 0, sleep_hook=None) -> dict:
    spec = case.spec
    team, n, k = spec.team, len(spec.team), spec.k
    labels = E.seat_labels(team)
    pos = [(i + first) % n for i in range(n)]  # speaking order: seat s is team position pos[s]
    seat_backend = [team[p] for p in pos]
    seat_label = [labels[p] for p in pos]
    rdir = wd / f"{spec.name}_c{case.idx}_{mode}"
    rdir.mkdir(parents=True, exist_ok=True)
    docs = {"policy": case.doc}
    if case.erratum:
        docs["erratum"] = case.erratum
    C.write_docs(rdir / "docs", docs)
    onto = rdir / "ontology.json"
    onto.write_text(json.dumps(case.onto), encoding="utf-8")
    container = rdir / "state.sbgk"
    kernel = Kernel(onto, rdir / "docs")
    t_start = time.time()

    own: list[list[dict]] = [[] for _ in range(n)]
    team_log: list[dict] = []
    messages: list[dict] = []
    created: dict[str, tuple[int, int]] = {}  # node -> (seat, step) of the event that created it
    full: dict | None = None
    status: dict[str, str] = {}
    nodes = 0
    notice, notice_step, notice_seat = None, None, None
    step_log: list[dict] = []
    goal_step = None
    call_errors = revokes = wrong_revokes = dropped_plain = 0
    prev_ok: set = set()
    special = case.special
    matrix: Counter = Counter()

    def refresh():
        nonlocal full, status, nodes
        full, snap = E.kernel_full(kernel, container, rdir)
        status = E.status_map(full)
        nodes = snap.get("nodes", 0)
        return full

    try:
        for step in range(1, spec.cap + 1):
            acting = [(step - 1) % n] if not spec.parallel else [(step - 1 + j) % n for j in range(n)]
            prompts = {seat: E.build_prompt(case, mode, seat, step, own[seat], team_log, messages, full,
                                            notice if (not spec.private_notice or seat == notice_seat) else None) for seat in acting}

            def do(seat):
                try:
                    be = backends[seat_backend[seat]]
                    return be.call(prompts[seat][0], f"{spec.name}-c{case.idx}-{mode}-s{step}-{seat_label[seat]}"), None
                except Exception as e:  # noqa: BLE001 - collected, then the run is aborted below
                    return None, str(e)[:300]

            if len(acting) == 1:
                results = {acting[0]: do(acting[0])}
            else:
                with cf.ThreadPoolExecutor(max_workers=len(acting)) as ex:
                    results = dict(zip(acting, ex.map(do, acting)))
            failed = [results[seat][1] for seat in acting if results[seat][1]]
            if failed:
                raise RuntimeError(f"model call failed at {spec.unit} {step}, run aborted (it is redone later from the call cache): {failed[0]}")
            recs = []
            for seat in acting:
                r, err = results[seat]
                pmeta = prompts[seat][1]
                events, message = ([], None) if err else parse_turn(r["text"], mode == "prose")
                over = max(0, len(events) - k)
                events = events[:k]
                rec = {"step": step, "seat": seat, "label": seat_label[seat], "backend": seat_backend[seat], "emitted": len(events) + over,
                       "over_budget": over, "accepted": 0, "new": 0, "repeat_partner": 0, "repeat_self": 0, "repeat_unavoidable": 0,
                       "repair": 0, "rejected": 0, "unsent": 0, "reject_codes": [], "revokes": 0, "repeat_after_notice": 0, "rederive_after_notice": 0,
                       "call_error": err, "cmdlen": pmeta.get("cmdlen"), "raw_hidden": pmeta.get("raw_hidden", 0), "raw_total": pmeta.get("raw_total", 0),
                       "compact": pmeta.get("compact", False)}
                items, stopped = [], False
                for ev in events:
                    if stopped:
                        items.append({"step": step, "seat": seat, "ev": ev, "resp": {"status": "unsent"}, "unsent": True})
                        rec["unsent"] += 1
                        continue
                    if not isinstance(ev, dict) or "__bad_json__" in ev:
                        resp = {"status": "error", "code": "BAD_JSON", "message": "the line is not valid JSON"}
                    elif ev.get("op") not in VALID_OPS:
                        resp = {"status": "error", "code": "UNKNOWN_OP", "message": f"unknown op '{ev.get('op')}'",
                                "expected_by_kernel": {"ops": sorted(VALID_OPS)}}
                    else:
                        resp = kernel.send(ev)
                    it = {"step": step, "seat": seat, "ev": ev, "resp": resp}
                    items.append(it)
                    if resp.get("status") != "ok":
                        rec["rejected"] += 1
                        rec["reject_codes"].append(resp.get("code"))
                        stopped = True
                        continue
                    rec["accepted"] += 1
                    node, op = resp.get("node"), resp.get("op")
                    need_refresh = False
                    if op == "revoke_evidence":
                        rec["revokes"] += 1
                        revokes += 1
                        it["cls"] = "revoke"
                        cur = refresh()
                        quote = next((e["quote"] for e in cur["evidence"] if e["id"] == node), "")
                        if spec.retract and quote not in case.withdrawn.values():
                            wrong_revokes += 1
                    elif resp.get("existed"):
                        cr = created.get(node)
                        if status.get(node) == "UNSUPPORTED":
                            it["cls"] = "repair"
                            rec["repair"] += 1
                            need_refresh = True
                        else:
                            it["cls"] = "repeat"
                            if cr is not None and cr[0] == seat:
                                rec["repeat_self"] += 1
                            else:
                                rec["repeat_partner"] += 1
                                it["repeat_of"] = cr[0] if cr else None
                                if cr is not None:
                                    matrix[f"{seat_label[seat]}->{seat_label[cr[0]]}"] += 1
                            if spec.parallel and cr is not None and cr[1] == step and cr[0] != seat:
                                rec["repeat_unavoidable"] += 1  # the partner's step was made in this very round: nobody could see it
                            if notice_step is not None and step > notice_step:
                                rec["repeat_after_notice"] += 1
                                if op == "derive":
                                    rec["rederive_after_notice"] += 1  # re-derived a conclusion that was (or is again) established
                    else:
                        rec["new"] += 1
                        if node is not None:
                            created.setdefault(node, (seat, step))
                            status[node] = resp.get("claim_status") or "ACTIVE"
                        it["cls"] = "new"
                    if resp.get("claim_status") not in (None, "SUPPORTED"):
                        need_refresh = True  # a conflict flips the partner claim too
                    if need_refresh:
                        refresh()
                own[seat].extend(items)
                team_log.extend(items)
                if message:
                    messages.append({"step": step, "seat": seat, "text": message})
                if r:
                    rec.update({"in_tokens": r["in_tokens"], "in_net": max(0, r["in_tokens"] - overhead.get(seat_backend[seat], 0)),
                                "out_tokens": r["out_tokens"], "cost_usd": r.get("cost_usd") or 0.0, "seconds": r["seconds"],
                                "tokens_estimated": r["tokens_estimated"], "tool_items": r.get("tool_items", 0),
                                "from_cache": bool(r.get("from_cache")), "message": message})
                else:
                    rec.update({"in_tokens": 0, "in_net": 0, "out_tokens": 0, "cost_usd": 0.0, "seconds": 0.0, "tokens_estimated": False,
                                "tool_items": 0, "from_cache": False, "message": None})
                if err:
                    call_errors += 1
                recs.append(rec)
            cur = refresh()
            ev_ = case.evaluate(cur)
            ok_now = {(c["s"], tuple(c["t"])) for c in cur["claims"] if c["p"] == "needs_review" and c["st"] == "SUPPORTED"} & case.gold_nr
            dropped_plain += len({x for x in prev_ok if x[0] not in special} - ok_now)
            prev_ok = ok_now
            if spec.retract and notice_step is None:
                bound = any(e["quote"] == case.trigger_quote for e in cur["evidence"])
                if (step >= 3 and bound) or step >= 5:
                    notice_step, notice = step, case.notice_text(step)
                    notice_seat = step % n  # the agent who speaks next (only it gets the notice when the notice is private)
            step_log.append({"step": step, "recs": recs, "done": ev_["done"], "false": ev_["false"], "conflicting": ev_["conflicting"],
                             "unsupported": ev_["unsupported"], "withdrawn_active": ev_["withdrawn_active"], "nodes": nodes,
                             "notice_issued": notice_step == step})
            if sleep_hook:
                sleep_hook(step)
            if ev_["goal"] and (not spec.retract or notice_step is not None):
                goal_step = step
                break
        cur = refresh()
        fin = case.evaluate(cur)
        missing = case.targets - fin["done"]
    finally:
        kernel.close()
        shutil.rmtree(rdir, ignore_errors=True)

    R = [x for s in step_log for x in s["recs"]]
    sm = lambda key: sum(x.get(key, 0) or 0 for x in R)  # noqa: E731
    rej = Counter(c for x in R for c in x["reject_codes"])
    raw_total = sum(x["raw_total"] for x in R)
    return {
        "scenario": spec.name, "case": case.idx, "mode": mode, "seats": seat_label, "backends": seat_backend, "version": VERSION,
        "steps_run": len(step_log), "goal_step": goal_step, "completed": goal_step is not None,
        "targets": case.targets, "targets_done": fin["done"], "missing_final": missing,
        "accepted": sm("accepted"), "new": sm("new"), "repeat_partner": sm("repeat_partner"), "repeat_self": sm("repeat_self"),
        "repeat_unavoidable": sm("repeat_unavoidable"), "repair": sm("repair"), "rejected": sm("rejected"), "reject_codes": dict(rej),
        "unsent": sm("unsent"), "over_budget": sm("over_budget"),
        "empty_steps": sum(1 for x in R if x["accepted"] == 0), "wasted_steps": sum(1 for x in R if x["new"] == 0),
        "wrong_facts": fin["wrong_facts"], "false_final": fin["false"], "stale_final": fin["stale"], "under_conflict_final": fin["under_conflict"],
        "withdrawn_active_final": fin["withdrawn_active"], "conflicting_final": fin["conflicting"], "x_ok": fin["x_ok"], "p_ok": fin["p_ok"],
        "revokes": revokes, "wrong_revokes": wrong_revokes, "dropped_plain": dropped_plain,
        "repeat_after_notice": sm("repeat_after_notice"), "rederive_after_notice": sm("rederive_after_notice"), "notice_step": notice_step,
        "in_tokens": sm("in_tokens"), "in_net": sm("in_net"), "out_tokens": sm("out_tokens"), "cost_usd": sm("cost_usd"), "seconds": sm("seconds"),
        "tool_items": sm("tool_items"), "from_cache": sum(1 for x in R if x["from_cache"]), "calls": len(R), "call_errors": call_errors,
        "raw_hidden_share": (sm("raw_hidden") / raw_total) if raw_total else 0.0, "compact_calls": sum(1 for x in R if x["compact"]),
        "max_cmdlen": max((x["cmdlen"] or 0) for x in R) if R else 0, "repeat_matrix": dict(matrix),
        "wall_s": time.time() - t_start, "step_log": step_log,
    }


# ------------------------------------------------------------------ driver

def run_scenario(name: str, n_cases: int, modes: list[str], workers: int = 6, fresh: bool = False, cases_from: int = 0) -> dict:
    spec = E.SPECS[name]
    E.OUT.mkdir(parents=True, exist_ok=True)
    RUNS.mkdir(parents=True, exist_ok=True)
    backends = {b: make_backend(b) for b in sorted(set(spec.team))}
    overhead = calibrate(backends)
    cases = [E.Case8(spec, i) for i in range(cases_from, n_cases)]
    wd = E.OUT / f"work_{name}"
    n = len(spec.team)
    jobs = [(c, m, c.idx % n) for c in cases for m in modes]

    def job(j):
        c, m, first = j
        f = RUNS / f"{name}_c{c.idx}_{m}.json"
        if f.exists() and not fresh:
            res = json.loads(f.read_text(encoding="utf-8"))
            if res.get("version") == VERSION and not res.get("error"):
                return res
        t0 = time.time()
        try:
            res = run_session(c, m, backends, overhead, wd, first)
        except Exception as e:  # noqa: BLE001 - a failed run is data, not a crash
            res = {"scenario": name, "case": c.idx, "mode": m, "error": str(e)[:400], "completed": False, "steps_run": 0, "version": VERSION}
        res["wall_s"] = res.get("wall_s", time.time() - t0)
        if not res.get("error"):
            f.write_text(json.dumps(res, ensure_ascii=False), encoding="utf-8")
        print(f"  [{name}] case {c.idx} {m:<9} {'+'.join(res.get('seats', []))}: completed={res.get('completed')} steps={res.get('steps_run')}/{spec.cap} "
              f"done={res.get('targets_done')}/{c.targets} accepted={res.get('accepted')} rep_p={res.get('repeat_partner')} rep_s={res.get('repeat_self')} "
              f"rej={res.get('rejected')} false={res.get('false_final')} ${res.get('cost_usd', 0):.2f} {res.get('wall_s', 0):.0f}s "
              f"{('ERROR ' + res['error']) if res.get('error') else ''}", flush=True)
        return res

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(job, jobs))
    data = {
        "scenario": name, "spec": {k: (list(v) if isinstance(v, tuple) else v) for k, v in E.SPECS[name].__dict__.items()},
        "backends": {b: {"label": be.label, "version": getattr(be, "version", ""), "tokens_estimated": not be.exact_tokens} for b, be in backends.items()},
        "overhead_in_tokens": overhead, "modes": modes, "version": VERSION,
        "case_info": [{"idx": c.idx, "targets": c.targets, "doc_bytes": len(c.doc), "seed": c.seed,
                       "roles": ({**c.role, "p_api": c.p_api, "p_services": len(c.p_services)} if c.role else None), "decoys": sorted(c.decoy), "min_events": c.min_events,
                       "gold_services": len(c.gold_services)} for c in cases],
        "results": results,
    }
    shutil.rmtree(wd, ignore_errors=True)
    return data
