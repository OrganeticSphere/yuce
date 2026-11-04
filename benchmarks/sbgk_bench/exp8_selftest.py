"""Offline self-test of the EXP-8 harness: no model is called.

A scripted 'agent' (it knows the case, it ignores what it is shown) plays through every scenario in every visibility mode, so that case
generation, prompt building and sizing, kernel flow, parallel merging, the erratum trigger, DRed / conflict handling, repeat accounting and
the goal check can be verified before any money is spent.   python benchmarks/run_exp8_stress.py --selftest
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import tempfile
import threading

from . import exp8_env as E
from . import exp8_run as R


def check_cases() -> list[str]:
    out = []
    for name, spec in E.SPECS.items():
        for idx in range(12):
            c = E.Case8(spec, idx)
            for lab, sent in c.clauses:
                assert c.doc.count(sent.encode()) == 1, f"{name} c{idx}: clause {lab} is not unique in the document"
            assert spec.gold[0] <= len(c.true_gold) <= spec.gold[1], (name, idx, len(c.true_gold))
            if spec.retract:
                assert len(c.gold_nr) == len(c.true_gold) - 2 and len(c.withdrawn) == 3 and len(c.p_services) >= 2
            if spec.systems:
                assert 1 <= len(c.gold_sys) <= len(c.gold_nr)
        c = E.Case8(spec, 0)
        out.append(f"{name}: doc {len(c.doc)} B, targets {c.targets}, gold services {len(c.gold_services)}, task {len(c.task_text())} chars")
    return out


class Scripted:
    """A cooperative but short-sighted agent: works through its own share of the services, re-creating the shared facts it needs."""
    exact_tokens = True
    label = "scripted"
    version = "selftest"

    def __init__(self, case: E.Case8):
        self.case = case
        self.queues: dict[str, list[dict]] = {}
        self.mine: dict[str, list[int]] = {}
        self.names: dict[str, dict[str, str]] = {}
        self.lock = threading.Lock()
        self.noticed: set[str] = set()
        self.p_done = False

    def _queue(self, letter: str, seat: int, n: int) -> list[dict]:
        c = self.case
        mine = [i for rank, i in enumerate(c.true_gold) if rank % n == seat]
        self.mine[letter] = mine
        role_of = {v: k for k, v in c.role.items()}
        q: list[dict] = []
        seen_dep = set()
        for i in mine:
            a = c.api_of[i]
            role = role_of.get(i)
            q.append({"n": f"eU{i}", "op": "bind", "label": f"U.{i}"})
            q.append({"n": f"fU{i}", "op": "use", "i": i, "ev": f"eU{i}", "pol": "POS"})
            if a not in seen_dep:
                seen_dep.add(a)
                q.append({"n": f"eD{a}", "op": "bind", "label": f"D.{a}"})
                q.append({"n": f"fD{a}", "op": "dep", "a": a, "ev": f"eD{a}"})
            if role in ("x", "y"):
                q.append({"n": f"eN{i}", "op": "bind", "label": f"N.{i}"})
                q.append({"n": f"fN{i}", "op": "use", "i": i, "ev": f"eN{i}", "pol": "NEG"})
            if role not in ("x", "y"):
                q.append({"n": f"rN{i}", "op": "nr", "i": i, "a": a})
            if c.spec.systems:
                q.append({"n": f"eP{i}", "op": "bind", "label": f"P.{i}"})
                q.append({"n": f"fP{i}", "op": "part", "i": i, "ev": f"eP{i}"})
                q.append({"n": f"rS{i}", "op": "sys", "i": i})
        return q

    def _on_notice(self, letter: str, q: list[dict], nm: dict[str, str]) -> None:
        c = self.case
        w, x, pa = c.role["w"], c.role["x"], c.p_api
        mine = self.mine[letter]
        new = []

        def drop(names):
            q[:] = [j for j in q if j["n"] not in names]

        if w in mine:
            drop({f"fU{w}", f"rN{w}", f"rS{w}"} if f"eU{w}" in nm else {f"eU{w}", f"fU{w}", f"rN{w}"})
            if f"eU{w}" in nm:
                new.append({"n": f"xU{w}", "op": "revoke", "ev": f"eU{w}"})
        if x in mine:
            nr = {"n": f"rN{x}", "op": "nr", "i": x, "a": c.api_of[x]}
            if f"eN{x}" in nm:
                drop({f"fN{x}"})
                new += [{"n": f"xN{x}", "op": "revoke", "ev": f"eN{x}"}, nr]
            else:
                drop({f"eN{x}", f"fN{x}"})
                q.append(nr)
        # the shared premise D.pa is withdrawn and restated in R.pa: the first agent that holds it revokes it and re-supports the fact
        if f"eD{pa}" in nm and f"fD{pa}" in nm:
            if not self.p_done:
                self.p_done = True
                new += [{"n": f"xD{pa}", "op": "revoke", "ev": f"eD{pa}"}, {"n": f"eR{pa}", "op": "bind", "label": f"R.{pa}"},
                        {"n": f"fR{pa}", "op": "dep", "a": pa, "ev": f"eR{pa}"}]
        elif f"eD{pa}" in nm:  # bound, fact not asserted yet: assert it from the restatement instead
            new.append({"n": f"eR{pa}", "op": "bind", "label": f"R.{pa}"})
            for j in q:
                if j["n"] == f"fD{pa}":
                    j["ev"] = f"eR{pa}"
        else:
            for j in q:
                if j["n"] == f"eD{pa}":
                    j["label"] = f"R.{pa}"
        q[0:0] = new

    def call(self, prompt: str, tag: str = "") -> dict:
        m = re.search(r'You are agent "([a-e])" \(seat (\d+) of (\d+)\)', prompt)
        letter, seat, n = m.group(1), int(m.group(2)) - 1, int(m.group(3))
        step = int(re.search(r"It is your (?:turn|round) \((?:turn|round) (\d+)\)", prompt).group(1))
        c, k = self.case, self.case.spec.k
        ev = []
        with self.lock:
            q = self.queues.setdefault(letter, self._queue(letter, seat, n))
            nm = self.names.setdefault(letter, {})
            if c.spec.retract and "NOTICE (published" in prompt and letter not in self.noticed:
                self.noticed.add(letter)
                self._on_notice(letter, q, nm)
            used = 0
            while q and used < k:
                job = q.pop(0)
                lid = f"{letter}{step}_{job['n']}"
                if job["op"] == "bind":
                    ev.append({"op": "bind_evidence", "local_id": lid, "doc_id": "policy", "exact_quote": c.quote[job["label"]]})
                elif job["op"] == "use":
                    i = job["i"]
                    lo, hi = c.use_t[i] if job["pol"] == "POS" else (c.use_t[i][0] + 20, c.use_t[i][1] + 10)
                    ev.append({"op": "assert_fact", "local_id": lid, "s": f"svc_{i:03d}", "p": "uses_api", "o": f"api_{c.api_of[i]:03d}", "polarity": job["pol"],
                               "ctx": "prod", "t": [lo, hi], "evidence": [nm[job["ev"]]]})
                elif job["op"] == "dep":
                    lo, hi = c.dep_t[job["a"]]
                    ev.append({"op": "assert_fact", "local_id": lid, "s": f"api_{job['a']:03d}", "p": "api_deprecated", "o": "true", "polarity": "POS",
                               "ctx": "prod", "t": [lo, hi], "evidence": [nm[job["ev"]]]})
                elif job["op"] == "nr":
                    ev.append({"op": "derive", "local_id": lid, "rule": "R_depr_review@1", "premises": [nm[f"fU{job['i']}"], nm[f"fD{job['a']}"]]})
                elif job["op"] == "part":
                    ev.append({"op": "assert_fact", "local_id": lid, "s": f"svc_{job['i']:03d}", "p": "part_of", "o": f"sys_{c.sys_of[job['i']]:02d}",
                               "polarity": "POS", "ctx": "prod", "t": [0, 1000], "evidence": [nm[job["ev"]]]})
                elif job["op"] == "sys":
                    ev.append({"op": "derive", "local_id": lid, "rule": "R_sys_flag@1", "premises": [nm[f"fP{job['i']}"], nm[f"rN{job['i']}"]]})
                elif job["op"] == "revoke":
                    ev.append({"op": "revoke_evidence", "target_evidence": nm[job["ev"]]})
                nm[job["n"]] = lid
                used += 1
        text = "\n".join(json.dumps(e, separators=(",", ":")) for e in ev)
        if "MESSAGE:" in prompt:
            text += "\nMESSAGE: scripted agent, ids " + ", ".join(e.get("local_id", "") for e in ev[:3])
        return {"text": text, "in_tokens": len(prompt) // 4, "cached_tokens": 0, "out_tokens": len(text) // 4, "cost_usd": 0.0, "seconds": 0.01,
                "tokens_estimated": True, "tool_items": 0}


def run_one(name: str, mode: str, idx: int = 0) -> dict:
    spec = E.SPECS[name]
    c = E.Case8(spec, idx)
    wd = pathlib.Path(tempfile.mkdtemp(prefix="exp8_selftest_"))
    try:
        brain = Scripted(c)
        return R.run_session(c, mode, {b: brain for b in set(spec.team)}, {b: 0 for b in set(spec.team)}, wd, first=0)
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def selftest(verbose: bool = True) -> int:
    for line in check_cases():
        print("case ok:", line)
    flow_test(verbose=False)
    print("flow test ok (partner repeat, conflict, erratum trigger, right/wrong revoke, repair, rejection + unsent)")
    bad = 0
    for name in E.SPECS:
        for mode in E.MODES:
            r = run_one(name, mode)
            msg = (f"{name:<8} {mode:<9} steps={r['steps_run']:>2}/{E.SPECS[name].cap} completed={r['completed']} done={r['targets_done']}/{r['targets']} "
                   f"acc={r['accepted']} new={r['new']} rep_p={r['repeat_partner']} rep_s={r['repeat_self']} unavoid={r['repeat_unavoidable']} repair={r['repair']} "
                   f"rej={r['rejected']} {r['reject_codes']} false={r['false_final']} stale={r['stale_final']} wd_active={r['withdrawn_active_final']} "
                   f"revokes={r['revokes']} wrong_rev={r['wrong_revokes']} maxcmd={r['max_cmdlen']} wall={r['wall_s']:.1f}s")
            if verbose:
                print(msg)
            if not r["completed"] and name != "retractp":  # in the private-notice variant the scripted agents (who never read it) may not finish
                bad += 1
    print("selftest finished;", "all scripted runs completed" if not bad else f"{bad} scripted runs did NOT complete")
    return bad


class FromScript:
    """Replays a fixed list of replies, one per call (used to test the bookkeeping on hand-made event sequences)."""
    exact_tokens = True
    label = "fixed"
    version = "selftest"

    def __init__(self, replies: list[str]):
        self.replies, self.i = replies, 0

    def call(self, prompt: str, tag: str = "") -> dict:
        text = self.replies[self.i] if self.i < len(self.replies) else ""
        self.i += 1
        return {"text": text or "\n", "in_tokens": len(prompt) // 4, "cached_tokens": 0, "out_tokens": 10, "cost_usd": 0.0, "seconds": 0.0,
                "tokens_estimated": True, "tool_items": 0}


def flow_test(verbose: bool = True) -> dict:
    """Hand-made sequence on a retraction case: partner repeat, a conflict, the erratum, revokes (right and wrong), cascade, repair, rejection."""
    spec = E.SPECS["retract"]
    c = E.Case8(spec, 0)
    r = c.role
    w, x, pa = r["w"], r["x"], c.p_api
    s1, s2 = c.p_services[0], c.p_services[1]

    def bind(lid, label):
        return json.dumps({"op": "bind_evidence", "local_id": lid, "doc_id": "policy", "exact_quote": c.quote[label]})

    def use(lid, i, ev, pol="POS"):
        lo, hi = c.use_t[i] if pol == "POS" else (c.use_t[i][0] + 20, c.use_t[i][1] + 10)
        return json.dumps({"op": "assert_fact", "local_id": lid, "s": f"svc_{i:03d}", "p": "uses_api", "o": f"api_{c.api_of[i]:03d}", "polarity": pol,
                           "ctx": "prod", "t": [lo, hi], "evidence": [ev]})

    def dep(lid, ev):
        return json.dumps({"op": "assert_fact", "local_id": lid, "s": f"api_{pa:03d}", "p": "api_deprecated", "o": "true", "polarity": "POS", "ctx": "prod",
                           "t": list(c.dep_t[pa]), "evidence": [ev]})

    def derive(lid, f_use, f_dep):
        return json.dumps({"op": "derive", "local_id": lid, "rule": "R_depr_review@1", "premises": [f_use, f_dep]})

    rev = lambda t: json.dumps({"op": "revoke_evidence", "target_evidence": t})  # noqa: E731
    replies = [
        "\n".join([bind("a1_e1", f"D.{pa}"), dep("a1_f1", "a1_e1"), bind("a1_e2", f"U.{s1}"), use("a1_f2", s1, "a1_e2"), derive("a1_r1", "a1_f2", "a1_f1")]),
        "\n".join([bind("b2_e1", f"D.{pa}"), bind("b2_e2", f"U.{w}"), use("b2_f1", w, "b2_e2"), bind("b2_e3", f"U.{s2}"), use("b2_f2", s2, "b2_e3")]),
        "\n".join([bind("c3_e1", f"N.{x}"), use("c3_f1", x, "c3_e1", "NEG"), bind("c3_e2", f"U.{x}"), use("c3_f2", x, "c3_e2")]),
        "\n".join([rev("a1_e1"), rev("c3_e1"), rev("b2_e2"), rev("a1_e2")]),
        "\n".join([bind("b5_e1", f"R.{pa}"), dep("b5_f1", "b5_e1"), derive("b5_r1", "b2_f2", "b5_f1"), bind("b5_e2", f"D.{pa}"), bind("b5_e3", f"U.{s2}")]),
    ]
    wd = pathlib.Path(tempfile.mkdtemp(prefix="exp8_flow_"))
    try:
        be = FromScript(replies)
        res = R.run_session(c, "graph", {b: be for b in set(spec.team)}, {b: 0 for b in set(spec.team)}, wd, first=0)
    finally:
        shutil.rmtree(wd, ignore_errors=True)
    if verbose:
        for s in res["step_log"][:6]:
            rec = s["recs"][0]
            print(f"  step {s['step']}: acc={rec['accepted']} new={rec['new']} rep_p={rec['repeat_partner']} rep_s={rec['repeat_self']} repair={rec['repair']} "
                  f"rej={rec['rejected']}{rec['reject_codes']} unsent={rec['unsent']} revokes={rec['revokes']} | done={s['done']} conflicting={s['conflicting']} "
                  f"unsupported={s['unsupported']} wd_active={s['withdrawn_active']} notice={s['notice_issued']}")
        print("  final:", {k: res[k] for k in ("notice_step", "wrong_revokes", "repair", "repeat_partner", "repeat_self", "rejected", "reject_codes", "unsent",
                                               "stale_final", "missing_final", "withdrawn_active_final", "completed", "rederive_after_notice")})
    s1r, s2r, s3r, s4r, s5r = [s["recs"][0] for s in res["step_log"][:5]]
    assert (s1r["new"], s1r["accepted"]) == (5, 5)
    assert (s2r["repeat_partner"], s2r["repeat_self"], s2r["new"]) == (1, 0, 4), s2r
    assert res["notice_step"] == 3, res["notice_step"]
    assert res["step_log"][2]["conflicting"] == 2, res["step_log"][2]
    assert (s4r["revokes"], res["wrong_revokes"]) == (4, 1), (s4r["revokes"], res["wrong_revokes"])
    assert res["step_log"][3]["unsupported"] >= 4  # dep fact, its conclusion, the NEG claim and the use fact of s1 lost their support
    assert s5r["repair"] == 1 and s5r["new"] == 2 and s5r["rejected"] == 1 and s5r["unsent"] == 1 and s5r["reject_codes"] == ["EVIDENCE_REVOKED"], s5r
    return res
