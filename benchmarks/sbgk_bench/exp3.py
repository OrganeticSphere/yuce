"""EXP-3: streaming JSONL fail-fast vs monolithic JSON repair.

30 multi-step tasks (12-15 lines) with one injected agent error each (non-existent quote, wrong interval
intersection, ambiguous alias, unsupported premise). The agent is *scripted*: it emits the faulty line,
then applies the kernel's feedback mechanically (documented policy below). This measures protocol cost and
the sufficiency of the kernel's feedback -- it does not measure LLM competence.

Arms
  A1  monolithic JSON graph, generic validator error (code + path), full regeneration per repair round
  A2  monolithic JSON graph, structured error, JSON-patch repair (faulty line + its propagated dependents)
  B   streaming JSONL into `sbgk serve`, stop at the failing seq, re-send only that line
"""

from __future__ import annotations

import json
import random
import subprocess

from . import common as C

LINE_WRAP = 2          # ", " between lines of a monolithic array
DOC_WRAP = 24          # {"graph":[ ... ]}
PATCH_OVERHEAD = 44    # {"op":"replace","path":"/graph/12","value": ... }
TYPES = ["quote", "interval", "alias", "premise"]
EXPECTED_CODE = {"quote": "QUOTE_NOT_FOUND_IN_BYTES", "interval": "INTERVAL_MISMATCH",
                 "alias": "AMBIGUOUS_ENTITY", "premise": "PREMISE_UNSUPPORTED"}
EXPECTED_K = {"quote": 4, "interval": 3, "alias": 5, "premise": 6}


def onto(n_nodes: int) -> dict:
    o = C.ontology_graph([f"n{i}" for i in range(n_nodes)])
    for e in o["entities"]:
        if e["id"] in ("n1", "n2"):
            e["aliases"] = ["gateway"]
    return o


class Task:
    def __init__(self, idx: int, kind: str, rng: random.Random):
        self.idx, self.kind = idx, kind
        L = {"quote": (4, 5), "interval": (4, 5), "alias": (4, 5), "premise": (3, 4)}[kind][(idx // 4) % 2]
        self.L = L
        self.onto = onto(L + 2)
        # interval of every edge fact; chain derivations intersect them
        self.T = [(100 + 3 * i, 400 + 10 * i) for i in range(L)]
        self.quotes = [f"Link L{i}: node n{i} connects to node n{i + 1} in production." for i in range(L)]
        twin = f"Link L0b: node n0 connects to node n1 in the disaster recovery site."
        paras = C.make_doc(rng, 3500, self.quotes + ([twin] if kind == "premise" else []), reserve_front=2, reserve_back=1)
        self.doc = C.join_doc(paras)
        self.twin_quote = twin
        self.gold, self.err = self._build()

    def _build(self):
        k, L, T = self.kind, self.L, self.T
        gold, err = [], []

        def claim(i, t):
            return C.claim_of("n0", "reach", f"n{i + 1}", t)

        if k == "premise":
            T_b = (100, 360)
            prelude_gold = [
                C.L_bind("e_a", "doc", self.quotes[0]),
                C.L_assert("f_a", "n0", "edge", "n1", T[0], ["e_a"]),
                C.L_bind("e_b", "doc", self.twin_quote),
                C.L_assert("f_b", "n0", "edge", "n1", T_b, ["e_b"]),
                C.L_revoke("e_a"),
            ]
            t_gold = [T_b]
            t_err = [T[0]]
            prem_gold, prem_err = ["f_b"], ["f_a"]
            gold += prelude_gold
            err += copy_ops(prelude_gold)
            gold.append(C.L_derive("r0", "R_seed@1", prem_gold, claim(0, T_b)))
            err.append(C.L_derive("r0", "R_seed@1", prem_err, claim(0, T[0])))
        else:
            first = [C.L_bind("e0", "doc", self.quotes[0]), C.L_assert("f0", "n0", "edge", "n1", T[0], ["e0"])]
            gold += first
            err += copy_ops(first)
            t_gold, t_err = [T[0]], [T[0]]
            gold.append(C.L_derive("r0", "R_seed@1", ["f0"], claim(0, T[0])))
            wrong = (T[0][0], T[0][1] + 40)
            err.append(C.L_derive("r0", "R_seed@1", ["f0"], claim(0, wrong if k == "interval" else T[0])))
            if k == "interval":
                t_err = [wrong]
        start_edge = 1
        for i in range(start_edge, L):
            q = self.quotes[i]
            b = C.L_bind(f"e{i}", "doc", q)
            s_gold = "n%d" % i
            a_gold = C.L_assert(f"f{i}", s_gold, "edge", f"n{i + 1}", T[i], [f"e{i}"])
            tg = C.intersect(t_gold[-1], T[i])
            te = C.intersect(t_err[-1], T[i])
            d_gold = C.L_derive(f"r{i}", "R_step@1", [f"r{i - 1}", f"f{i}"], claim(i, tg))
            d_err = C.L_derive(f"r{i}", "R_step@1", [f"r{i - 1}", f"f{i}"], claim(i, te))
            t_gold.append(tg)
            t_err.append(te)
            a_err = dict(a_gold)
            b_err = dict(b)
            if k == "quote" and i == 1:
                b_err = C.L_bind(f"e{i}", "doc", corrupt_quote(q, self.idx))
            if k == "alias" and i == 1:
                a_err = dict(a_gold)
                a_err["s"] = "gateway"
            gold += [b, a_gold, d_gold]
            err += [b_err, a_err, d_err]
        return C.numbered(gold), C.numbered(err)


def copy_ops(ops):
    return [dict(o) for o in ops]


def corrupt_quote(q: str, idx: int) -> str:
    variants = [
        lambda s: s.replace("connects to", "links up with"),
        lambda s: s.replace("in production", "in production environments"),
        lambda s: s.replace("node n", "nodes n", 1),
        lambda s: s.replace("Link", "Connection"),
    ]
    out = variants[idx % len(variants)](q)
    assert out != q
    return out


def line_bytes(op: dict) -> int:
    return len(json.dumps(op, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) + 1


def stream_bytes(ops) -> int:
    return sum(line_bytes(o) for o in ops)


def mono_bytes(ops) -> int:
    return stream_bytes(ops) - len(ops) + LINE_WRAP * len(ops) + DOC_WRAP


def is_ok(resp: dict) -> bool:
    return "ok" in resp or resp.get("status") == "ok"


class Serve:
    def __init__(self, ontology_path, docdir):
        self.p = subprocess.Popen([str(C.BIN), "serve", "--ontology", str(ontology_path), "--docs", str(docdir)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8", bufsize=1)
        self.sent = 0
        self.received = 0

    def send(self, obj: dict) -> dict:
        line = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        if obj.get("op") not in ("state", "finish"):
            self.sent += len(line.encode("utf-8")) + 1
        resp = self.p.stdout.readline()
        if obj.get("op") not in ("state", "finish"):
            self.received += len(resp.encode("utf-8"))
        return json.loads(resp)

    def close(self):
        try:
            self.p.stdin.close()
        finally:
            self.p.wait(timeout=10)


def repair(line: dict, err: dict, gold: dict) -> tuple[dict, dict]:
    """Mechanical repair from kernel feedback only. Where the feedback is a candidate list the scripted
    agent picks the candidate equal to its intended (gold) value if offered, else the first one."""
    new = json.loads(json.dumps(line))
    info = {}
    code = err["code"]
    exp = err.get("expected_by_kernel") or {}
    if code == "QUOTE_NOT_FOUND_IN_BYTES":
        cands = [c["exact_quote"] for c in exp["candidates"]]
        info = {"gold_in_candidates": gold["exact_quote"] in cands, "top1_is_gold": bool(cands) and cands[0] == gold["exact_quote"],
                "n_candidates": len(cands)}
        new["exact_quote"] = gold["exact_quote"] if gold["exact_quote"] in cands else cands[0]
    elif code == "INTERVAL_MISMATCH":
        new["claim"]["t"] = exp["t"]
        info = {"gold_in_candidates": exp["t"] == gold["claim"]["t"], "top1_is_gold": exp["t"] == gold["claim"]["t"]}
    elif code == "AMBIGUOUS_ENTITY":
        cands = exp["candidates"]
        want = gold[err["field"]]
        info = {"gold_in_candidates": want in cands, "top1_is_gold": bool(cands) and cands[0] == want, "n_candidates": len(cands)}
        new[err["field"]] = want if want in cands else cands[0]
    elif code == "PREMISE_UNSUPPORTED":
        names = [c["local_id"] for c in exp["candidates"]]
        bad = exp["premise"]
        want = [p for p in gold["premises"] if p not in line["premises"]]
        pick = want[0] if want and want[0] in names else (names[0] if names else None)
        info = {"gold_in_candidates": bool(want) and want[0] in names, "top1_is_gold": bool(names) and bool(want) and names[0] == want[0],
                "n_candidates": len(names)}
        if pick:
            new["premises"] = [pick if p == bad else p for p in new["premises"]]
    else:
        info = {"unhandled": code}
    return new, info


def run(quick: bool = False) -> dict:
    n_tasks = 8 if quick else 30
    rng = random.Random(3003)
    wd = C.workdir("exp3")
    kinds = [TYPES[i % 4] for i in range(n_tasks)]
    rows = []
    for idx, kind in enumerate(kinds):
        t = Task(idx, kind, rng)
        tdir = wd / f"t{idx:02d}"
        docdir = tdir / "docs"
        C.write_docs(docdir, {"doc": t.doc})
        op = tdir / "ontology.json"
        op.write_text(json.dumps(t.onto), encoding="utf-8")
        N = len(t.gold)
        k = next(i for i, (g, e) in enumerate(zip(t.gold, t.err), 1) if g != e)

        # ---- gold: control run (no false rejections) + reference root
        gs = tdir / "gold.jsonl"
        C.write_lines(gs, C.jsonl(t.gold))
        gold_rep = C.cli("apply", "--ontology", op, "--docs", docdir, "--stream", gs)
        control_clean = gold_rep["error"] is None and gold_rep["accepted"] == N
        pre = tdir / "prefix.jsonl"
        C.write_lines(pre, C.jsonl(t.gold[: k - 1]))
        prefix_root = C.cli("apply", "--ontology", op, "--docs", docdir, "--stream", pre)["state_root"]

        # ---- arm B: streaming with fail-fast + point repair
        sv = Serve(op, docdir)
        errors, repairs, rounds = [], [], 0
        acks = 0
        emitted_lines = 0
        emitted_bytes = 0
        detected_at = None
        prefix_ok = None
        for i, line in enumerate(t.err[:k], 1):
            emitted_lines += 1
            emitted_bytes += line_bytes(line)
            resp = sv.send(line)
            if is_ok(resp):
                acks += 1
                continue
            detected_at = resp["seq"]
            errors.append(resp)
            st = sv.send({"op": "state"})
            prefix_ok = st["state_root"] == prefix_root and st["last_seq"] == k - 1
            cur = line
            while not is_ok(resp) and rounds < 6:
                rounds += 1
                cur, info = repair(cur, resp, t.gold[k - 1])
                repairs.append({"code": resp["code"], **info})
                emitted_lines += 1
                emitted_bytes += line_bytes(cur)
                resp = sv.send(cur)
                if not is_ok(resp):
                    errors.append(resp)
            if is_ok(resp):
                acks += 1
        for line in t.gold[k:]:
            emitted_lines += 1
            emitted_bytes += line_bytes(line)
            resp = sv.send(line)
            acks += is_ok(resp)
        fin = sv.send({"op": "finish", "out": str(tdir / "final.sbgk")})
        sv.close()
        success = fin["state_root"] == gold_rep["state_root"]

        # ---- cost accounting
        first_err = errors[0] if errors else {}
        generic = {kk: first_err[kk] for kk in ("status", "seq", "code", "message") if kk in first_err}
        generic_bytes = len(json.dumps(generic).encode())
        struct_bytes = [len(json.dumps(e).encode()) for e in errors]
        diff_lines = [g for g, e in zip(t.gold, t.err) if g != e]
        a1_out = mono_bytes(t.err) + rounds * mono_bytes(t.gold)
        a1_in = rounds * generic_bytes
        a2_out = mono_bytes(t.err) + sum(line_bytes(g) + PATCH_OVERHEAD for g in diff_lines) + (rounds - 1) * (line_bytes(t.gold[k - 1]) + PATCH_OVERHEAD)
        a2_in = sum(struct_bytes)
        b_out = emitted_bytes
        b_in = sv.received
        rows.append({
            "task": idx, "type": kind, "lines": N, "injected_at": k, "detected_at": detected_at,
            "code": first_err.get("code"), "expected_code": EXPECTED_CODE[kind],
            "detected_ok": detected_at == k and first_err.get("code") == EXPECTED_CODE[kind],
            "prefix_preserved": bool(prefix_ok), "control_clean": control_clean,
            "rounds": rounds, "success": success,
            "repair_info": repairs,
            "cascade_lines": len(diff_lines) - 1,
            "A1": {"out": a1_out, "in": a1_in, "regen_lines": N * rounds},
            "A2": {"out": a2_out, "in": a2_in, "regen_lines": len(diff_lines) + rounds - 1},
            "B": {"out": b_out, "in": b_in, "regen_lines": rounds},
            "kernel_latency_us_p99": gold_rep["latency_us"]["p99"],
        })

    def arm(a):
        out = sum(r[a]["out"] for r in rows)
        inn = sum(r[a]["in"] for r in rows)
        return {"agent_output_bytes": out, "kernel_to_agent_bytes": inn, "total_bytes": out + inn,
                "total_tokens_est": C.tokens(out + inn), "output_tokens_est": C.tokens(out),
                "regenerated_lines": sum(r[a]["regen_lines"] for r in rows)}

    arms = {a: arm(a) for a in ("A1", "A2", "B")}
    for a in ("A1", "A2"):
        arms[a]["B_saves_total_pct"] = 100 * (1 - arms["B"]["total_bytes"] / arms[a]["total_bytes"])
        arms[a]["B_saves_output_pct"] = 100 * (1 - arms["B"]["agent_output_bytes"] / arms[a]["agent_output_bytes"])
    by_type = {}
    for ty in TYPES:
        rs = [r for r in rows if r["type"] == ty]
        if not rs:
            continue
        infos = [i for r in rs for i in r["repair_info"] if "gold_in_candidates" in i]
        by_type[ty] = {
            "tasks": len(rs), "detected_ok": sum(r["detected_ok"] for r in rs),
            "success": sum(r["success"] for r in rs), "mean_rounds": sum(r["rounds"] for r in rs) / len(rs),
            "gold_in_feedback": sum(i["gold_in_candidates"] for i in infos), "top1_is_gold": sum(i["top1_is_gold"] for i in infos),
            "feedback_items": len(infos), "injected_at": sorted({r["injected_at"] for r in rs}),
            "mean_cascade_lines": sum(r["cascade_lines"] for r in rs) / len(rs),
            "B_total_bytes": sum(r["B"]["out"] + r["B"]["in"] for r in rs),
            "A1_total_bytes": sum(r["A1"]["out"] + r["A1"]["in"] for r in rs),
        }
    return {
        "setup": {"tasks": len(rows), "lines_min": min(r["lines"] for r in rows), "lines_max": max(r["lines"] for r in rows),
                  "injected_steps": sorted({r["injected_at"] for r in rows}), "token_heuristic": "bytes/4"},
        "detection": {"detected_ok": sum(r["detected_ok"] for r in rows), "of": len(rows),
                      "prefix_preserved": sum(r["prefix_preserved"] for r in rows),
                      "clean_controls_without_false_reject": sum(r["control_clean"] for r in rows)},
        "repair": {"successful": sum(r["success"] for r in rows), "of": len(rows),
                   "mean_rounds": sum(r["rounds"] for r in rows) / len(rows)},
        "arms": arms, "by_type": by_type, "rows": rows,
        "pass": {
            "all_detected_at_injected_seq": all(r["detected_ok"] for r in rows),
            "all_prefixes_preserved": all(r["prefix_preserved"] for r in rows),
            "no_false_rejects": all(r["control_clean"] for r in rows),
            "all_repaired_to_gold_root": all(r["success"] for r in rows),
            "streaming_cheaper_than_regeneration": arms["B"]["total_bytes"] < arms["A1"]["total_bytes"],
        },
    }
