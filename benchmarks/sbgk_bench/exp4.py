"""EXP-4: DRed truth maintenance on diamond DAGs, rings (cycles) and random layered DAGs.

Every graph is a reachability program: `edge(u,v)` facts backed by quoted evidence and
`reach(n0,v)` claims derived with the rules R_seed / R_step. A claim reachable over several paths has several
justifications (alternative proofs). We revoke evidence and compare the kernel's statuses with an independent
Python reachability model, check incremental DRed against the kernel's from-scratch oracle, and measure time/memory.
"""

from __future__ import annotations

import json
import random
from collections import deque

from . import common as C

T = (0, 1000)


def pack_docs(sentences: list[str], rng: random.Random, per_doc: int = 450) -> tuple[dict[str, bytes], list[str]]:
    docs, doc_of = {}, []
    for j in range(0, len(sentences), per_doc):
        chunk = sentences[j:j + per_doc]
        paras = []
        for k in range(0, len(chunk), 4):
            paras.append(" ".join(chunk[k:k + 4] + [C.filler_sentence(rng)]))
        name = f"net_{j // per_doc:03d}"
        docs[name] = C.join_doc(paras)
        doc_of += [name] * len(chunk)
    return docs, doc_of


class Graph:
    def __init__(self, edges: list[tuple[str, str]], redundant: bool, rng: random.Random):
        self.edges = edges
        self.redundant = redundant
        self.nodes = sorted({x for e in edges for x in e} | {"n0"})
        self.n_ev = 2 if redundant else 1
        sents = []
        for i, (u, v) in enumerate(edges):
            sents.append(f"Link L{i}: node {u} connects to node {v} in production.")
            if redundant:
                sents.append(f"Record R{i}: the {u} to {v} link is confirmed by the audit log.")
        self.docs, doc_of = pack_docs(sents, rng)
        self.sents, self.doc_of = sents, doc_of
        self.onto = C.ontology_graph(self.nodes)
        self.ops = self._build_ops()

    def ev_local(self, i: int, which: int) -> str:
        return f"e{i}" if which == 0 else f"e{i}b"

    def _build_ops(self):
        ops = []
        for i, (u, v) in enumerate(self.edges):
            evs = []
            for w in range(self.n_ev):
                idx = i * self.n_ev + w
                ops.append(C.L_bind(self.ev_local(i, w), self.doc_of[idx], self.sents[idx]))
                evs.append(self.ev_local(i, w))
            ops.append(C.L_assert(f"f{i}", u, "edge", v, T, evs))
        out = {}
        for i, (u, v) in enumerate(self.edges):
            out.setdefault(u, []).append(i)
        first = {}
        q = deque(["n0"])
        seen = {"n0"}
        while q:
            u = q.popleft()
            for i in out.get(u, []):
                v = self.edges[i][1]
                name = f"r_{v}" if v not in first else f"r_{v}_{i}"
                if u == "n0":
                    ops.append(C.L_derive(name, "R_seed@1", [f"f{i}"], C.claim_of("n0", "reach", v, T)))
                else:
                    ops.append(C.L_derive(name, "R_step@1", [first[u], f"f{i}"], C.claim_of("n0", "reach", v, T)))
                if v not in first:
                    first[v] = name
                if v not in seen:
                    seen.add(v)
                    q.append(v)
        self.reached = seen - {"n0"}
        return ops

    def expected(self, revoked: set[tuple[int, int]]) -> dict[tuple[str, str, str], str]:
        alive = [any((i, w) not in revoked for w in range(self.n_ev)) for i in range(len(self.edges))]
        out = {}
        adj = {}
        for i, (u, v) in enumerate(self.edges):
            out[(u, "edge", v)] = "SUPPORTED" if alive[i] else "UNSUPPORTED"
            if alive[i]:
                adj.setdefault(u, []).append(v)
        reach, q = set(), deque(["n0"])
        seen = {"n0"}
        while q:
            u = q.popleft()
            for v in adj.get(u, []):
                if v not in seen:
                    seen.add(v)
                    q.append(v)
        for v in self.reached:
            out[("n0", "reach", v)] = "SUPPORTED" if v in seen else "UNSUPPORTED"
        return out


def diamond(d: int) -> list[tuple[str, str]]:
    e = []
    prev = "n0"
    for k in range(1, d + 1):
        a, b, n = f"a{k}", f"b{k}", f"m{k}"
        e += [(prev, a), (prev, b), (a, n), (b, n)]
        prev = n
    return e


def ring(m: int, alt_entry: int | None) -> list[tuple[str, str]]:
    e = [("n0", "c1")] + [(f"c{i}", f"c{i + 1}") for i in range(1, m)] + [(f"c{m}", "c1")]
    if alt_entry:
        e.append(("n0", f"c{alt_entry}"))
    return e


def layered(rng: random.Random, layers: int, width: int, indeg: int = 2) -> list[tuple[str, str]]:
    e = [("n0", f"v0_{w}") for w in range(width)]
    for l in range(1, layers):
        for w in range(width):
            for p in rng.sample(range(width), min(indeg, width)):
                e.append((f"v{l - 1}_{p}", f"v{l}_{w}"))
    return e


def run_scenario(name: str, g: Graph, revoked: set[tuple[int, int]], wd, diff_check: bool = False) -> dict:
    sd = wd / name
    docdir = sd / "docs"
    C.write_docs(docdir, g.docs)
    (sd / "ontology.json").write_text(json.dumps(g.onto), encoding="utf-8")
    base_stream = sd / "base.jsonl"
    C.write_lines(base_stream, C.jsonl(C.numbered(g.ops)))
    base_out = sd / "base.sbgk"
    base = C.cli("apply", "--ontology", sd / "ontology.json", "--docs", docdir, "--stream", base_stream,
                 *(["--out", base_out] if diff_check else []))
    assert base["error"] is None, base["error"]

    ops = list(g.ops) + [C.L_revoke(g.ev_local(i, w)) for (i, w) in sorted(revoked)]
    stream = sd / "full.jsonl"
    C.write_lines(stream, C.jsonl(C.numbered(ops)))
    out = sd / "final.sbgk"
    rep = C.cli("apply", "--ontology", sd / "ontology.json", "--docs", docdir, "--stream", stream,
                "--timings", "--oracle", "--out", out)
    assert rep["error"] is None, rep["error"]
    rev = [o for o in rep["ops"] if o["op"] == "revoke_evidence"]
    claims = C.cli("dump-claims", out)
    got = {(c["s"], c["p"], c["o"]): c["status"] for c in claims}
    want = g.expected(revoked)
    mismatches = [k for k in want if got.get(k) != want[k]]
    extra = [k for k in got if k not in want]
    over = sum(o["dred"]["over_deleted"] for o in rev)
    red = sum(o["dred"]["rederived"] for o in rev)
    net = sum(o["dred"]["net_removed"] for o in rev)
    n_claims = len(want)
    ingest = [o for o in rep["ops"] if o["op"] != "revoke_evidence"]
    slow = [o for o in ingest if o["ns"] > 1_000_000]
    diff = None
    if diff_check:
        d = C.cli("diff", base_out, out, "--reps", 300)
        na = {x["id"]: x["status"] for x in C.cli("dump-nodes", base_out)}
        nb = {x["id"]: x["status"] for x in C.cli("dump-nodes", out)}
        truth = {}
        for nid in na.keys() | nb.keys():
            if nid not in nb:
                truth[nid] = "only_in_a"
            elif nid not in na:
                truth[nid] = "only_in_b"
            elif na[nid] != nb[nid]:
                truth[nid] = "status"
        got = {e["id"]: e["change"] for e in d["entries"]}
        diff = {"nodes": len(nb), "differing_nodes": len(truth), "exact": got == truth,
                "buckets_differing": d["buckets_differing"], "leaves_scanned": d["leaves_scanned"],
                "us_p50": d["timing_us"]["p50"], "us_p99": d["timing_us"]["p99"]}
    return {
        "scenario": name, "edges": len(g.edges), "claims": n_claims, "nodes": rep["nodes"], "revokes": len(rev),
        "supported_after": sum(1 for v in want.values() if v == "SUPPORTED"),
        "unsupported_after": sum(1 for v in want.values() if v != "SUPPORTED"),
        "mismatches": len(mismatches), "unexpected_claims": len(extra), "oracle_ok": rep["oracle_ok"],
        "correct": not mismatches and not extra and rep["oracle_ok"],
        "dred_total_us": sum(o["ns"] for o in rev) / 1e3,
        "dred_max_us": max((o["ns"] for o in rev), default=0) / 1e3,
        "over_deleted": over, "rederived": red, "net_removed": net,
        "peak_delta_kib_max": max((o["peak_delta_bytes"] for o in rev), default=0) / 1024,
        "peak_alloc_mib": rep["peak_alloc_bytes"] / 2**20,
        "container_kib": rep.get("container_bytes", 0) / 1024,
        "build_ms": base["total_ms"],
        "ingest_p99_us": rep["latency_us"]["p99"],
        "ingest_max_us": rep["latency_us"]["max"],
        "ingest_ops": len(ingest), "ingest_over_1ms": len(slow), "ingest_slow_seq": [o["seq"] for o in slow][:12],
        "diff_vs_before": diff,
    }


def run(quick: bool = False) -> dict:
    rng = random.Random(4004)
    wd = C.workdir("exp4")
    rows = []
    depths = [4, 8, 16] if quick else [4, 8, 16, 32, 64, 128]
    for d in depths:
        for redundant in (False, True):
            g = Graph(diamond(d), redundant, rng)
            ia = [i for i, (u, v) in enumerate(g.edges) if (u, v) == ("n0", "a1")][0]
            ib = [i for i, (u, v) in enumerate(g.edges) if (u, v) == ("n0", "b1")][0]
            tag = "red" if redundant else "single"
            if not redundant:
                rows.append({"family": "diamond", "depth": d, "variant": "one_branch_cut", **run_scenario(f"dia{d}_{tag}_one", g, {(ia, 0)}, wd)})
                rows.append({"family": "diamond", "depth": d, "variant": "both_branches_cut", **run_scenario(f"dia{d}_{tag}_both", g, {(ia, 0), (ib, 0)}, wd)})
                k = max(1, d // 2)
                cut = {(i, 0) for i, (u, v) in enumerate(g.edges) if v == f"m{k}"}
                rows.append({"family": "diamond", "depth": d, "variant": "mid_cut", **run_scenario(f"dia{d}_{tag}_mid", g, cut, wd)})
            else:
                rows.append({"family": "diamond", "depth": d, "variant": "backup_evidence_one_lost",
                             **run_scenario(f"dia{d}_{tag}_lose1", g, {(ia, 0), (ib, 0)}, wd)})
                rows.append({"family": "diamond", "depth": d, "variant": "backup_evidence_all_lost",
                             **run_scenario(f"dia{d}_{tag}_loseall", g, {(ia, 0), (ib, 0), (ia, 1), (ib, 1)}, wd)})
    for m in ([4, 16] if quick else [4, 16, 64]):
        g = Graph(ring(m, None), False, rng)
        rows.append({"family": "ring", "depth": m, "variant": "cut_only_entry", **run_scenario(f"ring{m}_cut", g, {(0, 0)}, wd)})
        g2 = Graph(ring(m, max(2, m // 2)), False, rng)
        rows.append({"family": "ring", "depth": m, "variant": "cut_one_of_two_entries", **run_scenario(f"ring{m}_alt", g2, {(0, 0)}, wd)})
        rows.append({"family": "ring", "depth": m, "variant": "cut_both_entries",
                     **run_scenario(f"ring{m}_alt_both", g2, {(0, 0), (len(g2.edges) - 1, 0)}, wd)})
    sizes = [(6, 6), (12, 12)] if quick else [(8, 8), (16, 16), (24, 32), (32, 64), (48, 100), (64, 150)]
    for (L, W) in sizes:
        g = Graph(layered(rng, L, W), False, rng)
        idx = list(range(len(g.edges)))
        for label, k in (("random_1", 1), ("random_10", 10), ("random_5pct", max(1, len(g.edges) // 20))):
            pick = {(i, 0) for i in rng.sample(idx, k)}
            rows.append({"family": "layered", "depth": L * W, "variant": label,
                         **run_scenario(f"lay{L}x{W}_{label}", g, pick, wd, diff_check=(label == "random_1"))})

    fam = {}
    for f in ("diamond", "ring", "layered"):
        rs = [r for r in rows if r["family"] == f]
        fam[f] = {"scenarios": len(rs), "correct": sum(r["correct"] for r in rs),
                  "max_dred_us": max(r["dred_max_us"] for r in rs), "max_peak_delta_kib": max(r["peak_delta_kib_max"] for r in rs),
                  "max_nodes": max(r["nodes"] for r in rs)}
    diffs = [r["diff_vs_before"] for r in rows if r.get("diff_vs_before")]
    return {
        "setup": {"scenarios": len(rows), "families": fam,
                  "max_ingest_p99_us": max(r["ingest_p99_us"] for r in rows),
                  "max_ingest_max_us": max(r["ingest_max_us"] for r in rows),
                  "diff_at_scale": diffs},
        "rows": rows,
        "pass": {
            "all_statuses_match_independent_model": all(not r["mismatches"] and not r["unexpected_claims"] for r in rows),
            "dred_equals_batch_oracle": all(r["oracle_ok"] for r in rows),
            "merkle_diff_exact_at_scale": all(d["exact"] for d in diffs),
            "line_validation_p99_under_1ms": max(r["ingest_p99_us"] for r in rows) < 1000.0,
            "backup_evidence_keeps_everything_supported": all(
                r["unsupported_after"] == 0 for r in rows if r["variant"] == "backup_evidence_one_lost"),
            "alternative_entry_keeps_cycle_alive": all(
                r["unsupported_after"] == 1 for r in rows if r["variant"] == "cut_one_of_two_entries"),
            "sole_support_cascades_without_phantom_loops": all(
                r["supported_after"] == r["edges"] - (1 if r["variant"] == "cut_only_entry" else 0) - (2 if r["variant"] == "both_branches_cut" else 0)
                for r in rows if r["variant"] in ("cut_only_entry", "both_branches_cut")),
        },
    }
