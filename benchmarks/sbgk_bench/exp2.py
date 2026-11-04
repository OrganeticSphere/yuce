"""EXP-2: agent-noise eradication and permutation invariance.

50 pairs of semantically equivalent JSONL streams produced by two simulated agents that differ in
operation order (random topological order), local ids, key order, whitespace, alias spelling,
array order, redundant duplicate lines and omitted derive claims. After the kernel the node table,
offset index and state_merkle_root must match bit for bit. A second set of 50 pairs differs by exactly
one semantic mutation; `merkle_diff` must return exactly the symmetric difference of the node sets.
"""

from __future__ import annotations

import copy
import json
import random
import string

from . import common as C


class Spec:
    def __init__(self, rng: random.Random, n_pairs: int, n_extra: int, with_conflict: bool, n_revokes: int):
        self.n_pairs = n_pairs
        self.onto = C.ontology_review(n_pairs + n_extra + 2, n_pairs + n_extra + 2)
        self.facts: dict[str, dict] = {}   # key -> fact dict
        self.derived: dict[str, dict] = {}
        self.sentences: dict[str, str] = {}
        self.spare = []  # unused sentences for mutations
        for i in range(n_pairs):
            su = f"Clause {i + 1}.1: service svc_{i:03d} shall call interface api_{i:03d} in production environments."
            sd = f"Clause {i + 1}.2: interface api_{i:03d} is deprecated effective the first quarter."
            self.facts[f"u{i}"] = dict(s=f"svc_{i:03d}", p="uses_api", o=f"api_{i:03d}", t=(100, 200), pol="POS", quote=su)
            self.facts[f"d{i}"] = dict(s=f"api_{i:03d}", p="api_deprecated", o="true", t=(150, 300), pol="POS", quote=sd)
            self.derived[f"r{i}"] = dict(rule="R_depr_review@1", prem=[f"u{i}", f"d{i}"])
        for j in range(n_extra):
            i = n_pairs + j
            self.facts[f"x{j}"] = dict(s=f"svc_{i:03d}", p="uses_api", o=f"api_{i:03d}", t=(100 + j, 220),
                                       pol="POS", quote=f"Clause X.{j}: service svc_{i:03d} shall call interface api_{i:03d} in staging.")
        self.conflicts: list[tuple[str, str]] = []  # (neg fact key, derive key it must follow)
        if with_conflict and n_pairs:
            c = rng.randrange(n_pairs)
            self.facts["n0"] = dict(s=f"api_{c:03d}", p="api_deprecated", o="true", t=(200, 260), pol="NEG",
                                    quote=f"Clause N.0: interface api_{c:03d} was never deprecated in production.")
            self.conflicts.append(("n0", f"r{c}"))
        k = n_pairs + n_extra
        self.spare = [
            f"Clause S.1: service svc_{k:03d} shall call interface api_{k:03d} in production environments.",
            f"Clause S.2: service svc_{k + 1:03d} shall call interface api_{k + 1:03d} in production environments.",
        ]
        self.revokes = rng.sample(sorted(self.facts), min(n_revokes, len(self.facts)))
        # documents
        keys = sorted(self.facts)
        rng.shuffle(keys)
        half = len(keys) // 2
        self.doc_of = {key: ("doc_a" if idx < half else "doc_b") for idx, key in enumerate(keys)}
        self.docs = {}
        for d in ("doc_a", "doc_b"):
            sents = [self.facts[key]["quote"] for key in keys if self.doc_of[key] == d]
            if d == "doc_a":
                sents += self.spare
            paras = C.make_doc(rng, max(9000, len(sents) * 700), sents)
            self.docs[d] = C.join_doc(paras)
        self.spare_doc = "doc_a"

    # -------- semantics mirror (kept independent of the Rust kernel on purpose)
    def derived_claim(self, key: str) -> dict:
        d = self.derived[key]
        u, dd = self.facts[d["prem"][0]], self.facts[d["prem"][1]]
        return C.claim_of(u["s"], "needs_review", "true", C.intersect(u["t"], dd["t"]))


def mutate(spec: Spec, kind: str, rng: random.Random) -> Spec:
    m = copy.deepcopy(spec)
    if kind == "add_fact":
        k = m.n_pairs + len([x for x in m.facts if x.startswith("x")])
        m.facts["z0"] = dict(s=f"svc_{k:03d}", p="uses_api", o=f"api_{k:03d}", t=(100, 200), pol="POS", quote=m.spare[0])
        m.doc_of["z0"] = m.spare_doc
    elif kind == "change_time":
        i = rng.randrange(m.n_pairs)
        m.facts[f"u{i}"]["t"] = (100, 180)
    elif kind == "swap_evidence":
        i = rng.randrange(m.n_pairs)
        m.facts[f"u{i}"]["quote"] = m.spare[1]
        m.doc_of[f"u{i}"] = m.spare_doc
    elif kind == "extra_revoke":
        pool = [k for k in m.facts if k not in m.revokes and not k.startswith("n")]
        m.revokes = list(m.revokes) + [rng.choice(pool)]
    else:
        raise ValueError(kind)
    return m


def rand_name(rng: random.Random, style: str, prefix: str, i: int) -> str:
    if style == "seq":
        return f"{prefix}_{i}"
    return prefix + "".join(rng.choices(string.ascii_lowercase, k=7))


def alias_of(rng: random.Random, ent: str, p_alias: float) -> str:
    if ent.startswith(("svc_", "api_")) and rng.random() < p_alias:
        kind, idx = ent.split("_")
        return ("service " if kind == "svc" else "interface ") + str(int(idx))
    return ent


def render(spec: Spec, rng: random.Random, style: str, noisy: bool) -> list[str]:
    """Emit a valid stream for `spec` in a random topological order with agent-specific noise."""
    names = {}
    ev_name, fa_name, de_name = {}, {}, {}
    for i, k in enumerate(sorted(spec.facts)):
        ev_name[k] = rand_name(rng, style, "e", i)
        fa_name[k] = rand_name(rng, style, "f", i)
    for i, k in enumerate(sorted(spec.derived)):
        de_name[k] = rand_name(rng, style, "d", i)

    # dependency graph over abstract items
    deps: dict[tuple, set] = {}
    for k in spec.facts:
        deps[("bind", k)] = set()
        deps[("assert", k)] = {("bind", k)}
    for k, d in spec.derived.items():
        deps[("derive", k)] = {("assert", p) for p in d["prem"]}
    for neg, after in spec.conflicts:
        deps[("assert", neg)] |= {("derive", after)}
    for k in spec.revokes:
        deps[("revoke", k)] = {("assert", k)} | {("derive", d) for d in spec.derived}
    # a fact flagged for revocation must not be a premise of a derive issued later: all derives precede revokes (above)

    done: set = set()
    pending = dict(deps)
    order = []
    while pending:
        ready = sorted(it for it, dd in pending.items() if dd <= done)
        it = rng.choice(ready) if noisy else ready[0]
        order.append(it)
        done.add(it)
        del pending[it]

    ops = []
    for kind, k in order:
        if kind == "bind":
            f = spec.facts[k]
            ops.append(C.L_bind(ev_name[k], spec.doc_of[k], f["quote"]))
        elif kind == "assert":
            f = spec.facts[k]
            op = C.L_assert(fa_name[k], alias_of(rng, f["s"], 0.3 if noisy else 0), f["p"],
                            alias_of(rng, f["o"], 0.3 if noisy else 0), f["t"], [ev_name[k]], pol=f["pol"])
            ops.append(op)
            if noisy and rng.random() < 0.12:  # redundant duplicate assertion under a new local name
                dup = dict(op)
                dup["local_id"] = rand_name(rng, "rand", "dup", 0)
                ops.append(dup)
        elif kind == "derive":
            d = spec.derived[k]
            prem = [fa_name[p] for p in d["prem"]]
            if noisy:
                rng.shuffle(prem)
            claim = spec.derived_claim(k)
            ops.append(C.L_derive(de_name[k], d["rule"], prem, None if (noisy and rng.random() < 0.4) else claim))
        else:
            ops.append(C.L_revoke(ev_name[k]))

    lines = []
    for seq, op in enumerate(ops, 1):
        o = {"seq": seq}
        o.update(op)
        if noisy:
            for field in ("premises", "evidence"):
                if field in o and isinstance(o[field], list):
                    rng.shuffle(o[field])
            items = list(o.items())
            rng.shuffle(items)
            o = dict(items)
            sep = rng.choice([(",", ":"), (", ", ": "), (" , ", " : "), (",  ", ":  ")])
            line = json.dumps(o, separators=sep, ensure_ascii=rng.random() < 0.5)
            line = " " * rng.randint(0, 3) + line + " " * rng.randint(0, 3)
        else:
            line = json.dumps(o, separators=(",", ":"))
        lines.append(line)
    return lines


def run_stream(wd, tag, spec: Spec, lines):
    docdir = wd / f"{tag}_docs"
    C.write_docs(docdir, spec.docs)
    onto = wd / "ontology.json"
    onto.write_text(json.dumps(spec.onto), encoding="utf-8")
    stream = wd / f"{tag}.jsonl"
    C.write_lines(stream, lines)
    out = wd / f"{tag}.sbgk"
    rep = C.cli("apply", "--ontology", onto, "--docs", docdir, "--stream", stream, "--out", out)
    if rep["error"] is not None:
        raise AssertionError(f"{tag}: kernel rejected a generated stream: {rep['error']}")
    return out, rep


def run(quick: bool = False) -> dict:
    n_pairs_total = 10 if quick else 50
    wd = C.workdir("exp2")
    rng = random.Random(2002)
    identical = 0
    rows = []
    wal_differs = 0
    noise_bytes_ratio = []
    for i in range(n_pairs_total):
        spec = Spec(rng, rng.randint(8, 22), rng.randint(2, 8), with_conflict=(i % 3 == 0), n_revokes=rng.randint(2, 5))
        la = render(spec, random.Random(rng.random()), "seq", noisy=False)
        lb = render(spec, random.Random(rng.random()), "rand", noisy=True)
        oa, ra = run_stream(wd, "a", spec, la)
        ob, rb = run_stream(wd, "b", spec, lb)
        ta, tb = C.cli("node-table", oa), C.cli("node-table", ob)
        same = (ta["table_sha256"] == tb["table_sha256"] and ta["index_sha256"] == tb["index_sha256"]
                and ta["root"] == tb["root"])
        identical += same
        wal_differs += oa.read_bytes() != ob.read_bytes()
        noise_bytes_ratio.append(sum(map(len, lb)) / sum(map(len, la)))
        rows.append({"pair": i, "identical": same, "lines_a": len(la), "lines_b": len(lb),
                     "nodes": ra["nodes"], "conflicting_claims": ra["claims"]["conflicting"],
                     "root_a": ta["root"][:16], "root_b": tb["root"][:16]})

    # ---- one semantic mutation => exact diff
    diff_rows = []
    kinds = ["add_fact", "change_time", "swap_evidence", "extra_revoke"]
    times_p50, times_max = [], []
    for i in range(n_pairs_total):
        spec = Spec(rng, rng.randint(8, 22), rng.randint(2, 8), with_conflict=(i % 3 == 0), n_revokes=rng.randint(2, 5))
        kind = kinds[i % len(kinds)]
        mut = mutate(spec, kind, rng)
        oa, _ = run_stream(wd, "ma", spec, render(spec, random.Random(rng.random()), "seq", noisy=True))
        ob, _ = run_stream(wd, "mb", mut, render(mut, random.Random(rng.random()), "rand", noisy=True))
        d = C.cli("diff", oa, ob, "--reps", 2000)
        na = {x["id"]: x["status"] for x in C.cli("dump-nodes", oa)}
        nb = {x["id"]: x["status"] for x in C.cli("dump-nodes", ob)}
        truth = {}
        for nid in na.keys() | nb.keys():
            if nid in na and nid not in nb:
                truth[nid] = "only_in_a"
            elif nid in nb and nid not in na:
                truth[nid] = "only_in_b"
            elif na[nid] != nb[nid]:
                truth[nid] = "status"
        got = {e["id"]: e["change"] for e in d["entries"]}
        exact = got == truth
        diff_rows.append({"mutation": kind, "exact": exact, "truth_size": len(truth), "nodes": len(na),
                          "buckets_differing": d["buckets_differing"], "leaves_scanned": d["leaves_scanned"],
                          "diff_us_p50": d["timing_us"]["p50"], "diff_us_max": d["timing_us"]["max"],
                          "diff_us_p99": d["timing_us"]["p99"]})
        times_p50.append(d["timing_us"]["p50"])
        times_max.append(d["timing_us"]["p99"])
    by_kind = {}
    for k in kinds:
        rs = [r for r in diff_rows if r["mutation"] == k]
        by_kind[k] = {"cases": len(rs), "exact": sum(r["exact"] for r in rs),
                      "mean_nodes_differing": sum(r["truth_size"] for r in rs) / len(rs)}
    return {
        "setup": {"pairs": n_pairs_total, "mutation_pairs": n_pairs_total,
                  "mean_lines": sum(r["lines_a"] for r in rows) / len(rows),
                  "mean_nodes": sum(r["nodes"] for r in rows) / len(rows),
                  "pairs_with_conflicts": sum(r["conflicting_claims"] > 0 for r in rows),
                  "mean_noisy_stream_bytes_ratio": sum(noise_bytes_ratio) / len(noise_bytes_ratio),
                  "containers_with_different_wal": wal_differs},
        "identity": {"pairs": n_pairs_total, "byte_identical": identical, "rate": identical / n_pairs_total},
        "diff": {
            "cases": len(diff_rows), "exact": sum(r["exact"] for r in diff_rows),
            "by_mutation": by_kind,
            "median_us_p50": C.pct(times_p50, 0.5), "worst_us_p50": max(times_p50),
            "worst_us_p99": max(times_max),
            "mean_buckets_differing": sum(r["buckets_differing"] for r in diff_rows) / len(diff_rows),
            "mean_leaves_scanned": sum(r["leaves_scanned"] for r in diff_rows) / len(diff_rows),
            "mean_nodes": sum(r["nodes"] for r in diff_rows) / len(diff_rows),
        },
        "rows": rows, "diff_rows": diff_rows,
        "pass": {
            "bit_identical_100pct": identical == n_pairs_total,
            "diff_exact_100pct": all(r["exact"] for r in diff_rows),
            "diff_under_0_1ms": max(times_max) < 100.0,
            "noise_was_real": wal_differs == n_pairs_total,
        },
    }
