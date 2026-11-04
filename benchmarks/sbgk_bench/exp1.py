"""EXP-1: FastCDC byte-span resilience under document edits.

10 regulation-style documents (20-50 KB), 100 facts (+50 derived claims). Four edit scenarios per
document (insert/delete a paragraph at the start / in the middle). Compared:
  * naive anchors   (file_sha256, global_byte_offset)   -- strict and offset-only (lenient)
  * Source Arena    (chunk_hash, local_span) with DRed + automatic re-binding
"""

from __future__ import annotations

import json
import random

from . import common as C

SCENARIOS = ["insert_start", "delete_start", "insert_mid", "delete_mid"]


def build_corpus(rng: random.Random, n_docs: int, facts_per_doc: int):
    docs, stream, meta = {}, [], []
    onto = C.ontology_review(n_docs * facts_per_doc // 2 * 1, n_docs * facts_per_doc // 2 * 1)
    seq_ops = []
    for d in range(n_docs):
        pairs = facts_per_doc // 2
        sentences, rows = [], []
        for i in range(pairs):
            k = d * pairs + i
            su = f"Clause {d + 1}.{i + 1}.1: service svc_{k:03d} shall call interface api_{k:03d} in production environments."
            sd = f"Clause {d + 1}.{i + 1}.2: interface api_{k:03d} is deprecated effective the first quarter."
            sentences += [su, sd]
            rows.append((k, su, sd))
        paras = C.make_doc(rng, rng.randint(20_000, 50_000), sentences)
        doc_id = f"policy_{d:02d}"
        docs[doc_id] = paras
        for k, su, sd in rows:
            seq_ops += [
                C.L_bind(f"e_u{k}", doc_id, su),
                C.L_bind(f"e_d{k}", doc_id, sd),
                C.L_assert(f"f_u{k}", f"svc_{k:03d}", "uses_api", f"api_{k:03d}", (100, 200), [f"e_u{k}"]),
                C.L_assert(f"f_d{k}", f"api_{k:03d}", "api_deprecated", "true", (150, 300), [f"e_d{k}"]),
                C.L_derive(f"r{k}", "R_depr_review@1", [f"f_u{k}", f"f_d{k}"],
                           C.claim_of(f"svc_{k:03d}", "needs_review", "true", (150, 200))),
            ]
            meta.append({"doc": doc_id, "k": k, "su": su, "sd": sd})
    return onto, docs, C.numbered(seq_ops), meta


def edit(rng: random.Random, paras: list[str], fact_set: set[str], scenario: str) -> list[str]:
    p = list(paras)
    mid = len(p) // 2
    if scenario == "insert_start":
        p.insert(0, C.filler_paragraph(rng, 5, 7))
    elif scenario == "insert_mid":
        p.insert(mid, C.filler_paragraph(rng, 5, 7))
    elif scenario == "delete_start":
        del p[0]
    else:  # delete_mid: nearest non-fact paragraph to the middle
        for off in range(len(p)):
            for idx in (mid + off, mid - off):
                if 0 <= idx < len(p) and p[idx] not in fact_set:
                    del p[idx]
                    return p
    return p


def run_mode(mode: str, onto, docs, ops, meta, edits, n_facts, n_derived) -> dict:
    wd = C.workdir(f"exp1_{mode}")
    docdir = wd / "docs"
    C.write_docs(docdir, {k: C.join_doc(v) for k, v in docs.items()})
    (wd / "ontology.json").write_text(json.dumps(onto), encoding="utf-8")
    stream = wd / "stream.jsonl"
    C.write_lines(stream, C.jsonl(ops))
    base = wd / "base.sbgk"
    rep = C.cli("apply", "--ontology", wd / "ontology.json", "--docs", docdir, "--stream", stream,
                "--out", base, "--oracle", "--cdc-mode", mode)
    assert rep["error"] is None and rep["accepted"] == len(ops), rep["error"]

    rows = []
    for doc_id, paras in docs.items():
        orig = C.join_doc(paras)
        mine = [m for m in meta if m["doc"] == doc_id]
        quotes = [(m["k"], "u", m["su"].encode()) for m in mine] + [(m["k"], "d", m["sd"].encode()) for m in mine]
        anchors = {(k, kind): (orig.find(q), orig.find(q) + len(q), q) for k, kind, q in quotes}
        for sc in SCENARIOS:
            new = edits[(doc_id, sc)]
            f = wd / f"{doc_id}.{sc}.txt"
            f.write_bytes(new)
            r = C.cli("update-doc", base, "--doc-id", doc_id, "--file", f)
            lenient_ok = {key for key, (s, e, q) in anchors.items() if new[s:e] == q}
            strict_ok = set() if C.sha256_hex(new) != C.sha256_hex(orig) else set(anchors)
            broken_lenient = set(anchors) - lenient_ok
            derived_hit_lenient = {k for (k, _) in broken_lenient}
            ev_total = len(anchors)
            rows.append({
                "doc": doc_id, "scenario": sc, "doc_bytes": len(orig),
                "chunks_before": r["chunks_before"], "chunks_after": r["chunks_total"], "chunks_reused": r["chunks_reused"],
                "chunk_preservation": min(1.0, r["chunks_reused"] / max(1, r["chunks_before"])),
                "evidence_total": ev_total,
                "cdc_survived": ev_total - r["evidence_stale"],
                "naive_strict_survived": len(strict_ok),
                "naive_lenient_survived": len(lenient_ok),
                "cdc_nodes_recomputed": r["evidence_stale"] + r["claims_touched"],
                "naive_strict_nodes_recomputed": ev_total * 2 + len(mine),
                "naive_lenient_nodes_recomputed": len(broken_lenient) * 2 + len(derived_hit_lenient),
                "rebound_ok": r["rebound_ok"], "rebind_failed": r["rebind_failed"],
                "graph_restored": r["claims_supported_after"] == r["claims_supported_before"],
                "oracle_ok": r["oracle_ok"], "elapsed_us": r["elapsed_us"],
            })

    def agg(sel):
        rs = [r for r in rows if sel(r)]
        ev = sum(r["evidence_total"] for r in rs)
        pres = sorted(r["chunk_preservation"] for r in rs)
        return {
            "scenarios": len(rs),
            "chunk_preservation_mean": sum(pres) / len(pres),
            "chunk_preservation_median": pres[len(pres) // 2],
            "chunk_preservation_min": pres[0],
            "share_scenarios_ge_90pct": sum(x >= 0.9 for x in pres) / len(pres),
            "evidence_total": ev,
            "cdc_survival": sum(r["cdc_survived"] for r in rs) / ev,
            "naive_strict_survival": sum(r["naive_strict_survived"] for r in rs) / ev,
            "naive_lenient_survival": sum(r["naive_lenient_survived"] for r in rs) / ev,
            "nodes_recomputed_cdc": sum(r["cdc_nodes_recomputed"] for r in rs),
            "nodes_recomputed_naive_strict": sum(r["naive_strict_nodes_recomputed"] for r in rs),
            "nodes_recomputed_naive_lenient": sum(r["naive_lenient_nodes_recomputed"] for r in rs),
            "all_rebound": all(r["rebind_failed"] == 0 for r in rs),
            "all_graph_restored": all(r["graph_restored"] for r in rs),
            "all_oracle_ok": all(r["oracle_ok"] for r in rs),
        }

    sizes = [r["doc_bytes"] for r in rows if r["scenario"] == SCENARIOS[0]]
    return {
        "mode": mode,
        "setup": {
            "documents": len(docs), "facts": n_facts, "derived_claims": n_derived,
            "doc_bytes_min": min(sizes), "doc_bytes_max": max(sizes),
            "chunks_per_doc_mean": sum(r["chunks_before"] for r in rows) / len(rows),
            "ingest_latency_us": rep["latency_us"],
            "evidence_nodes": rep["kinds"]["evidence"],
            "multi_segment_evidence": rep["multi_segment_evidence"],
        },
        "overall": agg(lambda r: True),
        "by_scenario": {sc: agg(lambda r, sc=sc: r["scenario"] == sc) for sc in SCENARIOS},
        "rows": rows,
    }


def run(quick: bool = False) -> dict:
    rng = random.Random(1001)
    n_docs = 4 if quick else 10
    onto, docs, ops, meta = build_corpus(rng, n_docs, 10)
    edits = {}
    for doc_id, paras in docs.items():
        fact_set = {m["su"] for m in meta if m["doc"] == doc_id} | {m["sd"] for m in meta if m["doc"] == doc_id}
        for sc in SCENARIOS:
            edits[(doc_id, sc)] = C.join_doc(edit(random.Random(f"{doc_id}/{sc}"), paras, fact_set, sc))
    n_facts, n_derived = 2 * len(meta), len(meta)
    local = run_mode("localmax", onto, docs, ops, meta, edits, n_facts, n_derived)
    fast = run_mode("fastcdc", onto, docs, ops, meta, edits, n_facts, n_derived)
    o = local["overall"]
    return {
        "primary": local,
        "baseline_fastcdc": fast,
        "pass": {
            "median_chunk_preservation_ge_90pct": o["chunk_preservation_median"] >= 0.9,
            "chunks_ge_90pct_in_most_scenarios": o["share_scenarios_ge_90pct"] >= 0.75,
            "cdc_beats_naive": o["cdc_survival"] > o["naive_lenient_survival"] > -1,
            "graph_fully_restored": o["all_graph_restored"] and o["all_rebound"],
            "dred_matches_oracle": o["all_oracle_ok"] and fast["overall"]["all_oracle_ok"],
        },
    }
