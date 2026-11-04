"""EXP-5: minimal support cone vs full-graph hand-off.

A planner agent built a graph of 500-2000 nodes (many subsystems, shared APIs, revoked branches). The
receiver only needs one subsystem. We compare the size of what is pasted into the receiver's prompt and the
time needed to prepare it:
  * full graph JSON (every node with its status),
  * full active graph JSON (revoked / unsupported nodes dropped),
  * `project_minimal_cone(bytes, entity)` read through the byte index.
The cone is also checked for completeness (all supported claims about the entity are present) and soundness
(self-contained proofs; nothing revoked or unsupported).
"""

from __future__ import annotations

import json
import random

from . import common as C
from .exp4 import pack_docs


def build(rng: random.Random, n_sys: int, per_sys: int):
    n_services = n_sys * per_sys
    n_apis = max(4, n_services // 2)
    onto = C.ontology_review(n_services, n_apis, n_sys)
    shared = list(range(n_apis // 4))  # api pool shared across subsystems
    sents, quotes = [], {}

    def S(key: str, text: str):
        quotes[key] = len(sents)
        sents.append(text)

    api_dep = {}
    plan = []  # (svc, sys, api)
    for s in range(n_sys):
        own = [n_apis // 4 + s * max(1, (n_apis - n_apis // 4) // n_sys) + j for j in range(2)]
        for j in range(per_sys):
            svc = s * per_sys + j
            api = rng.choice(shared) if rng.random() < 0.25 else own[j % len(own)]
            api = min(api, n_apis - 1)
            plan.append((svc, s, api))
            api_dep.setdefault(api, rng.random() < 0.75)
    for svc, s, api in plan:
        S(f"u{svc}", f"Clause U.{svc}: service svc_{svc:03d} shall call interface api_{api:03d} in production environments.")
        S(f"p{svc}", f"Clause P.{svc}: service svc_{svc:03d} is part of system sys_{s:02d} for all purposes.")
    for api, dep in sorted(api_dep.items()):
        if dep:
            S(f"d{api}", f"Clause D.{api}: interface api_{api:03d} is deprecated effective the first quarter.")
    docs, doc_of = pack_docs(sents, rng)

    ops = []
    for svc, s, api in plan:
        ops += [
            C.L_bind(f"eu{svc}", doc_of[quotes[f"u{svc}"]], sents[quotes[f"u{svc}"]]),
            C.L_bind(f"ep{svc}", doc_of[quotes[f"p{svc}"]], sents[quotes[f"p{svc}"]]),
            C.L_assert(f"fu{svc}", f"svc_{svc:03d}", "uses_api", f"api_{api:03d}", (100, 200), [f"eu{svc}"]),
            C.L_assert(f"fp{svc}", f"svc_{svc:03d}", "part_of", f"sys_{s:02d}", (0, 1000), [f"ep{svc}"]),
        ]
    for api, dep in sorted(api_dep.items()):
        if dep:
            ops += [C.L_bind(f"ed{api}", doc_of[quotes[f"d{api}"]], sents[quotes[f"d{api}"]]),
                    C.L_assert(f"fd{api}", f"api_{api:03d}", "api_deprecated", "true", (150, 300), [f"ed{api}"])]
    for svc, s, api in plan:
        if api_dep[api]:
            ops.append(C.L_derive(f"rn{svc}", "R_depr_review@1", [f"fu{svc}", f"fd{api}"],
                                  C.claim_of(f"svc_{svc:03d}", "needs_review", "true", (150, 200))))
            ops.append(C.L_derive(f"rs{svc}", "R_sys_flag@1", [f"fp{svc}", f"rn{svc}"],
                                  C.claim_of(f"sys_{s:02d}", "sys_flagged", "true", (150, 200))))
    # revoked branches: ~15% of services lose their uses_api evidence; one shared deprecation notice is withdrawn
    revoked = [f"eu{svc}" for svc, _, _ in plan if rng.random() < 0.15]
    shared_dep = [a for a in shared if api_dep.get(a)]
    if shared_dep:
        revoked.append(f"ed{rng.choice(shared_dep)}")
    ops += [C.L_revoke(r) for r in revoked]
    return onto, docs, ops, n_sys


def check_cone(cone: dict, entity_claims: list[dict]) -> dict:
    claims = {c["id"]: c for c in cone["claims"]}
    steps = {s["id"]: s for s in cone["steps"]}
    ev = {e["id"] for e in cone["evidence"]}
    sound = True
    for c in claims.values():
        if c["st"] not in ("SUPPORTED", "CONFLICTING_SOURCES") or c.get("via") not in steps:
            sound = False
            continue
        st = steps[c["via"]]
        if st["claim"] != c["id"]:
            sound = False
        if st["kind"] == "assertion":
            sound &= st["evidence"] in ev
        else:
            sound &= all(p in claims for p in st["premises"])
    got = {(c["s"], c["p"], c["o"], tuple(c["t"])) for c in cone["claims"] if c["id"] in set(cone["targets"])}
    want = {(c["s"], c["p"], c["o"], tuple(c["t"])) for c in entity_claims}
    return {"sound_and_self_contained": sound, "complete": got == want, "targets": len(want)}


def run(quick: bool = False) -> dict:
    rng = random.Random(5005)
    wd = C.workdir("exp5")
    configs = [(6, 4)] if quick else [(14, 4), (28, 4), (55, 4)]
    rows = []
    for (n_sys, per) in configs:
        onto, docs, ops, _ = build(rng, n_sys, per)
        sd = wd / f"s{n_sys}"
        C.write_docs(sd / "docs", docs)
        (sd / "ontology.json").write_text(json.dumps(onto), encoding="utf-8")
        C.write_lines(sd / "stream.jsonl", C.jsonl(C.numbered(ops)))
        out = sd / "graph.sbgk"
        rep = C.cli("apply", "--ontology", sd / "ontology.json", "--docs", sd / "docs", "--stream", sd / "stream.jsonl", "--out", out, "--oracle")
        assert rep["error"] is None, rep["error"]
        all_claims = C.cli("dump-claims", out)
        for q in rng.sample(range(n_sys), min(5, n_sys)):
            ent = f"sys_{q:02d}"
            r = C.cli("cone", out, "--entity", ent, "--out", sd / f"cone_{q}.json", "--reps", 40)
            cone = json.loads((sd / f"cone_{q}.json").read_text(encoding="utf-8"))
            ent_claims = [c for c in all_claims if (c["s"] == ent or c["o"] == ent) and c["status"] in ("SUPPORTED", "CONFLICTING_SOURCES")]
            chk = check_cone(cone, ent_claims)
            rows.append({
                "nodes": rep["nodes"], "entity": ent, "container_bytes": r["container_bytes"],
                "cone_bytes": r["cone_bytes"], "full_all_bytes": r["full_all_bytes"], "full_active_bytes": r["full_active_bytes"],
                "cone_claims": r["cone_claims"], "cone_steps": r["cone_steps"], "cone_evidence": r["cone_evidence"],
                "cone_us_p50": r["cone_us"]["p50"], "full_all_us_p50": r["full_all_us"]["p50"], "full_active_us_p50": r["full_active_us"]["p50"],
                "unsupported_nodes_in_graph": rep["claims"]["unsupported"],
                **chk,
            })
    sizes = sorted({r["nodes"] for r in rows})
    by_size = {}
    for n in sizes:
        rs = [r for r in rows if r["nodes"] == n]
        m = lambda k: sum(r[k] for r in rs) / len(rs)
        by_size[n] = {
            "queries": len(rs),
            "cone_bytes": m("cone_bytes"), "full_all_bytes": m("full_all_bytes"), "full_active_bytes": m("full_active_bytes"),
            "cone_tokens": C.tokens(m("cone_bytes")), "full_all_tokens": C.tokens(m("full_all_bytes")),
            "full_active_tokens": C.tokens(m("full_active_bytes")),
            "saving_vs_full_all_pct": 100 * (1 - m("cone_bytes") / m("full_all_bytes")),
            "saving_vs_full_active_pct": 100 * (1 - m("cone_bytes") / m("full_active_bytes")),
            "cone_us": m("cone_us_p50"), "full_all_us": m("full_all_us_p50"), "full_active_us": m("full_active_us_p50"),
            "prep_speedup_vs_full_all": m("full_all_us_p50") / m("cone_us_p50"),
            "cone_claims": m("cone_claims"),
        }
    return {
        "setup": {"configs": configs, "nodes": sizes, "queries": len(rows), "token_heuristic": "bytes/4"},
        "by_size": by_size, "rows": rows,
        "pass": {
            "cones_complete": all(r["complete"] for r in rows),
            "cones_sound_and_self_contained": all(r["sound_and_self_contained"] for r in rows),
            "cone_smaller_than_active_graph": all(r["cone_bytes"] < r["full_active_bytes"] for r in rows),
        },
    }
