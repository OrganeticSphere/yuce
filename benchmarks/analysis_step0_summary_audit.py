"""Step 0 of the consilium plan, offline and model-free: audit the final answers of archived pilot runs
against the verified links of their own graph.

For every run directory (an archived PILOT_AC_LIVE10A* folder) and every phase and research question, with the final state of the
run's WAL (link statuses after the last verdict):
  one_sided_conflicts  an answer claim with an accepted `contradicts` link whose other end is not in the answer
  superseded_in_answer an answer claim that an accepted `supersedes` link marks as replaced (it is the link's `to`)
  qualified_in_answer  an answer claim that an accepted `qualifies` link qualifies, without the qualifying claim in the answer
Per run: accepted links by relation and how many join claims resting on different reports.

The final link state may postdate an answer (a link verified after the summary); the report says so. Usage:
  python benchmarks/analysis_step0_summary_audit.py <run dir> [<run dir> ...] > audit.json"""
from __future__ import annotations

import json
import pathlib
import sys
from collections import Counter, defaultdict


def wal_of(run: pathlib.Path) -> pathlib.Path:
    for p in (run / "arm_c" / "run.wal", run / "arm_c_run.wal"):
        if p.exists():
            return p
    raise FileNotFoundError(f"no WAL in {run}")


def load(run: pathlib.Path) -> tuple[dict, dict]:
    """Records (16-hex id -> kind, reports) and the final state of every link that reached a verdict."""
    records, locals_, links = {}, {}, {}
    for line in wal_of(run).open(encoding="utf-8"):
        frame = json.loads(line)
        p = frame.get("payload") or frame.get("body") or {}  # 0.1 frames: payload; 0.2: body
        cmd, res = p.get("command") or {}, (p.get("outcome") or {}).get("result") or {}
        actor = str(p.get("actor", ""))
        if cmd.get("kind") == "submit" and actor.startswith("w"):
            for ln, rid in zip(cmd.get("lines") or [], res.get("accepted") or []):
                rid = rid.lstrip("@")[:16]
                locals_[(actor, cmd.get("directive"), ln.get("local_id"))] = rid
                based = [b[1:17] if b.startswith("@") else locals_.get((actor, cmd.get("directive"), b), "") for b in ln.get("based_on") or []]
                records[rid] = {"kind": ln.get("kind"), "doc": ln.get("doc_id"), "based": based, "directive": cmd.get("directive")}
        elif cmd.get("kind") == "batch":
            ops, results = cmd.get("operations") or [], res.get("results") or []
            for i, op in enumerate(ops[:res.get("accepted_operations") or 0]):
                if op.get("kind") in ("set_link_status", "add_link") and i < len(results) and isinstance(results[i], dict) and results[i].get("id"):
                    r = results[i]
                    links[r["id"][:16]] = {"rel": r.get("rel"), "from": str(r.get("from", ""))[:16], "to": str(r.get("to", ""))[:16], "status": r.get("status")}

    def reports(rid: str, depth: int = 0) -> set:
        r = records.get(rid)
        if not r:
            return set()
        if r["doc"]:
            return {r["doc"]}
        return set().union(*(reports(b, depth + 1) for b in r["based"] if b)) if depth < 3 else set()

    for rid in records:
        records[rid]["reports"] = reports(rid)
    return records, links


def audit(run: pathlib.Path) -> dict:
    records, links = load(run)
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    accepted = [l for l in links.values() if l["status"] == "accepted"]
    cross = [l for l in accepted if records.get(l["from"], {}).get("reports") and records.get(l["to"], {}).get("reports")
             and records[l["from"]]["reports"] != records[l["to"]]["reports"]]
    out = {"run": run.name, "links_with_verdict": len(links), "accepted_links": dict(Counter(l["rel"] for l in accepted)),
           "accepted_cross_report": dict(Counter(l["rel"] for l in cross)), "answers": {}}
    by_end = defaultdict(list)
    for l in accepted:
        by_end[l["from"]].append(l)
        by_end[l["to"]].append(l)
    for ph in ("phase1", "phase2", "phase3"):
        rc = ((summary.get("arm_c") or {}).get(ph) or {}).get("receipt") or {}
        for rq, o in (rc.get("outcomes") or {}).items():
            ids = {a.lstrip("@")[:16] for a in o.get("answer_ids") or []}
            if not ids:
                out["answers"][f"{ph}/{rq}"] = {"outcome": o.get("outcome"), "claims": 0}
                continue
            one_sided, superseded, qualified = [], [], []
            for c in ids:
                for l in by_end.get(c, []):
                    other = l["to"] if l["from"] == c else l["from"]
                    if l["rel"] == "contradicts" and other not in ids:
                        one_sided.append([c, other])
                    if l["rel"] == "supersedes" and l["to"] == c:
                        superseded.append([c, l["from"], l["from"] in ids])
                    if l["rel"] == "qualifies" and l["to"] == c and l["from"] not in ids:
                        qualified.append([c, l["from"]])
            reports_in = set().union(*(records.get(c, {}).get("reports", set()) for c in ids))
            out["answers"][f"{ph}/{rq}"] = {"outcome": o.get("outcome"), "claims": len(ids), "reports": len(reports_in),
                                            "one_sided_conflicts": one_sided, "superseded_in_answer": superseded,
                                            "qualified_without_qualifier": qualified}
    return out


if __name__ == "__main__":
    print(json.dumps([audit(pathlib.Path(a)) for a in sys.argv[1:]], ensure_ascii=False, indent=1))
