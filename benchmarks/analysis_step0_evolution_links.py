"""Step 0 (a) of the consilium plan, offline and model-free: every evolution link (supersedes, contradicts) that reached the
graph of an archived pilot run, to read why none was accepted.

For each link: who proposed it (a swarm agent's relation line or the graph builder's add_link), the text and reports of both
ends, its final status, and every VERIFY_LINK or RESOLVE_CONFLICT verdict with its reason (from the call journal). Per run, also the evolution
relation lines the models wrote in any reply, whether or not the kernel stored them. Usage:
  python benchmarks/analysis_step0_evolution_links.py <run dir> [<run dir> ...] > links.json"""
from __future__ import annotations

import json
import pathlib
import sys
from collections import Counter

from analysis_step0_summary_audit import load, wal_of
from sbgk_bench.pilot_ac import source_document_paths

EVOLUTION = ("supersedes", "contradicts")


def report_names(run: pathlib.Path) -> dict:
    """doc_id -> report file name, from the run's own frozen inputs."""
    inputs = run / "inputs"
    snapshot = json.loads((inputs / "snapshot.json").read_text(encoding="utf-8"))
    docs = {p: (inputs / "repo" / p).read_bytes().decode("utf-8") for p in snapshot["reports"]}
    return {d: pathlib.Path(p).stem for d, p in source_document_paths((inputs / "manifest.json").read_bytes(), docs).items()}


def json_lines(text: str):
    for ln in (text or "").splitlines():
        ln = ln.strip()
        if ln.startswith("{"):
            try:
                yield json.loads(ln)
            except json.JSONDecodeError:
                continue


def proposals(run: pathlib.Path) -> tuple[dict, dict]:
    """Evolution links the kernel stored, keyed by (rel, from, to) with their link id, proposer and last status, and the text
    of every record a submit stored. A swarm relation line's record id is not its link's id, hence the key by ends."""
    stored, texts, locals_ = {}, {}, {}
    for line in wal_of(run).open(encoding="utf-8"):
        frame = json.loads(line)
        p = frame.get("payload") or frame.get("body") or {}  # 0.1 frames: payload; 0.2: body
        cmd, res = p.get("command") or {}, (p.get("outcome") or {}).get("result") or {}
        actor = str(p.get("actor", ""))
        if cmd.get("kind") == "submit" and actor.startswith("w"):
            for ln, rid in zip(cmd.get("lines") or [], res.get("accepted") or []):
                rid = rid.lstrip("@")[:16]
                locals_[(actor, cmd.get("directive"), ln.get("local_id"))] = rid
                texts[rid] = {"kind": ln.get("kind"), "by": actor, "text": ln.get("text") or ln.get("exact_quote") or ln.get("question"),
                              "subject": ln.get("subject"), "stance": ln.get("stance"), "as_of": ln.get("as_of")}
                if ln.get("kind") == "relation" and ln.get("rel") in EVOLUTION:
                    end = lambda e: e[1:17] if str(e).startswith("@") else locals_.get((actor, cmd.get("directive"), e), "")
                    stored.setdefault((ln["rel"], end(ln.get("from")), end(ln.get("to"))), {"link": None, "by": actor, "status": "proposed"})
        elif cmd.get("kind") == "batch":
            ops, results = cmd.get("operations") or [], res.get("results") or []
            for i, op in enumerate(ops[:res.get("accepted_operations") or 0]):
                r = results[i] if i < len(results) and isinstance(results[i], dict) else {}
                if op.get("kind") in ("add_link", "set_link_status") and r.get("rel") in EVOLUTION:
                    s = stored.setdefault((r["rel"], str(r.get("from", ""))[:16], str(r.get("to", ""))[:16]), {})
                    s.update(link=str(r.get("id", ""))[:16], by=s.get("by") or r.get("by") or actor, status=r.get("status"))
    return stored, texts


def verdicts(run: pathlib.Path) -> dict:
    """16-hex link id -> every VERIFY_LINK or RESOLVE_CONFLICT reply's verdict lines, in call order."""
    keys = {}
    for line in (run / "contexts.jsonl").open(encoding="utf-8"):
        c = json.loads(line)
        kind, key = c.get("kind"), str(c.get("key", ""))
        if (kind, key.split("@")[0]) in (("VERIFY_LINK", "verify:"), ("RESOLVE_CONFLICT", "conflict:")):
            keys[c["call_id"]] = key.split("@", 1)[1][:16]
    out = {}
    for line in (run / "calls.jsonl").open(encoding="utf-8"):
        c = json.loads(line)
        link = keys.get(c.get("call_id"))
        if link is None:
            continue
        lines = [{"verdict": v.get("verdict"), "reason": v.get("reason")} for v in json_lines(c.get("text")) if v.get("kind") == "verdict"]
        out.setdefault(link, []).append({"call_id": c["call_id"], "role": c.get("role"), "model": c.get("model"), "ok": c.get("ok"), "verdicts": lines})
    return out


def written(run: pathlib.Path) -> Counter:
    """Distinct evolution relation lines in any model reply, by role and rel (stored or not); a line a repair repeats with the
    same ends in the same task counts once."""
    seen = set()
    for line in (run / "calls.jsonl").open(encoding="utf-8"):
        c = json.loads(line)
        task = str(c.get("call_id", "")).rsplit("-", 1)[0]
        for v in json_lines(c.get("text")):
            for x in [v, *(op for op in v.get("operations") or [] if isinstance(op, dict))]:
                if x.get("rel") in EVOLUTION and x.get("kind") in ("relation", "link", "add_link", None):
                    seen.add((c.get("role"), task, x["rel"], str(x.get("from")), str(x.get("to"))))
    return Counter(f"{role}/{rel}" for role, _, rel, _, _ in seen)


def audit(run: pathlib.Path) -> dict:
    records, _ = load(run)
    stored, texts = proposals(run)
    names, verdict_of = report_names(run), verdicts(run)

    def end(rid: str) -> dict:
        t = texts.get(rid, {})
        return dict(t, id=rid, reports=sorted(names.get(d, d[:18]) for d in records.get(rid, {}).get("reports", set())))

    out = []
    for (rel, a, b), s in stored.items():
        a, b = end(a), end(b)
        out.append({"link": s["link"], "rel": rel, "by": s["by"], "status": s["status"],
                    "cross_report": bool(a["reports"] and b["reports"] and a["reports"] != b["reports"]),
                    "from": a, "to": b, "verify": verdict_of.get(s["link"], [])})
    return {"run": run.name, "written_in_replies": dict(written(run)),
            "stored": dict(Counter(f"{'builder' if l['by'] == 'builder' else 'swarm'}/{l['rel']}/{l['status']}" for l in out)),
            "links": out}


if __name__ == "__main__":
    print(json.dumps([audit(pathlib.Path(a)) for a in sys.argv[1:]], ensure_ascii=False, indent=1))
