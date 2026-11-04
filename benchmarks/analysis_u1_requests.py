"""U1 results, offline and model-free: what the graph builder's typed requests and their control readings did in one run.

The measures of the owner's decision of 2026-10-24 (note 2026-10-24_claude_owner_decision_builder_requests_L1_typed.md):
  requests      by type: lines the builder wrote, accepted, refused (with the kernel's reasons)
  tasks         request and control tasks by outcome (committed / given back) and by type
  origin        accepted records: first reading, written under a request (TR<n>-), under a control reading (TC<n>-)
  yield         per request type and for the control: model calls, their cost, records stored, records per call
  control       builder-chosen (A) against kernel-chosen (B) second readings: new records and new quotes per task, the share of
                empty outcomes, the cost per task
  verdicts      link verdicts split by whether a find_link_basis request was about the link: confirmed share in each (a higher
                confirmation rate must not be the builder confirming its own proposals through the swarm)
  self_basis    accepted links whose verdict rests only on what a request about that same link found
  recapture     with a previous run of the same corpus and section size: quotes of both, their overlap and the Lincoln-Petersen
                descriptive figure (dependent catches; no upper/lower population bound)
  pacing        backpressure (run 10A-17): the owner's status samples (backlog curve, readings in flight, paced skips, stall-guard
                lifts), first readings started per two minutes, the builder's idle time, the wall time of arm C, and for every
                accepted request whether its section's first reading had finished and whether first readings were still open
Usage:
  python benchmarks/analysis_u1_requests.py <run dir> [<previous run dir>] > u1.json"""
from __future__ import annotations

import json
import pathlib
import re
import sys
from collections import Counter, defaultdict

MARK = re.compile(r"^(T[A-Z]?)\d+-")


def wal_of(run: pathlib.Path) -> pathlib.Path:
    for p in (run / "arm_c" / "run.wal", run / "arm_c_run.wal"):
        if p.exists():
            return p
    raise FileNotFoundError(f"no WAL in {run}")


def mark(directive: str) -> str:
    m = MARK.match(directive or "")
    return m.group(1) if m else ""


def jsonl(path: pathlib.Path):
    if path.exists():
        for line in path.open(encoding="utf-8"):
            if line.strip():
                yield json.loads(line)


def read_wal(run: pathlib.Path) -> dict:
    """Records (16-hex id -> kind, directive, doc, quote), the accepted requests, task id -> request key, accepted link verdicts."""
    records, requests, task_key, verdicts = {}, {}, {}, []
    for line in wal_of(run).open(encoding="utf-8"):
        p = json.loads(line).get("payload") or {}
        cmd, res = p.get("command") or {}, (p.get("outcome") or {}).get("result") or {}
        if cmd.get("kind") == "submit":
            for ln, rid in zip(cmd.get("lines") or [], res.get("accepted") or []):
                records[rid.lstrip("@")[:16]] = {"kind": ln.get("kind"), "directive": cmd.get("directive"), "doc": ln.get("doc_id"),
                                                 "quote": ln.get("exact_quote")}
        elif cmd.get("kind") == "batch":
            ck = cmd.get("checkpoint") or {}
            key, ctx = str(ck.get("key") or ""), ck.get("context") or {}
            if res.get("checkpointed"):
                if re.fullmatch(r"request:\d+", key):
                    requests[key] = ctx
                elif key.startswith("task:request:") or key.startswith("task:control:"):
                    task_key[ctx.get("task_id")] = key[len("task:"):]
            ops, results = cmd.get("operations") or [], res.get("results") or []
            for i, op in enumerate(ops[:res.get("accepted_operations") or 0]):
                r = results[i] if i < len(results) and isinstance(results[i], dict) else {}
                if op.get("kind") == "set_link_status" and op.get("status") in ("accepted", "rejected"):
                    verdicts.append({"link": str(op.get("link"))[:16], "status": op.get("status"), "basis": [str(b)[:16] for b in op.get("basis") or []],
                                     "by": p.get("actor")})
    return {"records": records, "requests": requests, "task_key": task_key, "verdicts": verdicts}


def kind_of(key: str, requests: dict) -> str:
    """request:<n> -> its type; control:<n> -> control."""
    if key.startswith("control:"):
        return "control"
    return (requests.get(key) or {}).get("type", "?")


def analyse(run: pathlib.Path, previous: pathlib.Path | None = None) -> dict:
    w = read_wal(run)
    records, requests, task_key = w["records"], w["requests"], w["task_key"]
    events = list(jsonl(run / "events.jsonl"))

    # 1. the builder's request lines and the kernel's answers (an exact resend is counted once)
    lines, seen = Counter(), set()
    reasons = defaultdict(Counter)
    for e in events:
        for x in e.get("builder_requests") or []:
            ident = (e.get("card"), x.get("local_id"), x.get("status"), x.get("request"))
            if ident in seen or x.get("replayed"):
                continue
            seen.add(ident)
            ty = x.get("type") or "refused"
            if x.get("status") == "accepted":
                lines[f"{ty}/accepted"] += 1
            else:
                err = x.get("error") or {}
                lines["refused"] += 1
                reasons[err.get("field") or "?"][(err.get("message") or err.get("code") or "?")[:120]] += 1
    by_type = Counter(r.get("type") for r in requests.values())

    # 2. request and control tasks by outcome
    tasks = defaultdict(Counter)
    for e in events:
        if e.get("kind") == "REQUEST" and e.get("key"):
            tasks[kind_of(e["key"], requests)][e.get("outcome") or "?"] += 1

    # 3. records by origin, per request type
    origin = Counter()
    per_task = defaultdict(list)
    for rid, r in records.items():
        m = mark(r["directive"])
        if m in ("TR", "TC"):
            key = task_key.get(r["directive"])
            origin[f"{'request' if m == 'TR' else 'control'}/{kind_of(key, requests) if key else 'unfinished'}"] += 1
            per_task[r["directive"]].append(rid)
        else:
            origin["first_reading_and_checks"] += 1

    # 4. yield and cost per type, from the calls of each task
    key_of_call = {c.get("call_id"): c.get("key") for c in jsonl(run / "contexts.jsonl") if c.get("kind") == "REQUEST"}
    calls, cost = Counter(), Counter()
    for c in jsonl(run / "calls.jsonl"):
        key = key_of_call.get(c.get("call_id"))
        if key and c.get("role") == "REQUEST":
            k = kind_of(str(key).replace("verify:", ""), requests)
            calls[k] += 1
            cost[k] += c.get("cost_usd") or 0.0
    stored = Counter()
    for t, rids in per_task.items():
        key = task_key.get(t)
        stored[kind_of(key, requests) if key else "unfinished"] += len(rids)
    yield_ = {k: {"calls": calls[k], "cost_usd": round(cost[k], 6), "records": stored[k],
                  "records_per_call": round(stored[k] / calls[k], 3) if calls[k] else None} for k in sorted(set(calls) | set(stored))}

    # 5. control: builder-chosen (A, reread_gap) against kernel-chosen (B) second readings
    first_quotes = {(r["doc"], r["quote"]) for r in records.values() if r["kind"] == "observe" and mark(r["directive"]) not in ("TR", "TC")}
    group = {"A_builder": [], "B_kernel": []}
    for t, key in task_key.items():
        if key.startswith("control:"):
            g = "B_kernel"
        elif kind_of(key, requests) == "reread_gap":
            g = "A_builder"
        else:
            continue
        rids = per_task.get(t, [])
        new_quotes = {(records[r]["doc"], records[r]["quote"]) for r in rids if records[r]["kind"] == "observe"} - first_quotes
        group[g].append({"task": t, "key": key, "records": len(rids), "new_quotes": len(new_quotes)})
    control = {}
    for g, rows in group.items():
        keys = {r["key"] for r in rows}
        spend = sum(c for k, c in ((key_of_call.get(x.get("call_id")), x.get("cost_usd") or 0.0) for x in jsonl(run / "calls.jsonl")) if k in keys)
        n = len(rows)
        control[g] = {"tasks": n, "records_per_task": round(sum(r["records"] for r in rows) / n, 3) if n else None,
                      "new_quotes_per_task": round(sum(r["new_quotes"] for r in rows) / n, 3) if n else None,
                      "empty_share": round(sum(1 for r in rows if r["records"] == 0) / n, 3) if n else None,
                      "cost_per_task_usd": round(spend / n, 6) if n else None}

    # 6. accepted links whose verdict rests only on what a request about that same link found
    by_link = defaultdict(set)
    for key, ctx in requests.items():
        if ctx.get("type") == "find_link_basis":
            by_link[str(ctx.get("link"))[:16]].add(key)
    split = defaultdict(Counter)
    for v in w["verdicts"]:
        split["with_basis_request" if v["link"] in by_link else "without"][v["status"]] += 1
    verdicts = {k: dict(c, confirmed_share=round(c["accepted"] / (c["accepted"] + c["rejected"]), 3) if c["accepted"] + c["rejected"] else None)
                for k, c in split.items()}
    self_basis = []
    for v in (x for x in w["verdicts"] if x["status"] == "accepted"):
        asked = by_link.get(v["link"])
        if not asked:
            continue
        from_request = [b for b in v["basis"] if task_key.get(records.get(b, {}).get("directive")) in asked]
        self_basis.append({"link": v["link"], "basis": len(v["basis"]), "from_its_request": len(from_request),
                           "only_from_its_request": bool(v["basis"]) and len(from_request) == len(v["basis"])})

    out_pacing = pacing(run, events, requests)
    out = {"run": run.name, "pacing": out_pacing, "requests_accepted_by_type": dict(by_type), "request_lines": dict(lines),
           "refusal_reasons": {k: dict(v) for k, v in reasons.items()}, "tasks": {k: dict(v) for k, v in tasks.items()},
           "records_by_origin": dict(origin), "yield": yield_, "control": control, "verdicts": verdicts, "self_basis": self_basis}
    if previous is not None:
        prev = read_wal(previous)["records"]
        a = {(r["doc"], r["quote"]) for r in records.values() if r["kind"] == "observe"}
        b = {(r["doc"], r["quote"]) for r in prev.values() if r["kind"] == "observe"}
        m = len(a & b)
        out["recapture"] = {"previous": previous.name, "this_run_quotes": len(a), "previous_quotes": len(b), "both": m,
                            "lincoln_petersen": round(len(a) * len(b) / m) if m else None,
                            "caveat": "same model and prompts: dependent catches; descriptive estimator only, no guaranteed upper or lower bound"}
    return out


def pacing(run: pathlib.Path, events: list, requests: dict) -> dict:
    """The timing of backpressure from the call journal (wall clock) and the owner's status samples."""
    key_of_call = {c.get("call_id"): c.get("key") for c in jsonl(run / "contexts.jsonl")}
    calls = [c for c in jsonl(run / "calls.jsonl") if c.get("arm") == "C" and c.get("started_at")]
    if not calls:
        return {}
    t0 = min(c["started_at"] for c in calls)
    t1 = max(c.get("finished_at") or c["started_at"] for c in calls)
    reading = sorted(c["started_at"] - t0 for c in calls if c.get("role") == "EXTEND")
    bins = Counter(int(x // 120) for x in reading)
    busy, at = 0.0, None
    for a, b in sorted((c["started_at"], c.get("finished_at") or c["started_at"]) for c in calls if c.get("role") == "BUILDER"):
        if at is None or a > at:
            busy += b - a
            at = b
        elif b > at:
            busy += b - at
            at = b
    first_read = {}
    for c in calls:
        k = key_of_call.get(c.get("call_id"))
        if c.get("role") == "EXTEND" and k and c.get("finished_at"):
            first_read[k] = min(first_read.get(k, c["finished_at"]), c["finished_at"])
    asked_at = {c.get("call_id"): c.get("finished_at") for c in calls if c.get("role") == "BUILDER"}
    timing = []
    for e in events:
        for x in e.get("builder_requests") or []:
            if x.get("status") != "accepted" or x.get("replayed"):
                continue
            ctx = requests.get(x.get("request")) or {}
            when = asked_at.get(e.get("call_id"))
            section = f"doc:{ctx.get('doc_id')}#{ctx.get('section')}" if ctx.get("section") is not None else None
            read = first_read.get(section) if section else None
            timing.append({"request": x.get("request"), "type": ctx.get("type"), "reason": ctx.get("reason"),
                           "at_s": round(when - t0, 1) if when else None,
                           "section_read_before": (read <= when) if read and when else None,
                           "reading_still_open": any(r > when - t0 for r in reading) if when else None})
    samples = [{k: e.get(k) for k in ("t", "records", "builder_cursor", "builder_backlog", "extend_leases", "paced_skips", "stall_open",
                                      "stall_lifts", "stall_reengages", "requests_accepted")} for e in events if e.get("status_sample")]
    for x in samples:
        x["t"] = round(x["t"] - t0, 1) if x.get("t") else None
    return {"wall_s": round(t1 - t0, 1), "builder_busy_s": round(busy, 1), "builder_idle_s": round(t1 - t0 - busy, 1),
            "first_readings_per_2_min": {f"{2 * k}-{2 * k + 2} min": n for k, n in sorted(bins.items())},
            "last_first_reading_started_s": round(reading[-1], 1) if reading else None,
            "samples": samples, "requests": timing}


if __name__ == "__main__":
    args = [pathlib.Path(a) for a in sys.argv[1:]]
    print(json.dumps(analyse(args[0], args[1] if len(args) > 1 else None), ensure_ascii=False, indent=1))
