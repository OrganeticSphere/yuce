"""Step 1 of Gemini's plan after the consilium of 10A-17, its offline gates: the rows of `replay_step1` (every recorded swarm answer
of a live run through the current dispatcher, on the run's own state) summed up per run.

- The answers the recorded kernel stopped at a quote cut from its clause (its first refusal was ends_mid_clause or negation_before,
  Gemini's count): the lines they lost, how many the current kernel stores, and why the rest is still not stored.
- The lines the clause rules flagged themselves: stored now, or refused by which rule.
- The key sections of the consilium (10.08 #1, #2; 29.07 #1, #3): what their answers stored then and now.
- The summaries: stored lines, and the runner's partial delivery of a summary whose repairs are used up.
- Negation controls: every line refused for a negation cut off before it whose lead holds a negation word standing alone (not part
  of a hyphenated or snake-case name) must stay refused; one stored now is listed as a miss to read.
- Regressions: a line the recorded kernel stored that the current one does not.

Usage: python benchmarks/analysis_step1_replay.py <replay rows .jsonl> <run dir> [<rows> <run dir> ...] > step1.json"""
from __future__ import annotations

import json
import pathlib
import re
import sys
from collections import Counter

from analysis_step0_evolution_links import report_names

CLAUSE = "clause it belongs"
NEGATIONS = {"not", "no", "never", "neither", "nor", "without", "cannot"}
KEY_SECTIONS = {"2026-08-10": (1, 2), "2026-07-29": (1, 3)}


def negates(text: str, joined: str) -> bool:
    """The kernel's negation test on a lead (s0::negates): `joined` are the characters a word keeps inside it."""
    lower = text.lower()
    words = re.split(r"[^a-z0-9" + re.escape(joined) + "]", lower)
    return "n't" in lower or any(w in NEGATIONS for w in words)


def stored(x: dict) -> bool:
    return x["new"]["outcome"] in ("stored", "resent")


def why_not(x: dict) -> str:
    n = x["new"]
    if n["outcome"] == "refused":
        if (n.get("message") or "").startswith("a claim names only identifiers"):
            return "refused:missing_identifiers"
        return f"refused:{n.get('rule') or n.get('code')}"
    return n["outcome"]


def summarize(rows_path: pathlib.Path, run: pathlib.Path) -> dict:
    rows = [json.loads(ln) for ln in rows_path.read_text(encoding="utf-8").splitlines()]
    meta, rows = rows[0]["meta"], rows[1:]
    names = report_names(run)
    replayed = [r for r in rows if "skipped" not in r]
    out: dict = {"meta": meta, "answers": len(rows), "replayed": len(replayed),
                 "skipped": dict(Counter(r["skipped"] for r in rows if "skipped" in r))}

    # Gemini's count: answers whose first refusal was a clause rule, and the lines they lost
    s0 = [r for r in replayed if r["old"]["code"] and CLAUSE in (r["old"]["message"] or "")]
    lost = [x for r in s0 for x in r["per_line"] if x["old"] == "lost"]
    rescued = [x for x in lost if stored(x)]
    out["clause_stopped_answers"] = {
        "answers": len(s0), "lines": sum(r["lines"] for r in s0),
        "lost_then": len(lost), "stored_now": len(rescued),
        "rescue_rate": round(len(rescued) / len(lost), 3) if lost else None,
        "gate_rescue_rate": 0.70,
        "still_lost_why": dict(Counter(why_not(x) for x in lost if not stored(x)).most_common()),
        "answers_committed_now": sum(r["new"]["status"] == "COMMITTED" for r in s0),
    }

    # per task: its first answer through the current kernel against all its recorded answers (repairs included)
    tasks: dict = {}
    for r in replayed:
        tasks.setdefault(r["task"], []).append(r)
    hit = {r["task"] for r in s0}
    first_now = sum(rs[0]["new"]["stored"] for t, rs in tasks.items() if t in hit)
    all_then = sum(r["old"]["accepted"] for t, rs in tasks.items() if t in hit for r in rs)
    out["clause_stopped_tasks"] = {
        "tasks": len(hit), "answers_then": sum(len(rs) for t, rs in tasks.items() if t in hit),
        "stored_then_all_answers": all_then, "stored_now_first_answer": first_now,
        "first_answer_committed_now": sum(rs[0]["new"]["status"] == "COMMITTED" for t, rs in tasks.items() if t in hit),
    }

    # the lines the clause rules flagged themselves
    flagged = [x for r in replayed for x in r["per_line"] if {"negation_before", "ends_mid_clause"} & set(x.get("old_rules", []))]
    by_rule = {}
    for rule in ("ends_mid_clause", "negation_before"):
        xs = [x for x in flagged if rule in x.get("old_rules", [])]
        by_rule[rule] = {"lines": len(xs), "stored_now": sum(stored(x) for x in xs),
                         "now": dict(Counter("stored" if stored(x) else why_not(x) for x in xs).most_common())}
    out["clause_flagged_lines"] = by_rule

    # negation controls: a negation word standing alone in the lead stays refused
    controls, misses, freed = [], [], []
    for r in replayed:
        for x in r["per_line"]:
            lead = x.get("old_negation_lead")
            if lead is None or x["old"] == "resent":
                continue
            genuine = negates(lead, "_-")
            entry = {"call_id": r["call_id"], "local_id": x["local_id"], "lead": lead, "quote": x.get("quote"),
                     "now": "stored" if stored(x) else why_not(x)}
            if genuine:
                controls.append(entry)
                if stored(x):
                    misses.append(entry)
            elif stored(x):
                freed.append(entry)
    out["negation_controls"] = {
        "genuine": len(controls),
        "still_refused_by_negation_before": sum(c["now"] == "refused:negation_before" for c in controls),
        "now": dict(Counter(c["now"] for c in controls).most_common()),
        "stored_now_to_read": misses,
        "freed_names_not_negations": {"lines": len(freed), "examples": freed[:8]},
    }

    # the key sections of the consilium
    keys = {}
    for d, name in names.items():
        for date, secs in KEY_SECTIONS.items():
            if date in name:
                for k in secs:
                    keys[f"doc:{d}#{k}"] = f"{date} #{k}"
    sections = {}
    for r in replayed:
        if r["key"] in keys:
            claims = lambda pred: sum(1 for x in r["per_line"] if x["line_kind"] == "claim" and pred(x))  # noqa: E731
            sections.setdefault(keys[r["key"]], []).append({
                "call_id": r["call_id"], "lines": r["lines"],
                "then": {"status": r["old"]["status"], "stored": r["old"]["accepted"], "claims_stored": claims(lambda x: x["old"] == "stored")},
                "now": {"status": r["new"]["status"], "stored": r["new"]["stored"], "claims_stored": claims(lambda x: x["new"]["outcome"] == "stored"),
                        "refused": r["new"]["refused"], "excluded": r["new"]["excluded"]}})
    out["key_sections"] = {k: sections.get(k, []) for k in sorted(set(keys.values()))}

    # the summaries
    out["summaries"] = [{"call_id": r["call_id"], "rq": r["key"], "phase": r["phase"], "lines": r["lines"],
                         "then": {"status": r["old"]["status"], "stored": r["old"]["accepted"], "code": r["old"]["code"]},
                         "now": {"status": r["new"]["status"], "scope": r["new"]["repair_scope"], "stored": r["new"]["stored"],
                                 "refused": r["new"]["refused"], "excluded": r["new"]["excluded"], "error": r["new"]["error"],
                                 "refused_why": dict(Counter((x["new"].get("message") or "")[:70] for x in r["per_line"]
                                                             if x["new"]["outcome"] == "refused"))},
                         **({"fallback": r["fallback"]} if "fallback" in r else {})}
                        for r in replayed if r["kind"] == "SUMMARIZE"]

    # regressions: stored then, not now
    regressions = [{"call_id": r["call_id"], "local_id": x["local_id"], "now": why_not(x)}
                   for r in replayed for x in r["per_line"] if x["old"] == "stored" and not stored(x)]
    out["regressions"] = {"lines": len(regressions), "examples": regressions[:10]}
    out["all_answers"] = {
        "lost_then": sum(x["old"] == "lost" for r in replayed for x in r["per_line"]),
        "lost_now": sum(not stored(x) for r in replayed for x in r["per_line"]),
        "extended_quotes": sum(len(r["new"]["extended"] or []) for r in replayed),
    }
    return out


def main(argv: list[str]) -> None:
    pairs = list(zip(argv[1::2], argv[2::2]))
    print(json.dumps({pathlib.Path(run).name: summarize(pathlib.Path(rows), pathlib.Path(run)) for rows, run in pairs},
                     indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main(sys.argv)
