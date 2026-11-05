"""What a withdrawal cost and what it took with it, counted from a run's files with no model and no judgement.

For each side of a run folder and each withdrawal:

  calls           model calls after the withdrawal, split into the withdrawn page, the assembly of the answer, and other pages
  tokens          the tokens of those calls for each model apart: each model cuts text its own way, so its tokens are its own unit
  bytes           the bytes of those prompts and replies, the one size common to every model
  quotes          the quotes the answers of the stage before cited, split into those the withdrawal touched and the others;
                  of the others, how many the answers after it no longer cite: the collateral

and, on the kernel's side, for each reader and its model, the lines it sent and the quotes refused by reason.

A quote is touched when it is in the withdrawn page and overlaps the withdrawn text. A call is on the withdrawn page when its context
names that page, is assembly when it is a summary or a reduction, and is on other pages otherwise. A quote no longer cited is a fact
about the answer, not a loss of truth: an answer may drop a quote and say the same. What it counts is what a revision did not keep.

usage: python benchmarks/revision_outcomes.py <run_dir> [<run_dir> ...] [--json out.json]
Standard library only."""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

SIDES = (("C", "arm_c.json"), ("A", "arm_a.json"))


def rows_of(path: pathlib.Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def cited(answers: dict) -> set[tuple[str, str]]:
    return {(q["report"], q["quote"]) for answer in answers.values() for claim in answer.get("claims") or [] for q in claim.get("quotes") or []}


def touched(quote: tuple[str, str], withdrawn: dict) -> bool:
    report, text = quote
    return report == withdrawn["report"] and (text in withdrawn["quote"] or withdrawn["quote"] in text)


def where(call: dict, context: dict, page: str, doc_ids: set[str]) -> str:
    if context.get("answer_stage") == "reduce" or context.get("kind") == "SUMMARIZE" or call.get("role") == "SUMMARIZE":
        return "assembly"
    named = f"{context.get('report')} {context.get('key')}"
    return "withdrawn_page" if page in named or any(doc in named for doc in doc_ids) else "other_pages"


def tokens(call: dict) -> int:
    usage = call.get("usage") or {}
    return (usage.get("input") or 0) + (usage.get("output") or 0)


def outcomes(folder: pathlib.Path) -> list[dict]:
    calls = rows_of(folder / "calls.jsonl")
    contexts = {c.get("call_id"): c for c in rows_of(folder / "contexts.jsonl")}
    plan = json.loads((folder / "summary.json").read_text(encoding="utf-8")).get("withdrawn") or []
    rows = []
    for arm, name in SIDES:
        side = folder / name
        if not side.is_file():
            continue
        run = json.loads(side.read_text(encoding="utf-8"))
        if (run.get("phase2") or {}).get("status") == "SKIPPED" or not (run.get("phase1") or {}).get("answers"):
            continue
        for step in plan:
            n = step["phase"]
            before, after = (run.get(f"phase{n - 1}") or {}).get("answers") or {}, (run.get(f"phase{n}") or {}).get("answers") or {}
            doc_ids = {q["doc_id"] for a in before.values() for c in a.get("claims") or [] for q in c.get("quotes") or [] if q.get("doc_id") and q.get("report") == step["report"]}
            spent = {"withdrawn_page": 0, "assembly": 0, "other_pages": 0}
            by_model: dict[str, int] = {}
            sent = received = 0
            for call in calls:
                if call.get("phase") == n and call.get("arm") == arm:
                    spent[where(call, contexts.get(call.get("call_id")) or {}, step["report"], doc_ids)] += 1
                    model = call.get("model") or "unknown"
                    by_model[model] = by_model.get(model, 0) + tokens(call)
                    sent += call.get("prompt_bytes") or 0
                    received += len((call.get("text") or "").encode("utf-8"))
            had, has = cited(before), cited(after)
            hit = {q for q in had if touched(q, step)}
            rows.append({"run": folder.name, "side": arm, "step": step["step"], "calls": sum(spent.values()), **spent, "tokens_by_model": dict(sorted(by_model.items())), "bytes_sent": sent, "bytes_received": received,
                         "quotes_before": len(had),
                         "quotes_touched": len(hit), "quotes_untouched_not_cited_after": len((had - hit) - has), "touched_still_cited": len(hit & has)})
    return rows


def by_reader(folder: pathlib.Path) -> list[dict]:
    """On the kernel's side, for each reader and its model: lines sent, records stored, lines and quotes refused, from the run's replies."""
    summary = json.loads((folder / "summary.json").read_text(encoding="utf-8"))
    models = {row["agent"]: row.get("model") for row in summary.get("team") or []}
    rows: dict[str, dict] = {}
    for reply in rows_of(folder / "replies.jsonl"):
        if reply.get("arm") != "C":
            continue
        agent = str(reply.get("agent"))
        row = rows.setdefault(agent, {"run": folder.name, "reader": agent, "model": models.get(agent), "lines_sent": 0, "records_stored": 0, "lines_refused": 0,
                                      "quotes_cut_mid_clause": 0, "quotes_refused_otherwise": 0})
        row["lines_sent"] += reply.get("lines_submitted") or 0
        row["records_stored"] += reply.get("accepted") or 0
        row["lines_refused"] += reply.get("refused") or 0
        for problem in reply.get("problems") or []:
            if (problem.get("needs") or "").startswith("a quote keeps the clause"):
                row["quotes_cut_mid_clause"] += 1
            elif re.fullmatch(r"t\d+_?o\d*", problem.get("local_id") or ""):
                row["quotes_refused_otherwise"] += 1
    return sorted(rows.values(), key=lambda row: row["reader"])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("runs", nargs="+", type=pathlib.Path)
    ap.add_argument("--json", type=pathlib.Path)
    a = ap.parse_args()
    rows = [row for folder in a.runs for row in outcomes(folder) + by_reader(folder)]
    for row in rows:
        print(row)
    if a.json:
        a.json.write_text(json.dumps(rows, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
