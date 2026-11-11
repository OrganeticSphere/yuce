"""What a withdrawal cost and what it took with it, counted from a run's files with no model and no judgement.

For each side of a run folder and each withdrawal:

  calls           model calls after the withdrawal, split into the withdrawn page, the assembly of the answer, and other pages
  tokens          the tokens of those calls for each model apart: each model cuts text its own way, so its tokens are its own unit
  bytes           the bytes of those prompts and replies, the one size common to every model
  quotes          the quotes the answers of the stage before cited, split into those the withdrawal touched and the others;
                  of the others, how many the answers after it no longer cite: the collateral

on the kernel's side, the quotes the journal took after the withdrawal that still touch the withdrawn text, which has to be 0,
and for each reader and its model, the lines it sent, the quotes stored and the quotes refused by reason.

A quote is touched when it is in the withdrawn page and overlaps the withdrawn text, partly or wholly: both are found in the page's bytes
under the run's inputs, and a side whose page is missing there sees only containment, which `page_found` says. A call is on the withdrawn page when its context
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


def spans(text: str, page: str) -> list[tuple[int, int]]:
    found, at = [], page.find(text) if text else -1
    while at >= 0:
        found.append((at, at + len(text)))
        at = page.find(text, at + 1)
    return found


def touched(quote: tuple[str, str], withdrawn: dict, page: str | None = None) -> bool:
    report, text = quote
    if report != withdrawn["report"]:
        return False
    if text in withdrawn["quote"] or withdrawn["quote"] in text:
        return True
    return any(a < d and c < b for a, b in spans(text, page or "") for c, d in spans(withdrawn["quote"], page or ""))


def page_of(folder: pathlib.Path, report: str) -> str | None:
    path = folder / "inputs" / "repo" / report
    return path.read_bytes().decode("utf-8") if path.is_file() else None


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
            page = page_of(folder, step["report"])
            hit = {q for q in had if touched(q, step, page)}
            rows.append({"run": folder.name, "side": arm, "step": step["step"], "calls": sum(spent.values()), **spent, "tokens_by_model": dict(sorted(by_model.items())), "bytes_sent": sent, "bytes_received": received,
                         "page_found": page is not None, "quotes_before": len(had),
                         "quotes_touched": len(hit), "quotes_untouched_not_cited_after": len((had - hit) - has), "touched_still_cited": len(hit & has),
                         **({"withdrawn_text_stored_after": stored_after_withdrawal(folder, step, page)} if arm == "C" else {})})
    return rows


def quotes_stored(folder: pathlib.Path) -> dict[str, int] | None:
    """The quotes each author got stored, from the journal: the accepted records of a submission are the first of its lines."""
    journal = folder / "arm_c" / "run.wal"
    if not journal.is_file():
        return None
    stored: dict[str, int] = {}
    for frame in rows_of(journal):
        entry = (frame.get("payload") or frame.get("body") or {})
        command = entry.get("command") or {}
        if command.get("kind") == "submit":
            accepted = ((entry.get("outcome") or {}).get("result") or {}).get("accepted") or []
            quotes = sum(line.get("kind") == "observe" for line in (command.get("lines") or [])[:len(accepted)])
            stored[entry["actor"]] = stored.get(entry["actor"], 0) + quotes
    return stored


def stored_after_withdrawal(folder: pathlib.Path, step: dict, page: str | None) -> int | None:
    """The quotes the journal took after this withdrawal that touch its text: a wider quote must not bring it back. The withdrawal is
    the first command that withdrew the text or a stored quote touching it; a journal that did neither has no after."""
    journal = folder / "arm_c" / "run.wal"
    if not journal.is_file():
        return None
    frames = rows_of(journal)
    paths = {doc: identity.get("path") for doc, identity in ((((frames[0].get("payload") or frames[0].get("body") or {})).get("source_documents") or {}).items())} if frames else {}
    quotes: dict[str, tuple[str, str]] = {}
    after: int | None = None
    for frame in frames[1:]:
        entry = (frame.get("payload") or frame.get("body") or {})
        command = entry.get("command") or {}
        if command.get("kind") == "revoke" and after is None and command.get("record") in quotes and touched(quotes[command["record"]], step, page):
            after = 0
        if command.get("kind") == "revoke_text" and after is None and touched((paths.get(command.get("doc_id")), command.get("exact_quote") or ""), step, page):
            after = 0
        if command.get("kind") == "submit":
            accepted = ((entry.get("outcome") or {}).get("result") or {}).get("accepted") or []
            for line, record in zip(command.get("lines") or [], accepted):
                if line.get("kind") == "observe":
                    quote = (paths.get(line.get("doc_id"), line.get("doc_id")), line.get("exact_quote") or "")
                    quotes[record] = quote
                    if after is not None and touched(quote, step, page):
                        after += 1
    return after


def by_reader(folder: pathlib.Path) -> list[dict]:
    """On the kernel's side, for each reader and its model: lines sent, records and quotes stored, lines and quotes refused."""
    summary = json.loads((folder / "summary.json").read_text(encoding="utf-8"))
    quotes = quotes_stored(folder)
    models = {row["agent"]: row.get("model") for row in summary.get("team") or []}
    rows: dict[str, dict] = {}
    for reply in rows_of(folder / "replies.jsonl"):
        if reply.get("arm") != "C":
            continue
        agent = str(reply.get("agent"))
        row = rows.setdefault(agent, {"run": folder.name, "reader": agent, "model": models.get(agent), "lines_sent": 0, "records_stored": 0,
                                      "quotes_stored": None if quotes is None else quotes.get(agent, 0), "lines_refused": 0,
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
