"""Make the YuCe Live page of a journal: one HTML file that plays a recorded run back frame by frame.

The states on the page come from the kernel, read from the journal by the binary:
- `sbgk audit-verify` checks the journal first; a journal that does not verify gets no page;
- `sbgk audit-prov` gives the records, what each rests on, and the periods in which each stood, with the frame and the reason
  that ended a period;
- `sbgk audit-read coverage`, run on the first frames of the journal, gives the coverage table at a frame.

At frame N a record handed in by then stands while a period of it holds frame N; it fell, was withdrawn, went with its bytes to a
new version of its document, or (an answer) is no longer supported by grounds that still stand, when its last period ended; and it
never stood when the kernel gave it no period. The generator
compares this with `sbgk audit-prov --upto N+1`, the export of the first frames alone: with --check all (the default for a
journal of up to 200 frames and records) at every frame, with --check seals at every seal, every frame where a record's period
ended, and the last frame. A difference stops it with exit code 1. --states FILE writes the kernel's states at the compared
frames, for check_states.mjs, which runs the page's own script on them.

usage: python make_page.py --wal run.wal --out page.html [--bin path/to/sbgk] [--docs folder] [--note text]
                           [--check all|seals|none] [--coverage all|seals] [--states states.json]
--docs is the folder the documents were read from (the repository of a git manifest, or the folder of an opaque run): with it,
each quote is shown in its line of the document, after the document's SHA-256 is checked against the journal.
--note is a sentence about the run shown at the top of the page, such as how a withdrawal in it was chosen.
It exits 0 when the page is written, 1 when the journal or a check fails, 2 on a usage error. Python 3.10+, standard library only."""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import unquote

HERE = pathlib.Path(__file__).resolve().parent
TEMPLATE = HERE / "page.html"
FORMAT = "yuce-live-journal/1"
# the kernel's eight coverage statuses, folded into six cells on the page
COVERAGE = {"quoted": "q", "empty": "e", "second_reading_pending": "p", "second_reading_failed": "p", "pack_failed": "p",
            "left_by_budget": "b", "withdrawn": "w", "unread": "n"}
LABEL = {"observe": "q", "claim": "c", "hypothesis": "h", "done": "A"}
SMALL = 200  # up to this many frames and records a journal is short: checked, and its coverage taken, at every frame


def find_binary(given: str | None) -> pathlib.Path:
    if given:
        return pathlib.Path(given)
    repo = HERE.parent.parent
    target = pathlib.Path(os.environ.get("CARGO_TARGET_DIR") or repo / "target")
    for name in ("sbgk.exe", "sbgk"):
        candidate = (target if target.is_absolute() else repo / target) / "release" / name
        if candidate.is_file():
            return candidate
    found = shutil.which("sbgk") or shutil.which("yuce")
    if found:
        return pathlib.Path(found)
    sys.exit("no sbgk binary: build it with `cargo build --release` or pass --bin")


class Kernel:
    def __init__(self, binary: pathlib.Path, work: pathlib.Path):
        self.binary, self.work = binary, work

    def run(self, *args: str, ok=(0,)) -> dict:
        out = subprocess.run([str(self.binary), *args], capture_output=True, text=True, encoding="utf-8")
        if out.returncode not in ok:
            raise SystemExit(f"sbgk {args[0]} failed ({out.returncode}): {(out.stdout or out.stderr).strip()[:600]}")
        return json.loads(out.stdout)

    def prov(self, wal: pathlib.Path, upto: int | None = None) -> list:
        out = self.work / "export.jsonld"
        args = ["audit-prov", "--wal", str(wal), "--out", str(out)] + (["--upto", str(upto)] if upto is not None else [])
        self.run(*args)
        graph = json.loads(out.read_text(encoding="utf-8"))["@graph"]
        out.unlink()
        return graph

    def coverage(self, frames: list, upto: int) -> dict:
        prefix = self.work / "prefix.wal"
        prefix.write_bytes(b"".join(frames[:upto]))
        try:
            table = self.run("audit-read", "coverage", "--wal", str(prefix), "--limit", "100000000")
        finally:
            prefix.unlink()
        if table.get("truncated"):
            raise SystemExit(f"the coverage table at frame {upto - 1} came back cut")
        return table


def tail(iri: str) -> str:
    return unquote(iri.rsplit(":", 1)[1])


def frame_of(iri: str) -> int:
    return int(tail(iri))


def body_of(line: bytes) -> dict:
    """The frame's entry: `body` in a journal of format /3, `payload` in the older ones."""
    frame = json.loads(line)
    return frame["body"] if "body" in frame else frame.get("payload") or {}


def kernel_states(graph: list) -> dict:
    """record id -> [state, frame that ended its last period, reason, [ids it fell by]] for every record of the export.
    The state is "stands" while a period of it holds, "ended" when its last period ended, "never" when it has no period."""
    nodes = {n["@id"]: n for n in graph}
    periods = {}
    for n in graph:
        if "yuce:Standing" in n["@type"]:
            periods.setdefault(tail(n["prov:specializationOf"]), []).append(n)
    state = {}
    for rid in (n["yuce:recordId"] for n in graph if "yuce:Record" in n["@type"]):
        ps = periods.get(rid, [])
        if not ps:
            state[rid] = ["never", None, None, []]
        elif any("prov:wasInvalidatedBy" not in p for p in ps):
            state[rid] = ["stands", None, None, []]
        else:
            last = max(ps, key=lambda p: frame_of(p["prov:wasInvalidatedBy"]))
            why = nodes[last["prov:qualifiedInvalidation"]]
            state[rid] = ["ended", frame_of(last["prov:wasInvalidatedBy"]), why["yuce:reason"],
                          sorted(tail(x) for x in why.get("yuce:fallenBy", []))]
    return state


def page_state(periods: list, born: int, f: int) -> list | None:
    """What the page shows for one record at frame f, from its periods [from, to, reason, by]; None before it was handed in."""
    if born > f:
        return None
    ps = [p for p in periods if p[0] <= f]
    if not ps:
        return ["never", None, None, []]
    p = ps[-1]
    return ["stands", None, None, []] if p[1] is None or p[1] > f else ["ended", p[1], p[2], p[3]]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--wal", required=True, type=pathlib.Path, help="the journal")
    ap.add_argument("--out", required=True, type=pathlib.Path, help="the page to write")
    ap.add_argument("--bin", help="path to the sbgk (or yuce) binary")
    ap.add_argument("--docs", type=pathlib.Path, help="the folder the documents were read from, to show each quote in its line")
    ap.add_argument("--note", help="a sentence about the run, shown at the top of the page")
    ap.add_argument("--check", choices=("all", "seals", "none"), help="where to compare the page with audit-prov --upto")
    ap.add_argument("--coverage", choices=("all", "seals"), help="at which frames to take the coverage table")
    ap.add_argument("--states", type=pathlib.Path, help="write the kernel's states at the compared frames to this file")
    a = ap.parse_args()
    if a.out.resolve() == a.wal.resolve():
        print("--out is the journal itself", file=sys.stderr)
        return 2
    binary = find_binary(a.bin)
    with tempfile.TemporaryDirectory(prefix="yuce_live_") as tmp:
        return build(a, Kernel(binary, pathlib.Path(tmp)))


def build(a, kernel: Kernel) -> int:
    verify = kernel.run("audit-verify", "--wal", str(a.wal), ok=(0, 1))
    if verify.get("status") != "VERIFIED":
        print(f"the journal does not verify: {verify.get('status')} {verify.get('message', '')}", file=sys.stderr)
        return 1
    frames = a.wal.read_bytes().splitlines(keepends=True)
    if len(frames) != verify["entries"]:
        print(f"the journal has {len(frames)} lines and audit-verify read {verify['entries']} frames", file=sys.stderr)
        return 1
    bodies = [body_of(f) for f in frames]
    last = len(frames) - 1
    graph = kernel.prov(a.wal)
    nodes = {n["@id"]: n for n in graph}
    records = {n["yuce:recordId"]: n for n in graph if "yuce:Record" in n["@type"]}
    genesis = bodies[0]
    version = subprocess.run([str(kernel.binary), "--version"], capture_output=True, text=True).stdout.strip()

    # documents: every document of the export (those put during the run included), in the order of their names
    final_cov = kernel.coverage(frames, last + 1)
    has_cov = final_cov.get("available") is not False
    sources = genesis.get("source_documents") or {}
    doc_ids = {n["yuce:docId"] for n in graph if "yuce:Document" in n["@type"]} | set(sources)
    names = {d: ((sources.get(d) or {}).get("path") or d) for d in doc_ids}
    order = sorted(doc_ids, key=lambda d: (names[d], d))
    docs, did = [], {}
    for i, d in enumerate(order, 1):
        did[d] = f"D{i}"
        units = sorted((r["start"], r["end"]) for r in final_cov.get("rows", []) if r["doc_id"] == d)
        docs.append({"id": f"D{i}", "doc_id": d, "name": names[d], "units": len(units), "spans": units})
    texts, unchecked = {}, []
    if a.docs:
        for d in order:
            path = a.docs / names[d]
            data = path.read_bytes() if path.is_file() else None
            if data is not None and d in sources and hashlib.sha256(data).hexdigest() == sources[d].get("raw_sha256"):
                texts[d] = data
            else:
                unchecked.append(names[d])

    # labels in the order the records were handed in: frame, then their place among the frame's lines
    def place(n):
        cmd = bodies[frame_of(n["prov:wasGeneratedBy"])].get("command") or {}
        for i, line in enumerate(cmd.get("lines") or []):
            if line.get("kind") == n["yuce:kind"] and (n["yuce:kind"] == "done" or line.get("exact_quote", line.get("text")) == n.get("prov:value")):
                return i
        return 1 << 20
    ordered = sorted((n for n in records.values() if n["yuce:kind"] in LABEL),
                     key=lambda n: (frame_of(n["prov:wasGeneratedBy"]), place(n), n["yuce:recordId"]))
    label, count = {}, {}
    for n in ordered:
        p = LABEL[n["yuce:kind"]]
        count[p] = count.get(p, 0) + 1
        label[n["yuce:recordId"]] = f"{p}{count[p]}"
    short = {"@" + rid[:16]: lab for rid, lab in label.items()}

    # the question of each answer: the kernel's checkpoint of the answer task names it, else the done line handed in with it
    question_of = {}
    for body in bodies:
        ctx = ((body.get("command") or {}).get("checkpoint") or {}).get("context") or {}
        if ctx.get("done") and ctx.get("rq_id"):
            question_of[ctx["done"]] = ctx["rq_id"]
    for rid, n in records.items():
        if n["yuce:kind"] == "done" and rid not in question_of:
            lines = (bodies[frame_of(n["prov:wasGeneratedBy"])].get("command") or {}).get("lines") or []
            asked = [x.get("rq_id") for x in lines if x.get("kind") == "done"]
            if len(asked) == 1:
                question_of[rid] = asked[0]

    quotes, recs, answer_parts = {}, {}, {}
    for n in ordered:
        rid, kind, lab = n["yuce:recordId"], n["yuce:kind"], label[n["yuce:recordId"]]
        f, by = frame_of(n["prov:wasGeneratedBy"]), tail(n["prov:wasAttributedTo"])
        value = n.get("prov:value", "")
        if kind == "observe":
            d = unquote(n["prov:wasQuotedFrom"].split(":version:", 1)[1].rsplit(":", 2)[0])
            a_, b_ = n["yuce:start"], n["yuce:end"]
            q = {"d": did.get(d), "a": a_, "b": b_, "by": by, "f": f, "kid": "@" + rid[:16], "hit": value}
            data = texts.get(d)
            if data is not None and data[a_:b_].decode("utf-8", "replace") == value:
                start = max(data.rfind(b"\n", 0, a_) + 1, a_ - 240)
                end = data.find(b"\n", b_)
                end = min(end if end >= 0 else len(data), b_ + 240)
                q["pre"] = data[start:a_].decode("utf-8", "ignore")
                q["post"] = data[b_:end].decode("utf-8", "ignore")
            quotes[lab] = q
        else:
            on = [label[tail(x)] for x in n.get("prov:wasDerivedFrom", []) if tail(x) in label]
            r = {"k": {"claim": "claim", "hypothesis": "hypothesis", "done": "answer"}[kind], "f": f, "by": by, "on": on,
                 "kid": "@" + rid[:16]}
            if kind == "done":
                r["q"] = question_of.get(rid, "?")
                r["note"] = value
                for c in on:
                    answer_parts.setdefault(c, []).append(lab)
            else:
                r["t"] = value
            recs[lab] = r
    for lab, r in recs.items():
        if r["k"] == "answer":
            r["on"].sort(key=lambda c: int(c[1:]) if c[1:].isdigit() else 0)
        elif lab in answer_parts:
            r["part"] = answer_parts[lab]

    # periods: [from, to or null, reason or null, [labels it fell by]]; a record the kernel gave no period has none
    key = lambda x: (x[0], int(x[1:]) if x[1:].isdigit() else 0)
    periods = {lab: [] for lab in label.values()}
    for n in graph:
        if "yuce:Standing" in n["@type"]:
            rid = tail(n["prov:specializationOf"])
            if rid not in label:
                continue
            end = n.get("prov:wasInvalidatedBy")
            why = nodes[n["prov:qualifiedInvalidation"]] if end else {}
            periods[label[rid]].append(
                [frame_of(n["prov:wasGeneratedBy"]), frame_of(end) if end else None, why.get("yuce:reason"),
                 sorted((label[tail(x)] for x in why.get("yuce:fallenBy", []) if tail(x) in label), key=key)])
    for ps in periods.values():
        ps.sort(key=lambda p: (p[0], p[1] if p[1] is not None else 1 << 62))
    born = {label[rid]: frame_of(records[rid]["prov:wasGeneratedBy"]) for rid in label}

    # frames: who wrote it, what kind, the task the kernel closed, what it made and what it ended
    made, ended = {}, {}
    for lab, ps in periods.items():
        for p in ps:
            if p[1] is not None:
                ended.setdefault(p[1], []).append(lab)
    for lab, f in born.items():
        made.setdefault(f, []).append(lab)
    seal_no = {frame_of(n["prov:wasGeneratedBy"]): n for n in graph if "yuce:Seal" in n["@type"]}
    sealed = {f: i for i, f in enumerate(sorted(seal_no), 1)}
    out_frames = [{"a": "kernel", "k": "genesis"}]
    for f in range(1, last + 1):
        body = bodies[f]
        cmd = body.get("command") or {}
        e = {"a": body.get("actor"), "k": cmd.get("kind") or ("checkpoint" if "checkpoint" in cmd else "entry")}
        cp = cmd.get("checkpoint")
        if cp and cp.get("key", "").startswith("task:"):
            what = cp["key"][5:]
            ctx = cp.get("context") or {}
            if what.startswith("doc:"):
                d = what[4:].split("#", 1)[0]
                e["task"] = {"read": did.get(d, d), "by": ctx.get("agent")}
            elif what.startswith("rq:"):
                kept = (ctx.get("composition") or {}).get("retained_answer_ids", [])
                e["task"] = {"answer": what[3:], "by": ctx.get("agent"), "kept": [short[x] for x in kept if x in short]}
            else:
                e["task"] = {"other": what.split(":", 1)[0], "by": ctx.get("agent")}
        elif cp and cp.get("key") == "audit:mcp:coverage":
            e["k"] = "open"
        if f in made:
            e["made"] = sorted(made[f], key=key)
        if f in ended:
            e["ended"] = sorted(ended[f], key=key)
        if f in sealed:
            e["seal"] = sealed[f]
            e["root"] = seal_no[f].get("yuce:auditRoot", "")[:16]
        out_frames.append(e)

    # the kernel's coverage table at the frames the page shows it, when the kernel keeps one for the run
    small = last + 1 <= SMALL and len(label) <= SMALL
    marks = sorted(set(sealed) | set(ended) | {last})
    coverage = []
    if has_cov:
        cov_at = list(range(0, last + 1)) if (a.coverage or ("all" if small else "seals")) == "all" else [0] + marks
        for f in cov_at:
            table = final_cov if f == last else kernel.coverage(frames, f + 1)
            cells = {}
            for d in docs:
                rows = sorted((r for r in table.get("rows", []) if r["doc_id"] == d["doc_id"]), key=lambda r: r["start"])
                cells[d["id"]] = "".join(COVERAGE.get(r["status"], "p") for r in rows) if rows else "n" * d["units"]
            coverage.append({"at": f, "cells": cells})

    # the check: at each chosen frame, the page's reading of the periods gives what the export of the first frames alone gives
    check = a.check or ("all" if small else "seals")
    at = [] if check == "none" else list(range(0, last + 1)) if check == "all" else marks
    states = {}
    for f in at:
        got = {label[r]: [s, e, why, sorted((label[x] for x in by if x in label), key=key)]
               for r, (s, e, why, by) in kernel_states(kernel.prov(a.wal, f + 1)).items() if r in label}
        want = {lab: st for lab in label.values() if (st := page_state(periods[lab], born[lab], f)) is not None}
        if got != want:
            diff = sorted(k for k in set(got) | set(want) if got.get(k) != want.get(k))[:8]
            print(f"frame {f}: the page and audit-prov --upto {f + 1} differ on {diff}", file=sys.stderr)
            return 1
        states[f] = got

    questions = [{"id": q["id"], "text": q.get("text", "")} for q in genesis.get("questions") or []]
    data = {"format": FORMAT, "run": genesis.get("run_id"), "kernel": version, "note": a.note or "", "big": not small,
            "verify": {k: verify.get(k) for k in ("status", "entries", "records", "audit_root", "engine_root", "wal_head")},
            "docs": [{k: d[k] for k in ("id", "name", "units")} for d in docs], "docs_shown": bool(texts),
            "docs_unchecked": unchecked, "questions": questions,
            "frames": out_frames, "quotes": quotes, "recs": recs, "periods": periods, "coverage": coverage,
            "coverage_note": "" if has_cov else (final_cov.get("reason") or final_cov.get("message") or "the kernel keeps no coverage table for this run"),
            "checked": {"frames": len(at), "all": check == "all"},
            "not_shown": {k: v for k, v in {"question": sum(1 for n in records.values() if n["yuce:kind"] == "question")}.items() if v}}
    if a.states:
        a.states.write_text(json.dumps({"frames": {str(f): s for f, s in states.items()}}), encoding="utf-8")
    script_safe = json.dumps(data, ensure_ascii=True).replace("<", "\\" + "u003c")
    page = TEMPLATE.read_text(encoding="utf-8").replace("/*DATA*/null", script_safe)
    partial = a.out.with_name(a.out.name + ".partial")
    partial.write_text(page, encoding="utf-8", newline="\n")
    os.replace(partial, a.out)
    print(json.dumps({"status": "WRITTEN", "out": str(a.out), "frames": last, "records": len(recs) + len(quotes),
                      "checked_frames": len(at), "coverage_frames": len(coverage), "docs_shown": bool(texts), "docs_unchecked": unchecked}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
