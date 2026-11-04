"""Prepare blinded C1/C0 grading prompts offline, after the owner-authorized runs exist.
No provider call: this command creates a new directory with public prompts and a separate private key.
python benchmarks/prepare_dynamic_comparison.py --c1 RUN --c0 RUN --coverage-items FILE --out NEW_DIR
"""
from __future__ import annotations
import argparse
import hashlib
import json
import pathlib
import random
from sbgk_bench.blind_links import blinded_package, SAMPLE_SEED
from grade_agy_prompt import DEFAULT_GRADER

def load(path):
    return json.loads(path.read_text(encoding="utf-8"))

def answer_prompt(run, docs, coverage):
    arms = {k: load(run / f"arm_{k.lower()}.json") for k in ("A","C")}
    key = load(run / "answers_key.json")
    questions = load(run / "arm_c" / "questions.json")
    text = ["Grade two unnamed systems against the full reports only. Do not guess identity or use tools.",
            "For EVERY numbered claim, give correct / distorted / unsupported / stale / off-topic and a reason.",
            "For each fixed coverage item mark V1 / V2 / both / neither, and append genuine missing items separately.",
            "For each later phase check cumulative withdrawals: no answer may rely only on withdrawn text; preserve other supported facts.",
            "Conclude separately per research question, correctness before coverage. Missing or partial answers remain explicit.",
            "Return Markdown with one claim-verdict table, coverage tables per RQ, withdrawals per phase and RQ, and conclusions.", ""]
    text += ["=== CHECKLIST ===", (run / "checklist.md").read_text(encoding="utf-8"),
             "=== FIXED COVERAGE ITEMS ===", json.dumps(coverage, ensure_ascii=False),
             "=== FULL REPORTS ==="]
    text += [f"=== REPORT {p} ===\n{body}\n=== END REPORT ===" for p,body in sorted(docs.items())]
    counts = {}
    phases = sorted({k for arm in arms.values() for k in arm if k.startswith("phase") and k[5:].isdigit()},key=lambda k:int(k[5:]))
    for phase in phases:
        text += [f"=== {phase} ==="]
        n = int(phase[5:])
        for w in arms["C"].get("withdrawals") or []:
            if w["phase"] <= n:
                text += [f"Withdrawn: {w['report']}: {w['quote']}"]
        for q in questions:
            text += [f"Question {q['id']}: {q['text']}"]
            for label, arm_key in key.items():
                ph = arms[arm_key].get(phase) or {}
                ans = (ph.get("answers") or {}).get(q["id"])
                rows = (ans or {}).get("claims") or []
                text += [f"{label}: {len(rows)} claims"]
                if ans is None:
                    text += ["Answer unavailable; not a zero-error answer."]
                if ph.get("answers_partial") or (ph.get("receipt") or {}).get("status") not in (None,"TERMINAL"):
                    text += ["Partial or nonterminal answer."]
                for i,claim in enumerate(rows,1):
                    cid = f"V{label[-1]}-{n}-{q['id']}-{i}"
                    text += [f"{cid}: {claim['text']}"]
                    text += [f"> [{x['report']}] {x['quote']}" for x in claim.get("quotes") or []]
                if (ans or {}).get("unsettled"):
                    text += [f"Not settled: {ans['unsettled']}"]
                counts[f"{label}/{phase}/{q['id']}"] = len(rows)
    return "\n\n".join(text), {"variants":key,"claim_counts":counts}

def card_origins(arm):
    origins = {}
    for e in arm.get("events") or []:
        if e.get("outcome") != "CARD_SUBMITTED":
            continue
        for result in e.get("operation_results") or []:
            if result.get("link"):
                item = {k:e.get(k) for k in ("card","agent","builder_model","call_id")}
                if item not in origins.setdefault(result["link"],[]):
                    origins[result["link"]].append(item)
    return origins

def prepare(c1, c0, coverage_file, out):
    runs = {"C1":pathlib.Path(c1),"C0":pathlib.Path(c0)}
    summaries = {k:load(p/"summary.json") for k,p in runs.items()}
    heads = {s["provenance"]["git_head"] for s in summaries.values()}
    if len(heads)!=1 or any(s["provenance"]["changed_tracked_files"] for s in summaries.values()):
        raise ValueError("C1/C0 must use the same clean revision")
    if summaries["C1"].get("team") != summaries["C0"].get("team"):
        raise ValueError("C1/C0 must use the same reader models")
    corpora = [s["corpus"] for s in summaries.values()]
    if corpora[0] != corpora[1]:
        raise ValueError("C1/C0 must use identical captured source bytes and section configuration")
    if not summaries["C1"]["dynamic_roles"]["enabled"] or summaries["C0"]["dynamic_roles"]["enabled"]:
        raise ValueError("C1 is dynamic, C0 has the dedicated builder")
    docs = {p:(runs["C1"]/"inputs"/"repo"/p).read_bytes().decode("utf-8") for p in corpora[0]["reports"]}
    # Text decoding above is for prompts. Verify raw bytes independently, without newline normalization.
    for run in runs.values():
        for p, meta in corpora[0]["source_bytes"].items():
            raw=(run/"inputs"/"repo"/p).read_bytes()
            if hashlib.sha256(raw).hexdigest()!=meta["raw_sha256"] or len(raw)!=meta["size_bytes"]:
                raise ValueError(f"captured input changed: {p}")
    arms = {k:load(p/"arm_c.json") for k,p in runs.items()}
    prompt, key = blinded_package({k:v["phase1"]["link_sample"] for k,v in arms.items()},docs)
    for item in key["items"].values():
        arm = arms[item["branch"]]
        sample = arm["phase1"]["link_sample"]
        link = next(l for l in sample["links"] if l["id"]==item["link_id"])
        item["card_origins"] = card_origins(arm).get(link["short"],[])
    order=list(runs)
    random.Random(SAMPLE_SEED).shuffle(order)
    out=pathlib.Path(out)
    out.mkdir(parents=True,exist_ok=False)
    public=out/"public"; private=out/"private"
    public.mkdir(); private.mkdir()
    (public/"links_prompt.md").write_text(prompt,encoding="utf-8",newline="\n")
    coverage=load(pathlib.Path(coverage_file))
    answers={}
    for i,k in enumerate(order,1):
        text,answer_key=answer_prompt(runs[k],docs,coverage)
        name=f"answers_packet_{i}"
        (public/f"{name}_prompt.md").write_text(text,encoding="utf-8",newline="\n")
        answers[name]={"branch":k,**answer_key}
    result={"revision":next(iter(heads)),"links":key,"answers":answers,
            "link_judge":f"agy:{DEFAULT_GRADER}","answer_judge":f"agy:{DEFAULT_GRADER}",
            "warning":"Accepted is not correct. Dynamic roles and builder model both change; report the two factors.",
            "card_quality":"Join judge verdicts through private link origins; disclose missing or multiple origins, never guess a model."}
    (private/"key.json").write_text(json.dumps(result,indent=1),encoding="utf-8",newline="\n")
    return result

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for k in ("c1","c0","coverage-items","out"):
        ap.add_argument("--"+k,type=pathlib.Path,required=True)
    a=ap.parse_args()
    prepare(a.c1,a.c0,a.coverage_items,a.out)
    print(json.dumps({"prepared":str(a.out),"model_calls":0}))
if __name__=="__main__":
    main()
