"""Execute ONE prepared blind grading prompt via Antigravity, only after the owner's launch command.
Give only a public prompt file, never the directory holding the private variant key. No retries; price stays unknown.
"""
from __future__ import annotations
import argparse
import dataclasses
import hashlib
import json
import pathlib
import time
from sbgk_bench import pilot_ac as P

DEFAULT_GRADER = "gemini-4-argon-medium"

def grade(prompt: pathlib.Path, model_id: str, out: pathlib.Path):
    raw=prompt.read_bytes()
    text=raw.decode("utf-8")
    # Reserve before the call, so an existing grading cannot silently be retried or overwritten.
    out.mkdir(parents=True,exist_ok=False)
    (out/"status.json").write_text(json.dumps({"status":"CALL_PENDING","judge_model":f"agy:{model_id}"}),encoding="utf-8")
    model=P.AgyModel(model_id)
    call=P.call_model(model,text,call_id="blind-grading-1",arm="-",role="GRADER",phase=0)
    record=dataclasses.asdict(call)
    record["prompt_sha256"]=hashlib.sha256(raw).hexdigest()
    record["model_config"]=model.config
    record["judge_model"]=f"agy:{model_id}"
    (out/"call.json").write_text(json.dumps(record,ensure_ascii=False,indent=1),encoding="utf-8",newline="\n")
    (out/"grading.md").write_text(call.text,encoding="utf-8",newline="\n")
    (out/"status.json").write_text(json.dumps({"status":"ANSWERED" if call.ok else "FAILED","error":call.error,"judge_model":record["judge_model"]}),
                                  encoding="utf-8",newline="\n")
    if not call.ok:
        raise RuntimeError(call.error)
    return record

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--prompt",type=pathlib.Path,required=True)
    ap.add_argument("--model",default=DEFAULT_GRADER,help="exact Antigravity model id (without agy: prefix)")
    ap.add_argument("--out",type=pathlib.Path,required=True)
    a=ap.parse_args()
    result=grade(a.prompt,a.model,a.out)
    print(json.dumps({"ok":result["ok"],"out":str(a.out),"judge_model":result["judge_model"],"usage":result["usage"],"cost_usd":result["cost_usd"]}))
if __name__=="__main__":
    main()
