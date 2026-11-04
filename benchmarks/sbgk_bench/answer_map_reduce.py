"""Optional bounded report-local A answers, followed by a reduction with byte-checked quotes.

REDUCE="single" sends every partial answer to one reduction call. REDUCE="tree" merges them pairwise in report order, so each
call stays small and a later report meets the earlier one it may change (one 28 KB reduction on Flash timed out twice at 900 s in
run C1n_r1). A merge that fails passes its inputs on as a plain union of their validated claims, and the result says so."""
import hashlib,json,time
from . import answer_guidance as G
PARTIAL_CHARS=5000
PARTIAL_CLAIMS=8
REDUCE="single"
MERGE_CHARS_PER_REPORT=4500

def _own_calls(log,before,prefix):
    """The calls made since `before` whose id starts with `prefix` (single_answer's ids, its timeout retries included): the work's own
    calls, not those of work running at the same time."""
    return sum(1 for c in log.calls[before:] if c.call_id.startswith(prefix))

def _union(nodes):
    claims=[c for n in nodes for c in n["claims"]]
    return {"report":"+".join(n["report"] for n in nodes),"status":"COMPLETE" if all(n["status"]=="COMPLETE" for n in nodes) else "INCOMPLETE",
            "claims":claims,"unsettled":"; ".join(n["unsettled"] for n in nodes if n.get("unsettled")) or None,"error":None}

def partial(log,model,docs,withdrawn,q,phase,rules,name,role,context,notes_by_report,report):
    """One report's partial answer to q (the map step: the runner's lead in report order, or one Send of the LangGraph-native team):
    its row for the sink and the partial the reduction takes, or None when the log had stopped. Its calls are counted by their call
    ids, so partials made at the same time do not count each other's."""
    from . import pilot_ac as P
    text=docs[report]
    digest=hashlib.sha256(report.encode()).hexdigest()[:16]
    if not log.active():
        return {"report":report,"status":"NOT_ATTEMPTED","calls":0,"wall_s":0},None
    corpus=P.team_corpus(notes_by_report.get(report,[]),{report:text}) if notes_by_report is not None else P.single_corpus({report:text})
    report_withdrawn=[w for w in withdrawn if w["report"]==report]
    report_told="".join(f'WITHDRAWN QUOTE: "{w["quote"]}" (report {w["report"]}): a later revision withdraws it.\n' for w in report_withdrawn)
    rules=G.append_to(rules)
    prompt=(f'{corpus}\nANSWER_MAP: answer {q["id"]} for THIS REPORT ONLY.\nQUESTION {q["id"]}: {q["text"]}\n'
            f'{report_told}{rules}\nUse at most eight short claims and fit the entire partial answer in {PARTIAL_CHARS} characters. '
            'State unknown when this report does not settle the question; do not use another report or infer missing facts.')
    map_context=dict(context or {},key=f'answer-map:{q["id"]}:{digest}',report=report,answer_stage="map")
    if notes_by_report is not None:map_context.update({k:v for k,v in P.notes_context(notes_by_report.get(report,[])).items() if k!="notes"})
    before=len(log.calls);started=time.monotonic()
    a=P.single_answer(log,model,prompt,{report:text},report_withdrawn,phase=phase,rq=q["id"],role=role,name=f'{name}-map-{digest}',
        context=map_context,stop_on_model_error=False,max_response_chars=PARTIAL_CHARS,max_claims=PARTIAL_CLAIMS,
        repair_context=f'{corpus}\nQUESTION {q["id"]}: {q["text"]}\n{report_told}')
    prefix=f'A{phase}-{name}-map-{digest}-{q["id"]}-'
    made=[c for c in log.calls[before:] if c.call_id.startswith(prefix)];encoded=json.dumps((a or {}).get("claims") or [],ensure_ascii=False)
    status="NOT_ATTEMPTED" if not made and a is None else "COMPLETE" if a and a.get("complete") and len(encoded)<=PARTIAL_CHARS else "INCOMPLETE"
    row={"report":report,"status":status,"calls":len(made),"prompt_chars":sum(c.prompt_chars for c in made),"reply_chars":sum(len(c.text or "") for c in made),
         "validated_claims_chars":len(encoded),"wall_s":time.monotonic()-started,"answer":a}
    if len(encoded)>PARTIAL_CHARS:row["error"]="PARTIAL_CLAIMS_TOO_LONG; excluded from reduction, retained in artifacts"
    log.event(arm="A",phase=phase,kind="ANSWER_PARTIAL",rq_id=q["id"],**{k:v for k,v in row.items() if k!="answer"})
    return row,{"report":report,"status":status,"claims":a["claims"] if a and len(encoded)<=PARTIAL_CHARS else [],
                "unsettled":(a or {}).get("unsettled"),"error":row.get("error") or (a or {}).get("error")}

def answer(log,model,docs,withdrawn,q,phase,rules,name,role,context,notes_by_report,sink):
    partials=[]
    for report in docs:
        row,part=partial(log,model,docs,withdrawn,q,phase,rules,name,role,context,notes_by_report,report)
        sink.append(row)
        if part is not None:partials.append(part)
    if not log.active():return None
    return reduce(log,model,docs,withdrawn,q,phase,name,role,context,partials,sink)

def reduce(log,model,docs,withdrawn,q,phase,name,role,context,partials,sink,stop_on_model_error=None):
    """The reduction alone, over partial answers already made (`sink` holds their map rows); an offline replay calls it on the
    partials a run saved."""
    from . import pilot_ac as P
    told="".join(f'WITHDRAWN QUOTE: "{w["quote"]}" (report {w["report"]}): a later revision withdraws it.\n' for w in withdrawn)
    missing=[report for report in docs if not any(p["report"]==report and p["status"]=="COMPLETE" for p in partials)]
    reduce_rules=P.SINGLE_RULES.replace("Answer only from the reports above.","Answer only from the validated per-report partial answers above.",1)
    merges=[];mode=getattr(P,"ARM_A_REDUCE",REDUCE)
    if mode=="tree":
        level=0
        while len(partials)>2:
            level+=1;nxt=[]
            for i in range(0,len(partials),2):
                pair=partials[i:i+2]
                if len(pair)==1:nxt.append(pair[0]);continue
                covered={r for n in pair for r in n["report"].split("+")}
                # a merge of four reports needs about 15 000 characters on Flash: a fixed 9 000 refused it five times and it fell
                # back to the union (offline replay of run C1n_r1, RQ1)
                cap=min(P.SINGLE_RESPONSE_CHARS,MERGE_CHARS_PER_REPORT*len(covered))
                mprompt=(f'ARM A ANSWER REDUCE (merge level {level})\n'
                         f'PARTIAL ANSWERS:\n{json.dumps(pair,ensure_ascii=False)}\nEND PARTIAL ANSWERS\nQUESTION {q["id"]}: {q["text"]}\n'
                         f'{told}{reduce_rules}\nMerge the two supplied parts into one answer without adding unsupported facts. '
                         f'Preserve exact report paths and quotes. Fit the answer in {cap} characters.')
                mstart=time.monotonic();mbefore=len(log.calls)
                m=P.single_answer(log,model,mprompt,{r:t for r,t in docs.items() if r in covered},withdrawn,phase=phase,rq=q["id"],role=role,
                    name=f'{name}-merge-L{level}-{i//2}',context=dict(context or {},key=f'answer-merge:{q["id"]}:L{level}:{i//2}',answer_stage="merge"),
                    stop_on_model_error=False,max_response_chars=cap,
                    repair_context=f'PARTIAL ANSWERS:\n{json.dumps(pair,ensure_ascii=False)}\nQUESTION {q["id"]}: {q["text"]}\n{told}',
                    allowed_quotes={(v["report"],v["quote"]) for n in pair for c in n["claims"] for v in c["quotes"]})
                node=_union(pair)
                ok=bool(m) and m.get("complete") and m.get("claims")
                if ok:node.update(claims=m["claims"],unsettled=m.get("unsettled"))
                merges.append({"level":level,"reports":node["report"],"merged":bool(ok),"calls":_own_calls(log,mbefore,f'A{phase}-{name}-merge-L{level}-{i//2}-{q["id"]}-'),"wall_s":time.monotonic()-mstart,
                               "error":None if ok else ((m or {}).get("error") or "merge incomplete: inputs passed on as a union")})
                log.event(arm="A",phase=phase,kind="ANSWER_MERGE",rq_id=q["id"],**merges[-1])
                nxt.append(node)
                if not log.active():return None
            partials=nxt
    payload=json.dumps(partials,ensure_ascii=False)
    prompt=(f'ARM A ANSWER REDUCE\nPARTIAL ANSWERS:\n{payload}\nEND PARTIAL ANSWERS\nQUESTION {q["id"]}: {q["text"]}\n'
            f'{told}{reduce_rules}\nCombine the partial answers without adding unsupported facts. Preserve exact report paths and quotes. '
            'Mention incomplete/missing reports in done text; do not present them as covered.')
    start=time.monotonic();before=len(log.calls)
    final=P.single_answer(log,model,prompt,docs,withdrawn,phase=phase,rq=q["id"],role=role,name=f'{name}-reduce',
        context=dict(context or {},key=f'answer-reduce:{q["id"]}',answer_stage="reduce"),
        # the LangGraph-native team retries a failed reduction with its RetryPolicy before it stops the arm itself
        stop_on_model_error=mode!="tree" if stop_on_model_error is None else stop_on_model_error,
        repair_context=f'PARTIAL ANSWERS:\n{payload}\nQUESTION {q["id"]}: {q["text"]}\n{told}',
        allowed_quotes={(v["report"],v["quote"]) for p in partials for c in p["claims"] for v in c["quotes"]})
    if mode=="tree" and final is not None and not final.get("claims") and final.get("error"):
        u=_union(partials)
        final={"outcome":"answered" if u["claims"] else "unknown","claims":u["claims"],"unsettled":u["unsettled"],"refused_at_end":[],"repairs":0,
               "complete":u["status"]=="COMPLETE","reduce_fallback":f'final merge failed ({final["error"]}); answer is the union of the merged parts'}
    # counted by the reduction's own call ids: two reductions of the native teams run at the same time (Codex review of 70e8d31,
    # NATIVE-02: a global interval gave RQ1 the call of RQ2)
    log.event(arm="A",phase=phase,kind="ANSWER_REDUCE",rq_id=q["id"],prompt_chars=len(prompt),prompt_bytes=len(prompt.encode()),wall_s=time.monotonic()-start,calls=_own_calls(log,before,f'A{phase}-{name}-reduce-{q["id"]}-'),partial_reports=len(partials),missing_reports=missing)
    if final is not None:
        final["partial_reports_missing"]=missing
        final["complete"]=final.get("complete",False) and not missing
        final["map_reduce"]={"partial_reports":len(sink),"partial_calls":sum(r["calls"] for r in sink),"partial_reply_chars":sum(r.get("reply_chars",0) for r in sink),"reduce_prompt_chars":len(prompt),
                             "reduce":mode,"merges":merges}
    return final
