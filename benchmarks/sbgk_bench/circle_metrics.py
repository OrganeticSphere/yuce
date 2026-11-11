"""Circle telemetry from durable phase/card checkpoints and task outcomes. Acceptance is not semantic correctness."""
from __future__ import annotations
import collections
import json
from pathlib import Path
from xml.sax.saxutils import escape


def jsonl_prefix(path: Path, warnings: list[str]):
    """Read durable complete frames; an unfinished final write is explicitly excluded."""
    if not path.exists():
        warnings.append(f"{path.name}: not available")
        return
    with path.open("rb") as f:
        for raw in f:
            if not raw.strip():
                continue
            try:
                yield json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                if not raw.endswith(b"\n"):
                    warnings.append(f"{path.name}: incomplete trailing frame ignored")
                    return
                raise


def builder_empty_counts(events: list[dict], circle: int, phase: str = "BUILD") -> dict:
    counts = collections.defaultdict(collections.Counter)
    assignments = collections.defaultdict(set)
    for e in events:
        if e.get("circle") != circle or e.get("circle_phase") != phase or e.get("kind") != "BUILD":
            continue
        model = e.get("builder_model") or "unknown"
        if e.get("outcome") == "CARD_ASSIGNED":
            assignments[model].add(e.get("task") or (e.get("agent"), e.get("card")))
        if e.get("model_invoked") is True:
            c = counts[model]
            c["finished_model_attempts"] += 1
            c["empty_model_answers"] += e.get("explicit_empty") is True
            if e.get("outcome") == "CARD_DONE":
                c["closed_without_operations"] += e.get("closed_without_operations") is True
                c["closed_without_operations_unknown"] += "closed_without_operations" not in e
        elif e.get("model_invoked") is False and e.get("outcome") == "CARD_DONE":
            counts[model]["automatic_no_model_closes"] += 1
    for model, tasks in assignments.items():
        counts[model]["assignments"] = len(tasks)
    return {model: dict(c) for model,c in sorted(counts.items())}

def anomaly_counts(events, circle):
    relevant=[e for e in events if e.get("circle")==circle and e.get("circle_phase")=="BUILD"]
    cards={e.get("card") for e in relevant if e.get("ontology_anomaly") and e.get("card")}
    proposals=[r for e in relevant if e.get("ontology_anomaly") for r in e.get("operation_decisions") or [] if r.get("op")=="revise_concept"]
    proposal_ids=set()
    for event in relevant:
        if not event.get("ontology_anomaly"):continue
        for result in event.get("operation_results") or []:
            if result.get("op")=="revise_concept" and result.get("status")=="pending" and result.get("proposal"):
                proposal_ids.add(result["proposal"])
    return {"distinct_revision_proposals":len(proposal_ids),"revision_proposal_ids":sorted(proposal_ids),
            "distinct_hint_cards":len(cards),
            "revise_submissions_by_decision":dict(collections.Counter(r.get("decision","unknown") for r in proposals)),
            "unit":"distinct card IDs; revise submissions include retries, not unique proposals"}


def circle_metrics(wal: Path, events: list[dict], agent_models: dict[str,str] | None = None, *, frames=None) -> dict:
    boundaries=[]
    cards=collections.defaultdict(lambda:collections.Counter())
    reuses=collections.Counter()
    prior_reuses={}
    current=None
    reviews=[]
    source_warnings=[]
    for frame in (frames if frames is not None else jsonl_prefix(wal, source_warnings)):
        p=(frame.get("payload") or frame.get("body") or {})
        cmd=p.get("command") or {}
        ck=cmd.get("checkpoint") or {}
        ctx=ck.get("context") or {}
        result=(p.get("outcome") or {}).get("result") or {}
        for item in result.get("results") or []:
            if item.get("op")=="ontology_review" or item.get("review_decision")=="revise":
                reviews.append({"review_id":item.get("review_id"),"concept":item.get("concept") or (item.get("change") or {}).get("concept"),
                                "circle":item.get("circle"),"decision":item.get("decision") or item.get("review_decision"),
                                "subject":item.get("subject"),"basis":item.get("basis"),"reason":item.get("reason"),"proposal":item.get("proposal")})
        if not result.get("checkpointed"):
            continue
        if ck.get("key")=="audit:circles" and ctx.get("format")=="r2r-circles/1":
            current=(ctx["circle"],ctx["circle_phase"])
            boundaries.append(ctx)
        elif str(ck.get("key","")).startswith("builder:pool:closed:"):
            if ctx.get("circle_phase")=="BUILD":
                cards[ctx["circle"]][ctx.get("build_agent","unknown")]+=1
        elif str(ck.get("key","")).startswith("builder:reuse:"):
            key=ck["key"]
            hashes=set((ctx.get("receipts") or {}).keys())
            new=hashes-prior_reuses.get(key,set())
            prior_reuses[key]=hashes
            if current and current[1] in ("READ","BUILD"):
                reuses[current[0]]+=len(new)
    rows=[]
    for n in sorted({b["circle"] for b in boundaries if b["circle_phase"]=="READ"}):
        read=next(b for b in boundaries if b["circle"]==n and b["circle_phase"]=="READ")
        build=next((b for b in boundaries if b["circle"]==n and b["circle_phase"]=="BUILD"),None)
        end=next((b for b in boundaries if (b["circle"]>n and b["circle_phase"]=="READ") or
                  (b["circle"]==n and b["circle_phase"]=="FINAL")),None)
        def duration(a,b):
            if not a or not b or b["started_unix_ms"]<a["started_unix_ms"]:
                return None
            return (b["started_unix_ms"]-a["started_unix_ms"])/1000
        assigned={e["task"] for e in events if e.get("circle")==n and e.get("circle_phase")=="READ" and
                  e.get("outcome")=="TASK_ASSIGNED" and e.get("kind") in ("EXTEND","REQUEST")}
        task_events=[e for e in events if e.get("circle")==n and e.get("circle_phase")=="READ" and
                     e.get("kind") in ("EXTEND","REQUEST") and "lines_offered" in e]
        completed={e["task"] for e in task_events}
        offered=sum(e["lines_offered"] for e in task_events)
        stored=sum(e["lines_stored"] for e in task_events)
        first,last=read.get("snapshot") or {},(end or {}).get("snapshot") or {}
        def delta(key):
            return last.get(key,0)-first.get(key,0) if end and key in first and key in last else None
        idle = {"READ": {}, "BUILD": {}}
        for phase, begin, finish in (("READ",read,build),("BUILD",build,end)):
            if not begin or not finish:
                continue
            low, high = begin["started_unix_ms"]/1000, finish["started_unix_ms"]/1000
            for event in events:
                if event.get("kind") != "IDLE_WAIT":
                    continue
                a, b = event["start_unix_s"], event["end_unix_s"]
                if b < a:
                    continue
                seconds = max(0.0, min(b,high)-max(a,low))
                if seconds:
                    agent = event["agent"]
                    idle[phase][agent] = idle[phase].get(agent,0.0)+seconds
        from .agent_matrix import matrices
        matrix=matrices(events,agent_models or {},n)
        rows.append({"circle":n,"closed":bool(end),"read_s":duration(read,build),"build_s":duration(build,end),
                     "reading":{"offered":offered,"stored":stored,"acceptance":stored/offered if offered else None,
                                "unit":"distinct local_id per completed reading lease, across that lease's repairs",
                                "completed_leases":len(completed),"unfinished_leases":sorted(assigned-completed),
                                "repairs":sum(e["repairs"] for e in task_events),
                                "with_refusals":sum(bool(e.get("repairs") or e.get("error") or e.get("abandoned")) for e in task_events)},
                     "concepts_new":delta("concepts"),"concepts_reused":reuses[n],
                     "concepts_across_reports":last.get("concepts_across_reports") if end else None,
                     "concepts_across_reports_delta":delta("concepts_across_reports"),
                     "links_new_distinct":delta("links_total"),"links_accepted_delta":delta("links_accepted"),
                     "links_rejected_delta":delta("links_rejected"),"snapshot_start":first,"snapshot_end":last if end else None,
                     "cards_by_agent":dict(cards[n]),"idle_s_by_agent":idle,"model_matrix":matrix,
                     "ontology_anomalies":anomaly_counts(events,n),"ontology_reviews":[r for r in reviews if r["circle"]==n],
                     "builder_cards_by_model":builder_empty_counts(events,n)})
    return {"definition":"Structural line acceptance, not semantic accuracy; unknown denominators stay null. Final work is separate.",
            "concepts_reused_definition":"new durable bindings of propose_concept to existing concepts",
            "time_definition":"wall-clock checkpoint boundaries; restart downtime included; backwards clock gives null",
            "idle_definition":"acquire RPC and poll backoff intervals intersected with durable phase boundaries; model execution excluded",
            "empty_cards_definition":"Empty model answers are explicit [] on finished model card attempts; automatic no-model closes are separate. Assignments count leases, not unique card IDs.",
            "source_warnings":source_warnings,
            "final_builder_cards_by_model":builder_empty_counts(events,max((r["circle"] for r in rows),default=0),"FINAL"),
            "ontology_reviews":reviews,"rows":rows,"boundaries":boundaries}

def acceptance_svg(metrics:dict) -> str:
    rows=metrics["rows"]; width=800; height=340
    out=[f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}">',
         '<rect width="800" height="340" fill="white"/>',
         '<text x="55" y="25" font-family="sans-serif" font-size="17">Reading line acceptance by circle</text>',
         '<text x="55" y="47" font-family="sans-serif" font-size="12">Structural acceptance is not semantic correctness</text>']
    for pct in (0,25,50,75,100):
        y=270-pct*2
        out += [f'<line x1="55" y1="{y}" x2="755" y2="{y}" stroke="#ddd"/>',
                f'<text x="17" y="{y+4}" font-family="sans-serif" font-size="11">{pct}%</text>']
    points=[]
    for i,row in enumerate(rows):
        x=55+700*(i+.5)/max(1,len(rows));rate=row["reading"]["acceptance"]
        out.append(f'<text x="{x}" y="292" text-anchor="middle" font-family="sans-serif" font-size="12">{row["circle"]}</text>')
        if rate is not None:
            y=270-200*rate;points.append((x,y))
            label=f'circle {row["circle"]}: {row["reading"]["stored"]}/{row["reading"]["offered"]}; closed={row["closed"]}'
            out.append(f'<circle cx="{x}" cy="{y}" r="5" fill="#1967d2"><title>{escape(label)}</title></circle>')
    if points:
        line=" ".join(f"{x},{y}" for x,y in points)
        out.append(f'<polyline points="{line}" fill="none" stroke="#1967d2" stroke-width="1.5"/>')
    out.append('<text x="400" y="322" text-anchor="middle" font-family="sans-serif" font-size="12">Circle number; hover a point for counts</text></svg>')
    return "\n".join(out)


def matrix_markdown(metrics:dict,row_lines=lambda row:[])->str:
    out=["# Cross-model measurements","",
         "Builder operations: accepted/refused by the kernel. Relation verdicts: accepted/rejected/unresolved.",
         "A multi-author operation appears in each author row. These counts are not semantic correctness.",""]
    for row in metrics["rows"]:
        out += [f"## Circle {row['circle']}",""]
        out += ["### Empty card attempts by model","",
                "| Model | Assignments | Finished model attempts | Empty model answers | Closed without operations | Automatic closes |",
                "|---|---:|---:|---:|---:|---:|"]
        for model,c in row.get("builder_cards_by_model",{}).items():
            out.append("| "+model+" | "+" | ".join(str(c.get(k,0)) for k in
                ("assignments","finished_model_attempts","empty_model_answers","closed_without_operations","automatic_no_model_closes"))+" |")
        out += ["", "Explicit [] counts model answers. Unknown older no-operation counts are retained in JSON.", ""]
        m=row["model_matrix"]
        for key,label,reviewer,counts in (
            ("builder_operations","Builder operations","executing_model",("accepted","refused","unknown")),
            ("link_verdicts","Relation verdicts","checking_model",("accepted","rejected","unresolved"))):
            records=m[key]
            columns=sorted({r[reviewer] for r in records})
            authors=sorted({r["author_model"] for r in records})
            out += [f"### {label} ({'/'.join(counts)})","",
                    "| Author model | "+" | ".join(columns or ["No observations"])+" |",
                    "|---|"+"---|"*max(1,len(columns))]
            for author in authors:
                cells=[]
                for col in columns:
                    cells.append("/".join(str(sum(r.get(c,0) for r in records if r["author_model"]==author and r[reviewer]==col)) for c in counts))
                out.append("| "+author+" | "+" | ".join(cells)+" |")
            out += [""]
        out += row_lines(row)
    return "\n".join(out)
