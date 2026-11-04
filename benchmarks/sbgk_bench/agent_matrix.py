"""Measurement only: source author x executing model, with operation and verdict units kept separate."""
from __future__ import annotations
import collections

def operation_decisions(card:dict,ops:list[dict],reply:dict,sources:list[str]|None=None)->list[dict]:
    records={r["id"]:r for r in card.get("records",[])+card.get("neighbors",[])}
    refused={x["index"] for x in reply.get("refused") or [] if type(x.get("index")) is int}
    indexes=[i for i,op in enumerate(ops) if op.get("op")!="request"]
    results=reply.get("results") or []
    enough=len(results)==sum(i not in refused for i in indexes)
    recognized=reply.get("status") in ("CARD_DONE","REPAIR_REQUIRED")
    rows=[]
    for i,op in enumerate(ops):
        if op.get("op")=="request":
            continue
        refs=[op[k] for k in ("record","from","to","a","b","of") if isinstance(op.get(k),str)]
        if not refs and op.get("op") in ("propose_concept","keep","revise_concept"):
            refs=op.get("basis") or []
        authors=sorted({records[x]["author"] for x in refs if x in records and records[x].get("author")})
        decision=("refused" if i in refused or (recognized and not results and reply.get("accepted")==0) else
                  "accepted" if recognized and enough else "unknown")
        rows.append({"op":op.get("op"),"record":op.get("record"),"term":op.get("term"),"concept":op.get("concept"),
                     "authors":authors,"source":sources[i] if sources else "BUILDER","decision":decision})
    return rows

def concept_choice(card:dict,value)->str|None:
    if not isinstance(value,str):
        return None
    def norm(x):
        return " ".join(x.split()).casefold()
    matches=set()
    for cs in (card.get("candidates") or {}).values():
        for c in cs:
            if value==c["id"] or norm(value) in {norm(c["name"]),*(norm(a) for a in c.get("aliases") or [])}:
                matches.add(c["id"])
    return next(iter(matches)) if len(matches)==1 else None

def jev_comparison(card:dict,selected:list[dict],agent_ops:list[dict])->list[dict]:
    chosen={(op["record"],op["term"]):op for op in selected}
    rows=[]
    for op in agent_ops:
        other=chosen.get((op.get("record"),op.get("term"))) if op.get("op")=="map_term" else None
        if other:
            a,b=concept_choice(card,op.get("concept")),concept_choice(card,other.get("concept"))
            rows.append({"record":op["record"],"term":op["term"],"agent_concept":op.get("concept"),"jev_concept":other.get("concept"),
                         "agreement":"same" if a and a==b else "different" if a and b else "unresolved"})
    return rows

def matrices(events:list[dict],models:dict[str,str],circle:int)->dict:
    ops=collections.defaultdict(collections.Counter)
    verdicts=collections.defaultdict(collections.Counter)
    agreement=collections.defaultdict(collections.Counter)
    cards={}
    for e in events:
        if e.get("circle")!=circle or e.get("circle_phase")=="FINAL":
            continue
        if e.get("outcome")=="JEV_COVERAGE":
            # Stable card ID: reissued cards do not inflate the fraction of material terms covered.
            entry=cards.setdefault(e["card"],{"material":set(),"eligible":set(),"selected":set(),"suggested":set()})
            for target,field in (("material","material_keys"),("eligible","eligible_keys"),("selected","selected_keys"),("suggested","provisional_suggested_keys")):
                entry[target].update(tuple(x) for x in e.get(field) or [])
        for row in e.get("operation_decisions") or []:
            reviewer="Jev" if row["source"]=="JEV" else e.get("builder_model","unknown")
            authors=row.get("authors") or ["<unattributed>"]
            for author in authors:
                ops[(models.get(author,f"unknown:{author}"),reviewer,row.get("op"))][row["decision"]]+=1
        if "jev_agent_absent" in e:
            agreement[e.get("builder_model","unknown")]["not_attempted"]+=e["jev_agent_absent"]
        for row in e.get("jev_comparison") or []:
            agreement[e.get("builder_model","unknown")][row["agreement"]]+=1
        if e.get("kind") in ("VERIFY_LINK","RESOLVE_CONFLICT") and "repairs" in e:
            verdict=(e.get("verdict") or {}).get("status")
            decision=verdict if e.get("outcome")=="COMMITTED" and verdict in ("accepted","rejected") else "unresolved"
            for author in set(e.get("link_authors") or ["<unattributed>"]):
                verdicts[(models.get(author,f"unknown:{author}"),e.get("model","unknown"))][decision]+=1
    def flatten(data,fields):
        return [dict(zip(fields,key if isinstance(key,tuple) else (key,)),**dict(value)) for key,value in sorted(data.items(),key=lambda x:str(x[0]))]
    total=sum(len(e["material"]) for e in cards.values())
    selected=sum(len(e["selected"]) for e in cards.values())
    return {"builder_operations":flatten(ops,("author_model","executing_model","operation")),
            "link_verdicts":flatten(verdicts,("author_model","checking_model")),
            "jev_agreement":flatten(agreement,("agent_model",)),
            "jev_coverage":{"cards":len(cards),"material_terms":total,"eligible_terms":sum(len(e["eligible"]) for e in cards.values()),
                            "provisional_suggested_terms":sum(len(e["suggested"]) for e in cards.values()),"decided_terms":selected,"share":selected/total if total else None},
            "definition":"operation rows are kernel acceptance per submission; verdict rows are stored relation decisions. "
                         "A multi-author operation contributes to each author row. Neither matrix certifies semantic truth."}
