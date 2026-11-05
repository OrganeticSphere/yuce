"""Measurement only: source author x executing model, with operation and verdict units kept separate."""
from __future__ import annotations
import collections

def operation_decisions(card:dict,ops:list[dict],reply:dict)->list[dict]:
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
                     "authors":authors,"decision":decision})
    return rows

def matrices(events:list[dict],models:dict[str,str],circle:int)->dict:
    ops=collections.defaultdict(collections.Counter)
    verdicts=collections.defaultdict(collections.Counter)
    for e in events:
        if e.get("circle")!=circle or e.get("circle_phase")=="FINAL":
            continue
        for row in e.get("operation_decisions") or []:
            reviewer=row.get("source") or e.get("builder_model","unknown")
            authors=row.get("authors") or ["<unattributed>"]
            for author in authors:
                ops[(models.get(author,f"unknown:{author}"),reviewer,row.get("op"))][row["decision"]]+=1
        if e.get("kind") in ("VERIFY_LINK","RESOLVE_CONFLICT") and "repairs" in e:
            verdict=(e.get("verdict") or {}).get("status")
            decision=verdict if e.get("outcome")=="COMMITTED" and verdict in ("accepted","rejected") else "unresolved"
            for author in set(e.get("link_authors") or ["<unattributed>"]):
                verdicts[(models.get(author,f"unknown:{author}"),e.get("model","unknown"))][decision]+=1
    def flatten(data,fields):
        return [dict(zip(fields,key if isinstance(key,tuple) else (key,)),**dict(value)) for key,value in sorted(data.items(),key=lambda x:str(x[0]))]
    return {"builder_operations":flatten(ops,("author_model","executing_model","operation")),
            "link_verdicts":flatten(verdicts,("author_model","checking_model")),
            "definition":"operation rows are kernel acceptance per submission; verdict rows are stored relation decisions. "
                         "A multi-author operation contributes to each author row. Neither matrix certifies semantic truth."}
