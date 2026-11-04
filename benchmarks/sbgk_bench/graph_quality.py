"""Explicit Jev framing. No classifier calls or state changes in presentation helpers."""
import copy

def inline_card(card,selected):
    out=copy.deepcopy(card)
    if not selected:return out
    # Decisions are record-term specific; a term shared by two records need not select the same concept.
    out["fast_matches"]=[{"record":o["record"],"term":o["term"],"concept":o["concept"]} for o in selected]
    for term,cs in out.get("candidates",{}).items():
        for c in cs:
            if any(o["term"]==term and o["concept"]==c["id"] for o in selected):
                c["fast_match"]=True
                c["fast_match_records"]=sorted({o["record"] for o in selected if o["term"]==term and o["concept"]==c["id"]})
    return out
