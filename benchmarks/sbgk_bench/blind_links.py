"""Deterministic random accepted-link sample captured before withdrawals; branch and model keys stay private.
No model or network call is made here. Semantic quality remains the independent judge's opinion.
"""
from __future__ import annotations

import json
import random

SAMPLE_SEED = 20261025
SAMPLE_SIZE = 20


def capture_links(call, document_paths: dict[str, str], *, seed: int = SAMPLE_SEED, size: int = SAMPLE_SIZE) -> dict:
    response = call("audit_links", status="accepted")
    if response.get("status") != "LINKS":
        return {"status": "UNAVAILABLE", "response": response}
    links = sorted(response["links"], key=lambda x: x["id"])
    chosen = random.Random(seed).sample(links, min(size, len(links)))
    records = {}
    stack = [x[k] for x in chosen for k in ("from", "to")]
    while stack:
        rid = stack.pop()
        if rid in records:
            continue
        rec = call("audit_record", record=rid)
        if rec.get("status") != "RECORD":
            return {"status": "UNAVAILABLE", "record": rid, "response": rec}
        records[rid] = rec
        stack.extend(rec.get("based_on") or [])
        ends = rec.get("ends")
        if ends:
            stack.extend((ends[0], ends[2]))
    return {"status": "CAPTURED", "population": len(links), "size": len(chosen), "seed": seed,
            "links": chosen, "records": records, "document_paths": document_paths,
            "definition": "accepted at the phase-1 snapshot, before any withdrawal; sample without replacement"}


def blinded_package(samples: dict[str, dict], docs: dict[str, str], *, seed: int = SAMPLE_SEED) -> tuple[str, dict]:
    """Combine samples, shuffle, and strip branch, model, actor, source IDs and kernel acceptance from each judged item."""
    items, private = [], {}
    for branch, sample in sorted(samples.items()):
        if sample.get("status") != "CAPTURED":
            raise ValueError(f"missing complete link snapshot: {branch}")
        records, paths = sample["records"], sample["document_paths"]
        def record(rid, seen=None):
            seen = (seen or set()) | {rid}
            r = records[rid]
            body = r.get("body") or {}
            return {"kind": r["kind"], "text": r.get("text"), "stance": r.get("stance"),
                    "scope": {k: body[k] for k in ("subject", "valid", "as_of") if k in body},
                    "report": paths.get(r.get("doc_id")), "quote": r.get("quote"),
                    "basis": [record(x, seen) for x in r.get("based_on") or [] if x not in seen],
                    "ends": ([record(r["ends"][0], seen), r["ends"][1], record(r["ends"][2], seen)]
                             if r.get("ends") and not any(x in seen for x in (r["ends"][0], r["ends"][2])) else None)}
        for link in sample["links"]:
            items.append((branch, link["id"], {"from": record(link["from"]), "relation": link["rel"], "to": record(link["to"])}))
    random.Random(seed).shuffle(items)
    public = []
    for n, (branch, lid, item) in enumerate(items, 1):
        label = f"L{n:03d}"
        public.append({"id": label, **item})
        private[label] = {"branch": branch, "link_id": lid}
    instructions = (
        "Judge each numbered directed relation against the complete reports below. Do not guess branch or model. "
        "For each id return correct, incorrect, or unclear, with a concrete reason and supporting or contrary report passage. "
        "Check direction, subject, scope and time; different true facts need not be same_as. "
        "A quoted passage proves its bytes, not the whole assertion or relation. A hypothesis remains a hypothesis. "
        "Do not change an unclear result to correct. Return a Markdown table: id | verdict | reason | report evidence. "
        "Judge the relation's meaning using the full sources and shown endpoints; this is not a certification of the kernel's "
        "original link-basis selection, which this packet does not expose. Do not use tools.\n\n")
    reports = "\n\n".join(f"=== REPORT {path} ===\n{text}\n=== END REPORT ===" for path, text in sorted(docs.items()))
    prompt = instructions + reports + "\n\n=== RELATIONS ===\n" + json.dumps(public, ensure_ascii=False, indent=1)
    return prompt, {"seed": seed, "sample_sizes": {k: v["size"] for k, v in samples.items()},
                    "populations": {k: v["population"] for k, v in samples.items()}, "items": private}
