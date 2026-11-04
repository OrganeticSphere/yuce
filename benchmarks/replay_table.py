"""Tables of an offline WAL replay (`cargo run --release --example replay_wal`): the store's outcome of every recorded swarm
submission against the recorded one, the diagnostics of every refused one against the store's own line-by-line verdict, and the
builder's first answers under the run's operation limit and the current one.

    python benchmarks/replay_table.py <run dir> <replay.jsonl> > table.md
"""
import collections
import json
import sys
from pathlib import Path


def task_kinds(run: Path) -> dict[str, str]:
    """Task id -> kind, from the runner's call contexts (call ids are `C<phase>-<task id>-<attempt>`)."""
    kinds = {}
    for raw in (run / "journal.jsonl").open(encoding="utf-8"):
        e = json.loads(raw)
        r = e["record"]
        if e["kind"] == "context" and r.get("call_id", "").startswith("C") and r.get("kind"):
            kinds[r["call_id"].split("-", 1)[1].rsplit("-", 1)[0]] = r["kind"]
    return kinds


def builder_archive(run: Path) -> dict[str, dict]:
    out = {}
    for raw in (run / "events.jsonl").open(encoding="utf-8"):
        e = json.loads(raw)
        if e.get("agent") == "gb" and e.get("card"):
            out[e["card"]] = e
    return out


def main() -> None:
    run, replay = Path(sys.argv[1]), Path(sys.argv[2])
    rows = [json.loads(x) for x in replay.open(encoding="utf-8")]
    metas = [r["meta"] for r in rows if "meta" in r]
    swarm = [r for r in rows if "submission" in r]
    cards = [r for r in rows if "card" in r and "error" not in r]
    unavailable = [r for r in rows if "card" in r and "error" in r]
    kinds = task_kinds(run)

    print("## Shards and coverage\n")
    for m in metas:
        print(f"- {m['mode']} [{m['range'][0]}, {m['range'][1]}) of {m['wal_entries']} WAL entries, tool built from {m.get('revision')}")
    indices = [r["wal_index"] for r in swarm]
    names = [r["card"] for r in rows if "card" in r]
    print(f"- swarm rows {len(indices)}, distinct WAL entries {len(set(indices))}, in order: {indices == sorted(indices)}")
    print(f"- builder rows {len(names)}, distinct cards {len(set(names))}\n")

    print("## Swarm submissions: the store's outcome, recorded vs replayed\n")
    same = sum(r["same"] for r in swarm)
    refused = [r for r in swarm if r["replayed"]["failed_index"] is not None]
    print(f"- submissions: {len(swarm)}; identical outcome (accepted ids, failed index, code, message): {same}")
    print(f"- identical whole error: {sum(bool(r.get('same_error')) for r in swarm)}; identical audit and engine roots after the "
          f"submission: {sum(bool(r.get('same_roots')) for r in swarm)}")
    print(f"- refused submissions: {len(refused)}")
    for r in swarm:
        if not r["same"]:
            print(f"  - DIFFERENT {r['submission']}: recorded {r['recorded']} / replayed {r['replayed']}")

    print("\n## Diagnostics of the lines not taken vs the store's verdict on each line alone\n")
    verdicts = collections.Counter()
    by_kind = collections.defaultdict(collections.Counter)
    missed, alarms = [], []
    for r in refused:
        kind = kinds.get(r["directive"], "?")
        for p in r["per_line"]:
            verdicts[p["verdict"]] += 1
            by_kind[kind][p["verdict"]] += 1
            if p["verdict"] == "MISSED":
                missed.append((r["submission"], p))
            if p["verdict"] == "FALSE_ALARM":
                alarms.append((r["submission"], p))
    order = ["NAMED", "MISSED", "FALSE_ALARM", "OTHER_REFUSAL", "ACCEPTED"]
    print("| task kind | " + " | ".join(order) + " |")
    print("|---|" + "---:|" * len(order))
    for kind in sorted(by_kind):
        print(f"| {kind} | " + " | ".join(str(by_kind[kind][v]) for v in order) + " |")
    print("| **all** | " + " | ".join(f"**{verdicts[v]}**" for v in order) + " |")
    print("\nNAMED: the store refuses the line and the diagnostics name it. MISSED: refused for a quote, a basis or a bound, not named. "
          "FALSE_ALARM: named, but the store takes the line. OTHER_REFUSAL: refused for another reason (mostly a line resting on a refused "
          "one). ACCEPTED: taken, not named.")
    reasons = collections.Counter(p.get("same_reason") for r in refused for p in r["per_line"] if p["verdict"] == "NAMED")
    print(f"\nNAMED with the store's own reason: {reasons[True]}; named for another reason (the line is refused either way): {reasons[False]}")
    named_codes = collections.Counter()
    other_codes = collections.Counter()
    for r in refused:
        for p in r["per_line"]:
            code = (p["store"] or {}).get("code")
            if p["verdict"] == "NAMED":
                named_codes[code] += 1
            elif p["verdict"] == "OTHER_REFUSAL":
                other_codes[f"{code}: {(p['store'] or {}).get('message', '')[:70]}"] += 1
    print("\nNamed refusals by store code: " + ", ".join(f"{k} {v}" for k, v in named_codes.most_common()))
    print("\nOther refusals: " + "; ".join(f"{k} ({v})" for k, v in other_codes.most_common(8)))
    for sid, p in missed[:20]:
        print(f"\n- MISSED {sid} line {p['line']}: {p['store']}")
    for sid, p in alarms[:20]:
        print(f"\n- FALSE_ALARM {sid} line {p['line']}: {json.dumps(p['diagnostics'])[:400]}")

    print("\n## Builder: the recorded first answer of each card\n")
    for r in unavailable:
        print(f"- UNAVAILABLE {r['card']}: {r['error']}")
    archive = builder_archive(run)
    print("| card | ops | archive (outcome, repairs, abandoned) | limit 32 now | limit 64 now (accepted / refused) |")
    print("|---|---:|---|---|---|")
    moved = collections.Counter()
    for c in cards:
        a = archive.get(c["card"], {})
        k32, k64 = c.get("max_ops_32", {}), c.get("max_ops_64", {})
        moved[(a.get("abandoned"), k32.get("code") == "TOO_MANY_OPS", k64.get("status"))] += 1
        same_card = "" if k64.get("same_card", True) else " (card cut again with other records)"
        print(f"| {c['card']} | {c.get('ops')} | {a.get('outcome')}, {a.get('repairs')}, {a.get('abandoned')} | "
              f"{k32.get('status')} {k32.get('code') or ''} | {k64.get('status')} {k64.get('accepted')} / {k64.get('refused')}{same_card} |")
    print("\n(abandoned in the run, over 32 operations, status with 64): " + "; ".join(f"{k}: {v}" for k, v in moved.most_common()))
    over = [c for c in cards if c.get("max_ops_32", {}).get("code") == "TOO_MANY_OPS"]
    for same_card in (True, False):
        part = [c for c in over if c["max_ops_64"].get("same_card") == same_card]
        print(f"\nover 32 operations, card {'the same' if same_card else 'cut again'}: {len(part)} cards, with 64 accepted "
              f"{sum(c['max_ops_64'].get('accepted') or 0 for c in part)} / refused {sum(c['max_ops_64'].get('refused') or 0 for c in part)}")
    print(f"\nanswers within 32 operations: the 64 result is the 32 result (copied, not a second run): "
          f"{sum(bool(c.get('max_ops_64', {}).get('copied_from_32')) for c in cards)} cards")


if __name__ == "__main__":
    main()
