"""EXP-6: tamper-evident WAL and time travel by byte-prefix.

  6a  time travel: for every agent step k the graph rebuilt from `wal[..offset_k]` has exactly the root
      recorded live at step k -- on the original container and again after later appends (history is immutable)
  6b  single-bit tampering anywhere in the container (WAL frames, source chunks, header, node table, index,
      arena) must be caught by `verify`; exhaustive on a small container, sampled on the big one
  6c  an attacker who flips a payload bit *and recomputes the hash chain* is still caught by the state
      commitments (node table / root / replay)
  6d  an attacker who swaps a source chunk for forged content with a self-consistent chunk hash is caught by the
      evidence anchors / the log's chunk references
"""

from __future__ import annotations

import hashlib
import json
import random
import struct

from . import common as C
from .exp2 import Spec, render

CHAIN_ORIGIN = hashlib.sha256(b"SBGK-WAL-v1").digest()


def sections(buf: bytes) -> dict[str, tuple[int, int]]:
    a, t, w, i = struct.unpack_from("<IIII", buf, 8)
    return {"header": (0, 64), "arena": (a, t), "table": (t, w), "wal": (w, i), "index": (i, len(buf))}


def frames(buf: bytes) -> list[tuple[int, int]]:
    s, e = sections(buf)["wal"]
    out, pos = [], s
    while pos < e:
        (ln,) = struct.unpack_from("<I", buf, pos)
        out.append((pos, pos + ln))
        pos += ln
    return out


def recompute_chain(buf: bytearray, from_frame: int) -> None:
    fr = frames(bytes(buf))
    prev = CHAIN_ORIGIN if from_frame == 0 else bytes(buf[fr[from_frame - 1][1] - 32: fr[from_frame - 1][1]])
    for s, e in fr[from_frame:]:
        chain = hashlib.sha256(prev + bytes(buf[s:e - 32])).digest()
        buf[e - 32:e] = chain
        prev = chain


def build_big(wd, rng: random.Random):
    spec = Spec(rng, 40, 10, with_conflict=True, n_revokes=5)
    lines = render(spec, random.Random(1), "seq", noisy=False)
    docdir = wd / "docs"
    C.write_docs(docdir, spec.docs)
    (wd / "ontology.json").write_text(json.dumps(spec.onto), encoding="utf-8")
    C.write_lines(wd / "stream.jsonl", lines)
    base = wd / "base.sbgk"
    rep = C.cli("apply", "--ontology", wd / "ontology.json", "--docs", docdir, "--stream", wd / "stream.jsonl",
                "--out", base, "--track-roots", "--oracle")
    assert rep["error"] is None, rep["error"]
    (wd / "report.json").write_text(json.dumps(rep), encoding="utf-8")
    return spec, base, rep


def run(quick: bool = False) -> dict:
    rng = random.Random(6006)
    wd = C.workdir("exp6")
    spec, base, rep = build_big(wd, rng)

    # ---- 6a time travel
    tt = C.cli("timetravel-all", base, "--roots", wd / "report.json")
    # append history: two document updates (DocPut + re-binding frames)
    cur = base
    for j, (doc_id, data) in enumerate(spec.docs.items()):
        paras = data.decode().split("\n\n")
        paras.insert(2 if j == 0 else len(paras) // 2, C.filler_paragraph(random.Random(j), 5, 7))
        f = wd / f"{doc_id}.edit.txt"
        f.write_bytes(C.join_doc(paras))
        nxt = wd / f"after_{j}.sbgk"
        C.cli("update-doc", cur, "--doc-id", doc_id, "--file", f, "--out", nxt)
        cur = nxt
    appended = cur
    tt2 = C.cli("timetravel-all", appended, "--roots", wd / "report.json")
    wb, wa = base.read_bytes(), appended.read_bytes()
    sb, sa = sections(wb)["wal"], sections(wa)["wal"]
    wal_b, wal_a = wb[sb[0]:sb[1]], wa[sa[0]:sa[1]]
    prefix_immutable = wal_a[: len(wal_b)] == wal_b
    n_steps = len(rep["roots"])
    probes = {}
    for q in (0.1, 0.25, 0.5, 0.75, 1.0):
        k = max(1, int(n_steps * q))
        r = C.cli("timetravel", appended, "--seq", k, "--reps", 200)
        probes[str(q)] = {"seq": k, "wal_prefix_bytes": r["wal_offset"], "reconstruct_us_p50": r["reconstruct_us"]["p50"],
                          "reconstruct_us_p99": r["reconstruct_us"]["p99"], "nodes": r["nodes"]}
    full_us = tt2["full_replay_us"]["p50"]

    # ---- 6b bit flips
    v = C.cli("verify", appended)
    assert v["ok"], v
    flips = {}
    sampled = {"wal": 2000, "chunk": 2000, "header": 500, "table": 1500, "index": 1500, "arena": 1500, "all": 8000}
    if quick:
        sampled = {k: max(100, n // 10) for k, n in sampled.items()}
    for region, n in sampled.items():
        flips[region] = C.cli("tamper", appended, "--region", region, "--trials", n, "--seed", 7)
    # exhaustive on a tiny container
    tiny = wd / "tiny"
    tiny.mkdir(exist_ok=True)
    onto = C.ontology_graph(["n0", "n1", "n2"])
    (tiny / "ontology.json").write_text(json.dumps(onto), encoding="utf-8")
    C.write_docs(tiny / "docs", {"net": b"Link L0: node n0 connects to node n1 in production.\nLink L1: node n1 connects to node n2 in production.\n"})
    tiny_ops = C.numbered([
        C.L_bind("e0", "net", "Link L0: node n0 connects to node n1 in production."),
        C.L_assert("f0", "n0", "edge", "n1", (0, 9), ["e0"]),
        C.L_bind("e1", "net", "Link L1: node n1 connects to node n2 in production."),
        C.L_assert("f1", "n1", "edge", "n2", (0, 9), ["e1"]),
        C.L_derive("r0", "R_seed@1", ["f0"]),
        C.L_derive("r1", "R_step@1", ["r0", "f1"]),
        C.L_revoke("e1"),
    ])
    C.write_lines(tiny / "s.jsonl", C.jsonl(tiny_ops))
    C.cli("apply", "--ontology", tiny / "ontology.json", "--docs", tiny / "docs", "--stream", tiny / "s.jsonl", "--out", tiny / "t.sbgk")
    exhaustive = C.cli("tamper", tiny / "t.sbgk", "--region", "all", "--exhaustive")

    # ---- 6c chain-recomputing attacker
    buf0 = wa
    fr = frames(buf0)
    trials_c, caught_c, channels_c = (60 if quick else 400), 0, {}
    atk = wd / "attack.sbgk"
    for _ in range(trials_c):
        i = rng.randrange(len(fr))
        s, e = fr[i]
        pos = rng.randrange(s + 13, e - 32)  # payload bytes only
        b = bytearray(buf0)
        b[pos] ^= 1 << rng.randrange(8)
        recompute_chain(b, i)
        atk.write_bytes(bytes(b))
        r = C.cli("verify", atk)
        caught_c += not r["ok"]
        key = r.get("kind", "NOT_DETECTED")
        channels_c[key] = channels_c.get(key, 0) + 1

    # ---- 6d chunk swapped for forged content with a consistent hash
    arena_s, arena_e = sections(buf0)["arena"]
    n_entries = struct.unpack_from("<I", buf0, arena_s)[0]
    ents = []
    for k in range(n_entries):
        o = arena_s + 4 + 41 * k
        h = buf0[o:o + 32]
        kind = buf0[o + 32]
        off, ln = struct.unpack_from("<II", buf0, o + 33)
        ents.append((o, h, kind, off, ln))
    data_base = arena_s + 4 + 41 * n_entries
    chunk_ents = [x for x in ents if x[2] == 0]
    trials_d, caught_d, channels_d = (20 if quick else 100), 0, {}
    for _ in range(trials_d):
        o, h, kind, off, ln = chunk_ents[rng.randrange(len(chunk_ents))]
        b = bytearray(buf0)
        d = bytearray(b[data_base + off: data_base + off + ln])
        d[rng.randrange(ln)] ^= 1 << rng.randrange(8)
        b[data_base + off: data_base + off + ln] = d
        b[o:o + 32] = hashlib.sha256(bytes(d)).digest()  # forged but self-consistent address
        atk.write_bytes(bytes(b))
        r = C.cli("verify", atk)
        caught_d += not r["ok"]
        key = r.get("kind", "NOT_DETECTED")
        channels_d[key] = channels_d.get(key, 0) + 1

    total_flips = sum(f["trials"] for f in flips.values()) + exhaustive["trials"]
    total_missed = sum(f["undetected"] for f in flips.values()) + exhaustive["undetected"]
    return {
        "setup": {"agent_steps": n_steps, "wal_bytes_base": len(wal_b), "wal_bytes_after_appends": len(wal_a),
                  "container_bytes": len(wa), "frames": len(fr), "verify_us": v["elapsed_us"], "nodes": v["nodes"],
                  "chunks": v["chunks"], "tiny_container_bytes": exhaustive["container_bytes"]},
        "time_travel": {
            "base": tt, "after_appends": tt2, "history_prefix_immutable": prefix_immutable,
            "probes": probes, "full_replay_us_p50": full_us,
        },
        "bit_flips": {"by_region": flips, "exhaustive_tiny": exhaustive, "total_trials": total_flips, "total_undetected": total_missed},
        "chain_recomputing_attacker": {"trials": trials_c, "caught": caught_c, "by_channel": channels_c},
        "forged_chunk_with_consistent_hash": {"trials": trials_d, "caught": caught_d, "by_channel": channels_d},
        "pass": {
            "time_travel_roots_all_match": tt["mismatches"] == 0 and tt2["mismatches"] == 0 and tt["checked"] == n_steps,
            "history_prefix_immutable": prefix_immutable,
            "bit_flips_100pct_detected": total_missed == 0,
            "chain_recompute_attack_caught": caught_c == trials_c,
            "forged_chunk_caught": caught_d == trials_d,
        },
    }
