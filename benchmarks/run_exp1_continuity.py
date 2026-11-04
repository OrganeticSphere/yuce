#!/usr/bin/env python3
"""Repeat full EXP-1 and independently check ByteAnchor continuity.

The output directory is create-only; the original suite, reports and results are
never overwritten. Build the intended release binary before running this script.
No models, network requests, cargo builds or cargo tests are invoked.

    python benchmarks/run_exp1_continuity.py --out results/byteanchor-continuity-RUN_ID

EXP-1 uses its unchanged default LocalMax and FastCDC settings. The separate
correctness series uses FastCDC min=avg=max=64 to isolate ordered, repeated
chunks from changes in CDC boundaries. Its oracle reads current source bytes,
checks exact occurrences and every ACTIVE anchor span, and compares claim IDs
and statuses. The kernel's closure oracle is reported as a separate check.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import struct
import subprocess
import sys
import time
import traceback

from sbgk_bench import common as C
from sbgk_bench import exp1

BASELINE_REVISION = "d7571f78c58468e84f8ba01952c66b958b915953"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=True)
        handle.write("\n")


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def git(*args: str) -> bytes:
    return subprocess.run(["git", *args], cwd=C.ROOT, capture_output=True, check=True).stdout


def file_manifest(paths) -> dict:
    return {p.relative_to(C.ROOT).as_posix(): {"sha256": digest(p.read_bytes()), "bytes": p.stat().st_size}
            for p in sorted(set(paths)) if p.is_file()}


def historical_manifest(out: Path) -> dict:
    paths = [p for p in (C.ROOT / "results").rglob("*") if not p.is_relative_to(out)]
    paths += list(C.ROOT.glob("*REPORT*"))
    return file_manifest(paths)


def source_manifest() -> dict:
    # Include untracked runner/test sources: a HEAD plus a diff alone omits them.
    names = git("ls-files", "--cached", "--others", "--exclude-standard", "-z").decode("utf-8").split("\0")
    paths = [C.ROOT / name for name in names if name and not name.startswith(("results/", "target/"))]
    return file_manifest(paths)


class CliRecorder:
    def __init__(self, out: Path):
        self.out = out
        self.calls = 0
        (out / "cli").mkdir()

    def __call__(self, *args, stdin=None, binary=None, json_lines=False):
        self.calls += 1
        stem = f"{self.calls:04d}"
        cmd = [str(binary or C.BIN), *map(str, args)]
        started = utc()
        t0 = time.perf_counter()
        proc = subprocess.run(cmd, cwd=C.ROOT, input=stdin, capture_output=True, text=True, encoding="utf-8")
        (self.out / "cli" / f"{stem}.stdout").write_text(proc.stdout, encoding="utf-8")
        (self.out / "cli" / f"{stem}.stderr").write_text(proc.stderr, encoding="utf-8")
        with (self.out / "commands.jsonl").open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps({"call": self.calls, "argv": cmd, "stdin": stdin,
                                     "started_utc": started, "elapsed_seconds": time.perf_counter() - t0,
                                     "exit_code": proc.returncode}) + "\n")
        if proc.returncode:
            raise RuntimeError(f"CLI call {self.calls} exited {proc.returncode}: {proc.stderr[:500]}")
        return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()] if json_lines else json.loads(proc.stdout)


class Reader:
    """Minimal observation-only decoder of the documented v1 container layout."""

    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        result = self.data[self.pos:self.pos + n]
        if len(result) != n:
            raise ValueError("truncated container")
        self.pos += n
        return result

    def number(self, fmt: str) -> int:
        return struct.unpack("<" + fmt, self.take(struct.calcsize(fmt)))[0]

    def string(self) -> str:
        return self.take(self.number("H")).decode("utf-8")


def evidence_from_container(path: Path) -> dict:
    data = path.read_bytes()
    if data[:8] != b"SBGK\0\1\1\0":
        raise ValueError("only documented v1 containers are supported by this observer")
    arena_off, table_off, wal_off, _ = struct.unpack_from("<IIII", data, 8)
    arena = Reader(data[arena_off:table_off])
    entries = [(arena.take(32), arena.number("B"), arena.number("I"), arena.number("I"))
               for _ in range(arena.number("I"))]
    blob_start = arena.pos
    chunks = {h.hex(): arena.data[blob_start + off:blob_start + off + size]
              for h, kind, off, size in entries if kind == 0}
    if any(digest(value) != key for key, value in chunks.items()):
        raise ValueError("observed chunk hash mismatch")
    table = Reader(data[table_off:wal_off])
    count = table.number("I")
    table.take(256 * 32)
    result = {}
    for _ in range(count):
        node_id, kind, status = table.take(32).hex(), table.number("B"), table.number("B")
        table.number("I")  # rank
        payload = table.take(table.number("I"))
        table.take(table.number("H") * 32)
        if digest(payload) != node_id:
            raise ValueError("observed canonical node hash mismatch")
        if kind != 1:
            continue
        reader = Reader(payload)
        if reader.number("B") != 1:
            raise ValueError("incorrect evidence payload tag")
        doc_id, quote_hash, quote_len = reader.string(), reader.take(32).hex(), reader.number("I")
        segments = [(reader.take(32).hex(), reader.number("I"), reader.number("I"))
                    for _ in range(reader.number("B"))]
        if reader.pos != len(payload):
            raise ValueError("trailing evidence payload bytes")
        quote = b"".join(chunks[h][start:end] for h, start, end in segments)
        result[node_id] = {"doc_id": doc_id, "status": status, "quote_hash": quote_hash,
                           "quote_len": quote_len, "segments": segments, "quote": quote}
    return result


def occurrences(haystack: bytes, needle: bytes) -> list[int]:
    result, start = [], 0
    while needle:
        found = haystack.find(needle, start)
        if found < 0:
            break
        result.append(found)
        start = found + 1
    return result


def anchored_occurrences(ev: dict, current: bytes) -> list[int]:
    """Check spans against the current bytes and the known 64-byte fixture grid.

    This starts from byte-exact quote locations, never from the kernel's active
    flags, chunk-membership tests, document table or closure oracle.
    """
    quote = ev["quote"]
    if not quote or len(quote) != ev["quote_len"] or digest(quote) != ev["quote_hash"]:
        return []
    valid = []
    for start in occurrences(current, quote):
        end = start + len(quote)
        expected = []
        for chunk_start in range((start // 64) * 64, end, 64):
            chunk = current[chunk_start:chunk_start + 64]
            expected.append((digest(chunk), max(start, chunk_start) - chunk_start,
                             min(end, chunk_start + len(chunk)) - chunk_start))
        if ev["segments"] == expected:
            valid.append(start)
    return valid


def continuity_case(out: Path, name: str, old: bytes, new: bytes, quote: bytes,
                    expected_occurrences: int, survives: bool, rebind: bool = False,
                    alternative: bool = False) -> dict:
    work = out / "continuity" / name
    work.mkdir(parents=True)
    docs = {"primary": old}
    backup_quote = b"An independent source supports the same edge."
    if alternative:
        docs["backup"] = backup_quote
    C.write_docs(work / "docs", docs)
    write_json(work / "ontology.json", C.ontology_graph(["a", "b"]))
    ops = [C.L_bind("e", "primary", quote.decode("ascii")),
           C.L_assert("edge", "a", "edge", "b", (1, 2), ["e"]),
           C.L_derive("reach", "R_seed@1", ["edge"], C.claim_of("a", "reach", "b", (1, 2)))]
    if alternative:
        ops += [C.L_bind("alt", "backup", backup_quote.decode("ascii")),
                C.L_assert("same_edge", "a", "edge", "b", (1, 2), ["alt"])]
    C.write_lines(work / "stream.jsonl", C.jsonl(C.numbered(ops)))
    base, updated = work / "base.sbgk", work / "updated.sbgk"
    apply = C.cli("apply", "--ontology", work / "ontology.json", "--docs", work / "docs",
                  "--stream", work / "stream.jsonl", "--out", base, "--oracle",
                  "--cdc-mode", "fastcdc", "--cdc-min", 64, "--cdc-avg", 64, "--cdc-max", 64)
    if apply["error"] is not None or apply["accepted"] != len(ops):
        raise AssertionError(f"{name}: fixture ingestion failed: {apply}")
    old_evidence = evidence_from_container(base)
    main_ids = [key for key, ev in old_evidence.items() if ev["doc_id"] == "primary"]
    if len(main_ids) != 1 or len(old_evidence[main_ids[0]]["segments"]) < 2:
        raise AssertionError(f"{name}: fixture must bind exactly one multi-segment quote")
    old_id = main_ids[0]
    if (old_evidence[old_id]["status"] != 0 or old_evidence[old_id]["quote"] != quote
            or not anchored_occurrences(old_evidence[old_id], old)
            or len(occurrences(old, quote)) != 1):
        raise AssertionError(f"{name}: the original anchor must have one valid byte occurrence")
    before_nodes = C.cli("dump-nodes", base)
    expected_claim_ids = {node["id"] for node in before_nodes if node["kind"] == "claim"}
    if len(expected_claim_ids) != 2 or any(node["status"] != "SUPPORTED" for node in before_nodes if node["kind"] == "claim"):
        raise AssertionError(f"{name}: expected one edge and one supported derived claim")
    (work / "new.txt").write_bytes(new)
    update = C.cli("update-doc", base, "--doc-id", "primary", "--file", work / "new.txt", "--out", updated)
    nodes = C.cli("dump-nodes", updated)
    claims = C.cli("dump-claims", updated)
    verify = C.cli("verify", updated)
    after_evidence = evidence_from_container(updated)
    current_docs = dict(docs, primary=new)
    active = {key: ev for key, ev in after_evidence.items() if ev["status"] == 0}
    false_active = [key for key, ev in active.items() if not anchored_occurrences(ev, current_docs[ev["doc_id"]])]
    active_main = {key for key, ev in active.items() if ev["doc_id"] == "primary"}
    actual_claim_ids = {node["id"] for node in nodes if node["kind"] == "claim"}
    expected_status = "SUPPORTED" if survives or alternative else "UNSUPPORTED"
    new_chunk_hashes = [digest(new[start:start + 64]) for start in range(0, len(new), 64)]
    anchor_chunk_hashes = [h for h, _, _ in old_evidence[old_id]["segments"]]
    checks = {
        "fixture_exact_occurrence_count": len(occurrences(new, quote)) == expected_occurrences,
        "original_anchor_status": after_evidence[old_id]["status"] == (2 if rebind or not survives else 0),
        "active_primary_count": len(active_main) == int(survives),
        "rebind_identity": not rebind or (survives and old_id not in active_main and len(active_main) == 1),
        "zero_false_active": not false_active,
        "claim_identities_preserved": actual_claim_ids == expected_claim_ids,
        "claim_statuses_match_byte_oracle": all(node["status"] == expected_status for node in nodes if node["kind"] == "claim"),
        "claim_contents_preserved": {(row["s"], row["p"], row["o"]) for row in claims} == {("a", "edge", "b"), ("a", "reach", "b")},
        "separate_dred_oracle": update["oracle_ok"] is True,
        "container_verifies": verify.get("ok") is True,
    }
    if name in {"reorder", "insert_between", "repeated_hash_later_window", "insufficient_multiplicity",
                "relocate_whole_quote", "alternative_support"}:
        checks["fixture_retains_every_anchor_chunk_hash"] = set(anchor_chunk_hashes) <= set(new_chunk_hashes)
    if name == "insufficient_multiplicity":
        checks["fixture_requires_repeated_hash"] = len(anchor_chunk_hashes) == 2 and len(set(anchor_chunk_hashes)) == 1
        checks["fixture_has_only_one_copy"] = new_chunk_hashes.count(anchor_chunk_hashes[0]) == 1
    if name in {"unique_rebind", "ambiguous_rebind"}:
        checks["fixture_invalidates_original_chunks"] = not (set(anchor_chunk_hashes) & set(new_chunk_hashes))
    result = {"name": name, "quote_ascii": quote.decode("ascii"), "old_sha256": digest(old), "new_sha256": digest(new),
              "original_evidence_id": old_id, "active_primary_ids": sorted(active_main), "expected_claim_ids": sorted(expected_claim_ids),
              "expected_quote_occurrences": expected_occurrences, "expected_claim_status": expected_status,
              "original_anchor_segments": old_evidence[old_id]["segments"], "new_chunk_hashes": new_chunk_hashes,
              "false_active_ids": false_active,
              "checks": checks, "pass": all(checks.values()), "update": update, "claims": claims, "verify": verify}
    write_json(work / "result.json", result)
    return result


def continuity_series(out: Path) -> dict:
    def block(seed: int) -> bytes:
        rng = random.Random(seed)
        return bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(64))

    p, a, b, x, s = [block(seed) for seed in range(71, 76)]
    old, quote = p + a + b + s, a[-16:] + b[:16]
    specs = [
        ("reorder", old, p + b + a + s, quote, 0, False),
        ("insert_between", old, p + a + x + b + s, quote, 0, False),
        ("repeated_hash_later_window", old, p + a + x + a + b + s, quote, 1, True),
        ("insufficient_multiplicity", p + a + a + s, p + a + s, a[-16:] + a[:16], 0, False),
        ("relocate_whole_quote", old, s + a + b + p, quote, 1, True),
        ("remove_quote", old, p + x + s, quote, 0, False),
        ("unique_rebind", old, b"!" + old, quote, 1, True, True),
        ("ambiguous_rebind", old, b"!" + old + old, quote, 2, False),
        ("alternative_support", old, p + a + x + b + s, quote, 0, False, False, True),
    ]
    rows = [continuity_case(out, *spec) for spec in specs]
    return {"cdc_mode": "fastcdc", "cdc_min": 64, "cdc_avg": 64, "cdc_max": 64,
            "purpose": "Controlled chunk continuity, independent of production CDC boundary resilience",
            "oracle": "Current source byte occurrences, exact anchored spans, claim identities and statuses",
            "rows": rows, "pass": all(row["pass"] for row in rows)}


def compatibility_series(out: Path, baseline: Path) -> dict:
    """Keep legacy containers and the original JSON journal byte-for-byte intact.

    Journal recovery is performed only on separate copies. This demonstrates a
    semantic replay difference, not an authorized automatic migration policy.
    """
    work = out / "compat"
    work.mkdir()
    old, new, quote = b"P0p1A2a3B4b5S6s7", b"P0p1B4b5A2a3S6s7", b"a3B4"
    C.write_docs(work / "docs", {"primary": old})
    (work / "new.txt").write_bytes(new)
    write_json(work / "ontology.json", C.ontology_graph(["a", "b"]))
    ops = C.numbered([C.L_bind("e", "primary", quote.decode()),
                      C.L_assert("edge", "a", "edge", "b", (1, 2), ["e"]),
                      C.L_derive("reach", "R_seed@1", ["edge"], C.claim_of("a", "reach", "b", (1, 2)))])
    C.write_lines(work / "stream.jsonl", C.jsonl(ops))
    unaffected, affected = work / "legacy-unaffected.sbgk", work / "legacy-affected.sbgk"
    applied = C.cli("apply", "--ontology", work / "ontology.json", "--docs", work / "docs",
                    "--stream", work / "stream.jsonl", "--out", unaffected, "--oracle",
                    "--cdc-mode", "fastcdc", "--cdc-min", 4, "--cdc-avg", 4, "--cdc-max", 4,
                    binary=baseline)
    if applied["error"] is not None or applied["accepted"] != len(ops):
        raise AssertionError(f"legacy fixture ingestion failed: {applied}")
    update = C.cli("update-doc", unaffected, "--doc-id", "primary", "--file", work / "new.txt",
                   "--out", affected, binary=baseline)
    preserved_before = {p.name: digest(p.read_bytes()) for p in (unaffected, affected)}
    verification = {
        "baseline_unaffected": C.cli("verify", unaffected, binary=baseline),
        "baseline_affected": C.cli("verify", affected, binary=baseline),
        "current_unaffected": C.cli("verify", unaffected),
        "current_affected": C.cli("verify", affected),
    }
    journal_original = work / "legacy-original.jsonl"
    legacy_live = work / "legacy-live.sbgk"
    requests = [{"op": "put_document", "doc_id": "primary", "text": new.decode()},
                {"op": "finish", "out": str(legacy_live)}]
    live = C.cli("serve", "--base", unaffected, "--wal-path", journal_original, "--ack", "full",
                 stdin="\n".join(json.dumps(row) for row in requests) + "\n", binary=baseline, json_lines=True)
    original_bytes = journal_original.read_bytes()
    replay, journals = {}, {}
    for label, binary in (("baseline", baseline), ("current", C.BIN)):
        copied = work / f"{label}-replay-copy.jsonl"
        copied.write_bytes(original_bytes)
        snapshot = work / f"{label}-replayed.sbgk"
        response = C.cli("serve", "--base", unaffected, "--wal-path", copied,
                         stdin=json.dumps({"op": "finish", "out": str(snapshot)}) + "\n",
                         binary=binary, json_lines=True)
        replay[label] = {"response": response, "nodes": C.cli("dump-nodes", snapshot),
                         "verify": C.cli("verify", snapshot, binary=binary),
                         "snapshot_sha256": digest(snapshot.read_bytes())}
        journals[label] = {"copy_sha256_before": digest(original_bytes),
                           "copy_sha256_after": digest(copied.read_bytes())}
    claim_sets = {label: {node["id"] for node in rep["nodes"] if node["kind"] == "claim"}
                  for label, rep in replay.items()}
    claims = {label: [node for node in rep["nodes"] if node["kind"] == "claim"]
              for label, rep in replay.items()}
    checks = {
        "quote_absent_after_reorder": not occurrences(new, quote),
        "same_four_chunk_hashes_reordered": sorted(old[i:i + 4] for i in range(0, len(old), 4)) == sorted(new[i:i + 4] for i in range(0, len(new), 4)),
        "baseline_unaffected_verifies": verification["baseline_unaffected"].get("ok") is True,
        "baseline_affected_verifies": verification["baseline_affected"].get("ok") is True,
        "current_unaffected_verifies": verification["current_unaffected"].get("ok") is True,
        "current_affected_rejected_with_node_table_mismatch": verification["current_affected"].get("ok") is False and verification["current_affected"].get("kind") == "node_table_mismatch",
        "legacy_container_bytes_preserved": preserved_before == {p.name: digest(p.read_bytes()) for p in (unaffected, affected)},
        "original_journal_bytes_preserved": journal_original.read_bytes() == original_bytes,
        "replay_copy_bytes_preserved": all(row["copy_sha256_before"] == row["copy_sha256_after"] for row in journals.values()),
        "baseline_journal_replay_supported": len(claims["baseline"]) == 2 and all(row["status"] == "SUPPORTED" for row in claims["baseline"]),
        "current_journal_replay_unsupported": len(claims["current"]) == 2 and all(row["status"] == "UNSUPPORTED" for row in claims["current"]),
        "replayed_claim_identities_equal": len(claim_sets["baseline"]) == 2 and claim_sets["baseline"] == claim_sets["current"],
        "replayed_roots_differ": replay["baseline"]["response"][-1]["state_root"] != replay["current"]["response"][-1]["state_root"],
        "both_replayed_snapshots_verify_with_own_version": all(row["verify"].get("ok") is True for row in replay.values()),
    }
    return {"baseline_declared_build_revision": BASELINE_REVISION, "baseline_binary_sha256": digest(baseline.read_bytes()),
            "cdc_mode": "fastcdc", "cdc_min": 4, "cdc_avg": 4, "cdc_max": 4,
            "legacy_container_hashes": preserved_before, "verification": verification, "legacy_update": update,
            "legacy_live_response": live, "original_journal_sha256": digest(original_bytes),
            "journal_copies": journals, "journal_replay": replay, "checks": checks, "pass": all(checks.values()),
            "policy": "Evidence only. Original containers and journal are preserved; no format migration is performed."}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="new results/byteanchor-continuity-RUN_ID directory")
    parser.add_argument("--binary", type=Path, default=C.BIN, help="already-built sbgk binary")
    parser.add_argument("--baseline-bin", type=Path, help=f"optional already-built pre-fix binary from {BASELINE_REVISION}")
    parser.add_argument("--continuity-only", action="store_true", help="run only the separate byte-correctness series")
    args = parser.parse_args()
    out = args.out.resolve()
    results = (C.ROOT / "results").resolve()
    if out.parent != results or not out.name.startswith("byteanchor-continuity-"):
        parser.error("--out must be a new direct child results/byteanchor-continuity-RUN_ID")
    if out.exists():
        parser.error("--out already exists; use a new run ID (existing evidence is never resumed or overwritten)")
    C.BIN = args.binary.resolve()
    if not C.BIN.is_file():
        parser.error("the already-built binary does not exist")
    baseline = args.baseline_bin.resolve() if args.baseline_bin else None
    if baseline is not None and not baseline.is_file():
        parser.error("the supplied baseline binary does not exist")
    historical_before = historical_manifest(out)
    sources_before = source_manifest()
    binary_before = digest(C.BIN.read_bytes())
    baseline_before = digest(baseline.read_bytes()) if baseline is not None else None
    revision = git("rev-parse", "HEAD").decode().strip()
    patch = git("diff", "--binary", "HEAD")
    out.mkdir(parents=True, exist_ok=False)
    (out / "revision.patch").write_bytes(patch)
    write_json(out / "historical-before.json", historical_before)
    write_json(out / "sources-before.json", sources_before)
    write_json(out / "run.json", {"started_utc": utc(), "argv": sys.argv, "head": revision,
                                  "branch": git("branch", "--show-current").decode().strip(),
                                  "git_status": git("status", "--short").decode(), "diff_sha256": digest(patch),
                                  "binary": str(C.BIN), "binary_sha256": binary_before,
                                  "baseline_binary": str(baseline) if baseline else None,
                                  "baseline_binary_sha256": baseline_before,
                                  "baseline_declared_build_revision": BASELINE_REVISION if baseline else None,
                                  "baseline_provenance": "Operator-supplied pre-fix build; revision is declared, binary SHA256 is measured" if baseline else None,
                                  "python": platform.python_version(), "platform": platform.platform(),
                                  "cpu_count": os.cpu_count(), "full_exp1": not args.continuity_only,
                                  "source_manifest_sha256": digest((out / "sources-before.json").read_bytes())})
    C.RESULTS, C.WORK = out, out / "work"
    C.cli = CliRecorder(out)
    summary, t0, failure = {}, time.perf_counter(), None
    try:
        if not args.continuity_only:
            print("Running unchanged full EXP-1 (LocalMax and FastCDC)...", flush=True)
            result = exp1.run(quick=False)
            write_json(out / "exp1.json", result)
            summary["exp1_pass"] = all(result["pass"].values())
            summary["exp1_checks"] = result["pass"]
        print("Running independent continuity byte oracle...", flush=True)
        result = continuity_series(out)
        write_json(out / "continuity.json", result)
        summary["continuity_pass"] = result["pass"]
        summary["continuity_cases"] = {row["name"]: row["pass"] for row in result["rows"]}
        if baseline is not None:
            print("Checking preserved legacy containers and JSON journal replay copies...", flush=True)
            result = compatibility_series(out, baseline)
            write_json(out / "compatibility.json", result)
            summary["compatibility_pass"] = result["pass"]
            summary["compatibility_checks"] = result["checks"]
    except Exception:
        failure = traceback.format_exc()
        (out / "failure.txt").write_text(failure, encoding="utf-8")
    finally:
        historical_after = historical_manifest(out)
        sources_after = source_manifest()
        write_json(out / "historical-after.json", historical_after)
        write_json(out / "sources-after.json", sources_after)
        summary.update({"finished_utc": utc(), "elapsed_seconds": time.perf_counter() - t0,
                        "historical_files_unchanged": historical_before == historical_after,
                        "source_files_unchanged_during_run": sources_before == sources_after,
                        "binary_unchanged_during_run": binary_before == digest(C.BIN.read_bytes()),
                        "baseline_binary_unchanged_during_run": baseline is None or baseline_before == digest(baseline.read_bytes()),
                        "head_unchanged_during_run": revision == git("rev-parse", "HEAD").decode().strip(),
                        "exception": failure, "cli_calls": C.cli.calls})
        summary["pass"] = failure is None and all(summary.get(key, False) for key in
                                                  ["historical_files_unchanged", "source_files_unchanged_during_run",
                                                   "binary_unchanged_during_run", "head_unchanged_during_run", "continuity_pass"])
        if baseline is not None:
            summary["pass"] &= summary["baseline_binary_unchanged_during_run"] and summary.get("compatibility_pass", False)
        if not args.continuity_only:
            summary["pass"] &= summary.get("exp1_pass", False)
        write_json(out / "summary.json", summary)
        write_json(out / "artifact-manifest.json", file_manifest(out.rglob("*")))
    print(json.dumps(summary, indent=2), flush=True)
    return 0 if summary["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
