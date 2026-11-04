#!/usr/bin/env python3
"""EXP-10: resident MCP server, asynchronous leases, shared-premise lock, kernel auto-closure of P2A
-> results/exp10/ and SBGK_EXPERIMENT_REPORT_MCP_SWARM.md.

    python benchmarks/run_exp10_mcp_swarm.py --selftest        # offline checks, no model calls (~1 min)
    python benchmarks/run_exp10_mcp_swarm.py --smoke           # small deterministic series + 10C on 2 cases with real models
    python benchmarks/run_exp10_mcp_swarm.py                   # everything: 10A, 10A-RT, 10B, guard probes, 10C (6 cases, real models)
    python benchmarks/run_exp10_mcp_swarm.py --series a,b      # some series only (a, rt, b, guard, c)
    python benchmarks/run_exp10_mcp_swarm.py --report-only

Separate from every earlier experiment: it writes only results/exp10/ and the new report (EXP-9's call cache is read, never written).
10C needs Codex CLI, OpenClaw (deepseek-chat) and Claude Code >= 2.1.280 (Sonnet 5.5).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from sbgk_bench import common as C  # noqa: E402
from sbgk_bench import exp10_mcp_swarm as M  # noqa: E402

FILES = {"a": "exp10a.json", "rt": "exp10a_rt.json", "b": "exp10b.json", "guard": "guard.json", "c": "exp10c.json"}


def save(key: str, data: dict, suffix: str = "") -> None:
    M.OUT.mkdir(parents=True, exist_ok=True)
    f = M.OUT / (FILES[key].replace(".json", f"{suffix}.json"))
    f.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {f}")


def load(suffix: str = "") -> dict:
    out = {}
    for k, name in FILES.items():
        f = M.OUT / name.replace(".json", f"{suffix}.json")
        if f.exists():
            out[k] = json.loads(f.read_text(encoding="utf-8"))
    for extra in ("frames_identity_exp9.json", "machine.json", "quality.json"):
        f = M.OUT / extra
        if f.exists():
            out[extra.split(".")[0]] = json.loads(f.read_text(encoding="utf-8"))
    return out


def write_report(name: str | None = None) -> None:
    report_mcp_swarm = C.report_module("report_mcp_swarm")
    data = load()
    if not data:
        print("no results yet")
        return
    text, summary = report_mcp_swarm.render(data)
    out = C.ROOT / (name or C.report_name("SBGK_EXPERIMENT_REPORT_MCP_SWARM"))
    out.write_text(text, encoding="utf-8")
    (M.OUT / C.summary_name()).write_text(json.dumps(summary, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {out} and {M.OUT / C.summary_name()}")


def quality() -> dict:
    """`cargo test --release --workspace`: tests passed / failed and compiler warnings (the zero-breaking-changes gate)."""
    import re
    import subprocess
    r = subprocess.run(["cargo", "test", "--release", "--workspace"], cwd=C.ROOT, capture_output=True, text=True, encoding="utf-8")
    text = r.stdout + r.stderr
    passed = sum(int(x) for x in re.findall(r"test result: \w+\. (\d+) passed", text))
    failed = sum(int(x) for x in re.findall(r"(\d+) failed;", text))
    warnings = len(re.findall(r"^warning: ", text, flags=re.M))
    new = len(re.findall(r"^test (swarm::tests::\S+|concurrent_workers\S*|ttl_scope\S*|stdio_transport\S*) \.\.\. ok", text, flags=re.M))
    res = {"passed": passed, "failed": failed, "warnings": warnings, "new_tests": new, "exit_code": r.returncode}
    M.OUT.mkdir(parents=True, exist_ok=True)
    (M.OUT / "quality.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    print(f"cargo test: {res}")
    return res


def selftest() -> int:
    """No model calls: protocol, the three schedules on one c_long96 case, fan-in, guard probes, the 10C loop with the oracle worker."""
    t0 = time.time()
    checks = []

    def check(name: str, ok: bool, detail="") -> None:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})
        print(f"  [{'ok' if ok else 'FAIL'}] {name} {detail}")

    with M.McpServer() as srv:
        c = srv.client()
        names = {t["name"] for t in c.rpc("tools/list", {})["result"]["tools"]}
        need = {"sbgk_init_session", "sbgk_acquire_directive", "sbgk_submit_directive", "sbgk_post_erratum", "sbgk_query_cone", "sbgk_swarm_status"}
        check("MCP tools/list", need <= names, f"{len(names)} tools")
    a = M.exp10a([0], ks=(4, 16))
    check("10A: every final root equals the reference", all(r["root_ok"] for r in a["rows"]))
    check("10A: no collisions", all(r["collisions"] == 0 for r in a["rows"]))
    check("10A: full schedule never calls a worker for P2A", all(r["llm_calls_p2a"] == 0 for r in a["rows"] if r["schedule"] == "full"))
    b = M.exp10b([0])
    by = {r["dispatcher"]: r for r in b["rows"]}
    check("10B: shared-premise lock extracts every clause once", by["full"]["dep_binds"] == 6 and by["premise_lock"]["dep_binds"] == 6,
          f"target-only {by['target_only']['dep_binds']} / lock {by['premise_lock']['dep_binds']} / full {by['full']['dep_binds']}")
    check("10B: roots equal", all(r["root_ok"] for r in b["rows"]))
    g = M.guard_probes(0)
    check("guard probes", g["all_ok"])
    o = M.oracle_live_check(M.case_c(0))
    check("10C loop with the oracle worker reaches the goal", o["completed"] and o["collisions"] == 0, json.dumps(o))
    o = M.oracle_live_check(M.case_c(0, literal_enum=True))
    check("10C loop on the literal-enum ontology reaches the goal", o["completed"] and o["collisions"] == 0, json.dumps(o))
    res = {"checks": checks, "all_ok": all(x["ok"] for x in checks), "seconds": time.time() - t0, "machine": M.machine()}
    M.OUT.mkdir(parents=True, exist_ok=True)
    (M.OUT / "selftest.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    print(f"selftest {'passed' if res['all_ok'] else 'FAILED'} in {res['seconds']:.0f} s")
    return 0 if res["all_ok"] else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--series", default="a,rt,b,guard,c")
    ap.add_argument("--cases", type=int, default=None, help="cases per series (default: 4 for 10A/10B, 6 for 10C)")
    ap.add_argument("--workers", type=int, default=2, help="10C: runs in parallel (each run has 4 model workers)")
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--fresh", action="store_true", help="10C: redo runs that are already stored")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--quality", action="store_true", help="run cargo test and record tests / warnings for the report")
    ap.add_argument("--out", default=None)
    ap.add_argument("--lang", choices=["en", "ru"], default="en", help="report language: en (tracked report) or ru (local *_RU.md from the untracked *_ru.py modules)")
    args = ap.parse_args()
    C.REPORT_LANG = args.lang
    if args.report_only:
        write_report(args.out)
        return 0
    if not args.skip_build:
        C.build_release()
    if args.selftest:
        return selftest()
    if args.quality:
        q = quality()
        return 0 if q["failed"] == 0 and q["exit_code"] == 0 else 1
    series = args.series.split(",")
    sfx = "_smoke" if args.smoke else ""
    M.OUT.mkdir(parents=True, exist_ok=True)
    (M.OUT / "machine.json").write_text(json.dumps(M.machine(), indent=1), encoding="utf-8")
    n_ab = 1 if args.smoke else (args.cases or 4)
    if "a" in series:
        print(f"== 10A: {n_ab} case(s) x K {M.K_LIST} x 3 schedules", flush=True)
        save("a", M.exp10a(list(range(n_ab)), ks=(4, 16, 64) if args.smoke else M.K_LIST), sfx)
    if "rt" in series:
        print("== 10A-RT: real concurrency", flush=True)
        ref = M.run_sync(M.case96(0), 4, M.PROFILE_A, 10_000)["state_root"]
        save("rt", M.exp10a_rt(0, ks=(16,) if args.smoke else (16, 64, 100), ref_root=ref), sfx)
    if "b" in series:
        print(f"== 10B: {n_ab} fan-in case(s), K = 60", flush=True)
        save("b", M.exp10b(list(range(n_ab))), sfx)
    if "guard" in series:
        print("== guard probes", flush=True)
        n = 1 if args.smoke else (args.cases or 6)
        runs = [M.guard_probes(i) for i in range(n)]
        save("guard", {"runs": runs, "all_ok": all(r["all_ok"] for r in runs)}, sfx)
    if "c" in series:
        n = 2 if args.smoke else (args.cases or 6)
        print(f"== 10C: {n} case(s) x (sync, swarm), real models", flush=True)
        save("c", M.exp10c(n, workers=args.workers, fresh=args.fresh), sfx)
    if not args.smoke:
        try:
            write_report(args.out)
        except (ImportError, AttributeError, KeyError) as e:
            print(f"report not written: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
