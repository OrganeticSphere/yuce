#!/usr/bin/env python3
"""EXP-9: Compiler-Driven Directive Emitter + Stateless O(1) graph-builders -> results/exp9/ and SBGK_EXPERIMENT_REPORT_DIRECTIVE.md.

    python benchmarks/run_exp9_directive.py --oracle               # offline: compiler + harness with a deterministic worker (no model calls)
    python benchmarks/run_exp9_directive.py --smoke                # 2 cases per block, real models
    python benchmarks/run_exp9_directive.py --block b_parallel     # one block (default case count)
    python benchmarks/run_exp9_directive.py                        # every block
    python benchmarks/run_exp9_directive.py --window               # window size of stateful vs directive on identical graph states
    python benchmarks/run_exp9_directive.py --speed [--baseline-bin OLD_SBGK]   # compiler speed: resident `serve` op vs CLI (no models)
    python benchmarks/run_exp9_directive.py --report-only

Blocks: a_trio, a_solo (EXP-9A), b_parallel (EXP-9B), c_retract, c_long (EXP-9C). Separate from every earlier experiment:
it writes only results/exp9/ and the new report. Needs the built `sbgk` with emit-batch-directives, Codex CLI, OpenClaw
(deepseek-chat) and Claude Code >= 2.1.280 (Sonnet 5.5).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from sbgk_bench import common as C  # noqa: E402
from sbgk_bench import exp9_directive_emitter as X  # noqa: E402

DEFAULT_CASES = {"a_trio": 6, "a_solo": 6, "b_parallel": 6, "c_retract": 6, "c_long": 2}
MODEL_BLOCKS = ["a_trio", "a_solo", "b_parallel", "c_retract", "c_long"]


def load_all(oracle: bool = False) -> dict:
    data = {}
    for b in MODEL_BLOCKS:
        f = X.OUT / f"{b}{'_oracle' if oracle else ''}.json"
        if f.exists():
            data[b] = json.loads(f.read_text(encoding="utf-8"))
    return data


def write_report(name: str | None = None) -> None:
    report_directive = C.report_module("report_directive")
    data = load_all()
    oracle = load_all(oracle=True)
    if not data and not oracle:
        print("no results yet")
        return
    out = C.ROOT / (name or C.report_name("SBGK_EXPERIMENT_REPORT_DIRECTIVE"))
    text, summary = report_directive.render(data, oracle)
    out.write_text(text, encoding="utf-8")
    (X.OUT / C.summary_name()).write_text(json.dumps(summary, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {out} and {X.OUT / C.summary_name()}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--block", default=",".join(MODEL_BLOCKS))
    ap.add_argument("--cases", type=int, default=None)
    ap.add_argument("--modes", default=None, help="comma list; default: the block's modes")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--oracle", action="store_true", help="deterministic worker instead of models (directive mode only)")
    ap.add_argument("--fresh", action="store_true")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--window", action="store_true", help="deterministic window-size replay on identical graph states (c_long, c_long96)")
    ap.add_argument("--speed", action="store_true", help="compiler speed on the 16/20/48/96-service registers: resident serve op vs CLI, "
                    "identical states from the oracle worker (results/exp9/speed_resident.json)")
    ap.add_argument("--baseline-bin", default=None, help="with --speed: an older sbgk binary measured on the same states (frames must be identical)")
    ap.add_argument("--reps", type=int, default=3, help="with --speed: CLI calls per state (the resident op is called reps+2 times)")
    ap.add_argument("--cli-directives", action="store_true", help="per-round frames from the one-shot CLI on a snapshot (as in the "
                    "model runs of the report) instead of the resident serve op; the frames are identical")
    ap.add_argument("--out", default=None)
    ap.add_argument("--lang", choices=["en", "ru"], default="en", help="report language: en (tracked report) or ru (local *_RU.md from the untracked *_ru.py modules)")
    args = ap.parse_args()
    C.REPORT_LANG = args.lang
    if args.report_only:
        write_report(args.out)
        return 0
    X.RESIDENT = not args.cli_directives
    if not args.skip_build:
        C.build_release()
    if args.speed:
        from sbgk_bench import exp9_speed
        base = pathlib.Path(args.baseline_bin).resolve() if args.baseline_bin else None
        res = exp9_speed.run(baseline=base, reps_cli=args.reps, reps_serve=args.reps + 2)
        X.OUT.mkdir(parents=True, exist_ok=True)
        (X.OUT / "speed_resident.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
        print(f"identical frames on every state: {res['identical_all']}; wrote {X.OUT / 'speed_resident.json'}")
        write_report(args.out)
        return 0 if res["identical_all"] else 1
    if args.window:
        out = {}
        for b, idx, k in (("c_long", 0, None), ("c_long", 1, None), ("c_long96", 0, None), ("c_long96", 0, 3)):
            key = f"{b}_c{idx}" + (f"_k{k}" if k else "")
            out[key] = X.window_replay(b, idx, k)
            print(key, "steps", len(out[key]))
        X.OUT.mkdir(parents=True, exist_ok=True)
        (X.OUT / "window_replay.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
        write_report(args.out)
        return 0
    for b in args.block.split(","):
        n = 2 if args.smoke else (args.cases or DEFAULT_CASES[b])
        modes = ["directive"] if args.oracle else (args.modes.split(",") if args.modes else None)
        print(f"== {b}: {n} cases x {modes or X.MODES9[b]}{' (oracle)' if args.oracle else ''}", flush=True)
        data = X.run_block(b, n, modes, workers=args.workers, fresh=args.fresh, oracle=args.oracle)
        f = X.OUT / f"{b}{'_oracle' if args.oracle else ''}.json"
        if f.exists():
            prev = json.loads(f.read_text(encoding="utf-8"))
            if len(prev.get("case_info", [])) > len(data["case_info"]) or (set(prev.get("modes", [])) - set(data["modes"])):
                # merge: keep earlier runs of cases/modes this call did not cover
                keep = [r for r in prev["results"] if not any(r["case"] == x["case"] and r["mode"] == x["mode"] for x in data["results"])]
                data["results"] = keep + data["results"]
                data["modes"] = sorted(set(prev.get("modes", [])) | set(data["modes"]), key=lambda m: (X.MODES9[b] + ["directive"]).index(m))
                if len(prev["case_info"]) > len(data["case_info"]):
                    data["case_info"] = prev["case_info"]
        f.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
    try:
        write_report(args.out)
    except (ImportError, AttributeError) as e:
        print(f"report not written: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
