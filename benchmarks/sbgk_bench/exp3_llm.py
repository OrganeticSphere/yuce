"""EXP-3 with a live agent: Codex CLI (model gpt-5.6-sol by default) instead of the scripted repair policy.

Same 30 tasks and the same injected errors as `exp3.py` (imported, not modified). The first, faulty emission is still
scripted (it is the *injected* error); everything after it is produced by the model:

  A1  monolithic graph, generic validator error (code + seq + message)  -> model re-emits the whole graph
  A2  monolithic graph, structured error (expected_by_kernel, obligation) -> model emits a JSON patch
  B   streaming: lines 1..k-1 accepted, the model repairs line k from the structured error,
      then continues the stream with the remaining lines

The kernel judges every output; success means the final state root equals the gold root. Token usage comes from
`codex exec --json` (`turn.completed.usage`); the fixed per-call overhead of Codex itself (system prompt, tool schema)
is measured with a trivial prompt and subtracted to give "net" input tokens.

Nothing in the prompts contains the gold stream; the model sees the work order, the document, the ontology, the
faulty lines and the kernel feedback. Each call runs in an empty temporary directory, read-only sandbox, ephemeral
session, with the user's Codex config ignored; tool use is counted from the event stream and reported.
"""

from __future__ import annotations

import concurrent.futures as cf
import hashlib
import json
import pathlib
import random
import re
import shutil
import subprocess
import tempfile
import threading
import time

from . import common as C
from . import exp3

OUT = C.RESULTS / "exp3_llm"
CALLS = OUT / "calls"
MAX_ROUNDS = 3
_lock = threading.Lock()

SYSTEM_BRIEF = """You are the *proposer* agent in a deterministic knowledge-graph pipeline. You write short JSONL events; a trusted kernel
validates every line, binds quotes to the document bytes and computes all derived values. You never judge truth.
Do NOT use tools, do NOT read or write files; answer with the requested text only (no commentary, no code fences).

Event formats (one JSON object per line, `seq` consecutive starting at 1):
{"seq":n,"op":"bind_evidence","local_id":"e1","doc_id":"doc","exact_quote":"<byte-exact substring of the document>"}
{"seq":n,"op":"assert_fact","local_id":"f1","s":"n0","p":"edge","o":"n1","polarity":"POS","ctx":"prod","t":[from,to],"evidence":["e1"]}
{"seq":n,"op":"derive","local_id":"r1","rule":"R_step@1","premises":["r0","f1"],"claim":{"s":"n0","p":"reach","o":"n2","polarity":"POS","ctx":"prod","t":[from,to]}}
{"seq":n,"op":"revoke_evidence","target_evidence":"e1"}

Semantics: intervals are half-open [from,to). A derived claim's interval is the intersection of its premises' intervals
(max of the starts, min of the ends). A derivation needs every premise to be currently supported (a fact is supported while at
least one of its evidence items is not revoked). Entity names must be canonical ids or unambiguous aliases of the ontology.
"""


# ------------------------------------------------------------------ Codex plumbing

def find_codex() -> str:
    cands = list(pathlib.Path.home().glob("AppData/Roaming/npm/node_modules/@openai/codex/node_modules/@openai/codex-*/vendor/*/bin/codex.exe"))
    cands += [pathlib.Path(p) for p in shutil.which("codex") and [shutil.which("codex")] or []]
    best, best_v = None, (0, 0, 0)
    for c in cands:
        try:
            out = subprocess.run([str(c), "--version"], capture_output=True, text=True, timeout=30).stdout
            v = tuple(int(x) for x in re.search(r"(\d+)\.(\d+)\.(\d+)", out).groups())
        except Exception:
            continue
        if v > best_v:
            best, best_v = str(c), v
    if not best:
        raise RuntimeError("codex CLI not found")
    return best


class Agent:
    def __init__(self, codex: str, model: str, effort: str | None, timeout: int = 900):
        self.codex, self.model, self.effort, self.timeout = codex, model, effort, timeout
        self.cached = 0
        self.version = subprocess.run([codex, "--version"], capture_output=True, text=True).stdout.strip()

    def call(self, prompt: str, tag: str) -> dict:
        key = hashlib.sha256((self.model + str(self.effort) + prompt).encode()).hexdigest()[:24]
        f = CALLS / f"{key}.json"
        if f.exists():
            r = json.loads(f.read_text(encoding="utf-8"))
            r["from_cache"] = True
            with _lock:
                self.cached += 1
            return r
        last = None
        for attempt in range(3):
            tmp = pathlib.Path(tempfile.mkdtemp(prefix="sbgk_llm_"))
            try:
                cmd = [self.codex, "exec", "-m", self.model, "-s", "read-only", "--ephemeral", "--skip-git-repo-check",
                       "--ignore-user-config", "--ignore-rules", "--json", "-C", str(tmp)]
                if self.effort:
                    cmd += ["-c", f'model_reasoning_effort="{self.effort}"']
                cmd.append("-")
                t0 = time.time()
                p = subprocess.run(cmd, input=prompt, capture_output=True, text=True, encoding="utf-8", timeout=self.timeout)
                dt = time.time() - t0
            except subprocess.TimeoutExpired:
                last = {"error": "timeout"}
                continue
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
            text, usage, tool_items, errors = "", None, 0, []
            for line in p.stdout.splitlines():
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                t = ev.get("type")
                if t == "item.completed":
                    item = ev.get("item", {})
                    if item.get("type") == "agent_message":
                        text = item.get("text", "")
                    elif item.get("type") not in ("reasoning",):
                        tool_items += 1
                elif t == "turn.completed":
                    usage = ev.get("usage")
                elif t in ("error", "turn.failed"):
                    errors.append(ev)
            if text and usage:
                r = {"tag": tag, "model": self.model, "text": text, "usage": usage, "tool_items": tool_items, "seconds": dt,
                     "attempts": attempt + 1, "prompt_chars": len(prompt)}
                CALLS.mkdir(parents=True, exist_ok=True)
                f.write_text(json.dumps({**r, "prompt": prompt}, ensure_ascii=False, indent=0), encoding="utf-8")
                return r
            last = {"error": "no_message", "stderr": p.stderr[-400:], "events": errors[:2]}
        raise RuntimeError(f"codex call failed ({tag}): {last}")

    def baseline(self) -> dict:
        r = self.call('Reply with exactly one line of JSON: {"ok":1}. Do not use tools.', "baseline")
        return r["usage"]


# ------------------------------------------------------------------ prompts

def work_order(t: exp3.Task) -> str:
    L = t.L
    rows = "\n".join(f'  L{i}: "{t.quotes[i]}"  -> edge(n{i}, n{i + 1}), valid over t=[{t.T[i][0]},{t.T[i][1]})' for i in range(L))
    s = ("WORK ORDER. Document id: \"doc\" (below). Context \"prod\", polarity POS for everything. Record the chain of links below as a\n"
         "reachability graph from n0: for each link bind its sentence as evidence, assert the edge fact, and derive reach(n0, n_{i+1}).\n"
         "The first link is derived with rule R_seed@1 (premise: the edge fact), every later link with R_step@1 (premises: the previous\n"
         "derived reach claim and this link's edge fact). Per link the order is bind_evidence, assert_fact, derive.\n" + rows + "\n")
    if t.kind == "premise":
        s += ("Special case for link L0: the document also contains the sentence \"" + t.twin_quote + "\" (call it L0b). The agent first recorded L0\n"
              "(evidence e_a, fact f_a) and also recorded L0b (evidence e_b, fact f_b: edge(n0, n1) valid over t=[100,360)). Then it withdrew\n"
              "evidence e_a (revoke_evidence) because L0 was superseded. The derivation of reach(n0, n1) must therefore rest on the surviving\n"
              "fact f_b. The remaining links are recorded as above.\n")
    return s


def context_block(t: exp3.Task) -> str:
    return (SYSTEM_BRIEF + "\nONTOLOGY (JSON):\n" + json.dumps(t.onto, separators=(",", ":")) + "\n\nDOCUMENT \"doc\":\n<<<\n"
            + t.doc.decode("utf-8") + ">>>\n\n" + work_order(t))


def lines_text(ops: list[dict]) -> str:
    return "\n".join(json.dumps(o, separators=(",", ":"), ensure_ascii=False) for o in ops)


def prompt_A1(t, stream, err) -> str:
    generic = {k: err[k] for k in ("status", "seq", "code", "message") if k in err}
    return (context_block(t) + f"\nGRAPH YOU PRODUCED ({len(stream)} lines):\n" + lines_text(stream) +
            "\n\nThe kernel rejected it with this validator error:\n" + json.dumps(generic) +
            f"\n\nOutput the complete corrected graph as JSONL, one JSON object per line, starting with seq 1, covering the whole work order.")


def prompt_A2(t, stream, err) -> str:
    return (context_block(t) + f"\nGRAPH YOU PRODUCED ({len(stream)} lines):\n" + lines_text(stream) +
            "\n\nThe kernel rejected it with this structured error (expected_by_kernel is the value the kernel computed):\n" + json.dumps(err) +
            "\n\nOutput a JSON patch: a JSON array of objects {\"seq\": n, \"line\": {<complete replacement line>}} containing every line whose content "
            "must change - including later lines that depend on the fix. Output only the array.")


def prompt_B_repair(t, accepted, bad_line, err, history) -> str:
    s = context_block(t) + f"\nYou are streaming events to the kernel. Lines 1..{len(accepted)} were accepted:\n" + lines_text(accepted)
    s += "\n\nYour next line was REJECTED:\n" + json.dumps(bad_line, separators=(",", ":"), ensure_ascii=False)
    s += "\nKernel error (expected_by_kernel is the value the kernel computed):\n" + json.dumps(err)
    if history:
        s += "\nEarlier rejected attempts for this seq and their errors:\n" + "\n".join(json.dumps(h) for h in history)
    s += f"\n\nOutput ONLY the corrected line with seq {err['seq']} as a single JSON object."
    return s


def prompt_B_continue(t, accepted) -> str:
    return (context_block(t) + f"\nYou are streaming events to the kernel. Lines 1..{len(accepted)} were accepted:\n" + lines_text(accepted) +
            "\n\nContinue the stream: output the remaining lines (seq " + str(len(accepted) + 1) + " onward) until every link of the work order is derived, "
            "as JSONL, one JSON object per line.")


# ------------------------------------------------------------------ parsing

def strip_fences(text: str) -> str:
    return re.sub(r"^```[a-zA-Z]*\s*|\s*```\s*$", "", text.strip(), flags=re.M)


def parse_lines(text: str) -> list[dict]:
    out = []
    for ln in strip_fences(text).splitlines():
        ln = ln.strip().rstrip(",")
        if not ln.startswith("{"):
            continue
        try:
            o = json.loads(ln)
        except Exception:
            continue
        if isinstance(o, dict):
            out.append(o)
    return out


def parse_patch(text: str) -> list[dict]:
    t = strip_fences(text)
    try:
        arr = json.loads(t)
    except Exception:
        a, b = t.find("["), t.rfind("]")
        try:
            arr = json.loads(t[a:b + 1])
        except Exception:
            return []
    return [x for x in arr if isinstance(x, dict) and "seq" in x and isinstance(x.get("line"), dict)] if isinstance(arr, list) else []


# ------------------------------------------------------------------ kernel side

class TaskEnv:
    def __init__(self, t: exp3.Task, base: pathlib.Path):
        self.t = t
        self.dir = base / f"t{t.idx:02d}"
        self.docdir = self.dir / "docs"
        C.write_docs(self.docdir, {"doc": t.doc})
        self.onto = self.dir / "ontology.json"
        self.onto.write_text(json.dumps(t.onto), encoding="utf-8")
        gs = self.dir / "gold.jsonl"
        C.write_lines(gs, C.jsonl(t.gold))
        self.gold_root = C.cli("apply", "--ontology", self.onto, "--docs", self.docdir, "--stream", gs)["state_root"]
        self.k = next(i for i, (g, e) in enumerate(zip(t.gold, t.err), 1) if g != e)
        self.n = len(t.gold)

    def apply(self, ops: list[dict], tag: str) -> dict:
        p = self.dir / f"{tag}.jsonl"
        C.write_lines(p, [json.dumps(o, separators=(",", ":"), ensure_ascii=False) for o in ops])
        return C.cli("apply", "--ontology", self.onto, "--docs", self.docdir, "--stream", p)


def usage_add(acc: dict, r: dict):
    u = r["usage"]
    acc["calls"] += 1
    acc["input"] += u.get("input_tokens", 0)
    acc["cached"] += u.get("cached_input_tokens", 0)
    acc["output"] += u.get("output_tokens", 0)
    acc["reasoning"] += u.get("reasoning_output_tokens", 0)
    acc["seconds"] += r["seconds"]
    acc["tool_items"] += r["tool_items"]
    acc["from_cache"] += bool(r.get("from_cache"))
    acc["out_bytes"] += len(r["text"].encode("utf-8"))


def new_acc() -> dict:
    return {"calls": 0, "input": 0, "cached": 0, "output": 0, "reasoning": 0, "seconds": 0.0, "tool_items": 0, "from_cache": 0, "out_bytes": 0}


def run_A(agent: Agent, env: TaskEnv, arm: str) -> dict:
    t = env.t
    stream = [dict(o) for o in t.err]
    acc, rounds, trail = new_acc(), 0, []
    success = False
    while True:
        rep = env.apply(stream, f"{arm}_r{rounds}")
        if rep["error"] is None and rep["accepted"] == len(stream):
            success = rep["state_root"] == env.gold_root
            trail.append({"round": rounds, "accepted": rep["accepted"], "root_ok": success})
            break
        err = rep["error"]
        trail.append({"round": rounds, "error_code": err["code"], "error_seq": err.get("seq")})
        if rounds >= MAX_ROUNDS:
            break
        rounds += 1
        if arm == "A1":
            r = agent.call(prompt_A1(t, stream, err), f"t{t.idx}-A1-r{rounds}")
            usage_add(acc, r)
            new = parse_lines(r["text"])
            if not new:
                trail.append({"round": rounds, "parse_failure": True})
                break
            stream = new
        else:
            r = agent.call(prompt_A2(t, stream, err), f"t{t.idx}-A2-r{rounds}")
            usage_add(acc, r)
            patch = parse_patch(r["text"])
            if not patch:
                trail.append({"round": rounds, "parse_failure": True})
                break
            for p in patch:
                i = int(p["seq"]) - 1
                if 0 <= i < len(stream):
                    stream[i] = p["line"]
                elif i == len(stream):
                    stream.append(p["line"])
    return {"arm": arm, "success": success, "rounds": rounds, "usage": acc, "trail": trail}


def run_B(agent: Agent, env: TaskEnv) -> dict:
    t, k, n = env.t, env.k, env.n
    sv = exp3.Serve(env.onto, env.docdir)
    acc, trail, history = new_acc(), [], []
    accepted: list[dict] = []
    repairs = 0
    success = False
    extra_lines = 0
    try:
        for line in t.err[:k - 1]:
            assert exp3.is_ok(sv.send(line))
            accepted.append(line)
        resp = sv.send(t.err[k - 1])
        trail.append({"phase": "inject", "code": resp.get("code"), "seq": resp.get("seq")})
        bad = t.err[k - 1]
        pending = None if exp3.is_ok(resp) else (bad, resp)
        guard = 0
        while guard < 12:
            guard += 1
            if pending:
                if repairs >= MAX_ROUNDS:
                    break
                bad_line, err = pending
                repairs += 1
                r = agent.call(prompt_B_repair(t, accepted, bad_line, err, history), f"t{t.idx}-B-repair{repairs}")
                usage_add(acc, r)
                new = parse_lines(r["text"])
                if not new:
                    trail.append({"phase": "repair", "parse_failure": True})
                    break
                line = new[0]
                resp = sv.send(line)
                if exp3.is_ok(resp):
                    accepted.append(line)
                    history = []
                    pending = None
                    trail.append({"phase": "repair", "ok": True})
                else:
                    history.append({"line": bad_line, "error": {kk: err.get(kk) for kk in ("code", "message", "expected_by_kernel")}})
                    pending = (line, resp)
                    trail.append({"phase": "repair", "ok": False, "code": resp.get("code")})
                continue
            if len(accepted) >= n:
                break
            r = agent.call(prompt_B_continue(t, accepted), f"t{t.idx}-B-cont{guard}")
            usage_add(acc, r)
            lines = parse_lines(r["text"])
            if not lines:
                trail.append({"phase": "continue", "parse_failure": True})
                break
            for line in lines:
                if len(accepted) >= n:
                    extra_lines += 1
                    continue
                resp = sv.send(line)
                if exp3.is_ok(resp):
                    accepted.append(line)
                else:
                    pending = (line, resp)
                    trail.append({"phase": "continue", "ok": False, "code": resp.get("code"), "seq": resp.get("seq")})
                    break
        if len(accepted) == n:
            fin = sv.send({"op": "finish", "out": str(env.dir / "final_B.sbgk")})
            success = fin["state_root"] == env.gold_root
    finally:
        sv.close()
    return {"arm": "B", "success": success, "rounds": repairs, "usage": acc, "trail": trail, "accepted": len(accepted),
            "extra_lines_ignored": extra_lines}


# ------------------------------------------------------------------ driver

def run(model: str = "gpt-5.6-sol", effort: str | None = None, limit: int | None = None, workers: int = 4,
        arms: tuple[str, ...] = ("A1", "A2", "B"), fresh: bool = False, codex: str | None = None) -> dict:
    if fresh and OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True, exist_ok=True)
    agent = Agent(codex or find_codex(), model, effort)
    baseline = agent.baseline()
    rng = random.Random(3003)
    n_tasks = limit or 30
    tasks = [exp3.Task(i, exp3.TYPES[i % 4], rng) for i in range(n_tasks)]
    base = OUT / "work"
    envs = {t.idx: TaskEnv(t, base) for t in tasks}

    jobs = [(t.idx, arm) for t in tasks for arm in arms]

    def job(j):
        idx, arm = j
        env = envs[idx]
        t0 = time.time()
        try:
            res = run_B(agent, env) if arm == "B" else run_A(agent, env, arm)
        except Exception as e:  # keep the experiment going; the failure is part of the record
            res = {"arm": arm, "success": False, "rounds": 0, "usage": new_acc(), "trail": [{"exception": str(e)[:300]}]}
        res.update({"task": idx, "type": env.t.kind, "lines": env.n, "injected_at": env.k, "wall_s": time.time() - t0})
        print(f"  task {idx:02d} {arm:<2} {env.t.kind:<8} success={res['success']} rounds={res['rounds']} calls={res['usage']['calls']}", flush=True)
        return res

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(job, jobs))

    base_in = baseline.get("input_tokens", 0)
    scripted = {}
    for t in tasks:
        env = envs[t.idx]
        scripted[t.idx] = {"A_initial_bytes": exp3.mono_bytes(t.err), "B_prefix_bytes": exp3.stream_bytes(t.err[:env.k]), "lines": env.n}
    summary = {
        "model": model, "codex_version": agent.version, "reasoning_effort": effort or "default", "tasks": n_tasks,
        "baseline_call_usage": baseline, "cached_calls_reused": agent.cached, "results": results, "scripted_parts": scripted,
        "base_input_tokens": base_in,
    }
    shutil.rmtree(base, ignore_errors=True)
    (OUT / "exp3_llm.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False), encoding="utf-8")
    return summary
